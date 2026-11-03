import support  # noqa: F401  (isolates config, cache and state)
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zkit import build

# A clang+llvm release folder of LLVM 3.9-8 (bin/clang++ and include/): the plugins use the legacy pass manager.
OLD_CLANG = os.environ.get("ZKIT_TEST_OLD_CLANG")

# Two guarded statics: one whose destructor calls an empty base destructor (stock LLVM <= 8 drops its
# __cxa_atexit, LLVM 9's rule keeps it), one whose destructor is a bare `ret` (both rules drop it).
STATICS = """
struct Base { virtual ~Base() {} };
struct Derived : Base { Derived(); ~Derived(); int value; };
Derived::Derived() : value(1) {}
Derived::~Derived() {}
struct Plain { Plain(); ~Plain(); int value; };
Plain::Plain() : value(2) {}
Plain::~Plain() {}
template <typename T> T *get() { static T instance; return &instance; }
int derived() { return get<Derived>()->value; }
int plain() { return get<Plain>()->value; }
"""

# Two this-adjusting thunks: one whose `sub x0, x0, #152` starts the block of its tail call and is followed by a
# load through x0 (stock LLVM 3.9+ folds it into `ldr x8, [x0, #-152]!`, the pre-173b14db optimizer leaves it), and
# one whose same update starts its entry block (folded under both).
UPDATES = """
struct Node { void sync(); char pad[0x40]; long value; const long &get() { sync(); return value; } };
struct Base { virtual void s0(); virtual const long &self() const; char pad[0x90]; };
struct Face { virtual const long &look() const = 0; virtual long peek() const = 0; char pad[0x98]; };
struct Both : Base, Face { Node *node; const long &look() const; long peek() const; virtual long other() const; };
const long &Both::look() const { return node ? node->get() : self(); }
long Both::peek() const { return other(); }
"""


def compiled(clang: Path, source: Path, extra: list[str]) -> str:
    return subprocess.run([str(clang), "--target=aarch64-none-elf", "-fPIC", "-O3", "-fno-exceptions", "-fno-rtti",
                           "-ffunction-sections", "-S", str(source), "-o", "-", *extra], check=True,
                          capture_output=True, text=True).stdout


def pre_index_folds(asm: str) -> dict[str, int]:
    """`[x0, #-152]!` loads per function of the compiled assembly."""
    counts, function = {}, None
    for line in asm.splitlines():
        label = re.match(r"([A-Za-z_][\w$]*):", line)
        if label:
            function = label.group(1)
            counts.setdefault(function, 0)
        elif re.search(r"\[x0, #-152\]!", line):
            counts[function] += 1
    return counts


def registrations(clang: Path, source: Path, extra: list[str]) -> dict[str, int]:
    """__cxa_atexit calls per function of the compiled assembly."""
    asm = subprocess.run([str(clang), "--target=aarch64-none-elf", "-fPIC", "-O3", "-fno-exceptions", "-fno-rtti",
                          "-ffunction-sections", "-S", str(source), "-o", "-", *extra], check=True,
                         capture_output=True, text=True).stdout
    counts, function = {}, None
    for line in asm.splitlines():
        label = re.match(r"([A-Za-z_][\w$]*):", line)
        if label:
            function = label.group(1)
            counts.setdefault(function, 0)
        elif "bl\t__cxa_atexit" in line:
            counts[function] += 1
    return counts


class ClangPluginTests(unittest.TestCase):
    def test_unknown_plugin_and_missing_headers_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "bin" / "clang++"
            with self.assertRaisesRegex(ValueError, "no plugin 'nope'.*bare-return-atexit"):
                build.clang_plugin(Path(temp), clang, "nope")
            with self.assertRaisesRegex(ValueError, "has no LLVM headers"):
                build.clang_plugin(Path(temp), clang, "bare-return-atexit")

    def test_units_load_their_plugins(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            clang, plugin = root / "clang++", root / "build/tools/clang-plugins/p.so"
            clang.write_text("")
            config = {**build.settings({"platform": "switch", "build": {"compiler": str(clang)}}),
                      "clang_plugins": ["bare-return-atexit"], "extra_cflags": ["-DX"]}
            with mock.patch.object(build, "clang_plugin", return_value=plugin) as made, \
                    mock.patch.object(build, "source_root", return_value=None):
                step = build._compile(root, config, "a.cpp", build.Layout("build/t"), {}, [])
            made.assert_called_once_with(root, clang, "bare-return-atexit")
            self.assertEqual(step["flags"][-5:], ["-DX", "-Xclang", "-load", "-Xclang", plugin.as_posix()])
            self.assertIn("build/tools/clang-plugins/p.so", step["implicit"])

    @unittest.skipUnless(OLD_CLANG, "set ZKIT_TEST_OLD_CLANG to a clang+llvm 3.9-8 release folder")
    def test_bare_return_atexit_keeps_registrations_of_destructors_that_call_empty_ones(self):
        clang = Path(OLD_CLANG) / "bin" / "clang++"
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "statics.cpp"
            source.write_text(STATICS, encoding="utf-8")
            plugin = build.clang_plugin(Path(temp), clang, "bare-return-atexit")
            self.assertEqual(build.clang_plugin(Path(temp), clang, "bare-return-atexit"), plugin)  # built once
            stock = registrations(clang, source, [])
            ruled = registrations(clang, source, ["-Xclang", "-load", "-Xclang", str(plugin)])
            self.assertEqual((stock["_Z7derivedv"], stock["_Z5plainv"]), (0, 0))
            self.assertEqual((ruled["_Z7derivedv"], ruled["_Z5plainv"]), (1, 0))

    @unittest.skipUnless(OLD_CLANG, "set ZKIT_TEST_OLD_CLANG to a clang+llvm 3.9-8 release folder")
    def test_pre_index_skips_block_start_leaves_block_first_updates_unfolded(self):
        clang = Path(OLD_CLANG) / "bin" / "clang++"
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "updates.cpp"
            source.write_text(UPDATES, encoding="utf-8")
            plugin = build.clang_plugin(Path(temp), clang, "pre-index-skips-block-start")
            stock = pre_index_folds(compiled(clang, source, []))
            ruled_asm = compiled(clang, source, ["-Xclang", "-load", "-Xclang", str(plugin)])
            ruled = pre_index_folds(ruled_asm)
            inner, entry = "_ZThn152_NK4Both4lookEv", "_ZThn152_NK4Both4peekEv"
            self.assertEqual((stock[inner], stock[entry]), (1, 1))
            self.assertEqual((ruled[inner], ruled[entry]), (0, 1))
            self.assertIn("sub\tx0, x0, #152", ruled_asm)


if __name__ == "__main__":
    unittest.main()
