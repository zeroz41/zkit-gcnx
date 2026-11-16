import support  # noqa: F401  (isolates config, cache and state)
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zkit import build

# A clang+llvm release folder of LLVM 3.9-8 (bin/clang++ and include/): the plugins use the legacy pass manager.
OLD_CLANG = os.environ.get("ZKIT_TEST_OLD_CLANG")
# An official Windows clang release folder (bin/clang++.exe) that a plugin has a patch for, such as LLVM 3.9.1's
# win64 release, and what runs a Windows program on this system when it is not Windows (e.g. `wine`).
WINDOWS_CLANG = os.environ.get("ZKIT_TEST_WINDOWS_CLANG")
WINDOWS_RUNNER = shlex.split(os.environ.get("ZKIT_TEST_WINDOWS_RUNNER", ""))

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

# Statics whose destructors do nothing in different ways. Stock LLVM <= 8 drops the __cxa_atexit registration of
# each destructor that only calls ones that do nothing; LLVM 9's rule drops only a bare `ret`.
ATEXIT = """
extern void side_effect();
int counter;
struct Empty { ~Empty() {} };
Empty empty;                                  // dropped by both
static void nothing() {}
struct CallsNothing { ~CallsNothing() { nothing(); } };
CallsNothing calls_nothing;                   // kept by the rule
struct Member { ~Member() {} };
struct HasMember { Member member; ~HasMember() {} };
HasMember has_member;                         // kept by the rule: the destructor calls ~Member
struct Nested { HasMember inner; CallsNothing other; };
Nested nested;                                // kept by the rule
struct Real { ~Real() { side_effect(); } };
Real real;                                    // kept by both
struct Counts { ~Counts() { ++counter; } };
Counts counts;                                // kept by both
CallsNothing &local_static() { static CallsNothing object; return object; }  // kept by the rule
Real &local_real() { static Real object; return object; }
int use_all() { return counter + (&local_static() != 0) + (&local_real() != 0); }
"""
ATEXIT_STOCK = {"_ZN4RealD2Ev", "_ZN6CountsD2Ev"}
ATEXIT_RULED = ATEXIT_STOCK | {"_ZN12CallsNothingD2Ev", "_ZN9HasMemberD2Ev", "_ZN6NestedD2Ev"}


def compiled_asm(clang: list[str], source: Path, extra: list[str]) -> str:
    return subprocess.run([*clang, "--target=aarch64-none-elf", "-fPIC", "-O3", "-fno-exceptions", "-fno-rtti",
                           "-ffunction-sections", "-w", "-S", str(source), "-o", "-", *extra], check=True,
                          capture_output=True, text=True).stdout


def registered(clang: list[str], source: Path, extra: list[str]) -> set[str]:
    """The destructors the compiled assembly passes to __cxa_atexit: each call's (or tail call's) last destructor named
    before it."""
    found, last = set(), None
    for line in compiled_asm(clang, source, extra).splitlines():
        if not line.startswith("\t") or line.startswith("\t."):
            continue
        last = ([last] + re.findall(r"_Z\w*D[12]Ev", line))[-1]
        if re.match(r"\tbl?\t__cxa_atexit$", line):
            found.add(last)
    return found


def fake_patch(data: bytes, offset: int, new: bytes) -> dict:
    patched = data[:offset] + new + data[offset + len(new):]
    return {"sha256": hashlib.sha256(data).hexdigest(), "patched_sha256": hashlib.sha256(patched).hexdigest(),
            "edits": [{"offset": hex(offset), "old": data[offset:offset + len(new)].hex(), "new": new.hex()}]}


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
            with mock.patch.object(build, "clang_plugin", return_value=plugin) as made:
                step = build._compile(root, config, "a.cpp", build.Layout("build/t"), {}, [])
            made.assert_called_once_with(root, clang, "bare-return-atexit")
            self.assertEqual(step["flags"][-5:], ["-DX", "-Xclang", "-load", "-Xclang", plugin.as_posix()])
            self.assertIn("build/tools/clang-plugins/p.so", step["implicit"])

    def test_windows_compiles_with_the_patched_copy(self):
        data = b"MZ" + bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "win32"), \
                mock.patch.object(build, "clang_plugin") as made, \
                mock.patch.object(build, "plugin_patches", return_value=[fake_patch(data, 0x40, b"\xeb\x07")]):
            root = Path(temp)
            (root / "bin").mkdir()
            (root / "bin/clang++.exe").write_bytes(data)
            config = {**build.settings({"platform": "switch", "build": {"compiler": "bin/clang++"}}),
                      "clang_plugins": ["bare-return-atexit"], "extra_cflags": ["-DX"]}
            found, notes = {}, []
            with mock.patch.object(build, "patched_clang", wraps=build.patched_clang) as patched:
                for unit in ("a.cpp", "b.cpp"):
                    step = build._compile(root, config, unit, build.Layout("build/t"), found, notes)
                    self.assertEqual(step["flags"][-1], "-DX")
            patched.assert_called_once()  # once per build, not per unit
            made.assert_not_called()
            self.assertEqual(notes, [])
            copy = root / "bin/clang++-bare_return_atexit.exe"
            self.assertEqual(step["cc"], [str(copy)])
            self.assertEqual(step["implicit"], ["bin/clang++-bare_return_atexit.exe"])
            self.assertEqual(copy.read_bytes(), data[:0x40] + b"\xeb\x07" + data[0x42:])
            self.assertEqual((root / "bin/clang++.exe").read_bytes(), data)  # the official one is left as it is

    def test_windows_without_a_patch_builds_without_plugins_and_says_so_once(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "win32"), \
                mock.patch.object(build, "clang_plugin") as made:
            root = Path(temp)
            (root / "clang++.exe").write_text("")
            config = {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++")}}),
                      "clang_plugins": ["bare-return-atexit"], "extra_cflags": ["-DX"]}
            found, notes = {}, []
            for unit in ("a.cpp", "b.cpp"):
                step = build._compile(root, config, unit, build.Layout("build/t"), found, notes)
                self.assertEqual(step["flags"][-1], "-DX")
            made.assert_not_called()
            self.assertEqual(len(notes), 1)
            self.assertIn("cannot load plugins, and zkit has no patch for this clang++.exe", notes[0])
            self.assertIn(hashlib.sha256(b"").hexdigest(), notes[0])
            self.assertEqual(step["cc"], [str(root / "clang++.exe")])  # .exe left off in the project file

    def test_patched_clang_checks_the_binary_the_edits_and_the_result(self):
        data = bytes(range(256)) * 2
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "clang.exe"
            clang.write_bytes(data)
            good = fake_patch(data, 0x10, b"\x90\x90")
            with mock.patch.object(build, "plugin_patches", return_value=[]):
                self.assertIsNone(build.patched_clang(clang, ["bare-return-atexit"]))  # no patch for this binary
            with self.assertRaisesRegex(ValueError, "no plugin 'nope'"):
                build.patched_clang(clang, ["nope"])
            for wrong, message in (({**good, "edits": [{**good["edits"][0], "old": "0000"}]}, "does not fit"),
                                   ({**good, "edits": [{**good["edits"][0], "new": "90"}]}, "does not fit"),
                                   ({**good, "patched_sha256": "0" * 64}, "gave SHA-256")):
                with self.subTest(message=message), mock.patch.object(build, "plugin_patches", return_value=[wrong]), \
                        self.assertRaisesRegex(ValueError, message):
                    build.patched_clang(clang, ["bare-return-atexit"])
            with mock.patch.object(build, "plugin_patches", return_value=[good]):
                copy = build.patched_clang(clang, ["bare-return-atexit"])
                self.assertEqual(copy, Path(temp) / "clang-bare_return_atexit.exe")
                made = copy.stat().st_mtime_ns
                self.assertEqual(build.patched_clang(clang, ["bare-return-atexit"]), copy)
                self.assertEqual(copy.stat().st_mtime_ns, made)  # a good copy is kept
                copy.write_bytes(data)
                build.patched_clang(clang, ["bare-return-atexit"])
                self.assertEqual(hashlib.sha256(copy.read_bytes()).hexdigest(), good["patched_sha256"])  # remade
            self.assertEqual(sorted(path.name for path in Path(temp).iterdir()),
                             ["clang-bare_return_atexit.exe", "clang.exe"])

    def test_shipped_patches_are_well_formed(self):
        for table in sorted(build.PLUGINS.glob("*.patches.json")):
            with self.subTest(table=table.name):
                name = table.name.removesuffix(".patches.json").replace("_", "-")
                build.plugin_source(name)
                patches = json.loads(table.read_text(encoding="utf-8"))["patches"]
                self.assertEqual(build.plugin_patches(name), patches)
                self.assertEqual(len({patch["sha256"] for patch in patches}), len(patches))
                for patch in patches:
                    for key in ("sha256", "patched_sha256"):
                        self.assertRegex(patch[key], r"^[0-9a-f]{64}$")
                    end = 0
                    for edit in patch["edits"]:
                        offset = int(edit["offset"], 16)
                        old, new = bytes.fromhex(edit["old"]), bytes.fromhex(edit["new"])
                        self.assertGreaterEqual(offset, end)  # in order, none overlapping
                        self.assertEqual(len(old), len(new))
                        self.assertNotEqual(old, new)
                        self.assertTrue(edit["why"])
                        end = offset + len(old)

    def test_macos_leaves_llvm_symbols_to_clang(self):
        for platform, expected in (("darwin", True), ("linux", False)):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temp, \
                    mock.patch("sys.platform", platform), mock.patch.dict(os.environ, {"CXX": "c++"}), \
                    mock.patch.object(build.subprocess, "run") as run:
                clang = Path(temp) / "llvm/bin/clang++"
                config = Path(temp) / "llvm/include/llvm/Config/llvm-config.h"
                config.parent.mkdir(parents=True)
                config.write_text("#define LLVM_VERSION_MAJOR 3\n")
                run.return_value = subprocess.CompletedProcess([], 0, "", "")
                with mock.patch.object(Path, "replace"):
                    build.clang_plugin(Path(temp), clang, "bare-return-atexit")
                argv = run.call_args[0][0]
                self.assertEqual("dynamic_lookup" in argv and argv[argv.index("dynamic_lookup") - 1] == "-undefined",
                                 expected)

    def test_macos_builds_the_plugin_for_the_clang_architecture(self):
        # an x86-64 clang (Rosetta 2 on an Arm Mac) needs an x86-64 plugin; another format adds nothing
        for head, expected in ((b"\xcf\xfa\xed\xfe\x07\x00\x00\x01", ["-arch", "x86_64"]),
                               (b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", ["-arch", "arm64"]),
                               (b"\x7fELF\x02\x01\x01\x00", [])):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp, \
                    mock.patch("sys.platform", "darwin"), mock.patch.dict(os.environ, {"CXX": "c++"}), \
                    mock.patch.object(build.subprocess, "run") as run:
                clang = Path(temp) / "llvm/bin/clang++"
                clang.parent.mkdir(parents=True)
                clang.write_bytes(head + bytes(24))
                config = Path(temp) / "llvm/include/llvm/Config/llvm-config.h"
                config.parent.mkdir(parents=True)
                config.write_text("#define LLVM_VERSION_MAJOR 3\n")
                run.return_value = subprocess.CompletedProcess([], 0, "", "")
                with mock.patch.object(Path, "replace"):
                    build.clang_plugin(Path(temp), clang, "bare-return-atexit")
                argv = run.call_args[0][0]
                self.assertEqual(argv[argv.index("-arch"):argv.index("-arch") + 2] if "-arch" in argv else [],
                                 expected)

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
    def test_bare_return_atexit_keeps_only_bare_return_destructors_dropped(self):
        clang = Path(OLD_CLANG) / "bin" / "clang++"
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "atexit.cpp"
            source.write_text(ATEXIT, encoding="utf-8")
            plugin = build.clang_plugin(Path(temp), clang, "bare-return-atexit")
            self.assertEqual(registered([str(clang)], source, []), ATEXIT_STOCK)
            self.assertEqual(registered([str(clang)], source, ["-Xclang", "-load", "-Xclang", str(plugin)]),
                             ATEXIT_RULED)

    @unittest.skipUnless(WINDOWS_CLANG and (sys.platform == "win32" or WINDOWS_RUNNER),
                         "set ZKIT_TEST_WINDOWS_CLANG to an official Windows clang release folder with a patch "
                         "(and ZKIT_TEST_WINDOWS_RUNNER, e.g. wine, when this is not Windows)")
    def test_bare_return_atexit_patch_gives_the_plugins_rule(self):
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "bin" / "clang++.exe"
            clang.parent.mkdir()
            shutil.copyfile(Path(WINDOWS_CLANG) / "bin" / "clang++.exe", clang)
            source = Path(temp) / "atexit.cpp"
            source.write_text(ATEXIT, encoding="utf-8")
            copy = build.patched_clang(clang, ["bare-return-atexit"])
            self.assertIsNotNone(copy, "no patch for this clang++.exe")
            self.assertEqual(registered([*WINDOWS_RUNNER, str(clang)], source, []), ATEXIT_STOCK)
            self.assertEqual(registered([*WINDOWS_RUNNER, str(copy)], source, []), ATEXIT_RULED)


if __name__ == "__main__":
    unittest.main()
