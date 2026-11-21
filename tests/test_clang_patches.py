import support  # noqa: F401  (isolates config, cache and state)
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zkit import build

# An official clang release folder (bin/clang++, or bin/clang++.exe with ZKIT_TEST_PATCH_RUNNER) that the
# no-large-offset-merge rule has a patch for, such as LLVM 22.1.8's, and what runs it when it is a Windows program
# on another system (e.g. `wine`).
PATCH_CLANG = os.environ.get("ZKIT_TEST_PATCH_CLANG")
PATCH_RUNNER = os.environ.get("ZKIT_TEST_PATCH_RUNNER", "").split()
# An official clang release folder (bin/clang++) the no-ctor-evaluation rule has a patch for, such as LLVM 19.1.7's
# for Linux x86-64.
OPTIMIZER_PATCH_CLANG = os.environ.get("ZKIT_TEST_OPTIMIZER_PATCH_CLANG")

# A field past 0x40000: stock clang 18+ adds the offset's high part to the base and loads with the low part as the
# load's immediate; without the merge the offset is built in a register and the load takes it as its index.
FAR_FIELD = """
struct Big { char pad[0x4cb58]; int value; };
int far_field(const Big *big) { return big->value; }
"""


# A static initializer stock GlobalOpt runs at compile time: the store folds into the global's initializer and the
# unit has no _GLOBAL__sub_I_ function; without the evaluation the store stays code in one.
STATIC_INIT = """
struct Counter { int value; Counter() : value(7) {} };
Counter g_counter;
"""


def fake_patch(data: bytes, offset: int, new: bytes) -> dict:
    patched = data[:offset] + new + data[offset + len(new):]
    return {"sha256": hashlib.sha256(data).hexdigest(), "patched_sha256": hashlib.sha256(patched).hexdigest(),
            "edits": [{"offset": hex(offset), "old": data[offset:offset + len(new)].hex(), "new": new.hex()}]}


def far_field_asm(cc: list[str], source: Path) -> str:
    run = subprocess.run([*cc, "--target=aarch64-none-elf", "-O2", "-S", str(source), "-o", "-"], check=True,
                         capture_output=True, text=True)
    return " ".join(" ".join(line.split("//")[0].split()) for line in run.stdout.splitlines()
                    if line.startswith("\t") and not line.lstrip().startswith("."))


class ClangPatchesTest(unittest.TestCase):
    def test_units_compile_with_the_patched_copy_on_every_system(self):
        data = bytes(range(256)) * 4
        for platform, exe in (("linux", "clang++"), ("darwin", "clang++"), ("win32", "clang++.exe")):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temp, \
                    mock.patch("sys.platform", platform), mock.patch.object(build, "clang_plugin") as made, \
                    mock.patch.object(build, "clang_patches", return_value=[fake_patch(data, 0x40, b"\x66\x90")]):
                root = Path(temp)
                (root / "bin").mkdir()
                (root / "bin" / exe).write_bytes(data)
                config = {**build.settings({"platform": "switch", "build": {"compiler": "bin/clang++"}}),
                          "clang_patches": ["no-large-offset-merge"], "extra_cflags": ["-DX"]}
                found, notes = {}, []
                with mock.patch.object(build, "patched_clang", wraps=build.patched_clang) as patched:
                    for unit in ("a.cpp", "b.cpp"):
                        step = build._compile(root, config, unit, build.Layout("build/t"), found, notes)
                        self.assertEqual(step["flags"][-1], "-DX")
                patched.assert_called_once()  # once per build, not per unit
                made.assert_not_called()
                self.assertEqual(notes, [])
                copy = root / "bin" / exe.replace("clang++", "clang++-no_large_offset_merge")
                self.assertEqual(step["cc"], [str(copy)])
                self.assertEqual(step["implicit"], [copy.relative_to(root).as_posix()])
                self.assertEqual(copy.read_bytes(), data[:0x40] + b"\x66\x90" + data[0x42:])
                self.assertEqual((root / "bin" / exe).read_bytes(), data)  # the official one is left as it is

    def test_a_unit_without_the_rule_keeps_the_official_compiler(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "linux"):
            root = Path(temp)
            (root / "clang++").write_bytes(b"clang")
            config = {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++")}}),
                      "clang_patches": [], "extra_cflags": []}
            step = build._compile(root, config, "a.cpp", build.Layout("build/t"), {}, [])
            self.assertEqual(step["cc"], [str(root / "clang++")])
            self.assertEqual([path.name for path in root.iterdir()], ["clang++"])

    def test_without_a_patch_units_build_with_the_official_binary_and_say_so_once(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "linux"):
            root = Path(temp)
            (root / "clang++").write_text("")
            config = {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++")}}),
                      "clang_patches": ["no-large-offset-merge"], "extra_cflags": []}
            found, notes = {}, []
            for unit in ("a.cpp", "b.cpp"):
                step = build._compile(root, config, unit, build.Layout("build/t"), found, notes)
            self.assertEqual(len(notes), 1)
            self.assertIn("zkit has no patch for this clang++", notes[0])
            self.assertIn("build.clang_patches (no-large-offset-merge)", notes[0])
            self.assertIn(hashlib.sha256(b"").hexdigest(), notes[0])
            self.assertEqual(step["cc"], [str(root / "clang++")])

    def test_windows_applies_plugin_patches_then_rules_in_one_copy(self):
        data = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "win32"), \
                mock.patch.object(build, "clang_plugin") as made:
            root = Path(temp)
            (root / "clang++.exe").write_bytes(data)
            first = fake_patch(data, 0x10, b"\xeb\x07")
            once = data[:0x10] + b"\xeb\x07" + data[0x12:]
            second = fake_patch(once, 0x80, b"\x66\x90")
            with mock.patch.object(build, "plugin_patches", return_value=[first]), \
                    mock.patch.object(build, "clang_patches", return_value=[second]):
                config = {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++")}}),
                          "clang_plugins": ["bare-return-atexit"], "clang_patches": ["no-large-offset-merge"],
                          "extra_cflags": []}
                notes = []
                step = build._compile(root, config, "a.cpp", build.Layout("build/t"), {}, notes)
            made.assert_not_called()
            self.assertEqual(notes, [])
            copy = root / "clang++-bare_return_atexit+no_large_offset_merge.exe"
            self.assertEqual(step["cc"], [str(copy)])
            self.assertEqual(hashlib.sha256(copy.read_bytes()).hexdigest(), second["patched_sha256"])
            self.assertNotIn("-load", step["flags"])

    def test_linux_loads_plugins_and_patches_the_rules(self):
        data = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "linux"), \
                mock.patch.object(build, "clang_plugin", return_value=Path(temp) / "p.so") as made, \
                mock.patch.object(build, "clang_patches", return_value=[fake_patch(data, 0x40, b"\x66\x90")]):
            root = Path(temp)
            (root / "clang++").write_bytes(data)
            config = {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++")}}),
                      "clang_plugins": ["bare-return-atexit"], "clang_patches": ["no-large-offset-merge"],
                          "extra_cflags": []}
            step = build._compile(root, config, "a.cpp", build.Layout("build/t"), {}, [])
            copy = root / "clang++-no_large_offset_merge"
            self.assertEqual(step["cc"], [str(copy)])
            made.assert_called_once_with(root, root / "clang++", "bare-return-atexit")  # built against the official
            self.assertIn("-load", step["flags"])

    def test_optimizer_patches_patch_the_optimizer_not_the_compiler(self):
        """build.optimizer_patches: the optimizer stage (the step's `cc` and argv) runs a patched copy of the
        optimizer, made once per build; the compiler (`backend`) stays the official binary."""
        data = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "linux"), \
                mock.patch.object(build, "clang_patches", return_value=[fake_patch(data, 0x40, b"\x31\xc0\xc3")]):
            root = Path(temp)
            (root / "opt").mkdir()
            (root / "opt" / "clang++").write_bytes(data)
            (root / "cg").mkdir()
            (root / "cg" / "clang++").write_bytes(b"code generator")
            config = {**build.settings({"platform": "switch", "build": {"compiler": "cg/clang++",
                                                                        "optimizer": "opt/clang++"}}),
                      "optimizer_patches": ["no-ctor-evaluation"], "extra_cflags": []}
            found, notes = {}, []
            with mock.patch.object(build, "patched_clang", wraps=build.patched_clang) as patched:
                for unit in ("a.cpp", "b.cpp"):
                    step = build._compile(root, config, unit, build.Layout("build/t"), found, notes)
            patched.assert_called_once_with(root / "opt" / "clang++", [], ["no-ctor-evaluation"],
                                            "build.optimizer_patches")
            self.assertEqual(notes, [])
            copy = root / "opt" / "clang++-no_ctor_evaluation"
            self.assertEqual(step["cc"], [str(copy)])
            self.assertEqual(step["argv"][0], str(copy))
            self.assertEqual(step["backend"], [str(root / "cg" / "clang++")])
            self.assertIn(copy.relative_to(root).as_posix(), step["implicit"])
            self.assertEqual(copy.read_bytes(), data[:0x40] + b"\x31\xc0\xc3" + data[0x43:])
            self.assertEqual((root / "opt" / "clang++").read_bytes(), data)

    def test_without_an_optimizer_patch_units_optimize_with_the_official_binary_and_say_so_once(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch("sys.platform", "linux"):
            root = Path(temp)
            (root / "clang++").write_text("")
            config = {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++"),
                                                                        "optimizer": str(root / "clang++")}}),
                      "optimizer_patches": ["no-ctor-evaluation"], "extra_cflags": []}
            found, notes = {}, []
            for unit in ("a.cpp", "b.cpp"):
                step = build._compile(root, config, unit, build.Layout("build/t"), found, notes)
            self.assertEqual(len(notes), 1)
            self.assertIn("build.optimizer_patches (no-ctor-evaluation)", notes[0])
            self.assertIn(hashlib.sha256(b"").hexdigest(), notes[0])
            self.assertEqual(step["cc"], [str(root / "clang++")])

    def test_optimizer_patches_may_be_set_per_unit(self):
        config = build.settings({"platform": "switch", "build": {
            "compiler": "clang++", "optimizer": "clang++",
            "units": {"lib/*": {"optimizer_patches": ["no-ctor-evaluation"]}}}})
        self.assertEqual(build.unit_settings(config, "lib/a.cpp")["optimizer_patches"], ["no-ctor-evaluation"])
        self.assertFalse(build.unit_settings(config, "game/a.cpp").get("optimizer_patches"))

    def test_unknown_rule_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "clang"
            clang.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "no rule 'nope' \\(zkit has: .*no-large-offset-merge"):
                build.patched_clang(clang, [], ["nope"])

    def test_patched_clang_checks_the_binary_the_edits_and_the_result(self):
        data = bytes(range(256)) * 2
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "clang"
            clang.write_bytes(data)
            good = fake_patch(data, 0x10, b"\x66\x90")
            with mock.patch.object(build, "clang_patches", return_value=[]):
                self.assertIsNone(build.patched_clang(clang, [], ["no-large-offset-merge"]))
            for wrong, message in (({**good, "edits": [{**good["edits"][0], "old": "0000"}]}, "does not fit"),
                                   ({**good, "patched_sha256": "0" * 64}, "gave SHA-256")):
                with self.subTest(message=message), mock.patch.object(build, "clang_patches", return_value=[wrong]), \
                        self.assertRaisesRegex(ValueError, f"build.clang_patches: .*{message}"):
                    build.patched_clang(clang, [], ["no-large-offset-merge"])
            with mock.patch.object(build, "clang_patches", return_value=[good]):
                copy = build.patched_clang(clang, [], ["no-large-offset-merge"])
                self.assertEqual(copy, Path(temp) / "clang-no_large_offset_merge")
                self.assertEqual(copy.stat().st_mode, clang.stat().st_mode)

    def test_shipped_rules_are_well_formed(self):
        tables = sorted(build.PATCHES.glob("*.json"))
        self.assertTrue(tables)
        for table in tables:
            with self.subTest(table=table.name):
                name = table.stem.replace("_", "-")
                content = json.loads(table.read_text(encoding="utf-8"))
                self.assertTrue(content["about"])
                patches = content["patches"]
                self.assertEqual(build.clang_patches(name), patches)
                self.assertEqual(len({patch["sha256"] for patch in patches}), len(patches))
                for patch in patches:
                    self.assertTrue(patch["release"])
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

    @unittest.skipUnless(PATCH_CLANG, "set ZKIT_TEST_PATCH_CLANG to an official clang release folder the "
                                      "no-large-offset-merge rule has a patch for (ZKIT_TEST_PATCH_RUNNER: e.g. wine)")
    def test_no_large_offset_merge_keeps_the_register_offset(self):
        exe = "clang++.exe" if PATCH_RUNNER else "clang++"
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "bin" / exe
            clang.parent.mkdir()
            shutil.copyfile(Path(PATCH_CLANG) / "bin" / exe, clang)
            shutil.copymode(Path(PATCH_CLANG) / "bin" / exe, clang)
            source = Path(temp) / "far.cpp"
            source.write_text(FAR_FIELD, encoding="utf-8")
            copy = build.patched_clang(clang, [], ["no-large-offset-merge"])
            self.assertIsNotNone(copy, f"no patch for this {exe}")
            self.assertEqual(far_field_asm([*PATCH_RUNNER, str(clang)], source),
                             "add x8, x0, #76, lsl #12 ldr w0, [x8, #2904] ret")
            self.assertEqual(far_field_asm([*PATCH_RUNNER, str(copy)], source),
                             "mov w8, #52056 movk w8, #4, lsl #16 ldr w0, [x0, x8] ret")

    @unittest.skipUnless(OPTIMIZER_PATCH_CLANG, "set ZKIT_TEST_OPTIMIZER_PATCH_CLANG to an official clang release "
                                                "folder the no-ctor-evaluation rule has a patch for")
    def test_no_ctor_evaluation_keeps_the_static_initializer(self):
        with tempfile.TemporaryDirectory() as temp:
            clang = Path(temp) / "bin" / "clang++"
            clang.parent.mkdir()
            shutil.copyfile(Path(OPTIMIZER_PATCH_CLANG) / "bin" / "clang++", clang)
            shutil.copymode(Path(OPTIMIZER_PATCH_CLANG) / "bin" / "clang++", clang)
            source = Path(temp) / "init.cpp"
            source.write_text(STATIC_INIT, encoding="utf-8")
            copy = build.patched_clang(clang, [], ["no-ctor-evaluation"], "build.optimizer_patches")
            self.assertIsNotNone(copy, "no patch for this clang++")

            def ir(cc: Path) -> str:
                return subprocess.run([str(cc), "--target=aarch64-none-elf", "-O2", "-S", "-emit-llvm",
                                       str(source), "-o", "-"], check=True, capture_output=True, text=True).stdout
            stock, patched = ir(clang), ir(copy)
            self.assertIn("global %struct.Counter { i32 7 }", stock)   # evaluated: the store folded
            self.assertNotIn("_GLOBAL__sub_I_", stock)
            self.assertIn("_GLOBAL__sub_I_", patched)   # kept: the store stays code
            self.assertIn("store i32 7", patched)


if __name__ == "__main__":
    unittest.main()
