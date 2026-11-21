import support  # noqa: F401  (isolates config, cache and state)
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
from test_delink import CLANG, FLAGS, LLD  # noqa: E402
from test_structure import build_dol  # noqa: E402
from zkit import build, candidate, health, new, objects  # noqa: E402
from zkit.project import Project  # noqa: E402

NINJA, OBJDIFF = shutil.which("ninja"), shutil.which("objdiff-cli")
SYMBOLS = ("update__6TEnemyFv = .text:0x80003000; // type:function size:0x10\n"
           "TPlayer__sub_80003010 = .text:0x80003010; // type:function size:0x10\n"
           "fn_80003020 = .text:0x80003020; // type:function size:0x10\n"
           "__vt__6TEnemy = .data:0x80003100; // type:object size:0x8\n"
           "__vt__7TPlayer = .data:0x80003108; // type:object size:0x4\n"
           "lbl_80003200 = .sdata2:0x80003200; // type:object size:0x4\n")
SPLITS = ("Sections:\n\t.text type:code\n\ngame/Enemy.cpp:\n\t.text start:0x80003000 end:0x80003010\n"
          "\t.data start:0x80003100 end:0x80003108\n\ngame/Player.cpp:\n\t.text start:0x80003010 end:0x80003030\n"
          "\t.data start:0x80003108 end:0x8000310C\n\t.sdata2 start:0x80003200 end:0x80003204\n")
# A stand-in for `zkit link` until the relinker is merged: it "relinks" by copying the original (or a corrupted
# copy), and hands every other command to the real CLI.
STAND_IN = """import os, shutil, sys
from pathlib import Path
from zkit.cli import main
argv = sys.argv[1:]
if "link" in argv:
    out = Path(argv[argv.index("--out") + 1])
    out.mkdir(parents=True, exist_ok=True)
    data = bytearray(Path(os.environ["STAND_IN_ORIGINAL"]).read_bytes())
    if os.environ.get("STAND_IN_CORRUPT"):
        data[-1] ^= 1
    (out / "main.dol").write_bytes(bytes(data))
    sys.exit(0)
sys.exit(main(argv))
"""


def gamecube_project(root: Path, sources: bool = True, **settings) -> Path:
    """A GameCube repository (hand-assembled DOL, two units) with stand-in compiler files; its project file."""
    game = root / "game"
    (game / "config").mkdir(parents=True)
    (game / "orig").mkdir()
    (game / "orig/main.dol").write_bytes(build_dol())
    (game / "config/symbols.txt").write_text(SYMBOLS, encoding="utf-8")
    (game / "config/splits.txt").write_text(SPLITS, encoding="utf-8")
    for version in ("GC/2.6", "GC/1.2.5n"):
        (game / "build/compilers" / version).mkdir(parents=True)
        for tool in ("mwcceppc.exe", "mwldeppc.exe"):
            (game / "build/compilers" / version / tool).write_bytes(b"")
    (game / "tools").mkdir()
    (game / "tools/wibo").write_bytes(b"")
    if sources:
        (game / "src/game").mkdir(parents=True)
        (game / "src/game/Enemy.cpp").write_text("void update() {}\n", encoding="utf-8")
    target = {"repository": "decomp", "platform": "gamecube", "module": "main", "original": "orig/main.dol",
              "sha1": hashlib.sha1(build_dol()).hexdigest(), "symbols": "config/symbols.txt",
              "splits": "config/splits.txt", "report": "build/T/report.json",
              "build": {"compiler": "GC/2.6", "wrapper": "tools/wibo", "cflags": "-O4,p -inline auto",
                        "includes": ["include"], "objdiff_cli": "tools/none", **settings}}
    manifest = root / "project.json"
    manifest.write_text(json.dumps({"schema_version": 1, "id": "build-test",
                                    "repositories": {"decomp": {"root": "game", "role": "decomp"}},
                                    "targets": {"t": target}}), encoding="utf-8")
    return manifest


class SettingsTests(unittest.TestCase):
    def test_defaults_patterns_and_extra_flags(self):
        self.assertIsNone(build.settings({"platform": "gamecube"}))
        config = build.settings({"platform": "gamecube", "build": {
            "compiler": "GC/2.6", "cflags": ["-proc gekko", "-O4,p"],
            "units": {"game/*": {"compiler": "GC/1.2.5n", "extra_cflags": "-DGAME"},
                      "game/Enemy.cpp": {"extra_cflags": ["-O4,s"]}}}})
        self.assertEqual(config["wrapper"], "wibo")                       # a platform default
        self.assertEqual(build.words(config["cflags"]), ["-proc", "gekko", "-O4,p"])
        enemy, player, other = (build.unit_settings(config, u) for u in ("game/Enemy.cpp", "game/Player.cpp", "x.c"))
        self.assertEqual((enemy["compiler"], enemy["extra_cflags"]), ("GC/1.2.5n", ["-DGAME", "-O4,s"]))
        self.assertEqual((player["compiler"], player["extra_cflags"]), ("GC/1.2.5n", ["-DGAME"]))
        self.assertEqual((other["compiler"], other["extra_cflags"]), ("GC/2.6", []))
        self.assertEqual(build.settings({"platform": "switch", "build": {}})["compiler"], "clang++")
        with self.assertRaisesRegex(ValueError, "unknown setting"):
            build.settings({"build": {"units": {"*": {"cflag": "-O2"}}}})

    def test_a_library_built_elsewhere_has_its_own_source_root(self):
        """A library the game linked prebuilt cites the folder it was built in, not the game's: a `units` pattern
        gives its units their own `source_root`, and each compiles from a copy that names it `<its root>/<unit>`,
        with its own folder searched for quoted includes; a unit without the setting compiles src/ itself."""
        config = build.settings({"platform": "switch", "build": {
            "compiler": "clang++", "source_root": "D:/game/prog",
            "units": {"libs/mm/*": {"source_root": "C:/Lib/prog"}}}})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            paths, notes = build.layout("t", {}), []
            game, library = (build._compile(root, build.unit_settings(config, unit), unit, paths, {}, notes)
                             for unit in ("app/main.cpp", "libs/mm/thread.cpp"))
            self.assertEqual(game["stage"], {"source": "src/app/main.cpp", "named": "D:/game/prog/app/main.cpp",
                                             "copy": "build/t/rooted/app/main.cpp"})
            self.assertEqual(library["stage"]["named"], "C:/Lib/prog/libs/mm/thread.cpp")
            self.assertIn("-iquote src/app", " ".join(game["flags"]))
            self.assertEqual(game["argv"][-4:], ["-c", "src/app/main.cpp", "-o", "build/t/src/app/main.o"])
            bare = build.settings({"platform": "switch", "build": {"compiler": "clang++"}})
            plain = build._compile(root, build.unit_settings(bare, "app/main.cpp"), "app/main.cpp", paths, {}, notes)
            self.assertNotIn("stage", plain)
            self.assertNotIn("-iquote", plain["flags"])

    def test_the_compiler_must_say_an_accepted_version(self):
        """`compiler_version` is a string `clang --version` must contain, or a list of them (hosts whose own
        release of the compiler differs but compiles alike)."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "clang++").write_text("")
            for accepted, says, ok in (("clang version 3.9.1", "clang version 3.9.1 (tags/RELEASE_391/final)", True),
                                       ("clang version 3.9.1", "clang version 3.9.0 (tags/RELEASE_390/final)", False),
                                       (["clang version 3.9.1", "clang version 3.9.0"], "clang version 3.9.0", True),
                                       (["clang version 3.9.1", "clang version 3.9.0"], "clang version 4.0.1", False)):
                config = build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++"),
                                                                          "compiler_version": accepted}})
                unit = build.unit_settings(config, "a.cpp")
                with self.subTest(accepted=accepted, says=says), \
                        mock.patch.object(build, "clang_version", return_value=says):
                    if ok:
                        build._compile(root, unit, "a.cpp", build.layout("t", {}), {}, [])
                    else:
                        with self.assertRaisesRegex(ValueError, "it says 'clang version"):
                            build._compile(root, unit, "a.cpp", build.layout("t", {}), {}, [])

    def test_a_staged_copy_names_the_original_and_keeps_its_lines(self):
        """The copy's `#line` comes first, after a byte-order mark if there is one; every line keeps its number."""
        self.assertEqual(build.stage(b"int a;\n", "D:/p/a.cpp"), b'#line 1 "D:/p/a.cpp"\nint a;\n')
        self.assertEqual(build.stage(b"\xef\xbb\xbfint a;", 'C:\\x"y.cpp'),
                         b'\xef\xbb\xbf#line 1 "C:\\\\x\\"y.cpp"\nint a;')
        with tempfile.TemporaryDirectory() as temp:
            source, copy = Path(temp) / "a.cpp", Path(temp) / "out/a.cpp"
            source.write_bytes(b"int a;\n")
            rows = [{"source": str(source), "named": "D:/p/a.cpp", "copy": str(copy)}]
            self.assertEqual(build.write_staged(rows), 1)
            self.assertEqual(build.write_staged(rows), 0)                 # unchanged: left as it is

    def test_layout(self):
        self.assertEqual(build.layout("t", {"report": "build/GAME01/report.json"}).obj, "build/GAME01/obj")
        self.assertEqual(build.layout("t", {"build": {"dir": "out/x/"}}).src, "out/x/src")
        self.assertEqual(build.layout("t", {}).report, "build/t/report.json")


class NinjaCommandTests(unittest.TestCase):
    def test_objdiff_runs_the_ninja_installed_with_zkit_by_its_path(self):
        scripts = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")
        with mock.patch.object(sys, "base_prefix", "/somewhere/else"):
            with mock.patch.object(build.shutil, "which", return_value=str(scripts / "ninja")):
                self.assertEqual(build.ninja_command(), str((scripts / "ninja").resolve()))
            with mock.patch.object(build.shutil, "which", return_value="/usr/bin/ninja"):
                self.assertEqual(build.ninja_command(), "ninja")
            with mock.patch.object(build.shutil, "which", return_value=None):
                self.assertEqual(build.ninja_command(), "ninja")
        with mock.patch.object(sys, "base_prefix", sys.prefix), \
                mock.patch.object(build.shutil, "which", return_value=str(scripts / "ninja")):
            self.assertEqual(build.ninja_command(), "ninja")  # not a virtual environment: PATH finds it


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def configure(self, link: bool = False, **settings) -> dict:
        self.manifest = gamecube_project(self.root, **settings)
        self.game = self.root / "game"
        with mock.patch.object(build, "has_link", return_value=link):
            return build.configure(Project.load(self.manifest))

    def test_categories_become_objdiff_progress_categories(self):
        manifest = gamecube_project(self.root)
        data = json.loads(manifest.read_text())
        data["targets"]["t"]["categories"] = [{"id": "enemy", "name": "Enemies", "paths": ["game/Enemy.cpp"]},
                                              {"id": "game", "paths": ["game/"]}, {"id": "none", "paths": ["x/*"]}]
        manifest.write_text(json.dumps(data))
        with mock.patch.object(build, "has_link", return_value=False):
            result = build.configure(Project.load(manifest))
        config = json.loads((self.root / "game/objdiff.json").read_text())
        self.assertEqual(config["progress_categories"], [{"id": "enemy", "name": "Enemies"},
                                                         {"id": "game", "name": "game"}, {"id": "none", "name": "none"}])
        self.assertEqual([(u["name"], u["metadata"]["progress_categories"]) for u in config["units"]],
                         [("game/Enemy", ["enemy", "game"]), ("game/Player", ["game"])])
        self.assertFalse(any("in no category" in n for n in result["targets"]["t"]["notes"]))
        data["targets"]["t"]["categories"] = [{"id": "enemy", "paths": ["game/Enemy.cpp"]}]
        manifest.write_text(json.dumps(data))
        with mock.patch.object(build, "has_link", return_value=False):
            result = build.configure(Project.load(manifest))
        self.assertIn("1 units in no category (first: game/Player.cpp)", result["targets"]["t"]["notes"])

    def test_ninja_file_objdiff_and_compile_commands(self):
        result = self.configure(units={"game/*": {"compiler": "GC/1.2.5n", "extra_cflags": "-DGAME"},
                                       "game/Enemy.cpp": {"extra_cflags": ["-O4,s"]}})
        row = result["targets"]["t"]
        self.assertEqual((row["units"], row["objects"], row["compiled"], row["report"], row["link"]),
                         (2, 2, 1, None, False))
        self.assertTrue(any("objdiff-cli not found" in n for n in row["notes"]))
        self.assertTrue(any("no `zkit link`" in n for n in row["notes"]))
        text = (self.game / "build/build.ninja").read_text()
        self.assertIn("build build/T/original.sha1: sha1 orig/main.dol", text)
        self.assertIn("build build/T/obj/game/Enemy.o | build/T/obj/game/Player.o: delink config/splits.txt", text)
        self.assertIn("build build/T/src/game/Enemy.o: mwcc src/game/Enemy.cpp | tools/wibo $\n"
                      "    build/compilers/GC/1.2.5n/mwcceppc.exe", text)
        self.assertNotIn("src/game/Player.o", text)
        self.assertIn("default objects compile", text)
        units = json.loads((self.game / "objdiff.json").read_text())["units"]
        self.assertEqual([(u["name"], u.get("base_path")) for u in units],
                         [("game/Enemy", "build/T/src/game/Enemy.o"), ("game/Player", None)])
        from zkit.progress import module_of        # the module it links into, not the unit's folder
        self.assertEqual({module_of(u) for u in units}, {"main"})
        argv = ["tools/wibo", "build/compilers/GC/1.2.5n/mwcceppc.exe", "-O4,p", "-inline", "auto", "-i", "include",
                "-DGAME", "-O4,s", "-c", "src/game/Enemy.cpp", "-o", "build/T/src/game"]
        self.assertEqual(json.loads((self.game / "build/compile_commands.json").read_text())[0]["arguments"], argv)
        # `zkit try` compiles candidates with exactly this command
        found, workdir, source = candidate.compile_command(Project.load(self.manifest), "t", units[0])
        self.assertEqual((found, workdir, source), (argv, self.game, "src/game/Enemy.cpp"))
        # another target built last from the same source: its command builds its own object, not this one
        database = self.game / "build/compile_commands.json"
        entries = json.loads(database.read_text())
        entries[0].update(arguments=["other-compiler", "-c", "src/game/Enemy.cpp"], output="build/U/src/game/Enemy.o")
        database.write_text(json.dumps(entries))
        found, workdir, source = candidate.compile_command(Project.load(self.manifest), "t", units[0])
        self.assertEqual((found, workdir, source), (argv, self.game, "src/game/Enemy.cpp"))
        # a unit with no source file yet compiles as the build will compile it once it has one
        found, workdir, source = candidate.compile_command(Project.load(self.manifest), "t", units[1])
        self.assertEqual((found, workdir, source), (
            ["tools/wibo", "build/compilers/GC/1.2.5n/mwcceppc.exe", "-O4,p", "-inline", "auto", "-i", "include",
             "-DGAME", "-c", "src/game/Player.cpp", "-o", "build/T/src/game"], self.game, "src/game/Player.cpp"))

    def test_report_and_link_steps(self):
        (self.root / "objdiff-cli").write_bytes(b"")
        result = self.configure(link=True, objdiff_cli=str(self.root / "objdiff-cli"), ldflags="-fp hardware")
        row = result["targets"]["t"]
        self.assertEqual((row["report"], row["link"]), ("build/T/report.json", True))
        text = (self.game / "build/build.ninja").read_text()
        self.assertIn("build build/T/report.json: report | objdiff.json build/T/obj/game/Enemy.o", text.replace(
            " $\n    ", " "))
        # the linker as zkit link reads it: rule `link`, the edge writing <module>.elf
        self.assertIn("rule link\n  command = tools/wibo build/compilers/GC/2.6/mwldeppc.exe $ldflags -o $out "
                      "@$out.rsp", text)
        self.assertIn("build build/T/link/main.elf: link\n  ldflags = -fp hardware", text)
        self.assertIn("--target $target link --out $outdir --build build/build.ninja", text)
        self.assertIn("build build/T/ok: sha1 build/T/link/main.dol", text)
        self.assertIn("default build/T/ok build/progress/index.html", text)
        # every build leaves the browsable page of its reports
        self.assertIn("build build/progress/index.html build/progress/treemap.html: page | build/T/report.json",
                      text.replace(" $\n    ", " "))
        self.assertIn(" report --out build/progress --targets t\n", text)

    def test_no_link_without_the_linker(self):
        self.manifest = gamecube_project(self.root, linker="GC/9.9")
        with mock.patch.object(build, "has_link", return_value=True):
            row = build.configure(Project.load(self.manifest))["targets"]["t"]
        self.assertFalse(row["link"])
        self.assertTrue(any("mwldeppc.exe not found" in n for n in row["notes"]))

    def test_needs_build_settings(self):
        manifest = gamecube_project(self.root)
        data = json.loads(manifest.read_text())
        del data["targets"]["t"]["build"]
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "build"):
            build.configure(Project.load(manifest))


@unittest.skipUnless(NINJA, "needs ninja")
class NinjaRunTests(unittest.TestCase):
    """The generated file under real ninja: delink with the real zkit, link with the stand-in, check the hash."""

    def test_build_delinks_links_and_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = gamecube_project(root, sources=False)
            stand_in = root / "stand_in.py"
            stand_in.write_text(STAND_IN, encoding="utf-8")
            game = root / "game"
            project = Project.load(manifest)
            zkit = [sys.executable, str(stand_in), "--project", str(manifest)]
            with mock.patch.object(build, "has_link", return_value=True):
                build.configure(project, zkit=zkit)
            environment = {"STAND_IN_ORIGINAL": str(game / "orig/main.dol")}
            with mock.patch.dict(os.environ, environment):
                self.assertEqual(build.run_ninja(game, [], quiet=True), 0)
                self.assertTrue((game / "build/T/obj/game/Player.o").is_file())
                self.assertEqual((game / "build/T/ok").read_text().strip(), hashlib.sha1(build_dol()).hexdigest())
                (game / "build/T/link/main.dol").unlink()
                with mock.patch.dict(os.environ, {"STAND_IN_CORRUPT": "1"}):
                    self.assertEqual(build.run_ninja(game, [], quiet=True), 1)
                self.assertFalse((game / "build/T/ok").exists())


class ToolTests(unittest.TestCase):
    def test_depfile_from_wibo_and_sha1_check(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Enemy.d"
            path.write_text("Enemy.o: src\\game\\Enemy.cpp \\\n\tZ:\\work\\game\\include\\types.h \\\n"
                            "\tinclude\\game\\Enemy.h\n", encoding="utf-8")
            build.fix_depfile(path, "build/T/src/game/Enemy.o")
            self.assertEqual(path.read_text(), "build/T/src/game/Enemy.o: src/game/Enemy.cpp \\\n"
                                               "  /work/game/include/types.h \\\n  include/game/Enemy.h\n")
            stamp = Path(temp) / "ok"
            self.assertEqual(build.check_sha1(path, hashlib.sha1(path.read_bytes()).hexdigest(), stamp), 0)
            self.assertTrue(stamp.is_file())
            self.assertEqual(build.check_sha1(path, "0" * 40, stamp), 1)
            self.assertFalse(stamp.exists())

    def test_download_refuses_a_bundle_with_another_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                archive.writestr("GC/2.6/mwcceppc.exe", b"MZ")
            (root / "bundle.zip").write_bytes(data.getvalue())
            url = (root / "bundle.zip").as_uri()
            with self.assertRaisesRegex(ValueError, "refusing"):
                build.download_compilers(root / "compilers", url, "0" * 64)
            self.assertFalse((root / "compilers/GC").exists())
            result = build.download_compilers(root / "compilers", url, hashlib.sha256(data.getvalue()).hexdigest())
            self.assertEqual(result["files"], 1)
            self.assertEqual((root / "compilers/GC/2.6/mwcceppc.exe").read_bytes(), b"MZ")
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["bundle.zip", "compilers"])


class NewProjectTests(unittest.TestCase):
    def test_new_gamecube_project_is_ready_to_build(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.dol").write_bytes(build_dol())
            result = new.new(root / "main.dol", root / "game", game_id="TEST01")
            game = root / "game"
            target = json.loads(Path(result["manifest"]).read_text())["targets"]["test01"]
            self.assertEqual(target["sha1"], hashlib.sha1(build_dol()).hexdigest())
            self.assertEqual(target["build"], build.DEFAULTS["gamecube"])
            self.assertIn("zkit build", (game / "README.md").read_text())
            self.assertIn("objdiff.json", (game / ".gitignore").read_text())
            self.assertIn("check --staged", (game / ".git/hooks/pre-commit").read_text())
            self.assertIn("commit-msg", (game / ".git/hooks/commit-msg").read_text())
            self.assertTrue((game / "build/build.ninja").is_file())
            self.assertTrue((game / "src").is_dir())
            rows = {r["check"]: r for r in health.doctor(Project.load(result["manifest"]))["checks"]}
            self.assertIn("SHA-1 matches", rows["test01: original executable"]["detail"])
            (game / "orig/TEST01/sys/main.dol").write_bytes(build_dol() + b"\0")
            rows = {r["check"]: r for r in health.doctor(Project.load(result["manifest"]))["checks"]}
            self.assertEqual(rows["test01: original executable"]["status"], "fail")


A_CPP = """extern int g_counter;
int helper(int x);
int scaled(int v) { return v * 3 + g_counter; }
const char *greeting() { return "hello from a"; }
int both(int v) { return helper(v) + scaled(v); }
"""
B_CPP = """int g_counter = 3;
static int table[4] = {1, 2, 3, 4};
static int twice(int v) { return v * 2; }
int helper(int x) { return twice(x) + table[x & 3] + g_counter; }
"""


@unittest.skipUnless(CLANG and LLD and NINJA, "needs clang++, ld.lld and ninja")
class SwitchBuildTests(unittest.TestCase):
    """A module linked from two units, started with `zkit new`, split by hand, then built from the same
    sources: every function of both units must equal its target object."""

    def test_new_project_builds_and_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in (("a.cpp", A_CPP), ("b.cpp", B_CPP)):
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            self.assertEqual(build.run_ninja(game, [], quiet=True), 0)  # no sources: target objects only
            from zkit.elf import Elf
            linked = Elf.load(game / "orig/test/main.elf")
            at = {s.name: s.value for s in linked.symbols if s.name}
            rodata = linked.section(".rodata").address
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
                f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + 13:#x}\n\n"
                f"b.cpp:\n\t.text start:{at['_Z6helperi']:#x} end:{at['_Z6helperi'] + 36:#x}\n"
                f"\t.rodata.cst16 start:{at['_ZL5table']:#x} end:{at['_ZL5table'] + 16:#x}\n"
                f"\t.data start:{at['g_counter']:#x} end:{at['g_counter'] + 4:#x}\n", encoding="utf-8")
            (game / "src/a.cpp").write_text(A_CPP, encoding="utf-8")
            (game / "src/b.cpp").write_text(B_CPP, encoding="utf-8")
            data = json.loads(manifest.read_text())
            data["targets"]["test"]["build"].update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])
            manifest.write_text(json.dumps(data), encoding="utf-8")
            built = build.build(Project.load(manifest), quiet=True)
            self.assertTrue(built["ok"])
            self.assertEqual(built["targets"]["test"]["compiled"], 2)
            for unit in ("a", "b"):
                diff = objects.unit_diff(game / f"build/test/obj/{unit}.o", game / f"build/test/src/{unit}.o")
                self.assertEqual((diff["exact"], diff["compiled_only"]), (diff["total"], []), unit)
                self.assertGreater(diff["total"], 0)
            if OBJDIFF:
                measures = json.loads((game / "build/test/report.json").read_text())["measures"]
                self.assertEqual(measures["matched_code"], measures["total_code"])

    def test_a_weak_copy_another_unit_owns_is_not_this_unit_s_data(self):
        """Both units call an inline function with a static; the link kept a.cpp's copy (its COMDAT group came
        first), so b.cpp's original .bss holds only its own table while its compiled object also defines the weak
        copy. The report compares b's view, where that copy is a reference to a's (as the link resolves it), so
        b's .bss scores exact; a's view keeps the copy it owns; a wrong size in b's own data still fails."""
        from zkit.elf import Elf
        a_cpp = "inline int *slot() { static int s; return &s; }\nint a_counter;\n" \
                "int use_a() { return ++*slot() + a_counter; }\n"
        b_cpp = "inline int *slot() { static int s; return &s; }\nstatic int b_table[%d];\n" \
                "int use_b(int i) { b_table[i & 3] += *slot(); return b_table[i & 3]; }\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in (("a.cpp", a_cpp), ("b.cpp", b_cpp % 4)):
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            at = {s.name: (s.value, s.size) for s in Elf.load(game / "orig/test/main.elf").symbols if s.name}
            (a_start, _), (b_start, b_size) = at["_Z5use_av"], at["_Z5use_bi"]
            (static, _), (counter, _), (table, _) = at["_ZZ4slotvE1s"], at["a_counter"], at["_ZL7b_table"]
            self.assertEqual(sorted([static, counter]), [min(static, counter), table - 4])  # a's .bss, then b's
            symbols = game / "config/test/symbols.txt"   # b's table unnamed: objdiff pairs it by place, not name
            symbols.write_text(symbols.read_text().replace("_ZL7b_table =", f"lbl_{table:X} ="), encoding="utf-8")
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{a_start:#x} end:{b_start:#x}\n"
                f"\t.bss start:{min(static, counter):#x} end:{table:#x}\n\n"
                f"b.cpp:\n\t.text start:{b_start:#x} end:{b_start + b_size:#x}\n"
                f"\t.bss start:{table:#x} end:{table + 16:#x}\n", encoding="utf-8")
            (game / "src/a.cpp").write_text(a_cpp, encoding="utf-8")
            (game / "src/b.cpp").write_text(b_cpp % 4, encoding="utf-8")
            data = json.loads(manifest.read_text())
            data["targets"]["test"]["build"].update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])
            data["targets"]["test"]["build"]["objdiff_cli"] = OBJDIFF or str(root / "objdiff-cli")  # views: either
            manifest.write_text(json.dumps(data), encoding="utf-8")
            if OBJDIFF:
                self.assertTrue(build.build(Project.load(manifest), quiet=True)["ok"])
            else:   # a stand-in tool: the views are built, never its report
                (root / "objdiff-cli").write_text("", encoding="utf-8")
                build.configure(Project.load(manifest))
                self.assertEqual(build.run_ninja(game, ["build/test/view/a.o"], quiet=True), 0)
            defined = lambda path: {s.name for s in Elf.load(path).symbols if 0 < s.section < 0xFF00}
            self.assertIn("_ZZ4slotvE1s", defined(game / "build/test/src/b.o"))      # the compiled object: as built
            self.assertNotIn("_ZZ4slotvE1s", defined(game / "build/test/view/b.o"))  # the report's: a's copy
            self.assertIn("_ZZ4slotvE1s", defined(game / "build/test/view/a.o"))     # its owner's view keeps it
            self.assertEqual(Elf.load(game / "build/test/view/a.o").raw,
                             Elf.load(game / "build/test/src/a.o").raw)
            project = json.loads((game / "build/test/view/objdiff.json").read_text())
            self.assertEqual({u["name"]: u["base_path"] for u in project["units"]},
                             {"a": "a.o", "b": "b.o"})
            self.assertTrue(json.loads((game / "objdiff.json").read_text())["units"][1]["base_path"]
                            .endswith("build/test/src/b.o"))                         # every other reader's
            if not OBJDIFF:
                return

            def bss(unit):
                report = json.loads((game / "build/test/report.json").read_text())
                row = next(u for u in report["units"] if u["name"] == unit)
                return next(s for s in row["sections"] if s["name"] == ".bss").get("fuzzy_match_percent", 0)
            self.assertEqual((bss("a"), bss("b")), (100, 100))
            (game / "src/b.cpp").write_text(b_cpp % 5, encoding="utf-8")
            build.build(Project.load(manifest), quiet=True)
            self.assertLess(bss("b"), 100)

    def test_link_rebuilds_the_module_and_marks_the_units_it_proves(self):
        """`zkit link` on Switch: both units' objects placed where the original holds them, every relocation
        resolved as the module's linker did (calls, a string literal, a merged constant, a GOT load), the module
        identical; the report then marks both linked. A function the original lacks and nothing calls (one its
        linker's --gc-sections dropped) is left out, and the unit still links. A unit whose data differs from the
        original's is caught even when the report calls its code matched."""
        from zkit import nxlink
        from zkit.elf import Elf
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in (("a.cpp", A_CPP), ("b.cpp", B_CPP)):
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            linked = Elf.load(game / "orig/test/main.elf")
            at = {s.name: s.value for s in linked.symbols if s.name}
            rodata = linked.section(".rodata").address
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
                f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + 13:#x}\n\n"
                f"b.cpp:\n\t.text start:{at['_Z6helperi']:#x} end:{at['_Z6helperi'] + 36:#x}\n"
                f"\t.rodata.cst16 start:{at['_ZL5table']:#x} end:{at['_ZL5table'] + 16:#x}\n"
                f"\t.data start:{at['g_counter']:#x} end:{at['g_counter'] + 4:#x}\n", encoding="utf-8")
            data = json.loads(manifest.read_text())
            data["targets"]["test"]["build"].update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])
            manifest.write_text(json.dumps(data), encoding="utf-8")
            report = game / "build/test/report.json"

            def built(b_cpp: str, identical: bool = True) -> dict:
                (game / "src/a.cpp").write_text(A_CPP, encoding="utf-8")
                (game / "src/b.cpp").write_text(b_cpp, encoding="utf-8")
                # with objdiff-cli the build links too, and a link that is not identical fails it
                self.assertEqual(build.build(Project.load(manifest), quiet=True)["ok"], identical or not OBJDIFF)
                units = []
                for unit in ("a", "b"):   # what objdiff would say: every function exact
                    functions = [{"name": s.name, "size": str(s.size), "fuzzy_match_percent": 100.0,
                                  "metadata": {"virtual_address": str(at[s.name])}}
                                 for s in Elf.load(game / f"build/test/src/{unit}.o").symbols
                                 if s.kind == "func" and s.name in at]
                    size = sum(int(f["size"]) for f in functions)
                    units.append({"name": unit, "functions": functions, "sections": [{"name": ".data", "size": "4"}],
                                  "measures": {"total_code": str(size), "matched_code": str(size),
                                               "total_data": "4"}, "metadata": {"source_path": f"src/{unit}.cpp"}})
                report.write_text(json.dumps({"units": units, "measures": {}}), encoding="utf-8")
                return nxlink.link(Project.load(manifest), "test", game / "build/test/link")

            good = built(B_CPP)
            self.assertTrue(good["identical"], good)
            self.assertEqual(good["linked_units"], ["a.cpp", "b.cpp"], good["not_linked"])
            self.assertTrue(all(s["matches_header"] is None for s in good["segments"]))   # an ELF: no hashes
            marked = json.loads(report.read_text())
            self.assertEqual([u["metadata"].get("complete") for u in marked["units"]], [True, True])
            self.assertEqual(marked["measures"]["complete_units"], 2)
            self.assertEqual(marked["units"][1]["measures"]["matched_data"], "4")
            self.assertEqual(good["collected"], 0)
            one = nxlink.link_unit(Project.load(manifest), "test", "b.cpp", game / "build/test/src/b.o")
            self.assertTrue(one["linked"], one)                     # one unit's object, alone, into the original

            def candidate(text: str) -> dict:
                (root / "candidate.cpp").write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / "candidate.cpp"), "-o", str(root / "candidate.o")],
                               check=True, capture_output=True)
                return nxlink.link_unit(Project.load(manifest), "test", "b.cpp", root / "candidate.o")

            # a function the original lacks, reached only from a table the original lacks too: both dropped, also
            # while the unit misses a byte (g_counter left to another file)
            extra = ('__attribute__((section(".text.extra"))) static int extra(int v) { return v * 5; }\n'
                     '__attribute__((section(".data.hook"))) int (*g_hook)(int) = extra;\n')
            unreached = candidate(B_CPP + extra)
            self.assertTrue(unreached["linked"], unreached)
            self.assertEqual(sorted(unreached["collected"]), ["_ZL5extrai", "g_hook"])
            missing = candidate(B_CPP.replace("int g_counter = 3;", "extern int g_counter;") + extra)
            self.assertFalse(missing["linked"])
            self.assertTrue(missing["gaps"], missing)
            self.assertFalse(any("no such function" in p for p in missing["problems"]), missing["problems"])
            self.assertEqual(len(missing["collected"]), 2)
            # one placed code calls has no counterpart in the original: refused
            called = candidate(B_CPP.replace("static int twice", "__attribute__((noinline)) " + extra.split("\n")[0]
                                             + "\nstatic int twice").replace("twice(x) +", "twice(x) + extra(x) +"))
            self.assertFalse(called["linked"])
            self.assertTrue(any("_ZL5extrai" in p and "reaches it" in p for p in called["problems"]),
                            called["problems"])
            self.assertEqual(called["collected"], [])
            dropped = built(B_CPP + '__attribute__((section(".text.unused"))) int unused(int v) { return v - 1; }\n')
            self.assertTrue(dropped["identical"], dropped)
            self.assertEqual((dropped["linked_units"], dropped["collected"]), (["a.cpp", "b.cpp"], 1))
            bad = built(B_CPP.replace("g_counter = 3", "g_counter = 4"), identical=False)
            self.assertFalse(bad["identical"])
            self.assertEqual(bad["linked_units"], [])
            self.assertTrue(any("differs" in p for p in bad["problems"]), bad["problems"])
            alone = nxlink.link_unit(Project.load(manifest), "test", "b.cpp", game / "build/test/src/b.o")
            self.assertFalse(alone["linked"])
            self.assertIn("first_difference", alone)
            self.assertFalse(any(u["metadata"].get("complete") for u in json.loads(report.read_text())["units"]))

    def test_a_relaxing_link_matches_and_links(self):
        """A module whose linker relaxed address pairs (lld without --no-relax): the GOT load of a symbol the
        module defines became adrp+add, and every adrp+add of a near symbol became nop+adr; the GOT load of an
        import stayed. With `build.relax` the compiled units equal their target objects function by function,
        the report agrees, and the link rebuilds the module byte for byte; without it the diff sees the
        relaxed loads as differences."""
        from zkit import nxlink
        from zkit.elf import Elf
        # scaled's GOT load of g_counter is parted by the scheduler, so lld keeps .text's every GOT load of it; in
        # a section of its own an adjacent pair is relaxed twice, to adrp + add, then to nop + adr
        a_cpp = A_CPP + ('__attribute__((section(".text.where"))) int *where() { return &g_counter; }\n'
                         "extern int g_imported;\nint imported() { return g_imported; }\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in (("a.cpp", a_cpp), ("b.cpp", B_CPP)):
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--unresolved-symbols=ignore-all", "-o", str(root / "main.elf"),
                            str(root / "a.o"), str(root / "b.o")], check=True, capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            linked = Elf.load(game / "orig/test/main.elf")
            at = {s.name: s.value for s in linked.symbols if s.name}
            code = linked.data(linked.section(".text"))
            words = [int.from_bytes(code[i:i + 4], "little") for i in range(0, len(code), 4)]
            relaxed = [i for i in range(1, len(words)) if words[i - 1] == 0xD503201F and words[i] & 0x9F000000
                       == 0x10000000]
            self.assertEqual(len(relaxed), 3, "lld relaxed where's g_counter, the string and the table")
            base = linked.section(".text").address
            for name in ("_Z6scaledi", "_Z4bothi", "_Z8importedv"):   # GOT loads kept: an adrp, its ldr later
                self.assertTrue(any(words[(at[name] - base) // 4 + i] & 0x9F000000 == 0x90000000 for i in range(6)),
                                name)
            rodata = linked.section(".rodata").address
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
                f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + 13:#x}\n\n"
                f"b.cpp:\n\t.text start:{at['_Z6helperi']:#x} end:{at['_Z6helperi'] + 36:#x}\n"
                f"\t.rodata.cst16 start:{at['_ZL5table']:#x} end:{at['_ZL5table'] + 16:#x}\n"
                f"\t.data start:{at['g_counter']:#x} end:{at['g_counter'] + 4:#x}\n", encoding="utf-8")
            (game / "src/a.cpp").write_text(a_cpp, encoding="utf-8")
            (game / "src/b.cpp").write_text(B_CPP, encoding="utf-8")
            data = json.loads(manifest.read_text())
            data["targets"]["test"]["build"].update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])

            def diffs(relax: bool) -> dict:
                data["targets"]["test"]["build"]["relax"] = relax
                manifest.write_text(json.dumps(data), encoding="utf-8")
                project = Project.load(manifest)
                build.build(project, quiet=True)
                imports = objects.relaxed_imports(project, "test")
                self.assertEqual(imports, {"g_imported"} if relax else None)
                return {unit: objects.unit_diff(game / f"build/test/obj/{unit}.o", game / f"build/test/src/{unit}.o",
                                                imports=imports) for unit in ("a", "b")}

            plain = diffs(False)
            self.assertLess(plain["a"]["exact"], plain["a"]["total"], "relaxed loads differ without build.relax")
            for unit, diff in diffs(True).items():
                self.assertEqual((diff["exact"], diff["compiled_only"]), (diff["total"], []), (unit, diff))
            self.assertEqual((game / "build/test/obj/imports.txt").read_text().split(), ["g_imported"])
            report = game / "build/test/report.json"
            if OBJDIFF:
                measures = json.loads(report.read_text())["measures"]
                self.assertEqual(measures["matched_code"], measures["total_code"])
            units = []
            for unit in ("a", "b"):
                functions = [{"name": s.name, "size": str(s.size), "fuzzy_match_percent": 100.0,
                              "metadata": {"virtual_address": str(at[s.name])}}
                             for s in Elf.load(game / f"build/test/src/{unit}.o").symbols
                             if s.kind == "func" and s.name in at]
                size = sum(int(f["size"]) for f in functions)
                units.append({"name": unit, "functions": functions, "sections": [{"name": ".data", "size": "4"}],
                              "measures": {"total_code": str(size), "matched_code": str(size), "total_data": "4"},
                              "metadata": {"source_path": f"src/{unit}.cpp"}})
            report.write_text(json.dumps({"units": units, "measures": {}}), encoding="utf-8")
            done = nxlink.link(Project.load(manifest), "test", game / "build/test/link")
            self.assertTrue(done["identical"], done)
            self.assertEqual(done["linked_units"], ["a.cpp", "b.cpp"], done["not_linked"])

    def test_an_optimizer_and_a_code_generator(self):
        """build.optimizer: the original's compiler ran one release's optimizer and another's code generator. Each
        unit compiles to optimized bitcode with the optimizer, then to its object with the compiler and the same
        flags, its own passes off; the objects equal their targets, `zkit try` compiles alike, and no bitcode is
        left. A wrong optimizer_version and a plugin (whose passes would not run) are refused."""
        command = ["opt", "-O2", "-x", "c++", "-MMD", "-MF", "x.o.d", "-Iinc", "-c", "src/x.cpp", "-o", "x.o"]
        runs, bitcode = build.stages(command, ["cg"])
        self.assertEqual(bitcode, Path("x.bc"))
        self.assertEqual(runs[0], ["opt", "-O2", "-x", "c++", "-MMD", "-MF", "x.o.d", "-Iinc", "-c", "src/x.cpp",
                                   "-o", "x.bc", "-emit-llvm", "-MT", "x.o"])
        self.assertEqual(runs[1], ["cg", "-O2", "-x", "c++", "-Iinc", "-Xclang", "-disable-llvm-passes",
                                   "-Wno-unused-command-line-argument", "-c", "-x", "ir", "x.bc", "-o", "x.o"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in (("a.cpp", A_CPP), ("b.cpp", B_CPP)):
                (root / name).write_text(text, encoding="utf-8")
                out = str(root / name.replace(".cpp", ".o"))
                done = build.run_compile([CLANG, *[f for f in FLAGS if f != "-c"], "-c", str(root / name), "-o",
                                          out], [CLANG], capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stdout)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["a.cpp", "a.o", "b.cpp", "b.o"])
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            from zkit.elf import Elf
            linked = Elf.load(game / "orig/test/main.elf")
            at = {s.name: s.value for s in linked.symbols if s.name}
            rodata = linked.section(".rodata").address
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
                f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + 13:#x}\n\n"
                f"b.cpp:\n\t.text start:{at['_Z6helperi']:#x} end:{at['_Z6helperi'] + 36:#x}\n"
                f"\t.rodata.cst16 start:{at['_ZL5table']:#x} end:{at['_ZL5table'] + 16:#x}\n"
                f"\t.data start:{at['g_counter']:#x} end:{at['g_counter'] + 4:#x}\n", encoding="utf-8")
            (game / "src/a.cpp").write_text(A_CPP, encoding="utf-8")
            (game / "src/b.cpp").write_text(B_CPP, encoding="utf-8")
            data = json.loads(manifest.read_text())
            settings = data["targets"]["test"]["build"]
            settings.update(compiler=CLANG, optimizer=CLANG, cflags=[f for f in FLAGS if f != "-c"])
            manifest.write_text(json.dumps(data), encoding="utf-8")
            project = Project.load(manifest)
            built = build.build(project, quiet=True)
            self.assertTrue(built["ok"])
            self.assertIn("clang_stages", (game / "build/build.ninja").read_text())
            for unit in ("a", "b"):
                diff = objects.unit_diff(game / f"build/test/obj/{unit}.o", game / f"build/test/src/{unit}.o")
                self.assertEqual((diff["exact"], diff["compiled_only"]), (diff["total"], []), unit)
                self.assertGreater(diff["total"], 0)
            self.assertEqual(list((game / "build/test/src").glob("*.bc")), [])
            commands = json.loads((game / "build/compile_commands.json").read_text())
            self.assertTrue(all(c["arguments"][0] == CLANG and "-emit-llvm" not in c["arguments"] for c in commands))
            unit = objects.objdiff_units(project, "test")["a"]
            self.assertTrue(candidate.compare(project, "test", unit, "_Z6scaledi", A_CPP)["exact"])
            for setting, value in (("optimizer_version", "clang version 0.0.0-none"), ("clang_plugins", ["any"])):
                manifest.write_text(json.dumps({**data, "targets": {"test": {**data["targets"]["test"], "build": {
                    **settings, setting: value}}}}), encoding="utf-8")
                with self.assertRaises(ValueError, msg=setting):
                    build.configure(Project.load(manifest))

    def test_a_trap_word_the_original_compiler_wrote(self):
        """The original's compiler wrote each trap as `udf #0x8002` where clang writes `brk #1`. With `build.trap`
        the compiled unit equals its target object, the report agrees and `zkit try` compiles alike; without it
        the traps differ. A data word that reads as `brk #1` stays as it is."""
        from zkit.elf import Elf
        a_cpp = A_CPP + ("int checked(int v) { if (v < 0) __builtin_trap(); return v + 1; }\n"
                         "int ratio(int v) { if (!v) __builtin_trap(); return 100 / v; }\n")
        brk, udf = (0xD4200020).to_bytes(4, "little"), (0x00008002).to_bytes(4, "little")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in (("a.cpp", a_cpp), ("b.cpp", B_CPP)):
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            compiled = Elf.load(root / "a.o")
            text = compiled.section(".text")
            raw = bytearray(compiled.raw)   # the fork's object: its traps, in its code only
            traps = [at for at in range(text.offset, text.offset + text.size, 4) if raw[at:at + 4] == brk]
            self.assertEqual(len(traps), 2, "clang wrote both traps as brk #1")
            for at in traps:
                raw[at:at + 4] = udf
            (root / "a.o").write_bytes(bytes(raw))
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            linked = Elf.load(game / "orig/test/main.elf")
            at = {s.name: s.value for s in linked.symbols if s.name}
            rodata = linked.section(".rodata").address
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
                f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + 13:#x}\n\n"
                f"b.cpp:\n\t.text start:{at['_Z6helperi']:#x} end:{at['_Z6helperi'] + 36:#x}\n"
                f"\t.rodata.cst16 start:{at['_ZL5table']:#x} end:{at['_ZL5table'] + 16:#x}\n"
                f"\t.data start:{at['g_counter']:#x} end:{at['g_counter'] + 4:#x}\n", encoding="utf-8")
            (game / "src/a.cpp").write_text(a_cpp, encoding="utf-8")
            (game / "src/b.cpp").write_text(B_CPP, encoding="utf-8")
            data = json.loads(manifest.read_text())
            settings = data["targets"]["test"]["build"]
            settings.update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])
            seen = {}
            for trap in (None, "0x00008002"):
                if trap:
                    settings["trap"] = trap
                manifest.write_text(json.dumps(data), encoding="utf-8")
                project = Project.load(manifest)
                built = build.build(project, quiet=True)
                if OBJDIFF:  # the link reads the report, so without objdiff-cli there is none to fail
                    self.assertEqual(built["ok"], bool(trap), "the link rebuilds the module once traps are alike")
                diff = objects.unit_diff(game / "build/test/obj/a.o", game / "build/test/src/a.o")
                unit = objects.objdiff_units(project, "test")["a"]
                tried = candidate.compare(project, "test", unit, "_Z7checkedi", a_cpp)
                seen[trap] = (diff["exact"] == diff["total"], tried["exact"])
            self.assertEqual(seen, {None: (False, False), "0x00008002": (True, True)})
            if OBJDIFF:
                measures = json.loads((game / "build/test/report.json").read_text())["measures"]
                self.assertEqual(measures["matched_code"], measures["total_code"])
            commands = json.loads((game / "build/compile_commands.json").read_text())
            self.assertFalse(any("trap" in c["arguments"] for c in commands), "editors get the compiler's command")
            # a cold section's too: clang puts a deleting destructor of an abstract class in .text.unlikely.
            cold = root / "cold.o"
            (root / "cold.cpp").write_text("struct Shape { virtual ~Shape(); virtual int area() const = 0; };\n"
                                           "Shape::~Shape() {}\nextern const unsigned looks_like_a_trap = 0xD4200020u;\n",
                                           encoding="utf-8")
            subprocess.run([CLANG, *FLAGS, str(root / "cold.cpp"), "-o", str(cold)], check=True, capture_output=True)
            self.assertEqual(build.apply_trap(cold, "0x00008002"), 1)
            rewritten = Elf.load(cold)
            self.assertIn(udf, rewritten.data(rewritten.section(".text.unlikely.")))
            self.assertIn(brk, rewritten.data(rewritten.section(".rodata")), "data is never rewritten")
            self.assertEqual(build.apply_trap(cold, "0x00008002"), 0, "nothing left to rewrite")
            for wrong in ("udf", "0x1FFFFFFFF", 32770):
                with self.assertRaises(ValueError):
                    build.settings({"platform": "switch", "build": {"trap": wrong}})
            with self.assertRaises(ValueError):
                build.settings({"platform": "gamecube", "build": {"trap": "0x00008002"}})

    def test_a_renamed_symbol_reaches_the_target_objects(self):
        """The target objects take their function names from symbols.txt, also once a report exists: the index
        reads the report, which the objects themselves wrote, so a name the file changes must come from the file."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.cpp").write_text(A_CPP + B_CPP.replace("int g_counter = 3;\n", ""), encoding="utf-8")
            subprocess.run([CLANG, *FLAGS, str(root / "a.cpp"), "-o", str(root / "a.o")], check=True,
                           capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o")], check=True, capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game = root / "game"
            from zkit.elf import Elf
            symbols = Elf.load(game / "orig/test/main.elf").symbols
            at = {s.name: s.value for s in symbols if s.name}
            end = next(s.value + s.size for s in symbols if s.name == "_Z6helperi")   # its size varies by clang
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{end:#x}\n", encoding="utf-8")
            self.assertEqual(build.run_ninja(game, [], quiet=True), 0)
            (game / "build/test/report.json").write_text('{"units": []}', encoding="utf-8")  # a report exists
            symbols = game / "config/test/symbols.txt"
            text = symbols.read_text(encoding="utf-8")
            self.assertIn("_Z6scaledi = ", text)
            symbols.write_text(text.replace("_Z6scaledi = ", "_Z7renamedi = "), encoding="utf-8")
            self.assertEqual(build.run_ninja(game, [], quiet=True), 0)
            names = {s.name for s in Elf.load(game / "build/test/obj/a.o").symbols}
            self.assertIn("_Z7renamedi", names)
            self.assertNotIn("_Z6scaledi", names)

    def test_source_root_gives_the_original_file_name(self):
        """The original was built from `D:/proj/src/`, and its `__FILE__` says so: with `source_root` the build
        and `zkit try` compile src/a.cpp as `D:/proj/src/a.cpp`, so the function citing it matches; without, the
        citation reads src/a.cpp and does not."""
        cites = A_CPP.replace('"hello from a"', "__FILE__")
        original = "D:/proj/src/a.cpp"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "D:/proj/src").mkdir(parents=True)
            for name, text in (("a.cpp", cites), ("b.cpp", B_CPP)):
                (root / "D:/proj/src" / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, f"D:/proj/src/{name}", "-o", name.replace(".cpp", ".o")], cwd=root,
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game, manifest = root / "game", Path(result["manifest"])
            from zkit.elf import Elf
            linked = Elf.load(game / "orig/test/main.elf")
            at = {s.name: s.value for s in linked.symbols if s.name}
            rodata = linked.section(".rodata").address
            (game / "config/test/splits.txt").write_text(
                f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
                f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + len(original) + 1:#x}\n", encoding="utf-8")
            (game / "src/a.cpp").write_text(cites, encoding="utf-8")
            data = json.loads(manifest.read_text())
            settings = data["targets"]["test"]["build"]
            settings.update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])
            matched = {}
            for rooted in (False, True):
                if rooted:
                    settings["source_root"] = original.rsplit("/", 1)[0]
                manifest.write_text(json.dumps(data), encoding="utf-8")
                self.assertTrue(build.build(Project.load(manifest), quiet=True)["ok"])
                diff = objects.function_diff(game / "build/test/obj/a.o", game / "build/test/src/a.o", "_Z8greetingv")
                unit = objects.objdiff_units(Project.load(manifest), "test")["a"]
                tried = candidate.compare(Project.load(manifest), "test", unit, "_Z8greetingv", cites)
                matched[rooted] = (diff["exact"], tried["exact"])
            self.assertEqual(matched, {False: (False, False), True: (True, True)})
            # the string itself, not a path ending in it (clang's -working-directory makes the main file absolute)
            built = (game / "build/test/src/a.o").read_bytes()
            self.assertIn(original.encode() + b"\0", built)
            self.assertNotIn(b"/" + original.encode(), built)
            dry = subprocess.run(["ninja", "-f", "build/build.ninja", "-n", "-d", "explain", "build/test/src/a.o"],
                                 cwd=game, capture_output=True, text=True)
            self.assertIn("no work to do", dry.stdout, dry.stdout + dry.stderr)   # its dependencies are found


class ObjdiffUnitsTests(unittest.TestCase):
    def test_object_paths_come_back_from_the_repository_root_wherever_the_project_file_sits(self):
        """objdiff reads a unit's objects from its project file's folder: a target whose file sits in a subfolder
        (one of several targets) has them as ../../build/...; every reader joins them to the repository's root."""
        for where, prefix in (("objdiff.json", ""), ("config/t/objdiff.json", "../../")):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / where).parent.mkdir(parents=True, exist_ok=True)
                (root / where).write_text(json.dumps({"units": [
                    {"name": "a", "target_path": f"{prefix}build/t/obj/a.o", "base_path": f"{prefix}build/t/src/a.o",
                     "metadata": {"source_path": "src/a.cpp"}},
                    {"name": "b", "target_path": f"{prefix}build/t/obj/b.o"}]}), encoding="utf-8")
                manifest = root / "p.json"
                manifest.write_text(json.dumps({"schema_version": 1, "id": "prog", "repositories": {
                    "decomp": {"root": ".", "role": "decomp"}}, "targets": {"t": {
                        "repository": "decomp", "module": "main", "objdiff": where}}}), encoding="utf-8")
                units = objects.objdiff_units(Project.load(manifest), "t")
                self.assertEqual((units["a"]["target_path"], units["a"]["base_path"], units["b"]["target_path"]),
                                 ("build/t/obj/a.o", "build/t/src/a.o", "build/t/obj/b.o"), where)
                self.assertNotIn("base_path", units["b"])
                self.assertEqual(units["a"]["metadata"], {"source_path": "src/a.cpp"})


if __name__ == "__main__":
    unittest.main()
