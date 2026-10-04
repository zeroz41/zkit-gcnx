"""A fresh decomp-toolkit project: `init`, project selection from the working directory, and REL modules
(functions, callers across DOL and RELs, disassembly and xrefs from dtk's asm output). No game assets."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import test_bridge
from test_bridge import TEXT, build_dol

ASM = """.include "macros.inc"
.file "obj_test.cpp"

# .text:0x0 | 0x40 | size: 0x14
.fn ObjTest_Draw__FPv, global
/* 00000040 00000100  94 21 FF F0 */\tstwu r1, -0x10(r1)
/* 00000044 00000104  48 00 00 01 */\tbl update__6TEnemyFv
/* 00000048 00000108  3C 60 00 00 */\tlis r3, enemyTable@ha
/* 0000004C 0000010C  80 63 00 00 */\tlwz r3, enemyTable@l(r3)
/* 00000050 00000110  C0 22 00 00 */\tlfs f1, "@123"@sda21(r2)
.endfn ObjTest_Draw__FPv

# .text:0x14 | 0x54 | size: 0x8
.fn ObjTest_Execute__FPv, local
/* 00000054 00000114  48 00 00 01 */\tbl ObjTest_Draw__FPv
/* 00000058 00000118  4E 80 00 20 */\tblr
.endfn ObjTest_Execute__FPv

.section .rodata, "a"
.obj "@123", local
\t.4byte 0x3FA00000
.endobj "@123"
"""


class FreshProject(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from gcn_zkit.index import close_connections
        self.addCleanup(close_connections)  # runs first: Windows cannot delete an open database
        base = Path(self.temp.name)
        self.old_env = {k: os.environ.get(k) for k in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
                                                        "ZKIT_PROJECT", "ZKIT_REFRESH_TTL")}
        self.addCleanup(self.restore)
        for var in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
            os.environ[var] = str(base / var.lower())
        os.environ.pop("ZKIT_PROJECT", None)
        os.environ["ZKIT_REFRESH_TTL"] = "0"
        self.repo = repo = base / "mygame"
        (repo / "config/GAME01/rels/obj_test").mkdir(parents=True)
        (repo / "orig/GAME01/sys").mkdir(parents=True)
        (repo / "build/GAME01/obj_test/asm").mkdir(parents=True)
        (repo / "docs").mkdir()
        (repo / "README.md").write_text("My game decomp.\n", encoding="utf-8")
        (repo / "configure.py").write_text('DEFAULT_VERSION = 0\nVERSIONS = [\n    "GAME01",  # 0\n]\n',
                                           encoding="utf-8")
        (repo / "config/GAME01/config.yml").write_text(
            "# comment\nname: framework\nobject_base: orig/GAME01\nobject: sys/main.dol\n"
            "symbols: config/GAME01/symbols.txt\nsplits: config/GAME01/splits.txt\nmodules:\n"
            "- object: files/rel/obj_test.rel\n  symbols: config/GAME01/rels/obj_test/symbols.txt\n",
            encoding="utf-8")
        (repo / "orig/GAME01/sys/main.dol").write_bytes(build_dol())
        (repo / "config/GAME01/symbols.txt").write_text(
            "update__6TEnemyFv = .text:0x80003000; // type:function size:0xC\n"
            "fn_80003010 = .text:0x80003010; // type:function size:0x10\n"
            "enemyTable = .data:0x80003104; // type:object size:0x4\n", encoding="utf-8")
        report = {"measures": {"total_functions": 4}, "units": [
            {"name": "framework/auto_03_80003000_text", "metadata": {"module_name": "framework", "module_id": 0},
             "functions": [{"name": "update__6TEnemyFv", "size": "12", "metadata": {"virtual_address": str(TEXT)}},
                           {"name": "fn_80003010", "size": "16", "metadata": {"virtual_address": str(TEXT + 0x10)}}]},
            {"name": "obj_test/obj_test", "metadata": {"module_name": "obj_test", "module_id": 7},
             "functions": [{"name": "ObjTest_Draw__FPv", "size": "20",
                            "metadata": {"virtual_address": "64", "demangled_name": "ObjTest_Draw(void*)"}},
                           {"name": "ObjTest_Execute__FPv", "size": "8", "metadata": {"virtual_address": "84"}}]}]}
        (repo / "build/GAME01/report.json").write_text(json.dumps(report), encoding="utf-8")
        (repo / "build/GAME01/config.json").write_text("{}", encoding="utf-8")
        (repo / "build/GAME01/obj_test/asm/obj_test.s").write_text(ASM, encoding="utf-8")
        self.outside = base / "elsewhere"
        self.outside.mkdir()

    def restore(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def cli(self, *argv, cwd=None):
        from gcn_zkit.cli import main
        out = io.StringIO()
        previous = Path.cwd()
        os.chdir(cwd or self.repo)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = main(list(argv))
        finally:
            os.chdir(previous)
        return code, out.getvalue()

    def test_init_lookup_rels_and_selection(self):
        code, said = self.cli("init")
        self.assertEqual(code, 0, said)
        self.assertIn("4 functions indexed (2 in REL modules)", said)
        manifest = json.loads(next((Path(os.environ["XDG_CONFIG_HOME"]) / "gcn-zkit/projects").glob("*.json"))
                              .read_text(encoding="utf-8"))
        target = manifest["targets"]["game01"]
        self.assertEqual(target["original"], "orig/GAME01/sys/main.dol")
        self.assertEqual(target["module"], "framework")
        self.assertEqual(manifest["repositories"]["decomp"]["index_paths"], ["README.md", "docs"])

        # A REL function: module+offset address, callee in the DOL resolved through dtk's relocations.
        code, text = self.cli("lookup", "ObjTest_Draw")
        self.assertIn("obj_test+0x40 ObjTest_Draw(void*)", text)
        self.assertIn("0x80003000 TEnemy::update", text)
        self.assertNotIn("native cites", text)  # no native port configured
        # The DOL function is called from the REL.
        code, text = self.cli("lookup", "0x80003000")
        self.assertIn("obj_test+0x40", text)
        # A module address works as a query, also mid-function, and in a batch with a DOL address.
        code, text = self.cli("names", "obj_test+0x54", "0x80003010")
        self.assertIn("ObjTest_Execute__FPv", text)
        self.assertIn("fn_80003010", text)
        # A fresh process knows module names before any refresh.
        from gcn_zkit import index
        index._MODULE_NAMES.clear()
        index.close_connections()
        code, text = self.cli("asm", "obj_test+0x40")
        self.assertEqual(code, 0, text)
        # Disassembly from dtk asm (no objdump here), with the float constant shown.
        code, text = self.cli("asm", "ObjTest_Draw__FPv")
        self.assertIn("obj_test+0x50  C0220000  lfs f1, \"@123\"@sda21(r2)  ; = 1.25", text)
        # A DOL global read from a REL.
        code, text = self.cli("xrefs", "enemyTable")
        self.assertIn("REL modules: 1 refs in 1 module(s), most: obj_test x1", text)

        # Selection: inside the repo -> this project; the hook is silent anywhere else.
        code, text = self.cli("projects")
        self.assertIn("* mygame-game01", text)
        code, text = self.cli("hook", "session-start", cwd=self.outside)
        self.assertEqual((code, text), (0, ""))
        code, text = self.cli("hook", "session-start")
        self.assertIn("zkit brief", json.loads(text)["hookSpecificOutput"]["additionalContext"])

    def test_init_keeps_user_edits_and_no_report_fallback(self):
        (self.repo / "build/GAME01/report.json").unlink()
        code, said = self.cli("init")
        self.assertIn("no build/GAME01/report.json yet", said)
        self.assertIn("2 functions indexed", said)  # from symbols.txt
        path = next((Path(os.environ["XDG_CONFIG_HOME"]) / "gcn-zkit/projects").glob("*.json"))
        data = json.loads(path.read_text(encoding="utf-8"))
        data["repositories"]["decomp"]["rules"] = ["Commit as me"]
        data["targets"]["game01"]["sda_bases"] = {"r2": "0x80003100"}
        path.write_text(json.dumps(data), encoding="utf-8")
        self.cli("init")
        again = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(again["repositories"]["decomp"]["rules"], ["Commit as me"])
        self.assertEqual(again["targets"]["game01"]["sda_bases"], {"r2": "0x80003100"})

    def test_definitions_outside_the_unit_source(self):
        """Mature C++ decomps define many functions in headers or in .inc fragments the unit includes."""
        (self.repo / "include").mkdir()
        (self.repo / "src").mkdir()
        (self.repo / "include/enemy.h").write_text(
            "#pragma once\nint helper(); // declared\nstruct Other { int* reach() { return 0; } };\n"
            "class TEnemy {\npublic:\n    TEnemy* self() { return this; }\n    void update();\n};\n"
            "inline int getRupee() { return 5; }\n", encoding="utf-8")
        (self.repo / "src/enemy.cpp").write_text(
            '#include "enemy.h"\n#include "enemy_more.inc"\nconst int& TEnemy_ref();\n', encoding="utf-8")
        (self.repo / "src/enemy_more.inc").write_text(
            "void TEnemy::update() {\n    self();\n}\n", encoding="utf-8")
        report = json.loads((self.repo / "build/GAME01/report.json").read_text(encoding="utf-8"))
        unit = {"name": "framework/enemy", "metadata": {"module_name": "framework", "module_id": 0,
                                                         "source_path": "src/enemy.cpp"},
                "functions": [{"name": n, "size": "4", "fuzzy_match_percent": 100.0,
                               "metadata": {"virtual_address": str(a), "demangled_name": d}} for n, d, a in [
                    ("update__6TEnemyFv", "TEnemy::update()", TEXT),
                    ("self__6TEnemyFv", "TEnemy::self()", TEXT + 0x10),
                    ("getRupee__Fv", "getRupee()", TEXT + 0x20),
                    ("__dt__6TEnemyFv", "TEnemy::~TEnemy()", TEXT + 0x24)]]}
        report["units"] = [unit] + report["units"][1:]
        (self.repo / "build/GAME01/report.json").write_text(json.dumps(report), encoding="utf-8")
        self.cli("init")
        lines = {q: self.cli("lookup", q)[1].splitlines()[1] for q in ("0x80003000", "0x80003010", "0x80003020", "0x80003024")}
        self.assertIn("src/enemy_more.inc:1 (included by the unit", lines["0x80003000"])
        self.assertIn("include/enemy.h:6 (inline in a header", lines["0x80003010"])  # pointer return, class body
        self.assertIn("include/enemy.h:9 (inline in a header", lines["0x80003020"])  # free inline function
        self.assertIn("compiler-generated", lines["0x80003024"])

    def test_setup_with_a_project_file(self):
        """Your own project file (custom rules, a port) gets the same one-command setup."""
        self.cli("init", "--dry-run")
        manifest = Path(self.temp.name) / "my.project.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "mine", "repositories": {
            "decomp": {"root": str(self.repo), "role": "decomp", "index_paths": ["README.md"]}}}), encoding="utf-8")
        code, text = self.cli("setup", str(manifest), "--no-agents", cwd=self.outside)
        self.assertEqual(code, 0, text)
        self.assertIn(f"default project: {manifest.resolve()}", text)
        code, text = self.cli("projects")
        self.assertIn("* mine", text)

    def test_not_a_dtk_project(self):
        code, _ = self.cli("init", str(self.outside))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
