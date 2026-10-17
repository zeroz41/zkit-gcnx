"""Split units, cross-unit data references and vtable class evidence on a hand-assembled DOL."""

import support  # noqa: F401  (isolates config, cache and state)
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from test_bridge import BLR, addi, lis  # noqa: E402

TEXT, DATA, LIT = 0x80003000, 0x80003100, 0x80003200


def build_dol() -> bytes:
    code = [BLR] * 12
    # Enemy @3000: reads the player's vtable (data owned by Player) and a literal stored in Player's .sdata2.
    code[0], code[1], code[2], code[3] = lis(3, 0x8000), addi(3, 3, 0x3108), lis(4, 0x8000), addi(4, 4, 0x3200)
    # Player @3010 (named TPlayer, but only TEnemy's vtable holds it): reads the enemy's vtable.
    code[4], code[5] = lis(3, 0x8000), addi(3, 3, 0x3100)
    # fn @3020: in TPlayer's vtable only, no class in its name.
    text = struct.pack(">12I", *code)
    data = struct.pack(">3I", TEXT, TEXT + 0x10, TEXT + 0x20)  # __vt__6TEnemy[2] then __vt__7TPlayer[1]
    lit = struct.pack(">f", 2.0)
    offsets, addresses, sizes = [0] * 18, [0] * 18, [0] * 18
    offsets[0], addresses[0], sizes[0] = 0x100, TEXT, len(text)
    offsets[7], addresses[7], sizes[7] = 0x100 + len(text), DATA, len(data)
    offsets[8], addresses[8], sizes[8] = 0x100 + len(text) + len(data), LIT, len(lit)
    header = struct.pack(">18I18I18I3I", *offsets, *addresses, *sizes, 0, 0, TEXT).ljust(0x100, b"\0")
    return header + text + data + lit


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from zkit.index import close_connections
        self.addCleanup(close_connections)
        base = Path(self.temp.name)
        for var in ("XDG_CACHE_HOME", "XDG_STATE_HOME"):
            os.environ[var] = str(base / var.lower())
        os.environ["ZKIT_REFRESH_TTL"] = "0"
        repo = base / "game"
        (repo / "config").mkdir(parents=True)
        (repo / "build").mkdir()
        (repo / "src/game").mkdir(parents=True)
        (repo / "orig.dol").write_bytes(build_dol())
        (repo / "config/symbols.txt").write_text(
            "update__6TEnemyFv = .text:0x80003000; // type:function size:0x10\n"
            "TPlayer__sub_80003010 = .text:0x80003010; // type:function size:0x10\n"
            "fn_80003020 = .text:0x80003020; // type:function size:0x10\n"
            "__vt__6TEnemy = .data:0x80003100; // type:object size:0x8\n"
            "__vt__7TPlayer = .data:0x80003108; // type:object size:0x4\n"
            "lbl_80003200 = .sdata2:0x80003200; // type:object size:0x4\n", encoding="utf-8")
        (repo / "config/splits.txt").write_text(
            "Sections:\n\t.text type:code\n\ngame/Enemy.cpp:\n\t.text start:0x80003000 end:0x80003010\n"
            "\t.data start:0x80003100 end:0x80003108\n\ngame/Player.cpp:\n\t.text start:0x80003010 end:0x80003030\n"
            "\t.data start:0x80003108 end:0x8000310C\n\t.sdata2 start:0x80003200 end:0x80003204\n", encoding="utf-8")

        def unit(name, complete, functions):
            return {"name": "main/" + name, "metadata": {"module_name": "main", "source_path": f"src/{name}.cpp",
                                                         "complete": complete},
                    "functions": [{"name": n, "size": "16", "fuzzy_match_percent": 100.0,
                                   "metadata": {"virtual_address": str(a)}} for n, a in functions]}
        report = {"units": [unit("game/Enemy", False, [("update__6TEnemyFv", TEXT)]),
                            unit("game/Player", True, [("TPlayer__sub_80003010", TEXT + 0x10),
                                                       ("fn_80003020", TEXT + 0x20)])]}
        (repo / "build/report.json").write_text(json.dumps(report), encoding="utf-8")
        self.manifest = base / "project.json"
        self.manifest.write_text(json.dumps({
            "schema_version": 1, "id": "structure",
            "repositories": {"decomp": {"root": "game", "role": "decomp", "index_paths": ["src"]}},
            "targets": {"t": {"repository": "decomp", "module": "main", "report": "build/report.json",
                              "symbols": "config/symbols.txt", "splits": "config/splits.txt",
                              "original": "orig.dol"}}}), encoding="utf-8")
        from zkit.project import Project
        self.project = Project.load(self.manifest)

    def test_unit_lists_ranges_and_cross_unit_references(self):
        from zkit.structure import unit
        for query in ("game/Enemy", "game/Enemy.cpp", "main/game/Enemy", "0x80003104", "update__6TEnemyFv"):
            self.assertEqual(unit(self.project, query)["unit"], "game/Enemy.cpp", query)
        enemy = unit(self.project, "game/Enemy")
        self.assertEqual(enemy["functions"], {"total": 1, "exact": 1, "linked": 0, "provisional": 0})
        self.assertEqual([s["section"] for s in enemy["sections"]], [".text", ".data"])
        vtable = next(d for d in enemy["data"] if d["name"] == "__vt__6TEnemy")
        self.assertEqual(vtable["refs_outside"], [("game/Player.cpp", 1)])  # Player's code reads Enemy's vtable
        literal = enemy["outgoing"][0]
        self.assertEqual((literal["unit"], literal["section"], literal["literal"], literal["symbols"]),
                         ("game/Player.cpp", ".sdata2", True, ["lbl_80003200"]))
        self.assertTrue(any(o["section"] == ".data" and o["symbols"] == ["__vt__7TPlayer"] for o in enemy["outgoing"]))
        self.assertEqual(enemy["neighbours"][0]["after"], "game/Player.cpp")
        missing = unit(self.project, "0x80003300")
        self.assertFalse(missing["found"])
        self.assertIn("auto-generated unit", missing["hint"])

    def test_blocked_lists_exact_unlinked_units_with_reasons(self):
        from zkit.structure import blocked
        data = blocked(self.project)
        self.assertEqual([u["unit"] for u in data["units"]], ["game/Enemy.cpp"])
        self.assertEqual(data["linked_units"], 1)
        self.assertTrue(any("used by other units" in r for r in data["units"][0]["reasons"]))
        self.assertTrue(any("literal" in r for r in data["units"][0]["reasons"]))

    def test_classes_flags_contradicted_and_unclaimed_virtuals(self):
        from zkit.structure import classes
        data = classes(self.project)
        self.assertEqual(data["counts"], {"consistent": 1, "contradicted_strong": 1, "unclaimed": 1})
        wrong = data["contradicted"][0]
        self.assertEqual((wrong["name"], wrong["named_class"], wrong["classes"], wrong["strength"]),
                         ("TPlayer__sub_80003010", "TPlayer", ["TEnemy"], "strong"))
        self.assertEqual(data["unclaimed"][0]["suggestion"], "TPlayer")
        self.assertEqual(classes(self.project, name="TEnemy")["contradicted_total"], 1)
        self.assertEqual(classes(self.project, name="TOther")["contradicted_total"], 0)

    def test_data_lookup_and_name_range_show_owner_and_data(self):
        from zkit.bridge import lookup, names
        found = lookup(self.project, "0x80003200")
        self.assertEqual(found["owner_unit"]["unit"], "game/Player.cpp")
        rows = names(self.project, start=0x80003100, end=0x80003204)["rows"]
        self.assertEqual([r["name"] for r in rows], ["__vt__6TEnemy", "__vt__7TPlayer", "lbl_80003200"])
        code = names(self.project, start=TEXT, end=TEXT + 0x30)["rows"]
        self.assertEqual(len(code), 3)
        self.assertFalse(any(r.get("data") for r in code))

    def test_cli_and_mcp_agree(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
        cli = subprocess.run([sys.executable, "-m", "zkit.cli", "--project", str(self.manifest), "--json",
                              "unit", "game/Enemy"], capture_output=True, text=True, env=env, check=True)
        self.assertEqual(json.loads(cli.stdout)["unit"], "game/Enemy.cpp")
        text = subprocess.run([sys.executable, "-m", "zkit.cli", "--project", str(self.manifest), "classes"],
                              capture_output=True, text=True, env=env, check=True).stdout
        self.assertIn("[strong] 0x80003010 TPlayer__sub_80003010", text)
        import anyio
        from zkit.server import create_server
        server = create_server(self.project)

        async def call(name, arguments):
            result = await server.call_tool(name, arguments)
            content = result[0] if isinstance(result, tuple) else result
            return content[0].text

        mcp = anyio.run(call, "zkit_unit", {"query": "game/Enemy", "response_format": "json"})
        self.assertEqual(json.loads(mcp)["unit"], json.loads(cli.stdout)["unit"])
        self.assertIn("exact but not linked", anyio.run(call, "zkit_unit", {"blocked": True}))
        self.assertIn("TPlayer__sub_80003010", anyio.run(call, "zkit_classes", {}))


if __name__ == "__main__":
    unittest.main()
