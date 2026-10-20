"""Lookup tools and the MCP argument layer on the synthetic decomp: name resolution, ambiguity, batches, r2/r13
from the whole __init_registers, interior pointers, argument errors and the session's default repo."""

import support
import asyncio
import json
import os
import struct
import unittest

import test_bridge
from test_bridge import DATA, TEXT, addi, bl, lis, ori, BLR

support.ROOT  # isolated config, cache and state for this module


def long_init_dol() -> bytes:
    """test_bridge's program, with an __init_registers that clears registers before setting r2/r13 (as Twilight
    Princess does) and a data word pointing into the middle of the first function."""
    code = [0] * 48
    code[0], code[1], code[2] = bl(TEXT, TEXT + 0x10), bl(TEXT + 4, TEXT + 0x20), BLR
    code[4], code[5], code[6], code[7] = lis(3, 0x8000), addi(3, 3, 0x3104), (48 << 26) | (1 << 21) | (2 << 16), BLR
    code[8] = BLR
    code[16:28] = [addi(r, 0, 0) for r in range(3, 15)]  # li r3..r14, 0: 0x30 bytes before the bases
    code[28:33] = [lis(2, 0x8000), ori(2, 2, 0x3100), lis(13, 0x8000), ori(13, 13, 0x3100), BLR]
    text = struct.pack(">48I", *code)
    data = struct.pack(">fII", 1.5, TEXT, TEXT + 8)
    offsets, addresses, sizes = [0] * 18, [0] * 18, [0] * 18
    offsets[0], addresses[0], sizes[0] = 0x100, TEXT, len(text)
    offsets[7], addresses[7], sizes[7] = 0x100 + len(text), DATA, len(data)
    header = struct.pack(">18I18I18I3I", *offsets, *addresses, *sizes, 0, 0, TEXT).ljust(0x100, b"\0")
    return header + text + data


class LookupToolTests(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def add_function(self, name: str, demangled: str, address: int, size: int, match: float | None = 100.0) -> None:
        report = json.loads((self.decomp / "build/report.json").read_text(encoding="utf-8"))
        report["units"][0]["functions"].append(dict({"name": name, "size": str(size), "metadata": {
            "virtual_address": str(address), "demangled_name": demangled}},
            **({"fuzzy_match_percent": match} if match is not None else {})))
        (self.decomp / "build/report.json").write_text(json.dumps(report), encoding="utf-8")

    def call(self, tool: str, arguments: dict) -> str:
        from zkit.server import create_server

        async def scenario():
            blocks = await create_server(self.project).call_tool(tool, arguments)
            return "".join(b.text for b in (blocks[0] if isinstance(blocks, tuple) else blocks))
        return asyncio.run(asyncio.wait_for(scenario(), 15))

    def test_class_method_without_parameters_is_exact_not_a_fragment(self):
        from zkit.bridge import lookup, resolve, resolve_address
        from zkit.index import refresh
        self.add_function("updateAll__6TEnemyFv", "TEnemy::updateAll()", TEXT + 0x24, 4)
        refresh(self.project)
        self.assertEqual(resolve(self.project, "TEnemy::update"), [TEXT])
        self.assertEqual(len(resolve(self.project, "TEnemy::upd")), 2)  # a fragment still finds both
        with self.assertRaisesRegex(ValueError, "matches 2 functions: 0x80003000 TEnemy::update\\(\\); "
                                                "0x80003024 TEnemy::updateAll\\(\\)"):
            resolve_address(self.project, "TEnemy::upd")
        self.assertTrue(lookup(self.project, "TEnemy::upd")["ambiguous"])

    def test_a_member_defined_inside_its_namespace_block(self):
        import subprocess
        from zkit.bridge import lookup, readiness_of, refs
        from zkit.index import connect, containing
        self.add_function("build__Q22gf4FlagFRCQ22gf5Param", "gf::Flag::build(gf::Param const&)", TEXT + 0x24, 4)
        (self.decomp / "src/Enemy.cpp").write_text(
            "void TEnemy::update() {\n}\nnamespace other {\nvoid Flag::build(const Param& param) {\n}\n}\n"
            "namespace gf {\nvoid Flag::build(int a, int b) {\n}\n\nvoid Flag::build(const Param& param) {\n"
            "    make(param);\n}\n}  // namespace gf\n", encoding="utf-8")
        (self.decomp / "src/Flag.h").write_text("namespace gf {\nclass Flag {\npublic:\n"
                                                "    static void build(const Param& param);\n};\n}\n", encoding="utf-8")
        (self.decomp / "src/Other.h").write_text("class Other {\n    void build();\n};\n", encoding="utf-8")
        (self.decomp / "docs/BUILD.md").write_text("Run the build first. Flag::build makes the flags.\n",
                                                   encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.decomp)], check=True)
        subprocess.run(["git", "-C", str(self.decomp), "add", "-A"], check=True)
        data = lookup(self.project, "0x80003024", body=True)
        self.assertEqual((data["function"]["source_line"], data["body_lines"]), (11, [11, 13]))
        self.assertTrue(data["body"].startswith("void Flag::build(const Param& param) {"))
        row = containing(connect(self.project), "t", TEXT + 0x24)
        self.assertEqual(readiness_of(self.project, "t", row)["definition"], "src/Enemy.cpp:11")
        found = {r["ref"]: r["kind"] for r in refs(self.project, "gf::Flag::build")["rows"]}
        # the overload is the same name; other::Flag::build, Other::build and "the build" are not
        self.assertEqual(found, {"decomp:src/Enemy.cpp:8": "definition", "decomp:src/Enemy.cpp:11": "definition",
                                 "decomp:src/Flag.h:4": "declaration", "decomp:docs/BUILD.md:1": "use"})

    def test_pasted_queries_and_floor_of_near_misses(self):
        from zkit.bridge import split_queries, status_word
        self.assertEqual(split_queries("`0x80003000`,"), ["0x80003000"])
        self.assertEqual(split_queries("0X80003000 src/Enemy.cpp"), ["0X80003000", "src/Enemy.cpp"])
        self.assertEqual(split_queries("operator new"), ["operator new"])
        self.assertEqual(status_word({"match": 99.95, "unit": "u"}), "99.9%")  # never shown as 100.0%

    def test_names_say_what_a_query_is(self):
        from zkit.bridge import names
        from zkit.render import names as render_names
        self.add_function("updateAll__6TEnemyFv", "TEnemy::updateAll()", TEXT + 0x24, 4)
        text = render_names(names(self.project, ["nope_xyz", "TEnemy::upd", "0x80003014", "enemyTable"]))
        self.assertIn("nope_xyz: no function or symbol by that name", text)
        self.assertIn("TEnemy::upd: matches 2 functions", text)
        self.assertIn("0x80003010 TPlayer__sub_80003010 (+0x4)", text)
        self.assertIn("enemyTable .data size 0x4  [data]", text)

    def test_small_data_bases_come_from_all_of_init_registers(self):
        from zkit.bridge import xrefs
        from zkit.gc import Dol
        from zkit.inspect_dol import sda_bases
        (self.decomp / "orig.dol").write_bytes(long_init_dol())
        symbols = (self.decomp / "config/symbols.txt").read_text(encoding="utf-8")
        symbols = symbols.replace("__init_registers = .init:0x80003040; // type:function size:0x14",
                                  "__init_registers = .init:0x80003040; // type:function size:0x44")
        (self.decomp / "config/symbols.txt").write_text(symbols + "lbl_80003108 = .data:0x80003108; // type:object "
                                                        "size:0x4\n", encoding="utf-8")
        self.assertEqual(sda_bases(self.project, "t", Dol.load(self.decomp / "orig.dol")), {2: DATA, 13: DATA})
        self.assertIn("f32", xrefs(self.project, "lbl_80003100")["kinds"])  # lfs f1,0(r2) is decoded
        data = xrefs(self.project, "0x80003000")
        self.assertEqual((data["data_total"], data["data_to_start"]), (2, 1))  # one pointer lands inside it

    def test_argument_errors_name_the_valid_arguments_and_aliases_work(self):
        from zkit.server import create_server
        with self.assertRaisesRegex(Exception, r"unknown argument\(s\) sice\. zkit_progress takes: response_format, "
                                               r"since"):
            self.call("zkit_progress", {"sice": "x"})
        with self.assertRaisesRegex(Exception, "kind: Input should be 'decomp' or 'port' \\(got 'native'\\)"):
            self.call("zkit_contract", {"kind": "native"})
        with self.assertRaisesRegex(Exception, "size must be a number"):
            self.call("zkit_asm", {"query": "0x80003000", "size": "big"})
        self.assertIn("TEnemy::update()", self.call("zkit_names", {"query": "0x80003000"}))  # query -> queries
        self.assertIn("finish gate for decomp", self.call("zkit_gate", {"repository": "decomp"}))
        self.assertTrue(create_server(self.project))

    def test_tools_default_to_the_repo_the_session_works_in(self):
        here = os.getcwd()
        try:
            os.chdir(self.native)
            self.assertIn("check native vs HEAD", self.call("zkit_check", {}))
            os.chdir(self.decomp)
            self.assertIn("finish gate for decomp", self.call("zkit_gate", {}))
        finally:
            os.chdir(here)


if __name__ == "__main__":
    unittest.main()
