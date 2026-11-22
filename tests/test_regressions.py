"""Regression tests for failures seen in real Claude Code / Codex sessions (evals/replay/corpus.json)."""

import support  # noqa: F401  (isolates config, cache and state)
import asyncio
import json
import subprocess
import unittest

import test_bridge
from test_bridge import TEXT


class AuditRegressions(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def git(self, root, *args):
        subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                       check=True, capture_output=True)

    def test_several_addresses_in_one_query(self):
        from zkit.bridge import lookup, split_queries
        self.assertEqual(split_queries("0x80003000 0x80003010"), ["0x80003000", "0x80003010"])
        self.assertEqual(split_queries("8013E990,8013E998"), ["8013E990", "8013E998"])
        self.assertEqual(split_queries("TEnemy::update"), ["TEnemy::update"])
        data = lookup(self.project, "0x80003000 0x80003010")
        self.assertEqual([d["function"]["address"] for d in data["batch"]], ["0x80003000", "0x80003010"])

    def test_asm_honours_interior_start_with_size(self):
        from zkit.inspect_dol import disasm
        data = disasm(self.project, "t", TEXT + 0x14, 8)
        self.assertEqual(data["address"], "0x80003014")
        self.assertEqual(data["function"]["address"], "0x80003010")
        self.assertEqual(disasm(self.project, "t", TEXT + 0x14)["address"], "0x80003010")  # no size: whole function

    def test_data_by_symbol_and_unreadable_address(self):
        from zkit import bridge, inspect_dol
        address = bridge.resolve_address(self.project, "enemyTable", "t")
        self.assertEqual(address, 0x80003104)
        self.assertEqual(inspect_dol.read_data(self.project, "t", address, "ptr", 1)["rows"][0]["values"][0][:10],
                         "0x80003000")
        with self.assertRaisesRegex(ValueError, "not inside one section"):
            inspect_dol.read_data(self.project, "t", 0x80004000, "u32", 1)
        with self.assertRaisesRegex(ValueError, "Unknown type"):
            inspect_dol.read_data(self.project, "t", address, "float", 1)

    def test_xrefs_names_and_callers(self):
        from zkit import bridge
        refs = bridge.xrefs(self.project, "enemyTable", "t")
        self.assertIn("TPlayer__sub_80003010", [f for f, _ in refs["functions"]])
        self.assertEqual(refs["kinds"].get("addr"), 1)
        floats = bridge.xrefs(self.project, "lbl_80003100", "t")
        self.assertEqual(floats["kinds"].get("f32"), 1)
        rows = bridge.names(self.project, ["0x80003010", "enemyTable"], "t")["rows"]
        self.assertEqual(rows[0]["name"], "TPlayer__sub_80003010")
        self.assertEqual(rows[1]["name"], "enemyTable")
        self.assertEqual(bridge.names(self.project, target="t", regex="^TPlayer")["total"], 1)
        data = bridge.lookup(self.project, "0x80003010")
        self.assertEqual(data["callers"]["count"], 1)
        self.assertEqual(data["callers"]["by_class"], [("TEnemy", 1)])

    def test_definition_finder_skips_comments_externs_and_calls(self):
        from zkit.bridge import find_definition
        lines = ["// CARVE-GEN TODO: foo__3FooFv(void) hand-decompile",
                 "s32 foo__3FooFv(void *, void *); /* extern */",
                 "void bar() {", "    x = foo__3FooFv(a);", "    if (foo__3FooFv(b)) {", "    }", "}",
                 "s32 foo__3FooFv(void *a,", "                void *b) {", "    return 1;", "}"]
        self.assertEqual(find_definition(lines, ["foo__3FooFv"]), (7, 10))
        self.assertIsNone(find_definition(["s32 foo__3FooFvi(void);"], ["foo__3FooFv"]))

    def test_definition_finder_reads_namespace_and_class_blocks(self):
        from zkit.bridge import find_definition, parameter_count
        lines = ["namespace other {", "void Flag::build(const Param& p) {", "}", "}",
                 "namespace ns {", "void Flag::build(int a, int b) {", "}", "",
                 "void Flag::build(const Param& p) {", "    make(p);", "}", "}  // namespace ns",
                 "namespace a { namespace b {", "class C {", "    int get() const { return 1; }", "};", "} }"]
        names = ["_ZN2ns4Flag5buildERKNS_5ParamE", "ns::Flag::build"]
        self.assertEqual(find_definition(lines, names, params=parameter_count("ns::Flag::build(ns::Param const&)")),
                         (8, 10))
        self.assertEqual(find_definition(lines, names), (5, 6))  # no parameter types: the first overload
        self.assertEqual(find_definition(lines, ["a::b::C::get"]), (14, 14))  # an inline member, nested namespaces
        self.assertIsNone(find_definition(lines[4:], ["other::Flag::build"]))
        self.assertIsNone(find_definition(lines, ["b::C::get"]))  # a tail of the real name is another name
        self.assertEqual([parameter_count(s) for s in ("F::set(unsigned int, math::Col4 const&)",
                                                        "f(void (*)(int, int), int)", "F::get() const", "F::get")],
                         [2, 2, 0, None])

    def test_mcp_arguments_are_forgiving_but_strict(self):
        from zkit.server import create_server
        from mcp.server.fastmcp.exceptions import ToolError
        server = create_server(self.project)
        call = lambda name, args: asyncio.run(server.call_tool(name, args))
        text = lambda result: "".join(getattr(b, "text", "") for b in (result[0] if isinstance(result, tuple) else result))
        self.assertIn("0x80003000", text(call("zkit_asm", {"query": "0x80003000", "size": "0x8"})))
        self.assertIn("Enemy", text(call("zkit_search", {"query": "Enemy update"})))
        scoped = text(call("zkit_grounding", {"repo": "native", "path": "src/actors/Other.cpp"}))
        self.assertIn("src/actors/Other.cpp", scoped)
        with self.assertRaisesRegex(ToolError, "bogus"):
            call("zkit_grounding", {"repo": "native", "bogus": "src"})
        result = call("zkit_lookup", {"query": "0x80003000"})
        self.assertFalse(isinstance(result, tuple) and result[1])  # no duplicated structuredContent

    def test_check_reports_edited_existing_violation_as_debt(self):
        from zkit.bridge import check
        self.write_native("src/actors/Old.cpp", "// 80003000\nbool f() { return isSwamp(1); }\n")
        self.git(self.native, "add", "-A")
        self.git(self.native, "commit", "-qm", "old")
        self.write_native("src/actors/Old.cpp", "// 80003000\nbool f() { return isSwamp(2); }\n")
        rules = {f["rule"]: f["severity"] for f in check(self.project, "native")["findings"]}
        self.assertEqual(rules.get("forbidden-existing"), "info")
        self.assertNotIn("forbidden", rules)

    def test_check_reports_a_placeholder_the_symbols_carry_as_info(self):
        from zkit.bridge import check
        (self.decomp / "src/Call.cpp").write_text("void f() {\n    TPlayer__sub_80003010();\n    fn_80003030();\n}\n",
                                                  encoding="utf-8")
        found = {(f["rule"], f.get("line")): f["severity"]
                 for f in check(self.project, "decomp", paths=["src/Call.cpp"])["findings"]}
        self.assertEqual(found[("decomp-placeholder", "TPlayer__sub_80003010")], "info")
        self.assertIn(("decomp-debt-added", "fn_80003030"), found)   # no function of the symbols is named so

    def test_check_reads_placeholders_from_every_target_of_the_repository(self):
        from zkit.bridge import check
        from zkit.project import Project
        # another version of the game: its symbols name a function only it has
        (self.decomp / "config/symbols2.txt").write_text(
            "fn_80003030 = .text:0x80003030; // type:function size:0x4\n", encoding="utf-8")
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["targets"]["t2"] = dict(manifest["targets"]["t"], symbols="config/symbols2.txt",
                                         report="build/report2.json")
        manifest["targets"]["n"] = dict(manifest["targets"]["t2"], repository="native")  # another repository's
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        project = Project.load(self.manifest)
        (self.decomp / "src/Call.cpp").write_text("void f() {\n    fn_80003030();\n    fn_80003020();\n}\n",
                                                  encoding="utf-8")
        found = {(f["rule"], f.get("line")): f["severity"]
                 for f in check(project, "decomp", paths=["src/Call.cpp"])["findings"]}
        self.assertEqual(found[("decomp-placeholder", "fn_80003030")], "info")
        self.assertEqual(found[("decomp-placeholder", "fn_80003020")], "info")   # the first target's still counts
        self.assertNotIn(("decomp-debt-added", "fn_80003030"), found)
        manifest["targets"].pop("t2")
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        found = {(f["rule"], f.get("line")): f["severity"]
                 for f in check(Project.load(self.manifest), "decomp", paths=["src/Call.cpp"])["findings"]}
        self.assertIn(("decomp-debt-added", "fn_80003030"), found)   # only another repository's target names it

    def test_check_reads_a_line_inside_a_block_comment_as_comment(self):
        from zkit.bridge import check
        (self.decomp / "src/Doc.cpp").write_text("/*\n  the results are undefined.\n*/\nundefined4 g;\n",
                                                 encoding="utf-8")
        found = [(f["rule"], f["ref"]) for f in check(self.project, "decomp", paths=["src/Doc.cpp"])["findings"]
                 if f["rule"].startswith("decomp-debt")]
        self.assertEqual(found, [("decomp-debt-added", "src/Doc.cpp:4")])

    def test_check_judges_replaced_lines_against_their_whole_file(self):
        """A definition inside an `extern "C" {` block is extern "C" debt only in its file: editing it carries the debt
        over, adding a new definition inside the block adds it."""
        from zkit.bridge import check
        (self.decomp / "src/Block.cpp").write_text(
            'extern "C" {\nint hp__6TEnemyFPv(Best_80003000 *p) {\n    return 0;\n}\n}\n', encoding="utf-8")
        self.git(self.decomp, "init", "-q")
        self.git(self.decomp, "add", "-A")
        self.git(self.decomp, "commit", "-qm", "base")
        (self.decomp / "src/Block.cpp").write_text(
            'extern "C" {\nint hp__6TEnemyFPv(TUnk_80003000 *p) {\n    return 0;\n}\nint mp__6TEnemyFv(void) {\n'
            '    return 1;\n}\n}\n', encoding="utf-8")
        found = [(f["rule"], f["ref"], f["line"]) for f in check(self.project, "decomp")["findings"]
                 if f["rule"].startswith("decomp-debt") and f["line"].startswith("extern")]
        self.assertEqual(sorted(found), [("decomp-debt", "src/Block.cpp:2", 'extern "C" hp__6TEnemyFPv'),
                                         ("decomp-debt-added", "src/Block.cpp:5", 'extern "C" mp__6TEnemyFv')])

    def test_git_worktree_is_its_own_working_tree(self):
        from zkit.bridge import check
        tree = self.native.parent / "native-wt"
        self.git(self.native, "worktree", "add", "-q", "-b", "wt", str(tree))
        (tree / "src/actors/Swamp.cpp").write_text("// 80003000\nbool g() { return isSwamp(3); }\n", encoding="utf-8")
        self.assertEqual(self.project.locate(tree / "src"), ("native", str(tree.resolve())))
        self.assertEqual(self.project.locate(self.native / "src"), ("native", None))
        scoped, key = self.project.scope(str(tree))
        self.assertEqual(key, "native")
        inside = check(scoped, key)
        self.assertEqual(inside["worktree"], str(tree.resolve()))
        self.assertTrue(any(f["rule"] == "forbidden" for f in inside["findings"]))
        self.assertFalse(any(f["rule"] == "forbidden" for f in check(self.project, "native")["findings"]))

    def test_try_and_probe_compile_in_the_worktree_they_run_in(self):
        """A worker in a git worktree of the decomp compiles against that worktree's headers, not the main
        checkout's: from its cwd, from a candidate file inside it, or named with --repo."""
        import contextlib
        import io
        import os
        from unittest import mock
        from zkit import cli
        from zkit.project import tree_overlay
        self.git(self.decomp, "init", "-q")
        self.git(self.decomp, "add", "-A")
        self.git(self.decomp, "commit", "-qm", "base")
        tree = self.decomp.parent / "decomp-wt"
        self.git(self.decomp, "worktree", "add", "-q", "--detach", str(tree))
        wt = str(tree.resolve())
        here, worktree = self.project.locate(tree / "src")
        self.assertEqual(tree_overlay(self.project, "t", here, worktree).root("decomp"), tree.resolve())
        main_here, main_tree = self.project.locate(self.decomp)
        self.assertEqual(tree_overlay(self.project, "t", main_here, main_tree).root("decomp"), self.decomp.resolve())
        by_file = tree_overlay(self.project, "t", None, None, files=[tree / "src/Enemy.cpp"])
        self.assertEqual(by_file.worktree("decomp"), wt)
        self.assertIsNone(tree_overlay(self.project, "t", here, worktree, explicit=True).worktree("decomp"))
        # The build command comes from the worktree's own compile database, so `-i include` is its include/.
        from zkit import candidate
        for root in (self.decomp, tree):
            (root / "build/compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": "src/Enemy.cpp",
                "arguments": ["mwcc", "-i", "include", "-c", "src/Enemy.cpp"]}]), encoding="utf-8")
        unit = {"name": "Enemy", "base_path": "build/src/Enemy.o", "metadata": {"source_path": "src/Enemy.cpp"}}
        self.assertEqual(candidate.compile_command(by_file, "t", unit)[1], tree.resolve())
        self.assertEqual(candidate.compile_command(self.project, "t", unit)[1], self.decomp.resolve())
        seen = []
        result = {"unit": "Enemy", "source": "f.cpp", "command": "", "compiled": True, "warnings": "", "functions": []}
        fake = lambda project, *a, **k: seen.append(str(project.root("decomp"))) or result
        scratch = self.decomp.parent / "scratch"
        scratch.mkdir()
        (scratch / "f.cpp").write_text("void f() {}\n", encoding="utf-8")
        cwd = os.getcwd()
        try:
            with mock.patch("zkit.candidate.probe", fake), contextlib.redirect_stdout(io.StringIO()):
                for folder, extra in ((tree / "src", []), (self.decomp, []), (scratch, ["--repo", wt]),
                                      (tree, ["--repo", "decomp"])):
                    os.chdir(folder)
                    self.assertEqual(cli.main(["--project", str(self.manifest), "probe", "Enemy",
                                               str(scratch / "f.cpp"), *extra]), 0)
        finally:
            os.chdir(cwd)
        self.assertEqual(seen, [wt, str(self.decomp.resolve()), wt, str(self.decomp.resolve())])

    def test_cli_accepts_json_after_subcommand_and_batches_asm(self):
        from zkit import cli
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--project", str(self.manifest), "lookup", "0x80003000", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["function"]["address"], "0x80003000")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["--project", str(self.manifest), "asm", "0x80003000", "0x80003010"]), 0)
        self.assertIn("0x80003010", out.getvalue())


if __name__ == "__main__":
    unittest.main()
