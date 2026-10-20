"""Port tools judged against the decomp: readiness, port plans, the native check, fidelity views and test
selection. Each test reproduces an audited wrong or misleading answer on a synthetic decomp and port."""

import support
import asyncio
import json
import os
from pathlib import Path
import subprocess
import unittest

import test_bridge

support.ROOT  # isolated config, cache and state for this module


class PortToolTests(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def configure(self, change) -> None:
        config = json.loads(self.manifest.read_text(encoding="utf-8"))
        change(config)
        self.manifest.write_text(json.dumps(config), encoding="utf-8")
        from zkit.project import Project
        self.project = Project.load(self.manifest)

    def decomp_source(self, text: str, demangled: str = "TEnemy::update()", categories=None) -> None:
        (self.decomp / "src/Enemy.cpp").write_text(text, encoding="utf-8")
        report = json.loads((self.decomp / "build/report.json").read_text(encoding="utf-8"))
        report["units"][0]["functions"][0]["metadata"]["demangled_name"] = demangled
        (self.decomp / "build/report.json").write_text(json.dumps(report), encoding="utf-8")
        units = [{"name": "main/Enemy", "metadata": {"progress_categories": categories or ["game"]}}]
        (self.decomp / "objdiff.json").write_text(json.dumps({"units": units}), encoding="utf-8")

    def ready(self, address: int = test_bridge.TEXT) -> dict:
        from zkit.bridge import readiness
        from zkit.index import connect, containing, refresh
        refresh(self.project)
        return readiness(self.project, "t", containing(connect(self.project), "t", address))

    def commit_native(self) -> None:
        subprocess.run(["git", "-C", str(self.native), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.native), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm",
                        "x"], check=True)

    # -- readiness ---------------------------------------------------------------------------------------------

    def test_readiness_holds_placeholder_shaped_decomp(self):
        cases = {"this->m_30c = 1;": "offset-named members",
                 "x = *(f32 *)&this->unk_308;": "type-punned or cast-pointer derefs",
                 "y = *(s32 *)(this->base + 0x18);": "type-punned or cast-pointer derefs",
                 "((void (*)(TEnemy *))fn)(this);": "calls through function-pointer casts",
                 "use((ADSR_VARS_803B41C8 *)p);": "address-named types",
                 "vfunc_67__10TObjPlayerFv(this);": "vtable-slot names"}
        for body, reason in cases.items():
            self.decomp_source(f"void TEnemy::update() {{\n    {body}\n}}\n")
            ready = self.ready()
            self.assertFalse(ready["ready"], body)
            self.assertIn(reason, " ".join(ready["reasons"]), body)
        self.decomp_source("void TEnemy::update() {\n    is_flag_set__6TLobbyFv(this);\n}\n")
        ready = self.ready()  # a hand-mangled call names its callee in full: spelling debt, not a hold
        self.assertTrue(ready["ready"])
        self.assertEqual(ready["spelling"], ["hand-mangled member names x1"])
        self.decomp_source("#define enemyTab lbl_80003104\nvoid TEnemy::update() {\n    use(enemyTab);\n}\n")
        self.assertIn("enemyTab = lbl_80003104", " ".join(self.ready()["reasons"]))
        self.decomp_source("void TUnk_80001234::update() {\n}\n", demangled="TUnk_80001234::update()")
        self.assertIn("placeholder-shaped name", " ".join(self.ready()["reasons"]))

    def test_library_assembly_is_its_own_reference(self):
        self.decomp_source("asm void TEnemy::update() {\n    blr\n}\n", categories=["sdk"])
        ready = self.ready()
        self.assertEqual((ready["ready"], ready["reference"], ready["library"]), (True, "assembly", True))
        self.decomp_source("asm void TEnemy::update() {\n    blr\n}\n", categories=["game"])
        self.assertFalse(self.ready()["ready"])  # game code written as asm is not decompiled yet

    # -- port plan ---------------------------------------------------------------------------------------------

    def test_port_plan_orders_actions_and_explains_holds(self):
        from zkit.bridge import port_plan
        from zkit.render import port_plan as render_plan
        self.decomp_source("void TEnemy::update() {\n    this->m_30c = 1;\n}\n")
        plan = port_plan(self.project, "0x80003000", depth=9)
        actions = {n["address"]: n["action"] for n in plan["nodes"]}
        self.assertEqual(actions["0x80003020"], "decompile-first")  # cited but not exact: decomp work first
        self.assertEqual(actions["0x80003000"], "reuse-unverified")
        self.assertIn("capped at 4", plan["note"])
        text = render_plan(port_plan(self.project, "0x80003000 0x80003010"))
        self.assertIn("not ready: source still reads as decompiler output (offset-named members x1)", text)
        self.assertEqual(text.count("legend:"), 1)
        self.assertIn("limits:", text)
        data = render_plan(port_plan(self.project, "0x80003104"))  # data: what it is, not an empty reason
        self.assertTrue(data.startswith("0x80003104 is data, not code: enemyTable"), data)
        self.decomp_source("void TEnemy::update() {\n}\n", categories=["sdk"])
        self.assertEqual(port_plan(self.project, "0x80003000", depth=0)["root"]["action"], "platform")

    # -- native check ------------------------------------------------------------------------------------------

    def test_hold_applies_in_every_tier_and_carries_debt(self):
        from zkit.bridge import check
        self.configure(lambda c: c["repositories"]["native"].update(fidelity_tiers=[
            {"tier": "liberty", "pattern": "^src/ui/"}, {"tier": "exact", "pattern": "^src/actors/"}]))
        self.write_native("src/ui/Menu.cpp", "// forwards the walk request 80003010\nvoid walk() {}\n")
        found = [(f["rule"], f["severity"]) for f in check(self.project, "native")["findings"]
                 if f["ref"].startswith("src/ui/")]
        self.assertIn(("hold-until-clean", "error"), found)  # a citation claims behavior in any tier
        self.commit_native()
        self.write_native("src/ui/Menu.cpp", "// forwards the walk request 80003010.\nvoid walk() {}\n")
        result = check(self.project, "native")
        self.assertEqual([(f["rule"], f["severity"]) for f in result["findings"]], [("hold-existing", "info")])
        self.assertTrue(result["ok"])

    def test_citation_missing_sees_any_layout_and_header_cites(self):
        from zkit.bridge import check
        body = "".join(f"    x{i}();\n" for i in range(7))
        self.write_native("src/actors/Layout.cpp",
                          f"int multiLine(int value,\n    int other) {{\n{body}}}\n"
                          f"namespace detail {{\n    int indented(int value) {{\n{body}    }}\n}}\n"
                          f"unsigned maskOnly(unsigned v) {{\n    v &= 0x80000000U;\n{body}}}\n"
                          f"void Walker::step() {{\n{body}}}\n")
        self.write_native("src/actors/Layout.hpp", "struct Walker {\n    // Original 80003000.\n    void step();\n};\n")
        missing = {f["name"] for f in check(self.project, "native")["findings"] if f["rule"] == "citation-missing"}
        self.assertEqual(missing, {"multiLine", "indented", "maskOnly"})  # step is cited at its declaration

    def test_check_groups_repeats_and_accepts_paths_over_mcp(self):
        from zkit.bridge import check
        from zkit.render import check as render_check
        from zkit.server import create_server
        self.write_native("src/actors/Twice.cpp", "// 80003010\nvoid a() {}\n// 80003010 again\nvoid b() {}\n")
        text = render_check(check(self.project, "native"))
        self.assertEqual(text.count("hold-until-clean 0x80003010"), 1)
        self.assertIn("(2x)", text)
        self.assertIn("at src/actors/Twice.cpp:1, src/actors/Twice.cpp:3", text)

        async def scenario():
            result = await create_server(self.project).call_tool("zkit_check", {
                "repo": "native", "paths": ["src/actors"], "staged": False, "response_format": "json"})
            blocks = result[0] if isinstance(result, tuple) else result
            return json.loads("".join(b.text for b in blocks))
        data = asyncio.run(asyncio.wait_for(scenario(), 15))
        self.assertIn("src/actors/Twice.cpp:3", {f["ref"] for f in data["findings"]})  # folders expand
        with self.assertRaisesRegex(ValueError, "No such file or folder"):
            check(self.project, "native", paths=["src/nope"])

    def test_include_rules_are_part_of_the_check_with_debt(self):
        from zkit.bridge import check
        self.configure(lambda c: c["repositories"]["native"].update(architecture={
            "scan": ["src"], "include_roots": ["src"], "rules": [{
                "id": "actors-down", "sources": "^src/actors/", "forbidden_includes": "^ui/", "reason": "downward"}]}))
        self.write_native("src/ui/Menu.hpp", "// menu\n")
        self.write_native("src/actors/Uses.cpp", '#include "ui/Menu.hpp"\n#include <vector>\n')
        found = [(f["rule"], f["ref"]) for f in check(self.project, "native")["findings"] if "include" in f["rule"]]
        self.assertEqual(found, [("include-boundary", "src/actors/Uses.cpp:1")])
        self.commit_native()
        self.write_native("src/actors/Uses.cpp", '#include "ui/Menu.hpp"  // still\n#include <vector>\n')
        found = [(f["rule"], f["severity"]) for f in check(self.project, "native")["findings"] if "include" in f["rule"]]
        self.assertEqual(found, [("include-boundary-existing", "info")])
        from zkit.architecture import audit
        self.assertEqual(audit(self.project, "native", all_files=True)["system_includes"], 1)

    # -- tiers ---------------------------------------------------------------------------------------------------

    def test_unlisted_paths_are_exact_and_any_path_spelling_works(self):
        from zkit.tiers import summary, tier_of
        self.configure(lambda c: c["repositories"]["native"].update(fidelity_tiers=[
            {"tier": "liberty", "pattern": "^src/ui/"}]))
        self.assertEqual(tier_of(self.project, "native", "src/combat/DirectAttack.cpp"), "exact")
        files = summary(self.project, "native", [str(self.native / "src/actors"), "./src/actors/Enemy.cpp"])["files"]
        self.assertEqual(files["src/actors/Enemy.cpp"], "exact")
        self.assertIn("src/actors/Families.cpp", files)
        with self.assertRaises(ValueError):
            summary(self.project, "native", ["src/nope"])

    # -- constants ---------------------------------------------------------------------------------------------

    def test_constants_fold_literal_arithmetic_and_follow_header_cites(self):
        from zkit import fidelity
        self.write_native("src/actors/Tune.hpp", "struct Tune {\n    // Original 80003000.\n    float step(float x,\n"
                                                 "               float y);\n};\n")
        self.write_native("src/actors/Tune.cpp", "float Tune::step(float x,\n                 float y) {\n"
                                                 "    return x * (3.0F / 2.0F) + y * 1.49F + 2.25F;\n}\n")
        audit = fidelity.constant_audit(self.project, "native", ["src/actors/Tune.cpp"])
        kinds = {f["value"]: (f["kind"], f.get("folded")) for f in audit["findings"]}
        self.assertEqual(kinds, {1.49: ("near", None), 2.25: ("folded", "1.5*1.5")})
        self.assertEqual(audit["counts"]["verified"], 2)  # 3.0F / 2.0F folds to the 1.5 the original loads

    # -- grounding (with suspects merged in) -------------------------------------------------------------------

    def test_grounding_headline_is_readiness_and_ranks_by_share(self):
        from zkit import fidelity
        from zkit.render import grounding as render_grounding
        self.write_native("src/actors/Plain.cpp", "int plain(int v) {\n    return v + 1;\n}\n")
        data = fidelity.grounding(self.project, "native")
        total = data["total"]
        self.assertEqual((total["functions"], total["exact"], total["ready"]), (3, 2, 1))  # 80003010 is a placeholder
        self.assertEqual(total["named_pct"], 33.3)  # TPlayer__sub_80003010 and fn_80003020 are not names
        self.assertIn("src/actors/Plain.cpp", {r["path"] for r in data["uncited"]["rows"]})
        rows = {r["path"]: r for r in data["rows"]}
        self.assertTrue(any(a.startswith("clean-first") for a in rows["src/actors/Other.cpp"]["actions"]))
        self.assertIn("ready references", render_grounding(data))
        self.assertEqual(fidelity.grounding(self.project, "native", ["./src/actors/Enemy.cpp"])["total"]["functions"], 1)
        with self.assertRaises(ValueError):
            fidelity.grounding(self.project, "native", ["src/nope"])

    def test_a_linked_source_counts_as_tested(self):
        from zkit import fidelity
        build = self.native / "build"
        build.mkdir()
        self.write_native("tests/Main.cpp", "int main() { return 0; }\n")
        (build / "compile_commands.json").write_text(json.dumps([
            {"directory": str(build), "file": str(self.native / src), "output": f"CMakeFiles/{t}.dir/{src}.o"}
            for t, src in (("game", "src/actors/Other.cpp"), ("checks", "tests/Main.cpp"))]), encoding="utf-8")
        (build / "build.ninja").write_text(
            "build libgame.a: CXX_STATIC_LIBRARY_LINKER__game CMakeFiles/game.dir/src/actors/Other.cpp.o\n"
            "build checks: CXX_EXECUTABLE_LINKER__checks CMakeFiles/checks.dir/tests/Main.cpp.o libgame.a\n",
            encoding="utf-8")
        self.configure(lambda c: c["repositories"]["native"].update(tests={"build_dir": "build"}))
        rows = {r["path"]: r for r in fidelity.grounding(self.project, "native")["rows"]}
        self.assertTrue(rows["src/actors/Other.cpp"]["tested"])  # linked into the checks program, no include needed

    # -- drift ---------------------------------------------------------------------------------------------------

    def test_drift_reports_readiness_changes(self):
        from zkit import fidelity
        self.decomp_source("void TEnemy::update() {\n    this->m_30c = 1;\n}\n")
        fidelity.drift(self.project, accept=True)
        self.decomp_source("void TEnemy::update() {\n    this->speed = 1;\n}\n")
        changes = {c["address"]: c for c in fidelity.drift(self.project)["changes"]}
        self.assertEqual(changes["0x80003000"]["changes"], ["now-ready"])
        self.assertIn("src/actors/Enemy.cpp", {r["path"] for r in fidelity.drift(self.project)["reverify_files"]})

    def test_drift_is_read_only_over_mcp(self):
        from zkit.server import create_server
        tools = {t.name: t for t in create_server(self.project)._tool_manager.list_tools()}
        self.assertTrue(tools["zkit_drift"].annotations.readOnlyHint)
        self.assertNotIn("accept", tools["zkit_drift"].parameters["properties"])
        self.assertIn("since", tools["zkit_drift"].parameters["properties"])

    # -- reuse ---------------------------------------------------------------------------------------------------

    def test_reuse_compares_whole_bodies_and_names_groups(self):
        from zkit.bridge import reuse, variant_terms
        for name, body in (("A", "return std::isfinite(v);"), ("B", "return std::isfinite(v);"),
                           ("C", "return v == v;")):
            self.write_native(f"src/actors/Finite{name}.cpp", f"float isFinite(float v) {{ {body} }}\n"
                                                             f"inline const Vec& Position(const {name}State& s) "
                                                             "{ return s.p; }\n")
        data = reuse(self.project, "native")
        helpers = {d["name"]: d for d in data["identical_helpers"]}
        self.assertNotIn("isFinite", helpers)  # two copies of one body, one different: below three files
        self.assertEqual(helpers["Position"]["kind"], "same body, different parameter types")
        self.assertEqual(helpers["finite"]["kind"], "identical")
        with self.assertRaisesRegex(ValueError, "configured: families"):
            variant_terms(self.project, "no-such-family", None)
        self.assertEqual(reuse(self.project, "native", ["Wolf"])["enumeration_sites"]["files"], 2)

    # -- impact and test plans -----------------------------------------------------------------------------------

    def link_build(self) -> Path:
        build = self.native / "build"
        build.mkdir(exist_ok=True)
        self.write_native("src/world/World.hpp", "void world();\n")
        self.write_native("src/world/World.cpp", '#include "world/World.hpp"\nvoid world() {}\n')
        self.write_native("src/world/WorldSounds.cpp", '#include "world/World.hpp"\nvoid sounds() {}\n')
        self.write_native("tests/FieldChecks.cpp", "int main() { return 0; }\n")
        objects = (("game", "src/world/World.cpp"), ("game", "src/world/WorldSounds.cpp"),
                   ("field", "tests/FieldChecks.cpp"))
        (build / "compile_commands.json").write_text(json.dumps([
            {"directory": str(build), "file": str(self.native / src), "output": f"CMakeFiles/{t}.dir/{src}.o"}
            for t, src in objects]), encoding="utf-8")
        (build / "build.ninja").write_text(
            "build libgame.a: CXX_STATIC_LIBRARY_LINKER__game CMakeFiles/game.dir/src/world/World.cpp.o "
            "CMakeFiles/game.dir/src/world/WorldSounds.cpp.o\n"
            "build field: CXX_EXECUTABLE_LINKER__field CMakeFiles/field.dir/tests/FieldChecks.cpp.o libgame.a\n",
            encoding="utf-8")
        (build / "field").write_bytes(b"\x7fELF")
        test = lambda name, cost: {"name": name, "command": [str(build / "field"), name],
                                   "properties": [{"name": "LABELS", "value": ["local"]}]}
        (build / "catalog.json").write_text(json.dumps({"tests": [test("field-a", 2), test("field-b", 1)]}))
        (build / "Testing/Temporary").mkdir(parents=True)
        (build / "Testing/Temporary/CTestCostData.txt").write_text("field-a 1 2\nfield-b 1 1\n", encoding="utf-8")
        self.configure(lambda c: c["repositories"]["native"].update(tests={"build_dir": "build",
                                                                           "catalog": "build/catalog.json"}))
        return build

    def test_split_implementation_files_reach_tests_through_the_link(self):
        from zkit.native import impact
        from zkit.render import impact as render_impact
        self.link_build()
        data = impact(self.project, "native", ["src/world/WorldSounds.cpp"])
        self.assertEqual(data["groups"], {"linked": {"local": ["field-b"]}})  # cheapest test of the linking program
        self.assertEqual(data["deferred"], ["field-a"])
        self.assertEqual(data["untested_files"], [])
        text = render_impact(data)
        self.assertLess(text.index("ctest"), text.index("src/world/WorldSounds.cpp:"))  # commands come first
        self.assertEqual(impact(self.project, "native", ["src/world"])["changed"],
                         ["src/world/World.cpp", "src/world/World.hpp", "src/world/WorldSounds.cpp"])
        with self.assertRaisesRegex(ValueError, "No such file or folder"):
            impact(self.project, "native", ["src/nope.cpp"])

    def test_budget_says_when_direct_tests_alone_exceed_it(self):
        from zkit.native import impact
        self.link_build()
        self.write_native("tests/FieldChecks.cpp", '#include "world/World.hpp"\nint main() { return 0; }\n')
        data = impact(self.project, "native", ["src/world/World.hpp"], budget=0.5)
        self.assertEqual(sorted(data["groups"]["direct"]["local"]), ["field-a", "field-b"])
        self.assertIn("direct tests alone need 3.0 s recorded against the 0.5 s budget", data["notes"][0])

    def test_test_plan_reads_names_as_typed_and_counts_only_found_ones(self):
        from zkit.native import test_plan
        from zkit.render import test_plan as render_plan
        self.link_build()
        data = test_plan(self.project, "native", "field-a, missing-one")
        self.assertEqual((data["selected"], data["missing"]), (["field-a", "missing-one"], ["missing-one"]))
        self.assertTrue(render_plan(data).startswith("test plan for native: 1 selected checks (1 not in the catalog)"))

    def test_stale_lists_programs_that_are_not_linked(self):
        from zkit.native import stale
        self.link_build()
        self.assertEqual(stale(self.project, "native", ["field", "no-such-program"])["unknown_programs"],
                         ["no-such-program"])


class ScannerTests(unittest.TestCase):
    def test_definitions_in_any_layout(self):
        from zkit.cxx import definitions, scan
        text = ("namespace a {\n    int f(int x,\n          int y) {\n        return x;\n    }\n}\n"
                "struct S { int g() const { return 1; } S() : v{1}, w(2) {} int v, w; };\n"
                "enum class E : int { A, B };\nauto l = [](int x) { return x; };\n"
                "extern \"C\" {\nvoid c(void) { }\n}\nbool S::operator==(const S& o) const { return true; }\n")
        found = [(d.name, d.scope, d.in_class, d.line + 1, d.end + 1) for d in definitions(text)]
        self.assertEqual(found, [("f", "a", False, 2, 5), ("g", "S", True, 7, 7), ("S", "S", True, 7, 7),
                                 ("c", "", False, 11, 11), ("S::operator==", "", False, 13, 13)])
        self.assertEqual([d.qualified for d in definitions(text)], ["a::f", "S::g", "S::S", "c", "S::operator=="])
        self.assertEqual([(b.kind, b.name, b.open + 1, b.end + 1) for b in scan(text)[1]],
                         [("namespace", "a", 1, 6), ("class", "S", 7, 7), ("extern", "", 10, 12)])


if __name__ == "__main__":
    unittest.main()
