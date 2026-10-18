"""Synthetic decomp + native port, with a hand-assembled DOL. No game assets."""

import support  # noqa: F401  (isolates config, cache and state)
import json
import os
from pathlib import Path
import struct
import sys
import subprocess
import tempfile
import unittest

TEXT, DATA = 0x80003000, 0x80003100


def lis(rd, imm):
    return (15 << 26) | (rd << 21) | (imm & 0xFFFF)


def ori(ra, rs, imm):
    return (24 << 26) | (rs << 21) | (ra << 16) | (imm & 0xFFFF)


def addi(rd, ra, imm):
    return (14 << 26) | (rd << 21) | (ra << 16) | (imm & 0xFFFF)


def bl(site, target):
    return (18 << 26) | ((target - site) & 0x03FFFFFC) | 1


BLR = 0x4E800020
LFS_F1_R2 = (48 << 26) | (1 << 21) | (2 << 16) | 0  # lfs f1,0(r2)


def build_dol() -> bytes:
    code = [0] * 32
    # A @3000: bl B; bl C; blr      B @3010: lis/addi -> DATA+4; lfs f1,0(r2); blr
    code[0], code[1], code[2] = bl(TEXT, TEXT + 0x10), bl(TEXT + 4, TEXT + 0x20), BLR
    code[4], code[5], code[6], code[7] = lis(3, 0x8000), addi(3, 3, 0x3104), LFS_F1_R2, BLR
    code[8] = BLR  # C @3020 (not matched in the report)
    # __init_registers @3040
    code[16:21] = [lis(2, 0x8000), ori(2, 2, 0x3100), lis(13, 0x8000), ori(13, 13, 0x3100), BLR]
    text = struct.pack(">32I", *code)
    data = struct.pack(">fI", 1.5, TEXT)
    offsets, addresses, sizes = [0] * 18, [0] * 18, [0] * 18
    offsets[0], addresses[0], sizes[0] = 0x100, TEXT, len(text)
    offsets[7], addresses[7], sizes[7] = 0x100 + len(text), DATA, len(data)
    header = struct.pack(">18I18I18I3I", *offsets, *addresses, *sizes, 0, 0, TEXT).ljust(0x100, b"\0")
    return header + text + data


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from zkit.index import close_connections
        self.addCleanup(close_connections)  # runs first: Windows cannot delete an open database
        base = Path(self.temp.name)
        for var in ("XDG_CACHE_HOME", "XDG_STATE_HOME"):
            os.environ[var] = str(base / var.lower())
        os.environ["ZKIT_REFRESH_TTL"] = "0"  # every query must see the edits each test makes
        self.decomp, self.native = base / "decomp", base / "native"
        for directory in ["src", "docs", "build", "config"]:
            (self.decomp / directory).mkdir(parents=True)
        for directory in ["src/actors", "docs", "tests/fidelity"]:
            (self.native / directory).mkdir(parents=True)
        (self.decomp / "orig.dol").write_bytes(build_dol())
        (self.decomp / "AGENTS.md").write_text("## Finish a Session\n\n```\nninja\ntools/validate.py all\n```\n## Next\n", encoding="utf-8")
        (self.decomp / "src/Enemy.cpp").write_text("void TEnemy::update() {\n}\nvoid helper() {\n}\n", encoding="utf-8")
        (self.decomp / "docs/ENEMY.md").write_text("Enemy update 80003000 calls 80003010.\n", encoding="utf-8")
        (self.decomp / "config/symbols.txt").write_text(
            "update__6TEnemyFv = .text:0x80003000; // type:function size:0xC\n"
            "TPlayer__sub_80003010 = .text:0x80003010; // type:function size:0x10\n"
            "fn_80003020 = .text:0x80003020; // type:function size:0x4\n"
            "__init_registers = .init:0x80003040; // type:function size:0x14 scope:local\n"
            "lbl_80003100 = .sdata2:0x80003100; // type:object size:0x4\n"
            "enemyTable = .data:0x80003104; // type:object size:0x4\n")
        functions = [("update__6TEnemyFv", "TEnemy::update()", TEXT, 12, 100.0),
                     ("TPlayer__sub_80003010", None, TEXT + 0x10, 16, 100.0),
                     ("fn_80003020", None, TEXT + 0x20, 4, None),
                     ("__init_registers", None, TEXT + 0x40, 20, 100.0)]
        report = {"measures": {"matched_functions": 3, "total_functions": 4}, "units": [{
            "name": "main/Enemy", "metadata": {"module_name": "main", "source_path": "src/Enemy.cpp", "complete": True},
            "functions": [dict({"name": n, "size": str(s), "metadata": {"virtual_address": str(a),
                                                                       **({"demangled_name": d} if d else {})}},
                               **({"fuzzy_match_percent": m} if m is not None else {}))
                          for n, d, a, s, m in functions]}]}
        (self.decomp / "build/report.json").write_text(json.dumps(report), encoding="utf-8")
        (self.decomp / "build/.lock").write_text("pid 1 (old)", encoding="utf-8")
        self.write_native("src/actors/Enemy.cpp",
                          "// Original enemy update 80003000.\nvoid EnemyController::update() {\n  step();\n}\n"
                          "float finite(float v) {\n  return v;\n}\n")
        self.write_native("src/actors/Other.cpp", "// helperOriginal80003020 and 80003010\nfloat finite(float v) {\n  return v;\n}\n")
        self.write_native("src/actors/Third.cpp", "float finite(float v) {\n  return v;\n}\n// Bear Wolf Bird\n")
        self.write_native("src/actors/Families.cpp", "// Bear Wolf Bird table\n")
        self.write_native("tests/fidelity/enemy.json", json.dumps({"boundary": "update 80003000"}))
        subprocess.run(["git", "init", "-q", str(self.native)], check=True)
        subprocess.run(["git", "-C", str(self.native), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.native), "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-qm", "init"], check=True)
        self.manifest = base / "project.json"
        self.manifest.write_text(json.dumps({
            "schema_version": 1, "id": "synthetic", "knowledge": "knowledge",
            "repositories": {
                "decomp": {"root": "decomp", "role": "decomp", "index_paths": ["AGENTS.md", "docs", "src"],
                           "cite_paths": ["docs"], "locks": ["build/.lock"],
                           "finish": ["ninja", "tools/validate.py all", "tools/verify.py check"],
                           "finish_sources": [{"path": "AGENTS.md", "after": "## Finish a Session", "until": "^## "}]},
                "native": {"root": "native", "role": "native", "index_paths": ["src", "docs", "tests/fidelity"],
                           "cite_paths": ["src", "docs", "tests/fidelity"], "recipes": "tests/fidelity",
                           "checks": {"require_citation": True, "citation_min_lines": 1,
                                      "forbidden": [{"pattern": "isSwamp", "paths": "^src/",
                                                     "message": "no swamp-only branches"}]}}},
            "targets": {"t": {"repository": "decomp", "module": "main", "report": "build/report.json",
                              "symbols": "config/symbols.txt", "original": "orig.dol"}},
            "variants": {"families": ["Bear", "Wolf", "Bird"]}}))
        (base / "knowledge").mkdir()
        (base / "knowledge/lock.md").write_text("---\ntitle: Lock gotcha\napplies: decomp\nkind: gotcha\n---\nBody.\n", encoding="utf-8")
        from zkit.project import Project
        self.project = Project.load(self.manifest)

    def write_native(self, rel, text):
        path = self.native / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_dol_and_direct_calls(self):
        from zkit.gc import Dol, direct_calls
        dol = Dol.load(self.decomp / "orig.dol")
        self.assertEqual(direct_calls(dol, TEXT, 12), [(TEXT, TEXT + 0x10), (TEXT + 4, TEXT + 0x20)])
        backwards = struct.pack(">I", bl(TEXT + 0x20, TEXT))
        self.assertEqual((struct.unpack(">I", backwards)[0] >> 26), 18)
        self.assertEqual(struct.unpack(">f", dol.read(DATA, 4))[0], 1.5)
        with self.assertRaises(ValueError):
            dol.read(0x81000000, 4)

    def test_index_is_incremental(self):
        from zkit.index import refresh
        first = refresh(self.project)
        self.assertGreater(first["files_reindexed"], 4)
        self.assertEqual(refresh(self.project)["files_reindexed"], 0)
        self.write_native("src/actors/New.cpp", "// 80003010\n")
        self.assertEqual(refresh(self.project)["files_reindexed"], 1)
        (self.native / "src/actors/New.cpp").unlink()
        self.assertEqual(refresh(self.project)["files_removed"], 1)

    def test_lookup_joins_both_repos(self):
        from zkit.bridge import lookup
        data = lookup(self.project, "TEnemy::update")
        self.assertEqual(data["function"]["source"], "src/Enemy.cpp")
        self.assertEqual(data["function"]["source_line"], 1)
        self.assertEqual([c["address"] for c in data["callees"]], ["0x80003010", "0x80003020"])
        self.assertIn("src/actors/Enemy.cpp", {c["path"] for c in data["native_cites"]})
        self.assertEqual(data["recipes"], ["tests/fidelity/enemy.json"])
        callee = lookup(self.project, "0x80003014")  # interior address
        self.assertEqual(callee["function"]["name"], "TPlayer__sub_80003010")
        self.assertEqual(callee["callers"]["count"], 1)
        # A glued citation (helperOriginal80003020) still counts.
        self.assertTrue(any(c["path"] == "src/actors/Other.cpp" for c in lookup(self.project, "0x80003020")["native_cites"]))
        data = lookup(self.project, "0x80003104")
        self.assertFalse(data["found"])
        self.assertEqual(data["symbol"]["name"], "enemyTable")

    def test_port_plan_and_demand(self):
        from zkit.bridge import demand, port_plan
        plan = port_plan(self.project, "0x80003000", depth=1)
        actions = {n["address"]: n["action"] for n in plan["nodes"]}
        self.assertEqual(actions, {"0x80003000": "reuse", "0x80003010": "reuse-unverified", "0x80003020": "decompile-first"})
        self.assertIn("placeholder name", next(n for n in plan["nodes"] if n["address"] == "0x80003010")["not_ready"])
        rows = {r["address"]: r["need"] for r in demand(self.project)["rows"]}
        self.assertEqual(rows["0x80003020"], ["match", "name"])
        self.assertEqual(rows["0x80003010"], ["name"])
        self.assertNotIn("0x80003000", rows)

    def test_check_judges_only_added_lines(self):
        from zkit.bridge import check
        self.assertEqual(check(self.project, "native")["findings"], [])
        self.write_native("src/actors/Enemy.cpp", (self.native / "src/actors/Enemy.cpp").read_text(encoding="utf-8") +
                          "void tick() {\n  if (isSwamp) {}\n}\n" + "\n" * 20 + "int x; // typo 80009999\n")
        found = {f["rule"] for f in check(self.project, "native")["findings"]}
        self.assertEqual(found, {"citation-unresolved", "forbidden", "citation-missing"})
        self.assertFalse(check(self.project, "native")["ok"])

    def test_reuse_finds_copies_and_dispatch_sites(self):
        from zkit.bridge import reuse
        data = reuse(self.project, "native", ["Bear", "Wolf", "Bird"])
        self.assertEqual(data["identical_helpers"][0]["name"], "finite")
        self.assertEqual(data["identical_helpers"][0]["copies"], 3)
        self.assertEqual({r["path"] for r in data["enumeration_sites"]["rows"]},
                         {"src/actors/Families.cpp", "src/actors/Third.cpp"})

    def test_data_lookup_lists_table_slots_and_typed_queries(self):
        from zkit.bridge import lookup, typed_query
        from zkit.render import lookup as render_lookup
        text = render_lookup(lookup(self.project, "enemyTable"))
        self.assertTrue(text.startswith("0x80003104 is data, not code: enemyTable"), text)
        self.assertIn("+0x0 (slot 0) -> 0x80003000 TEnemy::update()", text)
        self.assertEqual(typed_query("0x804CCE50:ptr:12", "u32", 16), ("0x804CCE50", "ptr", 12))
        self.assertEqual(typed_query("lbl_80003100:f32", "u32", 16), ("lbl_80003100", "f32", 16))
        self.assertEqual(typed_query("TEnemy::update", "u32", 16), ("TEnemy::update", "u32", 16))

    def test_disasm_and_data(self):
        from zkit.gc import Dol
        from zkit.inspect_dol import disasm, read_data, sda_bases
        self.assertEqual(sda_bases(self.project, "t", Dol.load(self.decomp / "orig.dol")), {2: DATA, 13: DATA})
        text = disasm(self.project, "t", TEXT + 0x10)["text"]
        if "objdump" in disasm(self.project, "t", TEXT)["disassembler"]:
            self.assertIn("=0x80003104 enemyTable", text)
            self.assertIn("=0x80003100 lbl_80003100 = 1.5", text)
        rows = read_data(self.project, "t", DATA, fields=["f32", "ptr"], count=1)["rows"]
        self.assertEqual(rows[0]["values"], [1.5, "0x80003000 (TEnemy::update())"])

    def test_gate_drift_brief_handoff_and_locks(self):
        from zkit.activity import activity, write_handoff
        from zkit.session import brief, gate
        drift = gate(self.project, "decomp")["drift"]
        self.assertEqual(drift[0]["missing"], ["tools/verify.py check"])
        write_handoff(self.project, "native", "Bird idle verified; next: wire Wolf")
        if sys.platform.startswith("linux"):  # lock holders come from /proc/locks
            import fcntl
            with (self.decomp / "build/.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                locks = activity(self.project)["locks"]
                self.assertTrue(locks[0]["held"])
                self.assertEqual(locks[0]["holder_pid"], os.getpid())
            self.assertIn("stale", activity(self.project)["locks"][0]["note"])
        data = brief(self.project, "native")
        self.assertEqual(data["repos"]["native"]["handoffs"][0]["text"], "Bird idle verified; next: wire Wolf")
        self.assertIn("port_demand", data)
        from zkit.render import brief as render_brief
        self.assertIn("handoff", render_brief(data))

    def test_cli_and_hook(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"), ZKIT_PROJECT=str(self.manifest))
        run = lambda *a: subprocess.run([sys.executable, "-m", "zkit.cli", *a], capture_output=True, text=True,
                                        env=env, cwd=self.native, timeout=60)
        self.assertIn("TEnemy::update()", run("lookup", "80003000").stdout)
        self.assertIn("finite", run("reuse", "native").stdout)
        hook = json.loads(run("hook", "session-start").stdout)
        self.assertIn("native (native)", hook["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(run("lookup", "nothing-like-this").returncode, 0)
        self.assertEqual(run("lessons", "missing").returncode, 2)



    def test_native_impact_and_grounding(self):
        from zkit.fidelity import grounding
        from zkit.native import impact
        build = self.native / "build"
        build.mkdir()
        self.write_native("src/actors/Locomotion.hpp", "// 80003010\nfloat step();\n")
        self.write_native("src/actors/Wolf.hpp", '#include "actors/Locomotion.hpp"\n')
        self.write_native("src/actors/Bear.hpp", '#include "actors/Locomotion.hpp"\n')
        self.write_native("tests/Main.cpp", 'int main(int c,char**v){ if(v[1]==std::string("--wolf")) {\n runWolfTests();\n}'
                                            ' if(v[1]==std::string("--other")) {\n runOtherTests(); } }\n')
        self.write_native("tests/WolfTests.cpp", '#include "actors/Wolf.hpp"\nvoid runWolfTests() {\n}\n')
        self.write_native("tests/OtherTests.cpp", 'void runOtherTests() {\n}\n')
        self.write_native("tests/LocoTests.cpp", '#include "actors/Locomotion.hpp"\nint main() {\n}\n')
        obj = lambda target, src: {"directory": str(build), "file": str(self.native / src), "command": "c++",
                                   "output": f"{build}/CMakeFiles/{target}.dir/{src}.o"}
        (build / "compile_commands.json").write_text(json.dumps([
            obj("suite", "tests/Main.cpp"), obj("suite", "tests/WolfTests.cpp"), obj("suite", "tests/OtherTests.cpp"),
            obj("loco", "tests/LocoTests.cpp")]))
        test = lambda name, cmd, label: {"name": name, "command": cmd,
                                         "properties": [{"name": "LABELS", "value": [label]}]}
        (build / "catalog.json").write_text(json.dumps({"tests": [
            test("wolf", [f"{build}/suite", "--wolf"], "unit"), test("other", [f"{build}/suite", "--other"], "unit"),
            test("loco", [f"{build}/loco"], "reference"), test("build-suite", ["/usr/bin/cmake", "--build"], "unit")]}))
        config = json.loads(self.manifest.read_text(encoding="utf-8"))
        config["repositories"]["native"]["tests"] = {"build_dir": "build", "catalog": "build/catalog.json"}
        self.manifest.write_text(json.dumps(config), encoding="utf-8")
        from zkit.project import Project
        project = Project.load(self.manifest)
        data = impact(project, "native", ["src/actors/Locomotion.hpp"])
        self.assertEqual(data["files"][0]["consumers"], ["src/actors/Bear.hpp", "src/actors/Wolf.hpp"])
        self.assertEqual(data["groups"]["direct"], {"reference": ["loco"]})
        self.assertEqual(data["groups"]["near"], {"unit": ["wolf"]})  # "other" shares the binary, not the code
        self.assertIn("-R '^(loco)$'", data["commands"]["direct/reference"])
        ground = grounding(project, "native", ["src/actors"])
        self.assertEqual((ground["total"]["functions"], ground["total"]["exact"]), (3, 2))  # 80003020 is unmatched
        self.assertEqual(ground["rows"][0]["path"], "src/actors/Other.cpp")

    def test_dol_inside_disc_image(self):
        from zkit.gc import Dol
        dol = build_dol()
        disc = bytearray(0x10000)
        disc[0:6] = b"GTEST1"
        disc[0x1C:0x20] = struct.pack(">I", 0xC2339F3D)
        disc[0x420:0x424] = struct.pack(">I", 0x2000)
        disc[0x2000:0x2000 + len(dol)] = dol
        (self.decomp / "game.iso").write_bytes(bytes(disc))
        image = Dol.load(self.decomp / "game.iso")
        self.assertEqual(image.read(TEXT, 4), Dol.load(self.decomp / "orig.dol").read(TEXT, 4))
        self.assertEqual(len(image.raw), len(dol))


    def test_repo_aliases(self):
        self.assertEqual(self.project.repo_key("native"), "native")
        self.assertEqual(self.project.repo_key("decomp"), "decomp")
        self.assertEqual(self.project.repo_key(str(self.native)), "native")
        with self.assertRaises(ValueError):
            self.project.repo_key(str(self.native / "src"))  # a path inside a repo is a file argument
        with self.assertRaisesRegex(ValueError, "use one of"):
            self.project.repo_key("nonsense")


    def test_constants_suspects_and_drift(self):
        from zkit import fidelity
        # Function A (80003000) calls B, which loads 1.5 through r2: 1.5 verified, 1.49 near, 7.25 unsourced.
        self.write_native("src/actors/Tuning.cpp", "// Original 80003000.\nfloat tune(float x) {\n"
                                                   "  return x * 1.5F + 1.49F + 7.25F;\n}\n")
        audit = fidelity.constant_audit(self.project, "native", ["src/actors/Tuning.cpp"])
        self.assertEqual({f["kind"]: f["value"] for f in audit["findings"]}, {"near": 1.49, "unsourced": 7.25})
        self.assertEqual(audit["counts"]["verified"], 1)
        ranked = {r["path"]: r for r in fidelity.grounding(self.project, "native")["rows"]}
        self.assertTrue(any("decompile-first" in a for a in ranked["src/actors/Other.cpp"]["actions"]))
        self.assertEqual(ranked["src/actors/Tuning.cpp"]["near_constants"], 1)

        self.assertEqual(fidelity.drift(self.project)["baseline"], "none")    # reading never writes
        fidelity.drift(self.project, accept=True)
        report = json.loads((self.decomp / "build/report.json").read_text(encoding="utf-8"))
        functions = report["units"][0]["functions"]
        functions[2]["fuzzy_match_percent"] = 100.0           # fn_80003020 becomes exact...
        functions[2]["name"] = "TEnemy__helper"                # ...and gets renamed
        (self.decomp / "build/report.json").write_text(json.dumps(report), encoding="utf-8")
        (self.decomp / "src/Enemy.cpp").write_text("void TEnemy::update() {\n  changed();\n}\nvoid helper() {\n}\n", encoding="utf-8")
        changes = {c["address"]: c["changes"] for c in fidelity.drift(self.project)["changes"]}
        self.assertIn("now-exact", changes["0x80003020"])
        self.assertEqual(fidelity.drift(self.project)["not_listed"].get("renamed"), 1)  # counted, not a re-verify row
        quiet = fidelity.drift(self.project)["not_listed"]
        self.assertEqual(quiet.get("edited-but-still-exact"), 1)  # same bytes before and after: not a re-verify row
        self.assertNotIn("0x80003000", changes)
        files = {r["path"] for r in fidelity.drift(self.project)["reverify_files"]}
        self.assertIn("src/actors/Other.cpp", files)
        fidelity.drift(self.project, accept=True)
        self.assertEqual(fidelity.drift(self.project)["changes"], [])


    def test_fidelity_tiers_scope_the_checks(self):
        from zkit import fidelity
        from zkit.bridge import check
        from zkit.project import Project
        from zkit.tiers import tier_of
        config = json.loads(self.manifest.read_text(encoding="utf-8"))
        config["repositories"]["native"]["fidelity_tiers"] = [
            {"tier": "liberty", "pattern": "^src/ui/", "meaning": "menus"},
            {"tier": "exact", "pattern": "^src/", "meaning": "behavior"}]
        self.manifest.write_text(json.dumps(config), encoding="utf-8")
        project = Project.load(self.manifest)
        body = "// Original 80003000.\nfloat tune(float x) {\n  return x * 1.49F;\n}\nvoid fresh() {\n  a();\n}\n"
        self.write_native("src/ui/Menu.cpp", body)
        self.write_native("src/actors/Rule.cpp", body)
        self.assertEqual(tier_of(project, "native", "src/ui/Menu.cpp"), "liberty")
        self.assertEqual(tier_of(project, "native", "src/anything/New.cpp"), "exact")  # unlisted = exact
        refs = {f["ref"].split(":")[0] for f in fidelity.constant_audit(project, "native")["findings"]}
        self.assertEqual(refs, {"src/actors/Rule.cpp"})
        found = {(f["rule"], f["ref"].split(":")[0]) for f in check(project, "native")["findings"]}
        self.assertIn(("citation-missing", "src/actors/Rule.cpp"), found)
        self.assertIn(("constant-near-miss", "src/actors/Rule.cpp"), found)
        self.assertFalse(any(path == "src/ui/Menu.cpp" for _, path in found))


    def test_review_regressions(self):
        from zkit import bridge, fidelity, inspect_dol
        from zkit.gc import track_addresses
        # Option injection through base is refused and nothing is written.
        target = self.native / "pwned.txt"
        with self.assertRaises(ValueError):
            bridge.check(self.project, "native", base=f"--output={target}")
        self.assertFalse(target.exists())
        # Non-ASCII file names and ./ paths are judged, not silently skipped.
        self.write_native("src/actors/Énemy.cpp", "void x() { if (isSwamp) {} }\n")
        refs = {f["ref"] for f in bridge.check(self.project, "native")["findings"]}
        self.assertIn("src/actors/Énemy.cpp:1", refs)
        self.assertTrue(bridge.check(self.project, "native", paths=["./src/actors/Énemy.cpp"])["stats"])
        # --staged judges the index content, not the working tree.
        subprocess.run(["git", "-C", str(self.native), "add", "src/actors/Énemy.cpp"], check=True)
        self.write_native("src/actors/Énemy.cpp", "void x() {}\n")
        staged = {f["rule"] for f in bridge.check(self.project, "native", staged=True)["findings"]}
        self.assertIn("forbidden", staged)
        self.assertNotIn("forbidden", {f["rule"] for f in bridge.check(self.project, "native")["findings"]})
        # A missing original DOL degrades the constant audit instead of failing the whole check.
        (self.decomp / "orig.dol").rename(self.decomp / "orig.bak")
        try:
            result = bridge.check(self.project, "native", paths=["src/actors/Enemy.cpp"])
            self.assertIn("constants-skipped", {f["rule"] for f in result["findings"]})
        finally:
            (self.decomp / "orig.bak").rename(self.decomp / "orig.dol")
        # lis/addi chains: the later load uses the full computed address, not the stale high half.
        words = [lis(3, 0x8000), addi(3, 3, 0x3104), (32 << 26) | (4 << 21) | (3 << 16), BLR]
        self.assertEqual(track_addresses(words, TEXT, {})[TEXT + 8], (0x80003104, "load"))
        self.assertEqual(track_addresses([lis(3, 0x8000), bl(TEXT + 4, TEXT), addi(4, 3, 4)], TEXT, {}), {})
        # Sizes that are not word multiples do not crash the raw-word disassembly.
        self.assertTrue(inspect_dol.disasm(self.project, "t", TEXT, 6)["text"])
        # Without the objdiff report, drift refuses to judge instead of reporting everything as regressed.
        fidelity.drift(self.project, accept=True)
        (self.decomp / "build/report.json").rename(self.decomp / "build/report.bak")
        try:
            self.assertEqual(fidelity.drift(self.project)["changes"], [])
        finally:
            (self.decomp / "build/report.bak").rename(self.decomp / "build/report.json")


class FirstCommitTests(unittest.TestCase):
    def test_the_staged_change_of_a_first_commit_is_everything_staged(self):
        from zkit import bridge
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "README.md").write_text("a\nb\n")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            self.assertEqual(bridge._changed_files(root, staged=True), {"README.md": {1, 2}})
            with self.assertRaises(ValueError):
                bridge._resolve_base(root, "main~3")             # only an unborn HEAD stands for the empty tree


class DemangleTests(unittest.TestCase):
    def test_codewarrior_members(self):
        from zkit.index import cw_demangle
        self.assertEqual(cw_demangle("execute__7Actor_cFv"), "Actor_c::execute")
        self.assertEqual(cw_demangle("__ct__6TEnemyFPv"), "TEnemy::TEnemy")
        self.assertEqual(cw_demangle("__dt__6TEnemyFv"), "TEnemy::~TEnemy")
        self.assertIsNone(cw_demangle("fn_80003020"))
        self.assertIsNone(cw_demangle("__init_registers"))


if __name__ == "__main__":
    unittest.main()
