import support  # noqa: F401  (isolates config, cache and state)
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from zkit import hygiene, progress, quality
from zkit.project import Project

IDENTITY = "Dev Person <dev@example.org>"


def git(root: Path, *args: str, author: str = IDENTITY) -> str:
    name, email = author.split(" <")
    env = dict(os.environ, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email.rstrip(">"),
               GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email.rstrip(">"))
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True,
                          env=env).stdout


def report(functions: list[tuple[str, str, int, int, float]], data: list[tuple[str, str, int, int, float]],
           linked: set[str] = frozenset()) -> dict:
    """functions: (unit, name, address, size, match); data: (unit, section, address, size, match)."""
    units: dict[str, dict] = {}
    for unit, name, address, size, match in functions:
        u = units.setdefault(unit, {"name": unit, "functions": [], "sections": [],
                                    "metadata": {"module_name": "main", "complete": unit in linked}})
        u["functions"].append({"name": name, "size": str(size), "fuzzy_match_percent": match,
                               "metadata": {"virtual_address": str(address)}})
    for unit, section, address, size, match in data:
        u = units.setdefault(unit, {"name": unit, "functions": [], "sections": [],
                                    "metadata": {"module_name": "main", "complete": unit in linked}})
        u["sections"].append({"name": section, "size": str(size), "fuzzy_match_percent": match,
                              "metadata": {"virtual_address": str(address)}})
    exact = sum(size for _, _, _, size, match in functions if match == 100)
    return {"version": 2, "units": list(units.values()), "categories": [],
            "measures": {"total_code": str(sum(f[3] for f in functions)), "matched_code": str(exact),
                         "total_functions": len(functions),
                         "matched_functions": sum(1 for f in functions if f[4] == 100),
                         "total_data": str(sum(d[3] for d in data)),
                         "matched_data": str(sum(d[3] for d in data if d[4] == 100))}}


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.before = report([("main/a", "f", 0x80001000, 0x20, 100.0), ("main/a", "g", 0x80001020, 0x10, 90.0)],
                             [("main/a", ".data", 0x80100000, 0x40, 100.0)], linked={"main/a"})

    def test_rename_and_fold_are_not_losses(self):
        after = report([("main/b", "TClass::f", 0x80001000, 0x20, 100.0), ("main/b", "g", 0x80001020, 0x10, 95.0)],
                       [("main/b", ".data", 0x80100000, 0x20, 100.0), ("main/c", ".data", 0x80100020, 0x20, 100.0)],
                       linked={"main/b", "main/c"})
        delta = progress.compare(self.before, after)
        self.assertTrue(delta["ok"], delta["failures"])
        self.assertEqual([r["after"] for r in delta["renamed"]], ["TClass::f"])
        self.assertEqual([r["address"] for r in delta["improved"]], ["0x80001020"])

    def test_a_unit_renamed_into_another_folder_stays_in_its_module(self):
        """objdiff's report drops the module the project gives, so a unit renamed from `game/x` to `lib/y` would
        seem to move its functions to another module; in a target with one module it does not."""
        def bare(text_unit):
            out = report([(text_unit, "f", 0x80001000, 0x20, 0.0)], [(text_unit, ".data", 0x80100000, 0x40, 0.0)])
            for unit in out["units"]:
                unit["metadata"].pop("module_name")
            return out
        before, after = bare("game/x"), bare("lib/y")
        self.assertFalse(progress.compare(before, after)["ok"])           # by folder: a function disappeared
        self.assertTrue(progress.compare(before, after, "main")["ok"], progress.compare(before, after, "main"))

    def test_losses_are_named(self):
        after = copy.deepcopy(self.before)
        after["units"][0]["functions"][0]["fuzzy_match_percent"] = 99.0
        after["units"][0]["sections"][0]["fuzzy_match_percent"] = 50.0
        after["units"][0]["metadata"]["complete"] = False
        delta = progress.compare(self.before, after)
        self.assertFalse(delta["ok"])
        self.assertEqual([r["address"] for r in delta["regressed"]], ["0x80001000"])
        self.assertEqual(delta["exact_data_lost"][0]["size"], 0x40)
        self.assertEqual(len(delta["unlinked"]), 2)

    def test_summary_page_and_baselines(self):
        summary = progress.summary(self.before)
        self.assertEqual(summary["modules"][0]["measures"]["complete_units"], 1)
        page = progress.page([("T", self.before)], "Game <script>")
        self.assertIn("Game &lt;script&gt;", page)
        self.assertNotIn("</script><script>", page.split('id="data"')[1].split("</script>")[0])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build").mkdir()
            (root / "build/report.json").write_text(json.dumps(self.before), encoding="utf-8")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "prog", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}, "targets": {"t": {
                "repository": "decomp", "module": "main", "report": "build/report.json"}}}), encoding="utf-8")
            project = Project.load(manifest)
            first = progress.save_baseline(project, "t", "session:test")
            self.assertEqual(progress.save_baseline(project, "t", "again")["name"], first["name"])  # unchanged
            self.assertTrue(progress.since(project, "t")["ok"])
            index = progress.write_page(project, ["t"], root / "out")
            self.assertTrue(index.read_text(encoding="utf-8").startswith("<!doctype html>"))
            self.assertEqual(json.loads((root / "out/t.json").read_text(encoding="utf-8")), self.before)

    def test_page_shows_where_report_totals_differ_from_its_units(self):
        counts = {"total_code": "48", "matched_code": "32", "total_functions": 2, "matched_functions": 1}
        consistent = {"version": 2, "measures": dict(counts), "units": [
            {"name": "main/a", "metadata": {"module_name": "main"}, "measures": dict(counts), "sections": [],
             "functions": [{"name": "f", "size": "32", "fuzzy_match_percent": 100.0,
                            "metadata": {"virtual_address": "2147487744"}}]}]}
        changed = copy.deepcopy(consistent)
        changed["measures"]["total_code"] = "52"
        data = lambda report: json.loads(progress.page([("T", report)], "Game").split(
            'id="data" type="application/json">')[1].split("</script>")[0])["reports"][0]
        self.assertEqual((data(consistent)["differences"], data(consistent)["file"]), ({}, "T.json"))
        self.assertEqual(data(changed)["differences"], {"total_code": {"report": 52, "units": 48}})

    def test_readme_progress_table_between_markers_or_added(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build").mkdir()
            (root / "build/report.json").write_text(json.dumps(self.before), encoding="utf-8")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "readme", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}, "targets": {"t": {
                "repository": "decomp", "module": "main", "report": "build/report.json"}}}), encoding="utf-8")
            project = Project.load(manifest)
            readme = root / "README.md"
            readme.write_text("# Game\n\nAbout it.\n\n## Building\n\nninja\n", encoding="utf-8")
            self.assertTrue(progress.write_readme(project, ["t"], readme))
            text = readme.read_text(encoding="utf-8")
            self.assertLess(text.index("## Progress"), text.index("## Building"))
            self.assertIn("| Code |", text.split(progress.README_START)[1].split(progress.README_END)[0])
            self.assertFalse(progress.write_readme(project, ["t"], readme))      # same report: no change
            self.assertEqual(text.count(progress.README_START), 1)


class QualityTests(unittest.TestCase):
    def test_counts_patterns_and_compares_revisions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            dirty = ('extern "C" void update__6TEnemyFv(void *arg0) {\n'
                     '    s32 temp_r3 = *(s32 *)((u8 *)arg0 + 0x10); // M2C_FIELD in a comment is ignored\n'
                     '    fn_80012345(lbl_80450000, temp_r3);\n}\n')
            (root / "src/enemy.cpp").write_text(dirty, encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add enemy")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "q", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}}), encoding="utf-8")
            project = Project.load(manifest)
            counts = {c["key"]: c["count"] for c in quality.audit(project, "decomp")["counts"]}
            for key in ("extern_c", "mangled_member", "raw_offset", "decomp_temp", "arg_name", "function_placeholder",
                        "data_label"):
                self.assertGreater(counts[key], 0, key)
            self.assertEqual(counts["m2c_macro"], 0)
            (root / "src/enemy.cpp").write_text(
                "void TEnemy::update() {\n    s32 hp = this->hit_points;\n    take_damage(hp);\n}\n", encoding="utf-8")
            delta = quality.compare(project, "decomp", "HEAD")
            self.assertLess(delta["total"]["delta"], 0)
            self.assertEqual(delta["worse"], [])
            self.assertEqual(quality.audit(project, "decomp", revision="HEAD")["total"],
                             quality.compare(project, "decomp", "HEAD")["total"]["before"])

    def test_function_body_findings_skip_comments(self):
        catalog = quality.patterns()
        self.assertEqual(quality.findings("// raw *(u8 *)((u8 *)p + 0x10)\nreturn this->x;", catalog), [])
        self.assertTrue(quality.findings("return *(s32 *)((u8 *)p + 0x10);", catalog))


class HygieneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "README.md").write_text("# Game\n\nSee [docs/arch.md](docs/arch.md).\n", encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs/arch.md").write_text("Run tools/build.py.\n", encoding="utf-8")
        (self.root / "tools").mkdir()
        (self.root / "tools/build.py").write_text("print('build')\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Add the build")
        manifest = self.root / "p.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "h", "repositories": {
            "game": {"root": ".", "role": "decomp", "hygiene": {"identity": IDENTITY}}}}), encoding="utf-8")
        (self.root / ".git/info/exclude").write_text("p.json\n", encoding="utf-8")
        self.project = Project.load(manifest)

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_repository(self):
        result = hygiene.audit(self.project, "game")
        self.assertTrue(result["ok"], result)

    def test_upward_links_and_a_target_s_own_files_are_not_orphans(self):
        (self.root / "docs/notes.md").write_text("Units: [notes](../NOTES.txt).\n", encoding="utf-8")
        (self.root / "NOTES.txt").write_text("linked from docs/notes.md\n", encoding="utf-8")
        (self.root / "README.md").write_text("# Game\n\n[arch](docs/arch.md), [notes](docs/notes.md)\n",
                                             encoding="utf-8")
        (self.root / "config").mkdir()
        (self.root / "config/splits.txt").write_text("game/a.cpp:\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Add notes and splits")
        manifest = json.loads((self.root / "p.json").read_text(encoding="utf-8"))
        manifest["targets"] = {"t": {"repository": "game", "module": "main", "splits": "config/splits.txt"}}
        (self.root / "p.json").write_text(json.dumps(manifest), encoding="utf-8")
        found = hygiene.files(Project.load(self.root / "p.json"), "game")["findings"]
        self.assertEqual([f["path"] for f in found if f["kind"] == "orphan-doc"], [])

    def test_finds_what_must_not_be_committed(self):
        (self.root / "AGENTS.md").write_text("agent rules\n", encoding="utf-8")
        (self.root / "docs/TU_RECOVERY_2026_10_09.md").write_text("Later on 2026-10-09 we did things.\n",
                                                                     encoding="utf-8")
        (self.root / "tools/wave7_probe.py").write_text("print(1)\n", encoding="utf-8")
        (self.root / "docs/arch.md").write_text("Run tools/build.py and tools/gone.py.\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Cleanup cycle: lane: 5 TUs tidied: 0 banners, 3 includes, 2 joined, "
            "9 regrouped (26615 -> 26615 matched)\n\nLong body.\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
        git(self.root, "branch", "old-work")
        result = hygiene.audit(self.project, "game")
        kinds = {f["kind"] for f in result["files"]["findings"]}
        self.assertTrue({"agent-doc", "dated-doc", "unused-script", "stale-reference"} <= kinds, kinds)
        problems = " ".join(result["commits"]["problems"][0]["problems"])
        for text in ("trailer", "body", "characters", "tool summary"):
            self.assertIn(text, problems)
        self.assertTrue(any("old-work" in p for p in result["tree"]["problems"]))
        self.assertEqual(result["files"]["history"][0]["path"], "AGENTS.md")
        self.assertFalse(result["ok"])

    def test_commit_message_hook(self):
        good = hygiene.message(self.project, "game", "Match the enemy update\n# comment from git\n")
        bad = hygiene.message(self.project, "game", "Fix\n\nWhy it changed.\n\nCo-Authored-By: Codex <noreply@openai.com>\n")
        self.assertTrue(good["ok"], good)
        self.assertFalse(bad["ok"])


if __name__ == "__main__":
    unittest.main()
