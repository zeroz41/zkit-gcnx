import support  # noqa: F401  (isolates config, cache and state)
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from test_progress_hygiene import IDENTITY, git, report

from zkit import ci
from zkit.project import Project


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "README.md").write_text("# Game\n", encoding="utf-8")
        (self.root / "src").mkdir()
        (self.root / "src/a.cpp").write_text("void f() {}\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Add a")
        self.before = report([("main/a", "f", 0x1000, 0x20, 100.0), ("main/a", "g", 0x1020, 0x10, 90.0)],
                             [("main/a", ".data", 0x9000, 0x40, 100.0)], linked={"main/a"})
        (self.root / "baseline.json").write_text(json.dumps(self.before), encoding="utf-8")
        (self.root / "build").mkdir()
        manifest = self.root / "p.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "ci", "repositories": {
            "game": {"root": ".", "role": "decomp", "hygiene": {"identity": IDENTITY},
                     "quality": {"gate": "error"}}}, "targets": {"t": {
            "repository": "game", "module": "main", "report": "build/report.json"}}}), encoding="utf-8")
        (self.root / ".git/info/exclude").write_text("p.json\nbaseline.json\nbuild/\n", encoding="utf-8")
        self.project = Project.load(manifest)

    def tearDown(self):
        self.temp.cleanup()

    def gate(self, after: dict, built: bool = True, **kw):
        (self.root / "build/report.json").write_text(json.dumps(after), encoding="utf-8")
        steps = {"build": lambda project, target: (built, "compiled 2 units\nbuild: ok" if built else "error: x")}
        return ci.check(self.project, "t", str(self.root / "baseline.json"), "HEAD", out=self.root / "r/result.json",
                        steps=steps, **kw)

    def test_a_gain_passes_and_writes_the_result(self):
        after = report([("main/a", "f", 0x1000, 0x20, 100.0), ("main/a", "g", 0x1020, 0x10, 100.0)],
                       [("main/a", ".data", 0x9000, 0x40, 100.0)], linked={"main/a"})
        result = self.gate(after)
        self.assertTrue(result["ok"], result["checks"])
        written = json.loads((self.root / "r/result.json").read_text(encoding="utf-8"))
        self.assertEqual(written["result"], "pass")
        self.assertEqual([c["name"] for c in written["checks"]], ["build", "progress", "lint", "files"])
        self.assertEqual(written["delta"]["metrics"]["matched_functions"], {"before": 1, "after": 2, "delta": 1})
        self.assertEqual(written["delta"]["counts"]["new_exact"], 1)
        self.assertEqual(written["quality"]["files_changed"], 0)   # advisory, beside the checks
        self.assertIn("added", written["quality"]["total"])

    def test_a_lost_match_fails_and_is_named(self):
        after = report([("main/a", "f", 0x1000, 0x20, 99.0), ("main/a", "g", 0x1020, 0x10, 90.0)],
                       [("main/a", ".data", 0x9000, 0x40, 100.0)], linked={"main/a"})
        result = self.gate(after)
        self.assertFalse(result["ok"])
        self.assertEqual(result["result"], "fail")
        self.assertEqual(result["delta"]["regressed"], ["f (0x00001000)"])
        self.assertIs({c["name"]: c["ok"] for c in result["checks"]}["progress"], False)

    def test_a_failed_build_skips_the_comparison_but_still_lints(self):
        result = self.gate(self.before, built=False)
        ran = {c["name"]: c["ok"] for c in result["checks"]}
        self.assertEqual((ran["build"], ran["progress"]), (False, None))
        self.assertIn("lint", ran)
        self.assertIsNone(result["delta"])

    def test_added_raw_offsets_fail_the_lint(self):
        (self.root / "src/a.cpp").write_text("void f(char *p) { *(int *)(p + 0x18) = 0; }\n", encoding="utf-8")
        result = self.gate(self.before)
        lint = next(c for c in result["checks"] if c["name"] == "lint")
        self.assertIs(lint["ok"], False, lint)

    def test_game_files_fail_the_files_check(self):
        (self.root / "main.nso").write_bytes(b"NSO0" + bytes(60))
        git(self.root, "add", "main.nso")
        result = self.gate(self.before)
        files = next(c for c in result["checks"] if c["name"] == "files")
        self.assertIs(files["ok"], False, files)

    def test_outcome_needs_a_passing_build(self):
        self.assertEqual(ci.outcome([{"name": "lint", "ok": True}]), "fail")
        self.assertEqual(ci.outcome([{"name": "build", "ok": True}, {"name": "progress", "ok": None}]), "pass")


class CommentTests(unittest.TestCase):
    RUN = "https://github.com/owner/repo/actions/runs/123"

    def test_no_result_is_a_run_that_stopped_before_the_gate(self):
        text = ci.comment(None, "abcdef0123456789", self.RUN)
        self.assertTrue(text.startswith(ci.MARKER + "\n"))
        self.assertIn("CI failed", text)
        self.assertIn("`abcdef0123`", text)
        self.assertIn("stopped before the gate", text)

    def test_untrusted_values_are_escaped(self):
        result = {"result": "fail", "checks": [
            {"name": "build", "ok": True},
            {"name": "lint", "ok": False, "reason": "x | <img src=x> @owner [a](http://evil)",
             "output": "```\n@owner done\n```"}],
            "delta": {"metrics": {"matched_code": {"before": True, "after": 2, "delta": 1}},
                      "regressed": ["f`` <b>"], "failures": ["lost | <i>"], "counts": {"new_exact": "7"}}}
        text = ci.comment(result, "not-a-sha; rm", "javascript:alert(1)")
        self.assertNotIn("<img", text)
        self.assertNotIn("<b>", text)
        self.assertNotIn("<i>", text)
        self.assertNotIn("@owner", text)
        self.assertIn("\\[a\\](http://evil)", text)  # brackets escaped: no link
        self.assertNotIn("javascript", text)
        self.assertEqual(text.count("```"), 2)          # only the fence the renderer wrote
        self.assertNotIn("Matched code", text)          # a bool is not a number
        self.assertNotIn("7 new exact", text)           # a string is not a count
        self.assertIn("lost \\| &lt;i&gt;", text)

    def test_pass_needs_every_check_and_the_build(self):
        result = {"result": "pass", "checks": [{"name": "build", "ok": True}, {"name": "files", "ok": False}]}
        self.assertIn("CI failed", ci.comment(result))
        result = {"result": "pass", "checks": [{"name": "progress", "ok": True}]}
        self.assertIn("CI failed", ci.comment(result))

    def test_a_passing_result_shows_the_changes(self):
        result = {"result": "pass", "checks": [{"name": n, "ok": True} for n in ci.CHECKS],
                  "delta": {"metrics": {"matched_code": {"before": 1000, "after": 1240, "delta": 240},
                                        "complete_units": {"before": 5, "after": 5, "delta": 0}},
                            "counts": {"new_exact": 3, "renamed": 1}, "failures": [], "regressed": []}}
        text = ci.comment(result, "0123456789abcdef", self.RUN + "/attempts/2")
        self.assertIn("CI passed", text)
        self.assertIn(f"[run]({self.RUN}/attempts/2)", text)
        self.assertIn("| Matched code (bytes) | 1,000 | 1,240 | **+240** |", text)
        self.assertIn("| Linked units | 5 | 5 | 0 |", text)
        self.assertIn("3 new exact functions, 1 renamed functions.", text)

    QUALITY = {
        "rows": [
            {"key": "raw_offset", "name": "Byte-pointer offsets", "example": "(u8 *)p + 0x30", "group": "types",
             "category": "Types", "before": 10, "after": 8, "removed": 3, "added": 1},
            {"key": "arg_name", "name": "Numbered parameters", "example": "arg0, farg1", "group": "names",
             "category": "Names", "before": 5, "after": 5, "removed": 0, "added": 0},
            {"key": "this_cast", "name": "Casts of this to an unrelated class", "example": "((T *)this)->f()",
             "group": "ownership", "category": "Members in the wrong class", "before": 2, "after": 2,
             "removed": 0, "added": 0}],
        "total": {"before": 15, "after": 13, "removed": 3, "added": 1}, "files_changed": 2,
        "after_commit": "0123456789abcdef0123456789abcdef01234567",
        "new": [{"key": "raw_offset", "path": "src/a.cpp", "line": 7, "text": "(u8 *)p + 0x30"},
                {"key": "raw_offset", "path": "../../etc/x", "line": 1, "text": "(u8 *)q + 0x8"}],
        "new_total": 2}

    def test_quality_lists_the_moved_checks_and_every_check_collapsed(self):
        result = {"result": "pass", "checks": [{"name": n, "ok": True} for n in ci.CHECKS], "quality": self.QUALITY}
        text = ci.comment(result, "0123456789abcdef", self.RUN)
        moved, everything = text.split("<details><summary>All 3 checks by category</summary>")
        self.assertIn("**Debt -2**: this pull request removes 3 and adds 1 across 2 changed source files", moved)
        self.assertIn("| Byte-pointer offsets (`(u8 *)p + 0x30`) | 10 → **8** | 3 | 1 |", moved)
        self.assertNotIn("Numbered parameters", moved)           # unchanged: only in the full table
        self.assertNotIn("Members in the wrong class", moved)    # unchanged ownership is not shown
        self.assertIn("| **Total debt** | **15 → 13** | **3** | **1** |", moved)
        self.assertIn("| **Names** | | | |", everything)
        self.assertIn("| Numbered parameters (`arg0`, `farg1`) | 5 | 0 | 0 |", everything)
        self.assertIn("[`a.cpp:7`](https://github.com/owner/repo/blob/0123456789abcdef0123456789abcdef01234567/"
                      "src/a.cpp#L7)", text)
        self.assertIn("`x:1`", text)                             # a path out of the repository is not linked
        self.assertNotIn("../../etc", text.replace("`", ""))

    def test_quality_without_a_change_or_a_measure(self):
        unchanged = {**self.QUALITY, "rows": [{**r, "after": r["before"], "removed": 0, "added": 0}
                                              for r in self.QUALITY["rows"]],
                     "total": {"before": 15, "after": 15, "removed": 0, "added": 0}, "new": []}
        text = ci.comment({"result": "pass", "checks": [], "quality": unchanged})
        self.assertIn("**No change in any check**; the tree stays at 15.", text)
        self.assertNotIn("new finding", text)
        for broken in ({"error": "git diff: bad revision"}, None, {"total": {"before": "1"}}):
            text = ci.comment({"result": "pass", "checks": [], "quality": broken})
            self.assertIn("Not measured for this run", text)
        self.assertNotIn("Source quality", ci.comment({"result": "pass", "checks": []}))

    def test_quality_values_are_escaped(self):
        hostile = {**self.QUALITY, "rows": [{**self.QUALITY["rows"][0], "name": "<img src=x> @owner",
                                             "example": "`x` | y", "category": "[a](http://evil)"}],
                   "new": [{"key": "raw_offset", "path": "src/a.cpp", "line": 1, "text": "f`` | <b>"}],
                   "after_commit": "not a commit"}
        text = ci.comment({"result": "pass", "checks": [], "quality": hostile}, "", self.RUN)
        self.assertNotIn("<img", text)
        self.assertNotIn("@owner", text)
        self.assertIn("\\[a\\](http://evil)", text)                     # brackets escaped: no link
        self.assertNotIn("https://github.com/owner/repo/blob", text)   # no commit, no links
        self.assertIn("`fˋˋ \\| <b>`", text)                           # inside a code span < shows as itself

    def test_cli_renders_a_missing_file(self):
        out = subprocess.run([os.environ.get("PYTHON", "python3"), "-m", "zkit.cli", "ci", "comment", "/nonexistent",
                              "--sha", "abc"], capture_output=True, text=True,
                             env={**os.environ, "PYTHONPATH": str(Path(ci.__file__).parents[1])})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("stopped before the gate", out.stdout)


class ReportTests(unittest.TestCase):
    SHA, TREE, HEAD = "a" * 40, "b" * 40, "c" * 40

    def fake(self, runs: dict, artifacts: list, merged=True):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("report.json", '{"units": []}')
        calls = []

        def api(path, token):
            if path == "repos/o/r":
                return {"default_branch": "trunk"}
            if path == f"repos/o/r/commits/{self.SHA}":
                return {"commit": {"tree": {"sha": self.TREE}}}
            if path.endswith("/pulls"):
                return [{"head": {"sha": self.HEAD}, "merged_at": "2026-01-01T00:00:00Z" if merged else None}]
            if "/actions/artifacts?" in path:
                return {"artifacts": artifacts}
            return runs[int(path.rsplit("/", 1)[1])]

        def request(url, token, accept="", follow=True):
            calls.append((url, token))
            return "https://storage.example/zip" if not follow else archive.getvalue()
        return api, request, calls

    def artifact(self, run_id, name=None):
        return {"id": run_id * 10, "name": name or f"report-{self.TREE}", "expired": False,
                "workflow_run": {"id": run_id}}

    def test_only_a_trusted_run_s_report_counts_and_storage_never_sees_the_token(self):
        runs = {1: {"id": 1, "conclusion": "success", "path": ".github/workflows/ci.yml", "event": "pull_request",
                    "head_sha": "d" * 40},                                   # another pull request's run
                2: {"id": 2, "conclusion": "success", "path": ".github/workflows/ci.yml", "event": "pull_request",
                    "head_sha": self.HEAD}}
        api, request, calls = self.fake(runs, [self.artifact(1), self.artifact(2)])
        found, said = ci.fetch_report("o/r", self.SHA, "tok", api=api, request=request)
        self.assertEqual(json.loads(found), {"units": []})
        self.assertIn("run 2", said)
        self.assertEqual(calls, [("https://api.github.com/repos/o/r/actions/artifacts/20/zip", "tok"),
                                 ("https://storage.example/zip", None)])

    def test_no_trusted_run_means_no_report(self):
        runs = {1: {"id": 1, "conclusion": "success", "path": ".github/workflows/ci.yml", "event": "pull_request",
                    "head_sha": self.HEAD}}
        api, request, _ = self.fake(runs, [self.artifact(1)], merged=False)
        self.assertIsNone(ci.fetch_report("o/r", self.SHA, None, api=api, request=request)[0])
        api, request, _ = self.fake(runs, [self.artifact(1, name="report-other")])
        self.assertIsNone(ci.fetch_report("o/r", self.SHA, None, api=api, request=request)[0])

    def test_trusted(self):
        progress = {"conclusion": "success", "path": ".github/workflows/progress.yml", "event": "push",
                    "head_branch": "trunk", "head_sha": self.SHA}
        args = (self.SHA, set(), "trunk", ".github/workflows/ci.yml", ".github/workflows/progress.yml")
        self.assertTrue(ci.trusted(progress, *args))
        self.assertFalse(ci.trusted({**progress, "head_branch": "fork-main"}, *args))
        self.assertFalse(ci.trusted({**progress, "head_sha": self.HEAD}, *args))
        self.assertFalse(ci.trusted({**progress, "conclusion": "failure"}, *args))
        self.assertFalse(ci.trusted({**progress, "event": "pull_request"}, *args))
        self.assertFalse(ci.trusted({**progress, "path": ".github/workflows/other.yml"}, *args))


if __name__ == "__main__":
    unittest.main()
