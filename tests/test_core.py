import support  # noqa: F401  (isolates config, cache and state)
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from zkit.evidence import address, lookup, read_document, report_status, search
from zkit.project import Project, check_snapshot, snapshot
from zkit.recipes import check_recipe
from zkit.workflows import command_plan, doctor


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from zkit.index import close_connections
        self.addCleanup(close_connections)  # runs first: Windows cannot delete an open database
        self.base = Path(self.temp.name)
        self.root = self.base / "game"
        self.root.mkdir()
        for directory in ["src", "docs", "tests/fidelity", "build"]:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "AGENTS.md").write_text("Preserve original behavior.\n", encoding="utf-8")
        (self.root / "src/Actor.cpp").write_text("void update() {}\n", encoding="utf-8")
        (self.root / "docs/flame.md").write_text("# Flame\nRotation comes from the caller.\n", encoding="utf-8")
        (self.root / "original.dol").write_bytes(b"synthetic DOL identity")
        self.config = {
            "schema_version": 1, "id": "synthetic",
            "repositories": {"game": {
                "root": "game", "required_docs": ["AGENTS.md"],
                "search_paths": ["docs", "AGENTS.md"], "build_inputs": ["src"],
                "recipes": "tests/fidelity", "recipe_format": "fidelity-v1", "decomp_repository": "game"}},
            "targets": {"test": {"repository": "game", "module": "main", "report": "report.json",
                                  "original": "original.dol", "sha256": hashlib.sha256(b"synthetic DOL identity").hexdigest()}},
            "commands": {"test": {"repository": "game", "argv": ["echo", "$(touch BAD)", "a b"]}},
        }
        self.report = {"measures": {"matched_functions": 1}, "units": [{
            "name": "main/Actor", "metadata": {"module_name": "main", "source_path": "src/Actor.cpp", "complete": False},
            "functions": [{"name": "unknown", "size": "16", "fuzzy_match_percent": 100,
                           "metadata": {"virtual_address": str(0x80001000)}}]}]}
        self.recipe = {"boundary": "A component with a replaced caller", "excluded": ["real caller"],
                       "evidence": ["{root}/docs/flame.md"], "packages": ["particles"],
                       "original_checks": [{"name": "original", "command": ["python3", "check.py"], "timeout": 30}],
                       "tests": ["flame", "local-flame"]}
        self.path = self.base / "project.json"
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.config), encoding="utf-8")
        (self.root / "report.json").write_text(json.dumps(self.report), encoding="utf-8")
        (self.root / "tests/fidelity/flame.json").write_text(json.dumps(self.recipe), encoding="utf-8")
        self.project = Project.load(self.path)

    def test_relative_roots_do_not_depend_on_cwd(self):
        self.assertEqual(self.project.root("game"), self.root.resolve())

    def test_escape_and_absolute_paths_rejected(self):
        for value in ["../outside.txt", str(self.base / "outside.txt")]:
            with self.assertRaises(ValueError):
                self.project.file("game", value)

    def test_symlink_escape_rejected(self):
        (self.base / "secret.md").write_text("secret", encoding="utf-8")
        (self.root / "docs/escape.md").symlink_to(self.base / "secret.md")
        with self.assertRaises(ValueError):
            read_document(self.project, "game:docs/escape.md")
        self.assertEqual(search(self.project, "secret")["total_hits"], 0)

    def test_address_requires_explicit_hex(self):
        self.assertEqual(address("0x80001000"), 0x80001000)
        for value in ["80001000", "0x-1", True, -1, 2**32]:
            with self.assertRaises(ValueError):
                address(value)

    def test_interior_address_module_and_link_boundary(self):
        foreign = copy.deepcopy(self.report["units"][0])
        foreign["metadata"]["module_name"] = "other"
        self.report["units"].append(foreign)
        self.save()
        result = lookup(self.project, "test", "0x80001004")
        self.assertTrue(result["identity"]["verified"])
        self.assertEqual(result["function"]["offset"], 4)
        self.assertTrue(result["function"]["byte_exact_in_report"])
        self.assertFalse(result["function"]["unit_complete_in_report"])
        self.assertIsNone(result["function"]["semantic_name_verified"])
        self.assertIsNone(lookup(self.project, "test", "0x80001010")["function"])

    def test_overlapping_functions_are_ambiguous(self):
        self.report["units"].append(copy.deepcopy(self.report["units"][0]))
        self.save()
        with self.assertRaises(ValueError):
            lookup(self.project, "test", "0x80001000")

    def test_wrong_original_cannot_be_verified(self):
        (self.root / "original.dol").write_bytes(b"wrong revision")
        result = lookup(self.project, "test", "0x80001000")
        self.assertFalse(result["identity"]["verified"])

    def test_report_flags_newer_source(self):
        stamp = (self.root / "report.json").stat().st_mtime + 10
        os.utime(self.root / "src/Actor.cpp", (stamp, stamp))
        self.assertEqual(report_status(self.project, "test")["freshness"], "stale-by-mtime")

    def test_missing_docs_are_an_error(self):
        (self.root / "AGENTS.md").unlink()
        self.assertFalse(doctor(self.project)["ok"])

    def test_non_git_project_still_works(self):
        result = doctor(self.project)
        self.assertTrue(result["ok"])
        self.assertFalse(result["repositories"]["game"]["git"])

    def test_search_returns_current_hash_and_line(self):
        result = search(self.project, "rotation caller")["results"][0]
        self.assertEqual(result["line"], 2)
        self.assertEqual(result["reference"], "game:docs/flame.md")
        (self.root / "docs/flame.md").write_text("removed", encoding="utf-8")
        self.assertEqual(search(self.project, "rotation caller")["total_hits"], 0)

    def test_read_is_bounded_and_restricted_to_text_roots(self):
        self.assertIn("2: Rotation", read_document(self.project, "game:docs/flame.md", 2, 1)["text"])
        for ref, size in [("game:src/Actor.cpp", 20), ("game:docs/flame.md", 201)]:
            with self.assertRaises(ValueError):
                read_document(self.project, ref, 1, size)

    def test_plan_preserves_argv_and_does_not_execute(self):
        result = command_plan(self.project, "test")
        self.assertEqual(result["argv"][1], "$(touch BAD)")
        self.assertFalse(result["executed"])
        self.assertFalse((self.root / "BAD").exists())

    def test_recipe_preflight_is_not_execution(self):
        result = check_recipe(self.project, "game:tests/fidelity/flame.json")
        self.assertTrue(result["ready_for_review"])
        self.assertFalse(result["behavior_verified"])
        self.assertEqual(result["excluded"], ["real caller"])

    def test_recipe_missing_evidence_is_rejected(self):
        (self.root / "docs/flame.md").unlink()
        self.assertFalse(check_recipe(self.project, "game:tests/fidelity/flame.json")["ready_for_review"])

    def test_recipe_build_binding_is_explicit(self):
        self.recipe["evidence"].append("{build}/probe")
        (self.root / "build/probe").write_bytes(b"test executable")
        self.save()
        self.assertFalse(check_recipe(self.project, "game:tests/fidelity/flame.json")["ready_for_review"])
        self.config["repositories"]["game"]["recipe_bindings"] = {"build": "build"}
        self.save()
        self.assertTrue(check_recipe(self.project, "game:tests/fidelity/flame.json")["ready_for_review"])
        self.recipe["evidence"].append("{build}/../../outside")
        self.save()
        with self.assertRaises(ValueError):
            check_recipe(self.project, "game:tests/fidelity/flame.json")

    def test_recipe_missing_disabled_and_duplicate_tests(self):
        path = self.root / "build/catalog.json"
        path.write_text(json.dumps({"tests": [{"name": "flame", "properties": [{"name": "DISABLED", "value": True}]}]}), encoding="utf-8")
        result = check_recipe(self.project, "game:tests/fidelity/flame.json", "game:build/catalog.json")
        self.assertFalse(result["ready_for_review"])
        self.assertEqual(result["test_registration"]["missing"], ["local-flame"])
        self.assertEqual(result["test_registration"]["disabled"], ["flame"])
        self.recipe["tests"] = ["flame", "flame"]
        self.save()
        self.assertFalse(check_recipe(self.project, "game:tests/fidelity/flame.json")["ready_for_review"])

    def test_snapshot_detects_required_doc_change_and_manifest_change(self):
        old = snapshot(self.project)
        self.assertTrue(check_snapshot(self.project, old)["current"])
        (self.root / "AGENTS.md").write_text("new intent", encoding="utf-8")
        self.assertFalse(check_snapshot(self.project, old)["current"])
        self.config["intent"] = {"changed": True}
        self.save()
        self.assertEqual(check_snapshot(self.project, old)["changes"], ["project manifest changed"])

    def test_snapshot_rejects_cached_manifest_after_edit(self):
        self.path.write_text(self.path.read_text(encoding="utf-8") + "\n")
        with self.assertRaises(ValueError):
            snapshot(self.project)

    def test_snapshot_detects_dirty_to_dirty_edits(self):
        def run(*args):
            subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, check=True)
        run("init", "-q")
        run("add", ".")
        run("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        source = self.root / "src/Actor.cpp"
        source.write_text("dirty one", encoding="utf-8")
        old = snapshot(self.project)
        source.write_text("dirty two", encoding="utf-8")
        self.assertIn("repositories:game", check_snapshot(self.project, old)["changes"])

    def test_snapshot_detects_requested_ignored_asset_change(self):
        (self.root / "private.asset").write_bytes(b"first")
        old = snapshot(self.project, ["game:private.asset"])
        (self.root / "private.asset").write_bytes(b"second")
        self.assertIn("files:game:private.asset", check_snapshot(self.project, old)["changes"])


if __name__ == "__main__":
    unittest.main()
