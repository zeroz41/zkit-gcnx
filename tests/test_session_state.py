import support  # noqa: F401  (isolates config, cache and state)
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from zkit import paths, session
from zkit.activity import handoffs, write_handoff
from zkit.project import Project


class SessionStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Dev", "-c", "user.email=dev@example.org",
                        "commit", "-q", "--allow-empty", "-m", "Start"], check=True)
        manifest = self.root / "p.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "s", "repositories": {
            "game": {"root": ".", "role": "decomp"}}}), encoding="utf-8")
        (self.root / ".git/info/exclude").write_text("p.json\n", encoding="utf-8")
        self.project = Project.load(manifest)
        os.environ["ZKIT_AGENT"] = "claude:4242"

    def tearDown(self):
        os.environ.pop("ZKIT_AGENT", None)
        self.temp.cleanup()

    def test_gate_reviews_the_session(self):
        session.record_start(self.project)
        self.assertEqual(session.session_start(self.project)["agent"], "claude:4242")
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Dev", "-c", "user.email=dev@example.org",
                        "commit", "-q", "--allow-empty", "-m", "A subject that is much longer than seventy-two "
                        "characters and so breaks the rule"], check=True)
        review = session.gate(self.project, "game")["session"]
        problems = review["hygiene"]["commits"]["problems"]
        self.assertEqual(len(problems), 1)  # only the commit made after the session started
        self.assertIn("characters", problems[0]["problems"][0])

    def test_handoff_replaces_own_recent_note(self):
        write_handoff(self.project, "game", "first checkpoint")
        row = write_handoff(self.project, "game", "final note")
        self.assertIn("replaced", row)
        self.assertEqual([r["text"] for r in handoffs(self.project, "game", limit=5)], ["final note"])
        os.environ["ZKIT_AGENT"] = "codex:7"
        write_handoff(self.project, "game", "another session")
        self.assertEqual(len(handoffs(self.project, "game", limit=5)), 2)


class PathTests(unittest.TestCase):
    def test_legacy_folder_moves_once(self):
        with tempfile.TemporaryDirectory() as temp:
            old = Path(temp) / "gcn-zkit"
            (old / "projects").mkdir(parents=True)
            (old / "projects/x.link.json").write_text("{}", encoding="utf-8")
            saved = os.environ.get("XDG_CONFIG_HOME")
            os.environ["XDG_CONFIG_HOME"] = temp
            try:
                home = paths.config_home()
            finally:
                os.environ["XDG_CONFIG_HOME"] = saved
            self.assertEqual(home, Path(temp) / "zkit")
            self.assertTrue((home / "projects/x.link.json").is_file())
            self.assertFalse(old.exists())


if __name__ == "__main__":
    unittest.main()
