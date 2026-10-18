"""zkit m2c: how m2c is found and run, and when Ghidra's reading is added (needs no game)."""

import support  # noqa: F401  (isolates config, cache and state)
import json
import sys
import tempfile
import unittest
from pathlib import Path

from zkit import asmfile
from zkit.project import Project


def project(root: Path, **extra) -> Project:
    manifest = root / "project.json"
    manifest.write_text(json.dumps({"schema_version": 1, "id": "m2c-test", "repositories": {
        "decomp": {"root": "decomp", "role": "decomp"}},
        "targets": {"t": {"repository": "decomp", "module": "main", "original": "main.bin",
                          "platform": extra.pop("platform", "gamecube")}}, **extra}))
    (root / "decomp").mkdir(exist_ok=True)
    return Project.load(manifest)


class M2cTests(unittest.TestCase):
    def test_ghidra_is_added_only_where_m2c_fails_or_emits_goto(self):
        self.assertIsNone(asmfile.ghidra_advice("s32 f(s32 a) {\n    if (a) { return 1; }\n    return 0;\n}\n"))
        self.assertIn("2 goto", asmfile.ghidra_advice("void f(void) {\nloop:\n    goto loop;\n    goto loop;\n}\n"))
        self.assertIn("failed", asmfile.ghidra_advice(""))
        self.assertIn("M2C_ERROR", asmfile.ghidra_advice("void f(void) {\n    M2C_ERROR(/* unknown instruction */);\n}\n"))
        self.assertIsNone(asmfile.ghidra_advice("void f(void) {\n    gotoNext();\n}\n"))

    def test_a_project_adapter_is_run_as_configured(self):
        with tempfile.TemporaryDirectory() as temp:
            adapter = [".venv/bin/python", "tools/m2c_runner.py", "../m2c"]
            self.assertEqual(asmfile.find_m2c(project(Path(temp), m2c=adapter)), adapter)

    def test_a_checkout_beside_the_decomp_is_found(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "m2c").mkdir()
            (root / "m2c" / "m2c.py").write_text("")
            found = asmfile.find_m2c(project(root))
            self.assertEqual(found, [sys.executable, str(root / "m2c" / "m2c.py")])

    def test_switch_targets_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "zkit decompile"):
                asmfile.m2c(project(Path(temp), platform="switch"), "t", [0x7100000000])


if __name__ == "__main__":
    unittest.main()
