"""Stale build outputs from build.ninja, compile_commands.json and file times. Nothing is built."""

import support  # noqa: F401  (isolates config, cache and state)
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


class StaleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        for var in ("XDG_CACHE_HOME", "XDG_STATE_HOME"):
            os.environ[var] = str(base / var.lower())
        self.root = root = base / "port"
        build = root / "out" / "rel"
        for rel, text in {"src/core/Thing.cpp": '#include "core/Thing.hpp"\n', "src/core/Thing.hpp": "int f();\n",
                          "src/app/Main.cpp": '#include "core/Thing.hpp"\n', "src/tool/Tool.cpp": "int main(){}\n",
                          "src/core/Other.hpp": "// included by nothing\n"}.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        build.mkdir(parents=True)
        objects = {"src/core/Thing.cpp": "CMakeFiles/core.dir/src/core/Thing.cpp.o",
                   "src/app/Main.cpp": "CMakeFiles/game app.dir/src/app/Main.cpp.o",
                   "src/tool/Tool.cpp": "CMakeFiles/tool.dir/src/tool/Tool.cpp.o"}
        # Absolute outputs (as CMake writes them) and relative ones must both map to Ninja's build-relative paths.
        (build / "compile_commands.json").write_text(json.dumps([
            {"directory": str(build), "file": str(root / src), "command": f"c++ -c {src} -o '{obj}'",
             **({"output": str(build / obj)} if "core" in obj else {})} for src, obj in objects.items()]))
        (build / "build.ninja").write_text(
            "build CMakeFiles/core.dir/src/core/Thing.cpp.o: CXX_COMPILER__core ../../src/core/Thing.cpp\n"
            "build libcore.a: CXX_STATIC_LIBRARY_LINKER__core CMakeFiles/core.dir/src/core/Thing.cpp.o\n"
            "build game$ app: CXX_EXECUTABLE_LINKER__game CMakeFiles/game$ app.dir/src/app/Main.cpp.o | $\n"
            "    libcore.a || libcore.a\n"
            "build tool: CXX_EXECUTABLE_LINKER__tool CMakeFiles/tool.dir/src/tool/Tool.cpp.o\n", encoding="utf-8")
        now = time.time()
        for program in ("game app", "tool", "libcore.a"):
            (build / program).write_bytes(b"\x7fELF")
        for path in [*root.rglob("src/**/*.*"), *(build / p for p in ("game app", "tool", "libcore.a"))]:
            os.utime(path, (now - 100, now - 100))
        self.later = now - 10
        self.manifest = base / "project.json"
        self.manifest.write_text(json.dumps({"schema_version": 1, "id": "stale", "repositories": {"native": {
            "root": "port", "role": "native", "index_paths": ["src"],
            "tests": {"build_dir": "out/rel", "include_roots": ["src"], "scan": ["src"], "apps": ["game app"]}}}}))
        from zkit.project import Project
        self.project = Project.load(self.manifest)

    def touch(self, rel):
        os.utime(self.root / rel, (self.later, self.later))

    def verdicts(self, programs=None):
        from zkit.native import stale
        return {r["output"]: r for r in stale(self.project, "native", programs)["outputs"]}

    def test_fresh_build_is_not_stale(self):
        rows = self.verdicts(["game app", "tool"])
        self.assertFalse(any(r["stale"] for r in rows.values()))
        self.assertEqual(rows["game app"]["sources"], 2)  # its own object plus the library's

    def test_source_in_a_linked_library_makes_the_app_stale(self):
        self.touch("src/core/Thing.cpp")
        rows = self.verdicts(["game app", "tool"])
        self.assertTrue(rows["game app"]["stale"])
        self.assertEqual(rows["game app"]["newer"][0]["file"], "src/core/Thing.cpp")
        self.assertFalse(rows["tool"]["stale"])

    def test_header_reaches_programs_through_includers(self):
        self.touch("src/core/Thing.hpp")
        self.assertTrue(self.verdicts(["game app"])["game app"]["stale"])
        self.touch("src/core/Other.hpp")
        self.assertEqual(self.verdicts(["game app"])["game app"]["newer_count"], 1)  # an unused header is ignored

    def test_gate_reports_configured_stale_apps_and_cli_agrees(self):
        from zkit.session import gate
        self.assertEqual(gate(self.project, "native")["stale_apps"], [])
        self.touch("src/app/Main.cpp")
        self.assertEqual([a["output"] for a in gate(self.project, "native")["stale_apps"]], ["game app"])
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
        cli = subprocess.run([sys.executable, "-m", "zkit.cli", "--project", str(self.manifest), "--json",
                              "stale", "native"], capture_output=True, text=True, env=env, check=True)
        self.assertEqual([r["output"] for r in json.loads(cli.stdout)["outputs"] if r["stale"]], ["game app"])

    def test_without_ninja_says_so(self):
        (self.root / "out/rel/build.ninja").unlink()
        from zkit.native import stale
        self.assertFalse(stale(self.project, "native")["checked"])


if __name__ == "__main__":
    unittest.main()
