import support  # noqa: F401  (isolates config, cache and state)
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_build import A_CPP, B_CPP, NINJA, OBJDIFF  # noqa: E402
from test_delink import CLANG, FLAGS, LLD  # noqa: E402
from zkit import build, candidate, misses, new  # noqa: E402
from zkit.project import Project  # noqa: E402

# the candidate's factor comes from a header: the copy it is kept with has it wrong, the tree's (added later) right
CANDIDATE = A_CPP.replace("int scaled(int v) { return v * 3", '#include "factor.h"\nint scaled(int v) { return v * FACTOR')


@unittest.skipUnless(CLANG and LLD and NINJA, "needs clang++, ld.lld and ninja")
class MissesTests(unittest.TestCase):
    """A near-miss kept by `try --unit`, listed, restored with its header copy, and retried once the tree has
    what it waited on."""

    def setUp(self):
        state = tempfile.TemporaryDirectory()        # each test its own store (both projects share one id)
        self.addCleanup(state.cleanup)
        previous = os.environ["XDG_STATE_HOME"]
        os.environ["XDG_STATE_HOME"] = state.name
        self.addCleanup(os.environ.__setitem__, "XDG_STATE_HOME", previous)

    def project(self, root: Path) -> Path:
        for name, text in (("a.cpp", A_CPP), ("b.cpp", B_CPP)):
            (root / name).write_text(text, encoding="utf-8")
            subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                           check=True, capture_output=True)
        subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                        str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                       capture_output=True)
        result = new.new(root / "main.elf", root / "game", game_id="test")
        game, manifest = root / "game", Path(result["manifest"])
        from zkit.elf import Elf
        at = {s.name: s.value for s in Elf.load(game / "orig/test/main.elf").symbols if s.name}
        rodata = Elf.load(game / "orig/test/main.elf").section(".rodata").address
        (game / "config/test/splits.txt").write_text(
            f"a.cpp:\n\t.text start:{at['_Z6scaledi']:#x} end:{at['_Z6helperi']:#x}\n"
            f"\t.rodata.str1.1 start:{rodata:#x} end:{rodata + 13:#x}\n", encoding="utf-8")
        (game / "src/a.cpp").write_text(A_CPP.replace("v * 3", "v * 5"), encoding="utf-8")   # the tree's: wrong
        data = json.loads(manifest.read_text())
        data["targets"]["test"]["build"].update(compiler=CLANG, cflags=[f for f in FLAGS if f != "-c"])
        manifest.write_text(json.dumps(data), encoding="utf-8")
        # with objdiff-cli the build links too, and the tree's wrong scaled keeps the link from being identical
        self.assertEqual(build.build(Project.load(manifest), quiet=True)["ok"], not OBJDIFF)
        # objdiff's report of the tree (written here: the test needs no objdiff): scaled differs, the rest match
        functions = [{"name": name, "size": "4", "fuzzy_match_percent": 50.0 if name == "_Z6scaledi" else 100.0,
                      "metadata": {"virtual_address": str(at[name])}}
                     for name in ("_Z6scaledi", "_Z8greetingv", "_Z4bothi")]
        (game / "build/test/report.json").write_text(json.dumps({"units": [
            {"name": "a", "metadata": {"source_path": "src/a.cpp"}, "functions": functions}]}), encoding="utf-8")
        return manifest

    def test_kept_listed_restored_and_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.project(root)
            project = Project.load(manifest)
            work = root / "work"
            (work / "include").mkdir(parents=True)
            (work / "include/factor.h").write_text("#define FACTOR 4\n", encoding="utf-8")
            (work / "a.cpp").write_text(CANDIDATE, encoding="utf-8")
            tried = candidate.check_unit(project, "test", "a", work / "a.cpp", [work / "include"])
            scaled = next(r for r in tried["functions"] if r["function"] == "_Z6scaledi")
            self.assertFalse(scaled["exact"])

            listed = misses.listing(project, "test", unit="a")
            entry = next(e for e in listed["entries"] if e["function"] == "_Z6scaledi")
            self.assertEqual(entry["origin"], "unit")
            self.assertTrue(entry["with_headers"])
            kept = root / "kept/a.o"
            again = candidate.check_unit(project, "test", "a", work / "a.cpp", [work / "include"], keep=kept)
            self.assertEqual(again["compiled"], True)
            self.assertEqual(kept.read_bytes()[:4], b"\x7fELF")                # --keep writes the unit's object
            self.assertEqual(misses.listing(project, "test", unit="a")["candidates"], 1)   # the same text, once

            restored = misses.restore(project, "test", "_Z6scaledi", root / "restored")
            self.assertEqual(Path(restored["written"]).read_text(encoding="utf-8"), CANDIDATE)
            self.assertEqual((root / "restored/include/factor.h").read_text(encoding="utf-8"), "#define FACTOR 4\n")
            self.assertIn("--include", restored["try"])

            # nothing changed: the retry finds nothing new for scaled
            first = misses.retry(project, "test", unit="a", jobs=1)
            self.assertNotIn("_Z6scaledi", [e["function"] for e in first["identical"]])
            # the tree gains the header the candidate waited on: compiled with the tree's headers it is identical
            (root / "game/src/factor.h").write_text("#define FACTOR 3\n", encoding="utf-8")
            second = misses.retry(project, "test", unit="a", jobs=1)
            found = next(e for e in second["identical"] if e["function"] == "_Z6scaledi")
            self.assertEqual(found["headers"], "tree's")
            whole = next(c for c in second["candidates"] if c["headers"] == "tree's")
            self.assertIn("_Z6scaledi", whole["gained"])                 # and both, which inlines it
            self.assertEqual((whole["lost"], whole["dropped"], whole["adds"], whole["clean"]), ([], 0, [], True))
            self.assertEqual(misses.best(project, "test", found["address"])["origin"], "retry")

    def test_import_keeps_a_work_file_with_the_headers_beside_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = Project.load(self.project(root))
            work = root / "old/worker"
            (work / "include").mkdir(parents=True)
            (work / "wip").mkdir()
            (work / "include/factor.h").write_text("#define FACTOR 3\n", encoding="utf-8")
            (work / "wip/a_try.cpp").write_text(CANDIDATE, encoding="utf-8")
            (work / "wip/notes.txt").write_text("not a candidate", encoding="utf-8")
            done = misses.import_files(project, "test", [root / "old"], jobs=1)
            self.assertEqual((done["files"], done["failed"]), (1, 0))
            self.assertGreater(done["rows"], 0)
            best = misses.best(project, "test", misses.addresses_by_name(project, "test", ["_Z6scaledi"])["_Z6scaledi"])
            self.assertTrue(best["exact"])
            self.assertEqual(best["origin"], "import")
            self.assertEqual(misses.import_files(project, "test", [root / "old"], jobs=1)["rows"], 0)  # once only


if __name__ == "__main__":
    unittest.main()
