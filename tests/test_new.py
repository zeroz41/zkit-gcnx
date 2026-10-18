import support  # noqa: F401  (isolates config, cache and state)
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_delink import CLANG, FLAGS, LLD, SOURCES
from test_disc import image
from zkit import new


class KindTests(unittest.TestCase):
    def test_kinds_from_headers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dol = bytearray(0x100)
            dol[0x48:0x4C] = (0x80003100).to_bytes(4, "big")
            dol[0x90:0x94] = (0x100).to_bytes(4, "big")
            cases = {"game.iso": image(), "main.dol": bytes(dol), "main.nso": b"NSO0" + bytes(0x100),
                     "main.elf": b"\x7fELF" + bytes(0x100)}
            for name, data in cases.items():
                (root / name).write_bytes(data)
            self.assertEqual({name: new.kind_of(root / name) for name in cases},
                             {"game.iso": "disc", "main.dol": "dol", "main.nso": "nso", "main.elf": "elf"})
            (root / "notes.txt").write_bytes(b"hello" * 100)
            with self.assertRaises(ValueError):
                new.kind_of(root / "notes.txt")


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class NewSwitchProjectTests(unittest.TestCase):
    def test_new_project_from_a_module(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in SOURCES.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="test")
            game = root / "game"
            self.assertEqual((result["kind"], result["game"]), ("elf", "test"))
            self.assertGreater(result["functions"], 5)
            self.assertGreaterEqual(result["units"], 1)
            self.assertEqual(result["objects"], result["units"])
            self.assertTrue((game / "orig/test/main.elf").is_file())
            self.assertIn("orig/", (game / ".gitignore").read_text())
            self.assertTrue((game / "config/test/splits.txt").read_text().strip())
            objdiff = json.loads((game / "objdiff.json").read_text())
            self.assertEqual(len(objdiff["units"]), result["units"])
            manifest = json.loads(Path(result["manifest"]).read_text())
            self.assertEqual(manifest["targets"]["test"]["platform"], "switch")
            with self.assertRaises(ValueError):
                new.new(root / "main.elf", game, game_id="test")      # never over an existing project

    def test_a_module_s_exported_data_is_in_its_symbols(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            flags = [flag for flag in FLAGS if flag != "-fvisibility=hidden"]
            for name, text in SOURCES.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *flags, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                            str(root / "main.elf"), str(root / "a.o"), str(root / "b.o")], check=True,
                           capture_output=True)
            result = new.new(root / "main.elf", root / "game", game_id="data")    # its own project: its own index
            symbols = (root / "game/config/data/symbols.txt").read_text()
            self.assertGreater(result["data_objects"], 0)
            self.assertRegex(symbols, r"(?m)^g_counter = \.data:0x[0-9A-F]+; // type:object size:0x4 ")


if __name__ == "__main__":
    unittest.main()
