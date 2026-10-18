import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
from pathlib import Path

from zkit.disc import Disc
from zkit.gc import GC_DISC_MAGIC


def image() -> bytes:
    """A tiny disc: boot header, apploader, a one-section DOL, and an FST with a file at the root and one in a
    folder."""
    data = bytearray(0x8000)
    data[0:6] = b"GTST01"
    data[0x1C:0x20] = struct.pack(">I", GC_DISC_MAGIC)
    data[0x20:0x29] = b"Test Game"
    data[0x2440 + 0x14:0x2440 + 0x1C] = struct.pack(">2I", 0x100, 0x20)
    dol = bytearray(0x200)
    dol[0:4] = struct.pack(">I", 0x100)              # text0 offset
    dol[0x48:0x4C] = struct.pack(">I", 0x80003100)  # text0 address
    dol[0x90:0x94] = struct.pack(">I", 0x100)       # text0 size
    data[0x3000:0x3200] = dol
    names = b"a.bin\0dir\0b.rel\0"
    entries = [(0x01000000, 0, 4), (0, 0x4000, 3), (0x01000006, 0, 4), (10, 0x4100, 5)]
    fst = b"".join(struct.pack(">III", *e) for e in entries) + names
    data[0x3800:0x3800 + len(fst)] = fst
    data[0x420:0x42C] = struct.pack(">3I", 0x3000, 0x3800, len(fst))
    data[0x4000:0x4003] = b"abc"
    data[0x4100:0x4105] = b"Yaz0!"
    return bytes(data)


class DiscTests(unittest.TestCase):
    def test_reads_and_extracts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "game.iso"
            path.write_bytes(image())
            disc = Disc(path)
            self.assertEqual((disc.game_id, disc.title, disc.dol_size), ("GTST01", "Test Game", 0x200))
            self.assertEqual([(f.path, f.size) for f in disc.files], [("files/a.bin", 3), ("files/dir/b.rel", 5)])
            result = disc.extract(Path(temp) / "orig")
            self.assertEqual(result["rels"], ["files/dir/b.rel"])
            self.assertEqual((Path(temp) / "orig/files/dir/b.rel").read_bytes(), b"Yaz0!")
            self.assertEqual(len((Path(temp) / "orig/sys/main.dol").read_bytes()), 0x200)
            self.assertEqual(len((Path(temp) / "orig/sys/apploader.img").read_bytes()), 0x140)

    def test_rejects_other_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "x.iso"
            path.write_bytes(bytes(0x1000))
            with self.assertRaises(ValueError):
                Disc(path)


if __name__ == "__main__":
    unittest.main()
