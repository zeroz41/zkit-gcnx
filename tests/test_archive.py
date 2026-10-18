import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import archive


def yaz0_of(plain: bytes) -> bytes:
    """Hand-encoded Yaz0: "abc" as literals, then a 2-byte back-reference repeating it twice (length 6,
    distance 3), then a literal "!"."""
    body = bytes([0b11101000]) + b"abc" + bytes([(6 - 2) << 4 | 0, 3 - 1]) + b"!"
    return b"Yaz0" + struct.pack(">I", len(plain)) + bytes(8) + body


def rarc_of(files: dict[str, bytes]) -> bytes:
    """A one-directory RARC holding `files` (root node "root")."""
    names = bytearray(b".\0..\0root\0")
    offsets = {}
    for name in files:
        offsets[name] = len(names)
        names += name.encode() + b"\0"
    blobs, entries, cursor = bytearray(), [], 0
    for name, blob in files.items():
        entries.append(struct.pack(">HHHHII", 0, 0, 0x1100, offsets[name], cursor, len(blob)) + bytes(4))
        blobs += blob
        cursor += len(blob)
    nodes = struct.pack(">4sIHHI", b"ROOT", 5, 0, len(files), 0)
    info_size = 0x20
    node_offset = info_size
    entry_offset = node_offset + 16
    string_offset = entry_offset + 20 * len(files)
    info = struct.pack(">IIIIII", 1, node_offset, len(files), entry_offset, len(names), string_offset) + bytes(8)
    tables = info + nodes + b"".join(entries) + bytes(names)
    header = b"RARC" + struct.pack(">III", 0x20 + len(tables) + len(blobs), 0x20, len(tables)) + bytes(16)
    return header + tables + bytes(blobs)


class ArchiveTests(unittest.TestCase):
    def test_yaz0(self):
        self.assertEqual(archive.yaz0(yaz0_of(b"abcabcabc!")), b"abcabcabc!")
        with self.assertRaises(ValueError):
            archive.yaz0(b"RARC" + bytes(12))

    def test_rarc_and_unpack(self):
        data = rarc_of({"a.rel": yaz0_of(b"abcabcabc!"), "b.bin": b"xyz"})
        self.assertEqual(set(archive.rarc(data)), {"root/a.rel", "root/b.bin"})
        with tempfile.TemporaryDirectory() as temp:
            packed = Path(temp) / "RELS.arc"
            packed.write_bytes(data)
            written = archive.unpack(packed, Path(temp) / "out")
            self.assertEqual(sorted(p.name for p in written), ["a.rel", "b.bin"])
            self.assertEqual((Path(temp) / "out/root/a.rel").read_bytes(), b"abcabcabc!")


if __name__ == "__main__":
    unittest.main()
