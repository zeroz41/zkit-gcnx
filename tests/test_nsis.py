import support  # noqa: F401  (isolates config, cache and state)
import lzma
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import fetch, nsis

PLUGINSDIR, ALT_OUTDIR = 26, 31


class Strings:
    """An NSIS string table: text with variables as {n}, in one of the three encodings."""

    def __init__(self, style: str):
        self.style, self.table = style, bytearray(b"\0\0" if style == "unicode" else b"\0")

    def add(self, text: str) -> int:
        at = len(self.table) // (2 if self.style == "unicode" else 1)
        var = {"nsis2": 253, "nsis3": 3, "unicode": 3}[self.style]
        out = bytearray()
        for piece in text.replace("}", "{").split("{"):
            if piece.isdigit():
                number = int(piece)
                if self.style == "unicode":
                    out += struct.pack("<HH", var, number | 0x8000)
                else:
                    out += bytes([var, (number & 0x7F) | 0x80, (number >> 7) | 0x80])
            else:
                out += piece.encode("utf-16-le" if self.style == "unicode" else "cp1252")
        self.table += out + (b"\0\0" if self.style == "unicode" else b"\0")
        return at


def _lzma_stream(data: bytes, filter_flag: bool = False) -> bytes:
    props = bytes([(2 * 5 + 0) * 9 + 3]) + (1 << 16).to_bytes(4, "little")
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}])
    return (b"\0" if filter_flag else b"") + props + raw


def _block(raw: bytes) -> bytes:
    packed = _lzma_stream(raw)
    return struct.pack("<I", 0x80000000 | len(packed)) + packed


def installer(path: Path, style: str, packing: str, files: list[tuple[str, str, bytes]]) -> None:
    """Write an NSIS installer whose script sets each output folder and extracts each name's bytes (identical bytes
    stored once). Folders are NSIS strings ({21} is $INSTDIR); an "alt:" one is set through $_OUTDIR, as `File /r`
    does, and a last file goes to $PLUGINSDIR."""
    strings, entries, contents = Strings(style), [], []
    for outdir, name, body in files:
        if outdir.startswith("alt:"):  # StrCpy $_OUTDIR <folder>; SetOutPath $_OUTDIR
            entries.append([25, ALT_OUTDIR, strings.add(outdir[4:]), 0, 0, 0, 0])
            outdir = "{%d}" % ALT_OUTDIR
        entries.append([11, strings.add(outdir), 1, 0, 0, 0, 0])
        if body not in contents:
            contents.append(body)
        entries.append([20, 0, strings.add(name), contents.index(body), 0, 0, 0])
    entries.append([20, 0, strings.add("{%d}\\System.dll" % PLUGINSDIR), 0, 0, 0, 0])
    pieces = [_block(c) if packing == "lzma-blocks" else struct.pack("<I", len(c)) + c for c in contents]
    offsets = [sum(map(len, pieces[:index])) for index in range(len(pieces))]
    for entry in entries:
        if entry[0] == 20:
            entry[3] = offsets[entry[3]]
    entries_at = 4 + 8 * 8
    strings_at = entries_at + 28 * len(entries)
    blocks = [(0, 0), (0, 0), (entries_at, len(entries)), (strings_at, 0), (strings_at + len(strings.table), 0),
              (0, 0), (0, 0), (0, 0)]
    header = struct.pack("<I", 0) + b"".join(struct.pack("<II", *b) for b in blocks) + \
        b"".join(struct.pack("<7I", *e) for e in entries) + bytes(strings.table)
    data = b"".join(pieces)
    if packing == "solid-lzma":
        body = _lzma_stream(struct.pack("<I", len(header)) + header + data, filter_flag=True)
    elif packing == "stored":
        body = struct.pack("<I", len(header)) + header + data
    else:
        body = _block(header) + data
    first = struct.pack("<I", 0) + nsis.SIGNATURE + struct.pack("<II", len(header), len(body))
    path.write_bytes(b"MZ" + bytes(1022) + first + body)


FILES = [("{21}\\bin", "clang.exe", b"clang" * 300), ("{21}\\bin", "clang++.exe", b"clang" * 300),
         ("alt:{21}\\lib\\clang\\3.9.1", "include\\stddef.h", b"#define NULL 0\n"),
         ("{21}", "..\\outside.txt", b"no")]


class InstallerTests(unittest.TestCase):
    def test_every_encoding_and_packing_lists_and_extracts_the_installed_files(self):
        for style in ("nsis2", "nsis3", "unicode"):
            for packing in ("stored", "solid-lzma", "lzma-blocks"):
                with self.subTest(style=style, packing=packing), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    installer(root / "setup.exe", style, packing, FILES)
                    self.assertTrue(nsis.is_installer(root / "setup.exe"))
                    found = nsis.Installer(root / "setup.exe")
                    self.assertEqual(found.solid, packing == "solid-lzma")
                    # $PLUGINSDIR and a path climbing out of $INSTDIR are not installed files.
                    self.assertEqual(list(found.files), ["bin/clang.exe", "bin/clang++.exe",
                                                         "lib/clang/3.9.1/include/stddef.h"])
                    count = found.extract(lambda name: root / "out" / name)
                    self.assertEqual(count, 3)
                    self.assertEqual((root / "out/bin/clang++.exe").read_bytes(), b"clang" * 300)
                    self.assertEqual((root / "out/lib/clang/3.9.1/include/stddef.h").read_bytes(),
                                     b"#define NULL 0\n")

    def test_unpack_strips_and_keeps_members_of_an_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer(root / "setup.exe", "nsis3", "solid-lzma", FILES)
            count = fetch.unpack(root / "setup.exe", root / "out", "setup", ("clang*.exe",), strip=1)
            self.assertEqual(count, 2)
            self.assertEqual(sorted(p.name for p in (root / "out").iterdir()), ["clang++.exe", "clang.exe"])

    def test_other_files_are_not_installers(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plain.exe"
            path.write_bytes(b"MZ" + bytes(4000))
            self.assertFalse(nsis.is_installer(path))
            with self.assertRaisesRegex(ValueError, "not an NSIS installer"):
                nsis.Installer(path)


if __name__ == "__main__":
    unittest.main()
