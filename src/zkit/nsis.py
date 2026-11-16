"""The files an NSIS installer would put in its install folder, read without running it (how LLVM ships for Windows).

Layout (NSIS 2 and 3): a "first header" at a 512-byte boundary - flags, 0xDEADBEEF, "NullsoftInst", the header's
size and the size of everything after it. Then either one compressed stream (solid) of [u32 header size][header]
[data], or (not solid) the header and every file as their own blocks, each a u32 size whose top bit says compressed.
Each file in the data is a u32 size and its bytes. The header holds the install script: SetOutPath is a CreateDir
entry with its second parameter set, File an ExtractFile entry naming a string and a data offset. Strings carry
variables as codes: NSIS 2 (ANSI) uses 252-255, NSIS 3 uses 1-4 (ANSI or UTF-16)."""

import lzma
import struct
import zlib
from collections.abc import Iterator
from pathlib import Path

SIGNATURE = b"\xef\xbe\xad\xdeNullsoftInst"
CREATE_DIR, EXTRACT_FILE, ASSIGN_VAR = 11, 20, 25
INSTDIR, OUTDIR = 21, 22
CHUNK = 1 << 20


def is_installer(path: Path) -> bool:
    try:
        return _first_header(path) is not None
    except OSError:
        return False


def _first_header(path: Path) -> tuple[int, int, int] | None:
    """(offset of the data after the first header, header size, size of all that follows) or None."""
    with path.open("rb") as file:
        if file.read(2) != b"MZ":
            return None
        file.seek(0)
        offset = 0
        while block := file.read(512):
            if block[4:20] == SIGNATURE and len(block) >= 28:
                header_size, total = struct.unpack_from("<II", block, 20)
                return offset + 28, header_size, total
            offset += len(block)
    return None


def _lzma(props: bytes, bcj: bool):
    value = props[0]
    if value >= 9 * 5 * 5:
        raise ValueError("bad LZMA properties")
    lc, rest = value % 9, value // 9
    lp, pb = rest % 5, rest // 5
    lzma1 = {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": int.from_bytes(props[1:5], "little")}
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_X86}, lzma1] if bcj else [lzma1])


def _decoders(head: bytes) -> Iterator[tuple[str, int, object]]:
    """Ways the compressed bytes starting with `head` may be stored: (name, bytes to skip, new decompressor)."""
    if head[:1] == b"\x5d":
        yield "lzma", 5, lambda: _lzma(head[:5], False)
    if head[:1] in (b"\x00", b"\x01") and head[1:2] == b"\x5d":
        yield "lzma", 6, lambda: _lzma(head[1:6], head[0] == 1)
    yield "deflate", 0, lambda: zlib.decompressobj(-15)


def _chunks(file, start: int, size: int | None, decompressor) -> Iterator[bytes]:
    file.seek(start)
    left = size
    while left is None or left > 0:
        data = file.read(CHUNK if left is None else min(CHUNK, left))
        if not data:
            return
        if left is not None:
            left -= len(data)
        if decompressor is None:
            yield data
            continue
        out = decompressor.decompress(data)
        if out:
            yield out
        if decompressor.eof:
            return


class _Reader:
    """Sequential reads over a stream of chunks."""

    def __init__(self, chunks: Iterator[bytes]):
        self.chunks, self.buffer, self.position = chunks, memoryview(b""), 0

    def _fill(self) -> bool:
        if self.buffer:
            return True
        for chunk in self.chunks:
            if chunk:
                self.buffer = memoryview(chunk)
                return True
        return False

    def pipe(self, size: int, sinks: list) -> None:
        while size:
            if not self._fill():
                raise ValueError("the installer's data ends early")
            piece, self.buffer = self.buffer[:size], self.buffer[size:]
            for sink in sinks:
                sink(piece)
            size -= len(piece)
            self.position += len(piece)

    def read(self, size: int) -> bytes:
        out = bytearray()
        self.pipe(size, [out.extend])
        return bytes(out)


class Installer:
    """An NSIS installer: its header decoded and its files listed by install path."""

    def __init__(self, path: Path):
        found = _first_header(path)
        if found is None:
            raise ValueError(f"{path} is not an NSIS installer")
        self.path, (self.start, header_size, _) = path, found
        with path.open("rb") as file:
            file.seek(self.start)
            head = file.read(8)
            self.solid, self.header = self._read_header(file, head, header_size)
        self.files = self._files()

    def _read_header(self, file, head: bytes, header_size: int) -> tuple[bool, bytes]:
        for _, skip, new in _decoders(head):
            try:
                reader = _Reader(_chunks(file, self.start + skip, None, new()))
                if int.from_bytes(reader.read(4), "little") == header_size:
                    self.decoder, self.skip = new, skip
                    return True, reader.read(header_size)
            except (lzma.LZMAError, zlib.error, ValueError):
                pass
        word = int.from_bytes(head[:4], "little")
        if word & 0x80000000:
            size = word & 0x7FFFFFFF
            for method, skip, new in _decoders(head[4:]):
                try:
                    header = _Reader(_chunks(file, self.start + 4 + skip, size - skip, new())).read(header_size)
                    self.method, self.data = (method, skip), self.start + 4 + size
                    return False, header
                except (lzma.LZMAError, zlib.error, ValueError):
                    pass
        elif word == header_size:
            self.method, self.data = None, self.start + 4 + word
            file.seek(self.start + 4)
            return False, file.read(word)
        raise ValueError(f"{self.path}: an NSIS installer whose compression this reader does not know (bzip2?)")

    # The install script.

    def _blocks(self) -> list[tuple[int, int]]:
        return [struct.unpack_from("<II", self.header, 4 + 8 * index) for index in range(8)]

    def _strings_style(self, table: bytes) -> tuple[bool, tuple[int, int, int, int]]:
        """(UTF-16?, the (lang, shell, var, skip) codes)."""
        unicode = len(table) >= 64 and table[1:64:2].count(0) > 28
        if unicode:
            return True, (1, 2, 3, 4)
        old = sum(1 for at in range(len(table) - 2) if table[at] == 253 and table[at + 1] & 0x80 and table[at + 2] & 0x80)
        new = sum(1 for at in range(len(table) - 2) if table[at] == 3 and table[at + 1] & 0x80 and table[at + 2] & 0x80)
        return False, ((255, 254, 253, 252) if old >= new else (1, 2, 3, 4))

    def string(self, offset: int, variables: dict[int, str] | None = None) -> str:
        """The string at `offset`, with the given variables' values filled in and any other variable as $V<n>."""
        table = self.header[self._strings:]
        lang, shell, var, skip = self._codes
        out = []
        if self._unicode:
            at = offset * 2
            while at + 1 < len(table) and (code := table[at] | table[at + 1] << 8):
                at += 2
                if code in (lang, shell, var, skip):
                    value = table[at] | table[at + 1] << 8
                    at += 2
                    if code == skip:
                        out.append(chr(value))
                    else:
                        out.append(self._code(code, value & 0x7FFF, value & 0xFF, value >> 8, variables or {}))
                else:
                    out.append(chr(code))
            return "".join(out)
        at = offset
        while at < len(table) and (code := table[at]):
            at += 1
            if code in (lang, shell, var, skip):
                if code == skip:
                    out.append(chr(table[at]))
                    at += 1
                    continue
                low, high = table[at], table[at + 1]
                at += 2
                out.append(self._code(code, (low & 0x7F) | (high & 0x7F) << 7, low, high, variables or {}))
            else:
                out.append(chr(code) if code < 128 else bytes([code]).decode("cp1252", "replace"))
        return "".join(out)

    def _code(self, code: int, number: int, low: int, high: int, variables: dict[int, str]) -> str:
        lang, shell, var, _ = self._codes
        if code == var:
            return variables.get(number, f"$V{number}")
        if code == shell:
            return f"$SHELL{low}_{high}"
        return f"$(LANG{number})"

    def _files(self) -> dict[str, int]:
        """Install path (relative to the install folder, with /) -> data offset, in script order."""
        blocks = self._blocks()
        self._strings = blocks[3][0]
        self._unicode, self._codes = self._strings_style(self.header[blocks[3][0]:blocks[4][0] or len(self.header)])
        entries_at, count = blocks[2]
        # Walked in order, as 7-Zip does: SetOutPath sets $OUTDIR, StrCpy (whole strings) sets a variable - how
        # `File /r` reaches its subfolders, through $_OUTDIR.
        files, variables = {}, {INSTDIR: "$INSTDIR"}
        for index in range(count):
            which, *parm = struct.unpack_from("<7I", self.header, entries_at + 28 * index)
            if which == CREATE_DIR and parm[1]:
                variables[OUTDIR] = self.string(parm[0], variables)
            elif which == ASSIGN_VAR and not parm[2] and not parm[3]:
                variables[parm[0]] = self.string(parm[1], variables)
            elif which == EXTRACT_FILE:
                name = _inside(self.string(parm[1], variables), variables.get(OUTDIR))
                if name is not None:
                    files.setdefault(name, parm[2])
        return files

    # The data.

    def extract(self, place) -> int:
        """Write each file to place(its install path), skipping those it gives None; the number written."""
        wanted: dict[int, list[Path]] = {}
        for name, offset in self.files.items():
            destination = place(name)
            if destination is not None:
                wanted.setdefault(offset, []).append(destination)
        with self.path.open("rb") as file:
            reader = None
            if self.solid:
                reader = _Reader(_chunks(file, self.start + self.skip, None, self.decoder()))
                reader.read(4 + len(self.header))
                base = reader.position
            for offset in sorted(wanted):
                if self.solid:
                    reader.pipe(base + offset - reader.position, [])
                    size = int.from_bytes(reader.read(4), "little")
                    source = reader
                else:
                    file.seek(self.data + offset)
                    word = int.from_bytes(file.read(4), "little")
                    size = word & 0x7FFFFFFF
                    if word & 0x80000000:
                        file.seek(self.data + offset + 4)
                        # Every block is compressed as the header was (its own LZMA properties first).
                        way = next((way for way in _decoders(file.read(6)) if way[:2] == self.method), None)
                        if way is None:
                            raise ValueError(f"{self.path}: a file compressed unlike the header")
                        _, skip, new = way
                        source = _Reader(_chunks(file, self.data + offset + 4 + skip, size - skip, new()))
                        size = None
                    else:
                        source = _Reader(_chunks(file, self.data + offset + 4, size, None))
                outs = []
                for destination in wanted[offset]:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    outs.append(destination.open("wb"))
                try:
                    if size is None:
                        for chunk in source.chunks:
                            for out in outs:
                                out.write(chunk)
                    else:
                        source.pipe(size, [out.write for out in outs])
                finally:
                    for out in outs:
                        out.close()
                for destination in wanted[offset]:
                    destination.chmod(0o755)
        return sum(len(places) for places in wanted.values())


def _inside(path: str, outdir: str | None) -> str | None:
    """`path` relative to $INSTDIR with /, or None when it lies elsewhere ($PLUGINSDIR, $TEMP, ...)."""
    path = path.replace("\\", "/")
    if not path.startswith("$INSTDIR"):
        if path.startswith("$") or ":" in path or path.startswith("/") or outdir is None:
            return None
        path = f"{outdir.replace(chr(92), '/')}/{path}"
        if not path.startswith("$INSTDIR"):
            return None
    path = path[len("$INSTDIR"):]
    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == ".." or "$" in part:
            if part == ".." and parts:
                parts.pop()
                continue
            return None
        parts.append(part)
    return "/".join(parts)
