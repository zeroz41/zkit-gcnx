"""Nintendo's packed files on GameCube discs: Yaz0 compression and RARC archives.

Yaz0 ("Yaz0", the decompressed size, 8 reserved bytes, then groups of one code byte and eight items: a set bit
copies a byte, a clear bit a back-reference of 2 bytes (length 2-17 and distance 1-4096) or 3 bytes (length
18-273)). RARC ("RARC" header, nodes naming directories, 20-byte entries naming files with their data offset and
size, a string table): many games ship their REL modules inside one.
"""

from __future__ import annotations

import struct
from pathlib import Path


def is_yaz0(data: bytes) -> bool:
    return data[:4] == b"Yaz0"


def yaz0(data: bytes) -> bytes:
    """The decompressed bytes of a Yaz0 file."""
    if not is_yaz0(data):
        raise ValueError("not Yaz0 data")
    size = struct.unpack(">I", data[4:8])[0]
    out = bytearray()
    source = 16
    while len(out) < size:
        code = data[source]
        source += 1
        for bit in range(7, -1, -1):
            if len(out) >= size:
                break
            if code >> bit & 1:
                out.append(data[source])
                source += 1
                continue
            first, second = data[source], data[source + 1]
            source += 2
            distance = ((first & 0x0F) << 8 | second) + 1
            length = first >> 4
            if length == 0:
                length = data[source] + 0x12
                source += 1
            else:
                length += 2
            start = len(out) - distance
            if start < 0:
                raise ValueError("Yaz0 back-reference before the start of the data")
            for index in range(length):                      # may overlap what it is writing
                out.append(out[start + index])
    return bytes(out)


def rarc(data: bytes) -> dict[str, bytes]:
    """{path: bytes} of every file in a RARC archive (Yaz0-compressed archives are decompressed first)."""
    if is_yaz0(data):
        data = yaz0(data)
    if data[:4] != b"RARC":
        raise ValueError("not a RARC archive")
    data_offset = struct.unpack(">I", data[0x0C:0x10])[0] + 0x20
    info = 0x20
    node_count, node_offset, _entries, entry_offset, _strings_size, string_offset = struct.unpack(
        ">IIIIII", data[info:info + 24])
    node_offset += info
    entry_offset += info
    string_offset += info

    def name(offset: int) -> str:
        start = string_offset + offset
        return data[start:data.index(b"\0", start)].decode("shift_jis", "replace")
    out: dict[str, bytes] = {}

    def walk(node: int, prefix: str) -> None:
        base = node_offset + node * 16
        _kind, name_offset, _hash, count, first = struct.unpack(">4sIHHI", data[base:base + 16])
        for index in range(first, first + count):
            entry = entry_offset + index * 20
            _id, _hash, flags, entry_name, value, size = struct.unpack(">HHHHII", data[entry:entry + 16])
            label = name(entry_name & 0xFFFF if not flags >> 8 else entry_name)
            if (flags >> 8) & 0x02:                           # a directory: value is its node
                if label not in (".", ".."):
                    walk(value, f"{prefix}{label}/")
                continue
            out[f"{prefix}{label}"] = data[data_offset + value:data_offset + value + size]
    if node_count:
        base = node_offset
        walk(0, f"{name(struct.unpack('>I', data[base + 4:base + 8])[0])}/")
    return out


def unpack(path: Path, folder: Path) -> list[Path]:
    """Write a packed file's contents under `folder`, decompressed: a RARC's files, or a Yaz0 file."""
    data = path.read_bytes()
    plain = yaz0(data) if is_yaz0(data) else data
    if plain[:4] == b"RARC":
        written = []
        for name, blob in rarc(plain).items():
            blob = yaz0(blob) if is_yaz0(blob) else blob          # members are often compressed one by one
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
            written.append(target)
        return written
    target = folder / path.name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(plain)
    return [target]
