"""GameCube disc images (.iso/.gcm): the header, the file system table, and extraction into a project's `orig/`.

The layout every GameCube disc shares: the boot header (game code, title, the DOL and FST offsets) at 0, bi2 at
0x440, the apploader at 0x2440 (a 0x20-byte header giving its body and trailer sizes), the main DOL where the header
says, and the FST: 12-byte entries (a directory flag and a 24-bit name offset, then the file's offset and length,
or a directory's parent and the index after its last child) followed by their names. Files are read in place, so a
1.4 GB image is never loaded whole.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from .gc import GC_DISC_MAGIC


@dataclass(frozen=True)
class File:
    path: str        # "files/..." as extracted, without a leading slash
    offset: int
    size: int


class Disc:
    def __init__(self, path: Path):
        self.path = path
        with path.open("rb") as stream:
            head = stream.read(0x440)
            if len(head) < 0x440 or struct.unpack(">I", head[0x1C:0x20])[0] != GC_DISC_MAGIC:
                raise ValueError(f"{path} is not a GameCube disc image (no disc magic at 0x1C)")
            self.game_id = head[0:6].decode("ascii", "replace")
            self.title = head[0x20:0x400].split(b"\0", 1)[0].decode("shift_jis", "replace")
            self.dol_offset, self.fst_offset, self.fst_size = struct.unpack(">3I", head[0x420:0x42C])
            stream.seek(0x2440 + 0x14)
            body, trailer = struct.unpack(">2I", stream.read(8))
            self.apploader_size = 0x20 + body + trailer
            stream.seek(self.dol_offset)
            dol = stream.read(0x100)
            offsets, sizes = struct.unpack(">18I", dol[0:0x48]), struct.unpack(">18I", dol[0x90:0xD8])
            self.dol_size = max((o + n for o, n in zip(offsets, sizes) if n), default=0x100)
            stream.seek(self.fst_offset)
            self.fst = stream.read(self.fst_size)
        self.files = self._walk()

    def _walk(self) -> list[File]:
        count = struct.unpack(">I", self.fst[8:12])[0]
        names = count * 12

        def name(index: int) -> str:
            start = names + (struct.unpack(">I", self.fst[index * 12:index * 12 + 4])[0] & 0xFFFFFF)
            return self.fst[start:self.fst.index(b"\0", start)].decode("shift_jis", "replace")
        out: list[File] = []
        stack: list[tuple[int, str]] = []  # (index after the directory's last child, its path)
        index = 1
        while index < count:
            while stack and index >= stack[-1][0]:
                stack.pop()
            flags, first, second = struct.unpack(">III", self.fst[index * 12:index * 12 + 12])
            path = "/".join([p for _, p in stack] + [name(index)])
            if flags >> 24:
                stack.append((second, name(index)))
            else:
                out.append(File(f"files/{path}", first, second))
            index += 1
        return out

    def read(self, offset: int, size: int) -> bytes:
        with self.path.open("rb") as stream:
            stream.seek(offset)
            return stream.read(size)

    def system_files(self) -> list[File]:
        """The parts outside the file system: boot header, bi2, apploader, main DOL, FST."""
        return [File("sys/boot.bin", 0, 0x440), File("sys/bi2.bin", 0x440, 0x2000),
                File("sys/apploader.img", 0x2440, self.apploader_size), File("sys/main.dol", self.dol_offset,
                                                                              self.dol_size),
                File("sys/fst.bin", self.fst_offset, self.fst_size)]

    def sha1(self) -> str:
        digest = hashlib.sha1()
        with self.path.open("rb") as stream:
            while chunk := stream.read(1 << 22):
                digest.update(chunk)
        return digest.hexdigest()

    def extract(self, folder: Path) -> dict:
        """Write sys/ and files/ under `folder`; returns what was written."""
        written = total = 0
        with self.path.open("rb") as stream:
            for item in self.system_files() + self.files:
                target = folder / item.path
                target.parent.mkdir(parents=True, exist_ok=True)
                stream.seek(item.offset)
                remaining = item.size
                with target.open("wb") as out:
                    while remaining:
                        chunk = stream.read(min(remaining, 1 << 22))
                        if not chunk:
                            raise ValueError(f"{self.path} ends inside {item.path}")
                        out.write(chunk)
                        remaining -= len(chunk)
                written += 1
                total += item.size
        return {"game_id": self.game_id, "title": self.title, "files": written, "bytes": total,
                "dol": str(folder / "sys" / "main.dol"),
                "rels": [f.path for f in self.files if f.path.lower().endswith(".rel")]}
