"""What differs between consoles, behind one interface: how the original executable is read, how its code is
decoded, how addresses are written, and which disassembler and decompiler language fit.

- gamecube (also Wii): a DOL (or the main DOL inside a disc image), big-endian PowerPC, CodeWarrior names.
- switch: an NSO module or an ELF of one, little-endian AArch64, Itanium names. Addresses are stored as
  offsets from the module base and written base + offset (0x7100000000 by the usual convention).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ANY_HEX = re.compile(r"^(?:0[xX])?([0-9A-Fa-f]{6,16})$")


@dataclass(frozen=True)
class Section:
    kind: str       # "text" or "data"
    address: int
    size: int


class Platform:
    name = "generic"
    pointer_size = 4
    endian = ">"
    base = 0
    digits = 8
    ghidra_language = ""
    # The compiler gives every translation unit its own copy of each literal and the linker keeps them apart
    # (CodeWarrior); clang's mergeable sections share one copy across units, so literals prove nothing there.
    literals_per_unit = False

    def open(self, path: Path):
        raise NotImplementedError

    def sections(self, image) -> list[Section]:
        raise NotImplementedError

    def words(self, image, address: int, size: int) -> list[int]:
        return image.words(address, size)

    def read(self, image, address: int, size: int) -> bytes:
        return image.read(address, size)

    def calls(self, image, start: int, size: int) -> list[tuple[int, int]]:
        raise NotImplementedError

    def addresses(self, image, start: int, size: int, context: dict) -> list[tuple[int, int, str]]:
        """(pc, address, kind) for absolute addresses straight-line code forms; kind: addr, load, store, f32, f64."""
        raise NotImplementedError

    def indirect_calls(self, image, start: int, size: int) -> int:
        raise NotImplementedError

    def data_pointers(self, image) -> Iterable[tuple[int, int]]:
        """(holder, pointee) for pointer-sized words in data that point into the image."""
        raise NotImplementedError

    def in_image(self, image, value: int) -> bool:
        raise NotImplementedError

    def text(self, address: int) -> str:
        return f"0x{address + self.base:0{self.digits}X}"

    def parse(self, text: str) -> int | None:
        """An address as written by people or tools (with or without 0x, with or without the base)."""
        match = ANY_HEX.match(text.strip())
        if not match or (len(match[1]) < self.digits and not text.strip().lower().startswith("0x")):
            return None
        value = int(match[1], 16)
        return value - self.base if self.base and value >= self.base else value

    def cite_pattern(self) -> str:
        """Regex with one group finding original addresses cited in text."""
        raise NotImplementedError

    @property
    def cite_hint(self) -> str:
        """A character every cited address contains (a fast filter before the regex)."""
        return "8" if self.name == "gamecube" else f"{self.base >> 32:X}"[:1] or "0"

    def cite_value(self, group: str) -> int:
        value = int(group, 16)
        return value - self.base if self.base and value >= self.base else value


class GameCube(Platform):
    name = "gamecube"
    ghidra_language = "PowerPC:BE:32:Gekko_Broadway"
    literals_per_unit = True
    IMAGE = (0x80000000, 0x81800000)

    def open(self, path: Path):
        from .gc import Dol
        return Dol.load(path)

    def sections(self, image) -> list[Section]:
        return [Section(s.kind, s.address, s.size) for s in image.sections]

    def calls(self, image, start: int, size: int) -> list[tuple[int, int]]:
        from .gc import direct_calls
        return direct_calls(image, start, size)

    def addresses(self, image, start: int, size: int, context: dict) -> list[tuple[int, int, str]]:
        from .gc import track_addresses
        try:
            words = image.words(start, size)
        except ValueError:
            return []
        return [(pc, value, kind) for pc, (value, kind) in track_addresses(words, start, context.get("sda", {})).items()]

    def indirect_calls(self, image, start: int, size: int) -> int:
        try:
            return sum(1 for w in image.words(start, size) if w == 0x4E800421)  # bctrl
        except ValueError:
            return 0

    def data_pointers(self, image) -> Iterable[tuple[int, int]]:
        for section in image.sections:
            if section.kind != "data":
                continue
            raw = image.raw[section.offset:section.offset + section.size - section.size % 4]
            for index, word in enumerate(struct.unpack(f">{len(raw) // 4}I", raw)):
                if self.IMAGE[0] <= word < self.IMAGE[1]:
                    yield section.address + index * 4, word

    def in_image(self, image, value: int) -> bool:
        return self.IMAGE[0] <= value < self.IMAGE[1]

    def cite_pattern(self) -> str:
        return r"(?<![0-9A-Fa-f])(?:0x)?(8[01][0-9A-Fa-f]{6})(?![0-9A-Fa-f])"


class Switch(Platform):
    name = "switch"
    pointer_size = 8
    endian = "<"
    digits = 10
    ghidra_language = "AARCH64:LE:64:v8A"

    def __init__(self, base: int = 0x7100000000):
        self.base = base

    def open(self, path: Path):
        from .nx import load
        return load(path)

    def sections(self, image) -> list[Section]:
        return [Section("text" if s.kind == "code" else "data", s.offset, s.size) for s in image.segments
                if s.name != "bss"]

    def calls(self, image, start: int, size: int) -> list[tuple[int, int]]:
        from .aarch64 import direct_calls, tail_calls
        try:
            words = image.words(start, size)
        except ValueError:
            return []
        return direct_calls(words, start) + tail_calls(words, start, start + size)

    def addresses(self, image, start: int, size: int, context: dict) -> list[tuple[int, int, str]]:
        from .aarch64 import track_addresses
        try:
            words = image.words(start, size)
        except ValueError:
            return []
        out = []
        for pc, (address, kind) in track_addresses(words, start, image.pointers.get).items():
            out.append((pc, address, kind))
            # A load from a pointer slot (the GOT, a vtable reference) also refers to what the slot holds.
            if kind == "load" and address in image.pointers:
                out.append((pc, image.pointers[address], "addr"))
        return out

    def indirect_calls(self, image, start: int, size: int) -> int:
        from .aarch64 import indirect_calls
        try:
            return indirect_calls(image.words(start, size))
        except ValueError:
            return 0

    def data_pointers(self, image) -> Iterable[tuple[int, int]]:
        return image.pointers.items()

    def in_image(self, image, value: int) -> bool:
        return 0 <= value < len(image.image)

    def cite_pattern(self) -> str:
        high = f"{self.base >> 32:X}"
        return rf"(?<![0-9A-Fa-f])(?:0x)?({high}[0-9A-Fa-f]{{8}})(?![0-9A-Fa-f])"


def demangle_itanium(names: list[str]) -> list[str | None]:
    """Itanium C++ names demangled in one batch (llvm-cxxfilt or c++filt); None where nothing changes."""
    import shutil
    import subprocess
    tool = shutil.which("llvm-cxxfilt") or shutil.which("c++filt")
    if tool is None or not names:
        return [None] * len(names)
    result = subprocess.run([tool], input="\n".join(names), capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=300)
    lines = result.stdout.splitlines()
    if len(lines) != len(names):
        return [None] * len(names)
    return [line if line != name else None for name, line in zip(names, lines)]


def for_target(target: dict) -> Platform:
    kind = (target.get("platform") or "gamecube").lower()
    if kind in ("gamecube", "wii", "gc"):
        return GameCube()
    if kind in ("switch", "nx"):
        base = target.get("base", 0x7100000000)
        return Switch(int(base, 0) if isinstance(base, str) else int(base))
    raise ValueError(f"Unknown platform {kind!r}; use gamecube or switch")
