"""Relocatable and executable ELF files, 32 or 64 bit, either byte order: sections, symbols, relocations.

Enough to compare compiled objects with the original's split objects (GameCube PowerPC from decomp-toolkit,
Switch AArch64 from clang) without a dependency.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS, SHT_REL, SHT_DYNSYM = 2, 3, 4, 8, 9, 11
STT_NAMES = {0: "notype", 1: "object", 2: "func", 3: "section", 4: "file", 5: "common", 6: "tls"}
STB_NAMES = {0: "local", 1: "global", 2: "weak", 10: "unique"}
MACHINES = {20: "ppc", 21: "ppc64", 40: "arm", 62: "x86_64", 183: "aarch64", 8: "mips"}


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int
    align: int = 1


@dataclass(frozen=True)
class Symbol:
    index: int
    name: str
    value: int
    size: int
    kind: str      # func, object, section, file, notype
    bind: str      # local, global, weak
    section: int   # section index; 0 = undefined, 0xFFF1 = absolute, 0xFFF2 = common


@dataclass(frozen=True)
class Relocation:
    offset: int
    type: int
    symbol: int
    addend: int


class Elf:
    def __init__(self, raw: bytes, path: str = "<bytes>"):
        if raw[:4] != b"\x7fELF":
            raise ValueError(f"{path} is not an ELF file")
        self.raw, self.path = raw, path
        self.bits = 64 if raw[4] == 2 else 32
        self.endian = "<" if raw[5] == 1 else ">"
        e = self.endian
        if self.bits == 64:
            (self.type, self.machine_id, _, self.entry, _, shoff, _, _, _, _, shentsize, shnum,
             shstrndx) = struct.unpack(e + "HHIQQQIHHHHHH", raw[16:64])
        else:
            (self.type, self.machine_id, _, self.entry, _, shoff, _, _, _, _, shentsize, shnum,
             shstrndx) = struct.unpack(e + "HHIIIIIHHHHHH", raw[16:52])
        self.machine = MACHINES.get(self.machine_id, f"machine{self.machine_id}")
        headers = []
        for i in range(shnum):
            base = shoff + i * shentsize
            if self.bits == 64:
                name, kind, flags, addr, off, size, link, info, align, entsize = struct.unpack(
                    e + "IIQQQQIIQQ", raw[base:base + 64])
            else:
                name, kind, flags, addr, off, size, link, info, align, entsize = struct.unpack(
                    e + "IIIIIIIIII", raw[base:base + 40])
            headers.append((name, kind, flags, addr, off, size, link, info, entsize, align))
        names = headers[shstrndx] if shstrndx < len(headers) else None
        self.sections = [Section(i, self._string(names[4], h[0]) if names else "", *h[1:])
                         for i, h in enumerate(headers)]
        self._symbols: list[Symbol] | None = None

    @classmethod
    def load(cls, path: Path) -> "Elf":
        return cls(path.read_bytes(), str(path))

    def _string(self, table_offset: int, index: int) -> str:
        end = self.raw.find(b"\0", table_offset + index)
        return self.raw[table_offset + index:end].decode("utf-8", errors="replace")

    def section(self, name: str) -> Section | None:
        return next((s for s in self.sections if s.name == name), None)

    def data(self, section: Section) -> bytes:
        if section.type == SHT_NOBITS:
            return b""
        return self.raw[section.offset:section.offset + section.size]

    @property
    def symbols(self) -> list[Symbol]:
        if self._symbols is None:
            table = next((s for s in self.sections if s.type == SHT_SYMTAB), None) or \
                next((s for s in self.sections if s.type == SHT_DYNSYM), None)
            self._symbols = [] if table is None else self._read_symbols(table)
        return self._symbols

    def _read_symbols(self, table: Section) -> list[Symbol]:
        strings = self.sections[table.link].offset
        size = 24 if self.bits == 64 else 16
        out = []
        for i in range(table.size // size):
            base = table.offset + i * size
            if self.bits == 64:
                name, info, _, shndx, value, length = struct.unpack(self.endian + "IBBHQQ", self.raw[base:base + 24])
            else:
                name, value, length, info, _, shndx = struct.unpack(self.endian + "IIIBBH", self.raw[base:base + 16])
            out.append(Symbol(i, self._string(strings, name), value, length, STT_NAMES.get(info & 0xF, str(info & 0xF)),
                              STB_NAMES.get(info >> 4, str(info >> 4)), shndx))
        return out

    def relocations(self, target: Section) -> list[Relocation]:
        """Relocations that apply to one section, from its .rel/.rela section."""
        out = []
        for section in self.sections:
            if section.type not in (SHT_REL, SHT_RELA) or section.info != target.index:
                continue
            rela = section.type == SHT_RELA
            size = (24 if rela else 16) if self.bits == 64 else (12 if rela else 8)
            for i in range(section.size // size):
                base = section.offset + i * size
                chunk = self.raw[base:base + size]
                if self.bits == 64:
                    offset, info = struct.unpack(self.endian + "QQ", chunk[:16])
                    addend = struct.unpack(self.endian + "q", chunk[16:24])[0] if rela else 0
                    out.append(Relocation(offset, info & 0xFFFFFFFF, info >> 32, addend))
                else:
                    offset, info = struct.unpack(self.endian + "II", chunk[:8])
                    addend = struct.unpack(self.endian + "i", chunk[8:12])[0] if rela else 0
                    out.append(Relocation(offset, info & 0xFF, info >> 8, addend))
        return sorted(out, key=lambda r: r.offset)

    def functions(self) -> dict[str, Symbol]:
        """Defined function symbols by name (the first definition wins)."""
        out: dict[str, Symbol] = {}
        for symbol in self.symbols:
            if symbol.kind == "func" and 0 < symbol.section < 0xFF00 and symbol.name not in out:
                out[symbol.name] = symbol
        return out
