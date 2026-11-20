"""Relocatable and executable ELF files, 32 or 64 bit, either byte order: sections, symbols, relocations.

Enough to compare compiled objects with the original's split objects (GameCube PowerPC,
Switch AArch64 from clang) without a dependency.
"""

from __future__ import annotations

import collections
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
    align: int = 0


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


_LOADED: "collections.OrderedDict[tuple, Elf]" = collections.OrderedDict()
_LOADED_KEEP = 8


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
        self._relocations: dict[int, list[Relocation]] = {}
        self._functions: dict[str, Symbol] | None = None

    @classmethod
    def load(cls, path: Path) -> "Elf":
        """The parsed file, reused while it is unchanged on disk: comparing a unit's functions one by one reads the
        same two objects once instead of once per function."""
        try:
            stat = Path(path).stat()
            key = (str(Path(path).resolve()), stat.st_size, stat.st_mtime_ns, stat.st_ino)
        except OSError:
            key = None
        cached = _LOADED.get(key) if key else None
        if cached is not None:
            _LOADED.move_to_end(key)
            return cached
        elf = cls(Path(path).read_bytes(), str(path))
        if key:
            _LOADED[key] = elf
            while len(_LOADED) > _LOADED_KEEP:
                _LOADED.popitem(last=False)
        return elf

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
        """Relocations that apply to one section, from its .rel/.rela section, sorted by offset (read once; do not
        modify the list)."""
        if target.index not in self._relocations:
            self._relocations[target.index] = self._read_relocations(target)
        return self._relocations[target.index]

    def _read_relocations(self, target: Section) -> list[Relocation]:
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
        """Defined function symbols by name (the first definition wins; read once, do not modify)."""
        if self._functions is None:
            out: dict[str, Symbol] = {}
            for symbol in self.symbols:
                if symbol.kind == "func" and 0 < symbol.section < 0xFF00 and symbol.name not in out:
                    out[symbol.name] = symbol
            self._functions = out
        return self._functions


SHT_GROUP, GRP_COMDAT, SHF_EXECINSTR = 17, 1, 0x4


def without_foreign_data(raw: bytes, owned: set[str]) -> tuple[bytes, list[str]]:
    """The object as the link keeps it for a unit that owns the names in `owned`: each COMDAT group of data only
    (an inline function's static, its guard, a template's vtable) whose signature `owned` lacks is the copy another
    unit's object provided, so the link discarded it. Its sections are emptied and its symbols left undefined, as
    references to that other copy; layout, code and every other section are unchanged. Returns the bytes and the
    discarded groups' signatures (no change: the same bytes, [])."""
    elf = Elf(raw)
    discarded: dict[int, str] = {}
    for section in elf.sections:
        if section.type != SHT_GROUP or section.size < 8 or section.info >= len(elf.symbols):
            continue
        words = struct.unpack(f"{elf.endian}{section.size // 4}I", elf.data(section))
        members = [i for i in words[1:] if i < len(elf.sections)]
        signature = elf.symbols[section.info].name
        if not words[0] & GRP_COMDAT or not signature or signature in owned or \
                any(elf.sections[i].flags & SHF_EXECINSTR for i in members):
            continue
        discarded.update(dict.fromkeys(members, signature))
    if not discarded:
        return raw, []
    out, e = bytearray(raw), elf.endian
    if elf.bits == 64:
        shoff, shentsize = struct.unpack_from(e + "Q", raw, 40)[0], struct.unpack_from(e + "H", raw, 58)[0]
        size_at, size_format = 32, "Q"
    else:
        shoff, shentsize = struct.unpack_from(e + "I", raw, 32)[0], struct.unpack_from(e + "H", raw, 46)[0]
        size_at, size_format = 20, "I"
    for index in discarded:
        struct.pack_into(e + size_format, out, shoff + index * shentsize + size_at, 0)
    table = next((s for s in elf.sections if s.type == SHT_SYMTAB), None)
    for symbol in elf.symbols:
        if symbol.section not in discarded or symbol.kind == "section" or table is None:
            continue
        base = table.offset + symbol.index * (24 if elf.bits == 64 else 16)
        if elf.bits == 64:   # st_shndx, st_value, st_size
            struct.pack_into(e + "HQQ", out, base + 6, 0, 0, 0)
        else:
            struct.pack_into(e + "II", out, base + 4, 0, 0)
            struct.pack_into(e + "H", out, base + 14, 0)
    return bytes(out), list(dict.fromkeys(discarded.values()))


def with_got_loads_relaxed(raw: bytes, imports: set[str]) -> tuple[bytes, int]:
    """The AArch64 object as a relaxing lld links it into a module that defines every symbol but `imports` (the
    module's imported names): each GOT load lld turns into `adrp` + `add` (`aarch64.relaxed_pairs`, the rules
    that need no addresses) written so, its two relocations then ADR_PREL_PG_HI21 + ADD_ABS_LO12_NC to the same
    symbol, the instructions with cleared fields as an assembler writes them. The `nop` + `adr` a near target
    then becomes depends on addresses: the original's objects take it back to `adrp` + `add`. Layout, symbols and
    every other byte are unchanged. Returns the bytes and how many pairs changed (none: the same bytes, 0)."""
    from . import aarch64
    elf = Elf(raw)
    if elf.machine != "aarch64" or elf.bits != 64:
        return raw, 0
    e, out, changed = elf.endian, bytearray(raw), 0
    for rela in elf.sections:
        if rela.type != SHT_RELA or not 0 < rela.info < len(elf.sections):
            continue
        code = elf.sections[rela.info]
        if not code.flags & SHF_EXECINSTR or code.type == SHT_NOBITS:
            continue
        entries = [rela.offset + 24 * i for i in range(rela.size // 24)]
        relocations = []
        for at in entries:
            offset, info, addend = struct.unpack_from(e + "QQq", raw, at)
            relocations.append(Relocation(offset, info & 0xFFFFFFFF, info >> 32, addend))

        def word(offset: int, code=code) -> int:
            return struct.unpack_from(e + "I", raw, code.offset + offset)[0]

        def binds_locally(index: int, relocations=relocations) -> bool:
            r = relocations[index]
            symbol = elf.symbols[r.symbol] if r.symbol < len(elf.symbols) else None
            if symbol is None or symbol.section == 0xFFF1 or symbol.kind == "10":
                return False              # absolute (position-independent code keeps its GOT load) or an ifunc
            return symbol.bind == "local" or symbol.name not in imports   # an import is preemptible
        for index in aarch64.relaxed_pairs(relocations, word, binds_locally):
            first, second = relocations[index], relocations[index + 1]
            register = word(first.offset) & 31
            struct.pack_into(e + "I", out, code.offset + first.offset, 0x90000000 | register)
            struct.pack_into(e + "I", out, code.offset + second.offset, 0x91000000 | register << 5 | register)
            struct.pack_into(e + "Q", out, entries[index] + 8, first.symbol << 32 | aarch64.ADR_PREL_PG_HI21)
            struct.pack_into(e + "Q", out, entries[index + 1] + 8, second.symbol << 32 | aarch64.ADD_ABS_LO12_NC)
            changed += 1
    return (bytes(out), changed) if changed else (raw, 0)
