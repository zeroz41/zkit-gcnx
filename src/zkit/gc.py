"""GameCube binary formats shared by every game: DOL sections, symbol and
split files, and direct-call decoding. Nothing here knows about any one game."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple


GC_DISC_MAGIC = 0xC2339F3D


@dataclass(frozen=True)
class Section:
    kind: str  # "text" or "data"
    index: int
    offset: int
    address: int
    size: int


class Dol:
    """A DOL image. Reads are by virtual address, big-endian like the CPU."""

    def __init__(self, raw: bytes):
        if len(raw) < 0x100:
            raise ValueError("File is too small to be a DOL")
        offsets = struct.unpack(">18I", raw[0:0x48])
        addresses = struct.unpack(">18I", raw[0x48:0x90])
        sizes = struct.unpack(">18I", raw[0x90:0xD8])
        self.raw = raw
        self.bss = struct.unpack(">2I", raw[0xD8:0xE0])
        self.entry = struct.unpack(">I", raw[0xE0:0xE4])[0]
        self.sections = [
            Section("text" if i < 7 else "data", i if i < 7 else i - 7, offsets[i], addresses[i], sizes[i])
            for i in range(18) if sizes[i]
        ]
        for section in self.sections:
            if section.offset + section.size > len(raw):
                raise ValueError("DOL section extends past the end of the file")

    @classmethod
    def load(cls, path: Path) -> "Dol":
        """A .dol file, or the main executable inside a GameCube disc image (.iso/.gcm).

        Disc images are read in place: only the header and the DOL bytes are loaded."""
        with path.open("rb") as stream:
            head = stream.read(0x440)
            if len(head) >= 0x424 and struct.unpack(">I", head[0x1C:0x20])[0] == GC_DISC_MAGIC:
                offset = struct.unpack(">I", head[0x420:0x424])[0]
                stream.seek(offset)
                header = stream.read(0x100)
                if len(header) < 0x100:
                    raise ValueError("Disc image DOL header is truncated")
                offsets = struct.unpack(">18I", header[0:0x48])
                sizes = struct.unpack(">18I", header[0x90:0xD8])
                length = max(o + n for o, n in zip(offsets, sizes) if n)
                stream.seek(offset)
                return cls(stream.read(length))
            return cls(head + stream.read())

    def section_at(self, address: int) -> Section | None:
        for section in self.sections:
            if section.address <= address < section.address + section.size:
                return section
        return None

    def read(self, address: int, size: int) -> bytes:
        section = self.section_at(address)
        if section is None or address + size > section.address + section.size:
            raise ValueError(f"0x{address:08X}+{size} is not inside one DOL section")
        start = section.offset + address - section.address
        return self.raw[start:start + size]

    def words(self, address: int, size: int) -> list[int]:
        data = self.read(address, size - size % 4)
        return list(struct.unpack(f">{len(data) // 4}I", data))


def direct_calls(dol: Dol, start: int, size: int) -> list[tuple[int, int]]:
    """(site, target) for every `bl` (opcode 18, AA=0, LK=1) in a function.

    Indirect calls (bctrl through a vtable or pointer) are invisible here; the
    result is the exact set of direct callees, not the whole dynamic graph."""
    calls = []
    try:
        words = dol.words(start, size)
    except ValueError:
        return calls
    for i, word in enumerate(words):
        if word >> 26 == 18 and word & 3 == 1:
            displacement = word & 0x03FFFFFC
            if displacement & 0x02000000:
                displacement -= 0x04000000
            site = start + i * 4
            calls.append((site, (site + displacement) & 0xFFFFFFFF))
    return calls


SYMBOL_LINE = re.compile(
    r"^(?P<name>\S+)\s*=\s*(?P<section>[.\w]+):0x(?P<address>[0-9A-Fa-f]+);\s*//(?P<attrs>.*)$")


class Symbol(NamedTuple):  # a tuple: tens of thousands are built per process, and it marshals for the cache
    name: str
    section: str
    address: int
    type: str
    size: int
    scope: str
    data: str = ""  # the data kind symbols.txt records (string, float, 4byte, ...): what the bytes are, not where they point


def read_symbols(path: Path) -> list[Symbol]:
    """A symbols.txt. Unknown attributes are ignored."""
    symbols = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYMBOL_LINE.match(line.strip())
        if not match:
            continue
        attrs = dict(part.split(":", 1) for part in match["attrs"].split() if ":" in part)
        symbols.append(Symbol(match["name"], match["section"], int(match["address"], 16),
                              attrs.get("type", "unknown"), int(attrs.get("size", "0"), 16),
                              attrs.get("scope", "global"), attrs.get("data", "")))
    return symbols


SPLIT_UNIT = re.compile(r"^(?P<unit>\S[^:]*):\s*(?P<attrs>.*)$")
SPLIT_RANGE = re.compile(r"^\s+(?P<section>[.\w]+)\s+start:0x(?P<start>[0-9A-Fa-f]+)\s+end:0x(?P<end>[0-9A-Fa-f]+)")


def read_splits(path: Path) -> list[tuple[str, str, int, int]]:
    """(unit, section, start, end) rows from a splits.txt."""
    rows, unit = [], None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        if not line[0].isspace():
            match = SPLIT_UNIT.match(line)
            unit = match["unit"] if match and match["unit"] != "Sections" else None
            continue
        match = SPLIT_RANGE.match(line)
        if unit and match:
            rows.append((unit, match["section"], int(match["start"], 16), int(match["end"], 16)))
    return rows


def _sext16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


GPR_LOADS = {32, 33, 34, 35, 40, 41, 42, 43, 46}            # lwz lwzu lbz lbzu lhz lhzu lha lhau lmw
STORES = {36, 37, 38, 39, 44, 45, 47, 52, 53, 54, 55, 60, 61}
FP_LOADS = {48: "f32", 49: "f32", 50: "f64", 51: "f64", 56: "psq", 57: "psq"}
UPDATE_FORMS = {33, 35, 41, 43, 37, 39, 45, 49, 51, 53, 55, 57, 61}
D_FORM_ARITH = {7, 8, 12, 13}                                # mulli subfic addic addic. : dest rD
LOGICAL_IMM = {20, 21, 23, 26, 27, 28, 29}                   # rlwimi rlwinm rlwnm xori xoris andi. andis. : dest rA


def track_addresses(words: list[int], start: int, sda: dict[int, int]) -> dict[int, tuple[int, str]]:
    """Absolute addresses formed by straight-line code: {pc: (address, kind)}.

    Tracks lis/addis/addi/ori/oris register values and r2/r13 small-data bases; any other write to a
    tracked register, and every call (volatile r0, r3-r12), forgets it. kind is the access:
    "addr" (address computed), "load"/"store" (integer load, any store), "f32"/"f64"/"psq" (float loads)."""
    known: dict[int, int] = {}
    out: dict[int, tuple[int, str]] = {}

    def base(register: int) -> int | None:
        if register in (2, 13) and register in sda and register not in known:
            return sda[register]
        return known.get(register)

    for index, word in enumerate(words):
        pc = start + index * 4
        op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 15:                                         # addis / lis
            value = (imm << 16) & 0xFFFFFFFF
            if ra == 0:
                known[rd] = value
            elif base(ra) is not None:
                known[rd] = (base(ra) + value) & 0xFFFFFFFF
            else:
                known.pop(rd, None)
        elif op == 14:                                       # addi / li
            if ra and base(ra) is not None:
                known[rd] = (base(ra) + _sext16(imm)) & 0xFFFFFFFF
                out[pc] = (known[rd], "addr")
            else:
                known.pop(rd, None)
        elif op in (24, 25):                                 # ori / oris: rA = rS | imm
            if rd in known:
                known[ra] = known[rd] | (imm if op == 24 else imm << 16)
                if op == 24:
                    out[pc] = (known[ra], "addr")
            else:
                known.pop(ra, None)
        elif op in GPR_LOADS or op in STORES or op in FP_LOADS:
            b = base(ra) if ra else None
            offset = _sext16(imm) if op not in (56, 57, 60, 61) else (
                (imm & 0xFFF) - 0x1000 if imm & 0x800 else imm & 0xFFF)
            if b is not None:
                address = (b + offset) & 0xFFFFFFFF
                out[pc] = (address, FP_LOADS.get(op) or ("store" if op in STORES else "load"))
                if op in UPDATE_FORMS:
                    known[ra] = address
            elif op in UPDATE_FORMS:
                known.pop(ra, None)
            if op in GPR_LOADS:
                if op == 46:                                 # lmw rD..r31
                    for register in range(rd, 32):
                        known.pop(register, None)
                else:
                    known.pop(rd, None)
        elif op in D_FORM_ARITH:
            known.pop(rd, None)
        elif op in LOGICAL_IMM:
            known.pop(ra, None)
        elif op == 31:                                       # X-form: dest may be rD or rA
            known.pop(rd, None)
            known.pop(ra, None)
        elif op == 18 and word & 1:                          # bl clobbers volatile registers
            for register in (0, *range(3, 13)):
                known.pop(register, None)
        elif op == 19 and word & 1:                          # bctrl / blrl
            for register in (0, *range(3, 13)):
                known.pop(register, None)
    return out
