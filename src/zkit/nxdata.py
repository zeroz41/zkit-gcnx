"""Data objects of a Switch module, found from the module alone.

A stripped module names almost none of its data, but its code and its relocations say where each object starts:
every address the code forms (`adrp` with an `add`, `adr`) or loads and stores through (`adrp` with a load or a
store, a literal load), every address a relocated pointer holds, and every object the module itself sizes (its
exports). An address inside an object the module sizes is a member of it, not a start, and the linker's own
tables in the module (`.dynamic`, `.dynsym`, `.rela.dyn`, `.eh_frame`...) are no program object and end the one
before them; they are listed in sections of their own (`linker_tables`). An object runs to the next
start, less what is plainly not its own: a string the code only takes the address of ends at its NUL, and a scalar
the code only loads or stores, at one width, and that nothing points to, is that wide. The zero bytes after either,
up to an aligned start, are alignment padding, which belongs to the gap (a unit's data starts aligned).
"""

from __future__ import annotations

import bisect
import collections
from typing import Iterable

from . import aarch64

LOADS = {aarch64.LDST8: 1, aarch64.LDST16: 2, aarch64.LDST32: 4, aarch64.LDST64: 8, aarch64.LDST128: 16}
FORMED = {aarch64.ADD_ABS_LO12_NC, aarch64.ADR_PREL_LO21}
STRING_LIMIT = 0x1000      # a string longer than this is read as data, not text


def _literal_width(word: int) -> int:
    """The width an `ldr` (literal) reads: w, x or ldrsw; s, d or q."""
    opc = word >> 30
    if word >> 26 & 1:
        return {0: 4, 1: 8, 2: 16}.get(opc, 0)
    return {0: 4, 1: 8, 2: 4}.get(opc, 0)


def objects(module, functions: Iterable[tuple[int, int]], sized: Iterable[tuple[int, int]] = ()
            ) -> list[tuple[int, int, str]]:
    """(address, size, section) of each data object the module's code and pointers refer to that `sized` ((start,
    size) of the objects already known, the module's own symbols) does not hold already."""
    segments = sorted((s.offset, s.offset + s.size, s.name) for s in module.segments if s.kind == "data" and s.size)
    bounds = [s[0] for s in segments]

    def segment(address: int):
        index = bisect.bisect_right(bounds, address) - 1
        return segments[index] if index >= 0 and address < segments[index][1] else None
    whole: set[int] = set()                                   # addresses code forms or data points to
    widths: dict[int, set[int]] = collections.defaultdict(set)  # address -> widths code reads or writes it at
    for start, size in functions:
        try:
            words = module.words(start, size)
        except ValueError:
            continue
        found, _ = aarch64.code_relocations(words, start, module.pointers)
        for r in found:
            if r.got or r.kind in FORMED:
                whole.add(r.target)
            elif r.kind in LOADS:
                widths[r.target].add(LOADS[r.kind])
            elif r.kind == aarch64.LD_PREL_LO19:
                widths[r.target].add(_literal_width(module.u32(r.offset)))
    whole.update(module.pointers.values())
    known = sorted({(a, s) for a, s in sized if s} | {(a, b - a) for a, b in module.tables.values() if b > a})
    known_starts = [a for a, _ in known]
    linker = {a for a, _ in module.tables.values()}   # the linker's own tables: no object of the program's

    def member(address: int) -> bool:
        index = bisect.bisect_right(known_starts, address) - 1
        return index >= 0 and known[index][0] < address < known[index][0] + known[index][1]
    starts = sorted({a for a in whole | set(widths) if segment(a) and not member(a)} | set(bounds)
                    | set(known_starts) | linker)
    taken = set(known_starts) | linker
    out = []
    for position, address in enumerate(starts):
        held = segment(address)
        if held is None or address in taken:
            continue
        stop = min(starts[position + 1], held[1]) if position + 1 < len(starts) else held[1]
        out.append((address, _own_size(module, address, stop - address, held[2], whole, widths), f".{held[2]}"))
    return out


def _own_size(module, address: int, extent: int, section: str, whole: set[int], widths: dict[int, set[int]]) -> int:
    """An object's own size within the extent up to the next start (module docstring)."""
    size = extent
    if section == "rodata" and address in whole and not widths.get(address) and extent > 1:
        raw = module.read(address, min(extent, STRING_LIMIT))
        end = raw.find(b"\0")
        if end > 0 and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in raw[:end]):
            size = end + 1
    elif address not in whole and len(widths.get(address, ())) == 1:
        width = next(iter(widths[address]))
        if 0 < width < extent:
            size = width
    padding = extent - size
    if not padding:
        return extent
    tail = module.read(address + size, padding) if section != "bss" else b""
    if any(tail) or padding >= 32 or (address + extent) % (1 << padding.bit_length()):
        return extent                                   # what follows is data, or more than padding to a boundary
    return size


ARRAYS = (".init_array", ".fini_array")


def linker_tables(module) -> list[tuple[int, int, str, str | None]]:
    """(address, size, section, name) of the linker's own tables in the module's data segments, each in its own
    section (`.eh_frame`, `.rela.dyn`...), as a section table would place them: no unit's data reaches across. An
    initializer (finalizer) array is one unnamed entry per unit's initializer: the units' own."""
    data = [(s.offset, s.offset + s.size) for s in module.segments if s.kind == "data"]
    out: list[tuple[int, int, str, str | None]] = []
    for section, (start, end) in sorted(module.tables.items(), key=lambda kv: kv[1]):
        if end <= start or not section.startswith(".") or not any(a <= start < b for a, b in data):
            continue
        if section in ARRAYS:
            out += [(at, 8, section, None) for at in range(start, end - 7, 8)]
        else:
            out.append((start, end - start, section, "_" + section.strip(".").replace(".", "_")))
    return out
