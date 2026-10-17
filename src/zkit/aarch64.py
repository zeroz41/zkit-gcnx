"""AArch64 code facts zkit needs from an original binary: direct calls, indirect calls, and the absolute
addresses straight-line code forms (adrp + add/ldr/str, adr, literal loads). Decoding only; no emulation."""

from __future__ import annotations


def _sign(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def direct_calls(words: list[int], start: int) -> list[tuple[int, int]]:
    """(site, target) of every BL in a function."""
    out = []
    for index, word in enumerate(words):
        if word & 0xFC000000 == 0x94000000:
            site = start + index * 4
            out.append((site, site + _sign(word & 0x03FFFFFF, 26) * 4))
    return out


def tail_calls(words: list[int], start: int, end: int) -> list[tuple[int, int]]:
    """(site, target) of B instructions that leave the function (tail calls)."""
    out = []
    for index, word in enumerate(words):
        if word & 0xFC000000 == 0x14000000:
            site = start + index * 4
            target = site + _sign(word & 0x03FFFFFF, 26) * 4
            if not start <= target < end:
                out.append((site, target))
    return out


def indirect_calls(words: list[int]) -> int:
    """BLR count: calls through a register (virtual calls and function pointers)."""
    return sum(1 for word in words if word & 0xFFFFFC1F == 0xD63F0000)


# Load/store (unsigned immediate) access size by (size, V, opc): only the kind of access matters here.
def _ldst_kind(word: int) -> str:
    vector = word >> 26 & 1
    opc = word >> 22 & 3
    size = word >> 30
    if vector:
        if opc & 1:
            return {2: "f32", 3: "f64"}.get(size, "load")
        return "store"
    return "store" if opc == 0 else "load"


def _ldst_scale(word: int) -> int:
    size = word >> 30
    if word >> 26 & 1 and word >> 23 & 1:  # 128-bit vector register
        return 4
    return size


def track_addresses(words: list[int], start: int) -> dict[int, tuple[int, str]]:
    """{pc: (address, kind)} formed by straight-line code; kind is addr, load, store, f32 or f64.

    adrp sets a page in a register; a following add/ldr/str through that register completes the address. Calls
    forget the caller-saved registers; any other write to a tracked register is not followed (an over-approximation
    that keeps only addresses actually formed from an adrp)."""
    pages: dict[int, int] = {}
    out: dict[int, tuple[int, str]] = {}
    for index, word in enumerate(words):
        pc = start + index * 4
        rd = word & 31
        if word & 0x9F000000 == 0x90000000:                       # adrp
            imm = _sign(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21) << 12
            pages[rd] = (pc & ~0xFFF) + imm
            continue
        if word & 0x9F000000 == 0x10000000:                       # adr
            imm = _sign(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21)
            out[pc] = (pc + imm, "addr")
            pages.pop(rd, None)
            continue
        if word & 0x3B000000 == 0x18000000:                       # ldr (literal)
            out[pc] = (pc + _sign(word >> 5 & 0x7FFFF, 19) * 4, "f64" if word >> 26 & 1 else "load")
            pages.pop(rd, None)
            continue
        rn = word >> 5 & 31
        if word & 0x7F800000 == 0x11000000 and rn in pages:      # add (immediate), 32 or 64 bit
            imm = (word >> 10 & 0xFFF) << (12 if word >> 22 & 1 else 0)
            out[pc] = (pages[rn] + imm, "addr")
            if rd != rn:
                pages.pop(rd, None)
            else:
                pages.pop(rn, None)
            continue
        if word & 0x3B000000 == 0x39000000 and rn in pages:      # ldr/str (unsigned immediate)
            imm = (word >> 10 & 0xFFF) << _ldst_scale(word)
            out[pc] = (pages[rn] + imm, _ldst_kind(word))
            if _ldst_kind(word) != "store" and rd == rn:
                pages.pop(rn, None)
            continue
        if word & 0xFC000000 == 0x94000000 or word & 0xFFFFFC1F == 0xD63F0000:  # bl / blr
            for register in range(19):
                pages.pop(register, None)
            continue
        if rd in pages and word & 0x1C000000 in (0x10000000, 0x08000000) and rd != 31:
            pages.pop(rd, None)                                   # data-processing write to the register
    return out
