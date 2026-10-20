"""AArch64 code facts zkit needs from an original binary: direct calls, indirect calls, and the absolute
addresses straight-line code forms (adrp + add/ldr/str, adr, literal loads). Decoding only; no emulation."""

from __future__ import annotations

import collections
from dataclasses import dataclass


def written(word: int) -> tuple[int, ...]:
    """General registers an instruction writes (approximate but conservative: when unsure, its rd field).

    Branches and stores write nothing (bl/blr clobber is handled by callers); loads write rt (pairs also rt2);
    every data-processing instruction writes rd."""
    group = word >> 25 & 0xF
    if group in (0b1010, 0b1011):                                   # branches, exceptions, system
        return ()
    if group & 0b0101 == 0b0100:                                    # loads and stores
        if word >> 26 & 1:                                          # SIMD/FP registers: not general registers
            return ()
        pair = word & 0x38000000 == 0x28000000
        load = bool(word >> 22 & 1)
        if word & 0x3B000000 in (0x18000000, 0x19000000):           # literal loads (and prefetch)
            return (word & 31,)
        if not load:
            return ()
        return (word & 31, word >> 10 & 31) if pair else (word & 31,)
    return (word & 31,)


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


def track_addresses(words: list[int], start: int, load64=None) -> dict[int, tuple[int, str]]:
    """{pc: (address, kind)} formed by straight-line code; kind is addr, load, store, f32 or f64.

    adrp sets a page in a register; a following add/ldr/str through that register completes the address. Calls
    forget the caller-saved registers; any other write to a tracked register is not followed (an over-approximation
    that keeps only addresses actually formed from an adrp). `load64(address)` returns the pointer a 64-bit load
    reads when it is known (a relocated GOT or table slot), so `ldr x8, [got]; add x8, x8, #16` is followed."""
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
            address = pages[rn] + imm
            kind = _ldst_kind(word)
            out[pc] = (address, kind)
            if kind != "store":
                loaded = load64(address) if load64 is not None and word >> 30 == 3 and not word >> 26 & 1 else None
                if loaded is not None:
                    pages[rd] = loaded                             # the pointer the slot holds
                elif rd == rn or rd in pages:
                    pages.pop(rd, None)
            continue
        if word & 0xFC000000 == 0x94000000 or word & 0xFFFFFC1F == 0xD63F0000:  # bl / blr
            for register in range(19):
                pages.pop(register, None)
            continue
        for register in written(word):
            pages.pop(register, None)
    return out


THIS = "this"


def object_stores(words: list[int], start: int, load64=None) -> list[tuple]:
    """What straight-line code stores into objects and passes them to, in order: ("store", pc, object, offset,
    address) for each 64-bit store of an address the code formed (adrp + add, or a pointer `load64` knows a load
    read, then offset) into an object, and ("call", pc, target, object, offset) for each call and tail call, with
    what x0 holds (object None when not an object). An object is THIS (x0 on entry) or the pc of the call that
    returned it; moves, adds and write-back addressing follow it, and a call forgets the caller-saved registers."""
    held: dict[int, tuple] = {0: ("object", THIS, 0)}   # register -> ("address", value) / ("object", origin, offset)
    out: list[tuple] = []
    end = start + 4 * len(words)

    def store(pc: int, value: int, base: int, offset: int) -> None:
        v, b = held.get(value), held.get(base)
        if v is not None and b is not None and v[0] == "address" and b[0] == "object":
            out.append(("store", pc, b[1], b[2] + offset, v[1]))

    def advance(register: int, amount: int) -> None:          # write-back: the base register moves
        b = held.get(register)
        if b is not None and b[0] == "object":
            held[register] = ("object", b[1], b[2] + amount)
        else:
            held.pop(register, None)
    for index, word in enumerate(words):
        pc = start + 4 * index
        rd, rn = word & 31, word >> 5 & 31
        if word & 0x9F000000 == 0x90000000:                       # adrp
            imm = _sign(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21) << 12
            held[rd] = ("address", (pc & ~0xFFF) + imm)
        elif word & 0xFF800000 == 0x91000000:                     # add (immediate), 64 bit
            imm = (word >> 10 & 0xFFF) << (12 if word >> 22 & 1 else 0)
            v = held.get(rn)
            if v is None:
                held.pop(rd, None)
            else:
                held[rd] = (v[0], v[1] + imm) if v[0] == "address" else ("object", v[1], v[2] + imm)
        elif word & 0xFFC00000 == 0xF9400000:                     # ldr x (unsigned immediate)
            v = held.get(rn)
            loaded = load64(v[1] + (word >> 10 & 0xFFF) * 8) if v and v[0] == "address" and load64 else None
            if loaded is not None:
                held[rd] = ("address", loaded)
            else:
                held.pop(rd, None)
        elif word & 0xFFE0FFE0 == 0xAA0003E0:                     # mov x, x (orr with xzr)
            if (word >> 16 & 31) in held:
                held[rd] = held[word >> 16 & 31]
            else:
                held.pop(rd, None)
        elif word & 0xFFC00000 == 0xF9000000:                     # str x (unsigned immediate)
            store(pc, rd, rn, (word >> 10 & 0xFFF) * 8)
        elif word & 0xFFE00000 == 0xF8000000 and word >> 10 & 3 != 2:   # str x pre-, post-index, stur
            imm = _sign(word >> 12 & 0x1FF, 9)
            store(pc, rd, rn, imm if word >> 10 & 3 in (0, 3) else 0)
            if word >> 10 & 1:
                advance(rn, imm)
        elif word & 0xFE400000 == 0xA8000000 and word >> 23 & 3:  # stp x (offset, pre-, post-index)
            imm = _sign(word >> 15 & 0x7F, 7) * 8
            at = 0 if word >> 23 & 3 == 1 else imm
            store(pc, rd, rn, at)
            store(pc, word >> 10 & 31, rn, at + 8)
            if word >> 23 & 3 != 2:
                advance(rn, imm)
        elif word & 0x7C000000 == 0x14000000:                     # bl / b
            target = pc + _sign(word & 0x03FFFFFF, 26) * 4
            if word >> 31 or not start <= target < end:
                x0 = held.get(0)
                out.append(("call", pc, target, *(x0[1:] if x0 and x0[0] == "object" else (None, 0))))
            if word >> 31:
                for register in (*range(19), 30):
                    held.pop(register, None)
                held[0] = ("object", pc, 0)
        elif word & 0xFFFFFC1F == 0xD63F0000:                     # blr
            for register in (*range(19), 30):
                held.pop(register, None)
        else:
            if word & 0x3B200400 == 0x38000400:                   # load/store, pre- or post-index: base written
                advance(rn, _sign(word >> 12 & 0x1FF, 9))
            elif word & 0x3A000000 == 0x28000000 and word >> 23 & 1:   # pair, pre- or post-index
                scale = 4 << (word >> 30) if word >> 26 & 1 else 4 << (word >> 31)
                advance(rn, _sign(word >> 15 & 0x7F, 7) * scale)
            for register in written(word):
                held.pop(register, None)
        held.pop(31, None)                                         # the zero register or sp: never an address
    return out


# Relocations recovered for delinking (ELF AArch64 numbers)
ABS64, PREL32 = 257, 261
LD_PREL_LO19, ADR_PREL_LO21, ADR_PREL_PG_HI21, ADD_ABS_LO12_NC = 273, 274, 275, 277
LDST8, JUMP26, CALL26, LDST16, LDST32, LDST64, LDST128 = 278, 282, 283, 284, 285, 286, 299
ADR_GOT_PAGE, LD64_GOT_LO12_NC = 311, 312
LDST = {0: LDST8, 1: LDST16, 2: LDST32, 3: LDST64, 4: LDST128}


@dataclass
class Reloc:
    offset: int        # original address of the patched instruction or word
    kind: int
    target: int        # original address the reference resolves to (the symbol is found later)
    got: bool = False


def code_relocations(words: list[int], start: int, pointers: dict[int, int],
                     resolved=lambda target: False) -> tuple[list[Reloc], dict[int, int]]:
    """Relocations of a function's instructions, and the cleared instruction words by address.

    Branches inside the function, and calls `resolved(target)` says the assembler resolves itself (an
    internal-linkage function in the same section), keep their encoded offset and get no relocation."""
    end = start + len(words) * 4
    out: list[Reloc] = []
    cleared: dict[int, int] = {}
    pages: dict[int, tuple[int, int]] = {}  # register -> (page, pc of the adrp)
    pending: dict[int, list[int]] = collections.defaultdict(list)  # adrp pc -> indices of its paired relocs
    for index, word in enumerate(words):
        pc = start + index * 4
        if word & 0x7C000000 == 0x14000000:                                   # b / bl
            target = pc + _sign(word & 0x03FFFFFF, 26) * 4
            if not (start <= target < end and not word >> 31) and not resolved(target):
                out.append(Reloc(pc, CALL26 if word >> 31 else JUMP26, target))
                cleared[pc] = word & 0xFC000000
            if word >> 31:
                for register in range(19):
                    pages.pop(register, None)
            continue
        rd = word & 31
        if word & 0x9F000000 == 0x90000000:                                   # adrp
            imm = _sign(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21) << 12
            pages[rd] = ((pc & ~0xFFF) + imm, pc)
            cleared[pc] = word & ~((3 << 29) | (0x7FFFF << 5))
            continue
        if word & 0x9F000000 == 0x10000000:                                   # adr
            imm = _sign(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21)
            out.append(Reloc(pc, ADR_PREL_LO21, pc + imm))
            cleared[pc] = word & ~((3 << 29) | (0x7FFFF << 5))
            pages.pop(rd, None)
            continue
        if word & 0x3B000000 == 0x18000000:                                   # ldr (literal)
            out.append(Reloc(pc, LD_PREL_LO19, pc + _sign(word >> 5 & 0x7FFFF, 19) * 4))
            cleared[pc] = word & ~(0x7FFFF << 5)
            pages.pop(rd, None)
            continue
        rn = word >> 5 & 31
        if word & 0x7F800000 == 0x11000000 and not word >> 22 & 1 and rn in pages:  # add (immediate, lsl 0)
            page, origin = pages[rn]
            target = page + (word >> 10 & 0xFFF)
            pending[origin].append(len(out))
            out.append(Reloc(pc, ADD_ABS_LO12_NC, target))
            cleared[pc] = word & ~(0xFFF << 10)
            if rd != rn:
                pages.pop(rd, None)
            continue
        if word & 0x3B000000 == 0x39000000 and rn in pages:                  # ldr/str (unsigned immediate)
            page, origin = pages[rn]
            vector = word >> 26 & 1
            scale = word >> 30
            if vector and word >> 23 & 1:
                scale = 4
            target = page + ((word >> 10 & 0xFFF) << scale)
            got = not vector and scale == 3 and word >> 22 & 3 == 1 and target in pointers
            pending[origin].append(len(out))
            out.append(Reloc(pc, LD64_GOT_LO12_NC if got else LDST.get(scale, LDST64),
                             pointers[target] if got else target, got))
            cleared[pc] = word & ~(0xFFF << 10)
            if word >> 22 & 3 and rd == rn:
                pages.pop(rn, None)
            continue
        if word & 0xFFFFFC1F == 0xD63F0000:                                   # blr
            for register in range(19):
                pages.pop(register, None)
            continue
        for register in written(word):
            pages.pop(register, None)
    # Each adrp takes the symbol of the first reference it pairs with (GOT pairs use the GOT page type).
    for origin, members in pending.items():
        first = out[members[0]]
        out.append(Reloc(origin, ADR_GOT_PAGE if first.got else ADR_PREL_PG_HI21, first.target, first.got))
    for register_page in pages.values():  # an adrp whose low half is outside this function: keep its page
        page, origin = register_page
        if origin not in pending:
            out.append(Reloc(origin, ADR_PREL_PG_HI21, page))
    out.sort(key=lambda r: r.offset)
    return out, cleared


def guarded(words: list[int]) -> bool:
    """Whether a function begins by testing a guard byte (`ldrb`, then `tbz`/`tbnz`/`cbz`/`cbnz` on what it
    loaded): an initializer of a template's static member or an inline's static, which the linker keeps from
    whichever unit comes first, not a unit's own initializer."""
    for index, word in enumerate(words[:12]):
        if word & 0xFFC00000 == 0x39400000:                               # ldrb (unsigned immediate)
            loaded = word & 31
            if any((test & 0x7E000000 in (0x36000000, 0x34000000)) and test & 31 == loaded
                   for test in words[index + 1:index + 4]):
                return True
    return False
