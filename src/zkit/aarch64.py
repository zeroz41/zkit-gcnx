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


class _Joins:
    """Where straight-line register tracking must meet other paths: an instruction after b, br or ret is reached only
    by branches, so it holds what every branch to it agrees on; a branch target also meets what its forward branches
    held; a loop head forgets the registers its loop writes."""

    def __init__(self, words: list[int]):
        count = len(words)
        self.sources: dict[int, list[int]] = collections.defaultdict(list)
        self.loops: dict[int, set[int]] = collections.defaultdict(set)
        self.dead: set[int] = set()
        for index, word in enumerate(words):
            target = _local_target(word, index)
            if word & 0xFC000000 == 0x14000000 or word & 0xFE000000 == 0xD6000000 and \
                    word & 0xFFFFFC1F != 0xD63F0000:          # b, br, ret: nothing falls through
                self.dead.add(index + 1)
            if target is None or not 0 <= target < count:
                continue
            if target > index:
                self.sources[target].append(index)
            else:
                for inner in range(target, index + 1):
                    self.loops[target].update(written(words[inner]))
        self.saved: dict[int, dict] = {}

    def enter(self, index: int, state: dict) -> dict:
        """The state at an instruction, from the one straight-line code reaches it with."""
        incoming = [self.saved[s] for s in self.sources.get(index, ()) if s in self.saved]
        if index in self.dead:
            if not incoming:
                state = {}
            else:
                state, incoming = dict(incoming[0]), incoming[1:]
        if incoming:
            state = {r: v for r, v in state.items() if all(other.get(r) == v for other in incoming)}
        for register in self.loops.get(index, ()):
            state.pop(register, None)
        return state

    def leave(self, index: int, word: int, state: dict) -> None:
        """Remember what a forward branch carries to its target."""
        target = _local_target(word, index)
        if target is not None and target > index:
            self.saved[index] = dict(state)


def _local_target(word: int, index: int) -> int | None:
    """The instruction index a branch inside the function goes to (b, b.cond, cbz/cbnz, tbz/tbnz), else None."""
    if word & 0xFC000000 == 0x14000000:
        return index + _sign(word & 0x3FFFFFF, 26)
    if word & 0xFF000010 == 0x54000000 or word & 0x7E000000 == 0x34000000:
        return index + _sign(word >> 5 & 0x7FFFF, 19)
    if word & 0x7E000000 == 0x36000000:
        return index + _sign(word >> 5 & 0x3FFF, 14)
    return None


def track_addresses(words: list[int], start: int, load64=None) -> dict[int, tuple[int, str]]:
    """{pc: (address, kind)} formed by straight-line code; kind is addr, load, store, f32 or f64.

    adrp sets a page in a register; a following add/ldr/str through that register completes the address. Calls
    forget the caller-saved registers; any other write to a tracked register is not followed (an over-approximation
    that keeps only addresses actually formed from an adrp). `load64(address)` returns the pointer a 64-bit load
    reads when it is known (a relocated GOT or table slot), so `ldr x8, [got]; add x8, x8, #16` is followed."""
    pages: dict[int, int] = {}
    out: dict[int, tuple[int, str]] = {}
    joins = _Joins(words)
    for index, word in enumerate(words):
        pages = joins.enter(index, pages)
        joins.leave(index, word, pages)
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
    joins = _Joins(words)

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
        held = joins.enter(index, held)
        joins.leave(index, word, held)
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


def global_stores(words: list[int], start: int, load64=None) -> set[int]:
    """Addresses straight-line code stores into: a store of any width whose base register holds an address formed
    by adrp (+ add) or read from a pointer `load64` knows (a GOT slot), plus its offset. What a unit's static
    initializer stores into is what it constructs."""
    held: dict[int, int] = {}                                    # register -> the address it holds
    out: set[int] = set()
    joins = _Joins(words)
    for index, word in enumerate(words):
        held = joins.enter(index, held)
        joins.leave(index, word, held)
        pc = start + 4 * index
        rd, rn = word & 31, word >> 5 & 31
        if word & 0x9F000000 == 0x90000000:                       # adrp
            held[rd] = (pc & ~0xFFF) + (_sign(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21) << 12)
            continue
        if word & 0xFF800000 == 0x91000000 and rn in held:        # add (immediate), 64 bit
            held[rd] = held[rn] + ((word >> 10 & 0xFFF) << (12 if word >> 22 & 1 else 0))
            continue
        if word & 0xFFC00000 == 0xF9400000 and rn in held and load64:   # ldr x through a pointer slot
            loaded = load64(held[rn] + (word >> 10 & 0xFFF) * 8)
            if loaded is not None:
                held[rd] = loaded
                continue
        # a store: opc 00 (general registers), or 00/10 (SIMD/FP: 10 is a 128-bit one); else a load or prfm
        store = not word >> 22 & 3 if not word >> 26 & 1 else not word >> 22 & 1
        if word & 0x3B000000 == 0x39000000 and store and rn in held:     # str (unsigned immediate), any width
            scale = 4 if word >> 26 & 1 and word >> 23 & 1 else word >> 30
            out.add(held[rn] + ((word >> 10 & 0xFFF) << scale))
        elif word & 0x3B200000 == 0x38000000 and store and rn in held:   # stur, str pre-/post-index
            out.add(held[rn] + (_sign(word >> 12 & 0x1FF, 9) if word >> 10 & 3 != 1 else 0))
        elif word & 0x3A400000 == 0x28000000 and rn in held:      # stp (offset, pre-, post-index)
            scale = 4 << (word >> 30) if word >> 26 & 1 else 4 << (word >> 31)
            at = 0 if word >> 23 & 3 == 1 else _sign(word >> 15 & 0x7F, 7) * scale
            out.update((held[rn] + at, held[rn] + at + scale))
        if word & 0x7C000000 == 0x14000000 and word >> 31 or word & 0xFFFFFC1F == 0xD63F0000:   # bl, blr
            for register in (*range(19), 30):
                held.pop(register, None)
            continue
        for register in register_use(word)[1]:
            if register < V:
                held.pop(register, None)
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
                     resolved=lambda target: False, got: tuple[int, int] | None = None
                     ) -> tuple[list[Reloc], dict[int, int]]:
    """Relocations of a function's instructions, and the cleared instruction words by address.

    A 64-bit load through an adrp page is a GOT load (to the pointee) when it reads a relocated pointer inside
    `got`, the module's `.got` (start, end); any other load, of a pointer table's element in `.data` too, is a
    plain load of the word's own address. Without a known `.got` every relocated pointer counts as a slot.

    Branches inside the function, and calls `resolved(target)` says the assembler resolves itself (an
    internal-linkage function in the same section), keep their encoded offset and get no relocation."""
    end = start + len(words) * 4
    out: list[Reloc] = []
    cleared: dict[int, int] = {}
    pages: dict[int, tuple[int, int]] = {}  # register -> (page, pc of the adrp)
    pending: dict[int, list[int]] = collections.defaultdict(list)  # adrp pc -> indices of its paired relocs
    adrps: dict[int, int] = {}              # pc of every adrp -> its page
    joins = _Joins(words)
    for index, word in enumerate(words):
        pages = joins.enter(index, pages)
        joins.leave(index, word, pages)
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
            adrps[pc] = (pc & ~0xFFF) + imm
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
            pages.pop(rd, None)            # it holds the whole address now, the page no longer (rd == rn too)
            continue
        if word & 0x3B000000 == 0x39000000 and rn in pages:                  # ldr/str (unsigned immediate)
            page, origin = pages[rn]
            vector = word >> 26 & 1
            scale = word >> 30
            if vector and word >> 23 & 1:
                scale = 4
            target = page + ((word >> 10 & 0xFFF) << scale)
            slot = not vector and scale == 3 and word >> 22 & 3 == 1 and target in pointers \
                and (got is None or got[0] <= target < got[1])
            pending[origin].append(len(out))
            out.append(Reloc(pc, LD64_GOT_LO12_NC if slot else LDST.get(scale, LDST64),
                             pointers[target] if slot else target, slot))
            cleared[pc] = word & ~(0xFFF << 10)
            if word >> 22 & 3 and not vector:  # a load writes its general register, whichever it is
                pages.pop(rd, None)
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
    for origin, page in adrps.items():      # an adrp whose low half no path here reads: keep its page
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


# Registers an instruction reads and writes, for argument liveness. General registers are 0-30 (31, the zero
# register or sp, is left out), SIMD/FP registers 32-63 (v0 is 32). Where an encoding is not recognised the
# instruction reads nothing and writes its rd field: that can hide a read, never invent one.
V = 32
CALL_CLOBBERED = frozenset(range(0, 19)) | frozenset(range(V, V + 8)) | frozenset(range(V + 16, V + 32))


def _g(*fields: int) -> tuple[int, ...]:
    return tuple(f for f in fields if f != 31)


def register_use(word: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """(read, written) registers of one instruction. A call (bl, blr) writes the registers calls clobber."""
    rd, rn, rm, ra = word & 31, word >> 5 & 31, word >> 16 & 31, word >> 10 & 31
    op0 = word >> 25 & 0xF
    if op0 in (0b1000, 0b1001):                                         # data processing, immediate
        op1 = word >> 23 & 7
        if op1 <= 1:                                                    # adr, adrp
            return (), _g(rd)
        if op1 == 0b101:                                                # move wide: movk keeps the other bits
            return (_g(rd) if word >> 29 & 3 == 3 else ()), _g(rd)
        if op1 == 0b110 and word >> 29 & 3 == 1:                        # bfm (bfi, bfxil) keeps rd's other bits
            return _g(rn, rd), _g(rd)
        if op1 == 0b111:                                                # extr
            return _g(rn, rm), _g(rd)
        return _g(rn), _g(rd)                                           # add/sub, logical, sbfm/ubfm
    if op0 in (0b1010, 0b1011):                                         # branches, exceptions, system
        if word & 0xFC000000 == 0x94000000:                             # bl
            return (), tuple(CALL_CLOBBERED)
        if word & 0xFFFFFC1F == 0xD63F0000:                             # blr
            return _g(rn), tuple(CALL_CLOBBERED)
        if word & 0xFE000000 == 0xD6000000:                             # br, ret
            return _g(rn), ()
        if word & 0x7C000000 == 0x34000000:                             # cbz, cbnz, tbz, tbnz
            return _g(rd), ()
        if word & 0xFFF00000 == 0xD5300000:                             # mrs
            return (), _g(rd)
        if word & 0xFFF00000 == 0xD5100000:                             # msr (register)
            return _g(rd), ()
        return (), ()
    if op0 & 0b0101 == 0b0100:                                          # loads and stores
        return _load_store(word)
    if op0 & 0b0111 == 0b0101:                                          # data processing, register
        if word >> 28 & 1 == 0:                                         # logical, add/sub (shifted, extended)
            return _g(rn, rm), _g(rd)
        op2 = word >> 21 & 0xF
        if op2 == 0b0010:                                               # ccmp, ccmn: flags only
            return (_g(rn) if word >> 11 & 1 else _g(rn, rm)), ()
        if op2 & 0b1000:                                                # madd, msub, smaddl, umulh, ...
            return _g(rn, rm, ra), _g(rd)
        if op2 == 0b0110 and word >> 30 & 1:                            # one source: rbit, rev, clz
            return _g(rn), _g(rd)
        return _g(rn, rm), _g(rd)                                       # adc, csel, two sources
    return _simd(word)


def _load_store(word: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    rt, rn, rt2, rm = word & 31, word >> 5 & 31, word >> 10 & 31, word >> 16 & 31
    vector = word >> 26 & 1
    reg = (lambda r: (V + r,)) if vector else (lambda r: _g(r))
    if word & 0x3B000000 == 0x18000000:                                 # load literal (and prfm literal)
        return (), (() if not vector and word >> 30 == 3 else reg(rt))
    if word & 0x3F000000 == 0x08000000:                                 # exclusive, acquire/release
        load = word >> 22 & 1
        pair = word >> 21 & 1
        if load:
            return _g(rn), _g(rt) + (_g(rt2) if pair else ())
        status = _g(rm) if not word >> 23 & 1 else ()                   # stxr writes its status register
        return _g(rn) + _g(rt) + (_g(rt2) if pair else ()), status
    if word & 0x3A000000 == 0x28000000:                                 # pairs
        load = word >> 22 & 1
        index = word >> 23 & 3
        base = _g(rn) if index in (1, 3) else ()                        # post/pre-index write the base back
        if load:
            return _g(rn), reg(rt) + reg(rt2) + base
        return _g(rn) + reg(rt) + reg(rt2), base
    if word & 0x3B000000 == 0x39000000 or word & 0x3B200000 == 0x38000000 or \
            word & 0x3B200C00 == 0x38200800:                            # single register: imm, unscaled, reg offset
        size, opc = word >> 30, word >> 22 & 3
        if vector:
            load = opc & 1
        else:
            if size == 3 and opc == 2:                                  # prfm
                return (), ()
            load = opc != 0
        offset = _g(rm) if word & 0x3B200C00 == 0x38200800 else ()
        index = word >> 10 & 3
        base = _g(rn) if word & 0x3B200000 == 0x38000000 and index in (1, 3) else ()
        if load:
            return _g(rn) + offset, reg(rt) + base
        return _g(rn) + offset + reg(rt), base
    if word & 0xBF800000 in (0x0C000000, 0x0C800000) or word & 0xBF800000 in (0x0D000000, 0x0D800000):
        load = word >> 22 & 1                                           # ld1/st1 ... structures
        count = 4
        vectors = tuple(V + (rt + i) % 32 for i in range(count))
        base = _g(rn) if word >> 23 & 1 else ()
        if load:
            return _g(rn), vectors[:1] + base
        return _g(rn), base
    return (), ()


def _simd(word: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    rd, rn, rm, ra = word & 31, word >> 5 & 31, word >> 16 & 31, word >> 10 & 31
    vd, vn, vm, va = V + rd, V + rn, V + rm, V + ra
    if word & 0x5F000000 == 0x1E000000:                                 # scalar floating point (bit 31: sf)
        if word >> 21 & 1 == 0:                                         # fixed-point conversions
            opcode = word >> 16 & 7
            return ((vn,), _g(rd)) if opcode in (0, 1) else (_g(rn), (vd,))
        low = word >> 10 & 3
        if low == 0b10:                                                 # two sources
            return (vn, vm), (vd,)
        if low == 0b11:                                                 # fcsel
            return (vn, vm), (vd,)
        if low == 0b01:                                                 # fccmp
            return (vn, vm), ()
        if word >> 10 & 0x1F == 0b10000:                                # one source
            return (vn,), (vd,)
        if word >> 10 & 0xF == 0b1000:                                  # fcmp (with zero: rm unused)
            return ((vn,) if word >> 3 & 1 else (vn, vm)), ()
        if word >> 10 & 7 == 0b100:                                     # fmov immediate
            return (), (vd,)
        if word >> 10 & 0x3F == 0:                                      # to and from general registers
            opcode = word >> 16 & 7
            if opcode in (2, 3, 7):                                     # scvtf, ucvtf, fmov from general
                return _g(rn), (vd,)
            return (vn,), _g(rd)                                        # fcvt*, fmov to general
        return (), (vd,)
    if word & 0xDF000000 == 0x1F000000:                                 # fmadd, fmsub, fnmadd, fnmsub
        return (vn, vm, va), (vd,)
    if word & 0x9F000000 in (0x0E000000, 0x0F000000) or word & 0xDF000000 in (0x5E000000, 0x5F000000):
        # advanced SIMD: vector, and scalar
        u = word >> 29 & 1
        if word >> 24 & 1 == 0:
            if word >> 21 & 1 and word >> 10 & 1:                       # three same
                opcode = word >> 11 & 0x1F
                accumulate = opcode == 0b11001 or opcode == 0b10010 or \
                    (u == 1 and opcode == 0b00011 and word >> 22 & 3)   # fmla/fmls, mla/mls, bsl/bit/bif
                return ((vn, vm, vd) if accumulate else (vn, vm)), (vd,)
            if word >> 21 & 1 and word >> 10 & 3 == 0:                 # three different (widening)
                return (vn, vm), (vd,)
            if word >> 17 & 0x1F in (0b10000, 0b11000) and word >> 10 & 3 == 0b10:   # two-reg misc, across lanes
                return (vn,), (vd,)
            if word & 0x1FE08400 == 0x0E000400:                         # copy: dup, ins, umov, smov
                imm4 = word >> 11 & 0xF
                if u:                                                   # ins (element)
                    return (vd, vn), (vd,)
                if imm4 == 0:                                           # dup (element)
                    return (vn,), (vd,)
                if imm4 == 1:                                           # dup (general)
                    return _g(rn), (vd,)
                if imm4 == 3:                                           # ins (general)
                    return (vd,) + _g(rn), (vd,)
                return (vn,), _g(rd)                                    # umov, smov
            if word >> 21 & 1 == 0 and word >> 10 & 1 == 0:             # permute, ext, table lookup
                if word & 0x3F208C00 == 0x0E000000:                     # tbl, tbx
                    return ((vn, vm, vd) if word >> 12 & 1 else (vn, vm)), (vd,)
                return (vn, vm), (vd,)
            return (), (vd,)
        if word >> 10 & 1:                                              # shift by immediate, modified immediate
            if word >> 19 & 0x1F == 0:                                  # movi, mvni, orr/bic immediate, fmov
                cmode = word >> 12 & 0xF
                keep = cmode & 1 and cmode < 0b1100
                return ((vd,) if keep else ()), (vd,)
            opcode = word >> 11 & 0x1F
            keep = opcode in (0b00010, 0b00110) or (u and opcode in (0b01000, 0b01010))   # sra, rsra, sri, sli
            return ((vn, vd) if keep else (vn,)), (vd,)
        # by element: a half-word element's index takes the top bit of the register field
        element = V + (word >> 16 & (0xF if word >> 22 & 3 == 1 else 0x1F))
        opcode = word >> 12 & 0xF
        accumulate = opcode in ((0b0000, 0b0100) if u else (0b0001, 0b0101)) or opcode in (0b0010, 0b0011, 0b0110,
                                                                                            0b0111)
        return ((vn, element, vd) if accumulate else (vn, element)), (vd,)
    if word & 0xFF3E0C00 == 0x4E280800:                                 # aes, sha: read and write rd
        return (vd, vn), (vd,)
    return (), (vd,)


def argument_reads(words: list[int], start: int) -> set[int]:
    """Argument registers (x0-x7 as 0-7, v0-v7 as 32-39) some path from the entry reads before writing: what
    the function takes from its caller. A call reads nothing (what it passes on is not counted) and clobbers what
    calls clobber; a branch out of the function (a tail call) and an indirect branch end the path."""
    count = len(words)
    end = start + count * 4
    leaders = {0}
    successors: list[list[int]] = []
    targets: dict[int, int] = {}
    for index, word in enumerate(words):
        site = start + index * 4
        target = None
        if word & 0xFC000000 == 0x14000000:                             # b
            target = site + _sign(word & 0x3FFFFFF, 26) * 4
        elif word & 0xFF000010 == 0x54000000 or word & 0x7E000000 == 0x34000000:   # b.cond, cbz, cbnz
            target = site + _sign(word >> 5 & 0x7FFFF, 19) * 4
        elif word & 0x7E000000 == 0x36000000:                           # tbz, tbnz
            target = site + _sign(word >> 5 & 0x3FFF, 14) * 4
        elif word & 0xFE000000 == 0xD6000000 and word & 0xFFFFFC1F != 0xD63F0000:   # br, ret
            leaders.add(index + 1)
            continue
        if target is not None:
            leaders.add(index + 1)
            if start <= target < end and (target - start) % 4 == 0:
                targets[index] = (target - start) // 4
                leaders.add(targets[index])
    order = sorted(i for i in leaders if i < count)
    block_of = {first: n for n, first in enumerate(order)}
    use: list[set[int]] = []
    defined: list[set[int]] = []
    for n, first in enumerate(order):
        last = order[n + 1] if n + 1 < len(order) else count
        reads, writes = set(), set()
        for index in range(first, last):
            r, w = register_use(words[index])
            reads |= {x for x in r if x not in writes and (x < 8 or V <= x < V + 8)}
            writes |= set(w)
        word = words[last - 1]
        follow = []
        if word & 0xFC000000 == 0x14000000 or word & 0xFE000000 == 0xD6000000 and word & 0xFFFFFC1F != 0xD63F0000:
            if last - 1 in targets:
                follow.append(block_of[targets[last - 1]])
        else:
            if last - 1 in targets:
                follow.append(block_of[targets[last - 1]])
            if last < count:
                follow.append(block_of[last])
        use.append(reads)
        defined.append(writes)
        successors.append(follow)
    live = [set() for _ in order]
    changed = True
    while changed:
        changed = False
        for n in range(len(order) - 1, -1, -1):
            out = set()
            for s in successors[n]:
                out |= live[s]
            new = use[n] | (out - defined[n])
            if new != live[n]:
                live[n], changed = new, True
    return live[0] if live else set()
