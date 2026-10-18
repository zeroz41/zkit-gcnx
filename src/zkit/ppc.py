"""PowerPC (Gekko/Broadway, EABI) code: control flow inside a function, and the relocations an assembler would
have left in linked code.

Register values follow the function's control flow: basic blocks split at branches and branch targets, a block
starts with what every path into it agrees on, and code no path reaches starts knowing nothing. So a `lis` is never
paired with a use on a path it does not reach (straight-line reading does that after a `b` or across loop heads).

Relocations recovered:
- `lis rX, sym@ha` then `addi rY, rX, sym@l`, or a load/store `d(rX)` with `sym@l`: ADDR16_HA on the `lis`,
  ADDR16_LO on the second half (both 16-bit fields cleared);
- `lis rX, sym@h` then `ori rY, rX, sym@l`: ADDR16_HI and ADDR16_LO;
- a load, store or `addi` off r13 or r2 (the small-data bases): EMB_SDA21, the base register and offset cleared;
- `b`/`bl` leaving the function, or `bl` to its own start: REL24, `bc` leaving it: REL14, the displacement
  cleared.
Only addresses inside the image are relocations; a `lis` that builds a constant stays as it is.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
from typing import Callable

ADDR32, ADDR16_LO, ADDR16_HI, ADDR16_HA, REL24, REL14, EMB_SDA21 = 1, 4, 5, 6, 10, 11, 109
LOADS = {32, 33, 34, 35, 40, 41, 42, 43, 46, 48, 49, 50, 51}
STORES = {36, 37, 38, 39, 44, 45, 47, 52, 53, 54, 55}
UPDATE = {33, 35, 37, 39, 41, 43, 45, 49, 51, 53, 55}
FLOAT = {48, 49, 50, 51, 52, 53, 54, 55}
VOLATILE = (0, *range(3, 13))


# General registers each instruction writes (op 31 by extended opcode): exact, so a float register field is never
# mistaken for a general one (stfsx f2 writes no r2).
_X_RD = {23, 55, 87, 119, 279, 311, 343, 375, 534, 790, 20, 339, 19, 83, 371, 595, 659}      # indexed loads, mf*
_X_RD_MULTIPLE = {533, 597}                                                                  # lswx, lswi
_X_RA = {28, 60, 444, 412, 124, 316, 284, 476, 24, 536, 792, 824, 26, 922, 954}              # logical, shifts
_X_UPDATE = {55, 119, 311, 375, 567, 631, 183, 247, 439, 695, 759}                           # u-forms: also rA
_XO_RD = {266, 10, 138, 202, 234, 40, 8, 136, 200, 232, 104, 235, 75, 11, 491, 459}           # arithmetic (9-bit)


def writes(word: int) -> tuple[int, ...]:
    """General registers an instruction writes."""
    op, rd, ra = word >> 26, (word >> 21) & 31, (word >> 16) & 31
    if op in (7, 8, 12, 13, 14, 15) or (op in LOADS and op not in FLOAT and op != 46):
        return (rd, ra) if op in UPDATE else (rd,)
    if op == 46:                                                          # lmw
        return tuple(range(rd, 32))
    if op in UPDATE or op in (57, 61):                                    # float/store update forms, psq_lu/stu
        return (ra,)
    if op in (20, 21, 23, 24, 25, 26, 27, 28, 29):
        return (ra,)
    if op == 4 and (word >> 1) & 0x3F in (38, 39):                        # psq_lux / psq_stux
        return (ra,)
    if op == 31:
        xo = (word >> 1) & 0x3FF
        out: tuple[int, ...] = ()
        if xo in _X_RD or (word >> 1) & 0x1FF in _XO_RD:
            out = (rd,)
        elif xo in _X_RD_MULTIPLE:
            out = tuple(range(rd, 32))
        elif xo in _X_RA:
            out = (ra,)
        return out + ((ra,) if xo in _X_UPDATE else ())
    return ()


@dataclass
class Reloc:
    offset: int        # original address of the relocated field
    kind: int
    target: int        # original address the reference resolves to


def _sext(value: int, bits: int = 16) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


# Control flow

def branch(word: int, pc: int) -> tuple[int | None, bool, bool] | None:
    """(target or None for lr/ctr, conditional, links) of a branch instruction; None for anything else."""
    op = word >> 26
    if op == 18:
        displacement = _sext(word & 0x03FFFFFC, 26)
        target = displacement & 0xFFFFFFFF if word & 2 else (pc + displacement) & 0xFFFFFFFF
        return target, False, bool(word & 1)
    if op == 16:
        displacement = _sext(word & 0xFFFC)
        target = displacement & 0xFFFFFFFF if word & 2 else (pc + displacement) & 0xFFFFFFFF
        return target, not (word >> 21) & 0x14 == 0x14, bool(word & 1)
    if op == 19 and (word >> 1) & 0x3FF in (16, 528):                   # bclr / bcctr
        return None, not (word >> 21) & 0x14 == 0x14, bool(word & 1)
    return None


def blocks(words: list[int], start: int) -> tuple[list[int], dict[int, list[int]]]:
    """Block leaders (addresses, sorted) and each block's successors inside the function.

    A call falls through; a return, an indirect jump (bctr: jump tables) or a jump out of the function ends the
    path. Targets reached only through a jump table have no known predecessor and start knowing nothing."""
    end = start + 4 * len(words)
    leaders = {start}
    for index, word in enumerate(words):
        pc = start + index * 4
        found = branch(word, pc)
        if found is None:
            continue
        target, _, _ = found
        if target is not None and start <= target < end:
            leaders.add(target)
        if pc + 4 < end:
            leaders.add(pc + 4)
    ordered = sorted(leaders)
    successors: dict[int, list[int]] = {}
    for position, leader in enumerate(ordered):
        stop = ordered[position + 1] if position + 1 < len(ordered) else end
        last = stop - 4
        found = branch(words[(last - start) // 4], last)
        out = []
        if found is None:
            out.append(stop)
        else:
            target, conditional, links = found
            if target is not None and start <= target < end and not links:
                out.append(target)
            if conditional or links:
                out.append(stop)
        successors[leader] = [s for s in out if s < end]
    return ordered, successors


# Register state for relocations: register -> ("hi", value, lis addresses) or ("base", small-data base)

State = dict


def _meet(states: list[State]) -> State:
    first, rest = states[0], states[1:]
    out = {}
    for register, value in first.items():
        others = [s.get(register) for s in rest]
        if any(o is None or o[:2] != value[:2] for o in others):
            continue
        if value[0] == "hi":
            value = ("hi", value[1], frozenset().union(value[2], *(o[2] for o in others)))
        out[register] = value
    return out


def _step(state: State, pc: int, word: int, start: int, end: int, in_image, emit) -> None:
    """Apply one instruction to `state`; report relocations through `emit(kind, pc, target, word, lis)`."""
    op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
    found = branch(word, pc)
    if found is not None:
        target, _, links = found
        # leaving the function, or a call to its own start (recursion): the compiler names the symbol; an
        # absolute branch (`ba`, to a fixed vector) is not relocated
        if target is not None and op in (16, 18) and not word & 2 and (not start <= target < end or
                                                                       (links and target == start)):
            emit(REL14 if op == 16 else REL24, pc, target, word, None)
        if links:
            for register in VOLATILE:
                state.pop(register, None)
        return

    def low_half(register: int, delta: int, kind: int) -> None:
        _, value, origins = state[register]
        target = (value + delta) & 0xFFFFFFFF
        if in_image(target):
            emit(kind, pc, target, word, origins)

    def small_data(register: int) -> bool:
        held = state.get(register)
        if register and held is not None and held[0] == "base":
            target = (held[1] + _sext(imm)) & 0xFFFFFFFF
            if in_image(target):
                emit(EMB_SDA21, pc, target, word, None)
            return True
        return False
    if op == 15:                                                         # lis / addis
        if ra == 0:
            state[rd] = ("hi", (imm << 16) & 0xFFFFFFFF, frozenset({pc}))
        else:
            state.pop(rd, None)
        return
    if op in (12, 13, 14):                                               # addic, addic., addi / li
        if not small_data(ra) and ra and state.get(ra, ("",))[0] == "hi":
            low_half(ra, _sext(imm), ADDR16_HA)
        state.pop(rd, None)
        return
    if op == 24:                                                         # ori: rA = rS | imm
        held = state.get(rd)
        if held is not None and held[0] == "hi" and not held[1] & 0xFFFF:
            low_half(rd, imm, ADDR16_HI)
        state.pop(ra, None)
        return
    if op in LOADS or op in STORES:
        if not small_data(ra) and ra and state.get(ra, ("",))[0] == "hi":
            low_half(ra, _sext(imm), ADDR16_HA)
    for register in writes(word):
        state.pop(register, None)


def code_relocations(words: list[int], start: int, sda: dict[int, int],
                     in_image: Callable[[int], bool]) -> tuple[list[Reloc], dict[int, int]]:
    """Relocations of one function, and its instructions as an assembler writes them (relocated fields zero)."""
    end = start + 4 * len(words)
    leaders, successors = blocks(words, start)
    stops = {leader: (leaders[i + 1] if i + 1 < len(leaders) else end) for i, leader in enumerate(leaders)}
    # The small-data bases hold everywhere (the runtime sets them once); a block no known path reaches (a jump
    # table's case) starts with only those.
    entry: State = {register: ("base", value) for register, value in sda.items()}
    predecessors: dict[int, list[int]] = collections.defaultdict(list)
    for leader, targets in successors.items():
        for successor in targets:
            predecessors[successor].append(leader)
    states: dict[int, State] = {start: entry}
    ignore = lambda *args: None
    work = collections.deque([start])
    leaving: dict[int, State] = {}
    while work:                                    # states only shrink at each meet, so this settles
        leader = work.popleft()
        state = dict(states[leader])
        for pc in range(leader, stops[leader], 4):
            _step(state, pc, words[(pc - start) // 4], start, end, in_image, ignore)
        if leaving.get(leader) == state:
            continue
        leaving[leader] = state
        for successor in successors[leader]:
            merged = _meet([leaving[p] for p in predecessors[successor] if p in leaving]
                           + ([entry] if successor == start else []))
            if states.get(successor) != merged:
                states[successor] = merged
                work.append(successor)
    out: list[Reloc] = []
    cleared: dict[int, int] = {}
    paired: dict[int, tuple[int, int]] = {}         # lis address -> (kind, target) of its first low half

    def emit(kind: int, pc: int, target: int, word: int, origins) -> None:
        if kind in (REL24, REL14):
            out.append(Reloc(pc, kind, target))
            cleared[pc] = word & (0xFC000003 if kind == REL24 else 0xFFFF0003)
        elif kind == EMB_SDA21:
            out.append(Reloc(pc, kind, target))
            cleared[pc] = word & 0xFFE00000
        else:
            out.append(Reloc(pc + 2, ADDR16_LO, target))
            cleared[pc] = word & 0xFFFF0000
            for origin in origins:
                paired.setdefault(origin, (kind, target))
    for leader in leaders:
        state = dict(states.get(leader, entry))
        for pc in range(leader, stops[leader], 4):
            _step(state, pc, words[(pc - start) // 4], start, end, in_image, emit)
    for origin, (kind, target) in paired.items():    # each lis takes its first pair's symbol
        out.append(Reloc(origin + 2, kind, target))
        cleared[origin] = words[(origin - start) // 4] & 0xFFFF0000
    out.sort(key=lambda r: r.offset)
    return out, cleared
