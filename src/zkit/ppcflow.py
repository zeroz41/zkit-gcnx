"""Where `this`, constants and data addresses go inside a PowerPC function (the EABI: r3 is `this` and the first
argument, r3 the return value, r14-r31 survive calls).

One pass in address order, no path merging: a register keeps its value until an instruction writes it, and a call
forgets the volatile registers. That reads constructors, destructors and allocation sites exactly (they are
straight-line where it matters) and stays conservative elsewhere: an unknown value is never reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field

THIS, CONST, ADDR, NEW, RESULT = "this", "const", "addr", "new", "result"
STORES = {36: 4, 37: 4, 38: 1, 39: 1, 44: 2, 45: 2, 52: 4, 53: 4, 54: 8, 55: 8}   # stw stwu stb stbu sth sthu stfs(u) stfd(u)
FLOAT_STORES = {52, 53, 54, 55}
LOADS = {32: 4, 33: 4, 34: 1, 35: 1, 40: 2, 41: 2, 42: 2, 43: 2, 48: 4, 49: 4, 50: 8, 51: 8}
FLOAT_LOADS = {48, 49, 50, 51}
UPDATE = {33, 35, 37, 39, 41, 43, 45, 49, 51, 53, 55}


@dataclass(frozen=True)
class Value:
    kind: str           # this, const, addr, new (an allocation of `amount` bytes), result (of call `amount`)
    amount: int = 0     # this: offset; const/addr: value; new: size; result: callee address


@dataclass
class Store:
    pc: int
    base: Value         # what the address register held (this + k, an allocation, ...)
    offset: int
    width: int
    value: Value | None
    float: bool


@dataclass
class Access:
    pc: int
    base: Value
    offset: int
    width: int
    float: bool
    store: bool


@dataclass
class Call:
    pc: int
    target: int
    args: dict[int, Value]  # r3.. r10 where known


@dataclass
class Flow:
    stores: list[Store] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    accesses: list[Access] = field(default_factory=list)   # every load or store through `this` or an allocation


def flows(program, allocators: frozenset[int] = frozenset()) -> dict[int, Flow]:
    """{function index: Flow} for every function of a Program, computed once per set of allocators."""
    key = ("ppcflow", allocators)
    if key not in program.cache:
        out = {}
        for index, function in enumerate(program.functions):
            try:
                words = program.image.words(function.address, function.size)
            except ValueError:
                continue
            out[index] = flow(words, function.address, program.sda, allocators=allocators)
        program.cache[key] = out
    return program.cache[key]


def _sext(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def flow(words: list[int], start: int, sda: dict[int, int] | None = None, entry_this: bool = True,
         allocators: set[int] = frozenset()) -> Flow:
    """`entry_this`: r3 holds `this` on entry (a method). `allocators`: functions returning a fresh object of the
    size passed in r3 (operator new and its wrappers)."""
    regs: dict[int, Value] = {}
    if entry_this:
        regs[3] = Value(THIS, 0)
    for register, base in (sda or {}).items():
        regs[register] = Value(ADDR, base)
    out = Flow()

    def offset_of(value: Value, delta: int) -> Value | None:
        if value.kind == THIS:
            return Value(THIS, value.amount + delta)
        if value.kind == NEW:
            return Value(NEW, value.amount) if delta == 0 else None
        if value.kind in (ADDR, CONST):
            return Value(value.kind, (value.amount + delta) & 0xFFFFFFFF)
        return None

    for index, word in enumerate(words):
        pc = start + index * 4
        op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 14:                                                     # addi / li
            if ra == 0:
                regs[rd] = Value(CONST, _sext(imm) & 0xFFFFFFFF)
            elif ra in regs and (moved := offset_of(regs[ra], _sext(imm))) is not None:
                high = regs[ra].kind == CONST and not regs[ra].amount & 0xFFFF and regs[ra].amount
                regs[rd] = Value(ADDR, moved.amount) if high else moved   # lis + addi forms an address
            else:
                regs.pop(rd, None)
        elif op == 15:                                                   # addis / lis
            if ra == 0:
                regs[rd] = Value(CONST, (imm << 16) & 0xFFFFFFFF)
            elif ra in regs and regs[ra].kind in (CONST, ADDR):
                regs[rd] = Value(regs[ra].kind, (regs[ra].amount + (imm << 16)) & 0xFFFFFFFF)
            else:
                regs.pop(rd, None)
        elif op == 24:                                                   # ori: rA = rS | imm
            if rd in regs and regs[rd].kind == CONST:
                regs[ra] = Value(CONST, regs[rd].amount | imm)
            else:
                regs.pop(ra, None)
        elif op == 31 and (word >> 1) & 0x3FF == 444 and rd == (word >> 11) & 31:  # mr rA, rS (or rA,rS,rS)
            if rd in regs:
                regs[ra] = regs[rd]
            else:
                regs.pop(ra, None)
        elif op in STORES or op in LOADS:
            base = regs.get(ra) if ra else None
            offset = _sext(imm)
            width = STORES.get(op) or LOADS.get(op)
            is_float = op in FLOAT_STORES or op in FLOAT_LOADS
            if base is not None and base.kind in (THIS, NEW):
                out.accesses.append(Access(pc, base, offset, width, is_float, op in STORES))
            if op in STORES and base is not None:
                value = None if is_float else regs.get(rd)
                out.stores.append(Store(pc, base, offset, width, value, is_float))
            if op in LOADS and not is_float:
                regs.pop(rd, None)
            if op in UPDATE and ra:
                moved = offset_of(base, offset) if base is not None else None
                if moved is None:
                    regs.pop(ra, None)
                else:
                    regs[ra] = moved
        elif op == 18:                                                   # b / bl
            if word & 1:
                offset = word & 0x3FFFFFC
                if offset & 0x2000000:
                    offset -= 0x4000000
                target = (pc + offset) & 0xFFFFFFFF if not word & 2 else offset & 0xFFFFFFFF
                out.calls.append(Call(pc, target, {r: regs[r] for r in range(3, 11) if r in regs}))
                size = regs.get(3)
                for register in (0, *range(3, 13)):
                    regs.pop(register, None)
                if target in allocators and size is not None and size.kind == CONST:
                    regs[3] = Value(NEW, size.amount)
                else:
                    regs[3] = Value(RESULT, target)
        elif op == 19 and word & 1:                                      # bctrl / blrl
            for register in (0, *range(3, 13)):
                regs.pop(register, None)
        elif op == 46:                                                   # lmw
            for register in range(rd, 32):
                regs.pop(register, None)
        elif op in (7, 8, 12, 13):                                       # mulli subfic addic addic.: rD
            regs.pop(rd, None)
        elif op in (20, 21, 23, 26, 27, 28, 29):                         # rotates and logical immediates: rA
            regs.pop(ra, None)
        elif op == 31:                                                   # other X-form: rD or rA
            regs.pop(rd, None)
            regs.pop(ra, None)
    return out
