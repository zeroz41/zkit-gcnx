"""Functions, sections and small-data bases of a GameCube executable, found from the DOL alone.

A fresh project has only the original DOL. Everything here is read from its bytes, and every function start keeps
the evidence that proves it:

- **entry**: the DOL's entry point; **section**: the first word of `.init` and of `.text`;
- **ctors**/**dtors**: the code pointers in `.ctors`/`.dtors` (static constructors and destructors);
- **extabindex**: an exception-table index record gives a function's start and its exact size;
- **sled**: CodeWarrior's register save/restore runtime (`_savegpr_14`..`_restfpr_31`): one function per run of
  18 stores or loads of r14..r31 off r11 and its `blr`; calls into the middle of a run are entries (labels);
- **call**: the target of a `bl` in code already found;
- **tail call**: a `b` to a prologue (a frame is set up once, so no function jumps to one inside itself);
- **after end** / **after padding**: the first instruction after a function's last reachable one, straight away
  or after zero padding. Functions are laid out back to back, so code nothing reaches is still a function (dead
  code, or code reached only at run time);
- **address**: a code address that code forms (`lis`/`addi`: a callback, a thread entry);
- **pointer**: a data word holding a code address (vtables, callback tables), unless it is a jump-table case.

A function's extent follows its control flow from its start and ends at its last reachable instruction; it never
crosses another start, and a `b` that leaves it (a tail call, a jump into another function's shared epilogue)
ends the path. A `bl` falls through; a fall into the next start ends the function there. Jump tables (`lwzx`
from a table, `mtctr`, `bctr`) add their cases as blocks, as many as the `cmplwi` guarding the index allows, and
their cases are never starts. After the last reachable instruction, code that begins with an epilogue (it pops
the frame or restores lr before setting either up: what follows a call that never returns), a lone `blr` after a
jump (the dead return after an endless loop) and a `nop` after a return (an exception vector template's patch
slot) belong to the function.

A data word or formed address that lands inside a function's extent is one of its labels (a restart point, the
end of a copied range) unless a prologue is there; a formed address also starts a function after an instruction
nothing falls through (one the walk ran into through a conditional branch). Formed addresses and data words are
read last, once the gaps are filled and every jump table is known.

Data in code is skipped: MetroTRK's exception vector table (its header string, then one handler per exception
vector 0x100 apart up to the last vector's `rfi`), the linker's init tables, and words that decode as no
instruction.

Sections are named by content and order, as CodeWarrior links them: `.init` (the first code section), `extab` and
`extabindex` (data between `.init` and `.text`), `.text`, then `.ctors` and `.dtors` (lists of code pointers),
`.rodata` and `.data` before the small data; `.sdata` and `.sdata2` start 0x8000 below where r13 and r2 point;
`.bss`, `.sbss`, `.sbss2` are the zero-initialized ranges the linker's `_bss_init_info` lists (else the gaps of the
DOL's zero-initialized range), named by where they lie against the small data. The bases come from
`__init_registers`, the first function the entry point calls that sets both r2 and r13; exact section sizes come
from `_rom_copy_info` when it is found.

Data objects start where code forms an address (`addi`/`ori`), at every small-data access, where a data word
points (`lbl_`), at every jump table (`jumptable_`) and exception record (`@eti_`, `@etb_`), and run to the next
one, less the zero padding that aligns the next: a jump table holds its cases, a literal string (used by its
address, never loaded) ends at its NUL, and a small-data object code only loads and stores whole at one width,
never forming its address, is that wide; nothing ends before an address the code or data reaches inside it (on
Double Dash, 1,051 of 1,364 sizes the map gives come out exact, against 713 up to the next label). The target of
a `lis` and a load or store starts one only in `.rodata` (a constant read whole); elsewhere it is left to the
object before it, because CodeWarrior folds a member's offset into the access. Measured against
Twilight Princess's map, 2,420 of 2,438 such `.bss` targets are inside an object, and taking them would cut the
share of `.bss` and `.data` starts that are right from 65% and 92% to 18% and 29%; on PSO, units proposed from
these objects find more of the decomp's boundaries (9.21%, 54.45% of them right) than with every target (9.19%,
53.92%) or none in `.rodata` (8.27%, 53.88%).
"""

from __future__ import annotations

import bisect
import collections
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .ppc import branch, writes
from .ppc import code_relocations as ppc_relocations

BLR, BCTR, RFI, NOP, MFLR_R0, MTLR_R0 = 0x4E800020, 0x4E800420, 0x4C000064, 0x60000000, 0x7C0802A6, 0x7C0803A6
INVALID_OPS = {0, 1, 2, 5, 6, 9, 22, 30, 58, 62}       # no Gekko instruction has these primary opcodes
TRK_HEADER = b"Metrowerks Target Resident Kernel for PowerPC\0"
LAST_VECTOR = 0x1F00          # the 750's last exception vector
SLED_OPS = {36: 4, 32: 4, 54: 8, 50: 8}                # stw, lwz, stfd, lfd and their stride
TABLE_LIMIT = 1024            # jump-table cases read when no bound check is found
CODE_SECTIONS = (".init", ".text")
ZERO_SECTIONS = (".bss", ".sbss", ".sbss2")
LITERAL_SECTIONS = (".rodata", ".sdata2")     # where CodeWarrior puts string literals (-str readonly)
SMALL_SECTIONS = (".sdata", ".sbss", ".sdata2", ".sbss2")
ACCESS_WIDTHS = {32: 4, 33: 4, 34: 1, 35: 1, 36: 4, 37: 4, 38: 1, 39: 1, 40: 2, 41: 2, 42: 2, 43: 2, 44: 2, 45: 2,
                 48: 4, 49: 4, 50: 8, 51: 8, 52: 4, 53: 4, 54: 8, 55: 8}      # D-form loads and stores, bytes


@dataclass
class Found:
    sections: list[tuple[str, int, int]]               # (name, start, end), address order
    sda: dict[int, int]                                # r2, r13
    functions: dict[int, int]                          # start -> size
    evidence: dict[int, set[str]]                      # start -> the kinds of evidence above
    labels: dict[int, int] = field(default_factory=dict)        # entry inside a function -> that function
    objects: list[tuple[int, int, str, str]] = field(default_factory=list)   # (address, size, section, name)
    tables: dict[int, int] = field(default_factory=dict)        # jump table -> case count
    data_in_text: list[tuple[int, int]] = field(default_factory=list)

    def section_of(self, address: int) -> str | None:
        index = bisect.bisect_right([s[1] for s in self.sections], address) - 1
        return self.sections[index][0] if index >= 0 and address < self.sections[index][2] else None


def _sext(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def valid(word: int) -> bool:
    """A word that decodes as a Gekko instruction (zero, the padding word, does not)."""
    return word >> 26 not in INVALID_OPS


def _ends_path(word: int | None) -> bool:
    """An unconditional jump, return or `rfi`: nothing falls through to the next instruction."""
    if word is None:
        return False
    if word == RFI:
        return True
    found = branch(word, 0)
    return found is not None and not found[1] and not found[2]


def _prologue(words, address: int) -> bool:
    """`stwu r1,-N(r1)` (or `stwux r1,r1,rX`) at the address, or `mflr r0` with one, or `stw r0,N(r1)`, soon
    after."""
    first = words(address)
    if first is None:
        return False
    if (first & 0xFFFF8000) == 0x94218000 or (first & 0xFFFF07FE) == 0x7C21016E:
        return True
    if first != MFLR_R0:
        return False
    for offset in (4, 8, 12):
        word = words(address + offset)
        if word is None or branch(word, address + offset) is not None:
            return False
        if (word & 0xFFFF8000) == 0x94218000 or (word & 0xFFFF0000) == 0x90010000:
            return True
    return False


def _dead_tail(words, address: int, limit: int) -> bool:
    """Code after a function's last reachable instruction that is still the function's: straight-line code that
    pops a frame (`addi r1,r1,+N`, `lwz r1,0(r1)`) or restores lr before setting either up, or a lone `blr` after
    a jump. A `blr` after a `blr` is an empty function of its own."""
    if words(address) == BLR:
        before = words(address - 4)
        return before is not None and before >> 26 == 18 and not before & 1
    pc = address
    while pc < limit:
        word = words(pc)
        if word is None or not valid(word):
            return False
        op, rd, ra = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        if (word & 0xFFFF8000) == 0x94218000 or word == MFLR_R0:
            return False
        if word == MTLR_R0 or (op == 14 and rd == 1 and ra == 1 and not word & 0x8000) or \
                (op == 32 and rd == 1 and ra == 1):
            return True
        if branch(word, pc) is not None:
            return False
        pc += 4
    return False


class _Code:
    """The code sections as words, read by address."""

    def __init__(self, dol, ranges: list[tuple[int, int]]):
        self.dol = dol
        self.ranges = sorted(ranges)
        self.words = {start: dol.words(start, end - start) for start, end in self.ranges}
        self.starts = [start for start, _ in self.ranges]

    def section(self, address: int) -> tuple[int, int] | None:
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0 and address < self.ranges[index][1]:
            return self.ranges[index]
        return None

    def word(self, address: int) -> int | None:
        found = self.section(address)
        if found is None or address % 4:
            return None
        return self.words[found[0]][(address - found[0]) // 4]

    def read32(self, address: int) -> int | None:
        try:
            return struct.unpack(">I", self.dol.read(address, 4))[0]
        except ValueError:
            return None


# Sections and small data

def _init_tables(dol) -> tuple[list[tuple[int, int]], list[tuple[int, int]], int, int] | None:
    """The linker's `_rom_copy_info` (rom, ram, size of every loaded section, then zeros) and `_bss_init_info`
    (start, size of every zero-initialized section, then zeros) right after it, found by content:
    ([(address, size)], [(start, size)], table start, table end)."""
    first = min(dol.sections, key=lambda s: s.address)
    needle = struct.pack(">II", first.address, first.address)
    sizes = {s.address: s.size for s in dol.sections}
    for section in dol.sections:
        raw = dol.raw[section.offset:section.offset + section.size]
        at = raw.find(needle)
        while at >= 0:
            loaded, zero, cursor = [], [], at
            while at % 4 == 0 and cursor + 12 <= len(raw):
                rom, ram, size = struct.unpack(">III", raw[cursor:cursor + 12])
                cursor += 12
                if not (rom or ram or size):
                    break
                if rom != ram or ram not in sizes or size > sizes[ram]:
                    loaded = []
                    break
                loaded.append((ram, size))
            while loaded and cursor + 8 <= len(raw):
                start, size = struct.unpack(">II", raw[cursor:cursor + 8])
                cursor += 8
                if not (start or size):
                    return loaded, zero, section.address + at, section.address + cursor
                zero.append((start, size))
            at = raw.find(needle, at + 4)
    return None


def _pointer_list(dol, section, code: list[tuple[int, int]]) -> bool:
    """Every word zero or a code address (`.ctors`, `.dtors`)."""
    return all(w == 0 or any(a <= w < b for a, b in code) for w in dol.words(section.address, section.size))


def name_sections(dol, sda: dict[int, int]) -> tuple[list[tuple[str, int, int]], tuple[int, int] | None]:
    """(name, start, end) of every section in address order, and where the linker's init tables are."""
    tables = _init_tables(dol)
    exact = dict(tables[0]) if tables else {}
    text = sorted((s for s in dol.sections if s.kind == "text"), key=lambda s: s.address)
    data = sorted((s for s in dol.sections if s.kind == "data"), key=lambda s: s.address)
    main = text[1] if len(text) > 1 else text[0]
    names = {main.address: ".text"}
    if len(text) > 1:
        names[text[0].address] = ".init"
    for index, extra in enumerate(text[2:], 1):
        names[extra.address] = f".text{index}"
    early = [s for s in data if s.address < main.address]
    for section, name in zip(early, ("extab", "extabindex") if len(early) > 1 else ("extabindex",)):
        names[section.address] = name
    small = {sda[13] - 0x8000: ".sdata", sda[2] - 0x8000: ".sdata2"} if 2 in sda and 13 in sda else {}
    late = []
    for section in data:
        if section.address in small:
            names[section.address] = small[section.address]
        elif section.address > main.address and (not small or section.address < min(small)):
            late.append(section)
    code = [(s.address, s.address + s.size) for s in text]
    lists = [s for s in late if _pointer_list(dol, s, code)][:2]
    for section, name in zip(lists, (".ctors", ".dtors")):
        names[section.address] = name
    for section, name in zip(reversed([s for s in late if s.address not in names]), (".data", ".rodata")):
        names[section.address] = name
    for index, section in enumerate(s for s in data if s.address not in names):
        names[section.address] = f".data{index + 1}"
    out = [(names[s.address], s.address, s.address + exact.get(s.address, s.size)) for s in dol.sections]
    bss_start, bss_end = dol.bss[0], dol.bss[0] + dol.bss[1]
    if tables and tables[1]:
        zero = [(start, start + size) for start, size in tables[1] if size]
    else:
        zero, cursor = [], bss_start
        for start, end in sorted((s[1], s[2]) for s in out if bss_start <= s[1] < bss_end):
            if start > cursor:
                zero.append((cursor, start))
            cursor = max(cursor, end)
        if cursor < bss_end:
            zero.append((cursor, bss_end))
    sdata, sdata2 = (sda[13] - 0x8000, sda[2] - 0x8000) if small else (bss_end, bss_end)
    for start, end in zero:
        out.append((".sbss2" if start >= sdata2 else ".sbss" if start >= sdata else ".bss", start, end))
    out.sort(key=lambda s: s[1])
    return out, (tables[2], tables[3]) if tables else None


def small_data_bases(dol) -> tuple[dict[int, int], int | None]:
    """r2 and r13 as `__init_registers` sets them, and where it is: the first function the entry point calls that
    sets both."""
    from .program import _gamecube_sda
    for target in _straight_calls(dol, dol.entry):
        registers = _gamecube_sda(dol, target)
        if len(registers) == 2:
            return registers, target
    return {}, None


def _words_from(dol, start: int, count: int) -> list[int]:
    """Up to `count` words from an address, within its section."""
    section = dol.section_at(start)
    if section is None:
        return []
    return dol.words(start, min(4 * count, section.address + section.size - start))


def _straight_calls(dol, start: int) -> list[int]:
    """`bl` targets of the straight-line code from an address, up to its first jump or return."""
    out = []
    for index, word in enumerate(_words_from(dol, start, 64)):
        found = branch(word, start + 4 * index)
        if found is None:
            continue
        target, conditional, links = found
        if links and target is not None:
            out.append(target)
        elif not conditional:
            break
    return out


# Functions

@dataclass
class _Walk:
    end: int
    calls: list[int]
    tails: list[int]                 # b to a prologue inside the range
    cases: dict[int, list[int]]      # jump table -> its cases


class _Finder:
    def __init__(self, dol, sections: list[tuple[str, int, int]], sda: dict[int, int],
                 data_in_text: list[tuple[int, int]]):
        self.dol, self.sda = dol, sda
        self.code = _Code(dol, [(a, b) for n, a, b in sections if n in CODE_SECTIONS or n.startswith(".text")])
        self.data_in_text = list(data_in_text)
        self.evidence: dict[int, set[str]] = collections.defaultdict(set)
        self.starts: list[int] = []
        self.walks: dict[int, _Walk] = {}
        self.fixed: dict[int, int] = {}                                  # start -> exact end
        self.roots: dict[int, set[int]] = collections.defaultdict(set)   # start -> its dead tails
        self.formed: dict[int, list[int]] = {}                           # start -> code addresses it forms
        self.labels: dict[int, int] = {}
        self.tables: dict[int, int] = {}
        self.cases: set[int] = set()
        self.dirty: set[int] = set()

    def add(self, address: int, why: str) -> bool:
        """A start (refused outside code, inside an extent known exactly, in data, or at an entry label)."""
        if self.code.section(address) is None or address % 4 or address in self.labels:
            return False
        if address in self.evidence:
            self.evidence[address].add(why)
            return False
        owner = self._owner(address)
        if owner is not None and address < self.fixed.get(owner, 0):
            return False
        if any(a <= address < b for a, b in self.data_in_text):
            return False
        self.evidence[address].add(why)
        bisect.insort(self.starts, address)
        self.dirty.add(address)
        if owner is not None and owner in self.walks and self.walks[owner].end > address:
            self.dirty.add(owner)
        return True

    def _owner(self, address: int) -> int | None:
        index = bisect.bisect_right(self.starts, address) - 1
        return self.starts[index] if index >= 0 else None

    def next_start(self, start: int) -> int:
        """The next start after a function, or the end of its section."""
        index = bisect.bisect_right(self.starts, start)
        end = self.code.section(start)[1]
        return min(end, self.starts[index]) if index < len(self.starts) else end

    def containing(self, address: int) -> int | None:
        """The function whose extent holds an address."""
        owner = self._owner(address)
        if owner is not None and owner in self.walks and address < self.walks[owner].end:
            return owner
        return None

    def walk(self, start: int) -> _Walk:
        """The function's reachable instructions below the next start, from its start and its dead tails."""
        limit = min(self.next_start(start), self.fixed.get(start, 1 << 32))
        word_at = self.code.word
        seen: set[int] = set()
        calls, tails, cases = [], [], {}
        work = [start, *sorted(self.roots.get(start, ()))]
        while work:
            pc = work.pop()
            while pc < limit and pc not in seen:
                word = word_at(pc)
                if word is None or not valid(word):
                    break
                seen.add(pc)
                found = branch(word, pc)
                if found is None:
                    if word == RFI:
                        break
                    pc += 4
                    continue
                target, conditional, links = found
                if links:
                    if target is not None and word >> 26 == 18:
                        calls.append(target)
                    pc += 4
                    continue
                if target is None:
                    if word == BCTR:
                        table = self._table(pc, start, limit)
                        if table is not None:
                            cases[table[0]] = table[1]
                            work.extend(table[1])
                    if conditional:
                        pc += 4
                        continue
                    break
                if start <= target < limit:
                    if not conditional and target != start and _prologue(word_at, target):
                        tails.append(target)
                    else:
                        work.append(target)
                if conditional:
                    pc += 4
                    continue
                break
        end = max(seen) + 4 if seen else start
        while end < limit and word_at(end) == NOP and _ends_path(word_at(end - 4)):
            end += 4
        return _Walk(self.fixed.get(start, end), calls, tails, cases)

    def _table(self, pc: int, start: int, limit: int) -> tuple[int, list[int]] | None:
        """The jump table a `bctr` reads and its cases: `mtctr rX` from `lwzx rX, rA, rB`, the table address
        built in rA or rB, the case count from the `cmplwi` that guards the index (else every word from the
        table's start that lands inside the function)."""
        word_at = self.code.word
        lowest, cursor = max(start, pc - 0x60), pc - 4
        target = registers = bound = load = None
        while cursor >= lowest:
            word = word_at(cursor)
            found = branch(word, cursor)
            if found is not None and not found[1]:
                break
            op, rd, xo = word >> 26, (word >> 21) & 31, (word >> 1) & 0x3FF
            if target is None and op == 31 and xo == 467 and (word >> 11) & 0x3FF == 0x120:     # mtctr
                target = rd
            elif target is not None and registers is None and op == 31 and xo == 23 and rd == target:  # lwzx
                registers, load = ((word >> 16) & 31, (word >> 11) & 31), cursor
            elif op == 10 and registers is not None and bound is None:                          # cmplwi
                bound = (word & 0xFFFF) + 1
            cursor -= 4
        if registers is None:
            return None
        address = self._value(cursor + 4, load, registers)
        if address is None:                    # the base was set before a loop: read the function up to the load
            address = self._value(start, load, registers)
        if address is None or self.code.section(address) is not None:
            return None
        for count in ((bound, TABLE_LIMIT) if bound else (TABLE_LIMIT,)):
            cases = []
            for index in range(count):
                case = self.code.read32(address + 4 * index)
                if case is None or not start <= case < limit or case % 4:
                    break
                cases.append(case)
            if cases and (count == TABLE_LIMIT or len(cases) == count):
                self.tables[address] = len(cases)
                return address, cases
        return None

    def _value(self, lowest: int, pc: int, registers: tuple[int, int]) -> int | None:
        """The address one of two registers holds at `pc`: `lis` then `addi`/`ori`, or a small-data base plus an
        offset, in the code from `lowest` read in address order."""
        values: dict[int, int] = dict(self.sda)
        for cursor in range(lowest, pc, 4):
            word = self.code.word(cursor)
            op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            if op == 15 and ra == 0:
                values[rd] = (imm << 16) & 0xFFFFFFFF
            elif op == 14 and ra and ra in values:
                values[rd] = (values[ra] + _sext(imm)) & 0xFFFFFFFF
            elif op == 24 and rd in values:
                values[ra] = values[rd] | imm
            else:
                for register in writes(word):
                    values.pop(register, None)
        return next((values[r] for r in registers if r in values and r not in self.sda), None)

    def settle(self) -> None:
        """Walk every function whose range changed, adding what the walks prove, until nothing changes."""
        from .gc import track_addresses
        while self.dirty:
            for start in sorted(self.dirty):
                self.dirty.discard(start)
                result = self.walks[start] = self.walk(start)
                for cases in result.cases.values():
                    self.cases.update(cases)
                for target in result.calls:
                    self.add(target, "call")
                for target in result.tails:
                    self.add(target, "tail call")
                words = self.dol.words(start, result.end - start)
                self.formed[start] = [value for value, kind in track_addresses(words, start, {}).values()
                                      if kind == "addr" and self.code.section(value) and not value % 4]


def _sleds(code: _Code) -> list[tuple[int, int]]:
    """(start, end) of each register save/restore run: 18 stores or loads of r14/f14..r31/f31 off r11 in order,
    at one stride, then `blr`."""
    out = []
    for section_start, words in code.words.items():
        index = 0
        while index + 19 <= len(words):
            word, op = words[index], words[index] >> 26
            if op in SLED_OPS and (word >> 16) & 0x3FF == (14 << 5) | 11:
                stride, base = SLED_OPS[op], _sext(word & 0xFFFF)
                if words[index + 18] == BLR and all(
                        words[index + k] >> 16 == (op << 10) | ((14 + k) << 5) | 11
                        and _sext(words[index + k] & 0xFFFF) == base + stride * k for k in range(18)):
                    out.append((section_start + 4 * index, section_start + 4 * (index + 19)))
                    index += 19
                    continue
            index += 1
    return out


def _trk_table(code: _Code) -> tuple[int, int] | None:
    """MetroTRK's exception vector table: its header string, then one handler per exception vector, 0x100 apart,
    up to the last vector's `rfi`."""
    for section_start, words in code.words.items():
        at = struct.pack(f">{len(words)}I", *words).find(TRK_HEADER)
        if at < 0 or at % 4:
            continue
        for index in range((at + LAST_VECTOR) // 4, len(words)):
            if words[index] == RFI:
                return section_start + at, section_start + 4 * (index + 1)
    return None


def find_functions(dol, sections: list[tuple[str, int, int]], sda: dict[int, int],
                   data_in_text: list[tuple[int, int]]) -> _Finder:
    finder = _Finder(dol, sections, sda, data_in_text)
    trk = _trk_table(finder.code)
    if trk:
        finder.data_in_text.append(trk)
    for start, end in _sleds(finder.code):
        finder.add(start, "sled")
        finder.fixed[start] = end
        for entry in range(start + 4, end - 4, 4):
            finder.labels[entry] = start
    named = {n: (a, b) for n, a, b in sections}
    finder.add(dol.entry, "entry")
    for name in CODE_SECTIONS:
        if name in named:
            finder.add(named[name][0], "section")
    for name in (".ctors", ".dtors"):
        if name in named:
            for word in dol.words(named[name][0], named[name][1] - named[name][0]):
                if word:
                    finder.add(word, name[1:])
    if "extabindex" in named:
        words = dol.words(named["extabindex"][0], named["extabindex"][1] - named["extabindex"][0])
        for function, size in zip(words[0::3], words[1::3]):
            if size and finder.code.section(function):
                finder.add(function, "extabindex")
                if function in finder.evidence:
                    finder.fixed[function] = function + size
                    finder.dirty.add(function)
    finder.settle()
    data = [(a, b) for n, a, b in sections if not (n in CODE_SECTIONS or n.startswith(".text") or n in ZERO_SECTIONS)]
    while True:                  # gaps first: every jump table is known before data pointing into code is read
        before = len(finder.starts)
        _fill_gaps(finder)
        finder.settle()
        if len(finder.starts) == before:
            _pointers(finder, data)
            finder.settle()
            if len(finder.starts) == before:
                return finder


def _fill_gaps(finder: _Finder) -> None:
    """After each function's last reachable instruction: skip padding and data; code that is the function's own
    dead tail joins it; anything else starts a function."""
    word_at = finder.code.word
    for start in list(finder.starts):
        stop, pc = finder.next_start(start), finder.walks[start].end
        padded = False
        while pc < stop:
            inside = next((b for a, b in finder.data_in_text if a <= pc < b), None)
            word = word_at(pc)
            if inside is not None:
                pc = inside
            elif word == 0:
                pc, padded = pc + 4, True
            elif not valid(word):
                end = pc + 4
                while end < stop and word_at(end) and not valid(word_at(end)):
                    end += 4
                finder.data_in_text.append((pc, end))
                pc = end
            else:
                if start not in finder.fixed and not padded and _dead_tail(word_at, pc, stop):
                    finder.roots[start].add(pc)
                    finder.dirty.add(start)
                else:
                    finder.add(pc, "after padding" if padded else "after end")
                break


def _pointers(finder: _Finder, data: list[tuple[int, int]]) -> None:
    """Formed addresses and data words holding a code address, read once the gaps are filled (module docstring)."""
    tables = sorted((a, a + 4 * n) for a, n in finder.tables.items())
    found: list[tuple[int, str]] = [(v, "address") for values in finder.formed.values() for v in values]
    for start, end in data:
        for index, value in enumerate(finder.dol.words(start, end - start)):
            if value % 4 or finder.code.section(value) is None:
                continue
            slot = start + 4 * index
            position = bisect.bisect_right(tables, (slot, 1 << 32)) - 1
            if not (position >= 0 and tables[position][0] <= slot < tables[position][1]):
                found.append((value, "pointer"))
    word_at = finder.code.word
    for value, why in found:
        if value in finder.evidence:
            finder.evidence[value].add(why)
            continue
        if value in finder.cases or value in finder.labels or word_at(value) == NOP:
            continue
        owner = finder.containing(value)
        if owner is not None and value in finder.roots.get(owner, ()):
            finder.roots[owner].discard(value)       # what the gaps took for a dead tail is a function after all
            finder.add(value, why)
        elif owner is None or _prologue(word_at, value) or (why == "address" and _ends_path(word_at(value - 4))):
            finder.add(value, why)


# Data objects

def find_objects(dol, finder: _Finder, sections: list[tuple[str, int, int]],
                 init_tables: tuple[int, int] | None) -> list[tuple[int, int, str, str]]:
    """(address, size, section, name) of every data object the code and data refer to, each up to the next
    (module docstring)."""
    from .gc import track_addresses
    named = [(a, b, n) for n, a, b in sections]
    starts = [a for a, _, _ in named]
    in_code = lambda n: n in CODE_SECTIONS or n.startswith(".text")
    data_in_text = sorted(finder.data_in_text + ([init_tables] if init_tables else []))

    def section_of(address: int) -> tuple[int, int, str] | None:
        index = bisect.bisect_right(starts, address) - 1
        return named[index] if index >= 0 and address < named[index][1] else None
    labels: dict[int, str] = {}

    def mark(address: int, name: str | None = None) -> None:
        found = section_of(address)
        if found is None or (in_code(found[2]) and (address % 4 or not any(a <= address < b
                                                                          for a, b in data_in_text))):
            return                                    # in code, only whole words: an odd value is not a label
        if name or address not in labels:
            labels[address] = name or f"lbl_{address:08X}"
    for a, _, n in named:
        if not in_code(n):
            mark(a)
    for a, _ in data_in_text:
        mark(a)
    widths: dict[int, set[int]] = collections.defaultdict(set)   # address -> widths code accesses it with
    whole: set[int] = set()                    # addresses code forms or data points to: an object's extent matters
    for start, walk in finder.walks.items():
        words = dol.words(start, walk.end - start)
        for pc, (value, kind) in track_addresses(words, start, finder.sda).items():
            held = section_of(value)
            if kind == "addr":
                whole.add(value)
            else:
                widths[value].add(ACCESS_WIDTHS.get(words[(pc - start) // 4] >> 26, 0))
            if kind == "addr" or (words[(pc - start) // 4] >> 16) & 31 in finder.sda or \
                    (held is not None and held[2] == ".rodata"):
                mark(value)
    for a, b, n in named:
        if not (in_code(n) or n in ZERO_SECTIONS):
            for value in dol.words(a, b - a):
                if 0x80000000 <= value < 0x81800000:
                    mark(value)
                    whole.add(value)
    for table in finder.tables:
        mark(table, f"jumptable_{table:08X}")
    for a, b, n in named:                             # .ctors/.dtors: one entry per unit's initializer (or finalizer);
        if n in (".ctors", ".dtors"):                 # the zero words after them are the linker's terminator
            for at, word in zip(range(a, b, 4), dol.words(a, b - a)):
                if word:
                    mark(at)
    if init_tables:                                   # the linker's own tables, where its copy loop reads them
        mark(init_tables[0], "_rom_copy_info")
        words = dol.words(init_tables[0], init_tables[1] - init_tables[0])
        rows = next((k for k in range(0, len(words) - 2, 3) if not any(words[k:k + 3])), None)
        if rows is not None and init_tables[0] + 4 * (rows + 3) < init_tables[1]:
            mark(init_tables[0] + 4 * (rows + 3), "_bss_init_info")
    index = next(((a, b) for a, b, n in named if n == "extabindex"), None)
    if index:
        words = dol.words(index[0], index[1] - index[0])
        eti = _eti_init_info(index[0], words, [(a, b) for a, b, n in named if in_code(n)])
        entries = (eti - index[0]) // 4 if eti is not None else len(words)
        for offset in range(0, entries - 2, 3):
            mark(index[0] + 4 * offset, f"@eti_{index[0] + 4 * offset:08X}")
            mark(words[offset + 2], f"@etb_{words[offset + 2]:08X}")
        if eti is not None:
            mark(eti, "_eti_init_info")
    ordered = sorted(labels)
    reached = set(widths) | whole              # and what the delinker's own flow analysis finds the code reaching
    for start, walk in finder.walks.items():
        found, _ = ppc_relocations(dol.words(start, walk.end - start), start, finder.sda,
                                   lambda a: section_of(a) is not None)
        reached.update(r.target for r in found)       # a branch into data too: the delinker relocates it
    reached = sorted(reached)
    out = []
    for position, address in enumerate(ordered):
        _, end, name = section_of(address)
        stop = min(ordered[position + 1], end) if position + 1 < len(ordered) else end
        if in_code(name):
            stop = min(stop, next(b for a, b in data_in_text if a <= address < b))
        if name in (".ctors", ".dtors"):
            stop = min(stop, address + 4)             # one pointer: the zeros after are the linker's terminator
        size = _own_size(dol, address, stop - address, name, finder.tables.get(address), widths, whole, reached)
        out.append((address, size, name, labels[address]))
    return out


def _own_size(dol, address: int, extent: int, section: str, cases: int | None, widths: dict[int, set[int]],
              whole: set[int], reached: list[int]) -> int:
    """An object's own size within the extent up to the next label: the zero bytes after it up to an aligned
    next object are alignment padding, which belongs to the gap (a unit's data starts aligned), not to it. A jump
    table holds its cases; a literal string (`.rodata`, `.sdata2`: used by its address, never loaded) ends at its
    NUL; a small-data object code only
    loads and stores whole, at one width, and that nothing points to, is that wide. Nothing shrinks past an
    address code or data reaches inside its extent: that is a member CodeWarrior folded into the access."""
    size = extent
    if cases:
        size = min(extent, 4 * cases)
    elif section in LITERAL_SECTIONS and extent > 1 and address in whole and not widths.get(address):
        raw = dol.read(address, extent)
        end = raw.find(b"\0")
        if end > 0 and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in raw[:end]):
            size = end + 1
    elif section in SMALL_SECTIONS and address not in whole and len(widths.get(address, ())) == 1:
        width = next(iter(widths[address]))
        if 0 < width < extent:
            size = width
    if size == extent or bisect.bisect_left(reached, address + extent) > bisect.bisect_left(reached, address + size):
        return extent                                 # code or data reaches past it: a member, not padding
    padding = extent - size
    tail = dol.read(address + size, padding) if section not in ZERO_SECTIONS else b""
    if any(tail) or padding >= 32 or (address + extent) % (1 << padding.bit_length()):
        return extent                                 # what follows is data, or more than padding to a boundary
    return size


def _eti_init_info(start: int, words: list[int], code: list[tuple[int, int]]) -> int | None:
    """Where the linker's `_eti_init_info` begins in extabindex: records of (first entry, end of the entries, code
    start, code size), the first starting at the section and ending where the records begin, then a zero record."""
    for offset in range(0, len(words) - 3, 3):
        at = start + 4 * offset
        first, end, code_start, size = words[offset:offset + 4]
        if first == start and end == at and size and any(a <= code_start < b for a, b in code):
            return at
    return None


# Everything

def discover(dol) -> Found:
    """Sections, small-data bases, functions (with evidence), entry labels, jump tables and data objects."""
    sda, _ = small_data_bases(dol)
    sections, init_tables = name_sections(dol, sda)
    finder = find_functions(dol, sections, sda, [init_tables] if init_tables else [])
    functions = {s: finder.walks[s].end - s for s in finder.starts if finder.walks[s].end > s}
    return Found(sections, sda, functions, {s: set(finder.evidence[s]) for s in functions}, dict(finder.labels),
                 find_objects(dol, finder, sections, init_tables), dict(finder.tables),
                 sorted(finder.data_in_text))


def write_symbols(found: Found, path: Path) -> Path:
    """The result as a symbols.txt: `fn_` functions, entry labels, data objects."""
    rows = [(a, 0, f"fn_{a:08X} = {found.section_of(a)}:0x{a:08X}; // type:function size:0x{s:X}")
            for a, s in found.functions.items()]
    rows += [(a, 1, f"lbl_{a:08X} = {found.section_of(a)}:0x{a:08X}; // type:label") for a in found.labels]
    for address, size, section, name in found.objects:
        scope = " scope:local" if name.startswith(("jumptable_", "@")) else ""
        rows.append((address, 2, f"{name} = {section}:0x{address:08X}; // type:object size:0x{size:X}{scope}"))
    rows.sort()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(line + "\n" for _, _, line in rows), encoding="utf-8")
    return path


def summary(found: Found) -> dict:
    """Counts a person reads: functions by evidence, sections, small-data bases, objects."""
    kinds = collections.Counter(kind for kinds in found.evidence.values() for kind in kinds)
    return {"functions": len(found.functions), "code_bytes": sum(found.functions.values()),
            "evidence": dict(kinds.most_common()), "labels": len(found.labels), "jump_tables": len(found.tables),
            "objects": len(found.objects), "sda": {f"r{r}": f"0x{v:08X}" for r, v in sorted(found.sda.items())},
            "sections": [{"name": n, "start": f"0x{a:08X}", "end": f"0x{b:08X}"} for n, a, b in found.sections],
            "data_in_text": [[f"0x{a:08X}", f"0x{b:08X}"] for a, b in found.data_in_text]}


def discover_project(project, target: str | None, out: Path) -> dict:
    """Discover a target's original executable and write the result as a symbols.txt."""
    from .bridge import default_target
    from .inspect_dol import _dol
    from .platform import for_target
    target = default_target(project, target)
    if for_target(project.target(target)).name != "gamecube":
        raise ValueError(f"Target {target} is not a GameCube target; discovery reads a DOL")
    found = discover(_dol(project, target))
    write_symbols(found, out)
    return {"target": target, "written": str(out), **summary(found)}
