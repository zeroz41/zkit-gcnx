"""Delink: cut the original executable into one relocatable object per unit, as the compiler would have emitted
it, so objdiff can compare each unit with the project's compiled one.

Every reference the code and data make is turned back into a relocation against a symbol, and the relocated
fields are cleared, as an assembler leaves them. Each object carries objdiff's `.note.split` with the original
address of every symbol. Names come from the project's symbols; an address nothing names gets `lbl_<address>`,
the same name in every unit that refers to it.

The machine decides how code is read (ppc.py: lis/addi pairs, small-data accesses, branches; aarch64.py: adrp
pairs, GOT loads, branches) and which data words are pointers. On Switch the module's own dynamic relocations
say so. A GameCube executable keeps none, so a word is a pointer only on evidence: it is a function's start, a
place inside the one function a jump table serves, or the start of (or a place inside) a named object, and it
does not sit in data the symbols call strings or numbers. A REL module keeps them all (rel.py): its tables name
every reference but the calls makerel applied, which its bytes hold. Units come from a splits.txt.
"""

from __future__ import annotations

import bisect
import collections
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import aarch64, ppc
from .project import Project


@dataclass(frozen=True)
class Machine:
    name: str
    elf64: bool
    little: bool
    e_machine: int
    e_flags: int
    pointer: int       # bytes in a data pointer
    absolute: int      # relocation type of a data pointer

    @property
    def order(self) -> str:
        return "<" if self.little else ">"


PPC = Machine("ppc", elf64=False, little=False, e_machine=20, e_flags=0x80000000, pointer=4, absolute=ppc.ADDR32)
AARCH64 = Machine("aarch64", elf64=True, little=True, e_machine=183, e_flags=0, pointer=8,
                  absolute=aarch64.ABS64)

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOTE, SHT_NOBITS = 1, 2, 3, 4, 7, 8
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHF_STRINGS, SHF_INFO_LINK, SHF_TLS = 1, 2, 4, 0x10, 0x20, 0x40, 0x400


def section_traits(machine: Machine, name: str) -> tuple[int, int, int, int]:
    """(sh_type, sh_flags, sh_entsize, alignment) of an output section, from its name: the original keeps only
    loaded segments, so the splits name each range's section and objdiff pairs sections by that name.

    PowerPC follows CodeWarrior's objects (.sdata2 is writable there; code aligned to 4, data to 8); AArch64
    follows clang's (merge sections for strings and constants)."""
    alloc, write, execute = SHF_ALLOC, SHF_WRITE, SHF_EXECINSTR
    name = name.split("$", 1)[0] if machine is PPC else name    # `.ctors$10` is a .ctors the linker sorts first
    if name.startswith(".text") or name in (".init", ".fini"):     # not `.init_array`: pointers, below
        return SHT_PROGBITS, alloc | execute, 0, 4
    if name.startswith((".bss", ".sbss", ".tbss")):
        return SHT_NOBITS, alloc | write | (SHF_TLS if name.startswith(".tbss") else 0), 0, 8
    if machine is PPC:
        if name in (".rodata", "extab", "extabindex"):
            return SHT_PROGBITS, alloc, 0, 4 if name.startswith("extab") else 8
        if name in (".ctors", ".dtors"):
            return SHT_PROGBITS, alloc | write, 0, 4
        return SHT_PROGBITS, alloc | write, 0, 8
    if name.startswith(".tdata"):
        return SHT_PROGBITS, alloc | write | SHF_TLS, 0, 8
    if name.startswith((".init_array", ".fini_array")):
        return (14 if name.startswith(".init") else 15), alloc | write, 8, 8
    if name.startswith(".rodata.str"):
        size = int(match[1]) if (match := re.match(r"\.rodata\.str\d+\.(\d+)", name)) else 1
        return SHT_PROGBITS, alloc | SHF_MERGE | SHF_STRINGS, size, size
    if name.startswith(".rodata.cst"):
        size = int(match[1]) if (match := re.match(r"\.rodata\.cst(\d+)", name)) else 8
        return SHT_PROGBITS, alloc | SHF_MERGE, size, size
    if name.startswith((".rodata", ".gcc_except_table", ".eh_frame")):
        return SHT_PROGBITS, alloc, 0, 8
    return SHT_PROGBITS, alloc | write, 0, 8


def _section_order(machine: Machine, name: str) -> tuple[int, str]:
    kind, flags, _, _ = section_traits(machine, name)
    return (0 if flags & SHF_EXECINSTR else 3 if kind == SHT_NOBITS else 2 if flags & SHF_WRITE else 1), name


def internal_linkage(name: str, scope: str | None = None) -> bool:
    """A symbol other units cannot name: the symbols' own scope when they record one, else the Itanium name
    (static functions and data, anything in an anonymous namespace)."""
    if scope is not None:
        return scope == "local"
    return name.startswith("_ZL") or "_GLOBAL__N_" in name


@dataclass
class Unit:
    name: str
    ranges: dict[str, list[tuple[int, int]]] = field(default_factory=lambda: collections.defaultdict(list))
    renames: dict[tuple[str, int], str] = field(default_factory=dict)   # (section, range start) -> name in the object


def read_units(path: Path, base: int = 0, place: Callable[[str, int], int | None] | None = None) -> list[Unit]:
    """A splits.txt (`unit:` then `\\t.section start:0x.. end:0x..` lines); addresses written with or without the
    module base, or section-relative (a REL's) and placed by `place`."""
    from .gc import read_renames, read_splits
    key = lambda value: value - base if base and value >= base else value
    units: dict[str, Unit] = {}
    renames = read_renames(path)
    for name, section, start, end in read_splits(path):
        unit = units.setdefault(name, Unit(name))
        if place is None:
            unit.ranges[section].append((key(start), key(end)))
            if (name, section, start) in renames:
                unit.renames[(section, key(start))] = renames[(name, section, start)]
        elif place(section, start) is not None:
            unit.ranges[section].append((place(section, start), place(section, end)))
    return list(units.values())


@dataclass(frozen=True)
class Entry:
    address: int
    size: int
    name: str
    scope: str | None = None   # None: unknown (decided from the name)
    data: str = ""             # what the bytes are (string, float, ...), when the symbols say


# The linker's own names for section boundaries, the stack, heap and small-data bases: code that walks a section
# (a module's _prolog over .ctors) can only name its start through these, never through an object another unit
# defines there.
LINKER_LABEL = re.compile(r"^_(?:ctors|dtors|[fe]_?(?:init|text|extab|extabindex|ctors|dtors|rodata|data|sdata2?|"
                          r"sbss2?|bss|stack)(?:_rom)?|(?:db_)?stack_(?:addr|end)|heap_(?:addr|end)|"
                          r"(?:ABS_)?SDA2?_BASE_)$")


class Symbols:
    """Every name an address can take: functions, data objects and labels, then synthesized labels for the rest."""

    def __init__(self, functions: list[Entry], data: list[Entry], text: Callable[[int], str]):
        self.linker = {e.address: e.name for e in data if not e.size and LINKER_LABEL.match(e.name)}
        # a global label at the start of a local symbol: the name other units reach it by (`_savegpr_14` at the
        # local `__save_gpr`)
        self.aliases = {e.address: e.name for e in data if not e.size and e.scope == "global"
                        and not e.name.startswith(("lbl_", "@", ".L"))}
        best = {e.address: e for e in functions}
        best_function = set(best)
        for entry in data:  # one name per address: a function, else a sized object, else a label
            held = best.get(entry.address)
            if held is None or (held.address not in best_function and not held.size and entry.size):
                best[entry.address] = entry
        self.entries = sorted(best.values(), key=lambda e: e.address)
        self.starts = [e.address for e in self.entries]
        self.by_address = {e.address: e for e in self.entries}
        self.functions = {e.address: e for e in functions}
        self._function_starts = sorted(self.functions)
        self.text = text  # how addresses are written in labels

    def containing(self, address: int) -> Entry | None:
        """The sized symbol holding an address."""
        index = bisect.bisect_right(self.starts, address) - 1
        while index >= 0 and self.entries[index].address > address - 0x100000:
            entry = self.entries[index]
            if entry.address <= address < entry.address + max(entry.size, 1):
                return entry
            index -= 1
        return None

    def function_containing(self, address: int) -> Entry | None:
        index = bisect.bisect_right(self._function_starts, address) - 1
        if index < 0:
            return None
        entry = self.functions[self._function_starts[index]]
        return entry if address < entry.address + entry.size else None

    def resolve(self, address: int, kind: int = 0) -> tuple[str, int]:
        """(symbol, addend) for an address: the symbol containing it, else a label at it. An address half
        (lis/addi) at a linker boundary label names the label, and the start of a local symbol the global label
        sharing it."""
        if kind in (ppc.ADDR16_LO, ppc.ADDR16_HI, ppc.ADDR16_HA) and address in self.linker:
            return self.linker[address], 0
        entry = self.containing(address)
        if entry is not None:
            if entry.scope == "local" and entry.address == address and address in self.aliases:
                return self.aliases[address], 0
            return entry.name, address - entry.address
        return f"lbl_{self.text(address)}", 0


# Data pointers

def _jump_table(words: list[int], index: int, symbols: Symbols) -> bool:
    """A word into the middle of a function as a jump-table entry: a neighbour lands in the same function."""
    home = symbols.function_containing(words[index])
    if home is None:
        return False
    for neighbour in (index - 1, index + 1):
        if 0 <= neighbour < len(words) and symbols.function_containing(words[neighbour]) is home:
            return True
    return False


def data_pointers(read: Callable[[int, int], bytes], start: int, end: int, symbols: Symbols,
                  in_image: Callable[[int], bool], in_code: Callable[[int], bool],
                  order: str = ">") -> list[tuple[int, int, str]]:
    """(slot, pointee, evidence) for the aligned words of [start, end) that point into the image, apart from words
    inside data the symbols mark as strings (their bytes say so) and code addresses that are not word-aligned.

    On a GameCube executable a 32-bit value in 0x80000000-0x817FFFFF that lands in a section and is not a pointer
    is rare enough that every such word is taken (measured: no false pointer in 1,429 proven PSO units). The
    evidence says what the word points at: "function", "jump table", "inside function" (a function start the
    symbols lack, or a wrong boundary), "object", "inside object", or "unnamed" (no symbol covers it)."""
    first = start + (-start % 4)
    count = (end - first) // 4
    if count <= 0:
        return []
    words = list(struct.unpack(f"{order}{count}I", read(first, count * 4)))
    out = []
    for index, value in enumerate(words):
        slot = first + index * 4
        if not in_image(value) or (value % 4 and in_code(value)):
            continue
        holder = symbols.containing(slot)
        if holder is not None and holder.data in ("string", "wstring", "string_table", "wstring_table"):
            continue
        if value in symbols.functions:
            evidence = "function"
        elif symbols.function_containing(value) is not None:
            evidence = "jump table" if _jump_table(words, index, symbols) else "inside function"
        elif value in symbols.by_address:
            evidence = "object"
        elif symbols.containing(value) is not None:
            evidence = "inside object"
        else:
            evidence = "unnamed"
        out.append((slot, value, evidence))
    return out


# Writing objects

def _note(machine: Machine, addresses: list[int]) -> bytes:
    """objdiff's `.note.split`: the generator and each symbol's original address (index 0 is the null symbol)."""
    o, width = machine.order, "Q" if machine.elf64 else "I"
    out = bytearray()
    for kind, desc in ((b"GENR", b"zkit"), (b"VIRT", b"".join(struct.pack(o + width, a) for a in addresses))):
        out += struct.pack(o + "III", 6, len(desc), int.from_bytes(kind, "big"))
        out += b"Split\0\0\0" + desc + b"\0" * (-len(desc) % 4)
    return bytes(out)


# The compiler version each CodeWarrior .comment version is written with, as the GameCube compilers write it
# (measured: GC 1.0-1.2.5 write 8 / 2.3.0, 1.3.2 writes 10 / 2.4.2, 2.0-2.6 write 10 / 2.4.7, 2.7 writes 11 / 2.4.7,
# 3.0a3 14 / 4.0.0, 3.0a5 15 / 4.0.0; the linker reads the version, not the compiler).
MW_COMPILERS = {8: (2, 3, 0, 1), 10: (2, 4, 7, 1), 11: (2, 4, 7, 1), 14: (4, 0, 0, 1), 15: (4, 0, 0, 1)}
SHT_MWCATS = 0xCA2A82C2   # CodeWarrior's own section type, which its linkers skip


def _mw_comment(version: int, records: list[tuple[int, int, int]]) -> bytes:
    """CodeWarrior's `.comment`: a 0x2C-byte header (magic, version, compiler, pooled data, hardware float, Gekko)
    then 8 bytes per symbol-table entry: alignment, visibility (0xD weak), activity (0x8: never dead-strip)."""
    if version not in MW_COMPILERS:
        raise ValueError(f"No CodeWarrior .comment version {version} (known: {sorted(MW_COMPILERS)})")
    header = b"CodeWarrior" + bytes([version, *MW_COMPILERS[version], 1, 2]) + struct.pack(">HBB", 0x16, 0x2C, 0)
    return header + bytes(0x2C - len(header)) + b"".join(struct.pack(">IBBH", *row, 0) for row in records)


def write_object(machine: Machine, sections: list[tuple[str, int, bytes | int, int]], symbols: list[dict],
                 relocations: dict[str, list], path: Path, source: str | None = None,
                 comment: int | None = None, starts: dict[str, int] | None = None) -> None:
    """A relocatable ELF object for the machine.

    sections: (name, sh_type, data or NOBITS size, alignment); symbols: {name, section (name or None), value, size,
    kind, bind, address}; relocations: section name -> [(offset, type, symbol index, addend)]. With `comment` (a
    CodeWarrior .comment version, PowerPC only), the object carries the `.comment` mwld needs, marking every defined
    function and object active so the linker keeps it; below version 14 `.note.split` takes CodeWarrior's section
    type, since those linkers do not skip notes. `starts` gives each section's original address, which
    `.note.split` records for its section symbol (objdiff reports a section at it)."""
    o = machine.order
    sym_format, rela_format = (o + "IBBHQQ", o + "QQq") if machine.elf64 else (o + "IIIBBH", o + "IIi")
    shdr_format = o + ("IIQQQQIIQQ" if machine.elf64 else "IIIIIIIIII")
    ehdr_size, shdr_size = (64, 64) if machine.elf64 else (52, 40)

    def sym(name: int, info: int, shndx: int, value: int, size: int) -> bytes:
        if machine.elf64:
            return struct.pack(sym_format, name, info, 0, shndx, value, size)
        return struct.pack(sym_format, name, value, size, info, 0, shndx)

    def rela(offset: int, symbol: int, kind: int, addend: int) -> bytes:
        info = (symbol << 32) | kind if machine.elf64 else (symbol << 8) | kind
        return struct.pack(rela_format, offset, info, addend)

    section_index = {name: i + 1 for i, (name, *_rest) in enumerate(sections)}
    strings = bytearray(b"\0")

    def string(text: str) -> int:
        offset = len(strings)
        strings.extend(text.encode() + b"\0")
        return offset
    # null, then the file and section symbols (local, unnamed in objdiff's eyes), then locals, then the rest
    entries = [sym(0, 0, 0, 0, 0)]
    addresses = [0]
    if source:
        entries.append(sym(string(source), 4, 0xFFF1, 0, 0))   # STT_FILE, SHN_ABS
        addresses.append(0)
    for index, (name, *_rest) in enumerate(sections, 1):
        entries.append(sym(0, 3, index, 0, 0))                 # STT_SECTION
        addresses.append((starts or {}).get(name, 0))
    binds, kinds = {"local": 0, "global": 1, "weak": 2}, {"notype": 0, "object": 1, "func": 2, "section": 3}
    order = sorted(range(len(symbols)), key=lambda i: symbols[i]["bind"] != "local")
    index_of = {}
    for i in order:
        symbol = symbols[i]
        index_of[i] = len(entries)
        shndx = section_index.get(symbol["section"], 0) if symbol["section"] else 0
        entries.append(sym(string(symbol["name"]), (binds[symbol["bind"]] << 4) | kinds[symbol["kind"]], shndx,
                           symbol["value"], symbol["size"]))
        addresses.append(symbol["address"])
    first_global = 1 + (1 if source else 0) + len(sections) + sum(1 for s in symbols if s["bind"] == "local")
    content = list(sections)
    if comment is not None:
        def record(symbol: dict) -> tuple[int, int, int]:
            kind, defined = symbol["kind"], symbol["section"] is not None
            align = 4 if kind == "func" else (1 if symbol["value"] % 4 else 4) if kind == "object" else 0
            return align, 0xD if symbol["bind"] == "weak" else 0, 0x8 if defined and kind in ("func", "object") else 0
        records = [(0, 0, 0)] + ([(1, 0, 0)] if source else []) + [(align, 0, 0) for *_, align in sections]
        records += [record(symbols[i]) for i in order]
    symtab_index = len(content) + 1
    extra: list[tuple[str, int, bytes, int, int, int, int, int]] = []  # name, type, data, align, link, info, ent, flags
    extra.append((".symtab", SHT_SYMTAB, b"".join(entries), 4 if not machine.elf64 else 8, symtab_index + 1,
                  first_global, len(entries[0]), 0))
    extra.append((".strtab", SHT_STRTAB, bytes(strings), 1, 0, 0, 0, 0))
    for name, rows in relocations.items():
        if rows:
            data = b"".join(rela(offset, index_of[symbol], kind, addend) for offset, kind, symbol, addend in sorted(rows))
            extra.append((f".rela{name}", SHT_RELA, data, 4 if not machine.elf64 else 8, symtab_index,
                          section_index[name], struct.calcsize(rela_format), SHF_INFO_LINK))
    if comment is not None:
        extra.append((".comment", SHT_PROGBITS, _mw_comment(comment, records), 1, 0, 0, 1, 0))
    note_type = SHT_MWCATS if comment is not None and comment < 14 else SHT_NOTE
    extra.append((".note.split", note_type, _note(machine, addresses), 4, 0, 0, 0, 0))
    names = bytearray(b"\0")

    def section_name(text: str) -> int:
        offset = len(names)
        names.extend(text.encode() + b"\0")
        return offset
    body = bytearray(b"\0" * ehdr_size)
    headers = [struct.pack(shdr_format, *[0] * 10)]

    def place(data: bytes, align: int) -> int:
        while len(body) % max(align, 1):
            body.append(0)
        offset = len(body)
        body.extend(data)
        return offset
    for name, kind, data, align in content:
        _, flags, entsize, _ = section_traits(machine, name)
        size = data if kind == SHT_NOBITS else len(data)
        offset = place(b"" if kind == SHT_NOBITS else data, align)
        headers.append(struct.pack(shdr_format, section_name(name), kind, flags, 0, offset, size, 0, 0, align, entsize))
    for name, kind, data, align, link, info, entsize, flags in extra:
        offset = place(data, align)
        headers.append(struct.pack(shdr_format, section_name(name), kind, flags, 0, offset, len(data), link, info,
                                   align, entsize))
    shstrtab = section_name(".shstrtab")
    offset = place(bytes(names), 1)
    headers.append(struct.pack(shdr_format, shstrtab, SHT_STRTAB, 0, 0, offset, len(names), 0, 0, 1, 0))
    shoff = place(b"", 8 if machine.elf64 else 4)
    body.extend(b"".join(headers))
    ident = b"\x7fELF" + bytes([2 if machine.elf64 else 1, 1 if machine.little else 2, 1]) + b"\0" * 9
    if machine.elf64:
        header = ident + struct.pack(o + "HHIQQQIHHHHHH", 1, machine.e_machine, 1, 0, 0, shoff, machine.e_flags,
                                     ehdr_size, 0, 0, shdr_size, len(headers), len(headers) - 1)
    else:
        header = ident + struct.pack(o + "HHIIIIIHHHHHH", 1, machine.e_machine, 1, 0, 0, shoff, machine.e_flags,
                                     ehdr_size, 0, 0, shdr_size, len(headers), len(headers) - 1)
    body[:ehdr_size] = header
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))


def write_objdiff(path: Path, units: list[dict], compiled: Path) -> Path:
    """objdiff.json for delinked units: target = the delinked object, base = the compiled one."""
    folder = path.parent.resolve()
    relative = lambda p: os.path.relpath(Path(p).resolve(), folder)
    rows = []
    for unit in units:
        stem = unit["unit"].rsplit(".", 1)[0]
        rows.append({"name": stem, "target_path": relative(unit["object"]),
                     "base_path": relative(compiled / f"{stem}.o"), "metadata": {"source_path": unit["unit"]}})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"min_version": "2.0.0", "build_target": False, "build_base": False, "units": rows},
                               indent=2) + "\n", encoding="utf-8")
    return path


# The machine-specific reading of an image

@dataclass
class Image:
    """What the delinker reads from one original: its machine, bytes, names and how it decodes references."""
    machine: Machine
    base: int
    read: Callable[[int, int], bytes]
    symbols: Symbols
    in_image: Callable[[int], bool]
    code: Callable[[int, int, Callable[[int], bool]], tuple[list, dict[int, int]]]
    pointers: Callable[[int, int], list[tuple[int, int, str]]]
    text: Callable[[int], str]
    section_of: Callable[[int], str | None] = lambda address: None   # the section holding an address
    place: Callable[[str, int], int | None] | None = None   # section-relative splits and symbols (a REL)
    virtual: Callable[[int], int] | None = None             # the address objdiff shows, when not base + address

    def original(self, address: int) -> int:
        return self.virtual(address) if self.virtual else self.base + address


def _gamecube(project: Project, target: str) -> Image:
    from .program import Program
    program = Program.from_project(project, target)
    functions = [Entry(f.address, f.size, f.name, f.scope) for f in program.functions]
    data = [Entry(o.address, o.size, o.name, o.scope, o.data) for o in program.objects]
    data += [Entry(o.address, 0, o.name, o.scope) for o in program.labels if o.address not in program.function_index]
    config = project.target(target)
    if config.get("symbols"):  # objects inside code (vector tables, the linker's tables): Program keeps code to functions
        from .gc import read_symbols
        from .program import CODE_SECTIONS
        data += [Entry(s.address, s.size, s.name, s.scope, s.data) for s in read_symbols(
            project.file(config["repository"], config["symbols"])) if s.type == "object" and s.section in CODE_SECTIONS]
    text = lambda address: f"{address:08X}"
    symbols = Symbols(functions, data, text)
    sda = dict(program.sda)

    def code(start: int, size: int, resolved) -> tuple[list, dict[int, int]]:
        words = program.platform.words(program.image, start, size)
        found, cleared = ppc.code_relocations(words, start, sda, program.in_image)
        return [(r.offset, r.kind, r.target, False) for r in found], cleared
    return Image(PPC, 0, program.read, symbols, program.in_image, code,
                 lambda start, end: data_pointers(program.read, start, end, symbols, program.in_image,
                                                  program.in_code, ">"),
                 text, program.section_of)


def _local(scope: str | None) -> str | None:
    """A module's symbols say `scope:global` of every name its exports did not settle, so only a local scope is
    taken from them (a file's own, like its static initializer); the others go by the name (`internal_linkage`)."""
    return "local" if scope == "local" else None


def _switch(project: Project, target: str, platform) -> Image:
    from .bridge import _symbol_table
    from .index import connect, refresh
    from .inspect_dol import _dol
    module = _dol(project, target)
    table = _symbol_table(project, target)[0]
    config = project.target(target)
    if config.get("symbols") and project.file(config["repository"], config["symbols"]).is_file():
        # the symbols file names the functions: the index takes them from the last report, which these very
        # objects made, so a name the file changed would never reach them
        functions = sorted((Entry(s.address, s.size, s.name, _local(s.scope)) for s in table
                            if s.type == "function" and s.size and s.address < 1 << 32), key=lambda e: e.address)
    else:
        refresh(project)
        functions = [Entry(a, s, n) for a, s, n in connect(project).execute(
            "SELECT address, size, name FROM functions WHERE target=? AND address<? ORDER BY address",
            (target, 1 << 32))]
    data = [Entry(s.address, s.size, s.name, _local(s.scope)) for s in table if s.type != "function"]
    text = lambda address: platform.text(address)[2:]
    symbols = Symbols(functions, data, text)
    in_image = lambda address: module.segment_at(address) is not None

    def code(start: int, size: int, resolved) -> tuple[list, dict[int, int]]:
        found, cleared = aarch64.code_relocations(module.words(start, size), start, module.pointers, resolved)
        return [(r.offset, r.kind, r.target, r.got) for r in found], cleared

    def pointers(start: int, end: int) -> list[tuple[int, int]]:
        return [(slot, pointee, "dynamic relocation") for slot, pointee in module.pointers.items()
                if start <= slot and slot + 8 <= end]
    return Image(AARCH64, platform.base, module.read, symbols, in_image, code, pointers, text)


def _image(project: Project, target: str) -> Image:
    from .platform import for_target
    platform = for_target(project.target(target))
    if platform.name == "switch":
        return _switch(project, target, platform)
    if platform.name == "gamecube":
        from . import rel
        return rel.image(project, target) if rel.is_module(project.target(target)) else _gamecube(project, target)
    raise ValueError(f"No delinker for {platform.name} targets")


def _internal(entry: Entry | None, name: str) -> bool:
    """A call the assembler resolves itself: to a local symbol (its scope, or an Itanium internal name) or a label."""
    if entry is not None and entry.scope is not None:
        return entry.scope == "local"
    return name.startswith(("_ZL", "_ZN12_GLOBAL__N_", "lbl_", ".L")) or "_GLOBAL__N_" in name


@dataclass
class Cut:
    """One unit's sections as cut from the original and every reference they make, before any is named."""
    unit: Unit
    sections: list[list] = field(default_factory=list)   # [name, sh_type, bytearray or NOBITS size, alignment]
    placed: dict[str, list[tuple[int, int, int]]] = field(default_factory=dict)  # (start, end, section offset)
    found: dict[str, list[tuple[int, int, int, bool]]] = field(default_factory=dict)  # (address, type, target, GOT)
    pointers: collections.Counter = field(default_factory=collections.Counter)
    boundaries: list[int] = field(default_factory=list)  # data pointing into a function: a start the symbols lack

    def offset(self, section: str, address: int) -> int | None:
        return next((offset + address - s for s, e, offset in self.placed[section] if s <= address < e), None)

    def where(self, address: int) -> tuple[str, int] | None:
        """(section, offset) of an original address inside the unit."""
        for section, placed in self.placed.items():
            for start, end, offset in placed:
                if start <= address < end:
                    return section, offset + address - start
        return None

    def entries(self, symbols: Symbols) -> list[tuple[Entry, str, int]]:
        """(entry, section, offset) for every name inside the unit, in address order."""
        out = []
        for section, placed in self.placed.items():
            for start, end, offset in placed:
                first, last = bisect.bisect_left(symbols.starts, start), bisect.bisect_left(symbols.starts, end)
                out += [(e, section, offset + e.address - start) for e in symbols.entries[first:last]]
        return sorted(out, key=lambda row: row[0].address)


@dataclass(frozen=True)
class Plan:
    """What linking asks of one unit's object (delinking alone asks nothing): the global name of every address some
    other object reaches (one table for the whole link), labels other objects reach in this unit (defined here,
    global), names the linker itself defines (never defined here; a reference landing exactly on one's address
    names it, as mwld wants `_ctors` named, not the entry that starts .ctors), each section's alignment, the
    CodeWarrior .comment version, the sections to cover with symbols, and the addresses no object names (a compiled
    object keeps them local), whose references stay as the original's bytes: the link puts them where they were."""
    names: dict[int, str]
    labels: dict[str, int] = field(default_factory=dict)
    linker: dict[str, int | None] = field(default_factory=dict)   # name -> its address when the symbols place it
    alignment: dict[str, int] = field(default_factory=dict)
    comment: int | None = None
    fill: frozenset[str] = frozenset()   # sections whose every byte must belong to a symbol (see _fill)
    fixed: frozenset[int] = frozenset()  # addresses no object can name: references to them keep the original bytes


def _own_sections(image: Image, section: str, span: tuple[int, int], name: str):
    """A code range as (start, end, section in the object): on AArch64, a file-local function whose name has a dot
    (clang's `_GLOBAL__sub_I_<file>`) in the section clang compiles it into, `<section>.<its name>`. objdiff pairs a
    local symbol only between sections whose names agree once their last `.part` is dropped, which `.text` and
    `.text._GLOBAL__sub_I_a.cpp` do not."""
    start, end = span
    if image.machine is not AARCH64 or not section_traits(image.machine, section)[1] & SHF_EXECINSTR:
        yield start, end, name
        return
    symbols, cursor = image.symbols, start
    for function in symbols._function_starts[bisect.bisect_left(symbols._function_starts, start):]:
        if function >= end:
            break
        entry = symbols.functions[function]
        if "." in entry.name and internal_linkage(entry.name, entry.scope):
            stop = min(end, function + entry.size)
            if function > cursor:
                yield cursor, function, name
            yield function, stop, f"{section}.{entry.name}"
            cursor = stop
    if cursor < end:
        yield cursor, end, name


def cut_unit(image: Image, unit: Unit) -> Cut:
    """A unit's bytes, section by section (each range keeping its own alignment), with the reference fields cleared
    and every reference recorded by the address it reaches."""
    machine, symbols = image.machine, image.symbols
    o = machine.order
    cut = Cut(unit)
    groups = collections.defaultdict(list)            # name in the object -> ranges (a renamed range is its own)
    for base_name, spans in unit.ranges.items():
        for span in spans:
            for start, end, name in _own_sections(image, base_name, span, unit.renames.get((base_name, span[0]),
                                                                                            base_name)):
                groups[name].append((start, end))
    for section_name in sorted(groups, key=lambda n: (_section_order(machine, n.split("$", 1)[0]), n)):
        ranges = sorted(groups[section_name])
        kind, flags, _, alignment = section_traits(machine, section_name)
        nobits = kind == SHT_NOBITS
        blob = bytearray()
        used = 0
        placed: list[tuple[int, int, int]] = []  # (original start, original end, section offset)
        for start, end in ranges:
            natural = min(alignment, start & -start or alignment)  # keep the range's own alignment
            while used % natural:
                used += 1
                blob += b"" if nobits else b"\0"
            placed.append((start, end, used))
            used += end - start
            blob += b"" if nobits else image.read(start, end - start)
        cut.placed[section_name] = placed
        local = lambda address, section_name=section_name: cut.offset(section_name, address)
        found: list[tuple[int, int, int, bool]] = []
        if flags & SHF_EXECINSTR:
            for start, end, _ in placed:
                index = bisect.bisect_left(symbols._function_starts, start)
                for function in symbols._function_starts[index:]:
                    if function >= end:
                        break
                    entry = symbols.functions[function]
                    size = min(entry.size, end - function)
                    # the assembler resolves a call within its section to a local symbol, and to the calling
                    # function's own start (a recursion: clang never leaves a relocation for it)
                    relocs, cleared = image.code(function, size, lambda target, function=function: local(target)
                                                 is not None and target in symbols.functions and (
                                                     (image.machine is AARCH64 and target == function) or
                                                     _internal(symbols.functions[target],
                                                                                     symbols.functions[target].name)))
                    for site, word in cleared.items():
                        struct.pack_into(o + "I", blob, local(site), word)
                    found += relocs
        elif not nobits:
            width = "Q" if machine.pointer == 8 else "I"
            for start, end, _ in placed:
                for slot, pointee, evidence in image.pointers(start, end):
                    struct.pack_into(o + width, blob, local(slot), 0)  # the addend lives in the relocation
                    found.append((slot, machine.absolute, pointee, False))
                    cut.pointers[evidence] += 1
                    if evidence == "inside function":
                        cut.boundaries.append(slot)
        cut.found[section_name] = found
        cut.sections.append([section_name, kind, used if nobits else blob, alignment])
    return cut


def write_unit(image: Image, cut: Cut, path: Path, plan: Plan | None = None) -> dict[str, Any]:
    """The object of a cut unit; what it defines, what it references, and referenced addresses no range covers."""
    symbols = image.symbols
    names = plan.names if plan else {}
    landing = {address: name for name, address in plan.linker.items() if address is not None} if plan else {}
    rows: list[dict] = []
    index_by_name: dict[str, int] = {}
    references: dict[str, int] = collections.Counter()

    def symbol_index(name: str) -> int:
        if name not in index_by_name:
            index_by_name[name] = len(rows)
            rows.append({"name": name, "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
                         "address": 0})
        return index_by_name[name]
    relocations = collections.defaultdict(list)
    blobs = {n: bytearray(b) for n, _, b, _ in cut.sections if not isinstance(b, int)}
    for section_name, found in cut.found.items():
        for offset, kind, target, got in found:
            if target in landing:
                name, addend = landing[target], 0
            else:
                name, addend = symbols.resolve(target, kind)
                if plan and target - addend in plan.fixed:   # the original's bytes stay, unrelocated
                    word = offset & ~3
                    at = cut.offset(section_name, word)
                    blobs[section_name][at:at + 4] = image.read(word, 4)
                    continue
                name = names.get(target - addend, name)
            if got:
                addend = 0
            references[name] += 1
            relocations[section_name].append((cut.offset(section_name, offset), kind, symbol_index(name), addend))
    defined = 0
    for entry, section_name, value in cut.entries(symbols):
        if plan and entry.name in plan.linker:
            continue
        bind = "weak" if entry.scope == "weak" else "global" if entry.address in names else (
            "local" if internal_linkage(entry.name, entry.scope) else "global")
        rows[symbol_index(names.get(entry.address, entry.name))].update(
            section=section_name, value=value, size=entry.size, kind="func" if entry.address in symbols.functions
            else "object", bind=bind, address=image.original(entry.address))
        defined += 1
    key = lambda value: value - image.base if image.base and value >= image.base else value
    labels = {name: key(int(name[4:], 16)) for name in references if name.startswith("lbl_")}
    labels.update(plan.labels if plan else {})
    unassigned = []
    for name, address in labels.items():  # labels inside this unit are defined here; others belong to a unit or none
        row = rows[symbol_index(name)]
        if row["section"] is not None:
            continue
        placed_at = cut.where(address)
        if placed_at is not None:
            shared = address in names or (plan is not None and name in plan.labels)
            row.update(section=placed_at[0], value=placed_at[1], kind="object", bind="global" if shared else "local",
                       address=image.original(address))
        else:
            unassigned.append(address)
    for section_name in (plan.fill if plan else ()):
        rows += _fill(image, cut, section_name, rows)
    alignment = plan.alignment if plan else {}
    sections = [(n, k, b if isinstance(b, int) else bytes(blobs[n]), alignment.get(n, a)) for n, k, b, a in cut.sections]
    starts = {n: image.original(min(start for start, _, offset in placed if offset == 0))
              for n, placed in cut.placed.items() if any(offset == 0 for _, _, offset in placed)}
    write_object(image.machine, sections, rows, relocations, path, source=cut.unit.name.rsplit("/", 1)[-1],
                 comment=plan.comment if plan else None, starts=starts)
    return {"unit": cut.unit.name, "object": str(path), "defined": defined,
            "undefined": sum(1 for s in rows if s["section"] is None),
            "labels": sum(1 for s in rows if s["name"].startswith("lbl_")),
            "relocations": sum(len(v) for v in relocations.values()), "pointers": dict(cut.pointers),
            "pointers_inside_functions": [image.text(a) for a in cut.boundaries[:20]], "unassigned_addresses": unassigned}


def _fill(image: Image, cut: Cut, section_name: str, rows: list[dict]) -> list[dict]:
    """Local symbols `fill_<address>` over every run of a section no symbol covers: mwld copies a section symbol by
    symbol, so bytes outside every symbol (padding after a unit's last function, unnamed data) would vanish."""
    if section_name not in cut.placed:
        return []
    size = next(s[2] if s[1] == SHT_NOBITS else len(s[2]) for s in cut.sections if s[0] == section_name)
    spans = sorted((r["value"], r["value"] + r["size"]) for r in rows if r["section"] == section_name and r["size"])
    code = bool(section_traits(image.machine, section_name)[1] & SHF_EXECINSTR)
    out, cursor = [], 0
    for start, end in spans + [(size, size)]:
        if start > cursor:
            address = next(s + cursor - o for s, e, o in cut.placed[section_name] if o <= cursor < o + e - s)
            out.append({"name": f"fill_{image.text(address)}", "section": section_name, "value": cursor,
                        "size": start - cursor, "kind": "func" if code else "object", "bind": "local",
                        "address": image.original(address)})
        cursor = max(cursor, end)
    return out


def delink_unit(image: Image, unit: Unit, path: Path) -> dict[str, Any]:
    """One unit's object; what it defines, what it references, and referenced addresses no range covers."""
    return write_unit(image, cut_unit(image, unit), path)


def delink(project: Project, target: str, splits: Path, out_dir: Path, objdiff: Path | None = None,
           compiled: Path | None = None, only: set[str] | None = None) -> dict[str, Any]:
    """Write one object per unit of `splits` (or of `only`) into out_dir; report what each holds and what stayed
    outside every unit.

    With `objdiff`, also write objdiff's project file pairing each object with the compiled one of the same unit
    under `compiled` (unit a/b.cpp: compiled/a/b.o)."""
    image = _image(project, target)
    units = read_units(splits, image.base, image.place)
    assigned = sorted((start, end) for unit in units for ranges in unit.ranges.values() for start, end in ranges)
    starts = [a[0] for a in assigned]

    def in_some_unit(address: int) -> bool:
        index = bisect.bisect_right(starts, address) - 1
        return index >= 0 and assigned[index][0] <= address < assigned[index][1]
    report, outside = [], set()
    for unit in units:
        if only is not None and unit.name not in only and unit.name.rsplit(".", 1)[0] not in only:
            continue
        row = delink_unit(image, unit, out_dir / f"{unit.name.rsplit('.', 1)[0]}.o")
        unassigned = [a for a in row.pop("unassigned_addresses") if not in_some_unit(a) and image.in_image(a)]
        if unassigned:
            row["unassigned"] = [image.text(a) for a in sorted(unassigned)[:20]]
        outside.update(unassigned)
        report.append(row)
    if objdiff is not None:
        write_objdiff(objdiff, report, compiled or out_dir.parent / "build")
    return {"target": target, "units": report, "out": str(out_dir),
            "unassigned": len(outside),  # referenced addresses no unit's ranges cover: extend the splits
            **({"unassigned_examples": [image.text(a) for a in sorted(outside)[:20]]} if outside else {})}
