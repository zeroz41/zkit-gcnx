"""Link: put a GameCube executable back together with the project's own CodeWarrior linker (mwld), and prove it:
the DOL written from the linked ELF must equal the original byte for byte.

Each unit becomes one object, from one of three places: the original, delinked (delink.py); the project's compiled
object, for a unit the report proves complete; or both at once, for a unit only partly matched: the original
unit's layout with each function the report proves exact taken from the compiled object, its code and its
relocations. So "linked" follows "matched" function by function instead of waiting for whole units.

mwld lays out each output section from the objects in command-line order, symbol by symbol (bytes no symbol
covers vanish, so every byte of a delinked section gets one), each section at its own alignment. So the objects
must tile every section in address order: the splits' units, plus one unit per gap that alignment padding cannot
produce (non-zero bytes, a symbol, or more zeros than an alignment leaves), minus what the linker writes itself
(`_rom_copy_info` and `_bss_init_info` ending .init, `_eti_init_info` ending extabindex, the zero word ending
.ctors and .dtors). One link order must agree with every section's address order, and each delinked section's
alignment is the smallest that lands it on its original address after the object before it.
"""

from __future__ import annotations

import bisect
import collections
import hashlib
import heapq
import json
import os
import re
import shlex
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import delink
from .elf import SHT_NOBITS, Elf
from .project import Project

# What mwld writes itself: tables at the end of .init and extabindex, and names it defines (section bounds come
# from each section's name: _f_text, _e_text, _f_text_rom).
LINKER_OBJECTS = ("_rom_copy_info", "_bss_init_info", "_eti_init_info")
LINKER_NAMES = frozenset({*LINKER_OBJECTS, "_ctors", "_dtors", "_SDA_BASE_", "_SDA2_BASE_", "_ABS_SDA_BASE_",
                          "_ABS_SDA2_BASE_", "_stack_addr", "_stack_end", "_db_stack_addr", "_db_stack_end",
                          "__ArenaLo", "__ArenaHi", "_heap_addr", "_heap_end", "_nbfunctions", "SIZEOF_HEADERS"})
TABLE_SECTIONS = (".ctors", ".dtors")   # pointer tables the linker ends with a zero word
# mwld puts the .ctors and .dtors of the archive member of this name first (the C++ runtime's entries): the unit
# whose entries lead those tables is linked as that member, where it is in the link order (a CodeWarrior link map:
# __init_cpp_exceptions.cpp is the 372nd object in .text and the first in .ctors and .dtors).
RUNTIME_MEMBER = "__init_cpp_exceptions.o"
DOL_ALIGN = 32                          # a DOL section's size is a multiple of 32 bytes
ARENA_HI = 0x81700000                   # the arena's top in the SDK's linker script


@dataclass(frozen=True)
class OutputSection:
    name: str
    start: int
    end: int       # where the next section starts (or the zero-initialized memory ends)
    kind: str      # code, data or bss
    content: int   # where the units end and the linker's own tables (or table terminator) begin
    tables: int    # where those end


def output_sections(program, symbols: delink.Symbols) -> list[OutputSection]:
    """The original's sections in address order, each with the part units fill and the part mwld writes."""
    by_name = {e.name: e for e in symbols.entries}
    out = []
    for name, start, end in program.sections:
        kind, flags, _, _ = delink.section_traits(delink.PPC, name)
        role = "code" if flags & delink.SHF_EXECINSTR else "bss" if kind == SHT_NOBITS else "data"
        tables = [by_name[n] for n in LINKER_OBJECTS if n in by_name and start <= by_name[n].address < end]
        if tables:
            content = min(t.address for t in tables)
            finish = max(t.address + t.size for t in tables)
        elif name in TABLE_SECTIONS:
            words = struct.unpack(f">{(end - start) // 4}I", program.read(start, end - start))
            content = start + 4 * next((i + 1 for i in range(len(words) - 1, -1, -1) if words[i]), 0)
            finish = content + 4
        else:
            content = finish = end
        out.append(OutputSection(name, start, end, role, content, finish))
    return out


# Units in link order

def _padding(start: int, end: int, limit: int = DOL_ALIGN) -> int | None:
    """The alignment that pads [start, end) with zeros: a power of two dividing `end`, above the gap, at most `limit`."""
    if start == end:
        return 1
    align = 1 << (end - start).bit_length()
    return align if align <= limit and end % align == 0 else None


def link_units(units: list[delink.Unit], sections: list[OutputSection], read,
               symbols: delink.Symbols) -> list[delink.Unit]:
    """The splits' units cut back to what units hold (never the linker's tables), plus a unit `gap_<section>_<addr>`
    for each gap that is not padding an alignment produces (padding: zeros, no symbol there, and an alignment of at
    most 32 reaches the next start), so that the objects tile every section. A gap ending a section stops where its
    data and symbols do when padding can take it from there: those zeros are the DOL's padding, not data (the
    linker's table of sections records each one's true size); inside a section a gap runs to the next unit, whose
    compiled object may align less than the gap needs."""
    out = [delink.Unit(u.name, renames=dict(u.renames)) for u in units]
    for section in sections:
        rows = sorted((start, min(end, section.content), unit) for source, unit in zip(units, out)
                      for start, end in source.ranges.get(section.name, []) if start < section.content)
        cursor = section.start
        for start, end, unit in rows + [(section.content, section.content, None)]:
            if start < cursor:
                raise ValueError(f"{unit.name if unit else section.name}: {section.name} {start:#x} overlaps the unit "
                                 f"before it (which ends at {cursor:#x})")
            if start > cursor:
                data = b"" if section.kind == "bss" else read(cursor, start - cursor)
                inside = symbols.entries[bisect.bisect_left(symbols.starts, cursor):
                                         bisect.bisect_left(symbols.starts, start)]
                used = max([cursor + len(data.rstrip(b"\0"))] + [e.address + max(e.size, 1) for e in inside])
                if used > cursor or section is sections[-1] or _padding(cursor, start) is None:
                    stop = start if unit is not None or section is sections[-1] else next(
                        e for e in range(min(used, start), start + 1) if _padding(e, start) is not None)
                    gap = delink.Unit(f"gap_{section.name.lstrip('.')}_{cursor:08X}")
                    gap.ranges[section.name].append((cursor, stop))
                    out.append(gap)
            if unit is not None:
                unit.ranges[section.name].append((start, end))
                cursor = end
    return [u for u in out if u.ranges]


def link_order(units: list[delink.Unit], sections: list[OutputSection]) -> list[delink.Unit]:
    """An order of the units every section's address order agrees with (the splits' order where free to choose).

    The runtime's entry first in .ctors and .dtors (`__init_cpp_exceptions_reference`,
    `__destroy_global_chain_reference`) is not bound to its unit's place: mwld puts it first itself."""
    index = {id(u): i for i, u in enumerate(units)}
    successors: dict[int, set[int]] = collections.defaultdict(set)
    waiting = collections.Counter()
    key = {i: (i, 0) for i in range(len(units))}
    for section in sections:
        rows = sorted((start, index[id(u)]) for u in units for start, _ in u.ranges.get(section.name, []))
        if section.name in TABLE_SECTIONS and rows and rows[0][0] == section.start:
            rows = rows[1:]
        for (_, a), (_, b) in zip(rows, rows[1:]):
            if a != b and b not in successors[a]:
                successors[a].add(b)
                waiting[b] += 1
                if units[b].name.startswith("gap_"):
                    key[b] = min(key[b], (key[a][0], 1))
    ready = [(key[i], i) for i in range(len(units)) if not waiting[i]]
    heapq.heapify(ready)
    order = []
    while ready:
        _, i = heapq.heappop(ready)
        order.append(units[i])
        for j in successors[i]:
            waiting[j] -= 1
            if not waiting[j]:
                heapq.heappush(ready, (key[j], j))
    if len(order) < len(units):
        stuck = sorted(u.name for i, u in enumerate(units) if waiting[i])[:6]
        raise ValueError(f"No link order agrees with every section's address order; units in a cycle: {stuck}")
    return order


# The linker script and the DOL

def linker_script(sections: list[tuple[str, int]], origin: int, stack: int, force_active: list[str],
                  arena_hi: int = ARENA_HI) -> str:
    """mwld's script: the sections in order in one group from the origin (each `ALIGN`ed), the SDK's stack and
    arena symbols after the last section, and the names it must keep however unreferenced."""
    last = sections[-1][0]
    body = "\n".join(f"        {name} ALIGN({align:#x}):{{}}" for name, align in sections)
    keep = "\n".join(f"    {name}" for name in force_active)
    return (f"MEMORY\n{{\n    text : origin = {origin:#x}\n}}\n\nSECTIONS\n{{\n    GROUP:\n    {{\n{body}\n"
            f"        .stack ALIGN(0x100):{{}}\n    }} > text\n\n"
            f"    _stack_end = _f_{last.lstrip('.')} + SIZEOF({last});\n"
            f"    _stack_addr = (_stack_end + {stack:#x} + 0x7) & ~0x7;\n"
            "    _db_stack_addr = (_stack_addr + 0x2000);\n    _db_stack_end = _stack_addr;\n"
            "    __ArenaLo = (_db_stack_addr + 0x1f) & ~0x1f;\n"
            f"    __ArenaHi = {arena_hi:#x};\n}}\n\nFORCEACTIVE\n{{\n{keep}\n}}\n")


def dol_from_elf(elf: Elf) -> bytes:
    """A DOL from a linked ELF: its loaded sections in section order, code into the 7 text slots and the rest into
    the 11 data slots, each padded to 32 bytes; the zero-initialized range from the first such section to the end
    of the last; the ELF's entry point."""
    text, data, bss = [], [], []
    for section in elf.sections:
        if not section.flags & delink.SHF_ALLOC or not section.size:
            continue
        if section.type == SHT_NOBITS:
            bss.append(section)
        else:
            (text if section.flags & delink.SHF_EXECINSTR else data).append(section)
    if len(text) > 7 or len(data) > 11:
        raise ValueError(f"A DOL holds 7 code and 11 data sections; the ELF has {len(text)} and {len(data)}")
    header = bytearray(0x100)
    body = bytearray()
    for slot, section in [(i, s) for i, s in enumerate(text)] + [(7 + i, s) for i, s in enumerate(data)]:
        size = -(-section.size // DOL_ALIGN) * DOL_ALIGN
        struct.pack_into(">I", header, slot * 4, 0x100 + len(body))
        struct.pack_into(">I", header, 0x48 + slot * 4, section.address)
        struct.pack_into(">I", header, 0x90 + slot * 4, size)
        body += elf.data(section) + bytes(size - section.size)
    if bss:
        struct.pack_into(">II", header, 0xD8, bss[0].address, bss[-1].address + bss[-1].size - bss[0].address)
    struct.pack_into(">I", header, 0xE0, elf.entry)
    return bytes(header + body)


def first_difference(ours: bytes, original: bytes) -> tuple[int, int] | None:
    """(file offset, address) of the first byte where two DOLs differ (address 0 inside the header)."""
    if ours == original:
        return None
    offset = next((i for i, (a, b) in enumerate(zip(ours, original)) if a != b), min(len(ours), len(original)))
    if offset < 0x100:
        return offset, 0
    for slot in range(18):
        start, address, size = (struct.unpack_from(">I", original, base + slot * 4)[0] for base in (0, 0x48, 0x90))
        if size and start <= offset < start + size:
            return offset, address + offset - start
    return offset, 0


# The project's linker, as its build runs it

def _ninja(path: Path) -> tuple[dict[str, str], dict[str, dict[str, str]], list[tuple[list[str], str, dict]]]:
    """(file variables, rules, build edges as (outputs, rule, variables)) of a build.ninja, line continuations
    joined (enough of ninja's grammar to read a link command; no includes)."""
    text = re.sub(r"\$\n\s*", "", path.read_text(encoding="utf-8", errors="replace"))
    variables, rules, edges = {}, {}, []
    scope = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace() and scope is not None:
            name, _, value = line.strip().partition("=")
            scope[name.strip()] = value.strip()
            continue
        if line.startswith("rule "):
            scope = rules.setdefault(line[5:].strip(), {})
        elif line.startswith("build "):
            outputs, _, rest = line[6:].partition(":")
            scope = {}
            edges.append((outputs.split(), rest.split()[0] if rest.split() else "", scope))
        else:
            scope = None
            name, equals, value = line.partition("=")
            if equals:
                variables[name.strip()] = _expand(value.strip(), variables)
    return variables, rules, edges


def _expand(text: str, *scopes: dict[str, str]) -> str:
    def value(match: re.Match) -> str:
        name = match[1] or match[2]
        if name is None:
            return match[0][1:]
        return next((scope[name] for scope in scopes if name in scope), "")
    return re.sub(r"\$(?:\{(\w+)\}|(\w+)|[$ :])", value, text)


def linker_command(root: Path, build: Path, module: str) -> list[str]:
    """The argv the project's build links `module` with (rule `link`'s command for the edge writing <module>.elf),
    without its script, output and inputs: tools resolved under the repository root."""
    variables, rules, edges = _ninja(build)
    edge = next((e for e in edges if e[1] in rules and any(Path(o).name == f"{module}.elf" for o in e[0])), None)
    if edge is None:
        raise ValueError(f"{build} has no edge linking {module}.elf")
    _, rule, own = edge
    scope = {k: _expand(v, variables) for k, v in own.items()}
    command = _expand(rules[rule]["command"], {"out": "\0out", "in": "\0in"}, scope, variables)
    argv, skip = [], False
    for word in shlex.split(command):
        if skip:
            skip = False
        elif word in ("-lcf", "-o"):
            skip = True
        elif "\0" not in word:
            argv.append(str(root / word) if not os.path.isabs(word) and (root / word).exists() else word)
    return argv


def _runtime_member(units: list[delink.Unit], sections: list[OutputSection]) -> list[delink.Unit]:
    """The units with the entries leading .ctors and .dtors (the C++ runtime's, linked late but first in those
    tables) moved out of their unit into a unit of their own, linked as the archive member mwld puts first. A range
    named `.ctors$10` (`rename:`, the later runtime's way) stays: the linker sorts that by its name."""
    leading = {}
    for section in (s for s in sections if s.name in TABLE_SECTIONS):
        for unit in units:
            for start, end in unit.ranges.get(section.name, []):
                if start == section.start and (section.name, start) not in unit.renames:
                    leading[section.name] = (unit, (start, end))
    owners = {id(unit) for unit, _ in leading.values()}
    if not leading or id(units[0]) in owners:     # already first in link order: nothing to move
        return units
    member = delink.Unit(RUNTIME_MEMBER)
    for name, (unit, span) in leading.items():
        unit.ranges[name].remove(span)
        if not unit.ranges[name]:
            del unit.ranges[name]
        member.ranges[name].append(span)
    return [u for u in units if u.ranges] + [member]


def _globals(path: Path) -> set[str]:
    return {s.name for s in Elf.load(path).symbols if 0 < s.section < 0xFF00 and s.bind != "local" and s.name}


def write_archive(path: Path, members: list[Path], names: list[str]) -> Path:
    """A System V archive mwld reads: a symbol index (`/`) of every global each member defines, the long member
    names (`//`), then the members, each named as given."""
    datas = [m.read_bytes() for m in members]
    defined = [[s.name for s in Elf.load(m).symbols if 0 < s.section < 0xFF00 and s.bind != "local" and s.name]
               for m in members]
    longnames = b"".join(f"{n}/\n".encode() for n in names)
    header = lambda name, size: f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{size:<10}`\n".encode()
    pad = lambda blob: blob + (b"\n" if len(blob) % 2 else b"")
    count = sum(len(d) for d in defined)
    table_size = 4 + 4 * count + sum(len(n) + 1 for d in defined for n in d)
    cursor = 8 + 60 + len(pad(b"\0" * table_size)) + 60 + len(pad(longnames))
    offsets, name_at, at = [], [], 0
    for data, name in zip(datas, names):
        offsets.append(cursor)
        name_at.append(at)
        at += len(name) + 2
        cursor += 60 + len(pad(data))
    table = struct.pack(">I", count) + b"".join(struct.pack(">I", offsets[i]) for i, d in enumerate(defined)
                                                for _ in d)
    table += b"".join(n.encode() + b"\0" for d in defined for n in d)
    blob = b"!<arch>\n" + header("/", len(table)) + pad(table) + header("//", len(longnames)) + pad(longnames)
    for data, at in zip(datas, name_at):
        blob += header(f"/{at}", len(data)) + pad(data)
    path.write_bytes(blob)
    return path


def run_linker(argv: list[str], lcf: Path, objects: list[Path], out: Path) -> subprocess.CompletedProcess:
    """Link `objects` (in order) under `lcf` into `out`, running in out's folder with a response file."""
    folder = out.parent
    rsp = out.with_suffix(".rsp")
    rsp.write_text("".join(os.path.relpath(p, folder) + "\n" for p in objects), encoding="utf-8")
    return subprocess.run([*argv, "-lcf", os.path.relpath(lcf, folder), "-o", out.name, f"@{rsp.name}"],
                          cwd=folder, capture_output=True, text=True, timeout=600)


# Names across objects

def _owner_of(units: list[delink.Unit]):
    spans = sorted((start, end, unit) for unit in units for ranges in unit.ranges.values() for start, end in ranges)
    starts = [s[0] for s in spans]

    def owner(address: int) -> delink.Unit | None:
        i = bisect.bisect_right(starts, address) - 1
        return spans[i][2] if i >= 0 and address < spans[i][1] else None
    return owner


def shared_names(cuts: dict[str, delink.Cut], units: list[delink.Unit], symbols: delink.Symbols,
                 wanted: dict[str, set[str]], exports: dict[str, set[str]],
                 landing: set[int]) -> tuple[dict[int, str], dict[str, dict[str, int]], set[int]]:
    """(global name of every address an object reaches in another delinked unit, {unit: {label: address}} of names a
    unit must define for others, addresses no object can name), from the delinked references and the names
    compiled code asks for (`wanted`: unit -> names).

    A local symbol others reach turns global as `<name>_<address>` (the spelling decomp sources already use for
    such names, and unique), unless compiled code asks for it by another spelling. A compiled unit is reached by the
    names its object exports (`exports`: unit -> names), either spelling; what it keeps local cannot be named, so
    references to it keep the original's bytes. Addresses the linker names (`landing`) are its own."""
    owner = _owner_of(units)
    by_name = {e.name: e for e in symbols.entries}
    reached: dict[int, str] = {}
    asked: set[int] = set()
    unnamed: set[int] = set()
    labels: dict[str, dict[str, int]] = collections.defaultdict(dict)
    for name, cut in cuts.items():
        for found in cut.found.values():
            for _, _, target, _ in found:
                if target in landing:
                    continue
                symbol, addend = symbols.resolve(target)
                home = owner(target - addend)
                if home is None or home.name == name:
                    continue
                if home.name in exports:
                    spelled = f"{symbol}_{target - addend:08X}"
                    if symbol not in exports[home.name] and spelled in exports[home.name]:
                        reached[target - addend] = spelled
                        asked.add(target - addend)
                    elif symbol not in exports[home.name]:
                        unnamed.add(target - addend)
                    continue
                reached[target - addend] = symbol
    for unit, names in wanted.items():
        for symbol in names:
            entry = by_name.get(symbol)
            spelled = re.fullmatch(r"(.+)_([0-9A-F]{8})", symbol)
            if entry is None and spelled and getattr(symbols.by_address.get(int(spelled[2], 16)), "name", None) == \
                    spelled[1]:
                entry = symbols.by_address[int(spelled[2], 16)]
            address = entry.address if entry is not None else \
                int(symbol[4:], 16) if re.fullmatch(r"lbl_[0-9A-F]{8}", symbol) else None
            home = owner(address) if address is not None else None
            if home is None or home.name == unit or home.name in exports:
                continue
            if entry is not None:
                reached[address] = symbol
                asked.add(address)
            else:
                labels[home.name][symbol] = address
    names = {}
    for address, symbol in reached.items():
        entry = symbols.by_address.get(address)
        local = entry is not None and entry.name == symbol and delink.internal_linkage(entry.name, entry.scope)
        renamed = local and address not in asked and not symbol.endswith(f"{address:08X}")
        names[address] = f"{symbol}_{address:08X}" if renamed else symbol
        if symbol.startswith("lbl_") and entry is None:
            labels[owner(address).name][names[address]] = address
    return names, labels, unnamed


# Alignment

def _reach(cursor: int, start: int, usual: int) -> int | None:
    """The smallest alignment from `usual` (halved until it divides `start`) up that brings `cursor` to `start`."""
    align = usual
    while start % align:
        align //= 2
    while -(-cursor // align) * align != start:
        align *= 2
        if start % align or align > 1 << 16:
            return None
    return align


def alignments(order: list[delink.Unit], sections: list[OutputSection], sizes: dict[tuple[str, str], int],
               fixed: dict[tuple[str, str], int]) -> tuple[dict[str, dict[str, int]], list[tuple[str, int]], list[str]]:
    """({unit: {section: alignment}} for the objects zkit writes, [(section, ALIGN)] for the script, problems).

    `sizes` holds each object's section size, `fixed` the alignment of compiled sections (mwld places those at
    their own). Every other section, and every output section, gets the smallest alignment that lands it on its
    original start after what precedes it (the section's usual alignment when that already does)."""
    out: dict[str, dict[str, int]] = collections.defaultdict(dict)
    script, problems = [], []
    end = sections[0].start
    for section in sections:
        align = _reach(end, section.start, 4)
        if align is None:
            problems.append(f"{section.name} starts at {section.start:#x}, which no alignment reaches from the end of "
                            f"the section before ({end:#x})")
        script.append((section.name, align or 4))
        cursor = section.start
        for start, unit in sorted((s, u) for u in order for s, _ in u.ranges.get(section.name, [])):
            key = (unit.name, section.name)
            if key in fixed:
                placed = -(-cursor // fixed[key]) * fixed[key]
                if placed != start:
                    problems.append(f"{unit.name}: its compiled {section.name} (aligned {fixed[key]}) would land at "
                                    f"{placed:#x}, not {start:#x}")
            else:
                align = _reach(cursor, start, delink.section_traits(delink.PPC, section.name)[3])
                if align is None:
                    problems.append(f"{unit.name}: {section.name} at {start:#x} is out of reach from {cursor:#x}")
                out[unit.name][section.name] = align or 1
            cursor = start + sizes[key]
        end = cursor + section.tables - section.content
    return out, script, problems


# One object from two: the original unit with its exact functions compiled

def _virtual(elf: Elf) -> list[int]:
    """Each symbol's original address, from the object's `.note.split`."""
    note = elf.section(".note.split")
    data, position = (elf.data(note) if note else b""), 0
    while position + 12 <= len(data):
        size, length, kind = struct.unpack_from(">III", data, position)
        position += 12 + size + (-size % 4)
        if kind == int.from_bytes(b"VIRT", "big"):
            return list(struct.unpack_from(f">{length // 4}I", data, position))
        position += length + (-length % 4)
    return []


def combine(delinked: Path, compiled: Path, exact: list[str], out: Path, comment: int | None,
            address_of: dict[str, int], linkable: set[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Write `out`: the delinked unit with the code and relocations of each `exact` function taken from the compiled
    object. A relocation to a global name keeps the name (it must be one the link defines and reach the address the
    original does); one to a compiled local (a static, a pooled constant) is where the original relocates the same
    field, so it takes the original's target. Returns (functions taken, [(function, why it stayed delinked)])."""
    d, c = Elf.load(delinked), Elf.load(compiled)
    virtual = _virtual(d)
    content = [s for s in d.sections if s.flags & delink.SHF_ALLOC]
    data = {s.index: bytearray(d.data(s)) for s in content if s.type != SHT_NOBITS}
    rows, row_of = [], {}
    for symbol in d.symbols[1:]:
        if symbol.kind in ("file", "section"):
            continue
        row_of[symbol.index] = len(rows)
        defined = 0 < symbol.section < 0xFF00
        rows.append({"name": symbol.name, "section": d.sections[symbol.section].name if defined else None,
                     "value": symbol.value, "size": symbol.size, "kind": symbol.kind if defined else "notype",
                     "bind": symbol.bind, "address": virtual[symbol.index] if symbol.index < len(virtual) else 0})
    by_name = {row["name"]: i for i, row in enumerate(rows)}
    relocations = {s.index: [(r.offset, r.type, row_of[r.symbol], r.addend) for r in d.relocations(s)]
                   for s in content}
    where = lambda row: rows[row]["address"] if rows[row]["section"] else address_of.get(rows[row]["name"])
    ours, theirs = d.functions(), c.functions()
    taken, kept = [], []
    for name in exact:
        mine, compiled_function = ours.get(name), theirs.get(name)
        if mine is None or compiled_function is None:
            kept.append((name, "not defined in both objects"))
            continue
        section, source = d.sections[mine.section], c.sections[compiled_function.section]
        if mine.size != compiled_function.size or section.name != source.name:
            kept.append((name, f"compiled as {compiled_function.size:#x} bytes in {source.name}"))
            continue
        lo, hi, shift = mine.value, mine.value + mine.size, mine.value - compiled_function.value
        # by the instruction word: MWCC puts a small-data relocation on the half-word, the delinker on the word
        original = {r[0] & ~3: r for r in relocations[section.index] if lo <= r[0] < hi}
        mapped, why = [], None
        for reloc in c.relocations(source):
            if not compiled_function.value <= reloc.offset < compiled_function.value + mine.size:
                continue
            at, target = reloc.offset + shift, c.symbols[reloc.symbol]
            theirs_at = original.get(at & ~3)
            if target.bind != "local" and target.name and target.kind != "section":
                reached = address_of.get(target.name)
                if target.name not in linkable:
                    why = f"refers to {target.name}, which nothing in the link defines"
                elif theirs_at is not None and where(theirs_at[2]) is not None and reached is not None and \
                        where(theirs_at[2]) + theirs_at[3] != reached + reloc.addend:
                    why = f"reaches {target.name}+{reloc.addend:#x}, where the original reaches another address"
                else:
                    if target.name not in by_name:
                        by_name[target.name] = len(rows)
                        rows.append({"name": target.name, "section": None, "value": 0, "size": 0, "kind": "notype",
                                     "bind": "global", "address": 0})
                    mapped.append((at, reloc.type, by_name[target.name], reloc.addend))
            elif theirs_at is not None and theirs_at[1] == reloc.type:
                mapped.append((at, reloc.type, theirs_at[2], theirs_at[3]))
            else:
                why = f"its local reference at +{at - lo:#x} has no matching original relocation"
            if why:
                break
        if why:
            kept.append((name, why))
            continue
        data[section.index][lo:hi] = c.data(source)[compiled_function.value:compiled_function.value + mine.size]
        relocations[section.index] = [r for r in relocations[section.index] if not lo <= r[0] < hi] + mapped
        taken.append(name)
    sections = [(s.name, s.type, bytes(data[s.index]) if s.type != SHT_NOBITS else s.size, s.align) for s in content]
    source_name = next((s.name for s in d.symbols if s.kind == "file"), None)
    delink.write_object(delink.PPC, sections, rows, {s.name: relocations[s.index] for s in content}, out,
                        source=source_name, comment=comment)
    return taken, kept


# The whole link

def config_yml(path: Path) -> dict[str, Any]:
    """`mw_comment_version` and the `force_active` list of a config.yml (no YAML dependency)."""
    out: dict[str, Any] = {"force_active": []}
    if not path.is_file():
        return out
    listing = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.match(r"^\S", line):
            key, _, value = line.partition(":")
            listing = key.strip() if key.strip() == "force_active" and not value.strip() else None
            if key.strip() == "mw_comment_version" and value.strip().isdigit():
                out["mw_comment_version"] = int(value.strip())
        elif listing and (match := re.match(r"^\s+-\s*(.+?)\s*$", line)):
            out["force_active"].append(match[1].strip("'\""))
    return out


def stack_address(program) -> int | None:
    """r1 as `__init_registers` sets it (lis/ori or lis/addi): the stack's top, which the script reproduces."""
    start = next((f for f in program.functions if f.name == "__init_registers"), None)
    if start is None and hasattr(program.image, "entry"):   # not named yet: the entry point's register setup
        from .discover import small_data_bases
        found = small_data_bases(program.image)[1]
        index = program.function_index.get(found) if found is not None else None
        start = program.functions[index] if index is not None else None
    if start is None:
        return None
    value = None
    for word in program.image.words(start.address, start.size):   # some runtimes clear every register first
        op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 15 and rd == 1 and ra == 0:
            value = imm << 16
        elif value is not None and op == 24 and rd == 1 and ra == 1:
            return value | imm
        elif value is not None and op == 14 and rd == 1 and ra == 1:
            return (value + (imm - 0x10000 if imm & 0x8000 else imm)) & 0xFFFFFFFF
    return None


def compiled_units(project: Project, target: str, units: list[delink.Unit]) -> tuple[dict[str, dict], dict]:
    """({unit: {object, complete, exact, sizes, code}} for the units the project compiles, the report's measures):
    the object objdiff compares (`base_path`), whether the report proves the whole unit, the functions it proves
    exact and their sizes, the unit's code size."""
    from .objects import objdiff_units
    config = project.target(target)
    module, repository = config.get("module", ""), config["repository"]
    paired = objdiff_units(project, target)
    report = json.loads(project.file(repository, config["report"]).read_text(encoding="utf-8")) \
        if config.get("report") else {"units": []}
    rows = {u["name"]: u for u in report.get("units", [])}
    out = {}
    for unit in units:
        stem = unit.name.rsplit(".", 1)[0]
        name = next((n for n in (f"{module}/{stem}", stem) if n in paired), None)
        base = paired[name].get("base_path") if name else None
        if not base or not project.file(repository, base).is_file():
            continue
        row = rows.get(name, {})
        out[unit.name] = {"object": project.file(repository, base),
                          "complete": bool(row.get("metadata", {}).get("complete")) or _proven(row.get("measures", {})),
                          "exact": [f["name"] for f in row.get("functions", []) if f.get("fuzzy_match_percent") == 100],
                          "sizes": {f["name"]: int(f.get("size", 0)) for f in row.get("functions", [])},
                          "code": int(row.get("measures", {}).get("total_code", 0))}
    return out, report.get("measures", {})


def _proven(measures: dict) -> bool:
    """The report proves the whole unit: every byte of its code and of its data matches (a unit no decomp has
    marked complete yet, as in a project `zkit new` started)."""
    code, data = int(measures.get("total_code", 0) or 0), int(measures.get("total_data", 0) or 0)
    return code + data > 0 and int(measures.get("matched_code", 0) or 0) == code and \
        int(measures.get("matched_data", 0) or 0) == data


def _placement_align(elf: Elf, section) -> int:
    """The alignment mwld places a compiled section at: its own, or its first symbol's from the `.comment` (the
    linker lays out symbol by symbol)."""
    comment = elf.section(".comment")
    data = elf.data(comment) if comment else b""
    first = min((s for s in elf.symbols if s.section == section.index and s.kind in ("func", "object")),
                key=lambda s: s.value, default=None)
    align = section.align
    if first is not None and first.value == 0 and len(data) >= 0x2C + 8 * (first.index + 1):
        align = max(align, struct.unpack_from(">I", data, 0x2C + 8 * first.index)[0])
    return max(align, 1)


def _wanted(elves: dict[str, Elf], combined: dict[str, dict]) -> dict[str, set[str]]:
    """{unit: names its compiled code refers to}: every undefined name of a compiled object, and the global targets
    of the exact functions a combined unit takes."""
    wanted = {name: {s.name for s in elf.symbols[1:] if s.section == 0 and s.name} for name, elf in elves.items()}
    for name, source in combined.items():
        elf, exact = Elf.load(source["object"]), set(source["exact"])
        functions = [s for s in elf.symbols if s.kind == "func" and s.name in exact and 0 < s.section < 0xFF00]
        wanted[name] = {elf.symbols[r.symbol].name for f in functions for r in elf.relocations(elf.sections[f.section])
                        if f.value <= r.offset < f.value + f.size and elf.symbols[r.symbol].bind != "local"}
    return wanted


def _sizes(units: list[delink.Unit], elves: dict[str, Elf], cuts: dict[str, delink.Cut]) -> tuple[dict, dict, list]:
    """(size of each (unit, section) as mwld lays it out, alignment of each compiled one, problems). A compiled
    section runs to its last symbol, within the unit's range (mwld drops unreferenced symbols past it)."""
    sizes, fixed, problems = {}, {}, []
    for unit in units:
        for section, ranges in unit.ranges.items():
            key = (unit.name, section)
            if unit.name not in elves:                # a renamed range is its own object section
                sizes[key] = sum(s[2] if s[1] == SHT_NOBITS else len(s[2]) for s in cuts[unit.name].sections
                                 if s[0].split("$", 1)[0] == section)
                continue
            elf = elves[unit.name]
            held = elf.section(section)
            if held is None:
                problems.append(f"{unit.name}: the compiled object has no {section}")
                sizes[key], fixed[key] = 0, 1
                continue
            extent = held.size if section in TABLE_SECTIONS else max(
                (s.value + s.size for s in elf.symbols if s.section == held.index and s.kind in ("func", "object")),
                default=0)
            sizes[key], fixed[key] = min(extent, ranges[-1][1] - ranges[0][0]), _placement_align(elf, held)
    return sizes, fixed, problems


def _force_active(listed: list[str], sections: list[OutputSection], program, symbols: delink.Symbols) -> list[str]:
    """The names mwld must keep however unreferenced: the project's list, and every function .ctors and .dtors
    point at (nothing else refers to a static initializer)."""
    keep = list(listed)
    for section in (s for s in sections if s.name in TABLE_SECTIONS):
        size = section.content - section.start
        for word in struct.unpack(f">{size // 4}I", program.read(section.start, size)):
            if word in symbols.functions and symbols.functions[word].name not in keep:
                keep.append(symbols.functions[word].name)
    return keep


def _difference(dol: bytes, original: bytes, units: list[delink.Unit], symbols: delink.Symbols) -> dict | None:
    """Where the first differing byte is: file offset, address, unit, symbol, and 8 bytes of each."""
    found = first_difference(dol, original)
    if found is None:
        return None
    offset, address = found
    unit = _owner_of(units)(address) if address else None
    holder = symbols.containing(address) if address else None
    return {"offset": offset, "address": address, "unit": unit.name if unit else None,
            "symbol": f"{holder.name}+{address - holder.address:#x}" if holder else None,
            "ours": dol[offset:offset + 8].hex(), "original": original[offset:offset + 8].hex()}


def link(project: Project, target: str, out: Path, compiled: str = "functions", splits: Path | None = None,
         build: Path | None = None) -> dict[str, Any]:
    """Link the target into out/<module>.elf and out/<module>.dol and compare the DOL with the original.

    compiled: "none" (every unit delinked), "units" (the project's compiled object for each unit the report proves
    complete) or "functions" (also each exact function of the other units, in an object combining it with the
    delinked rest)."""
    from .program import Program
    config = project.target(target)
    repository, module = config["repository"], config.get("module") or target
    root = project.root(repository)
    splits = splits or project.file(repository, config["splits"])
    settings = config_yml(splits.parent / "config.yml")
    comment = settings.get("mw_comment_version", 10)
    image = delink._image(project, target)
    if image.machine is not delink.PPC:
        raise ValueError("zkit link builds GameCube executables")
    program = Program.from_project(project, target)
    symbols = image.symbols
    sections = output_sections(program, symbols)
    units = _runtime_member(link_order(link_units(delink.read_units(splits), sections, program.read, symbols),
                                       sections), sections)
    sources, measures = compiled_units(project, target, units) if compiled != "none" else ({}, {})
    elves = {u.name: Elf.load(sources[u.name]["object"]) for u in units
             if u.name in sources and sources[u.name]["complete"]}
    combined = {u.name: sources[u.name] for u in units if compiled == "functions" and u.name in sources and
                u.name not in elves and sources[u.name]["exact"]}
    cuts = {u.name: delink.cut_unit(image, u) for u in units if u.name not in elves}
    exports = {name: {s.name for s in elf.symbols if 0 < s.section < 0xFF00 and s.bind != "local" and s.name}
               for name, elf in elves.items()}
    linker = LINKER_NAMES | {f"_{edge}_{s.name.lstrip('.')}{rom}" for s in sections for edge in ("f", "e")
                             for rom in ("", "_rom")}
    placed = {e.name: e.address for e in [*symbols.entries, *program.labels] if e.name in linker}
    linker = {name: placed.get(name) for name in linker}
    names, labels, unnamed = shared_names(cuts, units, symbols, _wanted(elves, combined), exports,
                                          set(placed.values()))
    sizes, fixed, problems = _sizes(units, elves, cuts)
    align, script, troubles = alignments(units, sections, sizes, fixed)
    problems += troubles
    address_of = {e.name: e.address for e in symbols.entries}
    address_of.update((name, address) for address, name in names.items())
    linkable = set().union(*exports.values()) | set(linker) | {name for d in labels.values() for name in d} | {
        names.get(e.address, e.name) for cut in cuts.values() for e, _, _ in cut.entries(symbols)}
    for defined in labels.values():
        address_of.update(defined)
    objects, functions, kept = [], [], []
    for unit in units:
        if unit.name in elves:
            objects.append(sources[unit.name]["object"])
            continue
        stem = unit.name.rsplit(".", 1)[0]
        path = out / "obj" / f"{stem}.o"
        delink.write_unit(image, cuts[unit.name], path, delink.Plan(
            names, labels.get(unit.name, {}), linker, align.get(unit.name, {}), comment,
            frozenset(unit.ranges) - set(TABLE_SECTIONS), frozenset(unnamed)))
        if unit.name in combined:
            source, path = combined[unit.name], out / "combined" / f"{stem}.o"
            taken, held = combine(out / "obj" / f"{stem}.o", source["object"], source["exact"], path, comment,
                                  address_of, linkable)
            functions += [(unit.name, name, source["sizes"].get(name, 0)) for name in taken]
            kept += [(unit.name, name, why) for name, why in held]
        objects.append(path)
    member = next((i for i, u in enumerate(units) if u.name == RUNTIME_MEMBER), None)
    if member is not None:                             # an archive member of that name, kept by FORCEACTIVE
        objects[member] = write_archive(out / "runtime.a", [objects[member]], [RUNTIME_MEMBER])
    top = stack_address(program)
    lcf = out / "link.lcf"
    keep = _force_active(settings["force_active"], sections, program, symbols)
    if member is not None:
        keep += [n for n in sorted(_globals(objects[member].parent / "obj" / RUNTIME_MEMBER)) if n not in keep]
    lcf.write_text(linker_script(script, sections[0].start, top - sections[-1].end if top else 0x10000, keep),
                   encoding="utf-8")
    elf_path, dol_path = out / f"{module}.elf", out / f"{module}.dol"
    elf_path.unlink(missing_ok=True)
    argv = linker_command(root, build or root / "build.ninja", module)
    if "-m" not in argv:                              # mwld's default entry is `__start`: name the original's own
        entry = program.image.entry
        held = symbols.by_address.get(entry)
        argv += ["-m", names.get(entry) or (held.name if held is not None else "__start")]
    run = run_linker(argv, lcf, objects, elf_path)
    result: dict[str, Any] = {
        "target": target, "compiled": compiled, "objects": len(objects), "out": str(out),
        "units": {"delinked": len(cuts) - len(combined), "compiled": len(elves), "combined": len(combined),
                  "gaps": sum(1 for u in units if u.name.startswith("gap_"))},
        "functions_from_compiled": len(functions),
        "code_from_compiled": sum(sources[n]["code"] for n in elves) + sum(size for *_, size in functions),
        "report": {k: int(measures[k]) for k in ("total_code", "matched_code", "complete_code") if k in measures},
        "unnamed_references": len(unnamed),
        "kept_original": [{"unit": u, "function": f, "why": w} for u, f, w in kept],
        "problems": problems, "linker_output": (run.stdout + run.stderr).strip()[-4000:]}
    if run.returncode or not elf_path.is_file():
        result.update(linked=False, identical=False)
        return result
    dol = dol_from_elf(Elf.load(elf_path))
    dol_path.write_bytes(dol)
    original = program.image.raw
    result.update(linked=True, dol=str(dol_path), sha1=hashlib.sha1(dol).hexdigest(),
                  original_sha1=hashlib.sha1(original).hexdigest(), identical=dol == original)
    difference = _difference(dol, original, units, symbols)
    if difference:
        result["first_difference"] = difference
    if dol == original and config.get("report"):   # the units linked from their compiled objects, in the report
        from .progress import apply_link
        report = project.file(repository, config["report"])
        if report.is_file():
            result["report_updated"] = apply_link(report, [name.rsplit(".", 1)[0] for name in elves])
    return result
