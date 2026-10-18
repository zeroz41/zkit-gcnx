"""Delink: cut the original executable into one relocatable object per unit, as the compiler would have emitted
it, so objdiff can compare each unit with the project's compiled one.

Every reference the code and data make is turned back into a relocation against a symbol: calls and branches
(CALL26/JUMP26), page-relative address pairs (ADRP with ADD or a load/store), GOT loads, literal loads and
64-bit pointers in data. The relocated fields are cleared, as an assembler leaves them. Each object carries
objdiff's `.note.split` with the original address of every symbol. Symbols come from the project's function and
data lists; an address nothing names gets `lbl_<address>`, the same name in every unit that refers to it.

AArch64 (Switch) is implemented; units come from a splits.txt (decomp-toolkit's format).
"""

from __future__ import annotations

import bisect
import collections
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .aarch64 import ABS64, code_relocations
from .project import Project

def section_traits(name: str) -> tuple[int, int, int, int]:
    """(sh_type, sh_flags, sh_entsize, alignment) of an output section, from the name clang gives it: the original
    keeps only segments, so the splits name each range's section (.rodata.str1.1, .data.rel.ro, ...) and objdiff
    pairs sections by that name."""
    alloc, write, execute, merge, strings, tls = 0x2, 0x1, 0x4, 0x10, 0x20, 0x400
    if name.startswith(".text"):
        return 1, alloc | execute, 0, 4
    if name.startswith((".bss", ".tbss")):
        return 8, alloc | write | (tls if name.startswith(".tbss") else 0), 0, 8
    if name.startswith(".tdata"):
        return 1, alloc | write | tls, 0, 8
    if name.startswith((".init_array", ".fini_array")):
        return (14 if name.startswith(".init") else 15), alloc | write, 8, 8
    if name.startswith(".rodata.str"):
        size = int(match[1]) if (match := re.match(r"\.rodata\.str\d+\.(\d+)", name)) else 1
        return 1, alloc | merge | strings, size, size
    if name.startswith(".rodata.cst"):
        size = int(match[1]) if (match := re.match(r"\.rodata\.cst(\d+)", name)) else 8
        return 1, alloc | merge, size, size
    if name.startswith((".rodata", ".gcc_except_table", ".eh_frame")):
        return 1, alloc, 0, 8
    return 1, alloc | write, 0, 8


def _section_order(name: str) -> tuple[int, str]:
    kind, flags, _, _ = section_traits(name)
    return (0 if flags & 0x4 else 3 if kind == 8 else 2 if flags & 0x1 else 1), name


def internal_linkage(name: str) -> bool:
    """Static functions and data, and anything in an anonymous namespace, by the Itanium name."""
    return name.startswith("_ZL") or "_GLOBAL__N_" in name


def _internal(name: str) -> bool:
    """Internal linkage by its Itanium name (static functions and anonymous namespaces), or a local label."""
    return name.startswith(("_ZL", "_ZN12_GLOBAL__N_", "lbl_", ".L")) or "_GLOBAL__N_" in name


@dataclass
class Unit:
    name: str
    ranges: dict[str, list[tuple[int, int]]] = field(default_factory=lambda: collections.defaultdict(list))


def read_units(path: Path, base: int = 0) -> list[Unit]:
    """A splits.txt (`unit:` then `\\t.section start:0x.. end:0x..` lines); addresses written with or without the
    module base."""
    from .gc import read_splits
    key = lambda value: value - base if base and value >= base else value
    units: dict[str, Unit] = {}
    for name, section, start, end in read_splits(path):
        unit = units.setdefault(name, Unit(name))
        unit.ranges[section].append((key(start), key(end)))
    return list(units.values())


class Symbols:
    """Every name an address can take: functions, data symbols, then synthesized labels for the rest."""

    def __init__(self, functions: list[tuple[int, int, str]], data: list[tuple[int, int, str]], text: str):
        self.entries = sorted({(a, s, n) for a, s, n in functions + data}, key=lambda e: (e[0], -e[1]))
        self.starts = [e[0] for e in self.entries]
        self.by_address = {}
        for address, size, name in self.entries:
            self.by_address.setdefault(address, (address, size, name))
        self.functions = {a for a, _, _ in functions}
        self.text = text  # how addresses are written in labels

    def resolve(self, address: int) -> tuple[str, int]:
        """(symbol, addend) for an address: the symbol containing it, else a label at it."""
        index = bisect.bisect_right(self.starts, address) - 1
        while index >= 0 and self.entries[index][0] > address - 0x100000:
            start, size, name = self.entries[index]
            if start <= address < start + max(size, 1):
                return name, address - start
            index -= 1
        return f"lbl_{self.text(address)}", 0


def _note(addresses: list[int]) -> bytes:
    name = b"Split\0\0\0"
    out = bytearray()
    for kind, desc in ((b"GENR", b"zkit"), (b"VIRT", b"".join(struct.pack("<Q", a) for a in addresses))):
        out += struct.pack("<III", 6, len(desc), int.from_bytes(kind, "big"))
        out += name + desc + b"\0" * (-len(desc) % 4)
    return bytes(out)


def write_object(sections: list[tuple[str, int, bytes, int]], symbols: list[dict], relocations: dict[str, list],
                 path: Path) -> None:
    """An ELF64 little-endian AArch64 relocatable object.

    sections: (name, sh_type, data, alignment); symbols: {name, section (name or None), value, size, kind, bind,
    address}; relocations: section name -> [(offset, type, symbol index, addend)]."""
    names = bytearray(b"\0")

    def name_of(text: str) -> int:
        position = len(names)
        names.extend(text.encode() + b"\0")
        return position
    section_index = {name: i + 1 for i, (name, *_rest) in enumerate(sections)}
    strings = bytearray(b"\0")
    entries = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    order = sorted(range(len(symbols)), key=lambda i: symbols[i]["bind"] != "local")
    index_of = {}
    for i in order:
        symbol = symbols[i]
        offset = len(strings)
        strings.extend(symbol["name"].encode() + b"\0")
        info = ({"local": 0, "global": 1, "weak": 2}[symbol["bind"]] << 4) | {"notype": 0, "object": 1, "func": 2,
                                                                                "section": 3}[symbol["kind"]]
        shndx = section_index.get(symbol["section"], 0) if symbol["section"] else 0
        index_of[i] = len(entries)
        entries.append(struct.pack("<IBBHQQ", offset, info, 0, shndx, symbol["value"], symbol["size"]))
    first_global = 1 + sum(1 for s in symbols if s["bind"] == "local")
    addresses = [0] + [symbols[i]["address"] for i in order]
    blobs: list[tuple[str, int, bytes, int, int, int, int]] = []  # name, type, data, align, link, info, entsize
    for name, kind, data, align in sections:
        blobs.append((name, kind, data, align, 0, 0, 0))
    symtab_index = len(sections) + 1
    for name, rows in relocations.items():
        if not rows:
            continue
        data = b"".join(struct.pack("<QQq", offset, (index_of[symbol] << 32) | kind, addend)
                        for offset, kind, symbol, addend in sorted(rows))
        blobs.append((f".rela{name}", 4, data, 8, symtab_index, section_index[name], 24))
    blobs.append((".note.split", 7, _note(addresses), 4, 0, 0, 0))
    symtab = (".symtab", 2, b"".join(entries), 8, 0, first_global, 24)
    strtab = (".strtab", 3, bytes(strings), 1, 0, 0, 0)
    ordered = blobs[:len(sections)] + [symtab, strtab] + blobs[len(sections):]
    # relocation sections link to the symbol table, which now sits right after the content sections
    final = []
    for entry in ordered:
        name, kind, data, align, link, info, entsize = entry
        if kind == 4:
            link = len(sections) + 1
        if name == ".symtab":
            link = len(sections) + 2
        final.append((name, kind, data, align, link, info, entsize))
    shstrtab_name = name_of(".shstrtab")
    body = bytearray(b"\0" * 64)
    headers = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, kind, data, align, link, info, entsize in final:
        while len(body) % max(align, 1):
            body.append(0)
        offset = len(body)
        if kind != 8:
            body.extend(data)
        if kind == 4:
            flags = 0x40    # info link
        elif kind in (2, 3, 7):
            flags = 0
        else:
            _, flags, entsize, _ = section_traits(name)
        headers.append(struct.pack("<IIQQQQIIQQ", name_of(name), kind, flags, 0, offset,
                                   len(data) if kind != 8 else data, link, info, align, entsize))
    shstrtab_offset = len(body)
    body.extend(names)
    headers.append(struct.pack("<IIQQQQIIQQ", shstrtab_name, 3, 0, 0, shstrtab_offset, len(names), 0, 0, 1, 0))
    while len(body) % 8:
        body.append(0)
    shoff = len(body)
    body.extend(b"".join(headers))
    header = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack(
        "<HHIQQQIHHHHHH", 1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), len(headers) - 1)
    body[:64] = header
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))


def write_objdiff(path: Path, units: list[dict], out_dir: Path, compiled: Path) -> Path:
    """objdiff.json for delinked units: target = the delinked object, base = the compiled one."""
    import json
    import os
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


def delink(project: Project, target: str, splits: Path, out_dir: Path, objdiff: Path | None = None,
           compiled: Path | None = None) -> dict[str, Any]:
    """Write one object per unit of `splits` into out_dir; report what each holds and what stayed unnamed.

    With `objdiff`, also write objdiff's project file pairing each object with the compiled one of the same unit
    under `compiled` (unit a/b.cpp: compiled/a/b.o)."""
    from .bridge import _symbol_table
    from .index import connect, refresh
    from .inspect_dol import _dol
    from .platform import for_target
    platform = for_target(project.target(target))
    if platform.name != "switch":
        raise ValueError("Delinking is implemented for Switch (AArch64) modules; GameCube projects use dtk's split")
    refresh(project)
    db = connect(project)
    module = _dol(project, target)
    functions = [(a, s, n) for a, s, n in db.execute(
        "SELECT address, size, name FROM functions WHERE target=? AND address<? ORDER BY address", (target, 1 << 32))]
    data_symbols = [(s.address, s.size, s.name) for s in _symbol_table(project, target)[0] if s.type != "function"]
    symbols = Symbols(functions, data_symbols, lambda a: platform.text(a)[2:])
    units = read_units(splits, platform.base)
    assigned = sorted((start, end) for unit in units for ranges in unit.ranges.values() for start, end in ranges)

    def in_some_unit(address: int) -> bool:
        index = bisect.bisect_right(assigned, (address, 1 << 64)) - 1
        return index >= 0 and assigned[index][0] <= address < assigned[index][1]
    report = []
    unassigned_total: set[int] = set()
    for unit in units:
        sections, relocations, defined = [], collections.defaultdict(list), []
        references: dict[str, int] = {}
        symbol_rows: list[dict] = []
        index_by_name: dict[str, int] = {}

        def symbol_index(name: str) -> int:
            if name not in index_by_name:
                index_by_name[name] = len(symbol_rows)
                symbol_rows.append({"name": name, "section": None, "value": 0, "size": 0, "kind": "notype",
                                    "bind": "global", "address": 0})
            return index_by_name[name]
        placements: list[tuple[str, Any]] = []
        for section_name in sorted(unit.ranges, key=_section_order):
            ranges = sorted(unit.ranges[section_name])
            kind, flags, _, alignment = section_traits(section_name)
            nobits = kind == 8
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
                blob += b"" if nobits else module.read(start, end - start)
            local = lambda address, placed=placed: next((offset + address - s for s, e, offset in placed
                                                         if s <= address < e), None)
            placements.append((section_name, local))
            if flags & 0x4:
                for start, end, offset in placed:
                    for function, size, name in functions:
                        if not start <= function < end:
                            continue
                        words = module.words(function, size)
                        found, cleared = code_relocations(
                            words, function, module.pointers,
                            lambda target: local(target) is not None and target in symbols.functions and
                            _internal(symbols.resolve(target)[0]))
                        for site, word in cleared.items():
                            struct.pack_into("<I", blob, local(site), word)
                        for reloc in found:
                            name_for, addend = symbols.resolve(reloc.target)
                            if reloc.got:
                                addend = 0
                            references[name_for] = references.get(name_for, 0) + 1
                            relocations[section_name].append((local(reloc.offset), reloc.kind,
                                                              symbol_index(name_for), addend))
            elif not nobits:
                for start, end, offset in placed:
                    for slot, pointee in module.pointers.items():
                        if start <= slot < end and slot + 8 <= end:
                            name_for, addend = symbols.resolve(pointee)
                            struct.pack_into("<Q", blob, local(slot), 0)
                            relocations[section_name].append((local(slot), ABS64, symbol_index(name_for), addend))
            for address, size, name in symbols.entries:
                where = local(address)
                if where is None:
                    continue
                row = symbol_rows[symbol_index(name)]
                row.update(section=section_name, value=where, size=size,
                           kind="func" if address in symbols.functions else "object",
                           bind="local" if internal_linkage(name) else "global", address=platform.base + address)
                defined.append(name)
            sections.append((section_name, kind, used if nobits else bytes(blob), alignment))
        unassigned = []
        for name in references:  # labels inside this unit's ranges are defined here; others belong to a unit or none
            if not name.startswith("lbl_") or symbol_rows[symbol_index(name)]["section"] is not None:
                continue
            address = int(name[4:], 16)
            address = address - platform.base if platform.base and address >= platform.base else address
            for section_name, local in placements:
                where = local(address)
                if where is not None:
                    symbol_rows[symbol_index(name)].update(section=section_name, value=where, kind="object",
                                                           address=platform.base + address)
                    break
            else:
                if not in_some_unit(address):
                    unassigned.append(address)
        unassigned_total.update(unassigned)
        path = out_dir / f"{unit.name.rsplit('.', 1)[0]}.o"
        write_object(sections, symbol_rows, relocations, path)
        report.append({"unit": unit.name, "object": str(path), "defined": len(defined),
                       "undefined": sum(1 for s in symbol_rows if s["section"] is None),
                       "labels": sum(1 for s in symbol_rows if s["name"].startswith("lbl_")),
                       "relocations": sum(len(v) for v in relocations.values()),
                       **({"unassigned": [platform.text(a) for a in sorted(unassigned)[:20]]} if unassigned else {})})
    if objdiff is not None:
        write_objdiff(objdiff, report, out_dir, compiled or out_dir.parent / "build")
    return {"target": target, "units": report, "out": str(out_dir),
            "unassigned": len(unassigned_total),  # referenced addresses no unit's ranges cover: extend the splits
            **({"unassigned_examples": [platform.text(a) for a in sorted(unassigned_total)[:20]]}
               if unassigned_total else {})}
