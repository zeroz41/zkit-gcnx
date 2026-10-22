"""Link: put a Switch module back together from the project's compiled objects, and prove it byte for byte.

The module's own linker cannot be rerun (its dynamic tables, GOT and stubs would have to come out identical), so
every compiled section is placed where the original holds it and every relocation is resolved the way that
linker resolved it:

- a section at the address of a symbol it defines, by name (the unit's own copy when a name has several); a
  section no name places (a jump table, a constant pool) at the address the original's code reaches it through,
  its bytes then checked there; a template's discarded copy (a COMDAT group kept by another unit) not at all;
  nor, in a unit whose every byte comes from its object, a section neither the symbols name nor any placed code
  reaches: the module was linked with `--gc-sections`, which drops a function nothing calls (a constructor every
  caller inlined), and its bytes are nowhere in the unit;
- a literal of a mergeable section (strings, constants) where the original's reference lands on the same bytes;
- a call to an import through its stub, a GOT load through the slot whose dynamic relocation holds the target,
  a pointer in data only where the original carries a dynamic relocation to the same address;
- a constructor or destructor by its partner's name when the original names only one of the pair: clang emits the
  complete-object and base-object variants (C1/C2, D1/D2) of a class without virtual bases as one function under
  both names, and the module keeps one, so a derived destructor's call to its base's D2 lands on the base's D1.

The rebuilt module is the original with each placed byte written from the compiled objects. It must equal the
original, and on an NSO each segment must hash to its header's SHA-256: so `identical` is a proof, not a
comparison of one tool's reading with another's. A unit is linked when its code is all matched, its compiled
object covers every byte of its ranges (alignment padding aside) and every one of those bytes linked identically;
the build then marks it complete in objdiff's report, and its data matched, which on Switch only the link can
prove (clang merges a unit's string literals with every other unit's, so objdiff cannot pair them).
"""

from __future__ import annotations

import collections
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .elf import SHT_NOBITS, Elf, Section, Symbol
from .project import Project

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHF_STRINGS, SHF_GROUP = 0x1, 0x2, 0x4, 0x10, 0x20, 0x200
ABS64, ABS32, ABS16, PREL64, PREL32, PREL16 = 257, 258, 259, 260, 261, 262
LD_PREL_LO19, ADR_PREL_LO21, ADR_PREL_PG_HI21, ADR_PREL_PG_HI21_NC, ADD_ABS_LO12_NC = 273, 274, 275, 276, 277
LDST8, TSTBR14, CONDBR19, JUMP26, CALL26 = 278, 279, 280, 282, 283
LDST16, LDST32, LDST64, LDST128 = 284, 285, 286, 299
ADR_GOT_PAGE, LD64_GOT_LO12_NC = 311, 312
PAGE = {ADR_PREL_PG_HI21, ADR_PREL_PG_HI21_NC, ADR_GOT_PAGE}
LO12 = {ADD_ABS_LO12_NC: 0, LDST8: 0, LDST16: 1, LDST32: 2, LDST64: 3, LDST128: 4, LD64_GOT_LO12_NC: 3}
GOT = {ADR_GOT_PAGE, LD64_GOT_LO12_NC}
BRANCH = {CALL26: 26, JUMP26: 26, CONDBR19: 19, LD_PREL_LO19: 19, TSTBR14: 14}
PC_RELATIVE = {PREL64: 8, PREL32: 4, PREL16: 2}
# Sections a link reads but never places: the linker builds .eh_frame and .eh_frame_hdr from every object's
# unwind entries (the delinker leaves them to it too), and the rest is not loaded.
UNPLACED = (".eh_frame", ".comment", ".note", ".group", ".llvm_addrsig", ".debug", ".ARM.", ".gcc_except_table")
SEGMENTS = ("text", "rodata", "data")
PADDING = 16   # a run of zero bytes up to this long between two placed sections is alignment, not content
# an Itanium constructor or destructor variant closing its nested name: complete-object (1) or base-object (2)
STRUCTOR = re.compile(r"([CD])([12])(?=E)")


def structor_partner(name: str) -> str | None:
    """The other variant's name of a mangled constructor or destructor (C1 <-> C2, D1 <-> D2), or None."""
    found = list(STRUCTOR.finditer(name))
    if not name.startswith("_ZN") or not found:
        return None
    last = found[-1]
    other = "2" if last.group(2) == "1" else "1"
    return name[:last.start(2)] + other + name[last.end(2):]


@dataclass
class Placed:
    section: Section
    address: int
    data: bytearray
    unit: str
    reason: str                      # "name", "reference" (reached from placed code) or "array" (.init_array)
    resolved: bool = True            # every relocation resolved: only then are its bytes written


@dataclass
class UnitLink:
    name: str
    whole: bool                      # every function matched: the whole object is placed and may link
    sections: int = 0
    functions: int = 0               # exact functions placed from the compiled object
    code: int = 0                    # bytes placed from the compiled object
    data: int = 0
    covered: list[tuple[int, int]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    folded: list[str] = field(default_factory=list)   # template copies another unit's object provides
    collected: list[str] = field(default_factory=list)   # sections the original's linker dropped as unused
    unnamed: dict[int, str] = field(default_factory=dict)   # section index -> the name the symbols lack
    linked: bool = False
    gaps: list[str] = field(default_factory=list)


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def page_of(word: int, pc: int) -> int:
    """The page an `adrp` at pc reaches."""
    imm = _signed(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21)
    return (pc & ~0xFFF) + (imm << 12)


def lo12_of(word: int, kind: int) -> int:
    """The low 12 bits an `add`/load/store immediate supplies, scaled back to bytes."""
    return ((word >> 10) & 0xFFF) << LO12[kind]


def branch_of(word: int, pc: int, kind: int) -> int:
    bits = BRANCH[kind]
    shift = 0 if bits == 26 else 5
    return pc + (_signed(word >> shift & ((1 << bits) - 1), bits) << 2)


def patch(word: int, kind: int, value: int, pc: int) -> int:
    """The instruction at pc with its field set to reach `value` (S + A, or a GOT slot); ValueError when it cannot."""
    if kind in PAGE or kind == ADR_PREL_LO21:
        delta = (value & ~0xFFF) - (pc & ~0xFFF) if kind != ADR_PREL_LO21 else value - pc
        imm = delta >> 12 if kind != ADR_PREL_LO21 else delta
        if kind != ADR_PREL_PG_HI21_NC and not -(1 << 20) <= imm < (1 << 20):
            raise ValueError("out of range")
        return word & ~0x60FFFFE0 | (imm & 3) << 29 | (imm >> 2 & 0x7FFFF) << 5
    if kind in LO12:
        low = value & 0xFFF
        if low & ((1 << LO12[kind]) - 1):
            raise ValueError("misaligned")
        return word & ~(0xFFF << 10) | (low >> LO12[kind]) << 10
    if kind in BRANCH:
        delta = value - pc
        bits = BRANCH[kind]
        if delta & 3 or not -(1 << (bits + 1)) <= delta < (1 << (bits + 1)):
            raise ValueError("out of range")
        shift = 0 if bits == 26 else 5
        mask = ((1 << bits) - 1) << shift
        return word & ~mask | ((delta >> 2) << shift) & mask
    raise ValueError(f"relocation type {kind} is not supported")


def original_reaches(word: int, kind: int, pc: int) -> tuple[str, int] | None:
    """What the original instruction at pc says about its target: ("page", p), ("low", l) or ("address", a)."""
    if kind in PAGE:
        return "page", page_of(word, pc)
    if kind in LO12:
        return "low", lo12_of(word, kind)
    if kind in BRANCH:
        return "address", branch_of(word, pc, kind)
    return None


def _agrees(address: int, hint: tuple[str, int] | None) -> bool:
    if hint is None:
        return True
    kind, value = hint
    return (address & ~0xFFF) == value if kind == "page" else (address & 0xFFF) == value if kind == "low" \
        else address == value


class Linker:
    """One link of one Switch target: the original, its names, and every compiled object placed into it."""

    def __init__(self, project: Project, target: str):
        from .bridge import _symbol_table
        from .inspect_dol import _dol
        from .platform import for_target
        self.project, self.target = project, target
        self.config = project.target(target)
        self.platform = for_target(self.config)
        if self.platform.name != "switch":
            raise ValueError("nxlink links Switch modules")
        self.module = _dol(project, target)
        if not self.module.raw:
            raise ValueError("this zkit's module reader keeps no raw image: update zkit")
        self.original = self.module.raw
        self.image = bytearray(self.original)
        self.addresses: dict[str, list[int]] = collections.defaultdict(list)
        for symbol in _symbol_table(project, target)[0]:
            address = symbol.address - self.platform.base if symbol.address >= self.platform.base else symbol.address
            if address not in self.addresses[symbol.name]:
                self.addresses[symbol.name].append(address)
        for address, name in self.module.symbols.items():
            if address not in self.addresses[name]:
                self.addresses[name].append(address)
        self.stubs = {name: pc for pc, name in sorted(self.module.stubs().items())}
        self.slots: dict[int, list[int]] = collections.defaultdict(list)       # pointee -> GOT/data slots
        for slot, pointee in self.module.pointers.items():
            self.slots[pointee].append(slot)
        self.imported: dict[str, list[int]] = collections.defaultdict(list)    # import -> slots
        for slot, name in self.module.imports.items():
            self.imported[name].append(slot)

    # reading the original

    def word(self, address: int) -> int:
        return struct.unpack_from("<I", self.original, address)[0]

    def segment(self, address: int):
        return self.module.segment_at(address)

    # resolving one relocation

    def by_name(self, name: str, hint: tuple[str, int] | None, unit_ranges: list[tuple[int, int]]) -> int | None:
        """The address of a name: the only one, else the one inside the unit, else the one the original reaches."""
        found = self.addresses.get(name) or []
        if len(found) == 1:
            return found[0]
        if not found:
            partner = structor_partner(name)
            aliased = self.addresses.get(partner) or [] if partner else []
            if len(aliased) == 1:
                return aliased[0]
            return self.stubs.get(name)
        inside = [a for a in found if any(s <= a < e for s, e in unit_ranges)]
        if len(inside) == 1:
            return inside[0]
        agreeing = [a for a in found if _agrees(a, hint)]
        return agreeing[0] if agreeing else None

    def literal(self, piece: bytes, hints: list[tuple[str, int]]) -> int | None:
        """Where the original holds a merged literal: the address its references reach (a page and a low part from
        the instruction pair) whose bytes are the literal's."""
        pages = [v for k, v in hints if k == "page"] or [None]
        lows = [v for k, v in hints if k == "low"] or [None]
        addresses = [v for k, v in hints if k == "address"]
        for page in pages:
            for low in lows:
                if page is not None and low is not None:
                    addresses.append(page + low)
        for address in addresses:
            if self.original[address:address + len(piece)] == piece:
                return address
        # one half of the pair only: every place in the loaded image with those bytes that the half allows
        start = 0
        while True:
            at = self.original.find(piece, start)
            if at < 0:
                return None
            if all(_agrees(at, h) for h in hints) and self.segment(at) is not None:
                return at
            start = at + 1


@dataclass
class _Object:
    unit: str
    elf: Elf
    ranges: list[tuple[int, int]]
    whole: bool
    exact: set[str]
    discarded: dict[int, str] = field(default_factory=dict)   # sections of COMDAT groups another unit's copy holds


def _piece(elf: Elf, section: Section, offset: int) -> bytes:
    data = elf.data(section)
    if section.flags & SHF_STRINGS:
        end = data.find(b"\0", offset)
        return data[offset:end + 1 if end >= 0 else len(data)]
    return data[offset:offset + max(section.entsize, 1)]


def _placeable(section: Section) -> bool:
    return bool(section.flags & SHF_ALLOC) and section.size > 0 and not section.name.startswith(UNPLACED) \
        and not section.flags & SHF_MERGE


def link(project: Project, target: str, out: Path, compiled: str = "functions", splits: Path | None = None,
         mark: bool = True) -> dict[str, Any]:
    """Link the target's compiled objects into out/<module>.nso and compare it with the original.

    compiled: "none" (the original alone), "units" (the objects of units whose every function is matched) or
    "functions" (also each exact function of the other units). With `mark`, the report records the units this
    link proves."""
    from .delink import read_units
    from .link import compiled_units
    linker = Linker(project, target)
    config = linker.config
    splits = splits or project.file(config["repository"], config["splits"])
    units = read_units(splits, linker.platform.base)
    sources, measures = compiled_units(project, target, units)
    report_rows = _report_rows(project, target)
    objects: list[_Object] = []
    results: dict[str, UnitLink] = {}
    for unit in units:
        source = sources.get(unit.name)
        if source is None or compiled == "none":
            continue
        ranges = sorted(r for spans in unit.ranges.values() for r in spans)
        stem = unit.name.rsplit(".", 1)[0]
        row = report_rows.get(f"{config.get('module', '')}/{stem}") or report_rows.get(stem, {})
        whole = _code_matched(row)
        exact = set(source["exact"]) if compiled == "functions" or whole else set()
        if not whole and not exact:
            continue
        results[unit.name] = UnitLink(unit.name, whole)
        objects.append(_Object(unit.name, Elf.load(source["object"]), ranges, whole, exact))
    placed: dict[tuple[str, int], Placed] = {}
    for obj in objects:
        _place_named(linker, obj, placed, results[obj.unit])
    queue = list(placed)
    done: set[tuple[str, int]] = set()
    while queue:
        key = queue.pop(0)
        if key in done:
            continue
        done.add(key)
        obj = next(o for o in objects if o.unit == key[0])
        for new in _relocate(linker, obj, placed[key], placed, results[obj.unit]):
            queue.append(new)
    for key, item in placed.items():
        result = results[item.unit]
        _compare(linker, item, result)
    for obj in objects:
        _cover(linker, obj, results[obj.unit], placed)
    identical = bytes(linker.image) == linker.original
    segments = []
    for segment in linker.module.segments:
        if segment.name not in SEGMENTS:
            continue
        digest = hashlib.sha256(linker.image[segment.offset:segment.offset + segment.size]).digest()
        expected = linker.module.hashes.get(segment.name)
        segments.append({"segment": segment.name, "size": segment.size, "sha256": digest.hex(),
                         "matches_header": None if expected is None else digest == expected})
    linked = sorted(r.name for r in results.values() if r.linked) if identical else []
    out.mkdir(parents=True, exist_ok=True)
    module = config.get("module") or target
    nso = out / f"{module}.nso"
    _write_nso(linker, nso)
    result: dict[str, Any] = {
        "target": target, "compiled": compiled, "out": str(nso), "identical": identical, "ok": identical,
        "segments": segments,
        "units": {"compiled": len(objects), "whole": sum(1 for r in results.values() if r.whole),
                  "linked": len(linked)},
        "linked_units": linked,
        "functions_from_compiled": sum(r.functions for r in results.values()),
        "code_from_compiled": sum(r.code for r in results.values()),
        "data_from_compiled": sum(r.data for r in results.values()),
        "report": {k: int(float(measures[k])) for k in ("total_code", "matched_code", "complete_code")
                   if k in measures},
        "not_linked": [{"unit": r.name, "why": (r.problems + r.gaps)[:6]} for r in results.values()
                       if r.whole and not r.linked],
        "problems": [f"{r.name}: {p}" for r in results.values() for p in r.problems][:200],
        "folded": sum(len(r.folded) for r in results.values()),
        "collected": sum(len(r.collected) for r in results.values()),
    }
    if not identical:
        first = next(i for i, (a, b) in enumerate(zip(linker.image, linker.original)) if a != b)
        result["first_difference"] = {"address": linker.platform.text(first),
                                      "ours": linker.image[first:first + 8].hex(),
                                      "original": linker.original[first:first + 8].hex()}
    (out / "link.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    if mark and config.get("report"):
        from .progress import apply_link
        report = project.file(config["repository"], config["report"])
        if report.is_file():
            result["report_updated"] = apply_link(report, [u.rsplit(".", 1)[0] for u in linked])
    return result


def link_unit(project: Project, target: str, unit_name: str, object_path: Path,
              splits: Path | None = None) -> dict[str, Any]:
    """Whether one compiled object links: every section of it placed into the original at its unit's addresses,
    every relocation resolved as the original's code and data reach, and the image then compared with the
    original byte for byte (the rest of the image is the original's own). The proof `zkit build` gives a unit,
    for a candidate outside the tree."""
    from .delink import read_units
    linker = Linker(project, target)
    config = linker.config
    splits = splits or project.file(config["repository"], config["splits"])
    unit = next((u for u in read_units(splits, linker.platform.base) if u.name == unit_name), None)
    if unit is None:
        raise ValueError(f"{unit_name} is no unit of {splits}")
    ranges = sorted(r for spans in unit.ranges.values() for r in spans)
    result = UnitLink(unit.name, True)
    obj = _Object(unit.name, Elf.load(object_path), ranges, True, set())
    placed: dict[tuple[str, int], Placed] = {}
    _place_named(linker, obj, placed, result)
    queue = list(placed)
    done: set[tuple[str, int]] = set()
    while queue:
        key = queue.pop(0)
        if key in done:
            continue
        done.add(key)
        queue += _relocate(linker, obj, placed[key], placed, result)
    for item in placed.values():
        _compare(linker, item, result)
    _cover(linker, obj, result, placed)
    identical = bytes(linker.image) == linker.original
    out: dict[str, Any] = {"unit": unit.name, "linked": bool(identical and result.linked), "identical": identical,
                           "functions": result.functions, "code": result.code, "data": result.data,
                           "problems": result.problems[:40], "gaps": result.gaps[:40],
                           "folded": result.folded, "collected": result.collected}
    if not identical:
        first = next(i for i, (a, b) in enumerate(zip(linker.image, linker.original)) if a != b)
        out["first_difference"] = {"address": linker.platform.text(first),
                                   "ours": linker.image[first:first + 8].hex(),
                                   "original": linker.original[first:first + 8].hex()}
    return out


def _report_rows(project: Project, target: str) -> dict[str, dict]:
    config = project.target(target)
    path = project.file(config["repository"], config["report"]) if config.get("report") else None
    if path is None or not path.is_file():
        return {}
    return {u["name"]: u for u in json.loads(path.read_text(encoding="utf-8")).get("units", [])}


def _code_matched(row: dict) -> bool:
    """Every function of the unit is exact (a unit without code: its object is all data, which the link proves)."""
    m = row.get("measures") or {}
    number = lambda key: int(float(m.get(key) or 0))
    functions = row.get("functions") or []
    return bool(row) and number("matched_code") == number("total_code") and \
        all(f.get("fuzzy_match_percent") == 100 for f in functions)


SHT_GROUP, GRP_COMDAT = 17, 1


def _discarded(linker: Linker, obj: _Object) -> dict[int, str]:
    """{section index: its group's signature} of the COMDAT groups whose signature symbol the original holds
    outside the unit: the link kept another unit's copy of the whole group (a template's static, its guard, its
    initializer and that initializer's .init_array entry), so none of its sections are this unit's."""
    elf, out = obj.elf, {}
    for section in elf.sections:
        if section.type != SHT_GROUP or section.size < 8:
            continue
        words = struct.unpack(f"<{section.size // 4}I", elf.data(section))
        if not words[0] & GRP_COMDAT or section.info >= len(elf.symbols):
            continue
        signature = elf.symbols[section.info].name
        at = linker.by_name(signature, None, obj.ranges) if signature else None
        if at is not None and not any(s <= at < e for s, e in obj.ranges):
            out.update(dict.fromkeys(words[1:], signature))
    return out


def _place_named(linker: Linker, obj: _Object, placed: dict, result: UnitLink) -> None:
    """Place each section of the object that a name, or the unit's .init_array range, puts somewhere."""
    elf = obj.elf
    obj.discarded = _discarded(linker, obj)
    for signature in dict.fromkeys(obj.discarded.values()):
        result.folded.append(signature)
    defined = collections.defaultdict(list)
    for symbol in elf.symbols:
        if 0 < symbol.section < 0xFF00 and symbol.kind in ("func", "object") and symbol.name:
            defined[symbol.section].append(symbol)
    for section in elf.sections:
        if not _placeable(section) or section.index in obj.discarded:
            continue
        code = bool(section.flags & SHF_EXECINSTR)
        names = sorted(defined.get(section.index, []), key=lambda s: (s.value, s.bind == "local"))
        if not obj.whole and not (code and any(s.name in obj.exact for s in names)):
            continue
        if section.name.startswith(".init_array"):
            spans = [r for r in obj.ranges if _covers(linker, r, ".init_array")]
            address = spans[0][0] if spans and spans[0][1] - spans[0][0] == section.size else None
            if address is None:
                result.problems.append(f"{section.name}: no .init_array range of {section.size} bytes in the unit")
                continue
            placed[(obj.unit, section.index)] = Placed(section, address, bytearray(elf.data(section)), obj.unit,
                                                       "array")
            continue
        if not names:
            continue                      # placed later by what reaches it, if anything does
        address = None
        for symbol in names:
            at = linker.by_name(symbol.name, None, obj.ranges)
            if at is not None:
                address = at - symbol.value
                break
        if address is None:
            result.unnamed[section.index] = names[0].name   # placed if code reaches it, else maybe collected
            continue
        if not any(s <= address < e for s, e in obj.ranges):
            if section.flags & SHF_GROUP:
                result.folded.append(names[0].name)   # the copy the link kept is another unit's
            else:
                result.problems.append(f"{names[0].name} is at {linker.platform.text(address)}, outside the unit")
            continue
        data = bytearray(section.size) if section.type == SHT_NOBITS else bytearray(elf.data(section))
        placed[(obj.unit, section.index)] = Placed(section, address, data, obj.unit, "name")


def _covers(linker: Linker, span: tuple[int, int], name: str) -> bool:
    start, end = linker.module.tables.get(name, (None, None))
    return start is not None and start <= span[0] < end


def _relocate(linker: Linker, obj: _Object, item: Placed, placed: dict, result: UnitLink) -> list:
    """Resolve and apply the relocations of one placed section; returns sections it newly placed."""
    elf, section = obj.elf, item.section
    if section.type == SHT_NOBITS:
        return []
    relocations = elf.relocations(section)
    groups = collections.defaultdict(list)    # (symbol index, addend) -> original hints of its sites
    for r in relocations:
        pc = item.address + r.offset
        if r.type in PAGE or r.type in LO12 or r.type in BRANCH:
            hint = original_reaches(linker.word(pc), r.type, pc)
            if hint is not None:
                groups[(r.symbol, r.addend)].append(hint)
    new = []
    for r in relocations:
        pc = item.address + r.offset
        symbol = elf.symbols[r.symbol]
        if r.type == ABS64:
            pointee = linker.module.pointers.get(pc)
            hint = ("address", pointee) if pointee is not None else None
        else:
            hint = original_reaches(linker.word(pc), r.type, pc) if r.type not in PC_RELATIVE else None
        try:
            value, newly = _value(linker, obj, symbol, r, pc, hint, groups[(r.symbol, r.addend)], placed, result)
            new += newly
            if r.type in GOT:
                slot = _got_slot(linker, symbol, value, hint)
                if slot is None:
                    raise ValueError(f"no GOT slot holding {_label(linker, symbol, value)} where the original "
                                     "loads one")
                value = slot
            _apply(linker, item, r, value, symbol)
        except ValueError as error:
            result.problems.append(f"{_where(obj, item, r.offset)}: {error}")
            item.resolved = False
    return new


def _value(linker: Linker, obj: _Object, symbol: Symbol, r, pc: int, hint, hints: list, placed: dict,
           result: UnitLink):
    """S + A for a relocation (for a GOT relocation, the address the slot must hold, or -1 for an import's), and
    the sections it placed."""
    elf = obj.elf
    if 0 < symbol.section < 0xFF00:
        target = elf.sections[symbol.section]
        offset = symbol.value + r.addend
        key = (obj.unit, symbol.section)
        if key in placed:
            return placed[key].address + offset, []
        if target.flags & SHF_MERGE:
            piece = _piece(elf, target, offset)
            hints = hints if r.type not in GOT else []
            if r.type == ABS64:
                hints = [("address", linker.module.pointers[pc])] if pc in linker.module.pointers else []
            address = linker.literal(piece, hints)
            if address is None:
                raise ValueError(f"no copy of the literal {piece[:24]!r} where the original's reference lands")
            result.covered.append((address, address + len(piece)))
            return address, []
        if symbol.name and symbol.bind != "local" and symbol.kind != "section":
            found = linker.by_name(symbol.name, hint, obj.ranges)
            if found is not None:
                return found + r.addend, []
        if symbol.section in obj.discarded:
            raise ValueError(f"{symbol.name or target.name} is in {obj.discarded[symbol.section]}'s group, which "
                             "the link kept from another unit, and the symbols do not name it")
        if _placeable(target) and obj.whole and r.type not in GOT:
            # a section no name places, reached from placed code: where the original's references reach
            if r.type == ABS64 and hint is not None:
                hints = [hint]            # a table slot: the word the module's loader writes there
            address = _reached(linker, hints, r.type)
            if address is not None and target.flags & SHF_GROUP and \
                    not any(s <= address < e for s, e in obj.ranges):
                # an inline the link kept another unit's copy of (or folded with identical code): the same bytes
                start = address - offset
                if elf.relocations(target) or target.type == SHT_NOBITS or \
                        linker.original[start:start + target.size] != elf.data(target):
                    raise ValueError(f"{target.name} would be another unit's copy at "
                                     f"{linker.platform.text(address)}, whose bytes differ")
                result.folded.append(symbol.name or target.name)
                return address, []
            if address is None:
                hint_text = ""
                if r.type == ABS64 and re.search(r"D[12]Ev$", target.name):
                    hint_text = (" (a table slot: clang points a trivial destructor's slot at its base's when the "
                                 "destructor is inline, so declare it `{}` in the class and define none in the file)")
                raise ValueError(f"cannot tell where {target.name} goes from the original's references{hint_text}")
            base = address - offset
            data = bytearray(target.size) if target.type == SHT_NOBITS else bytearray(elf.data(target))
            placed[key] = Placed(target, base, data, obj.unit, "reference")
            return address, [key]
        raise ValueError(f"{symbol.name or target.name} is not placed")
    if not symbol.name:
        raise ValueError("relocation against an unnamed undefined symbol")
    found = linker.by_name(symbol.name, hint, obj.ranges)
    if found is None:
        if (r.type in GOT or r.type == ABS64) and symbol.name in linker.imported:
            return -1, []                 # an import: its slot (a GOT's, a table's) holds it by name
        raise ValueError(f"{symbol.name} is not in the symbols")
    return found + r.addend, []


def _reached(linker: Linker, hints: list, kind: int) -> int | None:
    addresses = [v for k, v in hints if k == "address"]
    pages = [v for k, v in hints if k == "page"]
    lows = [v for k, v in hints if k == "low"]
    if addresses:
        return addresses[0]
    if pages and lows:
        return pages[0] + lows[0]
    return None


def _got_slot(linker: Linker, symbol: Symbol, value: int, hint) -> int | None:
    """The GOT slot holding a value (or an import): one the original's load reaches, inside .got when the module
    says where that is."""
    candidates = linker.imported.get(symbol.name, []) if value == -1 else linker.slots.get(value, [])
    start, end = linker.module.tables.get(".got", (None, None))
    if start is not None:
        candidates = [s for s in candidates if start <= s < end]
    agreeing = [s for s in candidates if _agrees(s, hint)]
    return agreeing[0] if agreeing else None


def _apply(linker: Linker, item: Placed, r, value: int, symbol: Symbol) -> None:
    pc = item.address + r.offset
    data = item.data
    if r.type in PC_RELATIVE:
        size = PC_RELATIVE[r.type]
        delta = value - pc
        if not -(1 << (8 * size - 1)) <= delta < (1 << (8 * size - 1)):
            raise ValueError("out of range")
        data[r.offset:r.offset + size] = (delta & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        return
    if r.type == ABS64:
        # the module's loader writes this word: the original must carry a dynamic relocation to the same place
        expected = linker.module.pointers.get(pc)
        imported = linker.module.imports.get(pc)
        if value == -1 and imported is None or expected is None and imported is None:
            raise ValueError(f"no dynamic relocation at {linker.platform.text(pc)} for {symbol.name or 'a pointer'}")
        if expected is not None and expected != value:
            raise ValueError(f"points at {linker.platform.text(value)}, the original at {linker.platform.text(expected)}")
        if imported is not None and imported != symbol.name:
            raise ValueError(f"names {symbol.name}, the original imports {imported}")
        data[r.offset:r.offset + 8] = linker.original[pc:pc + 8] if imported is not None \
            else value.to_bytes(8, "little")
        return
    word = struct.unpack_from("<I", data, r.offset)[0]
    struct.pack_into("<I", data, r.offset, patch(word, r.type, value, pc))


def _where(obj: _Object, item: Placed, offset: int) -> str:
    names = [s for s in obj.elf.symbols if s.section == item.section.index and s.kind in ("func", "object")
             and s.value <= offset]
    owner = max(names, key=lambda s: s.value, default=None)
    return f"{owner.name}+0x{offset - owner.value:X}" if owner else f"{item.section.name}+0x{offset:X}"


def _label(linker: Linker, symbol: Symbol, value: int) -> str:
    return symbol.name or (linker.platform.text(value) if value >= 0 else "?")


def _compare(linker: Linker, item: Placed, result: UnitLink) -> None:
    """Write the placed bytes into the rebuilt image and record where they differ from the original's."""
    section, start = item.section, item.address
    size = section.size
    if section.type == SHT_NOBITS:
        segment = linker.segment(start)
        if segment is None or segment.name != "bss" or start + size > segment.offset + segment.size:
            result.problems.append(f"{section.name}: not inside the original's .bss")
            return
        result.data += size
        result.covered.append((start, start + size))
        return
    if not item.resolved:
        return                            # left as the original's bytes: the problems say why
    original = linker.original[start:start + size]
    if len(original) < size:
        result.problems.append(f"{section.name}: {size} bytes at {linker.platform.text(start)} run past the original's "
                               "end")
        return
    if bytes(item.data) != original:
        first = next(i for i, (a, b) in enumerate(zip(item.data, original)) if a != b)
        result.problems.append(f"{section.name}+0x{first:X} differs: {bytes(item.data[first & ~3:(first & ~3) + 4]).hex()} "
                               f"for {original[first & ~3:(first & ~3) + 4].hex()}")
    linker.image[start:start + size] = item.data
    result.covered.append((start, start + size))
    result.sections += 1
    if section.flags & SHF_EXECINSTR:
        result.code += size
        result.functions += 1
    else:
        result.data += size


def _cover(linker: Linker, obj: _Object, result: UnitLink, placed: dict | None = None) -> None:
    """A whole unit links when no problem stands and every byte of its ranges came from its object: its placed
    sections, the literals its code reaches, and every other literal of its mergeable sections that the original
    holds inside the unit (the linker keeps a literal no code reaches, in the unit that brought it). A section the
    symbols do not name and no placed code reached is one `--gc-sections` dropped when nothing else is missing;
    while a byte is, it may be that byte's original under another name."""
    unnamed = [name for index, name in result.unnamed.items() if (obj.unit, index) not in (placed or {})]
    unknown = [f"{name}: the symbols name no such function or object (its original is unnamed, or another "
               "unit's): name it, or move it to the unit that holds it" for name in unnamed]
    if not obj.whole:
        result.problems += unknown
        return
    for section in obj.elf.sections:
        if not (section.flags & SHF_ALLOC and section.flags & SHF_MERGE) or not section.size:
            continue
        offset = 0
        while offset < section.size:
            piece = _piece(obj.elf, section, offset)
            for start, end in obj.ranges:
                at = linker.original.find(piece, start, end)
                if at >= 0:
                    result.covered.append((at, at + len(piece)))
                    break
            offset += max(len(piece), 1)
    merged: list[list[int]] = []
    for start, end in sorted(result.covered):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in obj.ranges:
        if _covers(linker, (start, end), ".eh_frame"):
            continue
        cursor, holes = start, []
        for low, high in merged:
            if high <= cursor:
                continue
            if low >= end:
                break
            if low > cursor:
                holes.append((cursor, low))
            cursor = max(cursor, high)
        if cursor < end:
            holes.append((cursor, end))
        for low, high in holes:
            segment = linker.segment(low)
            content = linker.original[low:high] if segment is not None and segment.name != "bss" else bytes(0)
            if high - low >= PADDING or any(content):
                result.gaps.append(f"{linker.platform.text(low)}..{linker.platform.text(high)} ({high - low} bytes) "
                                   "not from the compiled object")
    if result.gaps:
        result.problems += unknown
    else:
        result.collected += unnamed
    result.linked = not result.problems and not result.gaps


def _write_nso(linker: Linker, path: Path) -> None:
    """The rebuilt module as an uncompressed NSO: the original's header (hashes, build id) and segments."""
    module = linker.module
    config = linker.config
    source = linker.project.file(config["repository"], config["original"]).read_bytes()
    if source[:4] != b"NSO0":
        path.write_bytes(bytes(linker.image))
        return
    header = bytearray(source[:0x100])
    name_offset, name_size = struct.unpack_from("<I", source, 0x1C)[0], struct.unpack_from("<I", source, 0x2C)[0]
    name = source[name_offset:name_offset + name_size] if name_offset and name_size else b""
    body, cursor = bytearray(name), 0x100 + len(name)
    struct.pack_into("<I", header, 0x1C, 0x100 if name else 0)
    flags = struct.unpack_from("<I", header, 0xC)[0] & ~0x7
    struct.pack_into("<I", header, 0xC, flags)
    for index, segment_name in enumerate(SEGMENTS):
        _, memory, size = struct.unpack_from("<III", source, 0x10 + index * 0x10)
        struct.pack_into("<I", header, 0x10 + index * 0x10, cursor)
        struct.pack_into("<I", header, 0x60 + index * 4, size)
        body += linker.image[memory:memory + size]
        cursor += size
    path.write_bytes(bytes(header) + bytes(body))
