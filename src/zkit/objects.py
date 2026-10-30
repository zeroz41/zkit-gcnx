"""Compiled objects against the original, and against themselves before a change.

Two questions every decomp asks, answered from the ELF objects the build already wrote:
- function: does the compiled function equal the original one (bytes and relocations), and where does it differ?
- identity: after a source change that must not change code (a cleanup, a rename, a header move), is every object
  identical to a saved copy, apart from the renames that change intended?
objdiff remains the authority for match percentages; these are fast exact checks with the differing lines shown.
"""

from __future__ import annotations

import bisect
import json
import re
import shutil
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .elf import Elf, Relocation, Section
from .project import Project

# Sections that never carry the program: compiler notes, debug info, line tables, address-significance tables.
SHF_WRITE, SHF_EXECINSTR, SHF_STRINGS = 0x1, 0x4, 0x20
SKIP_SECTIONS = re.compile(r"^(\.comment|\.mwcats.*|\.debug.*|\.line|\.note.*|\.llvm_addrsig|\.llvm\.call-graph-profile|"
                           r"\.ARM\.attributes|\.eh_frame|\.rela?\..*|\.symtab|\.strtab|\.shstrtab|\.group)$")


def _anonymous(name: str, bind: str) -> bool:
    """Compiler-numbered locals whose number is not stable across edits: MWCC @123, ...data.0 and function
    statics (init$63), clang .L and .str.N, AArch64 mapping symbols."""
    return bind == "local" and (name.startswith(("@", "...", ".L", "$x", "$d", ".str", "__func__."))
                                or re.search(r"\$\d+$", name) is not None)


def objdiff_units(project: Project, target: str) -> dict[str, dict]:
    """{unit name: objdiff.json unit} for a target's repository."""
    config = project.target(target)
    path = project.file(config["repository"], config.get("objdiff", "objdiff.json"))
    if not path.is_file():
        raise ValueError(f"No {path.name} in {config['repository']}: build the project once (it writes objdiff's "
                         "project file)")
    data = json.loads(path.read_text(encoding="utf-8"))
    return {u["name"]: u for u in data.get("units", []) if u.get("name")}


def _symbol_name(elf: Elf, index: int) -> str:
    symbol = elf.symbols[index] if index < len(elf.symbols) else None
    if symbol is None:
        return "?"
    if symbol.kind == "section" or not symbol.name:
        return f"<{elf.sections[symbol.section].name if symbol.section < len(elf.sections) else '?'}>"
    if _anonymous(symbol.name, symbol.bind):
        where = elf.sections[symbol.section].name if 0 < symbol.section < len(elf.sections) else "?"
        return f"<{where}+0x{symbol.value:X}>"
    return symbol.name


def _relocs(elf: Elf, section: Section, start: int, end: int, rename: dict[str, str],
            width: int = 4) -> dict[int, tuple]:
    """Relocations inside [start, end), keyed by the instruction word they patch (PowerPC relocates half-words
    inside an instruction), as (types, targets, addends) tuples."""
    grouped: dict[int, list[tuple]] = {}
    relocations = elf.relocations(section)  # sorted by offset
    first = bisect.bisect_left(relocations, start, key=lambda r: r.offset)
    for reloc in relocations[first:bisect.bisect_left(relocations, end, key=lambda r: r.offset)]:
        if start <= reloc.offset < end:
            name = _symbol_name(elf, reloc.symbol)
            word = (reloc.offset - start) // width * width
            grouped.setdefault(word, []).append((reloc.type, rename.get(name, name), reloc.addend, reloc.symbol))
    return {word: tuple(tuple(r[i] for r in rows) for i in range(4)) for word, rows in grouped.items()}


CONSTANT_SECTIONS = (".rodata", ".sdata2", ".sbss2")  # constant by name: MWCC marks .sdata2 writable


def _referenced(elf: Elf, index: int, addend: int, original=None) -> tuple[bytes, int, bool, bool] | None:
    """(bytes from the target on, known length, string section, unnamed) for a relocation to constant data this
    object defines, or (with `original`, a reader of the original's bytes by label) to a label another unit
    defines, such as a literal the linker merged into another unit's range; None for anything else (code,
    writable data, other undefined symbols)."""
    symbol = elf.symbols[index] if index < len(elf.symbols) else None
    if symbol is not None and symbol.section == 0 and original is not None and symbol.name.startswith("lbl_"):
        data = original(symbol.name)
        return (data[addend:], 0, False, True) if data else None
    if symbol is None or not 0 < symbol.section < min(0xFF00, len(elf.sections)):
        return None
    section = elf.sections[symbol.section]
    if section.flags & SHF_EXECINSTR or (section.flags & SHF_WRITE and not section.name.startswith(CONSTANT_SECTIONS)):
        return None
    start = symbol.value + addend
    data = bytes(max(0, section.size - start)) if section.type == 8 else elf.data(section)[start:]
    known = symbol.size - addend if symbol.kind != "section" and symbol.size > addend else section.entsize
    return data, known, bool(section.flags & SHF_STRINGS), _unnamed(symbol)


PPC_ACCESS = {32: 4, 33: 4, 34: 1, 35: 1, 36: 4, 37: 4, 38: 1, 39: 1, 40: 2, 41: 2, 42: 2, 43: 2, 44: 2, 45: 2,
              48: 4, 49: 4, 50: 8, 51: 8, 52: 4, 53: 4, 54: 8, 55: 8, 56: 8, 57: 8}  # primary opcode -> bytes


def _access(machine: str, word: bytes) -> int | None:
    """Bytes a PowerPC load/store instruction reads or writes (lfs 4, lfd 8, psq_l 8, ...); None otherwise (an
    addi taking an address, another machine)."""
    return PPC_ACCESS.get(word[0] >> 2) if machine == "ppc" and len(word) == 4 else None


def _same_bytes(left: tuple, right: tuple, width: int | None = None) -> bool:
    """Two _referenced() constants hold the same value: a string up to its NUL; the bytes the instruction
    accesses; else data over the size either side knows (its symbol or the merge section's entry)."""
    if left[2] or right[2]:
        end_left, end_right = left[0].find(b"\0"), right[0].find(b"\0")
        return end_left >= 0 and left[0][:end_left] == right[0][:end_right]
    length = width or max(left[1], right[1])
    return length > 0 and len(left[0]) >= length and left[0][:length] == right[0][:length]


def _same_literal(a: Elf, xa: tuple, b: Elf, xb: tuple, width: int | None = None, original=None) -> bool:
    """Relocations naming different symbols for the same constant: read-only data one side leaves unnamed (a
    literal in a merge section, a generated label), compared by its bytes. Two named constants stay different."""
    if xa[0] != xb[0] or len(xa[3]) != len(xb[3]):
        return False
    for ia, aa, ib, ab in zip(xa[3], xa[2], xb[3], xb[2]):
        left, right = _referenced(a, ia, aa, original), _referenced(b, ib, ab)
        if left is None or right is None or not (left[3] or right[3]) or not _same_bytes(left, right, width):
            return False
    return True


def _unnamed(symbol) -> bool:
    """A target the object does not name for itself: a section, a compiler-numbered local, a splitter's lbl_."""
    return symbol.kind == "section" or not symbol.name or _anonymous(symbol.name, symbol.bind) or \
        symbol.name.startswith("lbl_")


def _same_place(a: Elf, xa: tuple, b: Elf, xb: tuple) -> bool:
    """Relocations to writable data at the same offset of a same-named section of each object, one side naming it
    only by place (the split object's lbl_805D7260 and the compiled __AR_InternalSize): the same variable, as
    objdiff judges it. Two named variables stay different; constants are compared by value elsewhere."""
    if xa[0] != xb[0]:
        return False
    for ia, aa, ib, ab in zip(xa[3], xa[2], xb[3], xb[2]):
        left = a.symbols[ia] if ia < len(a.symbols) else None
        right = b.symbols[ib] if ib < len(b.symbols) else None
        if left is None or right is None or not (0 < left.section < min(0xFF00, len(a.sections))) \
                or not (0 < right.section < min(0xFF00, len(b.sections))) \
                or not (_unnamed(left) or _unnamed(right) or _plain(left.name) == _plain(right.name)):
            return False
        section = a.sections[left.section]
        if section.name != b.sections[right.section].name or left.value + aa != right.value + ab \
                or section.flags & SHF_EXECINSTR or not section.flags & SHF_WRITE or section.name.startswith(CONSTANT_SECTIONS):
            return False
        length = left.size - aa if left.kind != "section" else 0
        if _code_targets(a, ia, aa, length) != _code_targets(b, ib, ab, length):
            return False  # a jump table at the same place with other case targets
    return True


def _names_at(elf: Elf, index: int, addend: int) -> set[str]:
    """Every symbol name defined at a relocation's target place (labels alias the function they start)."""
    symbol = elf.symbols[index] if index < len(elf.symbols) else None
    if symbol is None or not 0 < symbol.section < min(0xFF00, len(elf.sections)):
        return {symbol.name} if symbol else set()
    where = symbol.value + addend
    return {_plain(s.name) for s in elf.symbols if s.section == symbol.section and s.value == where and not _unnamed(s)}


def _plain(name: str) -> str:
    """A name without the compiler's static-local number (MWCC fontEncode$25 is fontEncode)."""
    return re.sub(r"\$\d+$", "", name)


def _same_alias(a: Elf, xa: tuple, b: Elf, xb: tuple) -> bool:
    """Relocations whose targets share a name in both objects (__OSDBINTEND and __OSDBJump at one address)."""
    return xa[0] == xb[0] and all(_names_at(a, ia, aa) & _names_at(b, ib, ab)
                                  for ia, aa, ib, ab in zip(xa[3], xa[2], xb[3], xb[2]))


def _same_structor(xa: tuple, xb: tuple) -> bool:
    """Relocations to a constructor's or destructor's two variants (C1 and C2, D1 and D2), which clang emits as one
    function under both names: a module that names it once is called by the other name from other units."""
    from .nxlink import structor_partner
    return xa[0] == xb[0] and xa[2] == xb[2] and all(
        x == y or structor_partner(x) == y for x, y in zip(xa[1], xb[1]))


def _branch(word: bytes, machine: str = "ppc") -> tuple[int, int] | None:
    """(instruction bits without the displacement, signed displacement) of a PowerPC b/bc or an AArch64 b/bl."""
    if machine == "aarch64":
        value = int.from_bytes(word, "little")
        if value >> 26 in (0x05, 0x25):
            return value & ~0x03FFFFFF, (((value & 0x03FFFFFF) ^ 0x02000000) - 0x02000000) * 4
        return None
    if machine != "ppc":
        return None
    value = int.from_bytes(word, "big")
    if value >> 26 == 18:
        return value & ~0x03FFFFFC, ((value & 0x03FFFFFC) ^ 0x02000000) - 0x02000000
    if value >> 26 == 16:
        return value & ~0xFFFC, ((value & 0xFFFC) ^ 0x8000) - 0x8000
    return None


def _same_branch(elf: Elf, function, offset: int, relocated: bytes, reloc: tuple, resolved: bytes) -> bool:
    """A branch one object relocates (the split object's `b fn+0x10`) and the other has resolved in place: the
    same instruction to the same offset of the same function (a recursive call to itself, which the split object
    resolved in place)."""
    left, right = _branch(relocated, elf.machine), _branch(resolved, elf.machine)
    if left is None or right is None or left[0] != right[0] or len(reloc[3]) != 1:
        return False
    symbol = elf.symbols[reloc[3][0]] if reloc[3][0] < len(elf.symbols) else None
    if symbol is None or symbol.section != function.section:
        return False
    return symbol.value + reloc[2][0] + left[1] - function.value == offset + right[1]


def _code_targets(elf: Elf, index: int, addend: int, length: int) -> list[tuple] | None:
    """(offset, function, offset into it) of every code address a data table (a switch's jump table) holds in
    [symbol + addend, + length); None when the symbol is not data or holds no code address."""
    symbol = elf.symbols[index] if index < len(elf.symbols) else None
    if symbol is None or not 0 < symbol.section < min(0xFF00, len(elf.sections)) or length <= 0:
        return None
    section = elf.sections[symbol.section]
    if section.flags & SHF_EXECINSTR:
        return None
    start, out = symbol.value + addend, []
    functions = [f for f in elf.functions().values()]
    for reloc in sorted(elf.relocations(section), key=lambda r: r.offset):
        if not start <= reloc.offset < start + length or reloc.symbol >= len(elf.symbols):
            continue
        target = elf.symbols[reloc.symbol]
        where = target.value + reloc.addend
        if elf.machine == "aarch64" and reloc.type == R_AARCH64_PREL32:
            where -= reloc.offset - start  # clang's `.word .LBB - .LJTI`: the code adds the entry to the table
        owner = next((f for f in functions if f.section == target.section and f.value <= where < f.value + f.size),
                     None)
        if owner is None:
            return None
        out.append((reloc.offset - start, owner.name, where - owner.value))
    if not out and elf.machine == "aarch64" and not section.flags & SHF_WRITE:
        return _resolved_targets(elf, index, start, length)
    return out or None


R_AARCH64_PREL32 = 261


def _resolved_targets(elf: Elf, index: int, start: int, length: int) -> list[tuple] | None:
    """`_code_targets` of an AArch64 jump table a split object holds resolved (s32 entries, each relative to the
    table, and no relocations), read at the original addresses its `.note.split` records: the same (offset,
    function, offset into it) a compiled table's relocations give. None without addresses, or when an entry lands
    in no function (the bytes are not a table of this unit's code)."""
    from .apply import _virtual
    virtual, symbol = _virtual(elf), elf.symbols[index]
    if len(virtual) != len(elf.symbols) or length % 4:
        return None
    placed = [i for i in [index] + list(range(len(elf.symbols))) if elf.symbols[i].section == symbol.section
              and elf.symbols[i].kind != "section" and virtual[i]]
    if not placed:
        return None
    base = virtual[placed[0]] - elf.symbols[placed[0]].value + start  # the table's original address
    functions = [(virtual[i], s) for i, s in enumerate(elf.symbols) if s.kind == "func" and s.size and virtual[i]]
    data, out = elf.data(elf.sections[symbol.section])[start:start + length], []
    if len(data) != length:
        return None
    for offset in range(0, length, 4):
        where = base + struct.unpack_from(elf.endian + "i", data, offset)[0]
        owner = next(((va, f) for va, f in functions if va <= where < va + f.size), None)
        if owner is None:
            return None
        out.append((offset, owner[1].name, where - owner[0]))
    return out


def _tables(a: Elf, xa: tuple, b: Elf, xb: tuple) -> list[tuple]:
    """(original, compiled) code targets of each relocated data table, over the size the original's symbol
    gives (a jump table the original names jumptable_X and the compiler leaves unnamed)."""
    out = []
    for ia, aa, ib, ab in zip(xa[3], xa[2], xb[3], xb[2]):
        symbol = a.symbols[ia] if ia < len(a.symbols) else None
        length = symbol.size - aa if symbol and symbol.kind != "section" else 0
        out.append((_code_targets(a, ia, aa, length), _code_targets(b, ib, ab, length)))
    return out


def _same_table(a: Elf, xa: tuple, b: Elf, xb: tuple) -> bool:
    return xa[0] == xb[0] and all(left is not None and left == right for left, right in _tables(a, xa, b, xb))


def _table_note(a: Elf, xa: tuple, b: Elf, xb: tuple) -> str | None:
    """Which entry of a jump table differs, when both sides are tables of code addresses."""
    for left, right in _tables(a, xa, b, xb):
        if left and right and left != right:
            first = next((x, y) for x, y in zip(left, right) if x != y) if len(left) == len(right) else None
            return ("jump table entries differ" + (f": +0x{first[0][0]:X} -> {first[0][1]}+0x{first[0][2]:X} vs "
                                                   f"{first[1][1]}+0x{first[1][2]:X}" if first else ""))
    return None


def _section_literal_differs(a: Elf, xa: tuple, b: Elf, xb: tuple, width: int | None = None) -> bool:
    """Relocations spelled alike (`<.rodata.cst4>+0`) to constants whose bytes differ: the names say nothing."""
    for ia, aa, ib, ab, name in zip(xa[3], xa[2], xb[3], xb[2], xa[1]):
        left, right = (_referenced(a, ia, aa), _referenced(b, ib, ab)) if name.startswith("<") else (None, None)
        if left and right and not _same_bytes(left, right, width):
            return True
    return False


def _find(elf: Elf, name: str):
    functions = elf.functions()
    if name in functions:
        return functions[name]
    return None


def _reloc_text(reloc: tuple | None) -> str | None:
    if not reloc:
        return None
    return ", ".join(f"{name}{addend:+#x}" if addend else name for name, addend in zip(reloc[1], reloc[2]))


def label_reader(project: Project, target: str):
    """name -> up to 256 of the original's bytes at a `lbl_<address>` (None for any other name or address)."""
    from .inspect_dol import _dol
    from .platform import for_target
    platform = for_target(project.target(target))
    image = _dol(project, target)

    def read(name: str) -> bytes | None:
        address = platform.parse(name[4:]) if name.startswith("lbl_") else None
        for size in (256, 64, 16):
            try:
                return platform.read(image, address, size) if address is not None else None
            except (ValueError, IndexError, struct.error):
                continue
        return None
    return read


def function_diff(target_path: Path, base_path: Path, name: str, base_name: str | None = None,
                  rename: dict[str, str] | None = None, limit: int = 24, labels=None) -> dict[str, Any]:
    """Compare one function in the original's object with the compiled one. `labels` (`label_reader`) reads the
    constants the original's object reaches only by a label another unit defines."""
    rename = rename or {}
    original, built = Elf.load(target_path), Elf.load(base_path)
    a, b = _find(original, name), _find(built, base_name or name)
    out: dict[str, Any] = {"function": name, "target": str(target_path), "base": str(base_path),
                           "machine": original.machine}
    if a is None:
        raise ValueError(f"{name} is not a function in {target_path}")
    if b is None:
        out.update(exact=False, missing=True, size=a.size,
                   message=f"the compiled object defines no function {base_name or name}; check the name/mangling "
                           f"(it defines {len(built.functions())} functions)")
        return out
    sa, sb = original.sections[a.section], built.sections[b.section]
    da = original.data(sa)[a.value:a.value + a.size]
    db = built.data(sb)[b.value:b.value + b.size]
    ra = _relocs(original, sa, a.value, a.value + a.size, {})
    rb = _relocs(built, sb, b.value, b.value + b.size, {v: k for k, v in rename.items()})
    width, machine = 4, original.machine
    rows = []
    literals = 0
    for offset in range(0, max(len(da), len(db)), width):
        wa, wb = da[offset:offset + width], db[offset:offset + width]
        xa, xb = ra.get(offset), rb.get(offset)
        if xa and not xb and _same_branch(original, a, offset, wa, xa, wb) or \
                xb and not xa and _same_branch(built, b, offset, wb, xb, wa):
            continue
        if wa != wb or (xa and xb and xa[0] != xb[0]) or bool(xa) != bool(xb):
            rows.append({"offset": offset, "original": wa.hex(), "compiled": wb.hex(),
                         "original_reloc": _reloc_text(xa), "compiled_reloc": _reloc_text(xb)})
        elif xa and xb and (xa[1] != xb[1] or xa[2] != xb[2]):
            if _same_place(original, xa, built, xb) or _same_alias(original, xa, built, xb) \
                    or _same_structor(xa, xb) \
                    or _same_literal(original, xa, built, xb, _access(machine, wa), labels) \
                    or _same_table(original, xa, built, xb):
                literals += 1
                continue
            rows.append({"offset": offset, "original": wa.hex(), "compiled": wb.hex(),
                         "original_reloc": _reloc_text(xa), "compiled_reloc": _reloc_text(xb), "reloc_only": True,
                         **({"note": note} if (note := _table_note(original, xa, built, xb)) else {})})
        elif xa and xb and _section_literal_differs(original, xa, built, xb, _access(machine, wa)):
            rows.append({"offset": offset, "original": wa.hex(), "compiled": wb.hex(),
                         "original_reloc": _reloc_text(xa), "compiled_reloc": _reloc_text(xb), "reloc_only": True,
                         "note": "the constants these relocations point at differ"})
    reloc_only = rows and all(r.get("reloc_only") for r in rows)
    out.update(exact=not rows and len(da) == len(db), size=len(da), compiled_size=len(db), differences=len(rows),
               reloc_only=bool(reloc_only), rows=rows[:limit])
    if literals:
        out["literal_relocations"] = literals  # the same place, constant or jump table under another symbol name
    if rows:
        out["first_difference"] = rows[0]["offset"]
    return out


GAP = re.compile(r"^gap_\d+_[0-9A-Fa-f]+_\w+$")  # the splitter's name for bytes no function claims


def unit_diff(target_path: Path, base_path: Path, rename: dict[str, str] | None = None) -> dict[str, Any]:
    """Every function of a unit: exact, differing (with the count of differing words), or missing. A gap the
    splitter named (gap_03_80395908_text) that the compiled object lacks is padding, listed apart."""
    original, built = Elf.load(target_path), Elf.load(base_path)
    names = sorted(original.functions(), key=lambda n: original.functions()[n].value)
    rows, gaps = [], []
    for name in names:
        try:
            result = function_diff(target_path, base_path, name, rename=rename, limit=0)
        except ValueError as error:
            rows.append({"function": name, "error": str(error)})
            continue
        if result.get("missing") and GAP.match(name):
            gaps.append(name)
            continue
        rows.append({"function": name, "exact": result["exact"], "size": result["size"],
                     "differences": result.get("differences"), "missing": result.get("missing", False),
                     "reloc_only": result.get("reloc_only", False)})
    extra = sorted(set(built.functions()) - set(original.functions()))
    return {"target": str(target_path), "base": str(base_path), "functions": rows,
            "exact": sum(1 for r in rows if r.get("exact")), "total": len(rows), "compiled_only": extra,
            "gaps": gaps}


# Identity: the same compiled program before and after a change that must not change code.

def _sections(elf: Elf) -> dict[str, bytes | int]:
    out: dict[str, bytes | int] = {}
    for section in elf.sections:
        if not section.name or SKIP_SECTIONS.match(section.name) or section.type in (0, 2, 3):
            continue
        out[section.name] = section.size if section.type == 8 else elf.data(section)
    return out


def _defined(elf: Elf, rename: dict[str, str]) -> dict[str, list[tuple]]:
    out: dict[str, list[tuple]] = {}
    for symbol in elf.symbols:
        if not symbol.name or symbol.kind in ("section", "file") or _anonymous(symbol.name, symbol.bind):
            continue
        if not 0 < symbol.section < 0xFF00:
            continue  # undefined: matters only through relocations
        where = elf.sections[symbol.section].name if symbol.section < len(elf.sections) else str(symbol.section)
        out.setdefault(rename.get(symbol.name, symbol.name), []).append((where, symbol.value, symbol.size, symbol.bind))
    return out


def _all_relocs(elf: Elf, rename: dict[str, str]) -> dict[str, list[tuple]]:
    out = {}
    for section in elf.sections:
        if not section.name or SKIP_SECTIONS.match(section.name) or section.type in (0, 2, 3, 4, 9):
            continue
        rows = []
        for reloc in elf.relocations(section):
            name = _symbol_name(elf, reloc.symbol)
            rows.append((reloc.offset, reloc.type, rename.get(name, name), reloc.addend))
        if rows:
            out[section.name] = rows
    return out


def identical(before: Path, after: Path, rename: dict[str, str] | None = None) -> list[str]:
    """Differences between two objects (empty: identical code and data), with `rename` (old -> new) applied."""
    rename = rename or {}
    a, b = Elf.load(before), Elf.load(after)
    problems = []
    sa, sb = _sections(a), _sections(b)
    for name in sorted(set(sa) | set(sb)):
        if sa.get(name) != sb.get(name):
            problems.append(f"section {name} differs" if name in sa and name in sb else
                            f"section {name} only {'before' if name in sa else 'after'}")
    ya, yb = _defined(a, rename), _defined(b, {})
    for name in sorted(set(ya) | set(yb)):
        if ya.get(name) != yb.get(name):
            problems.append(f"symbol {name}: {ya.get(name)} -> {yb.get(name)}")
    ra, rb = _all_relocs(a, rename), _all_relocs(b, {})
    for name in sorted(set(ra) | set(rb)):
        if ra.get(name) != rb.get(name):
            problems.append(f"relocations of {name} differ")
    return problems


def _store(project: Project, target: str) -> Path:
    from .activity import state_dir
    return state_dir(project) / "objects" / target


def save(project: Project, target: str, label: str = "saved") -> dict[str, Any]:
    """Copy every built object of the target (objdiff base_path) aside, to compare after a change."""
    units = objdiff_units(project, target)
    repo = project.target(target)["repository"]
    root = project.root(repo)
    folder = _store(project, target) / re.sub(r"[^\w.-]", "_", label)
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    copied = missing = 0
    started = time.monotonic()
    paths = [u["base_path"] for u in units.values() if u.get("base_path")]
    for relative in paths:
        source = root / relative
        if not source.is_file():
            missing += 1
            continue
        destination = folder / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1
    meta = {"label": label, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "objects": copied,
            "missing": missing, "seconds": round(time.monotonic() - started, 1)}
    (folder / "meta.json").write_text(json.dumps(meta) + "\n", encoding="utf-8")
    return meta


def compare_saved(project: Project, target: str, label: str = "saved", rename: dict[str, str] | None = None,
                  limit: int = 40) -> dict[str, Any]:
    """Every built object against its saved copy: identical, changed (with what changed), new or gone."""
    folder = _store(project, target) / re.sub(r"[^\w.-]", "_", label)
    if not (folder / "meta.json").is_file():
        raise ValueError(f"No saved objects named {label}: `zkit objects --save` first")
    meta = json.loads((folder / "meta.json").read_text(encoding="utf-8"))
    units = objdiff_units(project, target)
    root = project.root(project.target(target)["repository"])
    changed, identical_count, new, gone, stale = [], 0, [], [], []
    saved_at = datetime.fromisoformat(meta["time"]).timestamp()
    for name, unit in sorted(units.items()):
        relative = unit.get("base_path")
        if not relative:
            continue
        current, before = root / relative, folder / relative
        if not current.is_file():
            if before.is_file():
                gone.append(relative)
            continue
        if not before.is_file():
            new.append(relative)
            continue
        if current.stat().st_mtime < saved_at - 1 and current.read_bytes() == before.read_bytes():
            stale.append(relative)  # not rebuilt since the copy: it proves nothing about the change
        problems = identical(before, current, rename)
        if problems:
            changed.append({"object": relative, "unit": name, "problems": problems[:6], "count": len(problems)})
        else:
            identical_count += 1
    return {"label": label, "saved": meta, "identical": identical_count, "changed": changed[:limit],
            "changed_count": len(changed), "new": new[:limit], "gone": gone[:limit], "not_rebuilt": len(stale),
            "ok": not changed and not gone,
            "limits": "Allocated sections, defined symbols and relocations with compiler-numbered locals compared by "
                      "place; debug and comment sections ignored. Objects not rebuilt since the copy are counted: "
                      "run the build before comparing."}


def disassembly(project: Project, target: str, path: Path, function: str, machine: str) -> list[str]:
    """The project's disassembler on one function of an object, when one is available."""
    tool = None
    if machine == "aarch64":
        from .fetch import llvm_tool
        tool = llvm_tool("llvm-objdump")
        args = [tool, "-d", "-r", "--no-show-raw-insn", f"--disassemble-symbols={function}", str(path)] if tool else None
    else:
        from .inspect_dol import _objdump
        tool = _objdump(project)
        args = [tool, "-d", "-r", f"--disassemble={function}", "-M", "gekko", str(path)] if tool else None
    if not args:
        return []
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    lines = result.stdout.splitlines()
    start = next((i for i, l in enumerate(lines) if re.search(r"<.*>:$", l)), None)
    return [l.rstrip() for l in lines[start + 1:]] if start is not None else []
