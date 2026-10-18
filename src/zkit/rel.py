"""GameCube REL modules: the relocatable modules OSLink loads next to the DOL at run time.

A REL is a header (0x40 bytes in version 1; version 2 adds the section and .bss alignment, version 3 the size
OSLinkFixed may reclaim), a table of sections (file offset with bit 0 marking code, and size; offset 0 is a section
with no bytes in the file: .bss, or a slot the linker left empty), the section bytes, and for every module it
refers to (the DOL is module 0, the REL's own id is itself) a list of 8-byte relocations: the distance from the
previous one (u16), an R_PPC type (u8), the target section (u8) and the addend (u32). Three types steer a list:
R_DOLPHIN_SECTION starts patching another section at its offset 0, R_DOLPHIN_NOP only moves on (gaps over
0xFFFF), R_DOLPHIN_END closes it. A target in the DOL is an absolute address; in a module, a section offset.

The linker leaves every relocated field zero, apart from calls: a `b`/`bl` between two places of one section of
the module itself is applied by makerel and leaves the table, and every other one points at `_unresolved` until
OSLink patches it. So the tables say exactly what every reference names (as Switch's dynamic relocations do),
except those calls, which the bytes themselves hold.

Reading follows OSLink (every entry moves the position; R_DOLPHIN_SECTION resets it). Writing follows makerel:
sections in index order at their alignment, then relocations by module (version 3: other modules by id, then the
module itself, then the DOL, so OSLinkFixed can reclaim the last two; versions 1-2: by id), section and offset.
"""

from __future__ import annotations

import bisect
import itertools
import struct
from dataclasses import dataclass, field
from pathlib import Path

NONE, ADDR32, ADDR24, ADDR16, ADDR16_LO, ADDR16_HI, ADDR16_HA, ADDR14, ADDR14_BRTAKEN, ADDR14_BRNTAKEN, \
    REL24, REL14, REL14_BRTAKEN, REL14_BRNTAKEN = range(14)
DOLPHIN_NOP, DOLPHIN_SECTION, DOLPHIN_END = 201, 202, 203
HEADER = {1: 0x40, 2: 0x48, 3: 0x4C}
# The sections makerel keeps: everything else (debug, symbol and relocation tables) is an empty slot.
PERMITTED = (".init", ".text", ".ctors", ".dtors", ".rodata", ".data", ".bss")
SHT_NOBITS, SHF_EXECINSTR = 8, 4


@dataclass(frozen=True)
class Section:
    index: int
    offset: int           # in the file; 0: no bytes there (.bss, or an empty slot)
    size: int
    executable: bool
    align: int = 1        # what places it after the previous one (the ELF's, or what its offset proves)


@dataclass(frozen=True)
class Reloc:
    section: int          # section patched
    offset: int           # place of the patched field in it
    kind: int             # R_PPC_* type
    module: int           # module holding the target; 0 is the DOL
    target_section: int   # its section (for the DOL, the section index the linker's ELF gave)
    addend: int           # offset in target_section; in the DOL, the absolute address


@dataclass
class Rel:
    module_id: int
    version: int
    sections: list[Section]
    data: dict[int, bytes]                      # section index -> bytes, for the sections placed in the file
    relocations: list[Reloc]
    name_offset: int = 0                        # the module's name in the game's string table (framework.str)
    name_size: int = 0
    align: int | None = None                    # version 2+: the largest section alignment
    bss_align: int | None = None
    prolog: tuple[int, int] = (0, 0)            # (section, offset); section 0: none
    epilog: tuple[int, int] = (0, 0)
    unresolved: tuple[int, int] = (0, 0)
    imports: list[tuple[int, int]] = field(default_factory=list)   # (module, file offset of its list), as read
    fix_size: int | None = None                 # as read (version 3)

    @property
    def bss(self) -> Section | None:
        return next((s for s in self.sections if s.size and s.index not in self.data), None)


def _align_up(value: int, align: int) -> int:
    return value + (-value % max(align, 1))


def read(raw: bytes) -> Rel:
    """A REL file. Raises ValueError for anything OSLink would not load: a nonzero runtime link, an unknown version,
    a section or relocation list outside the file, more than one .bss, or a relocation type OSLink does not know."""
    if len(raw) < HEADER[1]:
        raise ValueError("Too small to be a REL")
    (module_id, following, previous, count, table, name_offset, name_size, version, bss_size, rel_offset,
     imp_offset, imp_size) = struct.unpack_from(">12I", raw)
    prolog_section, epilog_section, unresolved_section, bss_section = raw[0x30:0x34]
    prolog, epilog, unresolved = struct.unpack_from(">3I", raw, 0x34)
    if following or previous or bss_section or version not in HEADER or len(raw) < HEADER[version]:
        raise ValueError("Not a REL: its runtime links are set, or its version is not 1-3")
    align, bss_align = struct.unpack_from(">2I", raw, 0x40) if version >= 2 else (None, None)
    fix_size = struct.unpack_from(">I", raw, 0x48)[0] if version >= 3 else None
    if table + count * 8 > len(raw):
        raise ValueError("REL section table runs past the end of the file")
    sections, data = [], {}
    cursor = table + count * 8
    for index in range(count):
        word, size = struct.unpack_from(">2I", raw, table + index * 8)
        offset = word & ~1
        placed = 1
        if offset:
            if offset + size > len(raw):
                raise ValueError(f"REL section {index} runs past the end of the file")
            data[index] = raw[offset:offset + size]
            placed = _alignment(cursor, offset, align or 32)
            cursor = offset + size
        sections.append(Section(index, offset, size, bool(word & 1), placed))
    if len([s for s in sections if s.size and not s.offset]) > 1:
        raise ValueError("REL has more than one section without bytes (.bss)")
    if sum(s.size for s in sections if not s.offset) != bss_size:
        raise ValueError("REL .bss size disagrees with its section table")
    if imp_offset + imp_size > len(raw):
        raise ValueError("REL import table runs past the end of the file")
    imports = [struct.unpack_from(">2I", raw, imp_offset + i * 8) for i in range(imp_size // 8)]
    relocations = [reloc for module, start in imports for reloc in _relocations(raw, start, module)]
    return Rel(module_id, version, sections, data, relocations, name_offset, name_size, align, bss_align,
               (prolog_section, prolog), (epilog_section, epilog), (unresolved_section, unresolved), imports,
               fix_size)


def _alignment(previous_end: int, offset: int, largest: int) -> int:
    """The largest power of two up to `largest` that moves previous_end to offset (0 when none does: the bytes are
    out of order or a gap no alignment explains, which `write` reports)."""
    align = largest
    while align >= 1:
        if _align_up(previous_end, align) == offset:
            return align
        align //= 2
    return 0


def _relocations(raw: bytes, start: int, module: int) -> list[Reloc]:
    out = []
    section, position, at = None, 0, start
    while True:
        if at + 8 > len(raw):
            raise ValueError(f"REL relocation list for module {module} runs past the end of the file")
        distance, kind, target, addend = struct.unpack_from(">HBBI", raw, at)
        at += 8
        position += distance
        if kind == DOLPHIN_END:
            return out
        if kind == DOLPHIN_SECTION:
            section, position = target, 0
        elif kind not in (NONE, DOLPHIN_NOP):
            if kind > REL14_BRNTAKEN:
                raise ValueError(f"Unknown REL relocation type {kind} at 0x{at - 8:X}")
            if section is None:
                raise ValueError(f"REL relocation before any R_DOLPHIN_SECTION at 0x{at - 8:X}")
            out.append(Reloc(section, position, kind, module, target, addend))


def load(path: Path) -> Rel:
    """A REL file, Yaz0-compressed or not (discs ship both)."""
    from .archive import is_yaz0, yaz0
    raw = Path(path).read_bytes()
    return read(yaz0(raw) if is_yaz0(raw) else raw)


def module_id(path: Path) -> int:
    """The module id a REL file declares, from its header alone; ValueError when the header is not a REL's (games
    also use the .rel suffix for data of their own)."""
    from .archive import is_yaz0, yaz0
    with Path(path).open("rb") as stream:
        head = stream.read(0x34)
        if is_yaz0(head):
            head = yaz0(head + stream.read())[:0x34]
    if len(head) < 0x34:
        raise ValueError(f"{path} is too small to be a REL")
    number, following, previous = struct.unpack_from(">3I", head)
    version = struct.unpack_from(">I", head, 0x1C)[0]
    if following or previous or head[0x33] or version not in HEADER:
        raise ValueError(f"{path} is not a REL")
    return number


# Writing

def _order(rel: Rel):
    if rel.version >= 3:
        group = lambda r: 2 if r.module == 0 else 1 if r.module == rel.module_id else 0
        return lambda r: (group(r), r.module, r.section, r.offset)
    return lambda r: (r.module, r.section, r.offset)


def write(rel: Rel) -> bytes:
    """The REL file for a module: section bytes placed by alignment after the header and section table, then the
    import table and relocation lists laid out as makerel does (offsets, R_DOLPHIN_SECTION/NOP/END entries,
    fix_size are all derived, not copied)."""
    count = len(rel.sections)
    cursor = HEADER[rel.version] + count * 8
    offsets = {}
    for section in rel.sections:
        if section.index in rel.data:
            if not section.align:
                raise ValueError(f"REL section {section.index} has no alignment that places it")
            cursor = _align_up(cursor, section.align)
            offsets[section.index] = cursor
            cursor += section.size
    if rel.version >= 3:
        cursor = _align_up(cursor, 4)
    ordered = sorted(rel.relocations, key=_order(rel))
    lists: list[tuple[int, bytearray]] = []
    for module, rows in itertools.groupby(ordered, key=lambda r: r.module):
        out = bytearray()
        section, position = None, 0
        for reloc in rows:
            if reloc.section != section:
                out += struct.pack(">HBBI", 0, DOLPHIN_SECTION, reloc.section, 0)
                section, position = reloc.section, 0
            gap = reloc.offset - position
            while gap > 0xFFFF:
                out += struct.pack(">HBBI", 0xFFFF, DOLPHIN_NOP, 0, 0)
                gap -= 0xFFFF
            out += struct.pack(">HBBI", gap, reloc.kind, reloc.target_section, reloc.addend)
            position = reloc.offset
        lists.append((module, out + struct.pack(">HBBI", 0, DOLPHIN_END, 0, 0)))
    imp_size = 8 * len(lists)
    rel_offset = imp_offset = 0
    if lists:
        if rel.version >= 3:
            imp_offset, rel_offset = cursor, cursor + imp_size
        else:
            rel_offset = cursor
            imp_offset = cursor + sum(len(body) for _, body in lists)
    starts, at = [], rel_offset
    for module, body in lists:
        starts.append((module, at))
        at += len(body)
    end = at if lists else cursor
    fix_size = next((start for module, start in starts if module in (0, rel.module_id)), end)
    bss = rel.bss
    header = struct.pack(">12I", rel.module_id, 0, 0, count, HEADER[rel.version], rel.name_offset, rel.name_size,
                         rel.version, bss.size if bss else 0, rel_offset, imp_offset, imp_size)
    header += bytes([rel.prolog[0], rel.epilog[0], rel.unresolved[0], 0])
    header += struct.pack(">3I", rel.prolog[1], rel.epilog[1], rel.unresolved[1])
    if rel.version >= 2:
        header += struct.pack(">2I", rel.align or 0, rel.bss_align or 0)
    if rel.version >= 3:
        header += struct.pack(">I", fix_size)
    out = bytearray(header)
    for section in rel.sections:
        word = offsets.get(section.index, 0) | int(section.executable)
        out += struct.pack(">2I", word, section.size)
    for index, offset in offsets.items():
        out += bytes(offset - len(out))
        out += rel.data[index]
    out += bytes(cursor - len(out))
    imports = b"".join(struct.pack(">2I", module, start) for module, start in starts)
    bodies = b"".join(body for _, body in lists)
    out += imports + bodies if rel.version >= 3 else bodies + imports
    return bytes(out)


# Making a REL from a partially linked ELF (what makerel does)

def exports(elf, module: int) -> dict[str, tuple[int, int, int]]:
    """{name: (module, section, value)} for what one linked file offers other modules: its defined global and weak
    symbols (the DOL's ELF gives absolute addresses, a module's partially linked ELF section offsets)."""
    out: dict[str, tuple[int, int, int]] = {}
    for symbol in elf.symbols:
        if symbol.bind in ("global", "weak") and symbol.section and symbol.name:
            out.setdefault(symbol.name, (module, symbol.section if symbol.section < 0xFF00 else 0, symbol.value))
    return out


def make(elf, module: int, offered: dict[str, tuple[int, int, int]], version: int = 3,
         like: Rel | None = None) -> Rel:
    """The REL of a module's partially linked ELF: its loadable sections (.init .text .ctors .dtors .rodata .data
    .bss; every other ELF section keeps an empty slot, so section numbers stay the ELF's), its relocations resolved
    to the module itself or, for an undefined symbol, to the module `offered` names, and its calls applied as
    makerel does: within one section applied and dropped, any other in `_unresolved`'s section pointed at it.

    `like` (the original REL) gives what an ELF does not say: the module id, version, the name's place in the
    game's string table, the header alignments, the table's length and each slot's code flag."""
    if like is not None:
        module, version = like.module_id, like.version
    sections, data = [], {}
    for section in elf.sections:
        kept = section.name in PERMITTED
        executable = like.sections[section.index].executable if like and section.index < len(like.sections) else \
            kept and bool(section.flags & SHF_EXECINSTR)
        sections.append(Section(section.index, 0, section.size if kept else 0, executable, max(section.align, 1)))
        if kept and section.type != SHT_NOBITS:
            data[section.index] = elf.data(section)
    if like is not None:
        sections = sections[:len(like.sections)] + [Section(s.index, 0, 0, s.executable)
                                                    for s in like.sections[len(sections):]]
    entry = {s.name: (s.section, s.value) for s in elf.symbols
             if s.name in ("_prolog", "_epilog", "_unresolved") and 0 < s.section < 0xFF00}
    unresolved = entry.get("_unresolved", (0, 0))
    relocations = []
    for section in elf.sections:
        if section.name not in PERMITTED:
            continue
        for reloc in elf.relocations(section):
            symbol = elf.symbols[reloc.symbol]
            if not symbol.section:
                if symbol.name not in offered:
                    raise ValueError(f"{symbol.name} (from {section.name}+0x{reloc.offset:X}) is defined by no module")
                owner, target, value = offered[symbol.name]
            elif symbol.section >= 0xFF00:
                owner, target, value = 0, 0, symbol.value
            else:
                owner, target, value = module, symbol.section, symbol.value
            found = Reloc(section.index, reloc.offset, reloc.type, owner, target, (value + reloc.addend) & 0xFFFFFFFF)
            local = owner == module and target == section.index
            if found.kind == REL24 and (local or section.index == unresolved[0]):
                _branch(data, found, found.addend if local else unresolved[1])
                if local:
                    continue
            relocations.append(found)
    loaded = [s for s in sections if s.index < len(elf.sections) and elf.sections[s.index].name in PERMITTED]
    bss = next((s for s in loaded if elf.sections[s.index].type == SHT_NOBITS), None)
    align = like.align if like else max((s.align for s in loaded), default=1)
    bss_align = like.bss_align if like else bss.align if bss else 1
    return Rel(module, version, sections, data, relocations, like.name_offset if like else 0,
               like.name_size if like else 0, align if version >= 2 else None, bss_align if version >= 2 else None,
               entry.get("_prolog", (0, 0)), entry.get("_epilog", (0, 0)), unresolved)


def make_all(dol: Path, modules: list[Path], out: Path, like: list[Path] | None = None,
             version: int = 3) -> list[dict]:
    """RELs for partially linked modules against the DOL's linked ELF, written to out/<name>.rel. Undefined symbols
    resolve against the DOL, then the other modules (in the order given). Module ids come from the original REL of
    the same name in `like` (files, or folders searched for them), else count from 1 in order."""
    from .elf import Elf
    originals = {}
    for path in like or []:
        for found in ([path] if path.is_file() else sorted(path.rglob("*.rel"))):
            originals.setdefault(found.stem.lower(), found)
    elves = [Elf.load(path) for path in modules]
    likes = [load(originals[p.stem.lower()]) if p.stem.lower() in originals else None for p in modules]
    numbers = [l.module_id if l else index + 1 for index, l in enumerate(likes)]
    offered = exports(Elf.load(dol), 0)
    for elf, number in zip(elves, numbers):
        for name, value in exports(elf, number).items():
            offered.setdefault(name, value)
    rows = []
    for path, elf, number, original in zip(modules, elves, numbers, likes):
        written = write(make(elf, number, offered, version, original))
        target = out / f"{path.stem}.rel"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(written)
        source = originals.get(path.stem.lower())
        rows.append({"module": path.stem, "id": number, "rel": str(target), "bytes": len(written),
                     **({"like": str(source), "identical": source.read_bytes() == written} if source else {})})
    return rows


def info(rel: Rel) -> dict:
    """What a REL holds: its header, sections, and relocations counted per imported module and per type."""
    names = dict(enumerate("NONE ADDR32 ADDR24 ADDR16 ADDR16_LO ADDR16_HI ADDR16_HA ADDR14 ADDR14_BRTAKEN "
                           "ADDR14_BRNTAKEN REL24 REL14 REL14_BRTAKEN REL14_BRNTAKEN".split()))
    imports: dict[int, dict[str, int]] = {}
    for reloc in rel.relocations:
        counts = imports.setdefault(reloc.module, {})
        counts[names[reloc.kind]] = counts.get(names[reloc.kind], 0) + 1
    return {"module_id": rel.module_id, "version": rel.version, "align": rel.align, "bss_align": rel.bss_align,
            "name": [rel.name_offset, rel.name_size], "fix_size": rel.fix_size,
            "prolog": list(rel.prolog), "epilog": list(rel.epilog), "unresolved": list(rel.unresolved),
            "sections": [{"index": s.index, "offset": s.offset, "size": s.size, "code": s.executable,
                          "bss": bool(s.size) and s.index not in rel.data, "align": s.align}
                         for s in rel.sections if s.size or s.offset],
            "relocations": len(rel.relocations), "imports": {str(k): v for k, v in imports.items()}}


def _branch(data: dict[int, bytes], reloc: Reloc, destination: int) -> None:
    """Point the `b`/`bl` a REL24 relocation patches at an offset of its own section."""
    blob = bytearray(data[reloc.section])
    word = struct.unpack_from(">I", blob, reloc.offset)[0]
    struct.pack_into(">I", blob, reloc.offset, (word & ~0x03FFFFFC) | ((destination - reloc.offset) & 0x03FFFFFC))
    data[reloc.section] = bytes(blob)


# One address space for a module: what the delinker and the index read

def split_sections(path: Path) -> list[str]:
    """The section names a splits.txt `Sections:` block lists, in order: they name a REL's sections that have a
    size, in index order."""
    names, inside = [], False
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        if not line[0].isspace():
            inside = line.strip() == "Sections:"
        elif inside:
            names.append(line.split()[0])
    return names


class Module:
    """A REL laid out in one address space, the module loaded at 0: sections with bytes at their file offset,
    .bss after the file at its alignment. DOL addresses (0x80000000 up) never collide with these; another module's
    address is shifted by its id << 32. Section names come from the splits' Sections block when there is one."""

    def __init__(self, rel: Rel, names: list[str] | None = None):
        self.rel = rel
        sized = [s for s in rel.sections if s.size]
        if names and len(names) != len(sized):
            raise ValueError(f"The splits name {len(names)} sections; the REL has {len(sized)} with a size")
        self.names = {s.index: (names[i] if names else ".text" if s.executable else ".bss" if s.index not in rel.data
                                else f".section{s.index}") for i, s in enumerate(sized)}
        self.index = {name: index for index, name in self.names.items()}
        end = max((s.offset + s.size for s in rel.sections if s.index in rel.data), default=0)
        self.base = {s.index: s.offset for s in rel.sections if s.index in rel.data}
        bss = rel.bss
        if bss is not None:
            self.base[bss.index] = _align_up(end, rel.bss_align or 32)
        self.spans = sorted((self.base[i], self.base[i] + s.size, i) for i, s in enumerate(rel.sections)
                            if i in self.base and s.size)

    @property
    def code(self) -> int | None:
        """The code section (the largest, should a module have more than one): what module+0xOFFSET counts in."""
        found = [s for s in self.rel.sections if s.executable and s.size and s.index in self.rel.data]
        return max(found, key=lambda s: s.size).index if found else None

    def key(self, address: int, others: dict[int, "Module"] | None = None) -> int | None:
        """The index's key for an address `target` returned: a DOL address as it is, code of this or another module
        as (module id << 32) | offset in its code section; None for module data."""
        if 0x80000000 <= address < 1 << 32:
            return address
        number, local = (address >> 32, address & 0xFFFFFFFF) if address >> 32 else (self.rel.module_id, address)
        holder = self if number == self.rel.module_id else (others or {}).get(number)
        if holder is None or holder.code is None:
            return None
        offset = local - holder.base[holder.code]
        return (number << 32) | offset if 0 <= offset < holder.rel.sections[holder.code].size else None

    def place(self, section: str, offset: int) -> int | None:
        """The address of a section-relative offset (as symbols and splits write them)."""
        index = self.index.get(section)
        return None if index is None else self.base[index] + offset

    def section_at(self, address: int) -> int | None:
        for start, end, index in self.spans:
            if start <= address < end:
                return index
        return None

    def offset(self, address: int) -> int:
        """Section-relative offset of an address inside the module (what the split objects record)."""
        index = self.section_at(address)
        return address if index is None else address - self.base[index]

    def target(self, reloc: Reloc, others: dict[int, "Module"] | None = None) -> int:
        """The address a relocation names: absolute in the DOL, laid out here for this module, shifted by the
        module id for another (its layout when known, else section << 24 | offset)."""
        if reloc.module == 0:
            return reloc.addend
        if reloc.module == self.rel.module_id:
            return self.base.get(reloc.target_section, 0) + reloc.addend
        other = (others or {}).get(reloc.module)
        local = other.base.get(reloc.target_section, 0) + reloc.addend if other else \
            (reloc.target_section << 24) | reloc.addend
        return (reloc.module << 32) | local

    def read(self, address: int, size: int) -> bytes:
        index = self.section_at(address)
        if index is None or address + size > self.base[index] + self.rel.sections[index].size:
            raise ValueError(f"0x{address:X}+{size} is not inside one section of the module")
        if index not in self.rel.data:
            return bytes(size)
        start = address - self.base[index]
        return self.rel.data[index][start:start + size]

    def relocations(self, start: int, end: int) -> list[tuple[int, Reloc]]:
        """(address of the patched field, relocation) for the fields inside [start, end)."""
        if "_fields" not in self.__dict__:
            self._fields = sorted(((self.base.get(r.section, 0) + r.offset, r) for r in self.rel.relocations
                                   if r.section in self.base), key=lambda row: row[0])
            self._field_starts = [a for a, _ in self._fields]
        low, high = bisect.bisect_left(self._field_starts, start), bisect.bisect_left(self._field_starts, end)
        return self._fields[low:high]


def _mask(kind: int, field: int) -> int:
    """What an assembler leaves of the word holding a relocated field (the field itself zero)."""
    if kind in (ADDR16, ADDR16_LO, ADDR16_HI, ADDR16_HA):
        return 0xFFFF0000 if field % 4 else 0x0000FFFF
    if kind in (ADDR24, REL24):
        return 0xFC000003
    if kind in (ADDR14, ADDR14_BRTAKEN, ADDR14_BRNTAKEN, REL14, REL14_BRTAKEN, REL14_BRNTAKEN):
        return 0xFFFF0003
    return 0 if kind == ADDR32 else 0xFFFFFFFF


def code_relocations(module: Module, start: int, size: int, others: dict[int, Module] | None = None
                     ) -> tuple[list[tuple[int, int, int]], dict[int, int]]:
    """(field address, R_PPC type, target) for every reference one function's code makes, and its words as an
    assembler leaves them (relocated fields zero): the table's entries, which are exact, plus the calls makerel
    applied, decoded from the bytes (branches leaving the function the table does not list; ppc.py's control flow
    decides what leaves). No `lis`/`addi` pair is decoded: the table holds every one, with its fields zero."""
    from . import ppc
    words = list(struct.unpack(f">{size // 4}I", module.read(start, size - size % 4)))
    found, cleared = [], {}
    for field, reloc in module.relocations(start, start + size - size % 4):
        word_at = field - field % 4
        cleared[word_at] = cleared.get(word_at, words[(word_at - start) // 4]) & _mask(reloc.kind, field)
        found.append((field, reloc.kind, module.target(reloc, others)))
    for reloc in ppc.code_relocations(words, start, {}, lambda address: False)[0]:
        if reloc.offset not in cleared:
            found.append((reloc.offset, reloc.kind, reloc.target))
            cleared[reloc.offset] = words[(reloc.offset - start) // 4] & _mask(reloc.kind, reloc.offset)
    return sorted(found), cleared


_HEADS: dict[tuple[str, int], int | None] = {}
_SYMBOLS: dict[tuple[str, int], list] = {}


def cached_id(path: Path) -> int | None:
    """module_id, read once per process while the file stays the same; None for a file that is not a REL."""
    try:
        key = (str(path), path.stat().st_mtime_ns)
    except OSError:
        return None
    if key not in _HEADS:
        try:
            _HEADS[key] = module_id(path)
        except (OSError, ValueError):
            _HEADS[key] = None
    return _HEADS[key]


def _symbols(path: Path) -> list:
    from .gc import read_symbols
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _SYMBOLS:
        _SYMBOLS[key] = read_symbols(path)
    return _SYMBOLS[key]


_MODULES: dict[str, tuple[int, Module]] = {}


def cached(path: Path) -> Module:
    """A REL file as a Module, parsed once per process while the file stays the same."""
    stamp = path.stat().st_mtime_ns
    held = _MODULES.get(str(path))
    if held is None or held[0] != stamp:
        held = _MODULES[str(path)] = (stamp, Module(load(path)))
    return held[1]


def is_module(config: dict) -> bool:
    """A target whose original is a REL (a module the DOL target named by `host` loads)."""
    return str(config.get("original", "")).lower().endswith(".rel")


def target_module(project, target: str) -> Module:
    config = project.target(target)
    splits = project.file(config["repository"], config["splits"]) if config.get("splits") else None
    names = split_sections(splits) if splits is not None and splits.is_file() else None
    return Module(load(project.file(config["repository"], config["original"])), names or None)


def _module_targets(project, host: str | None) -> dict[int, str]:
    """{module id: target} for the project's REL targets loaded by the same DOL target."""
    out = {}
    for name, config in project.config.get("targets", {}).items():
        if is_module(config) and config.get("host") == host:
            found = cached_id(project.file(config["repository"], config["original"]))
            if found is not None:
                out.setdefault(found, name)
    return out


def image(project, target: str):
    """The delinker's reading of a REL target: names from its symbols (section-relative, placed through the
    splits' Sections block), the DOL target named by `host` for module-0 targets, and the project's other REL
    targets for modules it imports; every reference from the relocation tables, the applied calls from the bytes."""
    from .delink import PPC, Entry, Image, Symbols
    config = project.target(target)
    module = target_module(project, target)
    functions, data = [], []

    def add(symbols_path: Path, place) -> None:
        for symbol in _symbols(symbols_path):
            address = place(symbol.section, symbol.address)
            if address is None:
                continue
            if symbol.type == "function" and symbol.size:
                functions.append(Entry(address, symbol.size, symbol.name, symbol.scope))
            elif symbol.type in ("object", "label"):
                data.append(Entry(address, symbol.size if symbol.type == "object" else 0, symbol.name, symbol.scope,
                                  symbol.data))
    if config.get("symbols"):
        add(project.file(config["repository"], config["symbols"]), module.place)
    host = config.get("host")
    if host and project.target(host).get("symbols"):
        add(project.file(project.target(host)["repository"], project.target(host)["symbols"]), lambda s, a: a)
    imported = {r.module for r in module.rel.relocations} - {0, module.rel.module_id}
    others = {}
    for number, name in _module_targets(project, host).items():
        if number in imported:
            others[number] = target_module(project, name)
            other = project.target(name)
            if other.get("symbols"):
                add(project.file(other["repository"], other["symbols"]),
                    lambda s, a, m=others[number], n=number: None if m.place(s, a) is None else (n << 32) | m.place(s, a))
    text = lambda address: f"{address:08X}"
    symbols = Symbols(functions, data, text)

    def code(start: int, size: int, resolved) -> tuple[list, dict[int, int]]:
        found, cleared = code_relocations(module, start, size, others)
        return [(field, kind, destination, False) for field, kind, destination in found], cleared

    def pointers(start: int, end: int) -> list[tuple[int, int, str]]:
        return [(field, module.target(reloc, others), "relocation") for field, reloc in module.relocations(start, end)
                if reloc.kind == ADDR32]
    return Image(PPC, 0, module.read, symbols, lambda address: module.section_at(address) is not None, code,
                 pointers, text, place=module.place, virtual=module.offset)


# What the index reads: the REL files a DOL target loads, and each function's calls and DOL references

def module_files(project, target: str) -> dict[int, list[Path]]:
    """{module id: REL files} for the modules a DOL target loads: the files and folders its `modules` lists, else
    every .rel on its disc (the original's folder, or the folder above `sys/`), plus the REL targets naming it
    `host`. A file whose header is not a REL's is left out."""
    config = project.target(target)
    roots = [project.file(config["repository"], path) for path in config.get("modules") or []]
    if not roots and config.get("original"):
        folder = project.file(config["repository"], config["original"]).parent
        roots = [folder.parent if folder.name == "sys" else folder]
    paths = set()
    for root in roots:
        if root.is_file():
            paths.add(root)
        elif root.is_dir():
            paths.update(path for path in root.rglob("*") if path.suffix.lower() == ".rel" and path.is_file())
    for other in project.config.get("targets", {}).values():
        if is_module(other) and other.get("host") == target:
            paths.add(project.file(other["repository"], other["original"]))
    out: dict[int, list[Path]] = {}
    for path in sorted(paths):
        number = cached_id(path)
        if number is not None:
            out.setdefault(number, []).append(path)
    return out


def pick(paths: list[Path], name: str | None) -> Path | None:
    """The file for a module: the only one with its id, else the one named after it."""
    if len(paths) == 1:
        return paths[0]
    named = [p for p in paths if name and p.stem.lower() == name.lower()]
    return named[0] if len(named) == 1 else None


def access(word: int) -> str:
    """What an instruction does with the address its low half forms: load, store, f32/f64/psq (float loads) or
    addr (an address computed)."""
    from .gc import FP_LOADS, GPR_LOADS, STORES
    op = word >> 26
    return FP_LOADS.get(op) or ("store" if op in STORES else "load" if op in GPR_LOADS else "addr")


def edges(module: Module, start: int, size: int, others: dict[int, Module] | None = None
          ) -> tuple[list[tuple[int, int]], list[tuple[int, int, str]]]:
    """One function's direct calls (site, callee) for every `bl`, and its references to the DOL (pc, address,
    access) for every low half or word naming one, in index keys (module.key)."""
    calls, refs = [], []
    for field, kind, destination in code_relocations(module, start, size, others)[0]:
        word_at = field - field % 4
        word = struct.unpack(">I", module.read(word_at, 4))[0]
        site = module.key(word_at, others)
        if kind == REL24 and word & 3 == 1:
            callee = module.key(destination, others)
            if callee is not None and site is not None:
                calls.append((site, callee))
        elif kind in (ADDR16_LO, ADDR16, ADDR32) and 0x80000000 <= destination < 1 << 32 and site is not None:
            refs.append((site, destination, access(word)))
    return calls, refs
