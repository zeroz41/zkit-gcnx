"""Names from other builds: library fingerprints (the SDK, the C library, the runtime, middleware every game links)
and name transfer between builds of one game, proposed only where the evidence admits one name.

A function's shape is its instruction words with every relocated field cleared, as an assembler leaves them, and
the kind and place of each relocation: linked code gives them through `ppc.code_relocations`, a relocatable object
states them. Equal shapes are the same machine code wherever it was linked. Each relocation also says what it
refers to: a symbol the donor names (with its addend), a string by its text, or nothing (an unnamed literal).
A file-local symbol is known by its name and its file, so two files' `static OnReset` stay apart.

Donors are builds whose names are known: an original with its symbols (a decomp's symbols.txt, a CodeWarrior
linker map) or compiled objects and libraries. Their signatures are kept in zkit's cache, one file per donor,
never in a repository.

A target function takes a donor name when, among the donor functions of its shape that agree with what is known
about the target so far, exactly one name remains and no other function of that shape in the target has as much
evidence for it. Evidence is the references the target already resolves to the donor's symbols (or texts) and the
layout: the linker keeps a file's functions in order, so a matched neighbour that is the donor's neighbour too
places it. A shape shorter than `MINIMUM_WORDS` needs such evidence (copies, setters and thin wrappers repeat in
every game). A matched function names what it refers to (its callees and its data, at the address each reference
resolves to, where the donors agree), a named virtual table names its slots from the donors' table of its class
(slot to slot by the code in them, `aligned`), and a C function whose code changed is still found by the exact set
of texts it uses. A function named any other way whose code is its donors' names what it refers to too. Texts
compare without a drive letter (`evidence_text`). Code that differs from a donor sibling's only in immediates
(`Matcher.families`) needs its neighbours to agree. Between two functions an original donor places in one order
(`gaps`), the functions of one shape, or of one such family, pair in order (or, more copies of one shape on one
side, by their references), and what is left pairs as changed code: one on each side, the pair that shares by far
the most of what it refers to, or, aligned in order, the pair whose code is by far the most alike. A
function whose code changed still calls what it called: its one unnamed callee is its donors' one unclaimed callee,
and its calls pair with its donors' in order between the calls both name (`calls`, `call_order`); its other
references pair the same way and name the data, tables and functions they point into (`data_order`). Every name is
then checked: an address two pieces of evidence name differently, and a name two addresses claim, are withdrawn,
and the matching runs again without them. A function's own `__FILE__` (a path its code points at the start of)
names the file it was compiled in, so a name whose donor functions cite only other files is refuted for that
address, and so is a class table's name where a slot's function cites another file than the donor class's function
in that slot, with that class's own names in its slots; the address may still take another name. On the Switch a
C++ name is refuted for code that reads an argument register its parameters cannot fill (`Matcher.fits`): an
update that changed a function's parameters changed its name, which no donor has.

On the Switch a shape clears what `aarch64.code_relocations` relocates (calls and branches out of the function,
adrp pages and the low halves paired with them, adr and literal loads), and a class table is an Itanium `_ZTV`
object: offset-to-top and typeinfo, then one pointer per slot, read through the module's relocations. A
module's import stubs are named by what they import in every build, so a call to one agrees by name.
"""

from __future__ import annotations

import bisect
import collections
import gzip
import hashlib
import json
import math
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import ppc
from .platform import platform_name
from .program import CODE_SECTIONS, Function, Program

VERSION = 4
MINIMUM_WORDS = 16       # a shorter shape proves nothing alone: copies and setters repeat in every game
CONFIRMING = 2           # agreed references a shorter one needs (one is a thin wrapper of a call any game makes)
MINIMUM_STRINGS = 12     # characters of referenced text a string-set match needs
SHARED_BITS = 8.5        # what changed code must still share with its donor (-log2 of each reference's frequency)
SIMILAR = 0.5            # how alike changed code must be to pair by likeness (`_State.similar`)
SIMILAR_MARGIN = 0.05    # by how much it must beat every other pairing of either function in its gap
SIMILAR_PAIRS = 40000    # the largest gap (target functions times donor functions) compared that way
# AArch64 instructions that hold an immediate: (mask, value) of the class, then the immediate's bits
AARCH64_IMMEDIATES = ((0x3B000000, 0x39000000, 0x003FFC00),    # load/store, unsigned scaled offset
                      (0x3A000000, 0x28000000, 0x003F8000),    # load/store pair
                      (0x3B200000, 0x38000000, 0x001FF000),    # load/store, unscaled or indexed offset
                      (0x1F000000, 0x11000000, 0x007FFC00),    # add/sub (and cmp) immediate
                      (0x1F800000, 0x12800000, 0x007FFFE0),    # move wide
                      (0x1F800000, 0x12000000, 0x007FFC00),    # logical immediate
                      (0x1F800000, 0x13000000, 0x007FFC00))    # bitfield (shifts by a constant)
POWERPC_REGISTER_FORMS = {4, 16, 18, 19, 30, 31, 59, 63}         # no 16-bit immediate in the low half


def skeleton(word: int, switch: bool) -> int:
    """An instruction without its immediate (an offset, a constant, a shift)."""
    if switch:
        for mask, value, immediate in AARCH64_IMMEDIATES:
            if word & mask == value:
                return word & ~immediate
        return word
    return word if word >> 26 in POWERPC_REGISTER_FORMS else word & 0xFFFF0000
TEXT_LIMIT = 256

# The masks an assembler leaves on a relocated instruction, by relocation type.
MASKS = {ppc.REL24: 0xFC000003, ppc.REL14: 0xFFFF0003, ppc.EMB_SDA21: 0xFFE00000,
         ppc.ADDR16_LO: 0xFFFF0000, ppc.ADDR16_HI: 0xFFFF0000, ppc.ADDR16_HA: 0xFFFF0000, ppc.ADDR32: 0}
UNNAMED = re.compile(r"^(?:\.\.\.|@|\$\$|\.L)|\$\d+$|^(?:fn|lbl|func|FUN|sub|LAB|DAT|PTR|zz|unk|jumptable|switch|"
                     r"gap|pad|auto)_[0-9A-Fa-f_]*$|^(?:fn|lbl|func|sub|zz)_[0-9A-Fa-f]{6,8}(?:_|$)|_[0-9A-Fa-f]{8}$")


def unnamed(name: str | None) -> bool:
    """No name worth transferring: a compiler local (`@123`, a function's static numbered `name$123` per build),
    a generated label, an address-named placeholder."""
    return not name or bool(UNNAMED.search(name))


def key(name: str, scope: str, unit: str) -> str:
    """How a donor symbol is known: a global by its name, a file-local one by its name and its file's stem."""
    if scope != "local" or not unit:
        return name
    return f"{name}\0{Path(unit.split()[-1]).stem.lower()}"


def display(name: str) -> str:
    return name.split("\0", 1)[0]


TABLES = ("__vt__", "_ZTV")      # a class table: CodeWarrior's, Itanium's


def c_name(name: str) -> bool:
    """Neither a CodeWarrior nor an Itanium C++ name: a C function's, whose parameters its name does not claim."""
    from .cwnames import parse
    plain = display(name)
    return not plain.startswith("_Z") and parse(plain) is None


def identity(image) -> str:
    """The SHA-1 of an opened original: a DOL's bytes, a module's loaded image."""
    raw = getattr(image, "raw", None)
    return hashlib.sha1(raw if raw is not None else bytes(image.image)).hexdigest()


def aligned(ours: list, theirs: list) -> list[tuple[int, int]]:
    """(target slot, donor slot) pairs of two tables of one class, by the code in each slot (elements compared
    with ==, None equal to nothing). An update that adds or removes a virtual moves every slot after it, so a slot's
    index names nothing by itself. Code that is the same in both tables and occurs once in each anchors them; between
    two anchors (or the tables' ends), as many slots on both sides pair in order where their code is the same, or
    differs in single slots between same ones (changed in place). Two changed slots side by side, or a different
    count, could be a slot added next to one removed: they pair with nothing."""
    import difflib
    a = [x if x is not None else ("?", 0, i) for i, x in enumerate(ours)]
    b = [x if x is not None else ("?", 1, j) for j, x in enumerate(theirs)]
    once_a, once_b = collections.Counter(a), collections.Counter(b)
    anchors = [(-1, -1)]
    for i, j, size in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks():
        anchors += [(i + k, j + k) for k in range(size) if once_a[a[i + k]] == 1 and once_b[b[j + k]] == 1]
    anchors.append((len(a), len(b)))
    pairs = []
    for (i0, j0), (i1, j1) in zip(anchors, anchors[1:]):
        if i0 >= 0:
            pairs.append((i0, j0))
        if i1 - i0 != j1 - j0:
            continue
        span = [(i0 + k, j0 + k) for k in range(1, i1 - i0)]
        changed = [a[i] != b[j] for i, j in span]
        if not any(x and y for x, y in zip(changed, changed[1:])):
            pairs += span
    return pairs


def itanium_slots(image, address: int, count: int, starts) -> list[tuple[str, int | str | None]] | None:
    """`count` slots of an Itanium class table (after offset-to-top and typeinfo), read through the module's
    relocations: ("function", start) for a pointer to a function start, ("import", name) for an imported one,
    ("other", None) for anything else (a secondary table's header, a pointer elsewhere). None when the table
    leaves its segment."""
    out: list[tuple[str, int | str | None]] = []
    for index in range(count):
        holder = address + 16 + 8 * index
        segment = image.section_at(holder)
        if segment is None or holder + 8 > segment.offset + segment.size:
            return None
        if holder in image.imports:
            out.append(("import", image.imports[holder]))
            continue
        pointee = image.pointers.get(holder)
        out.append(("function", pointee) if pointee in starts else ("other", None))
    return out


# Shapes

@dataclass(frozen=True)
class Reference:
    offset: int                  # byte offset of the relocated instruction in the function
    kind: int
    token: tuple | None          # ("n", key, addend), ("s", text) or None


@dataclass
class Signature:
    """One donor function: its key, size and shape, what each relocation names, the unit it was in, the keys
    of the functions the donor placed before and after it, and its place in the donor original's layout (an
    original's functions only; an object's have none)."""
    key: str
    size: int
    shape: str
    references: tuple[Reference, ...]
    unit: str = ""
    donor: str = ""
    before: str | None = None
    after: str | None = None
    place: int | None = None
    code: str = ""               # an original's function: its masked words (hex), to compare changed code
    weak: bool = False           # an inline or a template instance: the copy the linker kept from some unit

    @property
    def name(self) -> str:
        return display(self.key)


@dataclass
class Shape:
    """One target function: its shape, the address each relocation resolves to and its masked words."""
    address: int
    size: int
    shape: str
    references: list[tuple[int, int, int]]     # (instruction offset, kind, target address)
    code: bytes = b""


def digest(words: list[int], relocations: Iterable[tuple[int, int]]) -> str:
    """The shape: masked words plus the (instruction offset, kind) of every relocation."""
    h = hashlib.blake2b(digest_size=10)
    h.update(struct.pack(f">{len(words)}I", *words))
    for offset, kind in sorted(relocations):
        h.update(struct.pack(">IH", offset, kind))
    return h.hexdigest()


def image_shape(program: Program, function: Function, sda: dict[int, int] | None = None) -> Shape | None:
    """The shape of a linked function and where its relocations point."""
    try:
        words = program.platform.words(program.image, function.address, function.size)
    except ValueError:
        return None
    if not words:
        return None
    if program.platform.name == "switch":
        from . import aarch64
        found, cleared = aarch64.code_relocations(words, function.address, program.image.pointers)
    else:
        found, cleared = ppc.code_relocations(words, function.address, program.sda if sda is None else sda,
                                              program.in_image)
    masked = [cleared.get(function.address + 4 * i, word) for i, word in enumerate(words)]
    references = [((r.offset - function.address) // 4 * 4, r.kind, r.target) for r in found]
    return Shape(function.address, 4 * len(words), digest(masked, ((o, k) for o, k, _ in references)), references,
                 struct.pack(f"<{len(masked)}I", *masked))


def small_data(program: Program) -> dict[int, int]:
    """r2 and r13: the program's own, or, where nothing names `__init_registers` (a fresh analysis), as the
    first function the entry point calls that sets both sets them."""
    from .program import _gamecube_sda
    if program.sda or not hasattr(program.image, "entry"):
        return program.sda
    entry = program.image.entry
    end = next((s.address + s.size for s in program.platform.sections(program.image)
                if s.address <= entry < s.address + s.size), entry)
    for _, target in program.platform.calls(program.image, entry, min(0x100, end - entry)):
        found = _gamecube_sda(program.image, target)
        if len(found) == 2:
            return found
    return {}


DRIVE = re.compile(r"^[A-Za-z]:(?=[/\\])")
SOURCE = re.compile(r"[^/\\]+\.(?:c|cc|cpp|cxx)$", re.IGNORECASE)    # a `__FILE__`: the file code was compiled in


def evidence_text(text: str | None) -> str | None:
    """A text as evidence: a source path without its drive letter, which is the build machine's (one build's
    `D:/...` is another's `C:/...` for the same file)."""
    return DRIVE.sub("", text) if text else text


def source_file(text: str | None) -> str | None:
    """The source file a path names (case folded), or None for any other text."""
    found = SOURCE.search(text) if text and ("/" in text or "\\" in text) else None
    return found.group().casefold() if found else None


def text_at(read, address: int) -> str | None:
    """A printable NUL-terminated string starting at an address (`read(address, size)` raises ValueError past
    the end of what it can read)."""
    for size in (TEXT_LIMIT, 64, 16, 4, 1):
        try:
            raw = read(address, size)
            break
        except ValueError:
            continue
    else:
        return None
    end = raw.find(b"\0")
    if end < 0:
        return None if size == TEXT_LIMIT else _text_slow(read, address)
    raw = raw[:end]
    if any(not (0x20 <= b < 0x7F or b in (9, 10, 13)) for b in raw):
        return None
    return raw.decode("ascii")


def _text_slow(read, address: int) -> str | None:
    out = bytearray()
    while len(out) < TEXT_LIMIT:
        try:
            byte = read(address + len(out), 1)[0]
        except (ValueError, IndexError):
            return None
        if byte == 0:
            return out.decode("ascii")
        if not (0x20 <= byte < 0x7F or byte in (9, 10, 13)):
            return None
        out.append(byte)
    return None


# Donors

@dataclass
class Donor:
    name: str
    signatures: list[Signature] = field(default_factory=list)
    tables: dict[str, list[str | None]] = field(default_factory=dict)   # vtable key -> slot keys
    sizes: dict[str, int] = field(default_factory=dict)                 # data key -> size
    images: list[str] = field(default_factory=list)                     # sha1 of the originals it was read from
    sources: list[str] = field(default_factory=list)
    built: str = ""
    layout: list[str | None] = field(default_factory=list)              # an original's shapes, function by function
    platform: str = ""                                                   # gamecube or switch (empty: unknown)
    weak: list[str] = field(default_factory=list)                        # data keys that are weak (an inline's
                                                                         # static, a template's member or table)


def _units(rows: list[tuple[int, int, str]]):
    ordered = sorted(rows)
    starts = [row[0] for row in ordered]

    def at(address: int) -> str:
        i = bisect.bisect_right(starts, address) - 1
        return ordered[i][2] if i >= 0 and address < ordered[i][1] else ""
    return at


def _neighbours(signatures: list[Signature], order: list[str | None]) -> None:
    """Set each signature's layout neighbours from the keys in layout order (None where unnamed)."""
    position = {k: i for i, k in enumerate(order) if k is not None}
    for signature in signatures:
        i = position.get(signature.key)
        if i is not None:
            signature.before = order[i - 1] if i else None
            signature.after = order[i + 1] if i + 1 < len(order) else None


def _named_initializers(program: Program, unit_of) -> Program:
    """A donor's unnamed static initializers named as clang names them, after the units that place them
    (`_GLOBAL__sub_I_<file>`): another build's initializer of the same file then carries that file over, where
    nothing else in its unit may survive (a file the linker dropped all but its initializer of)."""
    from dataclasses import replace
    from .analyze import _initializers
    from .score import placeholder
    own = {a for a, guarded in _initializers(program).items() if not guarded}
    functions = []
    for f in program.functions:
        unit = unit_of(f.address) if f.address in own and placeholder(f.name) else None
        if unit:
            file = re.sub(r"[^A-Za-z0-9_.]", "_", unit.rsplit("/", 1)[-1])
            f = replace(f, name=f"_GLOBAL__sub_I_{file}", scope="local")
        functions.append(f)
    return program.derived(functions)


def add_program(donor: Donor, program: Program, units: list[tuple[int, int, str]] = ()) -> None:
    """Every named function of an original with symbols, its named virtual tables' slots and the sizes of the
    data its functions name. `units` ((start, end, unit) of any section) places file-local symbols."""
    from .delink import Entry, Symbols
    unit_of = _units(list(units))
    if units and program.platform.name == "switch":
        program = _named_initializers(program, unit_of)
    symbols = Symbols([Entry(f.address, f.size, f.name, f.scope) for f in program.functions],
                      [Entry(o.address, o.size, o.name, o.scope) for o in program.objects]
                      + [Entry(o.address, 0, o.name, o.scope) for o in program.labels
                         if o.address not in program.function_index], lambda a: f"{a:08X}")
    starts = {f.address: f for f in program.functions}

    def known(address: int, name: str, scope: str | None) -> str | None:
        return None if unnamed(name) else key(name, scope or "global", unit_of(address))
    order, found = [], []
    first = len(donor.layout)
    # a weak function (an inline or a template instance) is the copy the linker kept from whichever unit came
    # first: its place says nothing about the unit another build keeps it from
    weak = getattr(program.image, "weak", set())
    for index, function in enumerate(program.functions):
        named = known(function.address, function.name, function.scope)
        order.append(named)
        shape = image_shape(program, function)
        donor.layout.append(shape.shape if shape is not None else None)
        if shape is None or not named:
            continue
        references = []
        for offset, kind, target in shape.references:
            token = None
            entry = starts.get(target)
            if entry is not None:
                name = known(target, entry.name, entry.scope)
                token = ("n", name, 0) if name else None
            else:
                holder = symbols.containing(target)
                name = known(holder.address, holder.name, holder.scope) if holder is not None else None
                if name:
                    token = ("n", name, target - holder.address)
                    if holder.size:
                        donor.sizes[name] = holder.size
                    if (holder.address in weak or holder.scope == "weak") and name not in donor.weak:
                        donor.weak.append(name)
                else:
                    text = text_at(program.read, target)
                    token = ("s", text) if text is not None else None
            references.append(Reference(offset, kind, token))
        inline = function.address in weak or function.scope == "weak"
        found.append(Signature(named, shape.size, shape.shape, tuple(references), "" if inline else
                               unit_of(function.address), donor.name, place=first + index, code=shape.code.hex(),
                               weak=inline))
    _neighbours(found, order)
    donor.signatures += found
    # a table's slots: a function's key ("" when the donor does not name it), an import's name, None for any other
    # word (a pure virtual, a secondary table's header)
    switch = program.platform.name == "switch"
    for table in program.objects:
        if switch and table.name.startswith("_ZTV") and table.size >= 24:
            slots = itanium_slots(program.image, table.address, (table.size - 16) // 8, starts)
            if slots is None:
                continue
            donor.tables[key(table.name, table.scope, unit_of(table.address))] = [
                known(v, starts[v].name, starts[v].scope) or "" if kind == "function" else v if kind == "import"
                else None for kind, v in slots]
            continue
        if switch or not table.name.startswith("__vt__") or table.size < 12:
            continue
        try:
            words = struct.unpack(f">{table.size // 4}I", program.read(table.address, table.size // 4 * 4))
        except ValueError:
            continue
        donor.tables[key(table.name, table.scope, unit_of(table.address))] = [
            known(w, starts[w].name, starts[w].scope) or "" if w in starts else None for w in words[2:]]
    donor.images.append(identity(program.image))
    donor.platform = program.platform.name


def add_object(donor: Donor, elf, unit: str = "") -> None:
    """Every function a relocatable PowerPC object defines (CodeWarrior's, or a delinker's), its virtual
    tables' slots and the sizes of the data its functions name."""
    from .elf import SHT_NOBITS
    rows: dict[int, list] = collections.defaultdict(list)
    for symbol in elf.symbols:
        if symbol.kind in ("func", "object") and 0 < symbol.section < 0xFF00:
            rows[symbol.section].append(symbol)
    for index, symbols in rows.items():
        section = elf.sections[index]
        data = elf.data(section)
        relocations = elf.relocations(section) if section.type != SHT_NOBITS else []
        order, found = [], []
        for symbol in sorted(symbols, key=lambda s: s.value):
            named = None if unnamed(symbol.name) else key(symbol.name, symbol.bind, unit)
            if symbol.kind == "object" and named and symbol.name.startswith("__vt__") and symbol.size >= 12:
                slots: list[str | None] = [None] * ((symbol.size - 8) // 4)
                for r in relocations:
                    if symbol.value + 8 <= r.offset < symbol.value + symbol.size and r.type == ppc.ADDR32:
                        token = _object_token(elf, r, unit, {})
                        slots[(r.offset - symbol.value - 8) // 4] = token[1] if token and token[0] == "n" else None
                donor.tables[named] = slots
            if symbol.kind != "func" or not symbol.size:
                continue
            order.append(named)
            if not named:
                continue
            body = data[symbol.value:symbol.value + symbol.size]
            words = list(struct.unpack(f">{len(body) // 4}I", body[:len(body) // 4 * 4]))
            references, places = [], []
            for r in relocations:
                if not symbol.value <= r.offset < symbol.value + len(words) * 4 or r.type not in MASKS:
                    continue
                word = (r.offset - symbol.value) // 4
                words[word] &= MASKS[r.type]
                places.append((word * 4, r.type))
                references.append(Reference(word * 4, r.type, _object_token(elf, r, unit, donor.sizes)))
            found.append(Signature(named, len(words) * 4, digest(words, places), tuple(references), unit,
                                   donor.name, weak=symbol.bind == "weak"))
        _neighbours(found, order)
        donor.signatures += found


def _object_token(elf, reloc, unit: str, sizes: dict[str, int]) -> tuple | None:
    symbol = elf.symbols[reloc.symbol] if reloc.symbol < len(elf.symbols) else None
    if symbol is None:
        return None
    if symbol.kind != "section" and not unnamed(symbol.name):
        named = key(symbol.name, symbol.bind, unit)
        if symbol.kind == "object" and symbol.size:
            sizes[named] = symbol.size
        return ("n", named, reloc.addend)
    if not 0 < symbol.section < min(0xFF00, len(elf.sections)):
        return None
    section = elf.sections[symbol.section]
    if section.flags & 0x4:                       # code: an unnamed local function or label
        return None
    data = elf.data(section)

    def read(address: int, size: int) -> bytes:
        if address + size > len(data):
            raise ValueError("past the section")
        return data[address:address + size]
    text = text_at(read, (0 if symbol.kind == "section" else symbol.value) + reloc.addend)
    return ("s", text) if text is not None else None


def archive_members(raw: bytes) -> Iterable[tuple[str, bytes]]:
    """(name, bytes) of every member of a Unix `ar` archive (GNU and BSD long names)."""
    if not raw.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    cursor, names = 8, b""
    while cursor + 60 <= len(raw):
        header = raw[cursor:cursor + 60]
        name, size = header[:16].decode("latin1").rstrip(), int(header[48:58].decode("latin1").strip() or 0)
        body = raw[cursor + 60:cursor + 60 + size]
        cursor += 60 + size + (size & 1)
        if name == "//":
            names = body
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        if name.startswith("#1/"):
            length = int(name[3:])
            name, body = body[:length].decode("latin1").rstrip("\0"), body[length:]
        elif name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            name = names[start:names.index(b"\n", start)].decode("latin1").rstrip("/")
        else:
            name = name.rstrip("/")
        yield name, body


def objects_in(paths: Iterable[Path]) -> Iterable[tuple[str, bytes]]:
    """(unit, bytes) of every object in files, folders of them and `ar` archives."""
    for path in paths:
        files = sorted(p for p in path.rglob("*") if p.suffix in (".o", ".a")) if path.is_dir() else [path]
        for file in files:
            raw = file.read_bytes()
            if raw.startswith(b"!<arch>\n"):
                for member, body in archive_members(raw):
                    yield f"{file.stem}/{member}", body
            else:
                yield str(file.relative_to(path)) if path.is_dir() else file.name, raw


def map_program(platform, image: Path, map_path: Path) -> tuple[Program, list[tuple[int, int, str]]]:
    """An original named by a CodeWarrior linker map, and the map's units. A map does not mark file-local
    symbols, but a name it lists twice can only be one."""
    from . import mwmap
    from .gc import Symbol
    split = mwmap.read(map_path)
    count = collections.Counter([n for _, n in split.functions.values()] + [o[1] for o in split.objects.values()])
    scope = lambda name: "local" if count[name] > 1 else "global"
    symbols = [Symbol(name, ".text", address, "function", size, scope(name))
               for address, (size, name) in split.functions.items()]
    symbols += [Symbol(name, section, address, "object", size, scope(name))
                for address, (size, name, section) in split.objects.items()]
    units = [(start, end, unit) for unit, rows in split.units.items() for _, start, end in rows]
    return Program.from_symbol_list(platform, platform.open(image), symbols), units


def build(name: str, image: Path | None = None, symbols: Path | None = None, map_path: Path | None = None,
          splits: Path | None = None, objects: Iterable[Path] = ()) -> Donor:
    """A donor: an original (a DOL or disc image, or a Switch NSO or ELF) with its symbols.txt (and splits.txt,
    which places file-local names) or with a CodeWarrior map, and/or compiled objects and libraries."""
    from .elf import Elf
    from .gc import read_splits
    from .platform import GameCube, Switch
    donor = Donor(name, built=time.strftime("%Y-%m-%dT%H:%M:%S"))
    if image is not None:
        with image.open("rb") as stream:
            platform = Switch() if stream.read(4) in (b"NSO0", b"\x7fELF") else GameCube()
        if map_path is not None:
            program, units = map_program(platform, image, map_path)
        elif symbols is not None:
            program = Program.from_symbols(platform, image, symbols)
            units = [(start, end, unit) for unit, _, start, end in read_splits(splits)] if splits else []
        else:
            raise ValueError("An original needs its names: a symbols.txt or a linker map")
        add_program(donor, program, units)
        donor.sources.append(f"{image} named by {map_path or symbols}")
    for unit, raw in objects_in(objects):
        try:
            elf = Elf(raw, unit)
        except ValueError:
            continue
        if elf.machine == "ppc" and elf.type == 1:
            add_object(donor, elf, unit)
            donor.platform = "gamecube"
    donor.sources += [str(p) for p in objects]
    if not donor.signatures:
        raise ValueError(f"No named functions found for {name}")
    return donor


def folder() -> Path:
    from .paths import cache_home
    return cache_home() / "signatures"


def _path(name: str) -> Path:
    return folder() / f"{re.sub(r'[^\w.-]', '_', name)}.json.gz"


def save(donor: Donor) -> Path:
    path = _path(donor.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [[s.shape, s.key, s.size, s.unit, s.before, s.after,
             [[r.offset, r.kind, list(r.token) if r.token else None] for r in s.references], s.place, s.code,
             s.weak] for s in donor.signatures]
    data = {"version": VERSION, "name": donor.name, "built": donor.built, "sources": donor.sources,
            "images": donor.images, "tables": donor.tables, "sizes": donor.sizes, "layout": donor.layout,
            "platform": donor.platform, "functions": rows, "weak": donor.weak}
    temporary = path.with_name(path.name + ".partial")
    with gzip.open(temporary, "wt", encoding="utf-8") as stream:
        json.dump(data, stream, separators=(",", ":"))
    temporary.replace(path)
    return path


def load(name: str) -> Donor:
    path = _path(name)
    if not path.is_file():
        raise ValueError(f"No signatures named {name!r} (have: {', '.join(listed()) or 'none'}); build them with "
                         f"`zkit signatures build`")
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        data = json.load(stream)
    if data.get("version") != VERSION:
        raise ValueError(f"Signatures {name!r} were built by another zkit version; build them again")
    signatures = [Signature(k, size, shape, tuple(Reference(o, kind, tuple(t) if t else None) for o, kind, t in refs),
                            unit, data["name"], before, after, place, code, bool(weak and weak[0]))
                  for shape, k, size, unit, before, after, refs, place, code, *weak in data["functions"]]
    return Donor(data["name"], signatures, data["tables"], data["sizes"], data["images"], data["sources"],
                 data["built"], data["layout"], data["platform"], data.get("weak", []))


def listed() -> list[str]:
    base = folder()
    return sorted(p.name[:-len(".json.gz")] for p in base.glob("*.json.gz")) if base.is_dir() else []


def remove(name: str) -> bool:
    path = _path(name)
    if path.is_file():
        path.unlink()
        return True
    return False


# Matching a target against donors

@dataclass
class Proposal:
    address: int
    name: str
    kind: str                     # function, label (a place inside a function the code refers to) or object
    evidence: str                 # shape, shape+references, shape+layout, reference, slot, table, strings
    size: int = 0                 # the donors' size of the symbol, when they agree on one
    donors: tuple[str, ...] = ()
    unit: str = ""                # the donor unit it was in, when the donors agree on one
    source: int | None = None     # the function (or table) whose reference named it
    agreed: int = 0               # references and neighbours the target agreed with when its shape matched
    weak: bool = False            # every donor's function of that name is weak: an inline or template instance


def _canonical(donors: list[Donor]) -> dict[str, str]:
    """{plain key: file-local key} where donors disagree on a symbol's linkage (one build's static is another's
    global, a decomp's sources drop `static`) and only one file-local symbol has that name: one function."""
    keys = {k for d in donors for s in d.signatures for k in (s.key, s.before, s.after) if k}
    keys |= {r.token[1] for d in donors for s in d.signatures for r in s.references if r.token and r.token[0] == "n"}
    local: dict[str, list[str]] = collections.defaultdict(list)
    for k in keys:
        if "\0" in k:
            local[display(k)].append(k)
    return {name: found[0] for name, found in local.items() if len(found) == 1 and name in keys}


def _canonical_signature(signature: Signature, same: dict[str, str]) -> Signature:
    """A donor signature with the keys `same` renames renamed and its texts as evidence (`evidence_text`)."""
    from dataclasses import replace
    get = lambda k: same.get(k, k) if k else k
    token = lambda t: ("n", get(t[1]), t[2]) if t[0] == "n" else ("s", evidence_text(t[1]))
    return replace(signature, key=get(signature.key), before=get(signature.before), after=get(signature.after),
                   references=tuple(Reference(r.offset, r.kind, token(r.token)) if r.token else r
                                    for r in signature.references))


class Matcher:
    """The target's shapes against every donor signature."""

    def __init__(self, program: Program, donors: list[Donor]):
        self.program = program
        self.by_shape: dict[str, list[Signature]] = collections.defaultdict(list)
        self.by_key: dict[str, list[Signature]] = collections.defaultdict(list)
        self.tables: dict[str, list[list[str | None]]] = collections.defaultdict(list)
        self.sizes: dict[str, set[int]] = collections.defaultdict(set)
        same = _canonical(donors)
        self.weak = {same.get(name, name) for donor in donors for name in donor.weak}
        for donor in donors:
            for signature in donor.signatures:
                if same or any(r.token and r.token[0] == "s" and DRIVE.match(r.token[1]) for r in signature.references):
                    signature = _canonical_signature(signature, same)
                self.by_shape[signature.shape].append(signature)
                self.by_key[signature.key].append(signature)
            for name, slots in donor.tables.items():
                self.tables[same.get(name, name)].append([same.get(k, k) for k in slots])
            for name, size in donor.sizes.items():
                self.sizes[same.get(name, name)].add(size)
        self._arguments: dict[int, set[int]] = {}           # address -> argument registers its code reads
        self._capacity: dict[str, tuple[int, int] | None] | None = None
        self._donor_arguments: dict[str, set[int]] = {}     # key -> argument registers its donors' code reads
        functions = program.functions
        self.extent = {f.address: f.size for f in functions}
        self.neighbours = {f.address: (functions[i - 1].address if i else None,
                                       functions[i + 1].address if i + 1 < len(functions) else None)
                           for i, f in enumerate(functions)}
        self.shapes: dict[int, Shape] = {}
        self.groups: dict[str, list[int]] = collections.defaultdict(list)
        sda = small_data(program)
        for function in functions:
            shape = image_shape(program, function, sda)
            if shape is not None:
                self.shapes[function.address] = shape
                if shape.shape in self.by_shape:
                    self.groups[shape.shape].append(function.address)
        # per shape: the donor functions that refer to something nameable, the others by key, and the others
        # by the keys of their layout neighbours
        self.plain: dict[str, tuple] = {}
        self.keys: dict[str, set[str]] = {}
        for shape in self.groups:
            referring, plain = [], collections.defaultdict(list)
            before, after = collections.defaultdict(list), collections.defaultdict(list)
            for signature in self.by_shape[shape]:
                if any(r.token for r in signature.references):
                    referring.append(signature)
                    continue
                plain[signature.key].append(signature)
                before[signature.before].append(signature)
                after[signature.after].append(signature)
            before.pop(None, None)
            after.pop(None, None)
            self.plain[shape] = (referring, plain, before, after)
            self.keys[shape] = {s.key for s in self.by_shape[shape]}
        # what a group's decision depends on: the addresses its references and neighbours name, and its keys
        # (and per target function of a group, the addresses whose names its options depend on: `watchers`)
        self.dependents: dict[int, set[str]] = collections.defaultdict(set)
        self.watchers: dict[int, set[tuple[str, int]]] = collections.defaultdict(set)
        self.key_groups: dict[str, set[str]] = collections.defaultdict(set)
        for shape, addresses in self.groups.items():
            for signature in self.by_shape[shape]:
                self.key_groups[signature.key].add(shape)
            for address in addresses:
                for neighbour in self.neighbours[address]:
                    if neighbour is not None:
                        self.dependents[neighbour].add(shape)
                        self.watchers[neighbour].add((shape, address))
                for offset, _, target in self.shapes[address].references:
                    for addend in {r.token[2] for s in self.by_shape[shape] for r in s.references
                                   if r.offset == offset and r.token and r.token[0] == "n"}:
                        self.dependents[target - addend].add(shape)
                        self.watchers[target - addend].add((shape, address))
        self._texts: dict[int, str | None] = {}
        self._code: dict[int, tuple[int, ...]] = {}
        self._family: dict[int, tuple] | None = None
        self._families: set[tuple] = set()
        self._text_sets: tuple | None = None
        self._vtables = None
        # each donor original's layout, and its named functions by place
        self.layouts = {donor.name: donor.layout for donor in donors if donor.layout}
        self.placed = {(s.donor, s.place): s for entries in self.by_key.values() for s in entries
                       if s.place is not None}
        self._weights: dict[tuple, float] | None = None
        self._structors: dict[str, str] | None = None

    def structor(self, key: str) -> str | None:
        """A donor constructor's or destructor's name without its variant (C1, C2, C3; D0, D1, D2), as its
        demangled text: the same for every variant of one class's structor, None for any other name."""
        if self._structors is None:
            from .platform import demangle_itanium
            keys = sorted({display(k) for k in self.by_key if display(k).startswith("_ZN")})
            self._structors = {}
            for k, text in zip(keys, demangle_itanium(keys)):
                head, depth = "", 0
                for c in (text or "").split("(", 1)[0]:          # the name without template arguments
                    depth += (c == "<") - (c == ">")
                    head += c if depth == 0 and c != ">" else ""
                last, _, member = head.rpartition("::")
                if text and last and member.lstrip("~") == last.rpartition("::")[2]:
                    self._structors[k] = text
        return self._structors.get(display(key)) if key else None

    def uses(self, signature: Signature) -> set[tuple]:
        """What a donor function refers to by name or by text: ("n", key) and ("s", text) of four characters or
        more."""
        return {("n", r.token[1]) if r.token[0] == "n" else ("s", r.token[1]) for r in signature.references
                if r.token and (r.token[0] == "n" or len(r.token[1]) >= 4)}

    def weight(self, use: tuple) -> float:
        """Bits a shared reference is worth: -log2 of the share of donor functions that make it."""
        if self._weights is None:
            counts = collections.Counter(u for entries in self.by_key.values() for s in entries for u in self.uses(s))
            total = sum(len(entries) for entries in self.by_key.values())
            self._weights = {u: math.log2(total / (1 + n)) for u, n in counts.items()}
        return self._weights.get(use, 0.0)

    def code(self, item: Shape | Signature) -> tuple[int, ...]:
        """The masked words of a target function's shape or a donor original's function."""
        found = self._code.get(id(item))
        if found is None:
            raw = item.code if isinstance(item.code, bytes) else bytes.fromhex(item.code)
            found = self._code[id(item)] = struct.unpack(f"<{len(raw) // 4}I", raw)
        return found

    def families(self) -> dict[int, tuple]:
        """{id of a donor signature: its family} for donor functions that refer to the same things as another and
        differ from it only in immediates (a field offset, a virtual's slot, a constant): which of them a target
        with that code is rests on the immediates, and an update that moves a field or a slot moves them."""
        if self._family is None:
            self._family = {}
            switch = self.program.platform.name == "switch"
            buckets: dict[tuple, list[Signature]] = collections.defaultdict(list)
            for entries in self.by_key.values():
                for s in entries:
                    if s.code:
                        buckets[(s.size, s.references)].append(s)
            for rows in buckets.values():
                if len({s.shape for s in rows}) < 2:
                    continue
                skeletons: dict[tuple, list[Signature]] = collections.defaultdict(list)
                for s in rows:
                    skeletons[tuple(skeleton(w, switch) for w in self.code(s))].append(s)
                for words, found in skeletons.items():
                    if len({s.shape for s in found}) > 1:
                        self._family.update((id(s), ("family", hash(words))) for s in found)
            self._families = set(self._family.values())
        return self._family

    def twinned(self, signature: Signature) -> bool:
        return id(signature) in self.families()

    def group(self, address: int | None = None, signature: Signature | None = None, shape: str | None = None):
        """What a function pairs by in a gap: its shape, or its family (`families`), whose members pair in order
        like copies of one shape."""
        families = self.families()
        if signature is not None:
            return families.get(id(signature), shape if shape is not None else signature.shape)
        switch = self.program.platform.name == "switch"
        key = ("family", hash(tuple(skeleton(w, switch) for w in self.code(self.shapes[address]))))
        return key if key in self._families else self.shapes[address].shape

    def sources(self, address: int) -> set[str]:
        """The source files a target function's code cites: the paths that start where it points (an address
        inside a string is another literal's tail, merged into it)."""
        shape, strings = self.shapes.get(address), self.program.strings()
        return {f for _, _, t in shape.references if t in strings and (f := source_file(strings[t]))} if shape \
            else set()

    def donor_sources(self, key: str) -> set[str]:
        """The source files the donors' functions of a key cite."""
        return {f for e in self.by_key.get(key, ()) for r in e.references
                if r.token and r.token[0] == "s" and (f := source_file(r.token[1]))}

    def text(self, address: int) -> str | None:
        if address not in self._texts:
            self._texts[address] = evidence_text(text_at(self.program.read, address))
        return self._texts[address]

    def texts(self) -> tuple[dict[tuple, set[str]], dict[tuple, list[int]]]:
        """{texts: donor C keys} for donor functions using enough text, and {texts: target functions} for the
        target functions using exactly such a set."""
        if self._text_sets is None:
            donor_sets: dict[tuple, set[str]] = collections.defaultdict(set)
            for named, entries in self.by_key.items():
                if not c_name(named):
                    continue
                for signature in entries:
                    texts = tuple(sorted({r.token[1] for r in signature.references if r.token and r.token[0] == "s"}))
                    if texts and sum(map(len, texts)) >= MINIMUM_STRINGS:
                        donor_sets[texts].add(named)
            target_sets: dict[tuple, list[int]] = collections.defaultdict(list)
            for address, shape in self.shapes.items():
                texts = tuple(sorted({t for _, _, a in shape.references if (t := self.text(a)) is not None}))
                if texts in donor_sets:
                    target_sets[texts].append(address)
            self._text_sets = (donor_sets, target_sets)
        return self._text_sets

    def vtables(self):
        if self._vtables is None:
            from . import vtables
            self._vtables = vtables.find(self.program) if self.tables else {}
        return self._vtables

    def slot_classes(self) -> dict[tuple[int, str], set[str]]:
        """{(slot, key): the donor `_ZTV` classes whose table names that key in that slot}."""
        if getattr(self, "_slot_classes", None) is None:
            self._slot_classes = collections.defaultdict(set)
            for cls, rows in self.tables.items():
                if cls.startswith("_ZTV"):
                    for row in rows:
                        for i, k in enumerate(row):
                            if k:
                                self._slot_classes[(i, k)].add(cls)
        return self._slot_classes

    def itanium_tables(self) -> dict[int, list[tuple[str, int | str | None]]]:
        """Switch: every primary class table the code forms the address point of (offset-to-top zero, typeinfo
        zero without RTTI or a pointer into data with it, a function or an import in the first slot), by the
        table's start, with its slots up to the first word that is neither."""
        from .itanium import typeinfo_word
        if self._vtables is None:
            self._vtables = {}
            image, formed = self.program.image, set()
            if self.tables:
                for rows in self.program.refs.values():
                    formed.update(address for _, address, kind in rows if kind == "addr")
            for point in sorted(formed):
                start = point - 16
                if start < 0 or image.section_at(start) is None or point % 8 or image.section_at(point) is None:
                    continue
                if start in image.pointers or image.u64(start) or typeinfo_word(image, point - 8) is None:
                    continue
                slots = []
                while True:
                    slot = itanium_slots(image, start + 8 * len(slots), 1, self.extent)
                    if slot is None or slot[0][0] == "other":
                        break
                    slots += slot
                if slots:
                    self._vtables[start] = slots
        return self._vtables

    def fits(self, address: int, key: str) -> bool:
        """Whether a Switch function's code can carry a C++ name: every argument register some path reads before
        writing (`aarch64.argument_reads`) is one the name's parameters fill (`itanium.argument_registers`), or
        one the donors' code under that name reads as well."""
        if self.program.platform.name != "switch" or address not in self.extent:
            return True
        from .aarch64 import V, argument_reads
        name = display(key)
        if not re.match(r"_Z[NL0-9]", name):
            return True
        if self._capacity is None:
            from .platform import demangle_itanium
            from .itanium import argument_registers
            keys = sorted({display(k) for k in self.by_key if re.match(r"_Z[NL0-9]", display(k))})
            self._capacity = {k: argument_registers(d) if d else None
                              for k, d in zip(keys, demangle_itanium(keys))}
        capacity = self._capacity.get(name)
        if capacity is None:
            return True
        if address not in self._arguments:
            try:
                words = self.program.platform.words(self.program.image, address, self.extent[address])
            except ValueError:
                words = []
            self._arguments[address] = argument_reads(words, address) if words else set()
        general, vector = capacity
        extra = {r for r in self._arguments[address] if not (r < general if r < V else r - V < vector)}
        if not extra:
            return True
        # a read the donors' own code under that name makes too is the function's (an uninitialized local), not
        # a parameter the name lacks
        if key not in self._donor_arguments:
            reads: set[int] = set()
            for signature in self.by_key.get(key, ()):
                if signature.code:
                    words = list(struct.unpack(f"<{len(signature.code) // 8}I", bytes.fromhex(signature.code)))
                    reads |= argument_reads(words, 0)
            self._donor_arguments[key] = reads
        return extra <= self._donor_arguments[key]

    def run(self, strings: bool = True, rounds: int = 8, seeds: dict[int, str] | None = None) -> list[Proposal]:
        """Proposals, after withdrawing every name some evidence contradicts and matching again without it.
        `seeds` ({address: key}) are names the target already has that the caller trusts: known from the start,
        never proposed, they name what they refer to, call and hold as named functions do; evidence naming one
        otherwise is kept in `self.contradictions`."""
        banned_addresses: set[int] = set()
        banned_keys: set[str] = set()
        refuted: set[tuple[int, str]] = set()
        for _ in range(rounds):
            state = _State(self, banned_addresses, banned_keys, refuted, seeds or {})
            state.settle(strings)
            addresses, keys, pairs = state.conflicts()
            if addresses <= banned_addresses and keys <= banned_keys and pairs <= refuted:
                break
            banned_addresses |= addresses
            banned_keys |= keys
            refuted |= pairs
        self.contradictions = state.seed_conflicts()
        return sorted(state.proposals.values(), key=lambda p: p.address)


class _State:
    def __init__(self, matcher: Matcher, banned_addresses: set[int], banned_keys: set[str],
                 refuted: set[tuple[int, str]] = frozenset(), seeds: dict[int, str] | None = None):
        self.m = matcher
        self.banned_addresses, self.banned_keys = banned_addresses, banned_keys
        self.refuted = refuted                         # (address, key): that address is not that key
        self.known: dict[int, str] = {}                # address -> key
        self.owner: dict[str, int] = {}                # key -> address
        self.proposals: dict[int, Proposal] = {}
        self.votes: dict[int, dict[str, list[int]]] = collections.defaultdict(dict)
        self.clashes: set[str] = set()                 # keys two addresses claim
        self.contradicted: set[int] = set()            # addresses two pieces of evidence name differently
        self.named_tables: set[int] = set()
        self.dirty: set[str] = set(matcher.groups)     # groups to decide again
        self.later: list[tuple[int, list[Signature]]] = []  # functions named otherwise whose code is the donors'
        self.regrown: list[tuple[int, str, int, str]] = []  # votes for a function whose size changed past plausible
        self.cached: dict[tuple[str, int], dict] = {}  # (shape, address) -> its options, until a name they use
        self.changed = False
        self.seeds = seeds or {}
        self.against: list[tuple[int, str, str, int | None]] = []   # (address, name, evidence, source) vs a seed
        for address, named in self.seeds.items():
            self.known[address], self.owner[named] = named, address
            self.dirty |= matcher.dependents.get(address, set()) | matcher.key_groups.get(named, set())
            shape = matcher.shapes.get(address)
            same = [s for s in matcher.by_key.get(named, ()) if shape is not None and s.shape == shape.shape]
            if same:
                self.later.append((address, same))

    def seed_conflicts(self) -> list[dict]:
        """Seeds some evidence names otherwise: another name for a seed's address, the seed's name for another
        address, or code citing files its name's donor functions never cite (`miscited`)."""
        rows = [{"address": a, "seed": display(self.seeds[a]) if a in self.seeds else None, "name": display(n),
                 "evidence": e, "source": s} for a, n, e, s in self.against]
        rows += [{"address": a, "seed": display(k), "name": None, "evidence": "file", "source": None}
                 for a, k in self.seeds.items() if self.miscited(a, k)]
        return rows

    # evidence

    def support(self, signature: Signature, shape: Shape, disagreeing: list[int] | None = None
                ) -> tuple[int, int] | None:
        """(references, neighbours) of a donor function the target agrees with; None when a reference
        disagrees (a neighbour that differs proves nothing: layouts change between builds). The addresses whose
        names disagree go to `disagreeing`."""
        agreed = 0
        for reference, (_, _, target) in zip(signature.references, shape.references):
            token = reference.token
            if token is None:
                continue
            if token[0] == "n":
                known = self.known.get(target - token[2])
                if known is None:
                    continue
                if known != token[1]:
                    if disagreeing is not None:
                        disagreeing.append(target - token[2])
                    return None
                agreed += 1
            else:
                if self.m.text(target) != token[1]:
                    return None
                agreed += len(token[1]) >= 4
        before, after = self.m.neighbours[shape.address]
        placed = (signature.before is not None and self.known.get(before) == signature.before) + \
            (signature.after is not None and self.known.get(after) == signature.after)
        return agreed, placed

    def name(self, address: int, named: str, kind: str, evidence: str, source: int | None = None,
             entries: list[Signature] = (), agreed: int = 0) -> bool:
        if address in self.banned_addresses or named in self.banned_keys or self.known.get(address) == named \
                or (address, named) in self.refuted or kind == "function" and not self.m.fits(address, named):
            return False
        if address in self.known:
            self.contradicted.add(address)
            if address in self.seeds:
                self.against.append((address, named, evidence, source))
            return False
        if named in self.owner:
            self.clashes.add(named)
            if self.owner[named] in self.seeds:
                self.against.append((address, named, evidence, source))
            return False
        self.known[address], self.owner[named] = named, address
        self.dirty |= self.m.dependents.get(address, set()) | self.m.key_groups.get(named, set())
        for watcher in self.m.watchers.get(address, ()):
            self.cached.pop(watcher, None)
        entries = entries or self.m.by_key.get(named, ())
        sizes = {s.size for s in entries} if kind == "function" else self.m.sizes.get(named, set())
        units = {s.unit for s in entries if s.unit}
        self.proposals[address] = Proposal(address, display(named), kind, evidence,
                                           next(iter(sizes)) if len(sizes) == 1 else 0,
                                           tuple(sorted({s.donor for s in entries})),
                                           next(iter(units)) if len(units) == 1 else "", source, agreed,
                                           kind == "function" and bool(entries) and all(s.weak for s in entries)
                                           or kind == "object" and named in self.m.weak)
        self.changed = True
        if kind == "function":                           # however it was named: with its donors' code, it names
            shape = self.m.shapes.get(address)           # what it uses (`refer`)
            same = [s for s in entries if shape is not None and s.shape == shape.shape]
            if same:
                self.later.append((address, same))
        return True

    def plausible(self, address: int, named: str) -> bool:
        """A function named by evidence other than its shape keeps roughly the donors' extent of that name: a
        caller's call site stays the same when its callee is replaced (a new wrapper, another helper), and the
        target's own extent then gives it away."""
        size = self.m.extent.get(address)
        sizes = [s.size for s in self.m.by_key.get(named, ())]
        return not size or not sizes or min(sizes) * 3 <= size * 4 and size * 3 <= max(sizes) * 4

    def vote(self, address: int, named: str, source: int, evidence: str = "reference", checked: bool = False) -> None:
        if address in self.banned_addresses or (address, named) in self.refuted:
            return
        if not checked and not self.plausible(address, named):
            self.regrown.append((address, named, source, evidence))   # what it refers to decides (`calls`)
            return
        self.votes[address].setdefault(named, []).append(source)
        if len(self.votes[address]) == 1:
            kind = "function" if address in self.m.extent else "label" if self.m.program.in_code(address) else \
                "object"
            self.name(address, named, kind, evidence, source)

    def accept(self, address: int, named: str, agreed: tuple[int, int], entries: list[Signature]) -> None:
        evidence = "shape" + ("+references" if agreed[0] else "") + ("+layout" if agreed[1] else "")
        if self.name(address, named, "function", evidence, None, entries, sum(agreed)):
            self.refer(address, entries)

    def drain(self) -> None:
        """What the functions named by a reference or a slot, with the donors' code, refer to."""
        while self.later:
            self.refer(*self.later.pop())

    def refer(self, address: int, entries: list[Signature]) -> None:
        """A named function with its donors' shape names what each of its references names in all of them."""
        for index, (_, _, target) in enumerate(self.m.shapes[address].references):
            tokens = {t for e in entries if (t := e.references[index].token) is not None}  # unnamed there: silent
            token = next(iter(tokens), None)
            if len(tokens) == 1 and token[0] == "n":
                self.vote(target - token[2], token[1], address)

    # passes

    def options(self, shape: str, address: int) -> dict[str, tuple[tuple[int, int], list[Signature]]]:
        """Every donor key of a shape that agrees with a target function, with its best evidence and the donor
        functions behind it."""
        referring, plain, before, after = self.m.plain[shape]
        target = self.m.shapes[address]
        options: dict[str, tuple[tuple[int, int], list[Signature]]] = {}
        disagreeing: list[int] = []
        for signature in referring:
            if signature.key in self.banned_keys:
                continue
            agreed = self.support(signature, target, disagreeing)
            if agreed is not None:
                best, entries = options.get(signature.key, ((0, 0), []))
                options[signature.key] = (max(best, agreed, key=sum), entries + [signature])
        if disagreeing and not options and len(self.m.groups[shape]) == 1 and target.size // 4 >= MINIMUM_WORDS \
                and len({s.key for s in self.m.by_shape[shape]}) == 1:
            self.contradicted.update(disagreeing)    # a shape that names itself alone, against a derived name
        # functions referring to nothing nameable agree everywhere; only their neighbours can place them
        previous, following = (self.known.get(a) for a in self.m.neighbours[address])
        placed: dict[str, int] = collections.defaultdict(int)
        for signature in before.get(previous, ()):
            placed[signature.key] = max(placed[signature.key], 1 + (signature.after == following))
        for signature in after.get(following, ()):
            placed[signature.key] = max(placed[signature.key], 1 + (signature.before == previous))
        for named, entries in plain.items():
            if named in self.banned_keys:
                continue
            best, more = options.get(named, ((0, 0), []))
            options[named] = (max(best, (0, placed.get(named, 0)), key=sum), more + entries)
        if len(self.m.keys[shape]) > 1:
            # between names for one code, one neighbour proves nothing: the linker drops unused functions, so a
            # neighbour of one twin in the donor is a neighbour of the other in the target
            options = {k: ((agreed[0], agreed[1] if agreed[1] == 2 else 0), entries)
                       for k, (agreed, entries) in options.items()}
        return options

    def shapes(self) -> None:
        dirty, self.dirty = self.dirty, set()
        for shape in sorted(dirty):
            open_ = [a for a in self.m.groups[shape] if a not in self.known and a not in self.banned_addresses]
            viable: dict[int, dict[str, tuple[tuple[int, int], list[Signature]]]] = {}
            for address in open_:
                options = self.cached.get((shape, address))
                if options is None:
                    options = self.cached[(shape, address)] = self.options(shape, address)
                (named, (agreed, _)), = options.items() if len(options) == 1 else [(None, ((0, 0), []))]
                if named in self.owner and sum(agreed):
                    self.clashes.add(named)                  # the evidence points at a name already elsewhere
                viable[address] = {k: o for k, o in options.items() if k not in self.owner
                                   and (address, k) not in self.refuted}
            for address in open_:
                best = second = None
                for item in viable[address].items():
                    if best is None or sum(item[1][0]) > sum(best[1][0]):
                        best, second = item, best
                    elif second is None or sum(item[1][0]) > sum(second[1][0]):
                        second = item
                if best is None or second is not None and sum(second[1][0]) >= sum(best[1][0]):
                    continue                                 # no one name has the most evidence
                named, (agreed, entries) = best
                rivals = [sum(viable[b][named][0]) for b in open_ if b != address and named in viable[b]]
                if rivals and not (sum(agreed) and all(r < sum(agreed) for r in rivals)):
                    continue
                if self.m.shapes[address].size // 4 < MINIMUM_WORDS and agreed[0] < CONFIRMING and not agreed[1]:
                    continue
                if not agreed[1] and any(self.m.twinned(e) for e in entries):
                    continue
                self.accept(address, named, agreed, entries)

    def slot_code(self, kind: str, value) -> object:
        """What `aligned` compares a target slot by: its function's shape, an import's name."""
        if kind == "function":
            shape = self.m.shapes.get(value)
            return shape.shape if shape is not None else None
        return ("import", value) if kind == "import" else None

    def donor_code(self, named: str | None) -> object:
        """A donor slot's code: the shape of its function (where the donors agree on one), an import's name."""
        if not named:
            return None
        shapes = {s.shape for s in self.m.by_key.get(named, ())}
        return next(iter(shapes)) if len(shapes) == 1 else None if shapes else ("import", named)

    def name_slots(self, table: int, slots: list[tuple[str, int | str | None]], row: list[str | None]) -> None:
        """A named table's slots from one donor table of its class, as `aligned` pairs them."""
        ours = [self.slot_code(kind, value) for kind, value in slots]
        for i, j in aligned(ours, [self.donor_code(k) for k in row]):
            (kind, target), named = slots[i], row[j]
            if kind == "function" and named and named in self.m.by_key:
                self.vote(target, named, table, "slot")

    def tables(self) -> None:
        """A named table names its slots from the donors' table of that class, as `aligned` pairs them; an
        unnamed one takes the one donor class whose table agrees with every slot already named."""
        for address, table in self.m.vtables().items():
            named = self.known.get(address)
            if named is not None and named.startswith("__vt__"):
                if address in self.named_tables:
                    continue
                self.named_tables.add(address)
                slots = [("function", t) if t else ("other", None) for t in table.slots]
                for row in self.m.tables.get(named, []):
                    while row and row[-1] is None:          # trailing zeros are the next object's, as vtables reads
                        row = row[:-1]
                    self.name_slots(address, slots, row)
            elif named is None and address not in self.banned_addresses:
                known = [(i, self.known[t]) for i, t in enumerate(table.slots) if t in self.known]
                if not known:
                    continue
                fits = {cls for cls, rows in self.m.tables.items() if all(
                    len(slots) == len(table.slots) and all(slots[i] in (None, "", k) for i, k in known)
                    and any(slots[i] == k for i, k in known) for slots in rows)}
                if len(fits) == 1:
                    self.vote(address, fits.pop(), address, "table")

    def itanium(self) -> None:
        """Switch: a named `_ZTV` table names its primary table's slots (up to the first word that is neither a
        function nor an import) from the donors' primary table of that class, as `aligned` pairs them. An unnamed
        primary table takes the one donor class whose table agrees with every slot already named and has no
        other slot in their place."""
        image = self.m.program.image
        for named, address in list(self.owner.items()):
            if not named.startswith("_ZTV") or address in self.named_tables:
                continue
            self.named_tables.add(address)
            rows = self.m.tables.get(named, [])
            if not rows:
                continue
            slots = []
            while (slot := itanium_slots(image, address + 8 * len(slots), 1, self.m.extent)) and slot[0][0] != "other":
                slots += slot
            for row in rows:
                self.name_slots(address, slots, row[:row.index(None)] if None in row else row)
        for address, slots in self.m.itanium_tables().items():
            if address in self.known or address in self.banned_addresses:
                continue
            known = [(i, self.known[v]) for i, (kind, v) in enumerate(slots) if kind == "function" and v in self.known]
            if not known:
                continue
            candidates = set().union(*(self.m.slot_classes().get(item, ()) for item in known))
            fits = {cls for cls in candidates if all(
                len(row) >= len(slots) and (len(row) == len(slots) or row[len(slots)] is None)
                and all(row[i] in (None, "", k) for i, k in known) for row in self.m.tables[cls])}
            if len(fits) == 1:
                self.vote(address, fits.pop(), address, "table")

    def gaps(self) -> None:
        """Between two target functions named from one donor original's, in its order: functions of one shape take the
        donor's functions of that shape between the donor's two, in order where both sides have as many, else by their
        references (`agreeing`). Both builds link in one order and the linker only dropped what it did not need, so the
        code between two placed functions is the code between them in the donor, less what was dropped (and plus what
        was added). A gap whose matches would cross is left alone. A short copy paired by its references alone (copies
        more on one side, or in an order a reference of one pair contradicts), a thin wrapper of a call every class
        makes, needs a neighbour with its donor neighbour's code: an update that replaced a class keeps its wrappers'
        calls. What is left on both sides then pairs as changed code (`changed_code`)."""
        functions, index = self.m.program.functions, self.m.program.function_index
        extents = self.data_extents()
        anchors: dict[str, list[tuple[int, int]]] = collections.defaultdict(list)
        for address, named in self.known.items():
            if address not in index:
                continue
            places = collections.defaultdict(list)
            for signature in self.m.by_key.get(named, ()):
                if signature.place is not None:
                    places[signature.donor].append(signature.place)
            for donor, found in places.items():
                if len(found) == 1:
                    anchors[donor].append((index[address], found[0]))
        for donor, rows in anchors.items():
            layout = self.m.layouts.get(donor)
            if not layout:
                continue
            rows.sort()
            for (i, a), (j, b) in zip(rows, rows[1:]):
                if j - i < 2 or b - a < 2:
                    continue
                between = [functions[k].address for k in range(i + 1, j)]
                ours: dict[object, list[int]] = collections.defaultdict(list)   # group -> open functions, in order
                for t in between:
                    if t in self.m.shapes and t not in self.known and t not in self.banned_addresses:
                        ours[self.m.group(t)].append(t)
                theirs: dict[object, list[Signature | None]] = collections.defaultdict(list)   # unnamed: None
                for q in range(a + 1, b):
                    signature = self.m.placed.get((donor, q))
                    group = self.m.group(signature=signature, shape=layout[q]) if signature else layout[q]
                    if group in ours and (signature is None or signature.key not in self.owner):
                        theirs[group].append(signature)
                matches, by_references = [], set()
                for group, targets in ours.items():
                    candidates = theirs.get(group, [])
                    if len(candidates) == len(targets):          # as many on both sides: in order
                        pairs = [(t, s) for t, s in zip(targets, candidates) if s is not None]
                        matches += pairs
                        if any(self.support(s, self.m.shapes[t]) is None for t, s in pairs):
                            by_references |= {t for t, _ in pairs}   # the order refuted: each by its references
                    elif candidates and not isinstance(group, tuple):
                        found = self.agreeing(targets, [s for s in candidates if s is not None])
                        matches += found
                        by_references |= {t for t, _ in found}
                matches.sort(key=lambda m: m[0])
                if any(m[1].place > n[1].place for m, n in zip(matches, matches[1:])):
                    continue
                for t, signature in matches:
                    if signature.key in self.owner or signature.key in self.banned_keys:
                        continue
                    agreed = self.support(signature, self.m.shapes[t])
                    if agreed is None:
                        continue
                    if t in by_references and self.m.shapes[t].size // 4 < MINIMUM_WORDS and agreed[0] < CONFIRMING \
                            and not agreed[1] and not self.alike_neighbour(t, signature):
                        continue     # a thin wrapper whose one call any copy makes, where the code around it is other code
                    if signature.shape == self.m.shapes[t].shape:
                        self.accept(t, signature.key, (agreed[0], max(agreed[1], 1)), [signature])
                    else:                                        # a sibling in a family whose immediates moved
                        self.name(t, signature.key, "function", "layout" + ("+references" if agreed[0] else ""),
                                  None, [signature])
                rest = [t for t in between if t not in self.known and t not in self.banned_addresses]
                left = [s for q in range(a + 1, b) if (s := self.m.placed.get((donor, q))) is not None
                        and s.key not in self.owner and s.key not in self.banned_keys]
                for t, signature, evidence in self.changed_code(rest, left, extents):
                    self.name(t, signature.key, "function", evidence, None, [signature])

    def alike_neighbour(self, address: int, signature: Signature) -> bool:
        """A target function's neighbour, named or not, has the code of the donor function's neighbour there."""
        return any(n in self.m.shapes and key and self.m.shapes[n].shape == self.donor_code(key)
                   for n, key in zip(self.m.neighbours[address], (signature.before, signature.after)))

    def agreeing(self, targets: list[int], candidates: list[Signature]) -> list[tuple[int, Signature]]:
        """Copies of one shape, more on one side than the other: a target copy takes the one donor copy whose
        references agree with it (at least one agreeing, none disagreeing) when no other target copy agrees
        with that one."""
        agree = {t: [s for s in candidates if (r := self.support(s, self.m.shapes[t])) is not None and r[0] > 0]
                 for t in targets}
        takers = collections.Counter(id(s) for found in agree.values() for s in found)
        return [(t, found[0]) for t, found in agree.items() if len(found) == 1 and takers[id(found[0])] == 1]

    def changed_code(self, rest: list[int], left: list[Signature], extents) -> list[tuple[int, Signature, str]]:
        """Inside one gap, the target functions left (in address order) against the donor functions left:
        one of each, or two of each in order, of plausible sizes (and two not sharing more the other way
        round), are functions whose code changed (layout); otherwise a target function takes the donor
        function it shares the most with by what both refer to (named functions and data, texts), at least
        `SHARED_BITS` and over twice what any other pairing of either gets (layout+references), and what is
        left pairs by how alike it is (`similar`). Pairings that would cross are none. (Builds keep their
        link order, so one or two on each side pair in order; a longer gap more likely holds a function one build
        added or dropped, so it is scored.)"""
        if not rest or not left:
            return []
        if len(rest) == 1 and len(left) == 1:
            return [(rest[0], left[0], "layout")] if self.plausible(rest[0], left[0].key) else []
        theirs = {id(s): self.m.uses(s) for s in left}
        score = {}
        for t in rest:
            ours = self.target_uses(t, extents)
            for s in left:
                score[(t, id(s))] = sum(self.m.weight(u) for u in ours & theirs[id(s)])
        if len(rest) == len(left) == 2 and all(self.plausible(t, s.key) for t, s in zip(rest, left)):
            (t0, t1), (s0, s1) = rest, left
            if score[(t0, id(s1))] + score[(t1, id(s0))] <= score[(t0, id(s0))] + score[(t1, id(s1))]:
                return [(t0, s0, "layout"), (t1, s1, "layout")]
        chosen = []
        for t in rest:
            ranked = sorted(left, key=lambda s: -score[(t, id(s))])
            best, top = ranked[0], score[(t, id(ranked[0]))]
            if top < SHARED_BITS or len(ranked) > 1 and 2 * score[(t, id(ranked[1]))] > top:
                continue
            if any(2 * score[(u, id(best))] > top for u in rest if u != t) or not self.plausible(t, best.key):
                continue
            chosen.append((t, best, "layout+references"))
        crossing = lambda pairs: any(x[1].place > y[1].place for x, y in zip(pairs, pairs[1:]))
        if crossing(chosen):
            return []
        taken = {t for t, _, _ in chosen} | {id(s) for _, s, _ in chosen}
        alike = sorted(chosen + self.similar([t for t in rest if t not in taken],
                                             [s for s in left if id(s) not in taken], extents))
        return chosen if crossing(alike) else alike

    def similar(self, rest: list[int], left: list[Signature], extents) -> list[tuple[int, Signature, str]]:
        """Changed code in one gap by how alike it is. A target function and a donor function are as alike as
        the mean of the share of their masked words in common (difflib's ratio) and the share of what either
        refers to that both do (each reference by its weight); the target functions then align with the donor
        functions in order, for the most likeness in all (no two pairings crossing). A pairing stands when it
        reaches `SIMILAR`, beats every other pairing of either function in the gap by `SIMILAR_MARGIN`, and both
        are `MINIMUM_WORDS` long or more and of plausible sizes (layout+code). Shorter code stays: a getter whose
        field moved reads exactly like its neighbour did. A constructor or
        destructor whose class has another of its variants (C1/C2, D0/D1/D2) left in the gap stays too: one
        variant's code is another's inlined, as alike to either."""
        import difflib
        if not rest or not left or len(rest) * len(left) > SIMILAR_PAIRS or not all(s.code for s in left):
            return []
        theirs = [(self.m.code(s), self.m.uses(s)) for s in left]
        score = []
        for t in rest:
            ours, uses = self.m.code(self.m.shapes[t]), self.target_uses(t, extents)
            row = []
            for words, used in theirs:
                if 3 * min(len(ours), len(words)) < max(len(ours), len(words)):
                    row.append(0.0)                      # a third the size: at most half alike
                    continue
                code = difflib.SequenceMatcher(None, ours, words, autojunk=False).ratio()
                shared = sum(self.m.weight(u) for u in uses & used)
                other = sum(self.m.weight(u) for u in uses ^ used)
                row.append((code + shared / (shared + other)) / 2 if shared + other else code)
            score.append(row)
        n, m = len(rest), len(left)
        best = [[0.0] * (m + 1) for _ in range(n + 1)]       # the most likeness of rest[i:] against left[j:]
        for i in range(n - 1, -1, -1):
            for j in range(m - 1, -1, -1):
                take = score[i][j] + best[i + 1][j + 1] if score[i][j] >= SIMILAR else 0.0
                best[i][j] = max(best[i + 1][j], best[i][j + 1], take)
        chosen, i, j = [], 0, 0
        while i < n and j < m:
            if score[i][j] >= SIMILAR and best[i][j] == score[i][j] + best[i + 1][j + 1]:
                t, s, value = rest[i], left[j], score[i][j]
                rivals = [v for k, v in enumerate(score[i]) if k != j] + [score[k][j] for k in range(n) if k != i]
                if (value >= max(rivals, default=0.0) + SIMILAR_MARGIN and self.plausible(t, s.key)
                        and min(self.m.shapes[t].size, s.size) >= 4 * MINIMUM_WORDS
                        and not any(o is not s and self.m.structor(o.key) == self.m.structor(s.key) is not None
                                    for o in left)):
                    chosen.append((t, s, "layout+code"))
                i, j = i + 1, j + 1
            elif best[i][j] == best[i + 1][j]:
                i += 1
            else:
                j += 1
        return chosen

    def target_uses(self, address: int, extents) -> set[tuple]:
        """What a target function refers to, by the names known so far (a function's start, the data object
        holding an address, by its donors' size) and by text."""
        starts, rows = extents
        out = set()
        for _, _, target in self.m.shapes[address].references:
            named = self.known.get(target)
            if named is None:
                i = bisect.bisect_right(starts, target) - 1
                if i >= 0 and target < rows[i][1]:
                    named = rows[i][2]
            if named is not None:
                out.add(("n", named))
            elif (text := self.m.text(target)) is not None and len(text) >= 4:
                out.add(("s", text))
        return out

    def calls(self) -> None:
        """A named function whose code changed still calls what its donors' code calls: when one function it
        calls is unnamed and one function its donors call is unclaimed, they are one function unless a function it
        calls that is named is one its donors never call (an update inlined or outlined other calls), and its calls pair
        with its donors' in order (`call_order`). A caller one of whose pairings in order more callers contradict
        (another name for its callee, or another callee for its name) is misaligned, an update having moved its
        calls, and names nothing in order. Each pairing left needs no other caller saying otherwise, and a
        plausible size or, where an update grew or split the callee, what it refers to (`still_refers`), which also
        decides the references and slots that named a function of such a size (`vote`)."""
        from . import aarch64
        kinds = {ppc.REL24, aarch64.CALL26, aarch64.JUMP26}
        found: dict[int, dict[str, int]] = collections.defaultdict(dict)
        ordered: dict[int, set[tuple[int, str]]] = {}              # caller -> its (callee, key) pairings in order
        for address, named in list(self.known.items()):
            shape, entries = self.m.shapes.get(address), self.m.by_key.get(named, ())
            if shape is None or not entries or any(e.shape == shape.shape for e in entries):
                continue
            ours = {t for _, kind, t in shape.references if kind in kinds and t in self.m.extent
                    and t not in self.known and t not in self.banned_addresses}
            theirs = {frozenset(r.token[1] for r in e.references if r.kind in kinds and r.token and r.token[0] == "n"
                                and r.token[1] in self.m.by_key and r.token[1] not in self.owner
                                and r.token[1] not in self.banned_keys) for e in entries}
            called = {self.known[t] for _, kind, t in shape.references if kind in kinds and t in self.known}
            donor_calls = {r.token[1] for e in entries for r in e.references
                           if r.kind in kinds and r.token and r.token[0] == "n"}
            if len(ours) == 1 and len(theirs) == 1 and len(next(iter(theirs))) == 1 and called <= donor_calls:
                found[next(iter(ours))][next(iter(next(iter(theirs))))] = address
            pairs = set(self.call_order(shape, entries, kinds))
            if pairs:
                ordered[address] = pairs
        support = collections.Counter(pair for pairs in ordered.values() for pair in pairs)
        names, targets = collections.defaultdict(dict), collections.defaultdict(dict)
        for (target, key), count in support.items():
            names[target][key], targets[key][target] = count, count
        beaten = lambda t, k: any(n > support[(t, k)] for other, n in names[t].items() if other != k) or \
            any(n > support[(t, k)] for other, n in targets[k].items() if other != t)
        for address, pairs in ordered.items():
            if not any(beaten(t, k) for t, k in pairs):
                for target, key in pairs:
                    found[target].setdefault(key, address)
        extents = None
        for target, keys in found.items():
            if len(keys) == 1:
                (named, source), = keys.items()
                if self.plausible(target, named):
                    self.name(target, named, "function", "call", source)
                    continue
                if extents is None:
                    extents = self.data_extents()
                if self.still_refers(target, named, source, kinds, extents):
                    self.name(target, named, "function", "call+references", source)
        regrown, self.regrown = self.regrown, []
        for target, named, source, evidence in regrown:
            if target in self.known or named in self.owner:
                continue
            if extents is None:
                extents = self.data_extents()
            if self.still_refers(target, named, source, kinds, extents):
                self.vote(target, named, source, evidence + "+references", checked=True)

    def data_order(self) -> None:
        """A named function whose code changed still uses what its donors' code uses, in order: its references
        other than calls pair with its donors' (where they agree) between two that name the same thing (a text, or
        a function or data named so far), as many on both sides, and each pairing names what it points into at
        the donors' offset into theirs: data, a table, a function whose address it takes. A name another function
        gives otherwise is withdrawn."""
        import difflib
        from . import aarch64
        calls = {ppc.REL24, aarch64.CALL26, aarch64.JUMP26}
        starts, rows = self.data_extents()

        def named_at(target: int) -> str | None:
            if target in self.known:
                return self.known[target]
            i = bisect.bisect_right(starts, target) - 1
            return rows[i][2] if i >= 0 and target < rows[i][1] else None
        found: dict[int, dict[str, int]] = collections.defaultdict(dict)
        for address, named in list(self.known.items()):
            shape, entries = self.m.shapes.get(address), self.m.by_key.get(named, ())
            if shape is None or not entries or any(e.shape == shape.shape for e in entries):
                continue
            theirs = {tuple(r.token for r in e.references if r.kind not in calls) for e in entries}
            if len(theirs) != 1:
                continue
            theirs = next(iter(theirs))
            ours = [t for _, kind, t in shape.references if kind not in calls]
            a = []
            for i, t in enumerate(ours):
                text, known = self.m.text(t), named_at(t)
                a.append(("s", text) if text is not None else ("n", known) if known else ("?", i))
            b = [token[:2] if token else ("?", -1 - j) for j, token in enumerate(theirs)]
            i0 = j0 = 0
            for i1, j1, size in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks():
                if i1 - i0 == j1 - j0:
                    for t, token in zip(ours[i0:i1], theirs[j0:j1]):
                        if not token or token[0] != "n":
                            continue
                        start = t - token[2]
                        if start not in self.known and start not in self.banned_addresses \
                                and token[1] not in self.owner and token[1] not in self.banned_keys:
                            found[start].setdefault(token[1], address)
                i0, j0 = i1 + size, j1 + size
        for start, keys in found.items():
            if len(keys) == 1:
                (named, source), = keys.items()
                self.vote(start, named, source, "order")

    def data_extents(self):
        """The data named so far, by its donors' size, as `target_uses` reads it."""
        index = self.m.program.function_index
        rows = sorted((a, a + max(max(self.m.sizes.get(k, {1})), 1), k) for a, k in self.known.items()
                      if a not in index)
        return [r[0] for r in rows], rows

    def still_refers(self, target: int, named: str, source: int, kinds: set[int], extents) -> bool:
        """A callee whose size changed past `plausible` is still its donors' function when it shares at least
        `SHARED_BITS` of what it refers to with them and over twice what it shares with any other function its
        caller's donors call: a caller's call site stays when an update replaces the callee with a new wrapper,
        but the wrapper refers to other things."""
        ours = self.target_uses(target, extents)
        shared = lambda key: max((sum(self.m.weight(u) for u in ours & self.m.uses(s))
                                  for s in self.m.by_key.get(key, ())), default=0.0)
        mine = shared(named)
        if mine < SHARED_BITS:
            return False
        others = {r.token[1] for e in self.m.by_key.get(self.known.get(source), ()) for r in e.references
                  if r.kind in kinds and r.token and r.token[0] == "n" and r.token[1] in self.m.by_key
                  and r.token[1] != named}
        return all(2 * shared(other) < mine for other in others)

    def call_order(self, shape: Shape, entries: list[Signature], kinds: set[int]) -> list[tuple[int, str]]:
        """(callee, key) pairs of a function whose code changed: its calls in order against its donors' (where
        they agree), anchored where both name the same function (difflib's matching blocks); between two anchors
        (or an anchor and an end), as many calls on both sides pair in order, an unnamed callee with an unclaimed
        donor callee. An update that adds a call next to its neighbours' calls leaves the counts unequal there."""
        import difflib
        rows = {tuple(r.token[1] if r.token and r.token[0] == "n" and r.token[1] in self.m.by_key else None
                      for r in e.references if r.kind in kinds) for e in entries}
        if len(rows) != 1:
            return []
        theirs = next(iter(rows))
        ours = [t for _, kind, t in shape.references if kind in kinds and t in self.m.extent]
        a = [self.known.get(t) or ("?", i) for i, t in enumerate(ours)]
        b = [k if k is not None else ("?", -1 - j) for j, k in enumerate(theirs)]
        pairs, i0, j0 = [], 0, 0
        for i1, j1, size in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks():
            if i1 - i0 == j1 - j0:
                for t, named in zip(ours[i0:i1], theirs[j0:j1]):
                    if named is not None and t not in self.known and t not in self.banned_addresses \
                            and named not in self.owner and named not in self.banned_keys:
                        pairs.append((t, named))
            i0, j0 = i1 + size, j1 + size
        return pairs

    def strings(self) -> None:
        """Functions whose shape matched nothing, by the exact set of texts they refer to, where one donor name
        and one target function have that set. Only C names: the code changed, and a C++ name's parameters
        may have changed with it."""
        donor_sets, target_sets = self.m.texts()
        for texts, addresses in target_sets.items():
            keys = donor_sets[texts]
            named = next(iter(keys))
            if len(addresses) == 1 and len(keys) == 1 and addresses[0] not in self.known \
                    and self.plausible(addresses[0], named):
                self.name(addresses[0], named, "function", "strings")

    def settle(self, strings: bool) -> None:
        while True:
            self.changed = False
            self.shapes()
            self.drain()
            if self.m.program.platform.name == "switch":
                self.itanium()
            else:
                self.tables()
            self.drain()
            if not self.changed and strings:
                self.strings()
            if not self.changed:
                self.gaps()
                self.drain()
            if not self.changed:
                self.calls()
            if not self.changed:
                self.data_order()
                self.drain()
            if not self.changed:
                return

    def conflicts(self) -> tuple[set[int], set[str], set[tuple[int, str]]]:
        """Addresses two pieces of evidence name differently, keys two addresses claim, and names an address is
        not. A `__FILE__` names the file code was compiled in, so a function whose code cites source files that
        none of its name's donor functions cite is not theirs (a name its place or its calls moved onto other
        code), and a class table one of whose slots holds a function citing a file that the donor class's function
        there does not is not that class's, and neither are its slots named as that class's own methods (a wrapper
        any class has may have named the table, and a constructor whose code differs only in the class it builds
        does). Those names are refuted, not the addresses: each may still be named otherwise."""
        addresses = {a for a, keys in self.votes.items() if len(keys) > 1} | self.contradicted
        pairs = {(a, named) for a, named in self.known.items() if self.miscited(a, named)}
        tables = self.m.itanium_tables() if self.m.program.platform.name == "switch" else {}
        for address, named in list(self.known.items()):
            slots = tables.get(address) if named.startswith("_ZTV") else None
            rows = [(i, kind, v, row[i]) for row in self.m.tables.get(named, ()) if slots
                    for i, (kind, v) in enumerate(slots) if kind == "function" and i < len(row) and row[i]]
            if any(self.miscited(v, key) for _, _, v, key in rows):
                pairs.add((address, named))
                pairs |= {(v, key) for i, _, v, key in rows
                          if self.known.get(v) == key and self.m.slot_classes().get((i, key)) == {named}}
        return addresses, set(self.clashes), pairs

    def miscited(self, address: int, key: str) -> bool:
        ours = self.m.sources(address)
        theirs = self.m.donor_sources(key) if ours else set()
        return bool(theirs) and not ours & theirs


def propose(program: Program, donors: list[Donor], strings: bool = True, seeds: dict[int, str] | None = None,
            matcher: list | None = None) -> list[Proposal]:
    """Names for a target's functions and data from donors' signatures, read blind: the target's own names are
    never evidence (compare them with the proposals afterwards), unless the caller trusts some as `seeds`
    ({address: donor key}, `seeds`), which are then known from the start and never proposed. `matcher`, a list, receives
    the matcher (its `contradictions`). A donor read from this very original is left out."""
    image = identity(program.image) if hasattr(program.image, "raw") or hasattr(program.image, "image") else None
    m = Matcher(program, [d for d in donors if (image is None or image not in d.images)
                          and d.platform in ("", program.platform.name)])
    if matcher is not None:
        matcher.append(m)
    return m.run(strings, seeds=seeds)


def qualified(text: str | None) -> str | None:
    """A demangled function name without its parameters and qualifiers: `ns::Class::method`."""
    if not text or "(" not in text:
        return None
    depth = 0
    for i, c in enumerate(text):
        depth += (c == "<") - (c == ">")
        if c == "(" and depth == 0 and i:
            return text[:i]
    return None


def seeds(program: Program, matcher: Matcher) -> dict[int, str]:
    """The target's own names as seeds for `Matcher.run`, each as its donors' key: a name the donors have (a
    file-local one by its name where only one file has it), else a function whose parameters changed: the
    donors' only function of the same qualified name, where no target name is that function's and the target has
    only that one name of it (another build added a parameter and the decomp named the function so), or a complete
    (C1, D1) or base (C2, D2) structor whose donors spell the alias the other way. Placeholders and names two
    addresses share are none (a C++ name around an address placeholder or a `TUnk_` class too)."""
    from .platform import demangle_itanium
    from .score import placeholder
    plain: dict[str, set[str]] = collections.defaultdict(set)
    for k in list(matcher.by_key) + list(matcher.sizes) + list(matcher.tables):
        plain[display(k)].add(k)
    rows = [(f.address, f.name) for f in program.functions] + [(o.address, o.name) for o in program.objects]
    rows = [(a, n) for a, n in rows if n and not placeholder(n) and not unnamed(n)
            and not re.search(r"(?:fn|lbl)_[0-9A-Fa-f]{8,}|TUnk_[0-9A-Fa-f]{6,}", n)]  # a placeholder inside a C++ name
    count = collections.Counter(n for _, n in rows)
    out, missing = {}, []
    for address, name in rows:
        if count[name] != 1:
            continue
        keys = plain.get(name, set())
        if len(keys) == 1:
            out[address] = next(iter(keys))
        elif not keys:
            missing.append((address, name))
            out[address] = name
    functions = [(a, n) for a, n in missing if a in matcher.extent and n.startswith("_Z")]
    donor = sorted({display(k) for k in matcher.by_key if display(k).startswith("_Z")})
    texts = dict(zip(donor, demangle_itanium(donor))) if functions else {}
    by_qualified: dict[str, list[str]] = collections.defaultdict(list)
    for k, text in texts.items():
        if (q := qualified(text)) is not None:
            by_qualified[q].append(k)
    names = sorted({n for a, n in rows if a in matcher.extent and n.startswith("_Z")}) if functions else []
    ours = dict(zip(names, demangle_itanium(names)))
    target_qualified = collections.Counter(qualified(t) for t in ours.values())
    # C1 and C2 (D1 and D2) are one code where the class has no virtual base, and a symbols file may keep
    # either spelling of the alias; D0 (deleting) and C3 are others
    variant = lambda n: frozenset(v.replace("C2", "C1").replace("D2", "D1")
                                  for v in re.findall(r"(?<=[0-9A-Za-z_])(?:C[123]|D[012])E", n))
    same_variant = collections.Counter((qualified(t), variant(n)) for n, t in ours.items())
    for address, name in functions:
        q = qualified(ours.get(name))
        found = [k for k in by_qualified.get(q, [])] if q else []
        if variant(name):                                        # a structor: its own variant only
            found = [k for k in found if variant(k) == variant(name)]
            alone = same_variant[(q, variant(name))] == 1
        else:
            alone = target_qualified[q] == 1
        if len(found) == 1 and found[0] not in count and alone and len(plain[found[0]]) == 1:
            out[address] = next(iter(plain[found[0]]))
    return out


def renamed(program: Program, proposals: list[Proposal]) -> Program:
    """The program with every proposed name in place of a placeholder (its own names stay)."""
    from dataclasses import replace
    from .score import placeholder
    names = {p.address: p.name for p in proposals}
    weak = {p.address for p in proposals if p.weak}
    return program.derived([replace(f, name=names[f.address], scope="weak" if f.address in weak else f.scope)
                            if f.address in names and placeholder(f.name) else f for f in program.functions],
                           [replace(o, name=names[o.address], scope="weak" if o.address in weak else o.scope)
                            if o.address in names and placeholder(o.name) else o for o in program.objects])


# Projects and the command line

def donors(names: Iterable[str] = ()) -> list[Donor]:
    """The named donors, or every donor in the cache."""
    return [load(name) for name in (list(names) or listed())]


def build_project(project, target: str, name: str, complete: bool = False) -> Donor:
    """A donor from a project target: its original named by its symbols (its splits place file-local names), or
    with `complete` only the compiled objects of the units its objdiff report marks complete."""
    from .gc import read_splits
    from .objects import objdiff_units
    from .score import complete_units
    config = project.target(target)
    donor = Donor(name, built=time.strftime("%Y-%m-%dT%H:%M:%S"))
    if not complete:
        splits = project.file(config["repository"], config["splits"]) if config.get("splits") else None
        units = [(s, e, u) for u, _, s, e in read_splits(splits)] if splits and splits.is_file() else []
        add_program(donor, Program.from_project(project, target), units)
        donor.sources.append(f"{project.config['id']}:{target}")
        return donor
    from .elf import Elf
    if platform_name(config) == "switch":
        raise ValueError("Signatures from compiled objects read PowerPC objects only; build a Switch donor from its "
                         "original (without --complete)")
    if not config.get("report"):
        raise ValueError(f"Target {target} has no objdiff report to say which units are complete")
    proven = complete_units(project.file(config["repository"], config["report"]), config.get("module"))
    for unit, entry in objdiff_units(project, target).items():
        base = entry.get("base_path")
        source = (entry.get("metadata") or {}).get("source_path") or unit
        path = project.file(config["repository"], base) if base else None
        if path is None or not path.is_file() or not any(p == source or p == unit or unit.endswith("/" + p)
                                                         for p in proven):
            continue
        add_object(donor, Elf.load(path), source)
    donor.platform = "gamecube"
    donor.sources.append(f"{project.config['id']}:{target} complete units")
    return donor


def match_project(project, target: str, names: Iterable[str] = (), every: bool = False, seeded: bool = False) -> dict:
    """Proposals for a project target against the donors, each with the target's current name: new where that
    is a placeholder, differs where the target names it otherwise, same (listed with `every`)."""
    from .score import placeholder
    program = Program.from_project(project, target)
    chosen = donors(names)
    if not chosen:
        raise ValueError("No signatures in the cache yet; build a donor with `zkit signatures build`")
    current = {f.address: f.name for f in program.functions} | {o.address: o.name for o in program.objects}
    rows, counts = [], collections.Counter()
    made: list = []
    planted = None
    if seeded:
        planted = seeds(program, Matcher(program, chosen))
    proposals = propose(program, chosen, seeds=planted, matcher=made)
    for p in proposals:
        now = current.get(p.address)
        status = "new" if not now or placeholder(now) else "same" if now == p.name else "differs"
        counts[status] += 1
        counts[f"{p.kind}s"] += 1
        if status != "same" or every:
            rows.append({"address": f"0x{p.address:08X}", "name": p.name, "current": now, "status": status,
                         "kind": p.kind, "evidence": p.evidence, "size": p.size, "donors": list(p.donors),
                         "unit": p.unit, "source": f"0x{p.source:08X}" if p.source is not None else None})
    out = {"target": target, "donors": [d.name for d in chosen], "counts": dict(counts), "rows": rows}
    if seeded and made:
        out["contradicted"] = [{**c, "address": f"0x{c['address']:08X}"} for c in made[0].contradictions]
    return out


def command(args, project=None, target: str | None = None) -> tuple[dict, str]:
    """`zkit signatures build|list|remove|match`."""
    if args.action == "list":
        rows = []
        for name in listed():
            donor = load(name)
            rows.append({"name": name, "functions": len(donor.signatures), "tables": len(donor.tables),
                         "built": donor.built, "sources": donor.sources})
        text = "\n".join(f"{r['name']:<20} {r['functions']:>6} functions {r['tables']:>5} tables  {r['built']}  "
                         + "; ".join(r["sources"]) for r in rows)
        return {"cache": str(folder()), "donors": rows}, text or f"no signatures in {folder()} yet"
    if args.action == "remove":
        if not args.name:
            raise ValueError("Name the donor to remove")
        gone = remove(args.name)
        return {"removed": gone, "name": args.name}, f"{'removed' if gone else 'no signatures named'} {args.name}"
    if args.action == "build":
        if not args.name:
            raise ValueError("Name the donor: zkit signatures build NAME ...")
        given = lambda p: p.expanduser().resolve() if p else None
        if args.image or args.objects:
            donor = build(args.name, given(args.image), given(args.symbols), given(args.map), given(args.splits),
                          [given(p) for p in args.objects])
        elif project is not None:
            donor = build_project(project, target, args.name, args.complete)
        else:
            raise ValueError("Pass --image with --symbols or --map, or --objects; or run inside a project")
        path = save(donor)
        return ({"name": donor.name, "functions": len(donor.signatures), "tables": len(donor.tables),
                 "path": str(path)},
                f"{donor.name}: {len(donor.signatures):,} function signatures, {len(donor.tables):,} virtual tables "
                f"-> {path}")
    if args.action == "match":
        if project is None:
            raise ValueError("Run inside a project (or pass --project) to match its target")
        data = match_project(project, target, args.donor, args.all, getattr(args, "seeded", False))
        return data, match_text(data, args.limit)
    raise ValueError(f"Unknown signatures action {args.action}")


def match_text(data: dict, limit: int = 60) -> str:
    c = data["counts"]
    lines = [f"{data['target']}: {c.get('functions', 0):,} functions and {c.get('objects', 0):,} data symbols named "
             f"from {', '.join(data['donors'])}: {c.get('new', 0):,} new, {c.get('differs', 0):,} differ from the "
             f"current name, {c.get('same', 0):,} the same"]
    for row in data["rows"][:limit]:
        was = f" (now {row['current']})" if row["status"] == "differs" else ""
        via = f" via {row['source']}" if row["source"] else ""
        lines.append(f"  {row['address']} {row['name']}{was}  [{row['evidence']}{via}; {'/'.join(row['donors'])}"
                     + (f" {row['unit']}" if row["unit"] else "") + "]")
    if len(data["rows"]) > limit:
        lines.append(f"  ... {len(data['rows']) - limit} more (--limit, --json)")
    return "\n".join(lines)
