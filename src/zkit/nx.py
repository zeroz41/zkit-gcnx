"""Nintendo Switch executables: NSO modules (and plain ELF files of them) as a loaded, relocated image.

A module is read the way the loader maps it: its text, read-only and data segments decompressed (LZ4) at their
memory offsets, `MOD0` and the dynamic section parsed, dynamic symbols named and relative relocations applied,
so pointers in data (vtables, tables) hold the addresses the program sees. Function boundaries of a stripped
module come from `.eh_frame`, which clang writes for every function. Addresses are offsets from the module base;
`base` is only for display (0x7100000000 by the usual convention).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

NSO_MAGIC = b"NSO0"
DEFAULT_BASE = 0x7100000000
R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE = 257, 1025, 1026, 1027
DT_NULL, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_STRSZ, DT_JMPREL = 0, 2, 5, 6, 7, 8, 10, 23
DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAY, DT_FINI_ARRAYSZ = 25, 27, 26, 28
DT_HASH, DT_GNU_HASH, DT_PLTGOT = 4, 0x6FFFFEF5, 3
DT_RELRSZ, DT_RELR = 35, 36
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _decompress(chunk: bytes, size: int) -> bytes:
    """A segment's bytes: LZ4 (every NSO so far) or zstd (newer SDKs), by the data's own magic."""
    if chunk[:4] == ZSTD_MAGIC:
        try:
            import zstandard
        except ImportError as error:
            raise ValueError("This module's segments are zstd-compressed: install the `zstandard` Python package "
                             "(uv tool install --with zstandard zkit)") from error
        return zstandard.ZstdDecompressor().decompress(chunk, max_output_size=size)
    return lz4_block(chunk, size)


def lz4_block(source: bytes, size: int) -> bytes:
    """Decompress one LZ4 block (the format NSO segments use)."""
    try:
        import lz4.block  # optional speedup
        return lz4.block.decompress(source, uncompressed_size=size)
    except ImportError:
        pass
    out = bytearray()
    i, end = 0, len(source)
    while i < end:
        token = source[i]
        i += 1
        literal = token >> 4
        if literal == 15:
            while True:
                extra = source[i]
                i += 1
                literal += extra
                if extra != 255:
                    break
        out += source[i:i + literal]
        i += literal
        if i >= end:
            break
        offset = source[i] | source[i + 1] << 8
        i += 2
        length = (token & 15) + 4
        if token & 15 == 15:
            while True:
                extra = source[i]
                i += 1
                length += extra
                if extra != 255:
                    break
        start = len(out) - offset
        if offset >= length:
            out += out[start:start + length]
        else:
            pattern = bytes(out[start:])
            out += (pattern * (length // len(pattern) + 1))[:length]
    if len(out) != size:
        raise ValueError(f"LZ4 segment decompressed to {len(out)} bytes, expected {size}")
    return bytes(out)


@dataclass(frozen=True)
class Segment:
    name: str        # text, rodata, data, bss
    offset: int      # memory offset from the module base
    size: int
    kind: str        # "code" or "data"

    @property
    def address(self) -> int:
        return self.offset


@dataclass
class Module:
    """A loaded module: one flat image with segments, dynamic symbols and applied relocations."""
    image: bytearray
    segments: list[Segment]
    build_id: str = ""
    name: str = ""
    symbols: dict[int, str] = field(default_factory=dict)           # offset -> dynamic symbol name (defined)
    sizes: dict[int, int] = field(default_factory=dict)             # offset -> that symbol's size
    kinds: dict[int, str] = field(default_factory=dict)             # offset -> func or object
    weak: set[int] = field(default_factory=set)                     # weak symbols' offsets (inlines, templates)
    imports: dict[int, str] = field(default_factory=dict)           # data offset -> imported symbol it holds
    pointers: dict[int, int] = field(default_factory=dict)          # data offset -> offset it points to (relative)
    init_array: list[int] = field(default_factory=list)
    eh_frame_hdr: tuple[int, int] | None = None
    tables: dict[str, tuple[int, int]] = field(default_factory=dict)  # the linker's own: name -> (start, end)
    raw: bytes = b""                    # the image as stored, before the dynamic relocations are applied
    hashes: dict[str, bytes] = field(default_factory=dict)          # segment -> the NSO header's SHA-256 of it
    bss_end: int | None = None                                      # MOD0's: where the zero-initialized objects end

    @property
    def bss(self) -> tuple[int, int]:
        """The zero-initialized range: the bss segment up to where MOD0 says the objects end (an NSO header gives
        the segment's size rounded up to a page, and the rest is padding no object owns)."""
        segment = next((s for s in self.segments if s.name == "bss"), None)
        if segment is None:
            return (0, 0)
        end = segment.offset + segment.size
        if self.bss_end is not None and segment.offset < self.bss_end < end:
            end = self.bss_end
        return (segment.offset, end - segment.offset)

    def section_at(self, offset: int) -> Segment | None:
        segment = self.segment_at(offset)
        return segment if segment is not None and segment.name != "bss" else None

    def segment_at(self, offset: int) -> Segment | None:
        for segment in self.segments:
            if segment.offset <= offset < segment.offset + segment.size:
                return segment
        return None

    def read(self, offset: int, size: int) -> bytes:
        segment = self.segment_at(offset)
        if segment is None or offset + size > segment.offset + segment.size or segment.name == "bss":
            raise ValueError(f"0x{offset:X}+{size} is not inside one loaded segment")
        return bytes(self.image[offset:offset + size])

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.image, offset)[0]

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.image, offset)[0]

    def words(self, offset: int, size: int) -> list[int]:
        data = self.read(offset, size - size % 4)
        return list(struct.unpack(f"<{len(data) // 4}I", data))

    def functions(self) -> list[tuple[int, int]]:
        """(start, size) of every function: the unwind table's (clang writes one for every function it compiles),
        plus defined function symbols and import stubs it lacks."""
        found = dict(_eh_frame_functions(self, *self.eh_frame_hdr)) if self.eh_frame_hdr else {}
        for offset, kind in self.kinds.items():
            if kind == "func" and offset not in found and self.sizes.get(offset):
                found[offset] = self.sizes[offset]
        for offset in self.stubs():
            found.setdefault(offset, 16)
        return sorted(found.items())

    def stubs(self) -> dict[int, str]:
        """Import stubs (adrp x16 / ldr x17, [x16, #lo] / add x16, x16, #lo / br x17) -> the import they jump to."""
        if getattr(self, "_stubs", None) is not None:
            return self._stubs
        self._stubs = {pc: self.imports[slot] for pc, slot in _stub_slots(self).items() if slot in self.imports}
        return self._stubs


STUB_BRANCH = struct.pack("<I", 0xD61F0220)          # br x17: the last word of a PLT stub
PLT_PUSH, NOP = 0xA9BF7BF0, 0xD503201F                 # stp x16, x30, [sp, #-16]!: the PLT header's first word


def _stub_at(words: tuple[int, ...] | list[int], pc: int) -> int | None:
    """The slot a stub (adrp x16 / ldr x17, [x16, #lo] / add x16, x16, #lo / br x17) at `pc` jumps through."""
    first, second, third, fourth = words
    if first & 0x9F00001F != 0x90000010 or second & 0xFFC003FF != 0xF9400211 or third & 0xFFC003FF != 0x91000210 \
            or fourth != 0xD61F0220:
        return None
    imm = ((first >> 5 & 0x7FFFF) << 2) | (first >> 29 & 3)
    imm = (imm - (1 << 21) if imm & (1 << 20) else imm) << 12
    return (pc & ~0xFFF) + imm + ((second >> 10 & 0xFFF) << 3)


def _stub_slots(module: Module) -> dict[int, int]:
    """{stub address: the slot it jumps through} for every stub in the code segment."""
    text = next((s for s in module.segments if s.name == "text"), None)
    found: dict[int, int] = {}
    if text is None:
        return found
    image, end = module.image, text.offset + text.size
    at = image.find(STUB_BRANCH, text.offset + 12, end)
    while at != -1:
        pc = at - 12
        if pc % 4 == 0:
            slot = _stub_at(struct.unpack_from("<4I", image, pc), pc)
            if slot is not None:
                found[pc] = slot
        at = image.find(STUB_BRANCH, at + 4, end)
    return found


def _plt(module: Module) -> None:
    """`.plt`: the linker's stubs, one per jump slot of `.got.plt` (after its three reserved words) in slot order,
    16 bytes each, led by the header (stp x16, x30 / a stub's four words through the reserved slot that holds the
    resolver / padding to 32 bytes). Recorded only when the stubs of every jump slot are one run, as lld and GNU ld
    lay them out."""
    got = module.tables.get(".got.plt")
    if got is None or got[1] - got[0] <= 24:
        return
    first, count = got[0] + 24, (got[1] - got[0]) // 8 - 3
    by_slot = {slot: pc for pc, slot in _stub_slots(module).items() if first <= slot < got[1] and slot % 8 == 0}
    start = by_slot.get(first)
    if start is None or any(by_slot.get(first + 8 * k) != start + 16 * k for k in range(count)):
        return
    head = start - 32
    if head >= 0 and module.segment_at(head) is module.segment_at(start):
        words = struct.unpack_from("<8I", module.image, head)
        if words[0] == PLT_PUSH and _stub_at(words[1:5], head + 4) == got[0] + 16 \
                and all(w == NOP for w in words[5:]):
            start = head
    module.tables[".plt"] = (start, by_slot[first] + 16 * count)


def load(path: Path) -> Module:
    raw = path.read_bytes()
    if raw[:4] == NSO_MAGIC:
        return _from_nso(raw)
    if raw[:4] == b"\x7fELF":
        return _from_elf(raw)
    raise ValueError(f"{path} is neither an NSO module nor an ELF file")


def _from_nso(raw: bytes) -> Module:
    flags = struct.unpack_from("<I", raw, 0xC)[0]
    headers = [struct.unpack_from("<III", raw, 0x10 + i * 0x10) for i in range(3)]
    bss = struct.unpack_from("<I", raw, 0x3C)[0]
    packed = struct.unpack_from("<III", raw, 0x60)
    build_id = raw[0x40:0x60].rstrip(b"\0").hex()
    end = max(memory + size for _, memory, size in headers)
    image = bytearray(end + bss)
    segments = []
    for index, ((file_offset, memory, size), stored, name) in enumerate(zip(headers, packed, ("text", "rodata", "data"))):
        chunk = raw[file_offset:file_offset + stored]
        data = _decompress(chunk, size) if flags & (1 << index) else chunk[:size]
        image[memory:memory + size] = data
        segments.append(Segment(name, memory, size, "code" if name == "text" else "data"))
    data_end = headers[2][1] + headers[2][2]
    if bss:
        segments.append(Segment("bss", data_end, bss, "data"))
    module = Module(image, segments, build_id, raw=bytes(image),
                    hashes={name: raw[0xA0 + 0x20 * i:0xC0 + 0x20 * i] for i, name in enumerate(("text", "rodata", "data"))})
    _read_mod0(module)
    return module


def _from_elf(raw: bytes) -> Module:
    """An ELF of a module (as written by `to_elf`, nx2elf or a debug build): its PT_LOAD segments."""
    from .elf import Elf
    elf = Elf(raw)
    if elf.bits != 64:
        raise ValueError("Switch modules are 64-bit ELF files")
    phoff, phentsize, phnum = struct.unpack_from("<Q", raw, 32)[0], *struct.unpack_from("<HH", raw, 54)
    loads = []
    for i in range(phnum):
        kind, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", raw, phoff + i * phentsize)
        if kind == 1:
            loads.append((vaddr, offset, filesz, memsz, flags))
    base = min(v for v, *_ in loads) if loads else 0
    end = max(v + m for v, _, _, m, _ in loads) - base if loads else 0
    image = bytearray(end)
    segments = []
    for vaddr, offset, filesz, memsz, flags in sorted(loads):
        image[vaddr - base:vaddr - base + filesz] = raw[offset:offset + filesz]
        name = "text" if flags & 1 else "data" if flags & 2 else "rodata"  # PF_X, PF_W
        if filesz:
            segments.append(Segment(name, vaddr - base, filesz, "code" if flags & 1 else "data"))
        if memsz > filesz:
            segments.append(Segment("bss", vaddr - base + filesz, memsz - filesz, "data"))
    module = Module(image, segments, raw=bytes(image))
    for symbol in elf.symbols:
        if symbol.name and 0 < symbol.section < 0xFF00 and symbol.kind in ("func", "object"):
            module.symbols.setdefault(symbol.value - base, symbol.name)
            module.sizes.setdefault(symbol.value - base, symbol.size)
            module.kinds.setdefault(symbol.value - base, symbol.kind)
            if symbol.bind == "weak":
                module.weak.add(symbol.value - base)
    _read_mod0(module)
    if not module.pointers:  # a plain ELF: its PT_DYNAMIC holds the same tables MOD0 points at
        for i in range(phnum):
            kind, _, offset, vaddr, *_ = struct.unpack_from("<IIQQQQQQ", raw, phoff + i * phentsize)
            if kind == 2:
                _read_dynamic(module, vaddr - base)
            elif kind == 0x6474E550 and module.eh_frame_hdr is None:  # PT_GNU_EH_FRAME
                filesz = struct.unpack_from("<Q", raw, phoff + i * phentsize + 32)[0]
                module.eh_frame_hdr = (vaddr - base, vaddr - base + filesz)
        _unwind_tables(module)
    return module


def _read_mod0(module: Module) -> None:
    """MOD0 -> dynamic section -> symbols, relocations, init array, unwind table."""
    image = module.image
    if len(image) < 8:
        return
    mod0 = struct.unpack_from("<I", image, 4)[0]
    if image[mod0:mod0 + 4] != b"MOD0":
        return
    dynamic, bss_start, bss_end, eh_start, eh_end, _ = struct.unpack_from("<iiiiii", image, mod0 + 4)
    if bss_end > bss_start:
        module.bss_end = mod0 + bss_end
    if eh_end > eh_start:
        module.eh_frame_hdr = (mod0 + eh_start, mod0 + eh_end)
    module.tables["MOD0"] = (mod0, mod0 + 28)
    _read_dynamic(module, dynamic + mod0)
    _unwind_tables(module)


def _unwind_tables(module: Module) -> None:
    """`.eh_frame_hdr`, and `.eh_frame` from where the header says it starts to the end of what it holds."""
    if module.eh_frame_hdr is None:
        return
    start, end = module.eh_frame_hdr
    module.tables[".eh_frame_hdr"] = (start, end)
    try:
        frame, _ = _encoded(module, start + 4, module.image[start + 1], start)
    except (ValueError, struct.error):
        return
    position = frame
    while position + 4 <= len(module.image):         # CIEs and FDEs, each length-prefixed, up to a zero length
        length = struct.unpack_from("<I", module.image, position)[0]
        if not length or length == 0xFFFFFFFF:
            position += 4 if not length else 0
            break
        position += 4 + length
    module.tables[".eh_frame"] = (frame, position)


def _read_dynamic(module: Module, dynamic: int) -> None:
    image = module.image
    tags: dict[int, int] = {}
    position = dynamic
    while position + 16 <= len(image):
        tag, value = struct.unpack_from("<qQ", image, position)
        position += 16
        if tag == DT_NULL:
            break
        tags.setdefault(tag, value)
    module.tables[".dynamic"] = (dynamic, position)
    strtab, symtab = tags.get(DT_STRTAB), tags.get(DT_SYMTAB)
    for name, start_tag, size_tag in ((".dynstr", DT_STRTAB, DT_STRSZ), (".rela.dyn", DT_RELA, DT_RELASZ),
                                      (".rela.plt", DT_JMPREL, DT_PLTRELSZ), (".relr.dyn", DT_RELR, DT_RELRSZ),
                                      (".init_array", DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
                                      (".fini_array", DT_FINI_ARRAY, DT_FINI_ARRAYSZ)):
        if tags.get(start_tag) is not None and tags.get(size_tag):
            module.tables[name] = (tags[start_tag], tags[start_tag] + tags[size_tag])
    if tags.get(DT_HASH) is not None:                 # nbucket, nchain, then the buckets and chains
        start = tags[DT_HASH]
        buckets, chains = struct.unpack_from("<II", image, start)
        module.tables[".hash"] = (start, start + 8 + 4 * (buckets + chains))
    if tags.get(DT_GNU_HASH) is not None:             # header, bloom words, buckets, then chains to their last
        start = tags[DT_GNU_HASH]
        buckets, first, blooms, _ = struct.unpack_from("<IIII", image, start)
        chain = start + 16 + 8 * blooms + 4 * buckets
        top = max(struct.unpack_from(f"<{buckets}I", image, chain - 4 * buckets), default=0)
        if top >= first:
            position = chain + 4 * (top - first)
            while position + 4 <= len(image) and not struct.unpack_from("<I", image, position)[0] & 1:
                position += 4
            chain = position + 4
        module.tables[".gnu.hash"] = (start, chain)
    names: list[tuple[str, int, int]] = []
    if strtab is not None and symtab is not None:
        count = (strtab - symtab) // 24 if strtab > symtab else 0
        module.tables[".dynsym"] = (symtab, symtab + 24 * count)
        for i in range(count):
            name, info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", image, symtab + i * 24)
            end = image.find(b"\0", strtab + name)
            text = image[strtab + name:end].decode("utf-8", errors="replace")
            names.append((text, shndx, value))
            if text and shndx and value:
                module.symbols.setdefault(value, text)
                module.sizes.setdefault(value, size)
                module.kinds.setdefault(value, "func" if info & 0xF == 2 else "object")
                if info >> 4 == 2:                                  # STB_WEAK
                    module.weak.add(value)
    for start_tag, size_tag in ((DT_RELA, DT_RELASZ), (DT_JMPREL, DT_PLTRELSZ)):
        start, size = tags.get(start_tag), tags.get(size_tag)
        if start is None or not size:
            continue
        for i in range(size // 24):
            offset, info, addend = struct.unpack_from("<QQq", image, start + i * 24)
            kind, index = info & 0xFFFFFFFF, info >> 32
            if offset + 8 > len(image):
                continue
            if kind == R_AARCH64_RELATIVE:
                struct.pack_into("<Q", image, offset, addend & 0xFFFFFFFFFFFFFFFF)
                module.pointers[offset] = addend
            elif kind in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT) and index < len(names):
                name, shndx, value = names[index]
                if shndx and value:
                    struct.pack_into("<Q", image, offset, (value + addend) & 0xFFFFFFFFFFFFFFFF)
                    module.pointers[offset] = value + addend
                else:
                    module.imports[offset] = name if not addend else f"{name}+0x{addend:X}"
    start, size = tags.get(DT_RELR), tags.get(DT_RELRSZ)
    if start is not None and size:  # packed relative relocations: an address, then bitmaps of the next 63 words
        where = 0
        for i in range(size // 8):
            entry = struct.unpack_from("<Q", image, start + i * 8)[0]
            if entry & 1 == 0:
                where = entry
                if where + 8 <= len(image):
                    module.pointers[where] = struct.unpack_from("<Q", image, where)[0]
                where += 8
            else:
                bits = entry >> 1
                for bit in range(63):
                    if bits >> bit & 1:
                        slot = where + bit * 8
                        if slot + 8 <= len(image):
                            module.pointers[slot] = struct.unpack_from("<Q", image, slot)[0]
                where += 63 * 8
    start, size = tags.get(DT_INIT_ARRAY), tags.get(DT_INIT_ARRAYSZ)
    if start is not None and size:
        module.init_array = [module.u64(start + i * 8) for i in range(size // 8)]
    if tags.get(DT_PLTGOT) is not None:              # three reserved words, then a slot per jump-slot relocation
        start = tags[DT_PLTGOT]
        module.tables[".got.plt"] = (start, start + 8 * (3 + (tags.get(DT_PLTRELSZ) or 0) // 24))
    _got(module, dynamic)
    _plt(module)


def _got(module: Module, dynamic: int) -> None:
    """`.got`: the slots code loads addresses from, every one relocated, up to the first word no relocation fills
    or the next of the linker's tables. It follows `.dynamic` (lld), or, led by a word holding `.dynamic`'s own
    address, precedes `.got.plt` (GNU ld, whose spare dynamic entries part it from `.dynamic`) or follows it
    (Nintendo's linker)."""
    taken = list(module.tables.values())

    def word(at: int) -> int | None:
        segment = module.section_at(at)
        return module.u64(at) if segment is not None and at + 8 <= segment.offset + segment.size else None

    def slot(at: int) -> bool:
        return word(at) is not None and (at in module.pointers or at in module.imports) \
            and not any(a <= at < b for a, b in taken)

    def after(start: int, led: bool) -> tuple[int, int] | None:
        end = first = start + 8 if word(start) == dynamic else start
        if led and first == start:
            return None
        while slot(end):
            end += 8
        return (start, end) if end > first else None

    def before(end: int) -> tuple[int, int] | None:
        start = end
        while slot(start - 8):
            start -= 8
        return (start - 8, end) if start < end and word(start - 8) == dynamic else None
    plt = module.tables.get(".got.plt")
    found = after(module.tables[".dynamic"][1], False) or (plt and (before(plt[0]) or after(plt[1], True)))
    if found:
        module.tables[".got"] = found


def _encoded(module: Module, position: int, encoding: int, data_base: int = 0) -> tuple[int, int]:
    """(value, bytes read) of a DWARF pointer encoding."""
    form, apply = encoding & 0x0F, encoding & 0x70
    image = module.image
    if form == 0x0B:      # sdata4
        value, size = struct.unpack_from("<i", image, position)[0], 4
    elif form == 0x03:    # udata4
        value, size = struct.unpack_from("<I", image, position)[0], 4
    elif form == 0x0C:    # sdata8
        value, size = struct.unpack_from("<q", image, position)[0], 8
    elif form in (0x04, 0x00):  # udata8 / absptr
        value, size = struct.unpack_from("<Q", image, position)[0], 8
    elif form == 0x0A:    # sdata2
        value, size = struct.unpack_from("<h", image, position)[0], 2
    else:
        raise ValueError(f"unsupported pointer encoding 0x{encoding:02X}")
    if apply == 0x10:
        value += position
    elif apply == 0x30:
        value += data_base
    return value, size


def _uleb(module: Module, position: int) -> tuple[int, int]:
    value = shift = 0
    start = position
    while True:
        byte = module.image[position]
        position += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, position - start


def _eh_frame_functions(module: Module, start: int, end: int) -> list[tuple[int, int]]:
    image = module.image
    version, frame_enc, count_enc, table_enc = image[start:start + 4]
    if version != 1:
        return []
    position = start + 4
    _, used = _encoded(module, position, frame_enc, start)
    position += used
    count, used = _encoded(module, position, count_enc, start)
    position += used
    cie_encodings: dict[int, int] = {}
    out = []
    for _ in range(count):
        _, used = _encoded(module, position, table_enc, start)
        position += used
        fde, used = _encoded(module, position, table_enc, start)
        position += used
        cie = fde + 4 - struct.unpack_from("<I", image, fde + 4)[0]
        if cie not in cie_encodings:
            cie_encodings[cie] = _cie_encoding(module, cie)
        encoding = cie_encodings[cie]
        begin, used = _encoded(module, fde + 8, encoding)
        length, _ = _encoded(module, fde + 8 + used, encoding & 0x0F)
        if length:
            out.append((begin, length))
    return sorted(set(out))


def _cie_encoding(module: Module, cie: int) -> int:
    """The FDE pointer encoding a CIE's augmentation ('zR...') declares."""
    image = module.image
    position = cie + 9  # length, id, version
    end = image.find(b"\0", position)
    augmentation = image[position:end].decode("ascii", errors="replace")
    position = end + 1
    for _ in range(2):  # code and data alignment factors (LEB128)
        _, used = _uleb(module, position)
        position += used
    position += 1  # return address register (version 1: one byte)
    if not augmentation.startswith("z"):
        return 0x00
    _, used = _uleb(module, position)
    position += used
    for letter in augmentation[1:]:
        if letter == "R":
            return image[position]
        if letter == "P":
            encoding = image[position]
            position += 1
            _, used = _encoded(module, position, encoding)
            position += used
        elif letter == "L":
            position += 1
    return 0x00


def to_elf(module: Module, base: int = DEFAULT_BASE, functions: list[tuple[int, int, str]] | None = None) -> bytes:
    """An ELF executable of the loaded module (segments at `base`), with function symbols when given, for tools
    that read ELF: disassemblers, Ghidra's own AArch64 loader, objdiff."""
    sections = [s for s in module.segments]
    names = [b"", b".shstrtab", b".symtab", b".strtab"] + [f".{s.name}".encode() for s in sections]
    shstr = b"\0".join(names) + b"\0"
    name_offsets = {}
    cursor = 0
    for n in names:
        name_offsets[n] = cursor
        cursor += len(n) + 1
    strings = bytearray(b"\0")
    symbols = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    text_index = 4 + next((i for i, s in enumerate(sections) if s.name == "text"), 0)
    for start, size, name in functions or []:
        symbols.append(struct.pack("<IBBHQQ", len(strings), 0x12, 0, text_index, base + start, size))
        strings += name.encode() + b"\0"
    header_size, phsize = 64, 56
    loadable = [s for s in sections if s.name != "bss"]
    data_offset = header_size + phsize * len(sections)
    data_offset = (data_offset + 0xFFF) & ~0xFFF
    blob = bytearray(data_offset)
    file_offsets = {}
    for segment in loadable:
        file_offsets[segment.name] = len(blob)
        blob += module.image[segment.offset:segment.offset + segment.size]
        blob += b"\0" * (-len(blob) % 0x1000)
    tables = len(blob)
    blob += shstr
    symtab_offset = len(blob) + (-len(blob) % 8)
    blob += b"\0" * (symtab_offset - len(blob)) + b"".join(symbols)
    strtab_offset = len(blob)
    blob += strings
    shoff = len(blob) + (-len(blob) % 8)
    blob += b"\0" * (shoff - len(blob))
    program = bytearray()
    for segment in sections:
        flags = 5 if segment.kind == "code" else (4 if segment.name == "rodata" else 6)
        offset = file_offsets.get(segment.name, 0)
        filesz = 0 if segment.name == "bss" else segment.size
        program += struct.pack("<IIQQQQQQ", 1, flags, offset, base + segment.offset, base + segment.offset,
                               filesz, segment.size, 0x1000)
    blob[header_size:header_size + len(program)] = program
    shdrs = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             struct.pack("<IIQQQQIIQQ", name_offsets[b".shstrtab"], 3, 0, 0, tables, len(shstr), 0, 0, 1, 0),
             struct.pack("<IIQQQQIIQQ", name_offsets[b".symtab"], 2, 0, 0, symtab_offset, len(symbols) * 24, 3, 1,
                         8, 24),
             struct.pack("<IIQQQQIIQQ", name_offsets[b".strtab"], 3, 0, 0, strtab_offset, len(strings), 0, 0, 1, 0)]
    for segment in sections:
        kind = 8 if segment.name == "bss" else 1
        flags = 6 if segment.kind == "code" else (2 if segment.name == "rodata" else 3)
        shdrs.append(struct.pack("<IIQQQQIIQQ", name_offsets[f".{segment.name}".encode()], kind, flags,
                                 base + segment.offset, file_offsets.get(segment.name, 0), segment.size, 0, 0,
                                 0x1000 if segment.kind == "code" else 8, 0))
    blob += b"".join(shdrs)
    header = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
    header += struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, base, header_size, shoff, 0, header_size, phsize,
                          len(sections), 64, len(shdrs), 1)
    blob[:header_size] = header
    return bytes(blob)
