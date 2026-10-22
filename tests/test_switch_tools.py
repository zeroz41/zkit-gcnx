"""Read-only tools on a hand-built Switch module (an NSO with MOD0, a dynamic section and relocations): typed data
reads and strings, vtable slots, and the GOT, which code reaches through and no unit owns. No compiler needed."""

import support  # noqa: F401  (isolates config, cache and state)
import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import nx

RELATIVE, GLOB_DAT, JUMP_SLOT = nx.R_AARCH64_RELATIVE, nx.R_AARCH64_GLOB_DAT, nx.R_AARCH64_JUMP_SLOT
TEXT, RODATA, DATA, END = 0x0, 0x1000, 0x2000, 0x3000
VTABLE, NUMBERS, DYNAMIC, GOT_PLT, GOT, INIT = 0x2000, 0x2020, 0x2100, 0x2200, 0x2220, 0x2240
GNU_GOT = 0x21E0                                                       # .got right before .got.plt, as GNU ld puts it
SJIS, UTF8, LATIN = RODATA, RODATA + 0x10, RODATA + 0x30


def adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | (imm & 3) << 29 | (imm >> 2 & 0x7FFFF) << 5 | rd


def ldr(rt, rn, offset):
    return 0xF9400000 | (offset // 8) << 10 | rn << 5 | rt


def add(rd, rn, imm):
    return 0x91000000 | imm << 10 | rn << 5 | rd


RET = 0xD65F03C0


def module(got: int = GOT, bss: int = 0x100) -> bytes:
    """An NSO: two functions that reach a vtable and an import through the GOT and one that forms a table's address;
    the vtable (its methods relocated), a table of plain numbers, strings in three encodings, and the linker's
    tables laid out as Nintendo's linker does: .dynamic, .got.plt, .got (led by .dynamic's address), .init_array
    (or with the .got at `GNU_GOT`)."""
    image = bytearray(END)
    struct.pack_into("<I", image, 4, 0x8)                              # MOD0 at 8
    image[0x8:0xC] = b"MOD0"
    struct.pack_into("<6i", image, 0xC, DYNAMIC - 0x8, END - 0x8, END + 0x100 - 0x8, 0, 0, 0)
    code = {0x100: [adrp(8, 0x100, got + 8), ldr(8, 8, (got + 8) & 0xFFF), add(8, 8, 16), RET],
            0x120: [adrp(9, 0x120, got + 16), ldr(9, 9, (got + 16) & 0xFFF), RET],
            0x140: [adrp(10, 0x140, NUMBERS), add(10, 10, NUMBERS & 0xFFF), RET],
            0x160: [0x94000000 | ((0x100 - 0x160) >> 2 & 0x3FFFFFF), RET]}   # bl foo_set
    for start, words in code.items():
        struct.pack_into(f"<{len(words)}I", image, start, *words)
    image[SJIS:SJIS + 13] = "キャラツリー".encode("shift_jis") + b"\0"
    image[UTF8:UTF8 + 19] = "武器モーション".encode("utf-8") + b"\0"
    image[LATIN:LATIN + 6] = b"\x80Caf\xe9\0"                         # neither encoding: escaped
    struct.pack_into("<2Q", image, NUMBERS, 3, 10)                    # plain numbers, never relocated
    names = b"\0ext_func\0ext_data\0"
    symbols = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0) + struct.pack("<IBBHQQ", 1, 0x12, 0, 0, 0, 0) + \
        struct.pack("<IBBHQQ", 10, 0x11, 0, 0, 0, 0)
    relocations = [(VTABLE + 0x10, RELATIVE, 0, 0x100), (VTABLE + 0x18, RELATIVE, 0, 0x120),
                   (NUMBERS + 0x10, RELATIVE, 0, SJIS), (got + 8, RELATIVE, 0, VTABLE), (got + 16, GLOB_DAT, 2, 0),
                   (got + 24, RELATIVE, 0, NUMBERS), (INIT, RELATIVE, 0, 0x140)]
    rela = b"".join(struct.pack("<QQq", at, index << 32 | kind, addend) for at, kind, index, addend in relocations)
    plt = struct.pack("<QQq", GOT_PLT + 24, 1 << 32 | JUMP_SLOT, 0)
    symtab, strtab, rela_at, plt_at = RODATA + 0x100, RODATA + 0x148, RODATA + 0x200, RODATA + 0x300
    image[symtab:symtab + len(symbols)] = symbols
    image[strtab:strtab + len(names)] = names
    image[rela_at:rela_at + len(rela)] = rela
    image[plt_at:plt_at + len(plt)] = plt
    struct.pack_into("<Q", image, got, DYNAMIC)                       # GOT[0]: .dynamic, as linked
    tags = [(nx.DT_SYMTAB, symtab), (nx.DT_STRTAB, strtab), (nx.DT_STRSZ, len(names)), (nx.DT_RELA, rela_at),
            (nx.DT_RELASZ, len(rela)), (nx.DT_JMPREL, plt_at), (nx.DT_PLTRELSZ, len(plt)), (3, GOT_PLT),
            (nx.DT_INIT_ARRAY, INIT), (nx.DT_INIT_ARRAYSZ, 8), (nx.DT_NULL, 0)]
    for index, (tag, value) in enumerate(tags):
        struct.pack_into("<qQ", image, DYNAMIC + index * 16, tag, value)
    header = bytearray(0x100)
    header[:4] = b"NSO0"
    for index, (start, end) in enumerate(((TEXT, RODATA), (RODATA, DATA), (DATA, END))):
        struct.pack_into("<III", header, 0x10 + index * 0x10, 0x100 + start, start, end - start)
    struct.pack_into("<I", header, 0x3C, bss)                         # .bss
    struct.pack_into("<III", header, 0x60, RODATA - TEXT, DATA - RODATA, END - DATA)
    return bytes(header + image)


SYMBOLS = """foo_set = .text:0x00000100; // type:function size:0x10 scope:global
foo_data = .text:0x00000120; // type:function size:0xC scope:global
numbers = .text:0x00000140; // type:function size:0xC scope:global
lbl_7100001000 = .rodata:0x00001000; // type:object size:0x10 scope:global
lbl_7100001010 = .rodata:0x00001010; // type:object size:0x20 scope:global
lbl_7100001030 = .rodata:0x00001030; // type:object size:0x6 scope:global
_ZTV3Foo = .data:0x00002000; // type:object size:0x20 scope:global
lbl_7100002020 = .data:0x00002020; // type:object size:0x18 scope:global
lbl_7100002220 = .data:0x00002220; // type:object size:0x20 scope:global
"""
SPLITS = """a.cpp:
\t.text start:0x00000100 end:0x00000140
\t.data start:0x00002000 end:0x00002020

b.cpp:
\t.text start:0x00000140 end:0x00000150
\t.data start:0x00002020 end:0x00002038
"""


class SwitchToolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        from zkit.index import close_connections
        self.addCleanup(close_connections)
        self.root = Path(temp.name)
        for var in ("XDG_CACHE_HOME", "XDG_STATE_HOME"):
            os.environ[var] = str(self.root / var.lower())
        os.environ["ZKIT_REFRESH_TTL"] = "0"
        (self.root / "main").write_bytes(module())
        (self.root / "symbols.txt").write_text(SYMBOLS, encoding="utf-8")
        (self.root / "splits.txt").write_text(SPLITS, encoding="utf-8")
        (self.root / "project.json").write_text(json.dumps({
            "schema_version": 1, "id": "switch-tools", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
            "targets": {"t": {"repository": "decomp", "platform": "switch", "module": "main", "original": "main",
                              "symbols": "symbols.txt", "splits": "splits.txt"}}}), encoding="utf-8")
        from zkit.project import Project
        self.project = Project.load(self.root / "project.json")

    def test_bss_ends_where_mod0_says_not_at_the_page_rounded_size(self):
        """An NSO header gives .bss's size rounded up to a page; MOD0 gives where its objects end. The rest is
        padding: no unit's range reaches into it."""
        image = nx.load(self.root / "main")
        self.assertEqual(image.bss, (END, 0x100))
        (self.root / "main").write_bytes(module(bss=0x1000))
        image = nx.load(self.root / "main")
        self.assertEqual(image.bss, (END, 0x100))
        self.assertEqual(next(s for s in image.segments if s.name == "bss").size, 0x1000)
        from zkit import nxdata
        struct.pack_into("<I", image.image, DATA + 0x400, 0)                # nothing refers into .bss but a pointer
        image.pointers[DATA + 0x400] = END + 0x80
        found = {a: (size, section) for a, size, section in nxdata.objects(image, [])}
        self.assertEqual(found[END + 0x80], (0x80, ".bss"))                 # to MOD0's end, not the page's

    def test_a_section_placed_past_the_originals_end_is_a_problem_not_a_crash(self):
        """A section whose bytes would run past the end of the original image (an inline the original has no copy
        of, placed by a name that lands at its end) is reported, and the rebuilt image keeps its size."""
        from types import SimpleNamespace
        from zkit import nxlink
        from zkit.platform import Switch
        original = bytes(64)
        linker = SimpleNamespace(original=original, image=bytearray(original), platform=Switch(),
                                 segment=lambda at: None)
        section = SimpleNamespace(name=".text._Zfoo", size=16, type=1, flags=0)
        item = nxlink.Placed(section, 56, bytearray(16), "u", "name")
        result = nxlink.UnitLink("u", True)
        nxlink._compare(linker, item, result)
        self.assertEqual(len(linker.image), 64)
        self.assertTrue(any("run past the original's end" in p for p in result.problems))

    def test_a_link_reaches_a_structor_by_its_partner_when_the_original_names_one(self):
        """clang emits a class's complete- and base-object destructors (D1, D2) as one function under both names;
        the module keeps one. A derived destructor's call to its base's D2 lands on the base's D1, and a
        constructor's C1 on its C2; a pair the original names apart (a class with virtual bases) keeps its own."""
        from zkit import nxlink
        self.assertEqual(nxlink.structor_partner("_ZN2fw14CommonResourceD2Ev"), "_ZN2fw14CommonResourceD1Ev")
        self.assertEqual(nxlink.structor_partner("_ZN2gf3FooC1Ei"), "_ZN2gf3FooC2Ei")
        self.assertEqual(nxlink.structor_partner("_ZN2mm3mtl12PtrSingletonIN2gf3FooEED2Ev"),
                         "_ZN2mm3mtl12PtrSingletonIN2gf3FooEED1Ev")
        self.assertIsNone(nxlink.structor_partner("_ZN3Foo3setEv"))
        self.assertIsNone(nxlink.structor_partner("_Z6helperi"))
        (self.root / "symbols.txt").write_text(SYMBOLS.replace("foo_set = ", "_ZN3FooD1Ev = ").replace(
            "foo_data = ", "_ZN3BarC2Ev = ").replace("numbers = ", "_ZN3BazD2Ev = ") +
            "_ZN3BazD1Ev = .text:0x00000148; // type:function size:0x4 scope:global\n", encoding="utf-8")
        linker = nxlink.Linker(self.project, "t")
        self.assertEqual(linker.by_name("_ZN3FooD2Ev", None, []), 0x100)
        self.assertEqual(linker.by_name("_ZN3BarC1Ev", None, []), 0x120)
        self.assertEqual(linker.by_name("_ZN3BazD1Ev", None, []), 0x148)    # named apart: its own
        self.assertIsNone(linker.by_name("_ZN3QuxD2Ev", None, []))

    def test_a_link_points_a_table_slot_at_an_import_the_original_imports_there(self):
        """A class table's slot holds an import (`__cxa_pure_virtual`): the compiled table points at it by name, and
        the link keeps the original's word where the module's dynamic relocation names that import."""
        from types import SimpleNamespace
        from zkit import nxlink
        from zkit.elf import Symbol
        linker = nxlink.Linker(self.project, "t")
        name, slots = next(iter(linker.imported.items()))
        imported = Symbol(1, name, 0, 0, "notype", "global", 0)
        relocation = SimpleNamespace(type=nxlink.ABS64, addend=0, offset=0)
        value, _ = nxlink._value(linker, SimpleNamespace(elf=None, ranges=[]), imported, relocation, slots[0], None,
                                 [], {}, None)
        self.assertEqual(value, -1)
        item = nxlink.Placed(None, slots[0], bytearray(8), "a.cpp", "name")
        nxlink._apply(linker, item, relocation, value, imported)
        self.assertEqual(bytes(item.data), linker.original[slots[0]:slots[0] + 8])
        other = Symbol(2, name + "_other", 0, 0, "notype", "global", 0)
        with self.assertRaises(ValueError):
            nxlink._value(linker, SimpleNamespace(elf=None, ranges=[]), other, relocation, slots[0], None, [], {},
                          None)

    def test_a_table_slot_reaches_an_inline_the_link_kept_elsewhere_by_its_pointer(self):
        """A class table's slot points at an inline virtual the object emits as its own COMDAT copy, which no name
        places. The module's pointer in that slot says where it goes: another unit's identical copy (the one the
        link kept, or folded with identical code) is used, not placed; a copy whose bytes differ is a problem; a
        pointer inside the unit places it there."""
        from types import SimpleNamespace
        from zkit import nxlink
        from zkit.elf import Section, Symbol
        from zkit.platform import Switch
        ret = bytes.fromhex("c0035fd6")
        original = bytearray(0x100)
        original[0x40:0x44] = ret
        original[0x80:0x84] = ret
        slot, outside, inside = 0xC0, 0x40, 0x80
        linker = SimpleNamespace(original=bytes(original), platform=Switch(), module=SimpleNamespace(pointers={}),
                                 by_name=lambda name, hint, ranges: None)   # no name places it
        section = Section(1, ".text._ZN3Foo2vfEv", 1, nxlink.SHF_ALLOC | nxlink.SHF_EXECINSTR | nxlink.SHF_GROUP,
                          0, 0, 4, 0, 0, 0)
        elf = SimpleNamespace(sections=[None, section], relocations=lambda s: [], data=lambda s: ret)
        symbol = Symbol(1, "_ZN3Foo2vfEv", 0, 4, "func", "weak", 1)
        relocation = SimpleNamespace(type=nxlink.ABS64, addend=0, offset=0)
        obj = SimpleNamespace(elf=elf, ranges=[(0x80, 0x90), (0xC0, 0xC8)], whole=True, unit="u")

        def value(pointee, data=ret):
            elf.data = lambda s: data
            result, placed = nxlink.UnitLink("u", True), {}
            address, new = nxlink._value(linker, obj, symbol, relocation, slot, ("address", pointee), [], placed,
                                         result)
            return address, new, placed, result

        address, new, placed, result = value(outside)
        self.assertEqual((address, new, placed, result.folded), (outside, [], {}, ["_ZN3Foo2vfEv"]))
        with self.assertRaises(ValueError):
            value(outside, bytes.fromhex("1f2003d5"))
        address, new, placed, result = value(inside)
        self.assertEqual((address, new, result.folded), (inside, [("u", 1)], []))
        self.assertEqual(placed[("u", 1)].address, inside)

    def read(self, address, kind=None, **options):
        from zkit.inspect_dol import read_data
        return read_data(self.project, "t", address, kind, **options)

    @unittest.skipUnless(shutil.which("llvm-objdump"), "needs llvm-objdump")
    def test_asm_names_a_branch_target_by_its_current_name(self):
        """The disassembler reads a cached ELF of the module, written with the names of its time; a rename since
        must still name the branch target."""
        from zkit.inspect_dol import disasm
        caller = "caller = .text:0x00000160; // type:function size:0x8 scope:global\n"
        (self.root / "symbols.txt").write_text(SYMBOLS + caller, encoding="utf-8")
        self.assertIn("<foo_set>", disasm(self.project, "t", 0x160)["text"])
        (self.root / "symbols.txt").write_text(SYMBOLS.replace("foo_set", "foo_renamed") + caller, encoding="utf-8")
        self.assertIn("<foo_renamed>", disasm(self.project, "t", 0x160)["text"])

    def test_words_are_pointer_sized_where_the_module_relocates_them(self):
        table = self.read(VTABLE)
        self.assertEqual(table["kind"], "ptr")                         # a vtable: four slots, not eight halves
        self.assertEqual([r["values"][0] for r in table["rows"]],
                         ["0x0", "0x0", "0x7100000100 (foo_set)", "0x7100000120 (foo_data)"])
        self.assertEqual(self.read(SJIS)["kind"], "u32")              # nothing relocated: words

    def test_a_word_is_a_pointer_only_where_the_module_says_so(self):
        rows = [r["values"][0] for r in self.read(NUMBERS, "ptr", count=3)["rows"]]
        self.assertEqual(rows, ["0x3", "0xA", "0x7100001000 (lbl_7100001000)"])
        self.assertEqual(self.read(GOT + 16, "ptr", count=1)["rows"][0]["values"], ["ext_data (import)"])

    def test_strings_in_the_encoding_their_bytes_are(self):
        texts = [self.read(a, "str")["rows"][0]["values"][0] for a in (SJIS, UTF8, LATIN)]
        self.assertEqual(texts, ["キャラツリー", "武器モーション", "\\x80Caf\xe9"])

    def test_vtable_slots_count_from_the_first_virtual_in_both_views(self):
        from zkit.bridge import lookup
        from zkit.render import lookup as render
        table = render(lookup(self.project, "_ZTV3Foo"))
        self.assertIn("+0x10 (slot 0) -> 0x7100000100 foo_set", table)   # after offset-to-top and typeinfo
        self.assertIn("+0x18 (slot 1) -> 0x7100000120 foo_data", table)
        self.assertIn("vtable slot +0x18 (slot 1) in 1 table(s): _ZTV3Foo", render(lookup(self.project, "foo_data")))
        self.assertIn("+0x10 (slot 2) -> 0x7100001000", render(lookup(self.project, "lbl_7100002020")))  # 8-byte words

    def test_the_got_is_found_beside_got_plt(self):
        (self.root / "gnu").write_bytes(module(GNU_GOT))
        nintendo, gnu = nx.load(self.root / "main"), nx.load(self.root / "gnu")
        self.assertEqual(nintendo.tables[".got.plt"], (GOT_PLT, GOT_PLT + 32))   # three reserved words, one jump slot
        self.assertEqual(nintendo.tables[".got"], (GOT, INIT))                   # after .got.plt, up to .init_array
        self.assertEqual(gnu.tables[".got"], (GNU_GOT, GOT_PLT))                 # before it, past spare dynamic entries

    def test_code_reaching_through_the_got_refers_to_what_it_holds(self):
        from zkit.bridge import lookup, xrefs
        from zkit.render import lookup as render
        from zkit.structure import unit
        refs = xrefs(self.project, "_ZTV3Foo")
        self.assertEqual((refs["kinds"], refs["data_total"]), ({"addr": 2}, 0))   # foo_set's; the GOT slot is no data
        self.assertEqual(xrefs(self.project, "lbl_7100002220")["total"], 0)
        self.assertNotIn("pointed to from", render(lookup(self.project, "_ZTV3Foo")))
        view = unit(self.project, "a.cpp")
        self.assertEqual([(d["name"], d["refs_outside"]) for d in view["data"]], [("_ZTV3Foo", [])])
        self.assertEqual(view["outgoing"], [])                                    # the GOT is nobody's data
        self.assertIn("adrp/add", view["limits"])


if __name__ == "__main__":
    unittest.main()
