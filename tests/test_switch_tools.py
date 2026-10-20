"""Read-only tools on a hand-built Switch module (an NSO with MOD0, a dynamic section and relocations): typed data
reads and strings, and vtable slots. No compiler needed."""

import support  # noqa: F401  (isolates config, cache and state)
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import nx

RELATIVE, GLOB_DAT, JUMP_SLOT = nx.R_AARCH64_RELATIVE, nx.R_AARCH64_GLOB_DAT, nx.R_AARCH64_JUMP_SLOT
TEXT, RODATA, DATA, END = 0x0, 0x1000, 0x2000, 0x3000
VTABLE, NUMBERS, DYNAMIC, GOT_PLT, GOT, INIT = 0x2000, 0x2020, 0x2100, 0x2200, 0x2220, 0x2240
SJIS, UTF8, LATIN = RODATA, RODATA + 0x10, RODATA + 0x30


def adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | (imm & 3) << 29 | (imm >> 2 & 0x7FFFF) << 5 | rd


def ldr(rt, rn, offset):
    return 0xF9400000 | (offset // 8) << 10 | rn << 5 | rt


def add(rd, rn, imm):
    return 0x91000000 | imm << 10 | rn << 5 | rd


RET = 0xD65F03C0


def module() -> bytes:
    """An NSO: two functions that reach a vtable and an import through the GOT and one that forms a table's address;
    the vtable (its methods relocated), a table of plain numbers, strings in three encodings, and the linker's
    tables laid out as Nintendo's linker does: .dynamic, .got.plt, .got (led by .dynamic's address), .init_array."""
    image = bytearray(END)
    struct.pack_into("<I", image, 4, 0x8)                              # MOD0 at 8
    image[0x8:0xC] = b"MOD0"
    struct.pack_into("<6i", image, 0xC, DYNAMIC - 0x8, END - 0x8, END + 0x100 - 0x8, 0, 0, 0)
    code = {0x100: [adrp(8, 0x100, GOT + 8), ldr(8, 8, (GOT + 8) & 0xFFF), add(8, 8, 16), RET],
            0x120: [adrp(9, 0x120, GOT + 16), ldr(9, 9, (GOT + 16) & 0xFFF), RET],
            0x140: [adrp(10, 0x140, NUMBERS), add(10, 10, NUMBERS & 0xFFF), RET]}
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
                   (NUMBERS + 0x10, RELATIVE, 0, SJIS), (GOT + 8, RELATIVE, 0, VTABLE), (GOT + 16, GLOB_DAT, 2, 0),
                   (GOT + 24, RELATIVE, 0, NUMBERS), (INIT, RELATIVE, 0, 0x140)]
    rela = b"".join(struct.pack("<QQq", at, index << 32 | kind, addend) for at, kind, index, addend in relocations)
    plt = struct.pack("<QQq", GOT_PLT + 24, 1 << 32 | JUMP_SLOT, 0)
    symtab, strtab, rela_at, plt_at = RODATA + 0x100, RODATA + 0x148, RODATA + 0x200, RODATA + 0x300
    image[symtab:symtab + len(symbols)] = symbols
    image[strtab:strtab + len(names)] = names
    image[rela_at:rela_at + len(rela)] = rela
    image[plt_at:plt_at + len(plt)] = plt
    struct.pack_into("<Q", image, GOT, DYNAMIC)                       # GOT[0]: .dynamic, as linked
    tags = [(nx.DT_SYMTAB, symtab), (nx.DT_STRTAB, strtab), (nx.DT_STRSZ, len(names)), (nx.DT_RELA, rela_at),
            (nx.DT_RELASZ, len(rela)), (nx.DT_JMPREL, plt_at), (nx.DT_PLTRELSZ, len(plt)), (3, GOT_PLT),
            (nx.DT_INIT_ARRAY, INIT), (nx.DT_INIT_ARRAYSZ, 8), (nx.DT_NULL, 0)]
    for index, (tag, value) in enumerate(tags):
        struct.pack_into("<qQ", image, DYNAMIC + index * 16, tag, value)
    header = bytearray(0x100)
    header[:4] = b"NSO0"
    for index, (start, end) in enumerate(((TEXT, RODATA), (RODATA, DATA), (DATA, END))):
        struct.pack_into("<III", header, 0x10 + index * 0x10, 0x100 + start, start, end - start)
    struct.pack_into("<I", header, 0x3C, 0x100)                       # .bss
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
        (self.root / "project.json").write_text(json.dumps({
            "schema_version": 1, "id": "switch-tools", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
            "targets": {"t": {"repository": "decomp", "platform": "switch", "module": "main", "original": "main",
                              "symbols": "symbols.txt"}}}), encoding="utf-8")
        from zkit.project import Project
        self.project = Project.load(self.root / "project.json")

    def read(self, address, kind=None, **options):
        from zkit.inspect_dol import read_data
        return read_data(self.project, "t", address, kind, **options)

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


if __name__ == "__main__":
    unittest.main()
