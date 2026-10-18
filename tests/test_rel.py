import support  # noqa: F401  (isolates config, cache and state)
import json
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import delink, objects, rel
from zkit.elf import Elf
from zkit.project import Project

BLR, BL = 0x4E800020, 0x48000001
# One compiled unit, as MWCC leaves it (relocated fields zero): f_a calls f_b and the DOL's dol_func and takes the
# DOL's g_dol; f_b loads its own float; `_unresolved` is the module's stub; .data points at f_a and dol_func.
TEXT = [0x9421FFF0, BL, 0x3C600000, 0x38630000, BL, BLR,     # f_a      0x00
        0x3C800000, 0xC0240000, BLR,                         # f_b      0x18
        BLR]                                                 # _unresolved 0x24
SYMBOLS = """f_a = .text:0x00000000; // type:function size:0x18 scope:global
f_b = .text:0x00000018; // type:function size:0xC scope:global
_unresolved = .text:0x00000024; // type:function size:0x4 scope:global
k_float = .rodata:0x00000000; // type:object size:0x4 scope:local
table = .data:0x00000000; // type:object size:0x8 scope:global
buf = .bss:0x00000000; // type:object size:0x8 scope:global
"""
HOST = """dol_func = .text:0x80005000; // type:function size:0x10 scope:global
g_dol = .data:0x80300000; // type:object size:0x4 scope:global
"""
SPLITS = """Sections:
\t.text       type:code align:4
\t.rodata     type:rodata align:8
\t.data       type:data align:8
\t.bss        type:bss align:8

a.c:
\t.text       start:0x00000000 end:0x00000028
\t.rodata     start:0x00000000 end:0x00000004
\t.data       start:0x00000000 end:0x00000008
\t.bss        start:0x00000000 end:0x00000008
"""
OFFERED = {"dol_func": (0, 2, 0x80005000), "g_dol": (0, 5, 0x80300000)}


def unit_object(path: Path, data_size: int = 8, far: bool = False) -> None:
    """The compiled unit (also a valid partially linked module). With `far`, .data is 64 KiB longer and points at
    another module's object from its end (a relocation gap past 0xFFFF)."""
    rows = [{"name": n, "section": s, "value": v, "size": z, "kind": k, "bind": b, "address": 0} for n, s, v, z, k, b in [
        ("f_a", ".text", 0, 0x18, "func", "global"), ("f_b", ".text", 0x18, 0xC, "func", "global"),
        ("_unresolved", ".text", 0x24, 4, "func", "global"), ("k_float", ".rodata", 0, 4, "object", "local"),
        ("table", ".data", 0, 8, "object", "global"), ("buf", ".bss", 0, 8, "object", "global"),
        ("dol_func", None, 0, 0, "notype", "global"), ("g_dol", None, 0, 0, "notype", "global"),
        ("other_obj", None, 0, 0, "notype", "global")]]
    relocations = {".text": [(0x04, rel.REL24, 1, 0), (0x0A, rel.ADDR16_HA, 7, 0), (0x0E, rel.ADDR16_LO, 7, 0),
                             (0x10, rel.REL24, 6, 0), (0x1A, rel.ADDR16_HA, 3, 0), (0x1E, rel.ADDR16_LO, 3, 0)],
                   ".data": [(0, rel.ADDR32, 0, 0), (4, rel.ADDR32, 6, 0)]}
    size = data_size + (0x10008 if far else 0)
    if far:
        relocations[".data"].append((size - 4, rel.ADDR32, 8, 4))
    sections = [(".text", 1, b"".join(struct.pack(">I", w) for w in TEXT), 4), (".rodata", 1, struct.pack(">f", 1.5), 8),
                (".data", 1, bytes(size), 8), (".bss", 8, 8, 8)]
    delink.write_object(delink.PPC, sections, rows, relocations, path, source="a.c")


class RelFormat(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def made(self, version: int, far: bool = False) -> tuple[rel.Rel, bytes]:
        unit_object(self.root / "a.o", far=far)
        offered = dict(OFFERED, other_obj=(9, 3, 0x10))
        module = rel.make(Elf.load(self.root / "a.o"), 4, offered, version)
        return module, rel.write(module)

    def test_make_applies_calls_as_makerel_and_round_trips(self):
        module, raw = self.made(3, far=True)
        text = Elf.load(self.root / "a.o").section(".text").index
        words = struct.unpack(">10I", module.data[text])
        self.assertEqual(words[1], 0x48000015)            # bl f_b applied (0x04 -> 0x18) and out of the table
        self.assertEqual(words[4], 0x48000015)            # bl dol_func points at _unresolved (0x10 -> 0x24)
        self.assertEqual(module.unresolved, (text, 0x24))
        back = rel.read(raw)
        self.assertEqual([r.module for r in back.relocations][:1], [9])   # other modules, itself, then the DOL
        self.assertEqual(sorted({(r.module, r.kind) for r in back.relocations}),
                         [(0, rel.ADDR32), (0, rel.ADDR16_LO), (0, rel.ADDR16_HA), (0, rel.REL24), (4, rel.ADDR32),
                          (4, rel.ADDR16_LO), (4, rel.ADDR16_HA), (9, rel.ADDR32)])
        self.assertNotIn((text, 0x04), {(r.section, r.offset) for r in back.relocations})
        self.assertEqual([m for m, _ in back.imports], [9, 4, 0])
        self.assertEqual(back.fix_size, dict(back.imports)[4])           # OSLinkFixed keeps only module 9's list
        stream = raw[back.imports[0][1]:]
        self.assertIn(rel.DOLPHIN_NOP, stream[2::8][:4])                 # the 0x10004 gap needs one NOP
        far = next(r for r in back.relocations if r.module == 9)
        self.assertEqual((far.offset, far.target_section, far.addend), (0x1000C, 3, 0x14))
        self.assertEqual(rel.write(back), raw)
        self.assertEqual(rel.read(raw).data, module.data)

    def test_versions_one_and_two_order_by_module_and_put_relocations_first(self):
        _, raw = self.made(2)
        back = rel.read(raw)
        self.assertEqual([m for m, _ in back.imports], [0, 4])
        rel_offset, imp_offset = struct.unpack_from(">2I", raw, 0x24)
        self.assertLess(rel_offset, imp_offset)
        self.assertEqual(rel.write(back), raw)
        self.assertEqual((back.align, back.bss_align), (8, 8))

    def test_reader_refuses_what_oslink_would_not_load(self):
        _, raw = self.made(3)
        with self.assertRaises(ValueError):
            rel.read(raw[:4] + b"\0\0\0\1" + raw[8:])                     # a runtime link already set
        (self.root / "data.rel").write_bytes(b"\0\0\0\1\0\0\0\2" + bytes(0x40))
        with self.assertRaises(ValueError):
            rel.module_id(self.root / "data.rel")                       # a game's own .rel data
        back = rel.read(raw)
        broken = bytearray(raw)
        broken[back.imports[0][1] + 8 + 2] = 99                          # an R_PPC type OSLink does not know
        with self.assertRaises(ValueError):
            rel.read(bytes(broken))

    def test_yaz0_compressed_rel_reads_the_same(self):
        _, raw = self.made(3)
        packed = bytearray(b"Yaz0" + struct.pack(">I", len(raw)) + bytes(8))
        for start in range(0, len(raw), 8):                              # every item a literal byte
            packed += b"\xff" + raw[start:start + 8]
        (self.root / "packed.rel").write_bytes(bytes(packed))
        self.assertEqual(rel.module_id(self.root / "packed.rel"), 4)
        self.assertEqual(rel.write(rel.load(self.root / "packed.rel")), raw)

    def test_cli_info_and_make(self):
        from zkit.cli import main
        import contextlib
        import io
        unit_object(self.root / "a.o")
        dol = self.root / "dol.elf"
        rows = [{"name": n, "section": ".text", "value": v, "size": 4, "kind": "func", "bind": "global",
                 "address": 0} for n, v in (("dol_func", 0), ("g_dol", 4))]
        delink.write_object(delink.PPC, [(".text", 1, bytes(8), 4)], rows, {}, dol)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["rel", "make", str(self.root / "a.o"), "--dol", str(dol), "--out",
                                   str(self.root / "out")]), 0)
        made = rel.load(self.root / "out/a.rel")
        self.assertEqual(made.module_id, 1)
        self.assertEqual({r.addend for r in made.relocations if r.module == 0}, {0, 4})   # DOL ELF symbol values
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["rel", "info", str(self.root / "out/a.rel")])
        self.assertIn("REL module 1, version 3", out.getvalue())
        self.assertIn("-> the DOL: ADDR16_HA 1, ADDR16_LO 1, ADDR32 1, REL24 1", out.getvalue())


class RelDelink(unittest.TestCase):
    """Compiled unit -> REL (as makerel) -> delinked object: every function and data relocation comes back."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = self.root = Path(self.temp.name)
        unit_object(root / "a.o")
        (root / "orig").mkdir()
        (root / "orig/mod.rel").write_bytes(rel.write(rel.make(Elf.load(root / "a.o"), 4, OFFERED)))
        (root / "mod").mkdir()
        (root / "mod/symbols.txt").write_text(SYMBOLS, encoding="utf-8")
        (root / "mod/splits.txt").write_text(SPLITS, encoding="utf-8")
        (root / "host.txt").write_text(HOST, encoding="utf-8")
        (root / "project.json").write_text(json.dumps({
            "schema_version": 1, "id": "rel-test", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
            "targets": {"main": {"repository": "decomp", "platform": "gamecube", "module": "main",
                                 "symbols": "host.txt"},
                        "mod": {"repository": "decomp", "platform": "gamecube", "module": "mod", "host": "main",
                                "original": "orig/mod.rel", "symbols": "mod/symbols.txt",
                                "splits": "mod/splits.txt"}}}), encoding="utf-8")

    def test_delinked_unit_equals_the_compiled_one(self):
        project = Project.load(self.root / "project.json")
        result = delink.delink(project, "mod", self.root / "mod/splits.txt", self.root / "target")
        self.assertEqual(result["unassigned"], 0)
        target = self.root / "target/a.o"
        diff = objects.unit_diff(target, self.root / "a.o")
        self.assertEqual((diff["exact"], diff["total"]), (3, 3), diff["functions"])
        ours, theirs = Elf.load(target), Elf.load(self.root / "a.o")
        name = lambda elf, r: elf.symbols[r.symbol].name
        for section in (".data", ".text"):
            self.assertEqual([(r.offset, r.type, name(ours, r), r.addend) for r in ours.relocations(ours.section(section))],
                             [(r.offset, r.type, name(theirs, r), r.addend)
                              for r in theirs.relocations(theirs.section(section))], section)
            self.assertEqual(ours.data(ours.section(section)), theirs.data(theirs.section(section)), section)


if __name__ == "__main__":
    unittest.main()
