import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import delink, discover, link, units
from zkit.gc import read_renames
from zkit.program import DataObject

from test_link import section, unit, words


class _Objects:
    """Just the data objects of a program, for the unit bounds rules."""

    def __init__(self, objects, platform=None):
        from zkit.platform import GameCube
        from zkit.program import Program
        self.platform = platform or GameCube()
        self.objects = sorted(objects, key=lambda o: o.address)
        self._object_starts = [o.address for o in self.objects]
        self.object_at = Program.object_at.__get__(self)


class UnitBoundsTests(unittest.TestCase):
    """What a CodeWarrior link shows about where one object's data ends and the next begins."""

    def test_a_range_ends_where_the_next_object_could_start(self):
        shorts = _Objects([DataObject(0x100, 2, "a", ".sdata"), DataObject(0x102, 2, "b", ".sdata"),
                           DataObject(0x104, 2, "c", ".sdata"), DataObject(0x106, 2, "d", ".sdata"),
                           DataObject(0x108, 4, "e", ".sdata")])
        # no object's section starts off a word: the shorts up to 0x108 are the unit's
        self.assertEqual(units._word_bounds(shorts, 0x100, 0x102), (0x100, 0x104))
        self.assertEqual(units._word_bounds(shorts, 0x102, 0x106), (0x100, 0x108))
        self.assertEqual(units._word_bounds(shorts, 0x108, 0x10C), (0x108, 0x10C))
        last = _Objects([DataObject(0x200, 4, "x", ".rodata"), DataObject(0x204, 3, "y", ".rodata")])
        self.assertEqual(units._word_bounds(last, 0x204, 0x207), (0x204, 0x207))   # a section's end stays its own
        from zkit.platform import Switch
        strings = _Objects([DataObject(0x300, 3, "s", ".rodata"), DataObject(0x303, 5, "t", ".rodata"),
                            DataObject(0x308, 4, "u", ".rodata")], Switch())
        self.assertEqual(units._word_bounds(strings, 0x300, 0x303), (0x300, 0x303))  # clang: strings start anywhere

    def test_another_build_gives_way_to_what_the_code_states(self):
        """Functions 0-1 cite a.cpp, 9 cites b.cpp; another build put 4 in b.cpp, but the static initializer at 6
        ends a.cpp: that build's boundary before 4 is not taken, and the initializer's after 6 is."""
        ev = units.Evidence({}, [], [])
        ev.files = {0: "a.cpp", 1: "a.cpp", 4: "b.cpp", 9: "b.cpp"}
        ev.placed = {4}
        placed, stated = (2, 4, "a.cpp then b.cpp"), (7, 7, "6 is its unit's static initializer")
        ev.separations = [placed, stated]
        ev.direct = {stated}
        self.assertEqual(units._stated(ev), [stated])
        ev.separations, ev.direct = [placed], set()                 # where the code says nothing, it stands
        self.assertEqual(units._stated(ev), [placed])

    def test_claims_against_link_order_are_dropped(self):
        rows = [(0x10, 0x14, "a", ".data"), (0x14, 0x18, "c", ".data"), (0x18, 0x1C, "b", ".data"),
                (0x1C, 0x20, "b", ".data"), (0x20, 0x24, "c", ".data")]
        kept = units._in_link_order(rows, {"a": 0, "b": 1, "c": 2})
        self.assertEqual([r[2] for r in kept], ["a", "b", "b", "c"])          # c's early claim is a reference


class LinkerTableTests(unittest.TestCase):
    def test_eti_init_info_is_found_where_its_record_says(self):
        start, code = 0x80005660, [(0x800056C0, 0x80100000)]
        entries = [0x800FF0F8, 0x7C, 0x80005600, 0x800FF174, 0x78, 0x80005608]   # two 12-byte entries
        record = [start, start + 4 * len(entries), 0x800056C0, 0x2D2E60, 0, 0, 0, 0]
        self.assertEqual(discover._eti_init_info(start, entries + record, code), start + 4 * len(entries))
        self.assertIsNone(discover._eti_init_info(start, entries, code))

    def test_renamed_ranges_are_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "splits.txt"
            path.write_text("rt.cpp:\n\t.text       start:0x80000000 end:0x80000010\n"
                            "\t.ctors      start:0x80001000 end:0x80001004 rename:.ctors$10\n")
            self.assertEqual(read_renames(path), {("rt.cpp", ".ctors", 0x80001000): ".ctors$10"})
            read = delink.read_units(path)[0]
            self.assertEqual(read.renames, {(".ctors", 0x80001000): ".ctors$10"})
            self.assertEqual(delink.section_traits(delink.PPC, ".ctors$10"),
                             delink.section_traits(delink.PPC, ".ctors"))

    def test_an_initializer_array_is_data(self):
        """`.init_array` holds pointers, not code, though its name starts like `.init`."""
        kind, flags, size, _ = delink.section_traits(delink.AARCH64, ".init_array")
        self.assertEqual((kind, flags & delink.SHF_EXECINSTR, size), (14, 0, 8))      # SHT_INIT_ARRAY
        self.assertTrue(delink.section_traits(delink.PPC, ".init")[1] & delink.SHF_EXECINSTR)


class RuntimeMemberTests(unittest.TestCase):
    """The C++ runtime links late but leads .ctors and .dtors: mwld puts the tables of the archive member named
    __init_cpp_exceptions.o first (a CodeWarrior link map: 372nd object in .text, first in .ctors)."""

    def test_the_leading_entries_become_the_runtime_member(self):
        sections = [section(".text", 0x1000, 0x1100, "code"), section(".ctors", 0x1100, 0x1110),
                    section(".dtors", 0x1200, 0x1210)]
        game = unit("game.cpp", text=(0x1000, 0x1080), ctors=(0x1104, 0x1108))
        runtime = unit("runtime.cpp", text=(0x1080, 0x1100), ctors=(0x1100, 0x1104), dtors=(0x1200, 0x1208))
        out = link._runtime_member([game, runtime], sections)
        self.assertEqual([u.name for u in out], ["game.cpp", "runtime.cpp", link.RUNTIME_MEMBER])
        self.assertEqual(dict(out[-1].ranges), {".ctors": [(0x1100, 0x1104)], ".dtors": [(0x1200, 0x1208)]})
        self.assertEqual(dict(out[1].ranges), {".text": [(0x1080, 0x1100)]})
        renamed = unit("runtime.cpp", text=(0x1080, 0x1100), ctors=(0x1100, 0x1104))
        renamed.renames[(".ctors", 0x1100)] = ".ctors$10"                  # the later runtime: sorted by name
        game = unit("game.cpp", text=(0x1000, 0x1080), ctors=(0x1104, 0x1108))
        self.assertEqual([u.name for u in link._runtime_member([game, renamed], sections)],
                         ["game.cpp", "runtime.cpp"])

    def test_the_archive_indexes_every_global(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            symbols = [{"name": "__init_cpp_exceptions_reference", "section": ".ctors", "value": 0, "size": 4,
                        "kind": "object", "bind": "global", "address": 0},
                       {"name": "local_one", "section": ".ctors", "value": 0, "size": 0, "kind": "notype",
                        "bind": "local", "address": 0}]
            delink.write_object(delink.PPC, [(".ctors", 1, words(0), 4)], symbols, {}, root / "m.o")
            blob = link.write_archive(root / "rt.a", [root / "m.o"], [link.RUNTIME_MEMBER]).read_bytes()
            self.assertTrue(blob.startswith(b"!<arch>\n/ "))
            size = int(blob[8 + 48:8 + 58])
            table = blob[8 + 60:8 + 60 + size]
            count, offset = struct.unpack(">II", table[:8])
            self.assertEqual(count, 1)
            self.assertEqual(table[8:].rstrip(b"\0"), b"__init_cpp_exceptions_reference")
            self.assertEqual(blob[offset:offset + 2], b"/0")                 # the member, by its long name
            self.assertIn(f"{link.RUNTIME_MEMBER}/\n".encode(), blob)
            self.assertEqual(blob[offset + 60:offset + 64], b"\x7fELF")


class ProvenUnitTests(unittest.TestCase):
    def test_a_unit_whose_code_and_data_all_match_links_whole(self):
        self.assertTrue(link._proven({"total_code": "244", "matched_code": "244", "total_data": "129",
                                      "matched_data": "129"}))
        self.assertFalse(link._proven({"total_code": "244", "matched_code": "244", "total_data": "129",
                                       "matched_data": "28"}))     # data still differs: only its functions
        self.assertFalse(link._proven({}))


class BareProgramTests(unittest.TestCase):
    """A project straight from the disc names nothing: the register setup the entry point calls still gives the
    small-data bases (so small-data accesses get relocations) and the stack's top."""

    def test_register_setup_is_found_without_its_name(self):
        from zkit.gc import Symbol
        from zkit.platform import GameCube
        from zkit.program import Program
        from test_classes import Image, BLR, li, lis
        def ori(ra, rs, value): return (24 << 26) | (rs << 21) | (ra << 16) | value
        image = Image()
        clear = [li(r, 0) for r in range(32)]                 # some runtimes clear every register first
        image.functions = {"entry": [("bl", "setup"), BLR],
                           "setup": clear + [lis(1, 0x803E0000), ori(1, 1, 0x22F8), lis(2, 0x803D0000),
                                             ori(2, 2, 0x45A0), lis(13, 0x803D0000), ori(13, 13, 0x1420), BLR]}
        dol, functions, _ = image.build()
        symbols = [Symbol(f.name.replace("entry", "fn_entry").replace("setup", "fn_setup"), ".init", f.address,
                          "function", f.size, "global") for f in functions]
        program = Program.from_symbol_list(GameCube(), dol, symbols)
        self.assertEqual(program.sda, {2: 0x803D45A0, 13: 0x803D1420})
        self.assertEqual(link.stack_address(program), 0x803E22F8)


if __name__ == "__main__":
    unittest.main()
