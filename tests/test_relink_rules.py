import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
import unittest.mock
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
        literal = (3, 5, "two copies of one constant")              # the code's own evidence: it stands
        ev.separations = [placed, stated, literal]
        ev.direct, ev.borrowed, ev.pairs = {stated}, {placed}, {placed: ("a.cpp", "b.cpp")}
        self.assertEqual(units._stated(ev), [stated, literal])
        ev.separations, ev.direct = [placed], set()                 # where the code says nothing, it stands
        self.assertEqual(units._stated(ev), [placed])
        third = (2, 4, "a.cpp then lib/x.cpp")                      # a third file between them: the initializer
        ev.files[4] = "lib/x.cpp"                                   # can be its end, and that build's boundary
        ev.separations, ev.direct, ev.borrowed = [third, stated], {stated}, {third}     # stands
        ev.pairs = {third: ("a.cpp", "lib/x.cpp")}
        self.assertEqual(units._stated(ev), [third, stated])

    def test_weak_data_goes_where_the_order_allows(self):
        """An inline's static (weak) is the first using unit's copy, where its claim fits the order of the
        others; it never displaces one (the unit that kept the copy may not refer to it any more)."""
        order = {"a": 0, "b": 1, "c": 2}
        kept = [(0x10, 0x14, "a", ".bss"), (0x20, 0x24, "c", ".bss")]
        soft = [(0x18, 0x1C, "b", ".bss"), (0x30, 0x34, "a", ".bss"), (0x40, 0x44, "c", ".bss")]
        self.assertEqual(units._fitting(kept, soft, order, set(order), set(), []),
                         [(0x18, 0x1C, "b", ".bss"), (0x40, 0x44, "c", ".bss")])   # a's after c's: not a's

    def test_claims_against_link_order_are_dropped(self):
        rows = [(0x10, 0x14, "a", ".data"), (0x14, 0x18, "c", ".data"), (0x18, 0x1C, "b", ".data"),
                (0x1C, 0x20, "b", ".data"), (0x20, 0x24, "c", ".data")]
        kept = units._in_link_order(rows, {"a": 0, "b": 1, "c": 2})
        self.assertEqual([r[2] for r in kept], ["a", "b", "b", "c"])          # c's early claim is a reference


class _Code:
    """Just functions (one every 0x40 bytes), for the unit evidence rules."""

    def __init__(self, count, weak=(), unlisted=()):
        from types import SimpleNamespace
        from zkit.platform import Switch
        from zkit.program import Function
        self.platform = Switch()
        self.functions = [Function(0x1000 + 0x40 * i, 0x40, f"fn_{i}") for i in range(count)]
        listed = [f for i, f in enumerate(self.functions) if i not in unlisted]     # the module's symbol table
        self.image = SimpleNamespace(weak={self.functions[i].address for i in weak},
                                     symbols={f.address: f.name for f in listed})
        self.calls = {}


class UnitEvidenceTests(unittest.TestCase):
    """What a module's code states about which file a function was compiled in."""

    def test_a_class_s_own_functions_are_its_file_s(self):
        """K's 0 cites a.cpp: its strong 2 and 3 are a.cpp's, ahead of another build's unit for 3; its weak 4 is
        an inline kept from any unit, its 7, among b.cpp's citations, is a method defined in b.cpp, and its 1 is
        in no symbol table, so either."""
        from unittest import mock
        code = _Code(10, weak=[4], unlisted=[1])
        classes = {0: "K", 1: "K", 2: "K", 3: "K", 4: "K", 7: "K", 6: "M", 8: "M"}
        ev = units.Evidence({}, [], [])
        ev.files = {0: "a.cpp", 3: "c.cpp", 5: "b.cpp", 9: "b.cpp"}
        ev.placed = {3}
        with mock.patch.object(units, "_function_classes", return_value=classes):
            units._class_files(code, ev)
        self.assertEqual(ev.files, {0: "a.cpp", 2: "a.cpp", 3: "a.cpp", 5: "b.cpp", 9: "b.cpp"})
        self.assertEqual((ev.classed, ev.placed), ({2, 3}, set()))
        ev.files, ev.classed = {0: "a.cpp", 5: "b.cpp"}, set()
        with mock.patch.object(units, "_function_classes", return_value=classes):
            units._class_files(_Code(10), ev)                       # no weak marks: no class says anything
        self.assertEqual(ev.classed, set())

    def test_code_tied_to_neither_file_is_a_unit_of_its_own(self):
        """a.cpp cites 10 and its data reaches 14; b.cpp cites 150 and its data reaches back to 140: the 125
        functions between are neither's, with a boundary within reach of each file's evidence."""
        code = _Code(160)
        ev = units.Evidence({}, [(10, 14, "data"), (140, 150, "data")], [])
        units._untied(code, ev, [(10, "a.cpp"), (150, "b.cpp")])
        self.assertEqual(sorted(ev.edges), [(15, 15 + units.FILL_FUNCTIONS, "a.cpp's evidence ends"),
                                            (140 - units.FILL_FUNCTIONS, 140, "b.cpp's evidence starts")])
        self.assertEqual(ev.direct, set(ev.edges))
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            cuts = [c.position for c in units.boundaries(code, ev)]
        self.assertEqual(cuts, [15, 140])
        near = units.Evidence({}, [(10, 14, "data")], [])
        units._untied(_Code(60), near, [(10, "a.cpp"), (40, "b.cpp")])   # 25 between: one boundary, as before
        self.assertEqual(near.edges, {})

    def test_a_file_s_code_reaches_over_the_inlines_after_it(self):
        """11-80 are weak (inlines and template instances, emitted after the code that first uses them) but for
        40-41, in no symbol table: a.cpp's evidence reaches over them all, and the run tied to neither file starts
        at 81, though it is in none either."""
        code = _Code(160, weak=[i for i in range(11, 81) if i not in (40, 41)], unlisted=[40, 41, 81])
        ev = units.Evidence({}, [], [])
        units._untied(code, ev, [(10, "a.cpp"), (150, "b.cpp")])
        self.assertEqual(sorted(ev.edges.values()), [81, 150])     # over 40-41 (unknown, among inlines), not 81

    def test_the_module_s_start_and_end_bound_its_first_and_last_files(self):
        """Code before the first file's evidence, or after the last's, tied to neither and longer than its reach,
        is a unit of its own too (a start-up object, a library at the end); a boundary at the module's own start
        or end is none."""
        code = _Code(300)
        ev = units.Evidence({}, [], [])
        units._untied(code, ev, [(100, "a.cpp"), (110, "b.cpp")])
        self.assertEqual(sorted(ev.edges), [(100 - units.FILL_FUNCTIONS, 100, "a.cpp's evidence starts"),
                                            (111, 111 + units.FILL_FUNCTIONS, "b.cpp's evidence ends")])
        near = units.Evidence({}, [], [])
        units._untied(_Code(130), near, [(30, "a.cpp"), (110, "b.cpp")])     # 30 before, 19 after: in reach
        self.assertEqual([why for _, _, why in near.edges], ["a.cpp's evidence ends", "b.cpp's evidence starts"])

    def test_the_sdk_s_start_up_object_ends_at_its_markers(self):
        from zkit.program import Function
        code = _Code(60)
        code.functions[5:7] = [Function(code.functions[5].address, 4, "__nnDetailNintendoSdkRuntimeObjectFileRefer"),
                               Function(code.functions[6].address, 4, "__nnDetailNintendoSdkRuntimeObjectFile")]
        ev = units.Evidence({}, [], [])
        units._start_up_object(code, ev)
        self.assertEqual([lo for lo, _, _ in ev.separations], [7])
        self.assertEqual(ev.direct, set(ev.separations))

    def test_another_build_s_placeholder_is_no_piece_of_a_file(self):
        """`unit_<address>.cpp` is a unit no file names, not a piece of `unit.cpp`: it keeps its address as its
        identity (a piece of a file, `a_<address>.cpp`, is the file)."""
        code = _Code(10)
        code.strings, code.refs = (lambda: {}), {}
        code.function_index = {f.address: i for i, f in enumerate(code.functions)}
        ev = units.Evidence({}, [], [])
        units._file_evidence(code, ev, {code.functions[2].address: "unit_7100000024.cpp",
                                        code.functions[6].address: "a_7100000024.cpp"})
        self.assertEqual(ev.files, {2: "unit_7100000024.cpp", 6: "a.cpp"})

    def test_a_file_s_evidence_ends_at_a_boundary_within_its_reach(self):
        """Another boundary (a static initializer at 29) within reach of a.cpp's evidence is where a.cpp ends:
        no second boundary right after its evidence."""
        code = _Code(160)
        ev = units.Evidence({}, [(10, 14, "data")], [(30, 30, "29 is its unit's static initializer")])
        units._untied(code, ev, [(10, "a.cpp"), (150, "b.cpp")])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            cuts = [c.position for c in units.boundaries(code, ev)]
        self.assertEqual(cuts[0], 30)
        self.assertEqual(len(cuts), 2)


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
