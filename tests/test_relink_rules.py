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
        self.cflags = ["-O3", "-fPIC"]                 # a PIC module that inlines
        self.cache = {}
        self.functions = [Function(0x1000 + 0x40 * i, 0x40, f"fn_{i}") for i in range(count)]
        listed = [f for i, f in enumerate(self.functions) if i not in unlisted]     # the module's symbol table
        self.image = SimpleNamespace(weak={self.functions[i].address for i in weak},
                                     symbols={f.address: f.name for f in listed})
        self.calls = {}
        self.refs = {}                                   # no code takes an address
        self.function_index = {f.address: i for i, f in enumerate(self.functions)}


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

    def test_a_weak_function_is_in_its_earliest_user_s_unit(self):
        """Weak 6 is called by 2 and 8, so it is in 2's unit; weak 7 is in a weak table 3 refers to; weak 5 only in
        a table with a key function (emitted with that function alone); weak 4 is used only after it (a global's
        constructor), 9 by 8 before it, strong 1 by 0. No weak marks (GameCube): nothing."""
        code = _Code(10, weak=[4, 5, 6, 7, 9])
        at = {f.address: i for i, f in enumerate(code.functions)}
        weak_table = DataObject(0x9000, 0x20, "_ZTV1W", ".data", "weak")
        key_table = DataObject(0x9100, 0x20, "_ZTV1K", ".data")
        address = lambda i: code.functions[i].address
        code.calls = {0: [1], 2: [6], 8: [6, 9], 6: [4]}
        code.refs = {3: [(0, 0x9010, "addr")], 1: [(0, 0x9110, "addr")]}
        code.pointers = [(0x9010, address(7)), (0x9110, address(5))]
        code.function_index = at
        code.object_at = lambda a: weak_table if 0x9000 <= a < 0x9020 else key_table if 0x9100 <= a < 0x9120 \
            else None
        code.users = lambda: {weak_table: {3}, key_table: {1}}
        self.assertEqual([(lo, hi) for lo, hi, _ in units._first_users(code)], [(2, 6), (3, 7), (8, 9)])
        from zkit.platform import GameCube
        code.platform = GameCube()
        self.assertEqual(units._first_users(code), [])

    def test_a_weak_function_only_a_later_static_initializer_uses_is_that_unit_s(self):
        """Weak 2's address is taken only by 4, its unit's static initializer (a global's destructor registered at
        exit), and 7's only by the initializer 8: each is that unit's, created where the global is defined. 3 is
        used only by 8 too, but 4 ends a unit between them; 5 is called by 6 as well; data holds 6."""
        code = _Code(10, weak=[2, 3, 5, 6, 7])
        address = lambda i: code.functions[i].address
        code.calls = {6: [5], 8: [5]}
        code.refs = {4: [(0, address(2), "addr")], 8: [(0, address(i), "addr") for i in (3, 6, 7)]}
        code.pointers = [(0x9000, address(6))]
        code.object_at = lambda a: None
        with unittest.mock.patch.object(units, "_initializers", return_value=[4, 8]):
            self.assertEqual([(lo, hi) for lo, hi, _ in units._first_users(code)], [(2, 4), (7, 8)])
            from zkit.platform import GameCube
            code.platform = GameCube()
            self.assertEqual(units._first_users(code), [])

    def test_a_weak_marked_table_holding_its_class_s_own_definition_is_its_key_function_s(self):
        """W's table is marked weak and 2 forms its address, but it holds W's unmarked 5, defined among the code
        (6 is no slot of it) before its inline virtuals 8 and 9: W has a key function, so 8 and 9 are not 2's.
        Base B's inline virtual 1, held too, is emitted earlier for another table and does not count. Held right
        before them (7, a run with them), by another table too (a folded or inherited body) or by a class
        template's table, the mark stands."""
        from types import SimpleNamespace
        from unittest import mock
        code = _Code(12, weak=[1, 8, 9])
        address = lambda i: code.functions[i].address
        code.function_index = {f.address: i for i, f in enumerate(code.functions)}
        code.refs = {2: [(0, 0x9010, "addr")]}

        def first_users(own: int, symbol: str = "_ZTV1W", name: str = "W",
                        shared: bool = False) -> list[tuple[int, int]]:
            table = DataObject(0x9000, 0x40, symbol, ".data", "weak")
            other = DataObject(0xA000, 0x40, "_ZTV1V", ".data", "global")
            code.object_at = lambda a: table if 0x9000 <= a < 0x9040 else other if 0xA000 <= a < 0xA040 else None
            code.users = lambda: {table: {2}}
            code.pointers = [(0x9010 + 8 * k, address(i)) for k, i in enumerate((own, 8, 9, 1))]
            code.pointers += [(0xA010, address(own))] if shared else []
            named = {address(i): SimpleNamespace(thunk=False, owner=name) for i in (own, 8, 9)}
            named[address(1)] = SimpleNamespace(thunk=False, owner="B")
            code.cache = {}
            with mock.patch("zkit.itanium.methods", return_value=named):
                return [(lo, hi) for lo, hi, _ in units._first_users(code)]
        self.assertEqual(first_users(5), [])
        self.assertEqual(first_users(7), [(2, 8), (2, 9)])
        self.assertEqual(first_users(5, shared=True), [(2, 8), (2, 9)])
        self.assertEqual(first_users(5, "_ZTV1WIiE", "W<int>"), [(2, 8), (2, 9)])

    def test_a_weak_marked_table_with_a_key_function_is_its_key_function_s_unit_s(self):
        """W's table is marked weak and a.cpp's 2 forms its address, but it holds W's unmarked 5, among b.cpp's code
        apart from W's inline virtuals 8 and 9: W has a key function in b.cpp, and the table is b.cpp's data, not
        its first user's. Held right before them (7, a run with them), the mark stands: the table goes by its users."""
        from types import SimpleNamespace
        from unittest import mock
        code = _Code(12, weak=[8, 9])
        address = lambda i: code.functions[i].address
        owner = {i: "a.cpp" if i < 4 else "b.cpp" for i in range(12)}
        table = DataObject(0x9000, 0x40, "_ZTV1W", ".data", "weak")
        code.objects = [table]
        code.object_at = lambda a: table if 0x9000 <= a < 0x9040 else None
        code.refs = {2: [(0, 0x9010, "addr")]}
        code.users = lambda: {table: {2}}

        def rows(own: int) -> list[tuple[int, int, str, str]]:
            code.pointers = [(0x9010 + 8 * k, address(i)) for k, i in enumerate((own, 8, 9))]
            named = {address(i): SimpleNamespace(thunk=False, owner="W") for i in (own, 8, 9)}
            classes = {"W": SimpleNamespace(name="W", table=0x9000, groups=[SimpleNamespace(
                slots=[address(i) for i in (own, 8, 9)])])}
            code.cache = {}
            with mock.patch("zkit.itanium.recover", return_value=classes), \
                    mock.patch("zkit.itanium.methods", return_value=named):
                return units._key_function_tables(code, owner, set(code.image.weak))
        self.assertEqual(rows(5), [(0x9000, 0x9040, "b.cpp", ".data")])
        self.assertEqual(rows(7), [])

    def test_two_files_own_citations_part_whatever_data_joins_them(self):
        """3 cites a.cpp and 9 cites b.cpp themselves, with another build's units for 5 and 6 between and a global
        (2-12) holding everything together: a boundary still falls between 3 and 9, though not inside 5-7, where a
        weak 7 follows its first user 5 (one file including another)."""
        code = _Code(14)
        code.strings = lambda: {0x8000: "src/a.cpp", 0x8010: "src/b.cpp"}
        code.refs = {3: [(0, 0x8000, "addr")], 9: [(0, 0x8010, "addr")]}
        code.function_index = {f.address: i for i, f in enumerate(code.functions)}
        code.users = lambda: {}
        first = (5, 7, "7 is first used by 5")
        ev = units.Evidence({}, [(2, 12, "a global"), first], [], firsts=[first])
        placed = {code.functions[5].address: "src/a.cpp", code.functions[6].address: "src/b.cpp"}
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev, placed)
            cuts = [c.position for c in units.boundaries(code, ev)]
        self.assertIn((4, 9, "src/a.cpp then src/b.cpp"), ev.direct)
        self.assertEqual(len(cuts), 1)
        self.assertIn(cuts[0], (4, 5, 8, 9))
        # a.cpp's citations on both sides of b.cpp's: a.cpp includes b.cpp, and their citations part nothing
        code.refs[11] = [(0, 0x8000, "addr")]
        ev = units.Evidence({}, [(2, 12, "a global"), first], [], firsts=[first])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev, placed)
        self.assertFalse({row for row in ev.direct if row[0] <= 9 and row[1] >= 4})

    def test_a_run_another_build_put_in_another_file_between_two_longer_runs_says_nothing(self):
        """Switch, nothing cited: another build put 0-2 and 5-7 in a.cpp and 3-4 between them in b.cpp; a.cpp's
        code is one run, so 3-4 are no evidence for b.cpp there. d.cpp's 10-12 between c.cpp's two shorter runs
        (8-9, 13-14) stand: there it is c.cpp's that would be the strays."""
        code = _Code(15)
        code.strings = lambda: {}
        code.users = lambda: {}
        files =["a.cpp"] * 3 + ["b.cpp"] * 2 + ["a.cpp"] * 3 + ["c.cpp"] * 2 + ["d.cpp"] * 3 + ["c.cpp"] * 2
        placed = {f.address: files[i] for i, f in enumerate(code.functions)}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev, placed)
        self.assertEqual(sorted(ev.files), [0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14])
        self.assertNotIn("b.cpp", ev.files.values())

    def test_one_header_spelled_two_ways_is_two_units(self):
        """2 and 9 cite one header through two include folders (two projects' compiles): a boundary lies between
        them, where the code leaves 2's namespace (a:: for b:: at 6), though nothing else prefers a place; two
        citations spelled alike, or a module not clang's, say nothing."""
        code = _Code(12)
        from zkit.program import Function
        code.functions = [Function(f.address, f.size, f"_ZN1{'a' if i < 6 else 'b'}3f{i:02d}Ev")   # a::f00()..
                          for i, f in enumerate(code.functions)]
        code.strings = lambda: {0x8000: "D:/lib/a/proj/../../mcl\\inc/h.h", 0x8040: "D:/lib/b/proj/../../mcl/inc/h.h"}
        code.refs = {2: [(0, 0x8000, "addr")], 9: [(0, 0x8040, "addr")]}
        code.users = lambda: {}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev)
            cuts = [c.position for c in units.boundaries(code, ev)]
        row = next(r for r in ev.direct if r[:2] == (3, 9))
        self.assertIn("spelled two ways", row[2])
        self.assertEqual(cuts, [6])
        code.strings = lambda: {0x8000: "D:/lib/a/proj/../../mcl\\inc/h.h", 0x8040: "D:/lib/a/proj/../../mcl\\inc/h.h"}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev)
        self.assertFalse(ev.separations)
        from zkit.platform import GameCube
        code.strings = lambda: {0x8000: "D:/lib/a/proj/../../mcl\\inc/h.h", 0x8040: "D:/lib/b/proj/../../mcl/inc/h.h"}
        code.platform = GameCube()
        ev = units.Evidence({}, [], [])
        units._header_spellings(code, ev, code.strings())
        self.assertFalse(ev.separations)

    def test_headers_cited_through_two_project_folders_are_two_units(self):
        """2 and 9 cite two headers through two projects' folders (lib/a/proj, lib/b/proj: two projects' compiles):
        a boundary lies between them, where the code leaves 2's namespace (na:: for nb:: at 6). 4's climb out of
        lib/a/src, a folder holding a file 1 cites, is an including file's own `#include "../k.h"`, and 7's path
        is relative: neither names a project. One project's folder both ways, or a module not clang's, says
        nothing."""
        code = _Code(12)
        from zkit.program import Function
        code.functions = [Function(f.address, f.size, f"_ZN2n{'a' if i < 6 else 'b'}3f{i:02d}Ev")   # na::f00()..
                          for i, f in enumerate(code.functions)]
        strings = {0x8000: "D:/lib/a/proj/../../inc/h.h", 0x8040: "D:/lib/b/proj/../../inc\\b/g.h",
                   0x8080: "D:/lib/a/src/x.h", 0x80c0: "D:/lib/a/src/../inc/k.h", 0x8100: "../../inc/r.h"}
        code.strings = lambda: strings
        code.refs = {1: [(0, 0x8080, "addr")], 2: [(0, 0x8000, "addr")], 4: [(0, 0x80c0, "addr")],
                     7: [(0, 0x8100, "addr")], 9: [(0, 0x8040, "addr")]}
        code.users = lambda: {}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev)
            cuts = [c.position for c in units.boundaries(code, ev)]
        self.assertEqual([r[:2] for r in sorted(ev.direct)], [(3, 9)])
        self.assertIn("two projects' compiles", next(iter(ev.direct))[2])
        self.assertEqual(cuts, [6])
        strings[0x8040] = "d:/lib/A/proj/../../inc/b/g.h"
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._file_evidence(code, ev)
        self.assertFalse(ev.separations)
        from zkit.platform import GameCube
        strings[0x8040] = "D:/lib/b/proj/../../inc\\b/g.h"
        code.platform = GameCube()
        ev = units.Evidence({}, [], [])
        units._header_spellings(code, ev, code.strings())
        self.assertFalse(ev.separations)

    def test_files_whose_citations_interleave_are_one_unit(self):
        """a.cpp cites 2, 6 and 8 around b.cpp's 4: b.cpp is compiled inside a.cpp, one unit named after the
        file citing most, its other build's name too; c.cpp after them is its own."""
        ev = units.Evidence({}, [], [])
        ev.files = {2: "a.cpp", 4: "b.cpp", 6: "a.cpp", 8: "a.cpp", 9: "b.cpp", 12: "c.cpp", 14: "c.cpp"}
        ev.placed = {9}
        self.assertEqual(units._included(ev), {"b.cpp": "a.cpp"})

    def test_class_tables_out_of_their_methods_order_are_one_unit(self):
        """K's table lies before L's, but K's own methods (12, 13) come after L's (3): one unit from 3 to 12. M's
        after them is in order; N's is weak (no key function), O's in another loaded range of its section, and
        P's own method is weak: none of them says anything."""
        from types import SimpleNamespace
        from unittest import mock
        code = _Code(20, weak=[1])
        code.sections = [(".data", 0x9000, 0x9400), (".data", 0xA000, 0xA100)]
        tables = {0x9000: "K", 0x9100: "L", 0x9200: "M", 0x9300: "N", 0xA000: "O", 0x9380: "P"}
        own = {"K": [12, 13], "L": [3], "M": [15], "N": [2], "O": [0], "P": [1]}
        objects = {a: DataObject(a, 0x40, f"_ZTV1{c}", ".data", "weak" if c == "N" else "global")
                   for a, c in tables.items()}
        code.object_at = objects.get
        slot = {code.functions[i].address: c for c, rows in own.items() for i in rows}
        classes = {c: SimpleNamespace(name=c, table=a, groups=[SimpleNamespace(
            slots=[code.functions[i].address for i in own[c]])]) for a, c in tables.items()}
        named = {a: SimpleNamespace(thunk=False, owner=c) for a, c in slot.items()}
        with mock.patch("zkit.itanium.recover", return_value=classes), \
                mock.patch("zkit.itanium.methods", return_value=named):
            rows = units._tables_out_of_order(code)
        self.assertEqual([(lo, hi) for lo, hi, _ in rows], [(3, 12)])

    def test_another_class_s_code_forming_a_table_joins_it_short_of_a_deferred_tail(self):
        """K's table holds K::run (8); K's constructor is inline, and M::M (2), another class's constructor, forms
        the table's address: a join a deferred tail parts (`inlined`). K::K (5) forming L's table (L nested in K,
        holding L::run at 7) is K's own, and M::make (3) forming J's table (J::run at 9) is no constructor: joins."""
        from types import SimpleNamespace
        from unittest import mock
        code = _Code(10)
        k, l = DataObject(0x9000, 0x18, "_ZTV1K", ".data"), DataObject(0x9020, 0x18, "_ZTVN1K1LE", ".data")
        j = DataObject(0x9040, 0x18, "_ZTV1J", ".data")
        code.objects = [k, l, j]
        code.object_at = {0x9000: k, 0x9020: l, 0x9040: j}.get
        code.functions[2] = type(code.functions[2])(code.functions[2].address, 0x40, "_ZN1MC2Ev")
        code.functions[3] = type(code.functions[3])(code.functions[3].address, 0x40, "_ZN1M4makeEv")
        code.functions[5] = type(code.functions[5])(code.functions[5].address, 0x40, "_ZN1KC2Ev")
        code.refs = {2: [(0, 0x9010, "addr")], 5: [(0, 0x9030, "addr")], 3: [(0, 0x9050, "addr")]}
        code.users = lambda: {k: {2}, l: {5}, j: {3}}
        groups = {0x9000: [8], 0x9020: [7], 0x9040: [9]}
        ev = units.Evidence({}, [], [])
        with mock.patch("zkit.itanium._groups", side_effect=lambda program, address, size: [SimpleNamespace(
                slots=[code.functions[i].address for i in groups[address]])]), \
                mock.patch.object(units, "_function_classes", return_value={2: "M", 3: "M", 5: "K", 7: "K/L", 8: "K", 9: "J"}):
            rows = units._table_joins(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in rows], [(2, 8), (5, 7), (3, 9)])
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.inlined], [(2, 8)])

    def test_a_class_without_a_constructor_is_its_cited_file_s(self):
        """K::reflect (1) cites k.cpp, L::reflect (3) l.cpp; K::update (2) cites nothing and another build put it
        in l.cpp: K's file is k.cpp. M's 6 is beyond L's 7 (l.cpp's class) from M's own citation at 9: M says
        nothing there, nor does L's weak 4 (an inline, kept from any unit)."""
        from unittest import mock
        code = _Code(10)
        classes = {1: "K", 2: "K", 3: "L", 4: "L", 7: "L", 6: "M", 9: "M"}
        ev = units.Evidence({}, [], [])
        ev.files = {1: "k.cpp", 2: "l.cpp", 3: "l.cpp", 9: "m.cpp"}
        ev.placed = {2}
        code.functions[4] = type(code.functions[4])(code.functions[4].address, 0x40, "fn_4", "weak")
        with mock.patch.object(units, "_function_classes", return_value=classes):
            units._class_files(code, ev)
        self.assertEqual(ev.files[2], "k.cpp")
        self.assertEqual(ev.classed, {2})

    def test_a_file_s_unnamed_static_holds_its_users_together_however_far(self):
        """An unnamed static 0 and 100 use, over a.cpp's evidence alone, joins them; one over b.cpp's too, or a
        named global, or a tight run's (a join already), does not."""
        code = _Code(200)
        local = DataObject(0x9000, 8, "lbl_9000", ".bss")
        shared = DataObject(0x9010, 8, "lbl_9010", ".bss")
        named = DataObject(0x9020, 8, "_ZN1K6s_listE", ".bss")
        tight = DataObject(0x9030, 8, "lbl_9030", ".bss")
        code.users = lambda: {local: {0, 100}, shared: {40, 190}, named: {0, 100}, tight: {0, 20}}
        ev = units.Evidence({}, [], [])
        ev.files = {50: "a.cpp", 150: "b.cpp"}
        units._wide_statics(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.joins], [(0, 100)])

    def test_an_unnamed_object_across_a_stated_boundary_is_a_global(self):
        """Two copies of one literal put a boundary in 30..40: an unnamed object 0 and 100 use is then no file's
        static (a decomp's unnamed global) and joins nothing; one whose users the boundary does not part still does."""
        code = _Code(200)
        wide = DataObject(0x9000, 8, "lbl_9000", ".bss")
        after = DataObject(0x9010, 8, "lbl_9010", ".bss")
        code.users = lambda: {wide: {0, 100}, after: {50, 150}}
        ev = units.Evidence({}, [], [(30, 40, "two copies of one constant")])
        ev.files = {60: "a.cpp"}
        units._wide_statics(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.joins], [(50, 150)])

    def test_only_constants_loaded_into_float_registers_are_pooled_literals(self):
        """GameCube: a constant every access loads into a float register is a pooled literal (one copy per unit);
        one also read as an integer (a table, a local aggregate's initializer, emitted per use) or taken by address
        is not. Another platform's accesses say nothing."""
        from zkit.platform import Switch
        scalar = DataObject(0x9000, 4, "lbl_9000", ".sdata2")
        mixed = DataObject(0x9008, 8, "lbl_9008", ".rodata")
        formed = DataObject(0x9010, 4, "lbl_9010", ".sdata2")
        program = _Objects([scalar, mixed, formed])
        program.refs = {0: [(0, 0x9000, "f32"), (4, 0x9008, "f64")], 1: [(0, 0x9008, "u32"), (4, 0x9010, None)]}
        self.assertEqual(units._pooled_literals(program, {scalar, mixed, formed}), {scalar})
        program.platform = Switch()
        self.assertIsNone(units._pooled_literals(program, {scalar}))

    def test_a_pool_out_of_code_order_is_one_unit_s(self):
        """GameCube: b's user 2 comes before a's 5, yet b lies after a: 2-5 is one unit (a unit compiled
        `-inline deferred` pools in reverse). Not past POOL_REACH functions (f at 30, e at 60) or POOL_BYTES of
        pool (h, g), nor where two copies of one constant part the span or past a file's static initializer; one
        function's own `.rodata` copy (i) counts, a table two functions reach (k) does not. Another platform's pools
        say nothing."""
        from zkit.platform import Switch
        def at(address, size=4, section=".sdata2"):
            return DataObject(address, size, f"lbl_{address:X}", section)
        a, b, e, f, g, h = at(0x9000), at(0x9004), at(0x9010), at(0x9014), at(0x9100), at(0x9600)
        i, j, k, l = at(0xA000, 12, ".rodata"), at(0xA010, 4, ".rodata"), at(0xA020, 8, ".rodata"), \
            at(0xA030, 4, ".rodata")
        local = {a: [5], b: [2], e: [60], f: [30], g: [80], h: [78], i: [90], j: [88], k: [100, 101], l: [99]}
        program = _Objects(list(local))
        program.sections, program.function_index = [], {}
        program.refs = {n: [(0, o.address, "f32")] for n, o in enumerate([a, b, e, f, g, h, j, l])}
        program.refs[20] = [(0, i.address, "addr"), (4, k.address, "addr")]
        joins = units._pools_out_of_order(program, local)
        self.assertEqual([(lo, hi) for lo, hi, _ in joins], [(2, 5), (88, 90)])
        apart = [(3, 4, "two copies of one constant")]
        self.assertEqual([(lo, hi) for lo, hi, _ in units._pools_out_of_order(program, local, apart)], [(88, 90)])
        program.sections, program.function_index = [(".ctors", 0xB000, 0xB004)], {0x8000: 3}   # 3 is a file's
        program.read = lambda at, n: (0x8000).to_bytes(4, "big")                              # static initializer:
        self.assertEqual([(lo, hi) for lo, hi, _ in units._pools_out_of_order(program, local)], [(88, 90)])  # its end
        program.platform = Switch()
        self.assertEqual(units._pools_out_of_order(program, local), [])

    def test_a_nested_class_citing_nothing_is_its_enclosing_class_s_file(self):
        """K's 1 cites k.cpp; its nested K::Listener's 2 and 3 cite nothing and another build put them in m.cpp,
        whose own citation is at 5: they are k.cpp's. J::Inner's 7 has no enclosing file to take."""
        from unittest import mock
        code = _Code(10, weak=(9,))
        classes = {1: "K", 2: "K/Listener", 3: "K/Listener", 6: "J", 7: "J/Inner"}
        ev = units.Evidence({}, [], [])
        ev.files = {1: "k.cpp", 2: "m.cpp", 3: "m.cpp", 5: "m.cpp", 8: "n.cpp"}
        ev.placed = {2, 3}
        with mock.patch.object(units, "_function_classes", return_value=classes), \
                mock.patch.object(units, "_folded_destructors", return_value=set()):
            units._class_files(code, ev)
        self.assertEqual((ev.files[2], ev.files[3]), ("k.cpp", "k.cpp"))
        self.assertEqual(ev.classed, {2, 3})

    def test_merged_literals_come_in_link_order_once_per_block(self):
        """Units 0-9 in link order, strings then constants: the strings run 0..9 with one misplaced claim (a
        global another unit defines), the constants 0..9 again, then their other read-only data 0..9: blocks start
        at the constants and at the other data, not at the stray claim."""
        strings = [u for u in range(10) for _ in range(20)]
        strings.insert(60, 8)                         # one claim out of place: a few stand by a cut there
        constants = [u for u in range(10) for _ in range(3)]
        other = [u for u in range(10) for _ in range(12)]
        values = strings + constants + other
        self.assertEqual(units._cuts(values), [len(strings), len(strings) + len(constants)])
        self.assertEqual(units._cuts(list(range(50))), [])

    def test_another_build_s_unit_yields_to_the_code_s_joins(self):
        """Another build put 2-3 in a.cpp and 5 in b.cpp, but data only 2-5 use joins them: 5 is a.cpp's too, as
        most of that build's run says. 12 cites c.cpp itself and so outweighs that build's d.cpp for 10 in its
        join; 40-42 own citations of two files (one including the other): it says nothing. 20 and 30 no join
        covers keep that build's files."""
        ev = units.Evidence({}, [(2, 5, "data"), (10, 12, "data"), (40, 42, "data")], [])
        ev.files = {2: "a.cpp", 3: "a.cpp", 5: "b.cpp", 10: "d.cpp", 12: "c.cpp", 20: "e.cpp", 30: "f.cpp",
                    40: "g.cpp", 41: "x.cpp", 42: "h.cpp"}
        ev.placed = {2, 3, 5, 10, 20, 30, 41}
        units._joined_placements(ev)
        self.assertEqual(ev.files, {2: "a.cpp", 3: "a.cpp", 12: "c.cpp", 20: "e.cpp", 30: "f.cpp", 40: "g.cpp",
                                    41: "x.cpp", 42: "h.cpp"})
        self.assertEqual(ev.placed, {2, 3, 20, 30, 41})

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
        code.users = lambda: {}
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


class CheckTests(unittest.TestCase):
    """What `units --check` proposes for an existing splits.txt."""

    def test_no_fold_across_a_stated_boundary_or_two_static_initializers(self):
        """Data joins a/b, c/d and e/f. Two copies of one literal put a boundary between a and b, and c and d hold
        a static initializer each: only e+f is a fold. g holds two initializers (one per file): a split."""
        from unittest import mock
        code = _Code(16)
        code.objects = []
        table = [code.functions[i].address for i in (5, 6, 12, 14)]
        code.sections = [(".ctors", 0x9000, 0x9000 + 4 * len(table))]
        code.read = lambda at, n: table[(at - 0x9000) // 4].to_bytes(4, "big")
        splits = [(name, ".text", code.functions[lo].address, code.functions[hi].address + 0x40)
                  for name, lo, hi in [("a", 0, 1), ("b", 2, 3), ("c", 4, 5), ("d", 6, 7), ("e", 8, 9), ("f", 10, 11),
                                       ("g", 12, 15)]]
        ev = units.Evidence({}, [(1, 2, "x"), (5, 6, "y"), (9, 10, "z")], [(2, 2, "two copies of one constant")])
        units._initializers_apart(code, ev)
        with mock.patch.object(units, "evidence", return_value=ev), \
                mock.patch.object(units, "linker_code", return_value=set()):
            result = units.check(code, splits)
        self.assertEqual([r["units"] for r in result["folds"]], [["e", "f"]])
        self.assertEqual([(r["unit"], r["window"]) for r in result["splits"]],
                         [("g", [code.platform.text(code.functions[12].address), code.platform.text(code.functions[14].address)])])


    def test_a_pool_out_of_order_folds_every_unit_it_spans(self):
        """A pool out of code order joins 1-7 over a, b and c: a+b and b+c are folds; data joining d..f says only
        that some boundary there is wrong."""
        from unittest import mock
        code = _Code(16)
        code.objects, code.sections = [], []
        splits = [(name, ".text", code.functions[lo].address, code.functions[hi].address + 0x40)
                  for name, lo, hi in [("a", 0, 2), ("b", 3, 5), ("c", 6, 8), ("d", 9, 10), ("e", 11, 12),
                                       ("f", 13, 15)]]
        ordered = (1, 7, "the literal 0x9000 lies before 0x9010, whose users come first: one unit")
        ev = units.Evidence({}, [ordered, (10, 14, "lbl_9100 (.sbss) is one unit's")], [], ordered=[ordered])
        with mock.patch.object(units, "evidence", return_value=ev), \
                mock.patch.object(units, "linker_code", return_value=set()):
            result = units.check(code, splits)
        self.assertEqual(sorted(r["units"] for r in result["folds"]), [["a", "b"], ["b", "c"]])

    def test_a_boundary_lies_between_two_static_initializers(self):
        """.ctors calls 3 and 9 (a symbol names only its first entry, not the section's others): a boundary lies in
        4..9, the code's own statement."""
        code = _Code(12)
        code.objects = [DataObject(0x9000, 4, "__init_cpp_exceptions_reference", ".ctors")]
        code.sections = [(".ctors", 0x9000, 0x900C)]
        words = [code.functions[3].address, code.functions[9].address, 0]
        code.read = lambda at, n: words[(at - 0x9000) // 4].to_bytes(4, "big")
        ev = units.Evidence({}, [], [])
        units._initializers_apart(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.separations], [(4, 9)])
        self.assertEqual(ev.direct, set(ev.separations))


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

    def test_a_dotted_local_function_has_its_own_code_section(self):
        """clang compiles a file's static initializer, `_GLOBAL__sub_I_a.cpp`, into `.text._GLOBAL__sub_I_a.cpp`,
        and objdiff pairs a local symbol only between sections whose names agree without their last `.part`: the
        original's copy is cut into that section too, and only on AArch64."""
        functions = [delink.Entry(0x100, 0x20, "_Z1fv"), delink.Entry(0x120, 0x10, "_GLOBAL__sub_I_a.cpp", "local"),
                     delink.Entry(0x130, 0x10, "_Z1gv"), delink.Entry(0x140, 0x8, "_ZL1hv.part.0", "global")]
        symbols = delink.Symbols(functions, [], lambda a: f"{a:X}")
        image = delink.Image(delink.AARCH64, 0, None, symbols, None, None, None, None)
        self.assertEqual(list(delink._own_sections(image, ".text", (0x100, 0x148), ".text")),
                         [(0x100, 0x120, ".text"), (0x120, 0x130, ".text._GLOBAL__sub_I_a.cpp"),
                          (0x130, 0x148, ".text")])                     # a global keeps the unit's section
        self.assertEqual(list(delink._own_sections(image, ".data", (0x100, 0x148), ".data")),
                         [(0x100, 0x148, ".data")])
        image = delink.Image(delink.PPC, 0, None, symbols, None, None, None, None)
        self.assertEqual(list(delink._own_sections(image, ".text", (0x100, 0x148), ".text")),
                         [(0x100, 0x148, ".text")])


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


class NeighbourFolderTests(unittest.TestCase):
    def test_a_unit_no_file_names_takes_the_folder_of_the_files_around_it(self):
        """A build that links each folder's files in name order (case folded, so `_` after letters) puts a unit
        named after its class between two files of one folder into that folder; a hand-ordered link, where the
        files' own order is not sorted, places nothing."""
        files = [f"game/asset/f_{c}.cpp" for c in "abcdefghijklmnopqrstuvwxy"]
        named = [(i, i + 1, name, "file string") for i, name in enumerate(files)]
        named.insert(5, (99, 100, "ns/AssetUtil.cpp", "class"))
        named.insert(9, (199, 200, "unit_7100001000.cpp", "placeholder"))
        named.append((299, 300, "ns/Tail.cpp", "class"))                     # no file after it
        out = units._in_neighbours_folder(named, {})
        self.assertEqual(out[5][2], "game/asset/AssetUtil.cpp")
        self.assertEqual(out[9][2], "game/asset/unit_7100001000.cpp")
        self.assertEqual(out[-1][2], "ns/Tail.cpp")
        shuffled = [(i, i + 1, name, "file string") for i, name in enumerate(reversed(files))]
        shuffled.insert(5, (99, 100, "ns/AssetUtil.cpp", "class"))
        self.assertEqual(units._in_neighbours_folder(shuffled, {})[5][2], "ns/AssetUtil.cpp")

    def test_a_unit_between_two_folders_takes_the_folder_both_are_in(self):
        """Between the last file of one folder and the first of another, a sorted folder walk lists only files of
        the deepest folder both are in; with no folder in common the unit keeps its name."""
        files = [f"app/game/battle/ai/f_{c}.cpp" for c in "abcdefghijkl"] + \
            [f"app/game/battle/g_{c}.cpp" for c in "abcdefghijkl"] + [f"lib/x/h_{c}.cpp" for c in "a"]
        named = [(i, i + 1, name, "file string") for i, name in enumerate(files)]
        named.insert(12, (99, 100, "ai/AiScriptDataManager.cpp", "class"))
        named.insert(25, (199, 200, "unit_7100001000.cpp", "placeholder"))
        named.insert(27, (299, 300, "lib/Tail.cpp", "class"))                   # only the top folder in common
        named.append((399, 400, "lib/y/i_a.cpp", "file string"))
        out = units._in_neighbours_folder(named, {})
        self.assertEqual(out[27][2], "lib/Tail.cpp")
        self.assertTrue(units.UNNAMED.match("app/game/unit_7100001000.cpp"))   # a placeholder in a folder
        self.assertEqual(out[12][2], "app/game/battle/AiScriptDataManager.cpp")
        self.assertEqual(out[25][2], "unit_7100001000.cpp")


class DeferredTailTests(unittest.TestCase):
    """clang creates an inline or file-local function only data refers to when it emits that data, after every
    definition of its unit (`_deferred_tails`, `_held_reach`, `_shared_data`)."""

    def _code(self):
        """0-1 a.cpp's definitions, 2 weak and 3 file-local (in no symbol table), only a table holds them; 4 the
        weak base destructor of a member template, also only held; 5 b.cpp's first definition; 6 an inline of
        class B held only by B's table, before 7, B's definition; 8-9 strong."""
        code = _Code(10, weak=[2, 4, 6], unlisted=[3])
        names = {2: "_ZN1A6inlineEv", 4: "_ZN1TIiED2Ev", 5: "_ZN1B4makeEv", 6: "_ZN1B4peekEv", 7: "_ZN1B3useEv"}
        from dataclasses import replace
        code.functions = [replace(f, name=names.get(i, f.name)) for i, f in enumerate(code.functions)]
        table = DataObject(0x9000, 0x40, "lbl_9000", ".data")
        address = lambda i: code.functions[i].address
        code.pointers = [(0x9000, address(2)), (0x9008, address(3)), (0x9010, address(4)), (0x9018, address(6))]
        code.object_at = lambda a: table if 0x9000 <= a < 0x9040 else None
        code.users = lambda: {table: {1}}
        code.refs = {1: [(0, 0x9000, "addr")]}
        code.calls = {}
        return code

    def test_an_external_definition_after_a_unit_s_tail_starts_another_unit(self):
        """2 and 3 are a.cpp's tail: a boundary between them and 5, and none before them; 4 (a base destructor a
        derived destructor could have called and inlined) and 6 (before its own class's definition) cut
        nothing."""
        code = self._code()
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={6: "B", 7: "B"}):
            units._deferred_tails(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.tails], [(3, 5), (4, 5)])
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.joins], [(1, 2), (2, 3), (3, 4), (5, 6)])
        from zkit.platform import GameCube
        code.platform, ev = GameCube(), units.Evidence({}, [], [])
        units._deferred_tails(code, ev)
        self.assertEqual((ev.tails, ev.joins), ([], []))

    def test_a_tail_joins_only_code_emitting_data_that_holds_it(self):
        """6 is held only by a table code after it (8) forms: no join with 5 (its unit may have lost every
        definition to the linker); an initializer list's function (2) is no tail."""
        code = self._code()
        init = DataObject(0x9800, 0x8, "lbl_9800", ".init_array")
        later = DataObject(0x9400, 0x10, "lbl_9400", ".data")
        address = lambda i: code.functions[i].address
        code.pointers = [(0x9800, address(2)), (0x9008, address(3)), (0x9010, address(4)), (0x9400, address(6))]
        table = code.object_at(0x9000)
        code.object_at = lambda a: init if a == 0x9800 else later if a == 0x9400 else table if 0x9000 <= a < 0x9040 \
            else None
        code.users = lambda: {table: {1}, later: {8}}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._deferred_tails(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.joins], [(2, 3), (3, 4)])

    def test_a_tail_joins_code_using_an_object_whose_table_holds_it(self):
        """No code forms the table's address, but 1 uses an object whose first word points to it (a constant
        initialized instance of the class): the unit defining the object emits its table, so 2 and 3 join 1."""
        code = self._code()
        table = code.object_at(0x9000)
        instance = DataObject(0x9400, 0x10, "lbl_9400", ".data")
        code.pointers = code.pointers + [(0x9400, 0x9000)]
        code.object_at = lambda a: instance if 0x9400 <= a < 0x9410 else table if 0x9000 <= a < 0x9040 else None
        code.users = lambda: {instance: {1}}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._deferred_tails(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.joins], [(1, 2), (2, 3), (3, 4), (5, 6)])

    def test_data_holding_functions_only_it_refers_to_is_their_unit_s(self):
        """Every unit emitting the table emits the inline (2) and the file-local function (3) only it holds, so
        the kept copies come from one unit: the table is a.cpp's, whoever builds the class; a table whose only
        held functions are in two units, or are also called, has no such owner."""
        code = self._code()
        code.in_code = lambda a: False
        owner = {i: "a.cpp" if i < 7 else "b.cpp" for i in range(10)}
        weak = units._weak(code)
        held = [(0x9000, 0x9040, "a.cpp", ".data")]
        self.assertEqual(units._held_tables(code, owner, weak), held)
        owner[4] = owner[6] = "c.cpp"                  # 4 and 6: weak, held, but now in other units
        self.assertEqual(units._held_tables(code, owner, weak), [])
        code.pointers = code.pointers[:2]
        self.assertEqual(units._held_tables(code, owner, weak), held)
        code.calls = {8: {2}}
        code.pointers = code.pointers[:1]
        self.assertEqual(units._held_tables(code, owner, weak), [])

    def test_a_merged_literal_several_units_tables_name_is_the_first_unit_s(self):
        """Only data points to the string: a.cpp's table and b.cpp's (b first in memory, a first in link order).
        The linker keeps the first unit's copy; one table's string, or one some code uses, is not this rule's."""
        from types import SimpleNamespace
        string = DataObject(0x7000, 0x10, "lbl_7000", ".rodata")
        alone = DataObject(0x7010, 0x8, "lbl_7010", ".rodata")
        objects = {0x7000: string, 0x7010: alone}
        program = SimpleNamespace(users=lambda: {}, in_code=lambda a: False, object_at=objects.get,
                                  pointers=[(0x9000, 0x7000), (0x9100, 0x7000), (0x9108, 0x7010)])
        claims = [(0x9000, 0x9008, "b.cpp", ".data"), (0x9100, 0x9110, "a.cpp", ".data")]
        order = {"a.cpp": 0, "b.cpp": 1}
        self.assertEqual(units._shared_literals(program, claims, order, set(order)),
                         [(0x7000, 0x7010, "a.cpp", ".rodata")])
        program.users = lambda: {string: {3}}
        self.assertEqual(units._shared_literals(program, claims, order, set(order)), [])

    def test_a_named_function_a_table_holds_is_not_known_strong_without_the_module_s_listing(self):
        """Without a symbol table listing the module's functions, a name's binding is known only where it is weak:
        named 5 is strong, held 6 is not (its weak mark may not have come with its name), placeholders never."""
        code = self._code()
        code.image.symbols = {}
        weak, local, strong = units._bindings(code)
        self.assertEqual(local, set())
        self.assertEqual([i for i, s in enumerate(strong) if s], [5, 7])

    def test_code_using_data_keeps_the_functions_only_it_holds(self):
        """1 forms the table's address: the non-strong functions it holds after 1 count as its calls."""
        code = self._code()
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            self.assertEqual(sorted(units._held_reach(code)), [(1, 2), (1, 3), (1, 4), (1, 6)])

    def test_code_using_data_that_points_to_a_table_keeps_the_functions_the_table_holds(self):
        """No code forms the table's address; only a descriptor 1 uses points to it (a static method table a
        static class descriptor names): the table is emitted with the descriptor, so 1 keeps what it holds. A
        weak descriptor (any unit's copy) says nothing."""
        code = self._code()
        table = code.object_at(0x9000)
        descriptor = DataObject(0x9400, 0x10, "lbl_9400", ".data")
        code.pointers = code.pointers + [(0x9408, 0x9000)]
        code.object_at = lambda a: descriptor if 0x9400 <= a < 0x9410 else table if 0x9000 <= a < 0x9040 else None
        code.users = lambda: {descriptor: {1}}
        code.refs = {1: [(0, 0x9400, "addr")]}
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            self.assertEqual(sorted(units._held_reach(code)), [(1, 2), (1, 3), (1, 4), (1, 6)])
            from dataclasses import replace
            code.objects = [replace(descriptor, scope="weak")]
            self.assertEqual(sorted(units._held_reach(code)), [])

    def test_weak_data_is_no_one_unit_s(self):
        code = _Code(4)
        code.objects = [DataObject(0x9000, 8, "_ZTV1TIiE", ".data", "weak"), DataObject(0x9100, 8, "s", ".bss")]
        self.assertEqual(units._shared_data(code), {0x9000})

    def test_a_function_only_deferred_code_refers_to_is_a_tail(self):
        """0 (a.cpp) calls weak 1, created there; 1's body is emitted with the unit's other inlines, after every
        definition, and only it refers to weak 3, created then: 4, an external definition after 3, is b.cpp's.
        Weak 5 strong 4 calls too is created among the definitions: no tail. Weak 6, which nothing refers to, is a
        definition the unit emits anyway (a weak attribute), with its body: 7, which only 6 calls, is no tail."""
        code = _Code(10, weak=[1, 3, 5, 6, 7])
        code.pointers, code.object_at, code.users = [], lambda a: None, lambda: {}
        code.calls = {0: [1], 1: [3, 5], 4: [5], 6: [7]}
        ev = units.Evidence({}, [], [])
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            units._deferred_tails(code, ev)
        self.assertEqual([(lo, hi) for lo, hi, _ in ev.tails], [(4, 4)])

    def test_a_tail_parts_a_global_s_near_users_only(self):
        """A tail's boundary (before 4) goes through the run of a global's near users (2-6, `globals`: the next
        file reaches it through the GOT as its own file does) or of another class's code forming a table's address
        (`inlined`: a constructor its header defines), not through a run any other data holds."""
        code = _Code(8)
        code.pointers, code.object_at, code.users = [], lambda a: None, lambda: {}
        row = (2, 6, "g (.bss) is one unit's")
        ev = units.Evidence({}, [row], [])
        ev.globals, ev.tails = {row}, [(4, 4, "3 is created only by deferred code")]
        with unittest.mock.patch.object(units, "_function_classes", return_value={}):
            self.assertEqual([b.position for b in units.boundaries(code, ev)], [4])
            ev.globals, ev.inlined = set(), {row}
            self.assertEqual([b.position for b in units.boundaries(code, ev)], [4])
            ev.inlined = set()
            self.assertEqual(units.boundaries(code, ev), [])

    def test_a_global_is_what_code_loads_from_a_got_slot(self):
        """g's user 1 loads its address from the .got slot at 0x8008; s's users form it directly: g is a global,
        s is not; neither where the build's globals are not reached through the GOT."""
        from types import SimpleNamespace
        code = _Code(4)
        code.image = SimpleNamespace(tables={".got": (0x8000, 0x8100)}, pointers={0x8008: 0x9100})
        code.platform.words = lambda image, address, size: [address]
        s, g = DataObject(0x9000, 8, "lbl_9000", ".bss"), DataObject(0x9100, 8, "lbl_9100", ".bss")
        rows = {0: [(0x9000, "addr")], 1: [(0x8008, "load"), (0x9000, "addr")], 2: [(0x9000, "addr")]}
        track = lambda words, start, load64: {start + 4 * k: r for k, r in
                                              enumerate(rows.get((start - 0x1000) // 0x40, []))}
        with unittest.mock.patch("zkit.aarch64.track_addresses", track):
            self.assertEqual((units._through_got(code, g, [0, 1]), units._through_got(code, s, [0, 2])),
                             (True, False))
            code.cflags = ["-O3", "-fPIC", "-fvisibility=hidden"]
            self.assertFalse(units._through_got(code, g, [0, 1]))


class InitializerNameTests(unittest.TestCase):
    def test_only_a_unit_its_source_file_names_names_its_initializer(self):
        """clang names a file's static initializer after the file: a unit named by a file string gets
        `_GLOBAL__sub_I_<file>`; one named by its class, a placeholder or one piece of a file gets none."""
        from types import SimpleNamespace
        from zkit import analyze
        from zkit.program import Function
        program = SimpleNamespace(functions=[Function(0x100 + 0x10 * i, 0x10, f"fn_{i}") for i in range(4)])
        proposal = {"units": [{"unit": "src/a.cpp", "named_by": "file string", "first": 0, "end": 1},
                              {"unit": "src/Widget.cpp", "named_by": "class", "first": 1, "end": 2},
                              {"unit": "unit_00000120.cpp", "named_by": "placeholder", "first": 2, "end": 3},
                              {"unit": "src/b_00000130.cpp", "named_by": "file string", "first": 3, "end": 4}]}
        names = analyze._initializer_names(program, proposal, {0x100: False, 0x110: False, 0x120: False, 0x130: False})
        self.assertEqual([(p.address, p.name) for p in names], [(0x100, "_GLOBAL__sub_I_a.cpp")])


class DirectReachTests(unittest.TestCase):
    def test_a_static_every_user_forms_directly_is_one_unit_s_however_far_apart(self):
        """s (users 0 and 70, both forming its address with adrp) is a file's static: one span; g's user 70 loads
        it through a slot (no address formed), so g is a global; t's users are near each other (the tight joins'
        business); weak w is every unit's. Only built -fPIC with default visibility; not on the GameCube."""
        from unittest import mock
        code = _Code(80)
        code.platform.words = lambda image, address, size: [address]
        s, g = DataObject(0x9000, 8, "lbl_9000", ".bss"), DataObject(0x9100, 8, "lbl_9100", ".bss")
        t, w = DataObject(0x9200, 8, "lbl_9200", ".bss"), DataObject(0x9300, 8, "_ZGV", ".bss", "weak")
        formed = {0: [0x9000, 0x9100, 0x9200, 0x9300], 3: [0x9200], 70: [0x9000, 0x9300]}
        rows = lambda words, start, load64: {start + 4 * k: (a, "addr") for k, a in
                                             enumerate(formed.get((start - 0x1000) // 0x40, []))}
        users = {s: {0, 70}, g: {0, 70}, t: {0, 3}, w: {0, 70}}
        with mock.patch("zkit.aarch64.track_addresses", rows):
            spans = units._direct_reach(code, users, {0x9300})
        self.assertEqual([(lo, hi) for lo, hi, _ in spans], [(0, 70)])
        for flags in (["-fPIC", "-fvisibility=hidden"], ["-fPIE"], None):     # every global formed directly, or unknown
            code.cflags = flags
            with mock.patch("zkit.aarch64.track_addresses", rows):
                self.assertEqual(units._direct_reach(code, users, {0x9300}), [])
        from zkit.platform import GameCube
        code.platform = GameCube()
        self.assertEqual(units._direct_reach(code, users, set()), [])


    def test_a_span_counts_only_where_its_code_cites_one_file(self):
        """Spans 0-10 (cites a.cpp, another build places b.cpp), 20-30 (only another build's files), 40-50 (cites
        two files): only the first holds its users together."""
        ev = units.Evidence({}, [], [])
        ev.files = {2: "a.cpp", 5: "b.cpp", 22: "b.cpp", 25: "c.cpp", 42: "a.cpp", 48: "d.cpp"}
        ev.placed = {5, 22, 25}
        ev.reach = [(0, 10, "s"), (20, 30, "t"), (40, 50, "u")]
        self.assertEqual(units._cited_reach(ev), [(0, 10, "s")])


class HeldStaticsTests(unittest.TestCase):
    def _code(self):
        """2-5 file-local callbacks only table T holds; record R (a global, its user 7 loads it from a slot) holds
        T and the file-local 6; table U, formed directly by 8, holds 9; T also points at a literal function 0
        forms; 10 is held by T but also called; 11 is held by a class table."""
        from dataclasses import replace
        code = _Code(12)
        code.platform.words = lambda image, address, size: [address]
        statics = {2, 3, 4, 5, 6, 9, 10, 11}
        code.functions = [replace(f, name=f"_ZL{i}f" if i in statics else f.name) for i, f in enumerate(code.functions)]
        address = lambda i: code.functions[i].address
        t, r = DataObject(0x9000, 0x40, "_ZL7s_table", ".data"), DataObject(0x9100, 0x10, "rec", ".data")
        u, s = DataObject(0x9200, 0x8, "lbl_9200", ".data"), DataObject(0x9300, 0x8, "lbl_9300", ".rodata")
        v = DataObject(0x9400, 0x18, "_ZTV1V", ".data")
        objects = [t, r, u, s, v]
        code.objects = objects
        code.object_at = lambda a: next((o for o in objects if o.address <= a < o.address + o.size), None)
        code.pointers = [(0x9000, address(2)), (0x9008, address(3)), (0x9010, address(4)), (0x9018, address(5)),
                         (0x9020, 0x9300), (0x9028, address(10)), (0x9100, 0x9000), (0x9108, address(6)),
                         (0x9200, address(9)), (0x9410, address(11))]
        code.refs = {0: [(0, 0x9300, "addr")], 7: [(0, 0x9100, "addr")], 8: [(0, 0x9200, "addr")]}
        code.calls = {1: [10]}
        code.users = lambda: {s: {0}, r: {7}, u: {8}}
        formed = {0: [0x9300], 8: [0x9200]}                   # 7 loads rec from its slot
        rows = lambda words, start, load64: {start + 4 * k: (a, "addr") for k, a in
                                             enumerate(formed.get((start - 0x1000) // 0x40, []))}
        return code, rows

    def test_file_local_functions_only_data_holds_are_in_the_unit_of_that_data(self):
        """2-6 are one unit's (T's callbacks, R holds T and 6); 8 forms U, a writable object, directly: 8-9; not
        the literal's user 0, not called 10, not the class table's 11, not 7 (rec is a global)."""
        from unittest import mock
        code, rows = self._code()
        ev = units.Evidence({}, [], [])
        with mock.patch("zkit.aarch64.track_addresses", rows), mock.patch("zkit.itanium._groups", return_value=[]):
            self.assertEqual(sorted((lo, hi) for lo, hi, _ in units._held_statics(code, ev)), [(2, 6), (8, 9)])
            ev.files = {3: "a.cpp", 6: "b.cpp"}                # the code itself cites two files: no join there
            self.assertEqual(sorted((lo, hi) for lo, hi, _ in units._held_statics(code, ev)), [(8, 9)])
            ev.files = {}
            code.cflags = ["-O3", "-fPIE"]                     # every global formed directly: U is no proof
            self.assertEqual([(lo, hi) for lo, hi, _ in units._held_statics(code, ev)], [(2, 6)])
            from zkit.platform import GameCube
            code.platform = GameCube()
            self.assertEqual(units._held_statics(code, ev), [])


class AnotherBuildNameTests(unittest.TestCase):
    def test_a_file_s_name_from_another_build_yields_to_its_own_citations_anywhere(self):
        """a.cpp's own code is unit 3; another build also names units 0 and 2 after it (its coarser unit): on the
        Switch both are another file, the neighbour 2 on any platform."""
        named = [(0, 1, "a.cpp", "another build"), (1, 2, "b.cpp", "file string"), (2, 3, "a.cpp", "another build"),
                 (3, 4, "a.cpp", "file string")]
        rename = lambda first, end: (f"K{first}.cpp", "class")
        code = _Code(4)
        self.assertEqual([n for _, _, n, _ in units._not_another_build_s_file(code, named, rename)],
                         ["K0.cpp", "b.cpp", "K2.cpp", "a.cpp"])
        from zkit.platform import GameCube
        code.platform = GameCube()
        self.assertEqual([n for _, _, n, _ in units._not_another_build_s_file(code, named, rename)],
                         ["a.cpp", "b.cpp", "K2.cpp", "a.cpp"])

    def test_the_cited_files_decide_whether_the_link_is_sorted(self):
        """Another build's units named after their classes (`Zeta.cpp` before `f_b.cpp`) say nothing of the link's
        order: the files the code cites are in name order, so the class unit takes their folder."""
        files = [f"app/game/f_{c}.cpp" for c in "abcdefghijklmnopqrstuvwxy"]
        named = []
        for i, name in enumerate(files):
            named.append((2 * i, 2 * i + 1, name, "file string"))
            named.append((2 * i + 1, 2 * i + 2, f"app/game/Zeta{i}.cpp", "another build"))
        named.insert(5, (99, 100, "ns/AssetUtil.cpp", "class"))
        self.assertEqual(units._in_neighbours_folder(named, {})[5][2], "app/game/AssetUtil.cpp")


class GotImportTests(unittest.TestCase):
    def test_a_load_through_a_got_slot_of_imported_data_names_the_import(self):
        """A `.got` slot the dynamic linker fills with another module's data symbol has no pointee in the image:
        the load through it is still a GOT load, and the cut object names the import as the compiler's
        R_AARCH64_ADR_GOT_PAGE/LD64_GOT_LO12_NC do, not a label at the slot."""
        from zkit import aarch64
        # at 0x100: adrp x8, page 0x5000; ldr x8, [x8, #0x20]; ret
        words = [0xB0000028, 0xF9401108, 0xD65F03C0]
        found, _ = aarch64.code_relocations(words, 0x100, {}, got=(0x5000, 0x5100), imports={0x5020})
        self.assertEqual(sorted((r.offset, r.kind, r.target, r.got) for r in found), [
            (0x100, aarch64.ADR_GOT_PAGE, 0x5020, True), (0x104, aarch64.LD64_GOT_LO12_NC, 0x5020, True)])
        found, _ = aarch64.code_relocations(words, 0x100, {}, got=(0x5000, 0x5100))
        self.assertEqual([r.kind for r in found], [aarch64.ADR_PREL_PG_HI21, aarch64.LDST64])

        blob = struct.pack("<3I", *words)
        read = lambda address, size: blob[address - 0x100:address - 0x100 + size]
        symbols = delink.Symbols([delink.Entry(0x100, 0xC, "_Z4readv")], [], lambda a: f"{a:X}")

        def code_of(start, size, resolved):
            relocs, cleared = aarch64.code_relocations(list(struct.unpack(f"<{size // 4}I", read(start, size))),
                                                       start, {}, resolved, (0x5000, 0x5100), {0x5020})
            return [(r.offset, r.kind, r.target, r.got) for r in relocs], cleared
        image = delink.Image(delink.AARCH64, 0, read, symbols, lambda a: True, code_of, lambda a, b: [],
                             lambda a: f"{a:X}", imports={0x5020: "_ZN2ns4Data8intervalE"})
        unit = delink.Unit("a.cpp")
        unit.ranges[".text"].append((0x100, 0x10C))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "a.o"
            row = delink.write_unit(image, delink.cut_unit(image, unit), path)
            data = path.read_bytes()
        self.assertEqual((row["labels"], row["undefined"]), (0, 1))
        self.assertIn(b"_ZN2ns4Data8intervalE\0", data)
        self.assertNotIn(b"lbl_", data)


class RecursionTests(unittest.TestCase):
    def test_a_recursive_call_is_cut_resolved_as_clang_leaves_it(self):
        """clang 3.9 resolves a function's call to its own start in its object (no relocation, the offset encoded):
        the original's copy is cut the same way. A call to another global function keeps its relocation."""
        from zkit import aarch64
        code = struct.pack("<4I", 0x94000000, 0x97FFFFFF, 0x94000002, 0xD65F03C0)
        # at 0x100: bl 0x100 (itself, -0 words is encoded 0x94000000), at 0x104: bl 0x100 (-1 word),
        # at 0x108: bl 0x110 (+2 words, another function), at 0x10C: ret
        functions = [delink.Entry(0x100, 0x10, "_Z4selfv"), delink.Entry(0x110, 0x4, "_Z5otherv")]
        blob = code + struct.pack("<I", 0xD65F03C0)
        read = lambda address, size: blob[address - 0x100:address - 0x100 + size]
        symbols = delink.Symbols(functions, [], lambda a: f"{a:X}")

        def code_of(start, size, resolved):
            words = list(struct.unpack(f"<{size // 4}I", read(start, size)))
            found, cleared = aarch64.code_relocations(words, start, {}, resolved)
            return [(r.offset, r.kind, r.target, r.got) for r in found], cleared
        image = delink.Image(delink.AARCH64, 0, read, symbols, lambda a: True, code_of, lambda a, b: [],
                             lambda a: f"{a:X}")
        unit = delink.Unit("a.cpp")
        unit.ranges[".text"].append((0x100, 0x114))
        cut = delink.cut_unit(image, unit)
        self.assertEqual([(offset, target) for offset, _, target, _ in cut.found[".text"]], [(0x108, 0x110)])
