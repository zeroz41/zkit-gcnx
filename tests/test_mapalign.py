import support  # noqa: F401  (isolates config, cache and state)
import tempfile
import unittest
from pathlib import Path

from zkit import mapalign, mwmap, units
from zkit.program import DataObject, Function, Program

TEXT, DATA, SDATA, END = 0x80004000, 0x80100000, 0x80200000, 0x80300000


class Image:
    """Bytes by address (zero elsewhere), the addresses each function forms, and data words that point."""

    def __init__(self):
        self.bytes: dict[int, int] = {}
        self.refs: dict[int, list[tuple[int, int, str]]] = {}
        self.pointers: list[tuple[int, int]] = []

    def put(self, address: int, raw: bytes) -> None:
        for k, b in enumerate(raw):
            self.bytes[address + k] = b

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.bytes.get(address + k, 0) for k in range(size))


class Fake:
    name = "fake"
    literals_per_unit = False

    def addresses(self, image, start, size, context):
        return image.refs.get(start, [])

    def calls(self, image, start, size):
        return []

    def data_pointers(self, image):
        return image.pointers

    def read(self, image, address, size):
        return image.read(address, size)

    def sections(self, image):
        return []

    def text(self, address):
        return f"0x{address:08X}"


# Units of the map's build, in link order: (unit, [(function, size)]). The original has the same code except
# `debug.c` (a unit only that build links) and the third function of `drawn.cpp` (an assertion compiled in).
def _unit(name: str, stem: str, count: int, first: int) -> tuple[str, list[tuple[str, int]]]:
    return name, [(f"{stem}_{k}", 0x40 + 4 * (first + 7 * k)) for k in range(count)]


UNITS = [_unit("Lib.a first.c", "first", 7, 0), _unit("Lib.a debug.c", "debug_only", 2, 1),
         ("game.o", [("update__4GameFv", 0x1F8), ("draw__4GameFv", 0x9C), ("helper", 0x31C)]),
         _unit("Lib.a drawn.cpp", "drawn", 7, 2), _unit("Lib.a last.c", "last", 7, 3)]
CHANGED = {"drawn_2": 0x400}


def program_and_map(folder: Path) -> tuple[Program, Path, Image]:
    image = Image()
    functions, address, where = [], TEXT, {}
    for unit, rows in UNITS:
        if unit == "Lib.a debug.c":
            continue
        for name, size in rows:
            size = CHANGED.get(name, size)
            functions.append(Function(address, size, f"fn_{address:08X}"))
            where[name] = address
            address += size
    text_end = address
    # game.o's data: a table its code forms the address of (at +0x10 in its .data), the strings only that table
    # points to, and two small-data words its code loads
    table, strings = DATA + 0x40, DATA + 0x100
    image.refs[where["update__4GameFv"]] = [(0, table + 0x10, "addr"), (4, SDATA + 8, "load"),
                                                   (8, SDATA + 0xC, "store")]
    image.put(strings, b"one\0two\0\0\0\0\0")
    image.put(DATA + 0x70, b"\1")                    # data past game.o's piece that the analysis took for its
    image.put(table + 0x10, (strings).to_bytes(4, "big") + (strings + 4).to_bytes(4, "big"))
    image.pointers = [(table + 0x10, strings), (table + 0x14, strings + 4)]
    objects = [DataObject(DATA, 0x40, "lbl_other", ".data"), DataObject(table, 0x10, "lbl_t0", ".data"),
               DataObject(table + 0x10, 0xB0, f"lbl_{table + 0x10:08X}", ".data"),
               DataObject(strings, 0x10, f"lbl_{strings:08X}", ".data"),
               DataObject(SDATA + 8, 8, "lbl_s8", ".sdata"), DataObject(SDATA + 0xC, 4, "lbl_sc", ".sdata")]
    program = Program(Fake(), image, functions, objects)
    program.sections = [(".text", TEXT, text_end), (".data", DATA, SDATA), (".sdata", SDATA, END)]

    shift = 0x1000                                    # the other build links everything elsewhere
    lines = ["Link map of __start",
             " 1] update__4GameFv (func,global) found in game.o ",
             " 2] gTable (object,global) found in game.o ",
             " 3] @12 (object,local) found in game.o ",
             "", ".text section layout", "  Starting        Virtual", "  address  Size   address",
             "  -----------------------"]
    address = TEXT + shift
    for unit, rows in UNITS:
        where_unit = unit.replace("Lib.a ", "Lib.a\t").split("\t")
        label = " ".join(where_unit)
        lines.append(f"  00000000 {0x9000:06x} {address:08x}  1 .text \t{label} ")
        for name, size in rows:
            lines.append(f"  00000000 {size:06x} {address:08x}  4 {name} \t{label} ")
            address += size
    lines += ["", ".data section layout", "  Starting        Virtual", "  address  Size   address",
              "  -----------------------",
              f"  00000000 000030 {DATA + 0x2000:08x}  1 .data \tgame.o ",
              f"  00000000 000010 {DATA + 0x2000:08x}  4 gPad \tgame.o ",
              f"  00000000 000008 {DATA + 0x2010:08x}  4 gTable \tgame.o ",
              f"  00000000 000004 {DATA + 0x2018:08x}  4 @12 \tgame.o ",
              f"  00000000 000004 {DATA + 0x2020:08x}  1 .data \tLib.a last.c ",
              "", ".sdata section layout", "  Starting        Virtual", "  address  Size   address",
              "  -----------------------",
              f"  00000000 000008 {SDATA + 0x500:08x}  1 .sdata \tgame.o ",
              f"  00000000 000004 {SDATA + 0x500:08x}  4 sCount \tgame.o ",
              f"  00000000 000004 {SDATA + 0x504:08x}  4 sMode \tgame.o ", ""]
    path = folder / "debug.MAP"
    path.write_text("\n".join(lines), encoding="utf-8")
    return program, path, image


class MapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.program, cls.path, cls.image = program_and_map(Path(cls.folder.name))
        cls.layout = mwmap.layout(cls.path)
        cls.aligned = mapalign.align(cls.program, cls.layout)
        cls.units = {u.unit: u for u in cls.aligned.units}
        cls.start = {f.address: f for f in cls.program.functions}

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_layout_takes_extents_from_symbols_and_kinds_from_the_tree(self):
        first = self.layout.pieces[".text"][0]
        self.assertEqual(first.size, sum(size for _, size in UNITS[0][1]))   # the section line counts stripped code
        game = next(p for p in self.layout.pieces[".data"] if p.unit == "game.o")
        self.assertEqual([(s.name, s.kind, s.scope) for s in game.symbols][1:],
                         [("gTable", "object", "global"), ("@12", "object", "local")])

    def test_objects_that_line_up_take_names_and_ranges(self):
        last = self.units["Lib/last.c"]
        self.assertEqual(last.how, "map")
        names = {self.start[a].address: n for a, (n, _, _) in self.aligned.functions.items()}
        self.assertIn("last_2", names.values())
        self.assertIn("first_6", names.values())
        self.assertNotIn("Lib/debug.c", self.units)                # only the other build links it

    def test_object_whose_code_differs_is_bounded_by_its_neighbours(self):
        drawn = self.units["Lib/drawn.cpp"]
        self.assertEqual(drawn.how, "bounds")
        functions = [f for f in self.program.functions if drawn.ranges[0][1] <= f.address < drawn.ranges[0][2]]
        self.assertEqual(len(functions), 7)
        named = {n for n, _, _ in self.aligned.functions.values()}
        self.assertNotIn("drawn_2", named)                          # its own code differs: no name
        self.assertIn("drawn_6", named)                             # a run of its own proves the rest

    def test_data_placed_by_references_with_the_maps_sizes(self):
        game = self.units["game.cpp"]                               # a C++ name makes a bare object C++
        self.assertEqual(game.how, "map")
        data = {s: (a, b) for s, a, b in game.ranges}
        self.assertEqual(data[".data"], (DATA + 0x40 - 0x10 + 0x10, DATA + 0x40 + 0x20))
        self.assertEqual(data[".sdata"], (SDATA + 8, SDATA + 0x10))
        placed = {o.name: o for objects in self.aligned.objects.values() for o in objects}
        self.assertEqual((placed["gTable"].address, placed["gTable"].size), (DATA + 0x50, 8))
        self.assertEqual((placed["@12"].scope, placed["sMode"].size), ("local", 4))

    def test_apply_replaces_what_the_analysis_found_inside_placed_pieces(self):
        adopted = mapalign.apply(self.program, self.aligned)
        names = {o.address: o for o in adopted.objects}
        self.assertEqual(names[DATA + 0x50].name, "gTable")
        self.assertNotIn("lbl_s8", {o.name for o in adopted.objects})
        self.assertEqual(names[DATA + 0x60].size, 0xA0)             # the rest of a found object past the piece

    def test_units_keep_the_maps_units_and_claim_the_rest(self):
        proposal = units.propose(mapalign.apply(self.program, self.aligned), mapalign.fixed(self.aligned))
        by_name = {u["unit"]: u for u in proposal["units"]}
        self.assertEqual(by_name["Lib/drawn.cpp"]["named_by"], "bounds")
        self.assertEqual(by_name["game.cpp"]["named_by"], "map")
        with tempfile.TemporaryDirectory() as folder:
            text = units.write_splits(proposal, Path(folder) / "splits.txt").read_text()
        self.assertIn(f".data        start:0x{DATA + 0x40:08X} end:0x{DATA + 0x60:08X}", text)


class LinkOrderTests(unittest.TestCase):
    def test_a_fixed_range_against_many_claims_gives_way(self):
        order = {"a": 0, "b": 1, "c": 2, "d": 3, "late": 9}
        claims = [(0x10, 0x14, "a", ".data"), (0x20, 0x24, "b", ".data"), (0x30, 0x34, "c", ".data"),
                  (0x40, 0x44, "d", ".data")]
        early = (0x08, 0x0C, "late", ".data")
        kept = units._in_link_order(sorted(claims + [early]), order, {early: units.FIXED})
        self.assertEqual(kept, claims if len(claims) > units.FIXED else [early])
        kept = units._in_link_order(sorted(claims[:2] + [(0x18, 0x1C, "late", ".data")]), order,
                                    {(0x18, 0x1C, "late", ".data"): units.FIXED})
        self.assertEqual(kept, [(0x10, 0x14, "a", ".data"), (0x18, 0x1C, "late", ".data")])


if __name__ == "__main__":
    unittest.main()


class SizeTests(unittest.TestCase):
    """Discovery's sizes: an object's own bytes, not the distance to the next label."""

    def size(self, raw: bytes, section: str, at: int = 0x1000, cases=None, widths=None, whole=(), reached=()):
        from zkit.discover import _own_size
        image = Image()
        image.put(at, raw)
        reached = sorted({at, *reached, *(widths or {}), *whole})
        return _own_size(image, at, len(raw), section, cases, widths or {}, set(whole), reached)

    def test_string_ends_at_its_nul_and_the_padding_is_the_gaps(self):
        self.assertEqual(self.size(b"Japanese\0\0\0\0\0\0\0\0", ".rodata", whole={0x1000}), 9)
        self.assertEqual(self.size(b"French\0\0", ".sdata2", whole={0x1000}), 7)

    def test_a_loaded_literal_is_not_a_string(self):
        self.assertEqual(self.size(b"?\0\0\0\0\0\0\0", ".sdata2", widths={0x1000: {4}}), 4)  # 0.5f, by its width

    def test_small_data_word_loaded_whole(self):
        self.assertEqual(self.size(b"\0\0\0\1\0\0\0\0", ".sdata", widths={0x1000: {4}}), 4)

    def test_nothing_shrinks_past_what_code_reaches_inside(self):
        self.assertEqual(self.size(bytes(0x1C), ".sbss", widths={0x1000: {4}}, reached={0x100C}), 0x1C)

    def test_jump_table_holds_its_cases(self):
        self.assertEqual(self.size(bytes(0x1C) + bytes(4), ".data", cases=7), 0x1C)


class SymbolsFileTests(unittest.TestCase):
    def test_update_keeps_attributes_it_does_not_model(self):
        image = Image()
        program = Program(Fake(), image, [Function(0x80004000, 0x10, "localize__10KartLocaleFv")],
                          [DataObject(0x80100000, 4, "msCountry__10KartLocale", ".sdata")])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "symbols.txt"
            path.write_text("fn_80004000 = .text:0x80004000; // type:function size:0x10 scope:global align:16\n"
                            "lbl_80100000 = .sdata:0x80100000; // type:object size:0x8 scope:global hidden\n"
                            "lbl_80100004 = .sdata:0x80100004; // type:object size:0x4 scope:global\n"
                            "_ctors = .ctors:0x80200000; // type:label scope:global\n", encoding="utf-8")
            mapalign.update_symbols(path, program, {0x80100004})
            lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines, [
            "localize__10KartLocaleFv = .text:0x80004000; // type:function size:0x10 scope:global align:16",
            "msCountry__10KartLocale = .sdata:0x80100000; // type:object size:0x4 scope:global hidden",
            "_ctors = .ctors:0x80200000; // type:label scope:global"])


class OwnershipTests(unittest.TestCase):
    def program(self) -> Program:
        image = Image()
        functions = [Function(0x80004000 + 0x100 * k, 0x100, f"fn_{k}") for k in range(4)]
        table, strings = 0x80100000, 0x80100100
        image.refs[functions[1].address] = [(0, table, "addr")]
        image.put(table, strings.to_bytes(4, "big") + (strings + 8).to_bytes(4, "big"))
        image.pointers = [(table, strings), (table + 4, strings + 8)]
        ctors, dtors = 0x80200000, 0x80200010
        image.put(ctors, (functions[3].address).to_bytes(4, "big"))     # the runtime's initializer leads .ctors
        image.put(dtors, b"".join(a.to_bytes(4, "big") for a in (functions[0].address, functions[3].address,
                                                                    functions[0].address)))
        objects = [DataObject(table, 8, "lbl_table", ".data"), DataObject(strings, 8, "lbl_one", ".data"),
                   DataObject(strings + 8, 8, "lbl_two", ".data"), DataObject(ctors, 4, "lbl_c", ".ctors"),
                   DataObject(dtors, 12, "lbl_d", ".dtors")]
        program = Program(Fake(), image, functions, objects)
        program.sections = [(".text", 0x80004000, 0x80004400), (".data", table, 0x80100200),
                            (".ctors", ctors, ctors + 0x10), (".dtors", dtors, dtors + 0x10)]
        return program

    def test_data_only_other_data_points_to_is_its_units(self):
        program = self.program()
        claims = [(0x80100000, 0x80100008, "table.c", ".data")]
        self.assertEqual(units._through_data(program, units.evidence(program), claims),
                         [(0x80100100, 0x80100108, "table.c", ".data"), (0x80100108, 0x80100110, "table.c", ".data")])

    def test_the_runtimes_dtors_entries_lead_with_its_reference_to_the_chain(self):
        program = self.program()
        owner = {0: "chain.c", 1: "table.c", 2: "other.c", 3: "runtime.cpp"}
        rows = units._initializer_tables(program, owner)
        self.assertEqual([r[2] for r in rows if r[3] == ".dtors"], ["runtime.cpp", "runtime.cpp", "chain.c"])


class LayoutTests(unittest.TestCase):
    def test_two_objects_of_one_name_stay_apart_and_one_objects_sections_join(self):
        rows = [("Lib.a main.c", 0x80004000, [("ddh_open", 0x20)]), ("Lib.a buffer.c", 0x80004020, [("read", 0x10)]),
                ("Lib.a main.c", 0x80004030, [("gdev_open", 0x20)]), ("Lib.a sound.cpp", 0x80004050, [("a", 8)]),
                ("Lib.a sound.cpp", 0x80004058, [("__sinit_sound_cpp", 8)])]
        lines = ["", ".text section layout", "  Starting        Virtual", "  address  Size   address",
                 "  -----------------------"]
        for unit, address, symbols in rows:
            lines.append(f"  00000000 {sum(s for _, s in symbols):06x} {address:08x}  1 .text \t{unit} ")
            for name, size in symbols:
                lines.append(f"  00000000 {size:06x} {address:08x}  4 {name} \t{unit} ")
                address += size
        lines += ["", ".data section layout", "  Starting        Virtual", "  address  Size   address",
                  "  -----------------------", "  00000000 000004 80100000  1 .data \tLib.a main.c ",
                  "  00000000 000004 80100000  4 gPort \tLib.a main.c ", ""]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "game.MAP"
            path.write_text("\n".join(lines), encoding="utf-8")
            layout = mwmap.layout(path)
        self.assertEqual([p.unit for p in layout.pieces[".text"]],
                         ["Lib/main.c", "Lib/buffer.c", "Lib/main.c#2", "Lib/sound.cpp"])
        self.assertEqual(layout.pieces[".text"][-1].size, 0x10)
        self.assertEqual(layout.pieces[".data"][0].unit, "Lib/main.c#?")     # whose it is, the map does not say
        self.assertEqual(mapalign.source_name("Lib/main.c#2", []), "Lib/main.c")
