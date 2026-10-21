import support  # noqa: F401  (isolates config, cache and state)
import contextlib
import io
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import cli, delink, ppc, signatures
from zkit.elf import Elf
from zkit.platform import GameCube, Switch
from zkit.program import Program

TEXT, DATA = 0x80003100, 0x80100000
BLR, PROLOGUE, EPILOGUE = 0x4E800020, [0x9421FFF0, 0x7C0802A6, 0x90010014], [0x80010014, 0x7C0803A6, 0x38210010]


def li(rd, value): return (14 << 26) | (rd << 21) | (value & 0xFFFF)
def add(rd, ra, rb): return (31 << 26) | (rd << 21) | (ra << 16) | (rb << 11) | (266 << 1)
def mullw(rd, ra, rb): return (31 << 26) | (rd << 21) | (ra << 16) | (rb << 11) | (235 << 1)
def stw(rs, offset, ra): return (36 << 26) | (rs << 21) | (ra << 16) | (offset & 0xFFFF)


# A function body: words, or ("bl", function), ("lis", register, symbol), ("addi", rd, ra, symbol), ("stw", rs, ra,
# symbol) whose fields the image builder fills in with the symbol's address.
HELPER = [("lis", 4, "gLib"), ("stw", 3, 4, "gLib"), BLR]
WORK = PROLOGUE + [li(3, 7), ("bl", "LibHelper"), add(3, 3, 3), mullw(4, 3, 3), add(5, 4, 3), mullw(6, 5, 4),
                   add(7, 6, 5), ("lis", 8, "gLib"), ("addi", 8, 8, "gLib"), stw(7, 0, 8), li(3, 0)] + EPILOGUE + [BLR]
SET = [stw(4, 8, 3), BLR]
PANIC = PROLOGUE + [("lis", 3, "msg"), ("addi", 3, 3, "msg"), ("bl", "LibHelper")] + EPILOGUE + [BLR]
PANIC_V2 = PROLOGUE + [li(4, 1), ("lis", 3, "msg"), ("addi", 3, 3, "msg"), ("bl", "LibHelper")] + EPILOGUE + [BLR]
STATIC_A = PROLOGUE + [li(3, 1)] + [add(3, 3, 3)] * 12 + EPILOGUE + [BLR]
STATIC_B = PROLOGUE + [li(3, 2)] + [mullw(3, 3, 3)] * 12 + EPILOGUE + [BLR]
GAME = PROLOGUE + [li(3, 9)] + [mullw(3, 3, 4), add(3, 3, 4)] * 8 + EPILOGUE + [BLR]
TEXTS = {"msg": b"LibPanic: failed!!\0\0"}


class Image:
    """A DOL assembled from (name, body, scope, unit) functions, a 4-byte global `gLib`, strings and tables of
    words or function addresses."""

    def __init__(self, functions, tables=None):
        self.functions = functions
        self.tables = tables or {}

    def build(self, root: Path, stem: str, hide: bool = False) -> tuple[Path, Path]:
        addresses, cursor = {}, TEXT
        for name, body, _, _ in self.functions:
            addresses.setdefault(name, cursor)
            cursor += 4 * len(body)
        addresses["gLib"], data = DATA, bytearray(8)
        for name, raw in TEXTS.items():
            addresses[name] = DATA + len(data)
            data += raw
        for name, words in self.tables.items():
            addresses[name] = DATA + len(data)
            data += b"".join(struct.pack(">I", addresses[w] if isinstance(w, str) else w) for w in words)
        text = bytearray()
        for name, body, _, _ in self.functions:
            for word in body:
                pc = TEXT + len(text)
                if isinstance(word, tuple):
                    kind, *rest = word
                    value = addresses[rest[-1]]
                    ha, lo = ((value + 0x8000) >> 16) & 0xFFFF, value & 0xFFFF
                    word = {"bl": lambda: (18 << 26) | ((value - pc) & 0x3FFFFFC) | 1,
                            "lis": lambda: (15 << 26) | (rest[0] << 21) | ha,
                            "addi": lambda: (14 << 26) | (rest[0] << 21) | (rest[1] << 16) | lo,
                            "stw": lambda: (36 << 26) | (rest[0] << 21) | (rest[1] << 16) | lo}[kind]()
                text += struct.pack(">I", word)
        header = bytearray(0x100)
        struct.pack_into(">I", header, 0x00, 0x100)
        struct.pack_into(">I", header, 0x1C, 0x100 + len(text))
        struct.pack_into(">I", header, 0x48, TEXT)
        struct.pack_into(">I", header, 0x64, DATA)
        struct.pack_into(">I", header, 0x90, len(text))
        struct.pack_into(">I", header, 0xAC, len(data))
        struct.pack_into(">I", header, 0xE0, TEXT)
        dol = root / f"{stem}.dol"
        dol.write_bytes(bytes(header) + bytes(text) + bytes(data))
        lines, splits, cursor = [], {}, TEXT
        for name, body, scope, unit in self.functions:
            shown = f"fn_{cursor:08X}" if hide else name
            lines.append(f"{shown} = .text:0x{cursor:08X}; // type:function size:0x{4 * len(body):X} scope:{scope}")
            splits.setdefault(unit, []).append((cursor, cursor + 4 * len(body)))
            cursor += 4 * len(body)
        lines.append(f"{'lbl_%08X' % DATA if hide else 'gLib'} = .data:0x{DATA:08X}; // type:object size:0x4")
        for name, raw in TEXTS.items():
            lines.append(f"lbl_{addresses[name]:08X} = .data:0x{addresses[name]:08X}; // type:object "
                         f"size:0x{len(raw):X} data:string")
        for name, words in self.tables.items():
            shown = f"lbl_{addresses[name]:08X}" if hide else name
            lines.append(f"{shown} = .data:0x{addresses[name]:08X}; // type:object size:0x{4 * len(words):X}")
        symbols = root / f"{stem}.symbols.txt"
        symbols.write_text("\n".join(lines) + "\n", encoding="utf-8")
        (root / f"{stem}.splits.txt").write_text("".join(
            f"{unit}:\n" + "".join(f"\t.text       start:0x{s:08X} end:0x{e:08X}\n" for s, e in rows)
            for unit, rows in splits.items()), encoding="utf-8")
        return dol, symbols


DONOR = [("LibHelper", HELPER, "global", "lib/helper.c"), ("LibWork", WORK, "global", "lib/work.c"),
         ("LibSet", SET, "global", "lib/work.c"), ("LibPanic", PANIC, "global", "lib/work.c"),
         ("Static", STATIC_A, "local", "lib/a.c"), ("Static", STATIC_B, "local", "lib/b.c")]
TARGET = [("GameCopy", SET, "global", "game.c"), ("GameBig", GAME, "global", "game.c"),
          ("LibHelper", HELPER, "global", "lib/helper.c"), ("LibWork", WORK, "global", "lib/work.c"),
          ("LibSet", SET, "global", "lib/work.c"), ("LibPanic", PANIC_V2, "global", "lib/work.c"),
          ("Static", STATIC_B, "local", "lib/b.c"), ("Static", STATIC_A, "local", "lib/a.c")]


class SignatureTests(unittest.TestCase):
    """A donor build names a target whose names are hidden: by shape, by what a matched function refers to, by
    layout, by the texts a changed function uses, and file-local names per file; a game function that merely
    looks like a library one stays unnamed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def donor(self) -> signatures.Donor:
        dol, symbols = Image(DONOR).build(self.root, "donor")
        return signatures.build("lib", dol, symbols, splits=self.root / "donor.splits.txt")

    def target(self, functions=TARGET, tables=None) -> tuple[Program, dict[str, list[int]]]:
        dol, symbols = Image(functions, tables).build(self.root, "target", hide=True)
        program = Program.from_symbols(GameCube(), dol, symbols)
        where: dict[str, list[int]] = {}
        cursor = TEXT
        for name, body, _, _ in functions:
            where.setdefault(name, []).append(cursor)
            cursor += 4 * len(body)
        return program, where

    def test_names_from_a_donor(self):
        program, at = self.target()
        found = {p.address: p for p in signatures.propose(program, [self.donor()])}
        named = {a: p.name for a, p in found.items()}
        self.assertEqual(named[at["LibWork"][0]], "LibWork")
        self.assertEqual(found[at["LibWork"][0]].evidence, "shape")
        self.assertEqual(named[at["LibHelper"][0]], "LibHelper")          # its caller's reference names it
        self.assertEqual(found[at["LibHelper"][0]].source, at["LibWork"][0])
        self.assertEqual(named[DATA], "gLib")
        self.assertEqual(found[DATA].kind, "object")
        self.assertEqual(named[at["LibSet"][0]], "LibSet")                # short: placed by its neighbour
        self.assertIn("layout", found[at["LibSet"][0]].evidence)
        self.assertEqual(named[at["LibPanic"][0]], "LibPanic")            # changed code, same texts
        self.assertEqual(found[at["LibPanic"][0]].evidence, "strings")
        self.assertEqual([named.get(a) for a in at["Static"]], ["Static", "Static"])   # one per file
        self.assertEqual({found[a].unit for a in at["Static"]}, {"lib/a.c", "lib/b.c"})
        self.assertNotIn(at["GameCopy"][0], named)                        # same code as LibSet, elsewhere
        self.assertNotIn(at["GameBig"][0], named)

    def test_a_named_table_names_its_slots(self):
        """A constructor matched by shape names the table it installs; the table names a short virtual method
        nothing else places (its neighbours differ in the target)."""
        ctor = [("lis", 4, "__vt__3Foo"), ("addi", 4, 4, "__vt__3Foo"), stw(4, 0, 3)] + [add(5, 5, 5)] * 14 + [BLR]
        method_a = PROLOGUE + [li(3, 3)] + [mullw(3, 3, 3)] * 11 + EPILOGUE + [BLR]
        method_b = [li(3, 5), BLR]
        donor_functions = [("__ct__3FooFv", ctor, "global", "foo.cpp"), ("a__3FooFv", method_a, "global", "foo.cpp"),
                           ("b__3FooFv", method_b, "global", "foo.cpp")]
        table = {"__vt__3Foo": [0, 0, "a__3FooFv", "b__3FooFv"]}
        dol, symbols = Image(donor_functions, table).build(self.root, "donor")
        donor = signatures.build("classes", dol, symbols)
        self.assertEqual(donor.tables["__vt__3Foo"], ["a__3FooFv", "b__3FooFv"])
        program, at = self.target([("b__3FooFv", method_b, "global", "foo.cpp"), ("Game", GAME, "global", "x.c"),
                                   ("__ct__3FooFv", ctor, "global", "foo.cpp"),
                                   ("a__3FooFv", method_a, "global", "foo.cpp")], table)
        found = {p.address: p for p in signatures.propose(program, [donor])}
        self.assertEqual(found[at["__ct__3FooFv"][0]].name, "__ct__3FooFv")
        table_address = next(a for a, p in found.items() if p.name == "__vt__3Foo")
        self.assertEqual(found[table_address].source, at["__ct__3FooFv"][0])
        self.assertEqual((found[at["b__3FooFv"][0]].name, found[at["b__3FooFv"][0]].evidence), ("b__3FooFv", "slot"))

    def test_two_copies_of_one_shape_stay_unnamed(self):
        program, at = self.target([("LibHelper", HELPER, "global", "a.c"), ("LibWork", WORK, "global", "a.c"),
                                   ("Other", GAME, "global", "a.c"), ("LibWork", WORK, "global", "b.c")])
        names = {p.name for p in signatures.propose(program, [self.donor()])}
        self.assertNotIn("LibWork", names)

    def test_contradicting_evidence_withdraws_the_name(self):
        """Two matched callers whose donors name their common callee differently: the callee is named by
        neither, nor afterwards by its own shape; the callers keep their names."""
        other = PROLOGUE + [li(3, 8), ("bl", "LibHelper")] + [add(3, 3, 3)] * 10 + EPILOGUE + [BLR]
        dol, symbols = Image(DONOR + [("LibOther", other, "global", "lib/other.c")]).build(self.root, "donor")
        donor = signatures.build("lib", dol, symbols, splits=self.root / "donor.splits.txt")
        for signature in donor.signatures:
            if signature.key == "LibOther":
                signature.references = tuple(signatures.Reference(r.offset, r.kind, ("n", "Renamed", 0))
                                             for r in signature.references)
        program, at = self.target(TARGET + [("LibOther", other, "global", "lib/other.c")])
        named = {p.address: p.name for p in signatures.propose(program, [donor])}
        self.assertNotIn(at["LibHelper"][0], named)
        self.assertEqual((named[at["LibWork"][0]], named[at["LibOther"][0]]), ("LibWork", "LibOther"))

    def test_a_linker_map_names_a_donor(self):
        """A CodeWarrior map of another build: functions, data and units; a name it lists twice is file-local."""
        dol, _ = Image(DONOR).build(self.root, "donor")
        lines, cursor, units = [".text section layout", "  Starting        Virtual", "  address  Size   address",
                                "  -----------------------"], TEXT, {}
        for name, body, _, unit in DONOR:
            units.setdefault(unit, []).append((cursor, 4 * len(body), name))
            cursor += 4 * len(body)
        for unit, rows in units.items():
            start = rows[0][0]
            lines.append(f"  {start - TEXT:08x} {sum(r[1] for r in rows):06x} {start:08x}  1 .text \t{unit}")
            lines += [f"  {a - TEXT:08x} {size:06x} {a:08x}  4 {name} \t{unit}" for a, size, name in rows]
        lines += [".data section layout", "  Starting        Virtual", "  address  Size   address",
                  "  -----------------------", f"  00000000 000004 {DATA:08x}  4 gLib \tlib/helper.c"]
        path = self.root / "donor.MAP"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        donor = signatures.build("map", dol, map_path=path)
        program, at = self.target()
        named = {p.address: p.name for p in signatures.propose(program, [donor])}
        self.assertEqual((named[at["LibWork"][0]], named[DATA]), ("LibWork", "gLib"))
        self.assertEqual([named.get(a) for a in at["Static"]], ["Static", "Static"])

    def test_small_data_bases_from_the_entry_point(self):
        """A fresh analysis names nothing `__init_registers`: the first call of the entry point that sets r2 and
        r13 gives them, and a small-data access then has the shape the donor's has."""
        def ori(ra, rs, value): return (24 << 26) | (rs << 21) | (ra << 16) | (value & 0xFFFF)
        registers = [(15 << 26) | (2 << 21) | 0x8010, ori(2, 2, 0x8000), (15 << 26) | (13 << 21) | 0x8010,
                     ori(13, 13, 0x8000), BLR]
        start = [("bl", "__init_registers")] + [BLR]
        read = [(32 << 26) | (3 << 21) | (13 << 16) | (0x10000 - 0x8000), BLR] + [add(3, 3, 3)] * 14 + [BLR]
        functions = [("__start", start, "global", "s.c"), ("__init_registers", registers, "global", "s.c"),
                     ("ReadGlobal", read, "global", "r.c")]
        dol, symbols = Image(functions).build(self.root, "donor")
        donor = signatures.build("sda", dol, symbols)
        self.assertEqual(next(s for s in donor.signatures if s.key == "ReadGlobal").references[0].token,
                         ("n", "gLib", 0))
        program, at = self.target(functions + [("Game", GAME, "global", "game.c")])
        self.assertEqual(program.sda, {2: 0x80108000, 13: 0x80108000})   # found without the name
        self.assertEqual(signatures.small_data(program), {2: 0x80108000, 13: 0x80108000})
        named = {p.address: p.name for p in signatures.propose(program, [donor])}
        self.assertEqual((named[at["ReadGlobal"][0]], named[DATA]), ("ReadGlobal", "gLib"))

    def test_analyze_takes_the_cached_names(self):
        from zkit import analyze
        signatures.save(self.donor())
        program, at = self.target()
        result = analyze.analyze(program)
        self.assertEqual(result["symbols"][at["LibWork"][0]], ("LibWork", "function", 0))
        self.assertEqual(result["symbols"][DATA], ("gLib", "object", 0))
        signatures.remove("lib")

    def test_cache_round_trip_and_own_image_left_out(self):
        donor = self.donor()
        signatures.save(donor)
        self.assertIn("lib", signatures.listed())
        loaded = signatures.load("lib")
        self.assertEqual([(s.key, s.shape, s.references, s.before, s.after) for s in loaded.signatures],
                         [(s.key, s.shape, s.references, s.before, s.after) for s in donor.signatures])
        program = Program.from_symbols(GameCube(), self.root / "donor.dol", self.root / "donor.symbols.txt")
        self.assertEqual(signatures.propose(program, [loaded]), [])        # the donor's own original
        self.assertTrue(signatures.remove("lib"))

    def test_objects_and_libraries_give_the_same_shape(self):
        """A relocatable object of LibWork (relocations to LibHelper and gLib, fields cleared) has the shape the
        linked function has, in a file or as an archive member."""
        image = self.donor()
        words = []
        relocations = []
        for index, word in enumerate(WORK):
            if isinstance(word, tuple):
                kind = {"bl": ppc.REL24, "lis": ppc.ADDR16_HA, "addi": ppc.ADDR16_LO}[word[0]]
                target = 1 if word[0] == "bl" else 2
                relocations.append((4 * index + (0 if kind == ppc.REL24 else 2), kind, target, 0))
                word = 0x48000001 if word[0] == "bl" else (15 << 26) | (word[1] << 21) if word[0] == "lis" \
                    else (14 << 26) | (word[1] << 21) | (word[2] << 16)
            words.append(word)
        path = self.root / "work.o"
        delink.write_object(delink.PPC, [(".text", 1, struct.pack(f">{len(words)}I", *words), 4)], [
            {"name": "LibWork", "section": ".text", "value": 0, "size": 4 * len(words), "kind": "func",
             "bind": "global", "address": 0},
            {"name": "LibHelper", "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
             "address": 0},
            {"name": "gLib", "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
             "address": 0}], {".text": [(o, k, s, a) for o, k, s, a in relocations]}, path)
        member = path.read_bytes()
        archive = self.root / "lib.a"
        archive.write_bytes(b"!<arch>\n" + f"{'work.o/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(member):<10}`\n"
                            .encode() + member + (b"\n" if len(member) % 2 else b""))
        linked = next(s for s in image.signatures if s.key == "LibWork")
        for source in (path, archive):
            donor = signatures.build("objects", objects=[source])
            compiled = next(s for s in donor.signatures if s.key == "LibWork")
            self.assertEqual(compiled.shape, linked.shape)
            self.assertEqual([r.token for r in compiled.references], [r.token for r in linked.references])

    def test_command_line_builds_lists_and_matches(self):
        dol, symbols = Image(DONOR).build(self.root, "donor")
        target_dol, target_symbols = Image(TARGET).build(self.root, "target", hide=True)
        manifest = self.root / "project.json"
        manifest.write_text(json.dumps({
            "schema_version": 1, "id": "signatures", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
            "targets": {"t": {"repository": "decomp", "module": "main", "original": target_dol.name,
                              "symbols": target_symbols.name}}}), encoding="utf-8")

        def run(*argv) -> str:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(list(argv)), 0)
            return out.getvalue()
        self.assertIn("6 function signatures", run("signatures", "build", "cli-lib", "--image", str(dol),
                                                   "--symbols", str(symbols)))
        self.assertIn("cli-lib", run("signatures", "list"))
        said = run("--project", str(manifest), "signatures", "match")
        self.assertIn("LibWork", said)
        self.assertIn("new", said)
        data = json.loads(run("--project", str(manifest), "--json", "names", "--signatures"))
        self.assertIn("LibWork", {row["name"] for row in data["rows"]})
        self.assertIn("removed", run("signatures", "remove", "cli-lib"))


SWITCH_DONOR = """int g_counter = 3;
struct Base { virtual ~Base(); virtual int get() const; virtual int put(int v); int value; };
struct Child : Base { int get() const override; int put(int v) override; };
__attribute__((noinline)) int callee(int x) { return x * 5 + g_counter; }
int inner(int x);
int caller(int *v, int n) { int t = 0; for (int i = 0; i < n; i++) t += callee(v[i]) * (i ^ 0x55) + v[i] * 7;
  return t * 3 + n; }
Base::~Base() {}
int Base::get() const { return value + g_counter; }
int Base::put(int v) { value = v * 3 + g_counter; return value; }
int Child::get() const { return value * 2 + g_counter * 9; }
int Child::put(int v) { value = inner(v) - 1; return value; }
Base *make(bool child) { return child ? new Child() : new Base(); }
int first(int *v, int n) { int t = 1; for (int i = 0; i < n; i++) t = t * 31 + (v[i] >> 2) - i; return t ^ 0x1234; }
int dropped1(int x) { return x * 11 + 1; }
int seven() { return 7; }
int tweak(int x) { return x * 13 + 2; }
int last(int *v, int n) { int t = 9; for (int i = 0; i < n; i++) t = t * 17 - (v[i] << 3) + i; return t ^ 0x4321; }
int twin() { return 7; }
__attribute__((noinline)) int inner(int x) { return x * 21 + 4; }
__attribute__((noinline, visibility("default"))) inline int shared(int x) { return x * 41 + 9; }
int user(int x) { return shared(x) + 1; }
__attribute__((noinline, visibility("default"))) inline int &tally() { static int s_tally = 5; return s_tally; }
int bump(int x) { return tally() += x * 3; }
"""
# 3.0 of the same file: four functions changed, one added, one the linker no longer keeps
SWITCH_TARGET = SWITCH_DONOR
for old, new in (("x * 5 + g_counter", "x * 6 - g_counter"), ("x * 21 + 4", "x * 22 - 5"), ("x * 13 + 2", "x * 14 - 3"),
                 ("value = inner(v) - 1; return value; }",
                  "value = inner(v) + 1; return value; }\nint added(int x) { return x * 77 - 1; }"),
                 ("int dropped1(int x) { return x * 11 + 1; }\n", "")):
    SWITCH_TARGET = SWITCH_TARGET.replace(old, new)


# two functions an update changed, one between them it dropped and one it added
GAP_DONOR = """int first(int *v, int n) { int t = 1; for (int i = 0; i < n; i++) t = t * 31 + (v[i] >> 2) - i;
  for (int i = n - 1; i >= 0; i--) t ^= v[i] * (i + 3); return t ^ 0x1234; }
int mixing(int *v, int n) { int t = 5, u = 9; for (int i = 0; i < n; i++) { t = t * 37 + (v[i] ^ 0x15) - (i << 2);
  u += t >> 3; } for (int i = 0; i < n; i += 2) u ^= v[i] * 11; return t + u * 7 + n; }
int dropped(int *v, int n) { return v[n] * 3; }
int shuffle(int *v, int n) { for (int i = 1; i < n; i++) { int j = (v[i] * 7 + i) % n; int x = v[i]; v[i] = v[j];
  v[j] = x + 5; } int s = 0; for (int i = 0; i < n; i++) s = s * 13 + v[i]; return s; }
int last(int *v, int n) { int t = 9; for (int i = 0; i < n; i++) t = t * 17 - (v[i] << 3) + i;
  for (int i = 0; i < n; i++) t += v[i] * v[i]; return t ^ 0x4321; }
"""
GAP_TARGET = GAP_DONOR
for old, new in (("t * 37 + (v[i] ^ 0x15)", "t * 41 + (v[i] ^ 0x25)"), ("* 7 + i) % n", "* 9 + i) % n"),
                 ("int dropped(int *v, int n) { return v[n] * 3; }\n", ""),
                 ("int last(", "int added(int *v, int n) { return v[0] - n; }\nint last(")):
    GAP_TARGET = GAP_TARGET.replace(old, new)

# a class one update gave a virtual (@ADDED@) and took one from (@REMOVED@)
SHAPE_CLASS = """int g_scale = 3;
struct Shape { virtual ~Shape(); virtual int area() const; @ADDED@ virtual int edges() const; virtual int scale(int f);
  @REMOVED@ int w, h, d; };
Shape::~Shape() {}
int Shape::area() const { return w * h + g_scale * (w - h) + (w ^ 0x77) * (h | 9) - d * 5; }
int Shape::edges() const { int t = 0; for (int i = 0; i < w; i++) t += (h + i) * 2 - g_scale; return t ^ d; }
int Shape::scale(int f) { w = w * f + 1; h = h * f - 1; d = d * f + g_scale; return (w ^ h) + d * 3; }
int extra(Shape *s) { return s->d * 13 + s->w * 7 - s->h; }
Shape *build(int w, int h) { Shape *s = new Shape(); s->w = w; s->h = h; s->d = w * h + g_scale; return s; }
@BODY@"""
SHAPE_DEPTH = "virtual int depth() const;"
SHAPE_COLOR = "virtual int color() const;"
SHAPE_BODIES = {SHAPE_DEPTH: "int Shape::depth() const { return d * d - w * 11 + (h >> 2); }\n",
                SHAPE_COLOR: "int Shape::color() const { return (w << 4) + h * 19 - d; }\n"}


def shape_class(added: str, removed: str) -> str:
    return SHAPE_CLASS.replace("@ADDED@", added).replace("@REMOVED@", removed).replace(
        "@BODY@", SHAPE_BODIES.get(added, "") + SHAPE_BODIES.get(removed, ""))


@unittest.skipUnless(shutil.which("clang++") and shutil.which("ld.lld"), "needs clang++ and ld.lld")
class SwitchSignatureTests(unittest.TestCase):
    """A later build of a Switch module, its names stripped, named from an earlier one with symbols: by shape,
    by a changed callee's caller, by a changed virtual's slot in the table a matched constructor installs, by
    the place between two matched functions of a short one whose neighbours the linker dropped and of a changed
    one, and its data."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def module(self, stem: str, source: str, hide: bool) -> tuple[Path, Path, dict[str, int]]:
        """A linked module and a symbols.txt of it (placeholders where `hide`); the address of every name."""
        import subprocess
        (self.root / f"{stem}.cpp").write_text(source, encoding="utf-8")
        subprocess.run(["clang++", "--target=aarch64-none-elf", "-fPIC", "-fvisibility=hidden", "-O2",
                        "-fno-exceptions", "-fno-rtti", "-ffreestanding", "-c", str(self.root / f"{stem}.cpp"),
                        "-o", str(self.root / f"{stem}.o")], check=True, capture_output=True)
        elf = self.root / f"{stem}.elf"
        subprocess.run(["ld.lld", "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o", str(elf),
                        str(self.root / f"{stem}.o")], check=True, capture_output=True)
        linked = Elf.load(elf)
        lines, where = [], {}
        for symbol in linked.symbols:
            if symbol.kind not in ("func", "object") or not 0 < symbol.section < 0xFF00 or not symbol.size:
                continue
            section = linked.sections[symbol.section].name
            kind = "function" if symbol.kind == "func" else "object"
            where[symbol.name] = symbol.value
            name = (f"fn_{symbol.value:08X}" if kind == "function" else f"lbl_{symbol.value:08X}") if hide \
                else symbol.name
            lines.append(f"{name} = {section}:0x{symbol.value:08X}; // type:{kind} size:0x{symbol.size:X} "
                         f"scope:global")
        symbols = self.root / f"{stem}.symbols.txt"
        symbols.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return elf, symbols, where

    def test_names_from_an_earlier_build(self):
        elf, symbols, _ = self.module("donor", SWITCH_DONOR, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        self.assertIn("_ZTV5Child", donor.tables)
        self.assertEqual(len(donor.layout), len([s for s in donor.signatures]))
        elf, symbols, at = self.module("target", SWITCH_TARGET, hide=True)
        program = Program.from_symbols(Switch(), elf, symbols)
        found = {p.address: p for p in signatures.propose(program, [donor])}
        evidence = lambda name: (found[at[name]].name, found[at[name]].evidence) if at[name] in found else None
        self.assertEqual(evidence("_Z6callerPii"), ("_Z6callerPii", "shape"))
        self.assertEqual(evidence("_Z6calleei"), ("_Z6calleei", "reference"))         # its code changed
        self.assertEqual(evidence("_ZTV5Child")[0], "_ZTV5Child")                      # make() installs it
        self.assertEqual(found[at["_ZTV5Child"]].kind, "object")
        self.assertEqual(evidence("_ZN5Child3putEi"), ("_ZN5Child3putEi", "slot"))     # changed, never called
        self.assertEqual(evidence("g_counter")[0], "g_counter")
        self.assertEqual(found[at["_Z5sevenv"]].name, "_Z5sevenv")                     # between first and last
        self.assertIn("layout", found[at["_Z5sevenv"]].evidence)
        self.assertEqual(evidence("_Z5tweaki"), ("_Z5tweaki", "layout"))   # changed, alone between two placed
        self.assertEqual(evidence("_Z5inneri"), ("_Z5inneri", "call"))     # changed, the one a changed one calls
        self.assertNotIn("_Z8dropped1i", {p.name for p in found.values()})
        self.assertNotIn(at["_Z5addedi"], found)                                   # new code: no name to take

    def test_a_table_whose_slots_moved(self):
        """A later build adds a virtual and removes another, so the class table keeps its length but every slot
        after the new one moved: slots pair by their code, never by index, and the new virtual takes no name."""
        elf, symbols, _ = self.module("donor", shape_class("", SHAPE_DEPTH), hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", shape_class(SHAPE_COLOR, ""), hide=True)
        program = Program.from_symbols(Switch(), elf, symbols)
        found = {p.address: p.name for p in signatures.propose(program, [donor])}
        self.assertEqual(found.get(at["_ZTV5Shape"]), "_ZTV5Shape")
        for name in ("_ZNK5Shape4areaEv", "_ZNK5Shape5edgesEv", "_ZN5Shape5scaleEi"):
            self.assertEqual(found.get(at[name]), name)
        self.assertNotIn(at["_ZNK5Shape5colorEv"], found)
        self.assertNotIn("_ZNK5Shape5depthEv", found.values())

    def test_changed_code_pairs_by_likeness(self):
        """Between two matched functions, the donor has two functions an update changed with one it dropped
        between them, the target the two changed ones and one it added: each changed one takes the donor function
        it is most like, and the added one stays unnamed."""
        elf, symbols, _ = self.module("donor", GAP_DONOR, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", GAP_TARGET, hide=True)
        program = Program.from_symbols(Switch(), elf, symbols)
        found = {p.address: (p.name, p.evidence) for p in signatures.propose(program, [donor])}
        self.assertEqual(found.get(at["_Z5firstPii"]), ("_Z5firstPii", "shape"))
        self.assertEqual(found.get(at["_Z6mixingPii"]), ("_Z6mixingPii", "layout+code"))
        self.assertEqual(found.get(at["_Z7shufflePii"]), ("_Z7shufflePii", "layout+code"))
        self.assertNotIn(at["_Z5addedPii"], found)
        self.assertNotIn("_Z7droppedPii", {name for name, _ in found.values()})

    def test_a_source_path_from_another_drive(self):
        """An update built on another machine cites its source files from another drive: the code that cites
        them is still the same code."""
        source = ("void report(const char *file, int line);\n"
                  "int check(int *v, int n) { int t = 0; for (int i = 0; i < n; i++) { t = t * 7 + v[i];\n"
                  "  if (t < 0) report(\"@:/proj/src/check.cpp\", 12); } return t ^ n; }\n")
        elf, symbols, _ = self.module("donor", source.replace("@", "C"), hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", source.replace("@", "D"), hide=True)
        found = {p.address: (p.name, p.evidence)
                 for p in signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
        self.assertEqual(found.get(at["_Z5checkPii"]), ("_Z5checkPii", "shape+references"))
        self.assertEqual(signatures.evidence_text("C:\\proj\\a.cpp"), "\\proj\\a.cpp")

    def test_a_function_citing_another_file_is_not_the_donors(self):
        """An update replaced a function with another file's code at its place between two matched ones: it reads
        like the donor's, but its `__FILE__` is another file, so it takes no name. Cited from another drive, the
        same file is the same function."""
        def gap(path: str, factor: int) -> str:
            return GAP_DONOR.replace("int mixing(int *v, int n) { int t = 5, u = 9;",
                                     "void report(const char *file, int line);\n"
                                     f"int mixing(int *v, int n) {{ if (n < 0) report(\"{path}\", 3); int t = 5, u = 9;"
                                     ).replace("t * 37 + (v[i] ^ 0x15)", f"t * {factor} + (v[i] ^ 0x15)")
        elf, symbols, _ = self.module("donor", gap("C:/proj/src/mixing.cpp", 37), hide=False)
        donor = signatures.build("earlier", elf, symbols)
        for path, named in (("D:/proj/src/timer.cpp", False), ("D:/proj/src/mixing.cpp", True)):
            elf, symbols, at = self.module("target", gap(path, 41), hide=True)
            found = {p.address: p.name for p in
                     signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
            self.assertEqual(found.get(at["_Z6mixingPii"]) == "_Z6mixingPii", named, path)
            self.assertEqual(found.get(at["_Z5firstPii"]), "_Z5firstPii")

    def test_a_function_whose_parameters_an_update_changed(self):
        """An update gave `mixing` a float parameter its code reads: between two matched neighbours it still reads
        like the donor's `mixing(int*, int)`, but that name cannot fill s0, so it takes no name. The same change
        without the new parameter keeps the name."""
        elf, symbols, _ = self.module("donor", GAP_DONOR, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        for source, named in (
                (GAP_DONOR.replace("int mixing(int *v, int n) { int t = 5, u = 9;",
                                   "int mixing(int *v, int n, float w) { int t = 5, u = (int)(w * 9.0f);"), False),
                (GAP_DONOR.replace("t * 37 + (v[i] ^ 0x15)", "t * 41 + (v[i] ^ 0x15)"), True)):
            elf, symbols, at = self.module("target", source, hide=True)
            found = {p.address: p.name for p in
                     signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
            mixing = next(a for n, a in at.items() if n.startswith("_Z6mixingPi"))
            self.assertEqual(found.get(mixing) == "_Z6mixingPii", named, found.get(mixing))
            self.assertEqual(found.get(at["_Z5firstPii"]), "_Z5firstPii")

    def test_a_class_table_whose_slots_cite_another_file(self):
        """An update put a new class where the donor had another: `make` builds it with the same code, and its
        one-call `fin` reads like the donor class's, so both would name its table the donor class's; but its
        `init` cites another file than the donor class's `init`, so the table and `fin` take no name."""
        def source(cls: str, path: str, init: str) -> str:
            return (GAP_DONOR.replace("int mixing(", "int mixing_unused(")
                    .replace("int last(", "void report(const char *file, int line);\n"
                             "struct Obj { virtual ~Obj(); virtual void init(); virtual void fin(); int v; };\n"
                             f"struct {cls} : Obj {{ void init() override; void fin() override; }};\n"
                             "Obj::~Obj() {}\nvoid Obj::init() { v = 1; }\nvoid Obj::fin() { v = 0; }\n"
                             f"void {cls}::init() {{ {init} if (v < 0) report(\"{path}\", 9); }}\n"
                             f"void {cls}::fin() {{ Obj::fin(); }}\n"
                             f"Obj *make() {{ return new {cls}(); }}\nint last("))
        elf, symbols, _ = self.module("donor", source("Box", "C:/proj/src/box.cpp", "v = v * 3 + 1;"), hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", source("Timer", "D:/proj/src/timer.cpp",
                                                        "for (int i = 0; i < 9; i++) v = v * 5 + i;"), hide=True)
        found = {p.address: p.name for p in signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
        self.assertEqual(found.get(at["_Z4makev"]), "_Z4makev")       # the same code, building another class
        self.assertEqual(found.get(at["_ZN3Obj4initEv"]), "_ZN3Obj4initEv")
        self.assertNotIn("_ZTV3Box", found.values())
        self.assertNotIn(at["_ZN5Timer3finEv"], found)

    def test_a_wrapper_among_other_code_takes_no_name(self):
        """An update replaced the code between two matched functions: a one-call wrapper there calls what a donor
        wrapper called, but the code around it is not the code around the donor's (more copies on one side, or
        copies whose order another one's call refutes), so it takes no name; where its neighbour is, it does."""
        callees = "".join(f"__attribute__((noinline)) int {f}(int *v, int n) {{ int t = {k}; for (int i = 0; i < n; i++)"
                          f" t = t * {k + 30} + (v[i] ^ {k * 7}) - i * {k}; return t ^ {k * 1000 + 17}; }}\n"
                          for k, f in enumerate(("fa", "fb", "fc", "gx", "gy"), 1))
        long = lambda name, k: (f"int {name}(int *v, int n) {{ int s = {k}; for (int i = 1; i < n; i++) {{ s ^= v[i] "
                                f"* {k * 3 + 1} + (v[i - 1] >> {k % 5 + 1}); if (s & {k}) s += n * {k}; }} return s - {k}; }}\n")
        wrap = lambda name, callee: f"int {name}(int *v, int n) {{ return {callee}(v, n); }}\n"
        frame = lambda middle: GAP_DONOR.split("int mixing(")[0] + callees + middle + "int last(" + \
            GAP_DONOR.split("int last(")[1]
        cases = [  # (donor middle, target middle, target wrapper, its name or None)
            (wrap("w", "fa") + long("mid", 3), long("added", 8) + wrap("x", "fa") + wrap("y", "gy"), "x", None),
            (wrap("w", "fa") + long("mid", 3), wrap("x", "fa") + long("mid", 3) + wrap("y", "gy"), "x", "w"),
            (wrap("w1", "fa") + long("big1", 4) + wrap("w2", "fb") + long("big2", 5) + wrap("w3", "fc"),
             wrap("x1", "gx") + wrap("x2", "gy") + wrap("x3", "fc") + long("added", 9), "x3", None)]
        for donor_middle, target_middle, wrapper, expected in cases:
            elf, symbols, _ = self.module("donor", frame(donor_middle), hide=False)
            donor = signatures.build("earlier", elf, symbols)
            elf, symbols, at = self.module("target", frame(target_middle), hide=True)
            found = {p.address: p.name for p in
                     signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
            self.assertEqual(found.get(at["_Z5firstPii"]), "_Z5firstPii")
            self.assertEqual(found.get(at[f"_Z{len(wrapper)}{wrapper}Pii"]),
                             expected and f"_Z{len(expected)}{expected}Pii", (target_middle, found))

    def test_code_that_reads_like_its_twin(self):
        """A field added before two others moves both: the update's `sumA` reads the offset the first build's
        `sumB` read, so its code is exactly that `sumB`'s. Code that differs from a sibling in one immediate is
        named by its shape only with its neighbours agreeing; here its place names both."""
        source = ("int g_k = 3;\nstruct S { int pad; @ int a, b, c; };\n"
                  "int first(int *v, int n) { int t = 1; for (int i = 0; i < n; i++) t = t * 31 + (v[i] >> 2) - i;\n"
                  "  for (int i = n - 1; i >= 0; i--) t ^= v[i] * (i + 3); return t ^ 0x1234; }\n"
                  "int sumA(S *s, int n) { int t = 0; for (int i = 0; i < n; i++) t = (t + s->a * (i + g_k)) ^ (t >> 3);\n"
                  "  for (int i = 0; i < n; i += 3) t += (s->a << 2) - i * g_k; return t * 7; }\n"
                  "int sumB(S *s, int n) { int t = 0; for (int i = 0; i < n; i++) t = (t + s->b * (i + g_k)) ^ (t >> 3);\n"
                  "  for (int i = 0; i < n; i += 3) t += (s->b << 2) - i * g_k; return t * 7; }\n"
                  "int last(int *v, int n) { int t = 9; for (int i = 0; i < n; i++) t = t * 17 - (v[i] << 3) + i;\n"
                  "  for (int i = 0; i < n; i++) t += v[i] * v[i]; return t ^ 0x4321; }\n")
        elf, symbols, _ = self.module("donor", source.replace("@", ""), hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", source.replace("@", "int added;"), hide=True)
        found = {p.address: (p.name, p.evidence)
                 for p in signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
        self.assertEqual(found.get(at["_Z4sumAP1Si"]), ("_Z4sumAP1Si", "layout"))
        self.assertEqual(found.get(at["_Z4sumBP1Si"]), ("_Z4sumBP1Si", "layout"))

    def test_calls_pair_in_order(self):
        """An update changed a function and three it calls, and added a fourth call: nothing else places the
        callees (four changed or new functions against three in one gap, too short to compare), so its calls name
        them, in order between the calls both builds name. The new call and the one after it pair with nothing
        (one side has two calls there, the other one); once its neighbours are named, its place names the last."""
        bodies = ("{ int t = 1; for (int i = 0; i < n; i++) t = t * 31 + (v[i] >> 2) - i;\n"
                  "  for (int i = n - 1; i >= 0; i--) t ^= v[i] * (i + 3); return t ^ 0x1234; }\n",
                  "{ int t = 9; for (int i = 0; i < n; i++) t = t * 17 - (v[i] << 3) + i;\n"
                  "  for (int i = 0; i < n; i++) t += v[i] * v[i]; return t ^ 0x4321; }\n",
                  "{ int t = 5, u = 9; for (int i = 0; i < n; i++) { t = t * 37 + (v[i] ^ 0x15) - (i << 2);\n"
                  "  u += t >> 3; } for (int i = 0; i < n; i += 2) u ^= v[i] * 11; return t + u * 7 + n; }\n",
                  "{ for (int i = 1; i < n; i++) { int j = (v[i] * 7 + i) % n; int x = v[i]; v[i] = v[j];\n"
                  "  v[j] = x + 5; } int s = 0; for (int i = 0; i < n; i++) s = s * 13 + v[i]; return s; }\n")
        # clang lays functions out as it first meets them: anchor, mid, first, driver, then driver's callees
        source = ("#define NI __attribute__((noinline))\n"
                  "NI int anchor(int *v, int n) " + bodies[2] + "NI int mid(int *v, int n) " + bodies[3] +
                  "int first(int *v, int n) " + bodies[0] +
                  "NI int alpha(int x); NI int beta(int x); NI int gamma_(int x); NI int extra(int x);\n"
                  "int driver(int *v, int n) { int t = anchor(v, n); t += alpha(t); t ^= beta(t); t += mid(v, t);\n"
                  "  @EXTRA@ t -= gamma_(t); return t * 9; }\n"
                  "int last(int *v, int n) " + bodies[1] +
                  "NI int alpha(int x) { return @A@; }\nNI int beta(int x) { return @B@; }\n"
                  "@NEW@NI int gamma_(int x) { return @C@; }\n@OLD@")
        alpha, beta, gamma = ("((x * 3 + 1) ^ (x >> 7)) - (x & 0x3C) * (x | 5)",
                              "((x ^ (x >> 5)) * 7 - (x >> 9)) | ((x << 3) + 11)",
                              "(((x << 4) - x / 3) & (x >> 2)) + x % 13")
        earlier = (source.replace("@EXTRA@", "").replace("@A@", alpha).replace("@B@", beta).replace("@C@", gamma)
                   .replace("@NEW@", "").replace("@OLD@", "NI int dropped(int x) { return x % 7 + (x & 12); }\n"))
        later = (source.replace("@EXTRA@", "t += extra(t);").replace("@A@", alpha + " + 9")
                 .replace("@B@", beta + " - 4").replace("@C@", gamma + " - 2")
                 .replace("@NEW@", "NI int extra(int x) { return x / 9 - (x << 1); }\n").replace("@OLD@", ""))
        elf, symbols, _ = self.module("donor", earlier, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", later, hide=True)
        found = {p.address: (p.name, p.evidence)
                 for p in signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
        self.assertEqual(found.get(at["_Z6driverPii"]), ("_Z6driverPii", "layout+code"))
        self.assertEqual(found.get(at["_Z5alphai"]), ("_Z5alphai", "call"))
        self.assertEqual(found.get(at["_Z4betai"]), ("_Z4betai", "call"))
        self.assertNotIn(at["_Z5extrai"], found)
        self.assertEqual(found.get(at["_Z6gamma_i"]), ("_Z6gamma_i", "layout+code"))

    def test_data_pairs_in_order(self):
        """An update changed the only function that uses three globals and added a fourth use: its data
        references, in order against its donor's between the ones both name (a text here), name the globals before
        the text; after it, the new global's use leaves the counts unequal and both stay unnamed."""
        bodies = ("{ int t = 1; for (int i = 0; i < n; i++) t = t * 31 + (v[i] >> 2) - i;\n"
                  "  for (int i = n - 1; i >= 0; i--) t ^= v[i] * (i + 3); return t ^ 0x1234; }\n",
                  "{ int t = 9; for (int i = 0; i < n; i++) t = t * 17 - (v[i] << 3) + i;\n"
                  "  for (int i = 0; i < n; i++) t += v[i] * v[i]; return t ^ 0x4321; }\n")
        source = ("int g_alpha = 3; int g_beta = 5; @NEW@int g_gamma = 7; void report(const char *text);\n"
                  "int first(int *v, int n) " + bodies[0] +
                  "int mix(int x) { int t = g_alpha * x; t ^= g_beta + (x >> 3); report(\"mixing values\");\n"
                  "  @USE@ t -= g_gamma * 11; return t @OP@ 9; }\n"
                  "int last(int *v, int n) " + bodies[1])
        earlier = source.replace("@NEW@", "").replace("@USE@", "").replace("@OP@", "*")
        later = source.replace("@NEW@", "int g_added = 2; ").replace("@USE@", " t += g_added;").replace("@OP@", "+")
        elf, symbols, _ = self.module("donor", earlier, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        elf, symbols, at = self.module("target", later, hide=True)
        found = {p.address: (p.name, p.evidence)
                 for p in signatures.propose(Program.from_symbols(Switch(), elf, symbols), [donor])}
        self.assertEqual(found.get(at["_Z3mixi"]), ("_Z3mixi", "layout"))
        self.assertEqual(found.get(at["g_alpha"]), ("g_alpha", "order"))
        self.assertEqual(found.get(at["g_beta"]), ("g_beta", "order"))
        self.assertNotIn(at["g_added"], found)
        self.assertNotIn(at["g_gamma"], found)

    def test_aligned_slots(self):
        same = signatures.aligned(list("abcdef"), list("abcdef"))
        self.assertEqual(same, [(i, i) for i in range(6)])
        self.assertEqual(signatures.aligned(list("abXdef"), list("abcdef")), [(i, i) for i in range(6)])  # changed
        self.assertEqual(signatures.aligned(list("abNcde"), list("abcdeR")),        # one added, one removed
                         [(0, 0), (1, 1), (3, 2), (4, 3), (5, 4)])
        self.assertEqual(signatures.aligned(list("aXYd"), list("abcd")), [(0, 0), (3, 3)])  # two side by side
        self.assertEqual(signatures.aligned(["s", "s", "a"], ["s", "s", "s", "a"]), [(2, 3)])  # repeats can slide

    def test_analyze_names_the_module_and_adds_its_data(self):
        """With the donor cached, a fresh analysis of the stripped build renames its functions and adds the data
        the donor names that its symbols lack, each with the donor's size."""
        from zkit import analyze
        elf, symbols, _ = self.module("donor", SWITCH_DONOR, hide=False)
        signatures.save(signatures.build("earlier", elf, symbols))
        elf, symbols, at = self.module("target", SWITCH_TARGET, hide=True)
        symbols.write_text("".join(line + "\n" for line in symbols.read_text().splitlines() if "type:function" in line))
        program = Program.from_symbols(Switch(), elf, symbols)
        written = analyze.write(program, analyze.analyze(program), symbols, self.root / "analysis")
        text = (self.root / "analysis" / "symbols.txt").read_text()
        signatures.remove("earlier")
        self.assertGreater(written["signature_names"], 10)
        self.assertRegex(text, rf"(?m)^_Z6callerPii = \.text:0x{at['_Z6callerPii']:08X}; // type:function ")
        self.assertRegex(text, rf"(?m)^_ZTV5Child = \.\w+:0x{at['_ZTV5Child']:08X}; // type:object size:0x30 ")
        self.assertRegex(text, rf"(?m)^g_counter = \.data:0x{at['g_counter']:08X}; // type:object size:0x4 ")
        self.assertRegex(text, rf"(?m)^_Z6sharedi = \.text:0x{at['_Z6sharedi']:08X}; // .* scope:weak")  # inline
        self.assertRegex(text, rf"(?m)^_Z4useri = \.text:0x{at['_Z4useri']:08X}; // .* scope:global")
        self.assertRegex(text, rf"(?m)^_ZZ5tallyvE7s_tally = \.\w+:0x{at['_ZZ5tallyvE7s_tally']:08X}; // .* scope:weak")
        addresses = [int(line.split(":0x")[1][:8], 16) for line in text.splitlines()]
        self.assertEqual(addresses, sorted(addresses))
        splits = (self.root / "analysis" / "splits.txt").read_text()
        last = max(at['g_counter'], at['_ZZ5tallyvE7s_tally'])                      # and the inline's static
        self.assertRegex(splits, rf"\.data +start:0x[0-9A-F]+ end:0x{last + 4:08X}\n")  # its unit's

    def test_a_weak_function_has_no_unit(self):
        """An inline function is the copy the linker kept from whichever unit came first, so the donor's unit
        is not evidence for it; its neighbours keep theirs."""
        elf, symbols, at = self.module("donor", SWITCH_DONOR, hide=False)
        splits = self.root / "donor.splits.txt"
        splits.write_text(f"lib.cpp:\n\t.text start:0x{min(at.values()):08X} end:0x{max(at.values()) + 0x100:08X}\n")
        donor = signatures.build("earlier", elf, symbols, splits=splits)
        units = {s.key: s.unit for s in donor.signatures}
        self.assertEqual((units["_Z6sharedi"], units["_Z4useri"]), ("", "lib.cpp"))
        weak = {s.key: s.weak for s in donor.signatures}
        self.assertEqual((weak["_Z6sharedi"], weak["_Z4useri"]), (True, False))   # and a name keeps its binding

    def test_cache_keeps_the_layout(self):
        elf, symbols, _ = self.module("donor", SWITCH_DONOR, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        signatures.save(donor)
        loaded = signatures.load("earlier")
        self.assertEqual(loaded.layout, donor.layout)
        self.assertEqual([s.place for s in loaded.signatures], [s.place for s in donor.signatures])
        self.assertEqual([s.weak for s in loaded.signatures], [s.weak for s in donor.signatures])
        self.assertTrue(any(s.weak for s in loaded.signatures))
        self.assertTrue(signatures.remove("earlier"))


if __name__ == "__main__":
    unittest.main()
