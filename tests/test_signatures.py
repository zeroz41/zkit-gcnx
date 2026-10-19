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
"""
# 3.0 of the same file: four functions changed, one added, one the linker no longer keeps
SWITCH_TARGET = SWITCH_DONOR
for old, new in (("x * 5 + g_counter", "x * 6 - g_counter"), ("x * 21 + 4", "x * 22 - 5"), ("x * 13 + 2", "x * 14 - 3"),
                 ("value = inner(v) - 1; return value; }",
                  "value = inner(v) + 1; return value; }\nint added(int x) { return x * 77 - 1; }"),
                 ("int dropped1(int x) { return x * 11 + 1; }\n", "")):
    SWITCH_TARGET = SWITCH_TARGET.replace(old, new)


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
        addresses = [int(line.split(":0x")[1][:8], 16) for line in text.splitlines()]
        self.assertEqual(addresses, sorted(addresses))
        splits = (self.root / "analysis" / "splits.txt").read_text()
        self.assertRegex(splits, rf"\.data +start:0x[0-9A-F]+ end:0x{at['g_counter'] + 4:08X}\n")  # its unit's

    def test_a_weak_function_has_no_unit(self):
        """An inline function is the copy the linker kept from whichever unit came first, so the donor's unit
        is not evidence for it; its neighbours keep theirs."""
        elf, symbols, at = self.module("donor", SWITCH_DONOR, hide=False)
        splits = self.root / "donor.splits.txt"
        splits.write_text(f"lib.cpp:\n\t.text start:0x{min(at.values()):08X} end:0x{max(at.values()) + 0x100:08X}\n")
        donor = signatures.build("earlier", elf, symbols, splits=splits)
        units = {s.key: s.unit for s in donor.signatures}
        self.assertEqual((units["_Z6sharedi"], units["_Z4useri"]), ("", "lib.cpp"))

    def test_cache_keeps_the_layout(self):
        elf, symbols, _ = self.module("donor", SWITCH_DONOR, hide=False)
        donor = signatures.build("earlier", elf, symbols)
        signatures.save(donor)
        loaded = signatures.load("earlier")
        self.assertEqual(loaded.layout, donor.layout)
        self.assertEqual([s.place for s in loaded.signatures], [s.place for s in donor.signatures])
        self.assertTrue(signatures.remove("earlier"))


if __name__ == "__main__":
    unittest.main()
