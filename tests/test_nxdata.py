import support  # noqa: F401  (isolates config, cache and state)
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_delink import CLANG, LLD
from zkit import nx, nxdata, units
from zkit.elf import Elf
from zkit.platform import Switch
from zkit.program import Program
from zkit.gc import Symbol

FLAGS = ["--target=aarch64-none-elf", "-fPIC", "-fvisibility=hidden", "-O2", "-fno-exceptions", "-fno-rtti",
         "-ffreestanding", "-fasynchronous-unwind-tables", "-c"]
# Two files that cite themselves, and between them the copy of an inline's static that the first one's code
# and the second one's both use (the linker keeps one copy of it, from whichever file comes first).
SOURCES = {
    "a.cpp": """void report(const char *file, int line);
inline int &shared() { static int s_shared; return s_shared; }
const char *g_names[] = {"alpha", "beta", "gamma"};
int g_count;
const char *pick(int i) { if (i < 0) report("C:/proj/src/game/a.cpp", 4); g_count++; return g_names[i % 3]; }
void rename(int i, const char *name) { g_names[i % 3] = name; }
int seed(int v);
int g_seeded = seed(1);
int touchA(int v) { if (v > 99) report("C:/proj/src/game/a.cpp", 5); return shared() += v; }
""",
    "b.cpp": """void report(const char *file, int line);
inline int &shared() { static int s_shared; return s_shared; }
int touchB(int v) { if (v < -99) report("C:/proj/src/game/b.cpp", 3); return shared() -= v * 3; }
int other(int v) { if (v == 7) report("b.cpp", 4); return v * 11 + 2; }
int seed(int v);
int g_later = seed(2);
""",
}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class ModuleDataTests(unittest.TestCase):
    """A stripped module's data, found from its code and pointers, and the units its code cites."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        for name, text in SOURCES.items():
            (root / name).write_text(text, encoding="utf-8")
            subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                           check=True, capture_output=True)
        link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                str(root / "a.o"), str(root / "b.o")]
        subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
        subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
        cls.at = {s.name: s for s in Elf.load(root / "full.elf").symbols}
        cls.module = nx.load(root / "main.elf")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_objects_from_code_and_pointers(self):
        found = {a: (size, section) for a, size, section in
                 nxdata.objects(self.module, self.module.functions())}
        self.assertEqual(found[self.at["g_count"].value], (4, ".bss"))         # loaded and stored at one width
        table = self.at["g_names"].value
        self.assertEqual(found[table][1], ".data")                              # pointers: relocated, writable
        self.assertGreaterEqual(found[table][0], 24)
        strings = {self.module.read(a, size): a for a, (size, section) in found.items() if section == ".rodata"}
        self.assertIn(b"alpha\0", strings)                                      # a string ends at its NUL
        self.assertIn(b"C:/proj/src/game/a.cpp\0", strings)
        tables = {section: (a, a + size) for a, size, section, _ in nxdata.linker_tables(self.module)}
        self.assertTrue({".eh_frame_hdr", ".eh_frame", ".dynsym", ".dynstr", ".dynamic", ".rela.dyn"} <= set(tables))
        self.assertFalse([a for a in found for start, end in tables.values() if start <= a < end])  # none of ours

    def test_units_follow_the_files_the_code_cites(self):
        """The inline's static joins the first file's code to the second's, but each file cites itself: two
        units, and the second file's relative citation is the same file as its full one."""
        functions = self.module.functions()
        symbols = [Symbol(f"fn_{a:08X}", ".text", a, "function", s, "global") for a, s in functions]
        symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                     for a, size, section in nxdata.objects(self.module, functions)]
        symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                    for a, size, section, name in nxdata.linker_tables(self.module)]
        program = Program.from_symbol_list(Switch(), self.module, symbols)
        proposal = units.propose(program)
        owner = {}
        for unit in proposal["units"]:
            for index in range(unit["first"], unit["end"]):
                owner[program.functions[index].address] = unit["unit"]
        self.assertEqual(owner[self.at["_Z4picki"].value], "game/a.cpp")
        self.assertEqual(owner[self.at["_Z6touchAi"].value], "game/a.cpp")
        self.assertEqual(owner[self.at["_Z6touchBi"].value], "game/b.cpp")
        self.assertEqual(owner[self.at["_Z5otheri"].value], "game/b.cpp")
        arrays = sorted((row["start_key"], unit["unit"]) for unit in proposal["units"] for row in unit["data"]
                        if row["section"] == ".init_array")
        self.assertEqual([unit for _, unit in arrays], ["game/a.cpp", "game/b.cpp"])   # each file's initializer
        self.assertFalse([row for unit in proposal["units"] for row in unit["data"]
                          if row["section"] in (".dynamic", ".eh_frame", ".dynsym")])  # the linker's, nobody's


# a global one file constructs and both files' code reads
CONSTRUCTED = {
    "a.cpp": """void report(const char *file, int line);
struct Info { const char *name; const Info *base; int count; };
const char *label(int v);
Info g_info = {label(1), nullptr, 3};
int countA(int v) { if (v > 99) report("C:/proj/src/game/a.cpp", 4); return g_info.count + v; }
""",
    "b.cpp": """void report(const char *file, int line);
struct Info { const char *name; const Info *base; int count; };
extern Info g_info;
const char *nameB(int v) { if (v < 0) report("C:/proj/src/game/b.cpp", 3); return v ? g_info.name : "none"; }
""",
}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class ConstructedDataTests(unittest.TestCase):
    def test_a_global_belongs_to_the_unit_whose_initializer_constructs_it(self):
        """Both files' code reads `g_info`, so its users say nothing; the first file's static initializer stores
        into it, so it is that file's."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in CONSTRUCTED.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                    str(root / "a.o"), str(root / "b.o")]
            subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
            subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
            at = {s.name: s for s in Elf.load(root / "full.elf").symbols}
            module = nx.load(root / "main.elf")
            functions = module.functions()
            symbols = [Symbol(f"fn_{a:08X}", ".text", a, "function", s, "global") for a, s in functions]
            symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section in nxdata.objects(module, functions)]
            symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section, name in nxdata.linker_tables(module)]
            proposal = units.propose(Program.from_symbol_list(Switch(), module, symbols))
            info = at["g_info"].value
            owners = [unit["unit"] for unit in proposal["units"] for row in unit["data"]
                      if row["section"] == ".bss" and int(row["start_key"]) <= info < int(row["end_key"])]
            self.assertEqual(owners, ["game/a.cpp"])


GOT_SOURCE = """extern int g_ext;
int g_local = 3;
void report();
void *g_table[] = {(void *)&report, (void *)&g_local};
int use() { report(); return g_ext + g_local; }
"""


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class GotTests(unittest.TestCase):
    def test_the_got_holds_no_data_and_code_reaching_through_it_refers_to_what_it_holds(self):
        """Default visibility: lld writes a .got right after .dynamic, and use() loads g_local's address from it."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "got.cpp").write_text(GOT_SOURCE, encoding="utf-8")
            flags = [f for f in FLAGS if f != "-fvisibility=hidden"]
            subprocess.run([CLANG, *flags, str(root / "got.cpp"), "-o", str(root / "got.o")], check=True,
                           capture_output=True)
            subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", str(root / "got.o"),
                            "-o", str(root / "got.elf")], check=True, capture_output=True)
            elf, module = Elf.load(root / "got.elf"), nx.load(root / "got.elf")
        sections = {s.name: (s.address, s.address + s.size) for s in elf.sections if s.name}
        self.assertEqual((module.tables[".got"], module.tables[".got.plt"]), (sections[".got"], sections[".got.plt"]))
        at = {s.name: s for s in elf.symbols if s.name}
        got = range(*sections[".got"])
        pointers = list(Switch(0).data_pointers(module))
        self.assertFalse([h for h, _ in pointers if h in got])
        self.assertIn((at["g_table"].value + 8, at["g_local"].value), pointers)   # a table's pointer is still data
        refs = Switch(0).addresses(module, at["_Z3usev"].value, at["_Z3usev"].size, {})
        self.assertIn(at["g_local"].value, [a for _, a, _ in refs])
        self.assertFalse([a for _, a, _ in refs if a in got])
        self.assertIn(".got", {section for _, _, section, _ in nxdata.linker_tables(module)})


if __name__ == "__main__":
    unittest.main()


# a file whose static initializer builds a global, then a file of one class's methods
INITIALIZED = {
    "a.cpp": """void report(const char *file, int line);
struct Info { const char *name; const Info *base; int count;
              Info(const char *n, const Info *b) : name(n), base(b), count(0) {} };
extern Info g_base;
const char *label(int v);
Info g_a(label(1), &g_base);
int countA(int v) { if (v > 99) report("C:/proj/src/game/a.cpp", 4); return g_a.count + v; }
""",
    "b.cpp": """void report(const char *file, int line);
struct B { int v; B(); int get() const; int put(int x); };
B::B() : v(0) {}
int B::get() const { if (v < 0) report("C:/proj/src/game/b.cpp", 3); return v; }
int B::put(int x) { if (x == 7) report("C:/proj/src/game/b.cpp", 4); v = x; return v * 3; }
""",
}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class InitializerNameTests(unittest.TestCase):
    def test_an_initializer_takes_its_files_name_not_a_constructors(self):
        """`.init_array` calls the first file's static initializer, which the symbols misname as the next file's
        class's constructor: the analysis withdraws that name, keeps the initializer with its file and names it
        as clang did."""
        from zkit import analyze
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in INITIALIZED.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                    str(root / "a.o"), str(root / "b.o")]
            subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
            subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
            at = {s.name: s for s in Elf.load(root / "full.elf").symbols}
            module = nx.load(root / "main.elf")
            initializer = at["_GLOBAL__sub_I_a.cpp"].value
            named = {at[n].value: n for n in ("_ZN1BC2Ev", "_ZNK1B3getEv", "_ZN1B3putEi")}
            named[initializer] = "_ZN1BC1Ev"                    # what a wrong donor name would say
            symbols = [Symbol(named.get(a, f"fn_{a:08X}"), ".text", a, "function", s, "global")
                       for a, s in module.functions()]
            symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section in nxdata.objects(module, module.functions())]
            symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section, name in nxdata.linker_tables(module)]
            program = Program.from_symbol_list(Switch(), module, symbols)
            result = analyze.analyze(program)
            self.assertEqual(result["symbols"][initializer], ("_GLOBAL__sub_I_a.cpp", "function", 0))
            self.assertIn(initializer, result["local"])
            owner = {program.functions[i].address: u["unit"] for u in result["units"]["units"]
                     for i in range(u["first"], u["end"])}
            self.assertEqual(owner[initializer], "game/a.cpp")
            self.assertEqual(owner[at["_ZN1BC2Ev"].value], "game/b.cpp")
