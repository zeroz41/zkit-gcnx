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


# a class whose key function is in the first file, built only by a template instance the second file uses
KEYED = {
    "a.cpp": """void report(const char *file, int line);
struct Node { virtual ~Node(); virtual int run(int v); int m_count; };
Node::~Node() {}
int Node::run(int v) { if (v > 99) report("C:/proj/src/game/a.cpp", 4); return m_count += v; }
int touchA(int v) { if (v < -5) report("C:/proj/src/game/a.cpp", 6); return v * 7; }
""",
    "b.cpp": """void report(const char *file, int line);
struct Node { virtual ~Node(); virtual int run(int v); int m_count; };
template <class T> T *make(void *where) { return new (where) T(); }
inline void *operator new(unsigned long, void *where) { return where; }
Node *build(void *where) { if (!where) report("C:/proj/src/game/b.cpp", 5); return make<Node>(where); }
int touchB(int v) { if (v == 3) report("C:/proj/src/game/b.cpp", 7); return v + 1; }
""",
}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class KeyFunctionTableTests(unittest.TestCase):
    def test_a_table_is_its_key_functions_units_whatever_builds_it(self):
        """Only the second file's code (a template instance constructing the class) refers to `Node`'s table,
        but clang emits a table with its key function, in the first file: the table is that file's."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in KEYED.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                    str(root / "a.o"), str(root / "b.o")]
            subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
            subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
            at = {s.name: s for s in Elf.load(root / "full.elf").symbols}
            module = nx.load(root / "main.elf")
            named = {at[n].value: n for n in ("_ZN4NodeD2Ev", "_ZN4NodeD0Ev", "_ZN4Node3runEi")
                     if n in at}
            weak = {at[n].value for n in at if n.startswith("_Z4makeI4NodeEPT_Pv")}
            symbols = [Symbol(named.get(a, f"fn_{a:08X}"), ".text", a, "function", s,
                              "weak" if a in weak else "global") for a, s in module.functions()]
            symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section in nxdata.objects(module, module.functions())
                        if a != at["_ZTV4Node"].value]
            symbols.append(Symbol("_ZTV4Node", ".data", at["_ZTV4Node"].value, "object", at["_ZTV4Node"].size,
                                  "global"))
            symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section, name in nxdata.linker_tables(module)]
            program = Program.from_symbol_list(Switch(), module, symbols)
            proposal = units.propose(program)
            table = at["_ZTV4Node"].value
            owners = [unit["unit"] for unit in proposal["units"] for row in unit["data"]
                      if row["start_key"] <= table < row["end_key"]]
            self.assertEqual(owners, ["game/a.cpp"])


def _module(sources: dict[str, str], root: Path):
    """A stripped module linked from `sources` (a.cpp first), its full ELF's symbols, and the module."""
    for name, text in sources.items():
        (root / name).write_text(text, encoding="utf-8")
        subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                       check=True, capture_output=True)
    link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
            *[str(root / name.replace(".cpp", ".o")) for name in sources]]
    subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
    subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
    return {s.name: s for s in Elf.load(root / "full.elf").symbols}, nx.load(root / "main.elf")


def _program(module, names: dict[int, tuple[str, str]] = {}, objects: dict[int, tuple[str, int]] = {}):
    symbols = [Symbol(names.get(a, (f"fn_{a:08X}",))[0], ".text", a, "function", s,
                      names.get(a, ("", "global"))[1]) for a, s in module.functions()]
    symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                for a, size, section in nxdata.objects(module, module.functions()) if a not in objects]
    symbols += [Symbol(name, ".data" if a not in () else ".data", a, "object", size, "global")
                for a, (name, size) in objects.items()]
    symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                for a, size, section, name in nxdata.linker_tables(module)]
    return Program.from_symbol_list(Switch(), module, symbols)


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class DonorInitializerTests(unittest.TestCase):
    def test_a_donors_initializer_takes_its_units_file_name(self):
        """A donor's unnamed static initializer is named after the unit its splits put it in, so another build's
        copy of that initializer can carry the file over."""
        from zkit import signatures
        with tempfile.TemporaryDirectory() as temp:
            at, module = _module(INITIALIZED, Path(temp))
            program = _program(module)
            init = at["_GLOBAL__sub_I_a.cpp"].value
            unit_of = lambda address: "game/a.cpp" if address <= init else "game/b.cpp"
            named = signatures._named_initializers(program, unit_of)
            self.assertEqual(next(f.name for f in named.functions if f.address == init), "_GLOBAL__sub_I_a.cpp")


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class TableSizeTests(unittest.TestCase):
    def test_an_unsized_table_is_read_from_its_slots_and_takes_its_labels(self):
        """A class table no donor sizes is as long as its two header words and its function slots; a placeholder
        label inside it goes and one running into it ends at its start."""
        from zkit import analyze
        from zkit.program import DataObject
        with tempfile.TemporaryDirectory() as temp:
            at, module = _module(KEYED, Path(temp))
            table = at["_ZTV4Node"]
            program = _program(module)
            self.assertEqual(analyze._table_size(program, table.value), table.size)
            labels = Program(program.platform, program.image, program.functions,
                             [DataObject(table.value - 8, 16, f"lbl_{table.value - 8:08X}", ".data", "global"),
                              DataObject(table.value + 16, 8, f"lbl_{table.value + 16:08X}", ".data", "global")], program.sda)
            absorbed, resized = analyze._room_for(labels, {table.value: table.size})
            self.assertEqual((absorbed, resized), ({table.value + 16}, {table.value - 8: 8}))


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class ExternalDataTests(unittest.TestCase):
    def test_a_global_one_files_initializer_constructs_joins_no_users(self):
        """Both files' code reads `g_info`, which the first file's static initializer constructs: a global that
        file defines and the other reaches through the GOT, so no join makes the users one unit."""
        with tempfile.TemporaryDirectory() as temp:
            at, module = _module(CONSTRUCTED, Path(temp))
            program = _program(module)
            g = at["g_info"].value
            self.assertIn(g, units._initialized(program))
            self.assertFalse([why for _, _, why in units.evidence(program).joins if f"{g:08X}" in why])


# b.cpp's code the linker dropped left its literals (written here as the object would carry them: a string c.cpp
# uses too, its path, a string only it used); b.cpp's kept code cites itself by its relative path
DROPPED = {
    "a.cpp": """void report(const char *file, int line);
int fa(int v) { if (v > 9) report("C:/proj/src/game/a.cpp", 1); return v + 1; }
""",
    "b.cpp": """void report(const char *file, int line);
__asm__(".pushsection .rodata.str1.1,\\"aMS\\",@progbits,1\\n.asciz \\"child == nullptr\\"\\n"
        ".asciz \\"C:/proj/src/game/b.cpp\\"\\n.asciz \\"b gone\\"\\n.popsection");
int fb(int v) { if (v > 9) report("b.cpp", 2); return v * 2; }
""",
    "c.cpp": """void report(const char *file, int line);
int fc(int v) { if (v > 9) report("C:/proj/src/game/c.cpp", 3); if (v < 0) report("child == nullptr", 4);
                return v - 1; }
""",
}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class DroppedCodeTests(unittest.TestCase):
    def test_a_dropped_files_literals_are_its_own(self):
        """Strings no code refers to are objects of their own, not the tail of the string before them, and the
        path among them is its file's (the unit its kept code names by a shorter path): b.cpp's range holds it,
        and c.cpp's starts after b.cpp's."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in DROPPED.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *FLAGS, str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            # -O0: each object's strings in link order, as the original's linker keeps them (lld's merging
            # orders them by hash)
            subprocess.run([LLD, "-O0", "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                            "--strip-all", *(str(root / n.replace(".cpp", ".o")) for n in DROPPED), "-o",
                            str(root / "main.elf")], check=True, capture_output=True)
            module = nx.load(root / "main.elf")
            functions = module.functions()
            found = nxdata.objects(module, functions)
            texts = {module.read(a, size): a for a, size, section in found if section == ".rodata"}
            for text in (b"child == nullptr\0", b"C:/proj/src/game/b.cpp\0", b"b gone\0"):
                self.assertIn(text, texts)                                  # each its own object
            symbols = [Symbol(f"fn_{a:08X}", ".text", a, "function", s, "global") for a, s in functions]
            symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global") for a, size, section in found]
            symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section, name in nxdata.linker_tables(module)]
            program = Program.from_symbol_list(Switch(), module, symbols)
            ranges = {unit["unit"]: (row["start_key"], row["end_key"]) for unit in units.propose(program)["units"]
                      for row in unit["data"] if row["section"] == ".rodata"}
            path = texts[b"C:/proj/src/game/b.cpp\0"]
            self.assertLessEqual(ranges["b.cpp"][0], path)
            self.assertLess(path, ranges["b.cpp"][1])
            self.assertGreaterEqual(ranges["game/c.cpp"][0], ranges["b.cpp"][1])


# a class whose table no symbol names (the module is stripped): only its second virtual cites its file, the three
# after it cite nothing, and the next file's code follows
CLASSES = {
    "a.cpp": """void report(const char *file, int line);
int fa(int v) { if (v > 9) report("C:/proj/src/game/a.cpp", 1); return v + 1; }
struct A { virtual ~A(); virtual int f(int); virtual int g(int); virtual int h(int); int x; };
A::~A() {}
int A::f(int v) { if (v > 9) report("C:/proj/src/game/a.cpp", 5); return v + x; }
int A::g(int v) { return v * x + 3; }
int A::h(int v) { return v - x * 7; }
inline void *operator new(__SIZE_TYPE__, void *at) { return at; }
A *makeA(void *at) { return new (at) A(); }
""",
    "b.cpp": """void report(const char *file, int line);
int fb(int v) { if (v > 9) report("C:/proj/src/game/b.cpp", 2); return v * 2; }
int fb2(int v) { if (v < 0) report("C:/proj/src/game/b.cpp", 3); return v - 2; }
""",
}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class UnnamedClassTests(unittest.TestCase):
    def test_an_unnamed_tables_own_functions_are_one_units(self):
        """Only A::f cites a.cpp, and nothing ties A::g and A::h to it but A's table: the functions only that
        table holds are one unit's, so they are a.cpp's, not the next file's."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in CLASSES.items():
                (root / name).write_text(text, encoding="utf-8")
                subprocess.run([CLANG, *[f for f in FLAGS if f != "-fno-rtti"], "-fno-rtti", "-ffunction-sections",
                                str(root / name), "-o", str(root / name.replace(".cpp", ".o"))],
                               check=True, capture_output=True)
            link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                    *(str(root / n.replace(".cpp", ".o")) for n in CLASSES)]
            subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
            subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
            at = {s.name: s.value for s in Elf.load(root / "full.elf").symbols}
            module = nx.load(root / "main.elf")
            functions = module.functions()
            symbols = [Symbol(f"fn_{a:08X}", ".text", a, "function", s, "global") for a, s in functions]
            symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section in nxdata.objects(module, functions)]
            symbols += [Symbol(name or f"lbl_{a:08X}", section, a, "object", size, "global")
                        for a, size, section, name in nxdata.linker_tables(module)]
            program = Program.from_symbol_list(Switch(), module, symbols)
            owner = {}
            for unit in units.propose(program)["units"]:
                for index in range(unit["first"], unit["end"]):
                    owner[program.functions[index].address] = unit["unit"]
            self.assertEqual(owner[at["_ZN1A1fEi"]], "game/a.cpp")
            self.assertEqual(owner[at["_ZN1A1gEi"]], "game/a.cpp")
            self.assertEqual(owner[at["_ZN1A1hEi"]], "game/a.cpp")
            self.assertEqual(owner[at["_Z2fbi"]], "game/b.cpp")
