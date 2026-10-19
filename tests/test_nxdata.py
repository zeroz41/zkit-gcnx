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
int touchA(int v) { if (v > 99) report("C:/proj/src/game/a.cpp", 5); return shared() += v; }
""",
    "b.cpp": """void report(const char *file, int line);
inline int &shared() { static int s_shared; return s_shared; }
int touchB(int v) { if (v < -99) report("C:/proj/src/game/b.cpp", 3); return shared() -= v * 3; }
int other(int v) { if (v == 7) report("b.cpp", 4); return v * 11 + 2; }
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

    def test_units_follow_the_files_the_code_cites(self):
        """The inline's static joins the first file's code to the second's, but each file cites itself: two
        units, and the second file's relative citation is the same file as its full one."""
        functions = self.module.functions()
        symbols = [Symbol(f"fn_{a:08X}", ".text", a, "function", s, "global") for a, s in functions]
        symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                     for a, size, section in nxdata.objects(self.module, functions)]
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


if __name__ == "__main__":
    unittest.main()
