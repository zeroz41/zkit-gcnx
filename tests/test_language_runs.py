import support  # noqa: F401  (isolates config, cache and state)
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_delink import CLANG, LLD
from test_nxdata import FLAGS
from zkit import nx, nxdata, units
from zkit.elf import Elf
from zkit.gc import Symbol
from zkit.platform import Switch
from zkit.program import Program

# a.cpp and b.cpp cite themselves; between them a C file (plain names reaching plain names only) that cites nothing.
# b.cpp also defines a C-callable function (its code reaches a C++ name) and a namespace-scope C++ function.
LANGUAGES = {
    "a.cpp": """void report(const char *file, int line);
namespace game { struct A { int v; int run(int n); int get() const; }; }
int game::A::run(int n) { if (n > 9) report("C:/proj/src/game/a.cpp", 1); v += n; return v; }
int game::A::get() const { if (v < 0) report("C:/proj/src/game/a.cpp", 2); return v * 3; }
""",
    "z.c": """__attribute__((noinline)) int zstep(int v) { return v * 7 + (v >> 3); }
int zrun(const int *p, int n) { int s = 0; for (int i = 0; i < n; i++) s += zstep(p[i]); return s; }
int zsum(const int *p, int n) { int s = 1; for (int i = 0; i < n; i++) s ^= p[i] << (i & 7); return s; }
""",
    "b.cpp": """void report(const char *file, int line);
namespace game { struct B { int v; static int make(int n); int put(int n); }; }
int game::B::make(int n) { if (n > 9) report("C:/proj/src/game/b.cpp", 1); return n * 5; }
int game::B::put(int n) { if (n < 0) report("C:/proj/src/game/b.cpp", 2); v = n; return v; }
int scaled(int n) { return game::B::make(n) + 1; }
extern "C" int b_api(int n) { return game::B::make(n) * 2; }
""",
}

# a.cpp's C interface: plainly named functions reaching no C++ name, never one another, among its members.
INTERFACE = {
    "a.cpp": """void report(const char *file, int line);
namespace game { struct A { int v; int run(int n); int get() const; int put(int n); }; }
int game::A::run(int n) { if (n > 9) report("C:/proj/src/game/a.cpp", 1); v += n; return v; }
int game::A::get() const { if (v < 0) report("C:/proj/src/game/a.cpp", 2); return v * 3; }
extern "C" int a_scale(int n) { return n * 3 + (n >> 2); }
extern "C" int a_mix(int n, int m) { return (n ^ m) * 5 + (m >> 1); }
int game::A::put(int n) { v = n * 7; return v; }
""",
    "b.cpp": LANGUAGES["b.cpp"],
}


def build(sources: dict[str, str], root: Path) -> tuple[dict[str, int], dict[int, str]]:
    """Links the sources into a stripped module; the address of each name, the unit owning each address."""
    objects = []
    for name, text in sources.items():
        (root / name).write_text(text, encoding="utf-8")
        language = ["-x", "c"] if name.endswith(".c") else []
        objects.append(str(root / (name.rsplit(".", 1)[0] + ".o")))
        subprocess.run([CLANG, *FLAGS, *language, "-ffunction-sections", str(root / name), "-o", objects[-1]],
                       check=True, capture_output=True)
    link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all", *objects]
    subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
    subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
    at = {s.name: s.value for s in Elf.load(root / "full.elf").symbols}
    name = {v: k for k, v in at.items() if k.startswith(("_Z", "z", "b_", "a_"))}
    module = nx.load(root / "main.elf")
    functions = module.functions()
    symbols = [Symbol(name.get(a, f"fn_{a:08X}"), ".text", a, "function", s, "global") for a, s in functions]
    symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                for a, size, section in nxdata.objects(module, functions)]
    program = Program.from_symbol_list(Switch(), module, symbols)
    program.cflags = FLAGS
    owner = {}
    for unit in units.propose(program)["units"]:
        for index in range(unit["first"], unit["end"]):
            owner[program.functions[index].address] = unit["unit"]
    return at, owner


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class LanguageRunTests(unittest.TestCase):
    def test_a_cpp_files_c_interface_is_no_unit_of_its_own(self):
        """a_scale and a_mix are plainly named and reach no C++ name, as a C file's functions would, but neither
        reaches the other: nothing says they are a file of their own, so no unit of their own parts them from the
        cited files' members (which of the two keeps them, the citations' own boundary decides)."""
        with tempfile.TemporaryDirectory() as temp:
            at, owner = build(INTERFACE, Path(temp))
            self.assertLess(at["_ZNK4game1A3getEv"], at["a_scale"])
            self.assertLess(at["a_mix"], at["_ZN4game1A3putEi"])
            for c in ("a_scale", "a_mix", "_ZN4game1A3putEi"):
                self.assertIn(owner[at[c]], ("game/a.cpp", "game/b.cpp"), c)

    def test_a_c_file_between_two_cpp_files_is_a_unit_of_its_own(self):
        """Nothing cites z.c; one boundary lies somewhere between a.cpp's citations and b.cpp's. Where z.c's plainly
        named functions (reaching no C++ name) meet a class's members, on both sides, a C file meets a C++ one: z.c
        is neither file's (the citations' own boundary may part it too). b.cpp's own C-callable b_api (its code
        calls game::B::make) and its namespace-scope `scaled` stay b.cpp's."""
        with tempfile.TemporaryDirectory() as temp:
            at, owner = build(LANGUAGES, Path(temp))
            self.assertLess(at["_ZNK4game1A3getEv"], at["zstep"])
            self.assertLess(at["zsum"], at["_ZN4game1B4makeEi"])
            self.assertEqual(owner[at["_ZNK4game1A3getEv"]], "game/a.cpp")
            for c in ("zstep", "zrun", "zsum"):
                self.assertNotIn(owner[at[c]], ("game/a.cpp", "game/b.cpp"), c)
            for cpp in ("_ZN4game1B4makeEi", "_Z6scaledi", "b_api"):
                self.assertEqual(owner[at[cpp]], "game/b.cpp", cpp)


if __name__ == "__main__":
    unittest.main()
