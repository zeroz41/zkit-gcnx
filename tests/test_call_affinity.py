import support  # noqa: F401  (isolates config, cache and state)
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_delink import CLANG, LLD
from test_key_function_tails import COMPILE
from zkit import nx, units
from zkit.elf import Elf
from zkit.gc import Symbol
from zkit.platform import Switch
from zkit.program import Program

# Nothing in the code places the boundary: another build places pool.cpp's methods and hand.cpp's; the two functions
# between, which that build lacks (added since), only call pool.cpp's first method, further back than a short call.
TAKE = "int lib::Pool::take(int n) { return " + " + ".join(f"tick(n + {i})" for i in range(12)) + " - top; }\n"
FILL = "".join(f"int lib::Pool::f{i}(int x) {{ return x * {i + 3} + top - tick(x); }}\n" for i in range(24))
POOL = "int tick(int n);\nnamespace lib { struct Pool { int top; __attribute__((visibility(\"hidden\"))) " \
    "int take(int n); " + "".join(f"int f{i}(int x); " for i in range(24)) + "}; }\n" + TAKE + FILL + """
int drain(lib::Pool &p, int n) { int s = 0; for (int i = 0; i < n; ++i) s += p.take(i); return s; }
int refill(lib::Pool &p, int n) { return p.take(n) + p.take(n * 2) + p.take(n + 7); }
"""
HAND = """int tick(int n);
namespace lib { struct Hand { int cards; int draw(int n); int play(int n); }; }
int lib::Hand::draw(int n) { return cards - tick(n); }
int lib::Hand::play(int n) { return cards + tick(n * 3); }
"""


def owners(root: Path, pool: str = "lib/pool.cpp", hand: str = "lib/hand.cpp",
           sources: tuple[str, ...] = ()) -> tuple[dict[str, int], dict[int, str]]:
    """Builds both files into a stripped module and proposes its units with the other build's placements (`pool`'s
    and `hand`'s names for the two files' code)."""
    objects = []
    for name, text in {"pool.cpp": POOL, "hand.cpp": HAND}.items():
        (root / name).write_text(text, encoding="utf-8")
        objects.append(str(root / name.replace(".cpp", ".o")))
        subprocess.run([CLANG, *COMPILE, "-ffunction-sections", str(root / name), "-o", objects[-1]], check=True,
                       capture_output=True)
    link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all", *objects]
    subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
    subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
    at = {s.name: s.value for s in Elf.load(root / "full.elf").symbols if s.name}
    name = {a: n for n, a in at.items() if n.startswith("_Z")}
    module = nx.load(root / "main.elf")
    symbols = [Symbol(name.get(a, f"fn_{a:08X}"), ".text", a, "function", size, "global")
               for a, size in module.functions()]
    program = Program.from_symbol_list(Switch(), module, symbols)
    program.cflags = COMPILE
    placed = {a: (pool if n.startswith("_ZN3lib4Pool") else hand) for a, n in name.items()
              if n.startswith(("_ZN3lib4Pool", "_ZN3lib4Hand"))}
    owner = {}
    for unit in units.propose(program, placed=placed, sources=sources)["units"]:
        for index in range(unit["first"], unit["end"]):
            owner[program.functions[index].address] = unit["unit"]
    return at, owner


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class CallAffinityTests(unittest.TestCase):
    def test_functions_another_build_lacks_go_with_the_file_whose_code_they_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            at, owner = owners(Path(tmp))
        take, drain, refill = at["_ZN3lib4Pool4takeEi"], at["_Z5drainRN3lib4PoolEi"], at["_Z6refillRN3lib4PoolEi"]
        draw = at["_ZN3lib4Hand4drawEi"]
        self.assertLess(take, drain)
        self.assertLess(refill, draw)
        self.assertTrue(owner[take].endswith("pool.cpp"))
        self.assertTrue(owner[draw].endswith("hand.cpp"))
        self.assertEqual(owner[drain], owner[take])
        self.assertEqual(owner[refill], owner[take])

    def test_a_file_of_the_sources_keeps_its_name(self):
        """Another build's placeholder (`unit_<its address>.cpp`) and piece (`hand_<its address>.cpp`) take this
        build's address, unless they are files of the sources (a compiled object's unit): then each is its own
        file under that name."""
        pool, hand = "lib/unit_7100001234.cpp", "lib/hand_7100005678.cpp"
        with tempfile.TemporaryDirectory() as tmp:
            at, owner = owners(Path(tmp), pool, hand)
            _, kept = owners(Path(tmp), pool, hand, (pool, hand))
        take, draw = at["_ZN3lib4Pool4takeEi"], at["_ZN3lib4Hand4drawEi"]
        self.assertRegex(owner[take], r"^lib/unit_[0-9A-F]+\.cpp$")             # this build's address
        self.assertNotEqual(owner[take], pool)
        self.assertEqual(owner[draw], "lib/hand.cpp")
        self.assertEqual((kept[take], kept[draw]), (pool, hand))
