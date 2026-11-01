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

# task.cpp: Count::reset, Task's methods (its first one cheap), then a value type's constructors and
# Count's other methods. util.cpp calls Task's cheap method without inlining it (the two are different files) and
# calls the constructors (too costly to inline) right after: only Count's own reset says where the code between goes,
# and the unit is Task's, not that of the type only constructed in it.
DECL = "#pragma GCC visibility push(hidden)\nint tick(int n);\n"    # direct calls in the shared module
# a recursive helper the inliner never inlines, defined before both files and further back than a short call
BASE = DECL + "int tick(int n) { return n <= 0 ? 1 : tick(n - 1) * 3 + tick(n - 2); }\n" + \
    "".join(f"int fill{i}(int x) {{ return x * {i + 5} + (x >> {i % 7 + 1}); }}\n" for i in range(24))
TASK = DECL + """
namespace lib {
struct Task { int top; int peek() const; int run(int n); int step(int n); int last(int n); };
struct Count { int n; void reset(); bool add(int k); bool sub(int k); };
struct Pair { int a, b; Pair(int x); Pair(int x, int y); };
}
void lib::Count::reset() { n = tick(0); }
int lib::Task::peek() const { return top; }
int lib::Task::run(int n) { return tick(n) + tick(n * 2) + top; }
int lib::Task::step(int n) { return tick(n + 3) - tick(top); }
int lib::Task::last(int n) { return tick(n) * tick(n + top); }
lib::Pair::Pair(int x) : a(tick(x + 0) + tick(x + 1) + tick(x + 2) + tick(x + 3) + tick(x + 4) + tick(x + 5) + tick(x + 6) + tick(x + 7) + tick(x + 8) + tick(x + 9)), b(tick(x)) {}
lib::Pair::Pair(int x, int y) : a(tick(x)), b(tick(y * 2) + tick(y * 3) + tick(y * 4) + tick(y * 5) + tick(y * 6) + tick(y * 7) + tick(y * 8) + tick(y * 9) + tick(y * 10) + tick(y * 11)) {}
bool lib::Count::add(int k) { if (k == 0) return false; for (int i = 0; i < k; ++i) n += tick(i); return true; }
bool lib::Count::sub(int k) { if (k == 0) return false; for (int i = 0; i < k; ++i) n -= tick(i); return true; }
"""
UTIL = DECL + """
namespace lib {
struct Task { int top; int peek() const; };
struct Pair { int a, b; Pair(int x); Pair(int x, int y); };
struct Util { static int first(const Task &t); static int second(int n); };
}
int lib::Util::first(const lib::Task &t) { lib::Pair p(t.peek()); lib::Pair q(t.peek(), 2); return p.a + q.b; }
int lib::Util::second(int n) { lib::Pair p(n); lib::Pair q(n, n); lib::Pair r(n + 1); return p.b + q.a + r.a; }
"""


def owners(root: Path) -> tuple[dict[str, int], dict[int, str]]:
    """Builds both files into a stripped module and proposes its units."""
    objects = []
    for name, text in {"base.cpp": BASE, "task.cpp": TASK, "util.cpp": UTIL}.items():
        (root / name).write_text(text, encoding="utf-8")
        objects.append(str(root / name.replace(".cpp", ".o")))
        subprocess.run([CLANG, *COMPILE, "-ffunction-sections", str(root / name), "-o", objects[-1]], check=True,
                       capture_output=True)
    link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all", *objects]
    subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
    subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
    at = {s.name: s.value for s in Elf.load(root / "full.elf").symbols if s.name}
    name = {a: n for n, a in sorted(at.items()) if n.startswith("_Z")}
    module = nx.load(root / "main.elf")
    symbols = [Symbol(name.get(a, f"fn_{a:08X}"), ".text", a, "function", size, "global")
               for a, size in module.functions()]
    program = Program.from_symbol_list(Switch(), module, symbols)
    program.cflags = COMPILE
    owner = {}
    for unit in units.propose(program)["units"]:
        for index in range(unit["first"], unit["end"]):
            owner[program.functions[index].address] = unit["unit"]
    return at, owner


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class ClassSidesTests(unittest.TestCase):
    def test_a_class_between_two_files_goes_with_its_own_other_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            at, owner = owners(Path(tmp))
        peek, add, first = at["_ZNK3lib4Task4peekEv"], at["_ZN3lib5Count3addEi"], at["_ZN3lib4Util5firstERKNS_4TaskE"]
        pair = at["_ZN3lib4PairC2Ei"]
        self.assertLess(peek, pair)
        self.assertLess(pair, add)
        self.assertLess(add, first)
        self.assertNotEqual(owner[peek], owner[first])
        self.assertEqual(owner[add], owner[peek])
        self.assertEqual(owner[pair], owner[peek])
        self.assertTrue(owner[peek].endswith("Task.cpp"))   # not the constructed value type's


if __name__ == "__main__":
    unittest.main()
