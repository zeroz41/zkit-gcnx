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

# One file defining two classes: Card's methods cite the file, then a long run of Deck's methods (210) cites nothing.
# Card's table has a key function (its destructor) in this file, so clang emits it here with Card::kind, an inline
# virtual only that table holds, deferred to the end of the file's code: after all of Deck's.
REPORT = 'void report(const char *file, int line);\n'
DECK = "".join(f"int lib::Deck::m{i}(int x) {{ return x * {i + 3} + top - {i}; }}\n" for i in range(210))
OBJ = REPORT + """namespace lib {
struct Card { virtual ~Card(); virtual int kind() const { return 7; } virtual int value(int n) const; int v; };
struct Deck { int top; """ + "".join(f"int m{i}(int x); " for i in range(210)) + """};
}
lib::Card::~Card() { if (v < 0) report("C:/proj/src/lib/card.cpp", 3); }
int lib::Card::value(int n) const { if (n > v) report("C:/proj/src/lib/card.cpp", 9); return v * n; }
""" + DECK
NEXT = REPORT + """namespace lib { struct Table { int seats; int seat(int n); int leave(int n); }; }
int lib::Table::seat(int n) { if (n > seats) report("C:/proj/src/lib/table.cpp", 2); return seats - n; }
int lib::Table::leave(int n) { if (n < 0) report("C:/proj/src/lib/table.cpp", 6); return seats + n; }
"""
SOURCES = {"card.cpp": OBJ, "table.cpp": NEXT}
COMPILE = [f for f in FLAGS if f != "-fvisibility=hidden"]     # inlines keep their weak binding in the link


def build(sources: dict[str, str], root: Path) -> tuple[dict[str, int], dict[int, str]]:
    """Links the sources into a stripped module named as a symbol list names it (functions and class tables, with
    their bindings); the address of each name, the unit owning each address."""
    objects = []
    for name, text in sources.items():
        (root / name).write_text(text, encoding="utf-8")
        objects.append(str(root / name.replace(".cpp", ".o")))
        subprocess.run([CLANG, *COMPILE, "-ffunction-sections", str(root / name), "-o", objects[-1]], check=True,
                       capture_output=True)
    link = [LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all", *objects]
    subprocess.run([*link, "-o", str(root / "full.elf")], check=True, capture_output=True)
    subprocess.run([*link, "--strip-all", "-o", str(root / "main.elf")], check=True, capture_output=True)
    full = [s for s in Elf.load(root / "full.elf").symbols if s.name]
    at = {s.name: s.value for s in full}
    name = {s.value: s for s in full if s.name.startswith("_Z")}
    module = nx.load(root / "main.elf")
    functions = module.functions()
    symbols = [Symbol(name[a].name if a in name else f"fn_{a:08X}", ".text", a, "function", size,
                      "weak" if a in name and name[a].bind == "weak" else "global") for a, size in functions]
    tables = [s for s in full if s.name.startswith("_ZTV")]
    symbols += [Symbol(f"lbl_{a:08X}", section, a, "object", size, "global")
                for a, size, section in nxdata.objects(module, functions)
                if not any(t.value <= a < t.value + t.size for t in tables)]
    symbols += [Symbol(t.name, ".data", t.value, "object", t.size, "weak" if t.bind == "weak" else "global")
                for t in tables]
    program = Program.from_symbol_list(Switch(), module, symbols)
    program.cflags = COMPILE
    owner = {}
    for unit in units.propose(program)["units"]:
        for index in range(unit["first"], unit["end"]):
            owner[program.functions[index].address] = unit["unit"]
    return at, owner


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class KeyFunctionTailTests(unittest.TestCase):
    def test_an_inline_virtual_after_another_class_s_code_is_its_key_function_s_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            at, owner = build(SOURCES, Path(tmp))
        value, kind = at["_ZNK3lib4Card5valueEi"], at["_ZNK3lib4Card4kindEv"]
        first, last = at["_ZN3lib4Deck2m0Ei"], at["_ZN3lib4Deck4m209Ei"]
        seat = at["_ZN3lib5Table4seatEi"]
        self.assertLess(last, kind)                    # the deferred inline follows all of Deck's code
        self.assertEqual({owner[value], owner[first], owner[last], owner[kind]}, {owner[value]})
        self.assertTrue(owner[value].endswith("card.cpp"))
        self.assertTrue(owner[seat].endswith("table.cpp"))
