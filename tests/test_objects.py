import support  # noqa: F401  (isolates config, cache and state)
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from zkit import objects
from zkit.elf import Elf

CLANG = shutil.which("clang")
TARGETS = {"aarch64": "aarch64-none-elf", "ppc": "powerpc-unknown-eabi"}
SOURCE = """
int g;
int h;
static float k = 1.5f;
int add(int a, int b) { return a + b + g; }
float scale(float x) { return x * k; }
"""


def build(folder: Path, name: str, source: str, triple: str) -> Path:
    c, o = folder / f"{name}.c", folder / f"{name}.o"
    c.write_text(source, encoding="utf-8")
    subprocess.run([CLANG, f"--target={triple}", "-O2", "-c", str(c), "-o", str(o)], check=True,
                   capture_output=True)
    return o


@unittest.skipUnless(CLANG, "needs clang to build PowerPC and AArch64 objects")
class ObjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_reads_both_machines(self):
        for machine, triple in TARGETS.items():
            elf = Elf.load(build(self.root, machine, SOURCE, triple))
            self.assertEqual(elf.machine, machine)
            self.assertEqual(set(elf.functions()), {"add", "scale"})
            self.assertEqual(elf.bits, 64 if machine == "aarch64" else 32)

    def test_identical_and_renamed(self):
        for machine, triple in TARGETS.items():
            a = build(self.root, f"{machine}-a", SOURCE, triple)
            b = build(self.root, f"{machine}-b", SOURCE, triple)
            self.assertEqual(objects.identical(a, b), [])
            c = build(self.root, f"{machine}-c", SOURCE.replace("add(", "sum("), triple)
            self.assertTrue(objects.identical(a, c))
            self.assertEqual(objects.identical(a, c, {"add": "sum"}), [], machine)

    def test_function_diff_code_and_relocation_only(self):
        for machine, triple in TARGETS.items():
            original = build(self.root, f"{machine}-o", SOURCE, triple)
            same = objects.function_diff(original, build(self.root, f"{machine}-s", SOURCE, triple), "add")
            self.assertTrue(same["exact"], machine)
            other_global = build(self.root, f"{machine}-g", SOURCE.replace("+ g;", "+ h;"), triple)
            diff = objects.function_diff(original, other_global, "add")
            self.assertFalse(diff["exact"])
            self.assertTrue(diff["reloc_only"], (machine, diff["rows"]))
            changed = build(self.root, f"{machine}-x", SOURCE.replace("a + b + g", "a * b + g"), triple)
            diff = objects.function_diff(original, changed, "add")
            self.assertFalse(diff["exact"] or diff["reloc_only"])
            unit = objects.unit_diff(original, changed)
            self.assertEqual((unit["exact"], unit["total"]), (1, 2))

    def test_a_structor_called_by_its_other_variant_is_the_same_call(self):
        """A destructor calls its base's D2, the original module names that function D1: the same function under
        the ABI's two names. Another class's destructor is not."""
        call = "void {0}(void);\nvoid fin(void) {{ {0}(); }}\n"
        original = build(self.root, "dtor-o", call.format("_ZN4BaseD1Ev"), TARGETS["aarch64"])
        same = objects.function_diff(original, build(self.root, "dtor-s", call.format("_ZN4BaseD2Ev"),
                                                     TARGETS["aarch64"]), "fin")
        self.assertTrue(same["exact"], same)
        other = objects.function_diff(original, build(self.root, "dtor-x", call.format("_ZN5OtherD2Ev"),
                                                      TARGETS["aarch64"]), "fin")
        self.assertTrue(other["reloc_only"] and not other["exact"], other)

    def test_literals_compare_by_value(self):
        # A writable .sdata2 (MWCC marks it so) still holds constants, compared by bytes when one side is unnamed;
        # relocations spelled alike (a merge section + 0) to different constants are a difference.
        literal = ('volatile float {0} __attribute__((section(".sdata2"))) = {1};\n'
                   'float scale(float x) {{ return x * {0}; }}\n')
        triple = TARGETS["ppc"]
        named = lambda name, tag, value="1.5f": build(self.root, f"lit-{tag}", literal.format(name, value), triple)
        original = named("lbl_80001000", "o")
        self.assertTrue(objects.function_diff(original, named("k", "b"), "scale")["exact"])
        self.assertFalse(objects.function_diff(original, named("k", "c", "2.5f"), "scale")["exact"])
        folded = lambda tag, value: build(self.root, f"fold-{tag}", f"float scale(float x) {{ return x * {value}; }}\n",
                                          triple)
        self.assertTrue(objects.function_diff(folded("a", "1.5f"), folded("b", "1.5f"), "scale")["exact"])
        self.assertFalse(objects.function_diff(folded("a", "1.5f"), folded("c", "2.5f"), "scale")["exact"])



class CandidateCommandTests(unittest.TestCase):
    def test_restage_mwcc_and_clang(self):
        from zkit.candidate import _restage
        root = Path("/repo")
        mwcc = ["build/tools/wibo", "build/compilers/GC/2.6/mwcceppc.exe", "-O4,p", "-i", "include", "-MMD",
                "-c", "src/game/a.cpp", "-o", "build/G/src/game"]
        argv, expected = _restage(mwcc, "src/game/a.cpp", root / "build/t/a.cpp", root / "build/t",
                                  root / "src/game", root)
        self.assertEqual(argv[:4], ["build/tools/wibo", "build/compilers/GC/2.6/mwcceppc.exe", "-i", "src/game"])
        self.assertIn("build/t/a.cpp", argv)
        self.assertEqual(argv[argv.index("-o") + 1], "build/t")
        self.assertNotIn("-MMD", argv)
        clang = ["clang++", "-O3", "-MD", "-MF", "a.d", "-c", "/repo/src/a.cpp", "-o", "obj/a.o"]
        argv, expected = _restage(clang, "/repo/src/a.cpp", root / "build/t/a.cpp", root / "build/t",
                                  root / "src", root)
        self.assertEqual(argv[:2], ["clang++", "-Isrc"])
        self.assertEqual(argv[argv.index("-o") + 1], "build/t/a.o")
        self.assertNotIn("-MF", argv)


if __name__ == "__main__":
    unittest.main()
