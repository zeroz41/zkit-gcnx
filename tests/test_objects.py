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


if __name__ == "__main__":
    unittest.main()
