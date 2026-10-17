import support  # noqa: F401  (isolates config, cache and state)
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from zkit import delink, objects
from zkit.elf import Elf
from zkit.project import Project

CLANG, LLD, OBJDIFF = shutil.which("clang++"), shutil.which("ld.lld"), shutil.which("objdiff-cli")
FLAGS = ["--target=aarch64-none-elf", "-fPIC", "-fvisibility=hidden", "-O2", "-fno-exceptions", "-fno-rtti",
         "-ffreestanding", "-fno-asynchronous-unwind-tables", "-c"]
SOURCES = {
    "a.cpp": """extern int g_counter;
int helper(int x);
struct Base { virtual ~Base(); virtual int get() const; int value; };
struct Child : Base { int get() const override; };
Base::~Base() {}
int Base::get() const { return value + g_counter; }
int Child::get() const { return value * 2 + helper(value); }
static float scale = 1.5f;
float scaled(float v) { return v * scale; }
const char *greeting() { return "hello from a"; }
Base *make(bool child) { return child ? new Child() : new Base(); }
""",
    "b.cpp": """int g_counter = 3;
static int table[4] = {1, 2, 3, 4};
static int twice(int v) { return v * 2; }
int helper(int x) { return twice(x) + table[x & 3] + g_counter; }
int sum(const int *values, int count) { int total = 0; for (int i = 0; i < count; i++) total += values[i];
  return total; }
""",
}


def sections_of(path: Path) -> dict[str, tuple[int, int]]:
    """{section: (start, end)} of a linked ELF's output sections."""
    elf = Elf.load(path)
    return {s.name: (s.address, s.address + s.size) for s in elf.sections if s.name and s.address}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class DelinkTests(unittest.TestCase):
    """Link two compiled units into a module, delink it back from a splits.txt, and require every function and
    data section to equal what the compiler wrote (relocations included)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "orig").mkdir()
        for name, text in SOURCES.items():
            (self.root / name).write_text(text, encoding="utf-8")
            subprocess.run([CLANG, *FLAGS, str(self.root / name), "-o", str(self.root / "orig" / name.replace(
                ".cpp", ".o"))], check=True, capture_output=True)
        # --no-relax: lld would otherwise rewrite GOT loads into direct ones (Nintendo's modules are not relaxed)
        subprocess.run([LLD, "-shared", "--no-relax", "--unresolved-symbols=ignore-all", "-o",
                        str(self.root / "orig" / "main.elf"), str(self.root / "orig" / "a.o"),
                        str(self.root / "orig" / "b.o")], check=True, capture_output=True)
        (self.root / "project.json").write_text(json.dumps({
            "schema_version": 1, "id": "delink-test", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
            "targets": {"main": {"repository": "decomp", "platform": "switch", "base": 0, "module": "main",
                                 "original": "orig/main.elf"}}}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def splits(self) -> Path:
        linked = Elf.load(self.root / "orig" / "main.elf")
        address = {s.name: s.value for s in linked.symbols if s.name}
        size = {s.name: s.size for s in linked.symbols if s.name}
        text, rodata = sections_of(self.root / "orig" / "main.elf")[".text"], \
            sections_of(self.root / "orig" / "main.elf")[".rodata"]
        string = linked.data(linked.section(".rodata"))
        string_end = rodata[0] + string.index(b"\0") + 1
        lines = ["a.cpp:",
                 f"\t.text start:{text[0]:#x} end:{address['_Z6helperi']:#x}",
                 f"\t.rodata.str1.1 start:{rodata[0]:#x} end:{string_end:#x}",
                 f"\t.data.rel.ro start:{address['_ZTV4Base']:#x} end:{address['_ZTV5Child'] + 40:#x}",
                 "", "b.cpp:",
                 f"\t.text start:{address['_Z6helperi']:#x} end:{address['_Z3sumPKii'] + size['_Z3sumPKii']:#x}",
                 f"\t.rodata.cst16 start:{address['_ZL5table']:#x} end:{address['_ZL5table'] + 16:#x}",
                 f"\t.data start:{address['g_counter']:#x} end:{address['g_counter'] + 4:#x}", ""]
        path = self.root / "splits.txt"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def test_round_trip_equals_the_compiled_objects(self):
        project = Project.load(self.root / "project.json")
        result = delink.delink(project, "main", self.splits(), self.root / "target")
        self.assertEqual(result["unassigned"], 0)
        for unit in ("a", "b"):
            target, compiled = self.root / "target" / f"{unit}.o", self.root / "orig" / f"{unit}.o"
            diff = objects.unit_diff(target, compiled)
            self.assertEqual(diff["exact"], diff["total"], (unit, [f for f in diff["functions"] if not f["exact"]]))
            ours, theirs = Elf.load(target), Elf.load(compiled)
            for section in ours.sections:
                if section.name.startswith((".rodata", ".data")) and not section.name.startswith(".rela"):
                    self.assertEqual(ours.data(section), theirs.data(theirs.section(section.name)), section.name)

    def test_unassigned_reference_is_reported(self):
        project = Project.load(self.root / "project.json")
        splits = self.splits()
        splits.write_text("\n".join(line for line in splits.read_text().splitlines() if ".rodata.str" not in line))
        result = delink.delink(project, "main", splits, self.root / "target")
        self.assertEqual(result["unassigned"], 1)

    @unittest.skipUnless(OBJDIFF, "needs objdiff-cli")
    def test_objdiff_scores_everything_matched(self):
        project = Project.load(self.root / "project.json")
        delink.delink(project, "main", self.splits(), self.root / "target",
                      objdiff=self.root / "objdiff.json", compiled=self.root / "orig")
        subprocess.run([OBJDIFF, "report", "generate", "-p", str(self.root), "-o", str(self.root / "report.json")],
                       check=True, capture_output=True)
        measures = json.loads((self.root / "report.json").read_text())["measures"]
        self.assertEqual(measures["matched_code"], measures["total_code"])
        self.assertEqual(measures["matched_data"], measures["total_data"])


if __name__ == "__main__":
    unittest.main()
