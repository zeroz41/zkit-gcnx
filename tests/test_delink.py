import support  # noqa: F401  (isolates config, cache and state)
import json
import shutil
import subprocess
import struct
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


class NoteTests(unittest.TestCase):
    def test_split_note_places_each_section_at_its_original_address(self):
        import struct
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unit.o"
            delink.write_object(delink.PPC, [(".text", 1, b"\x4e\x80\x00\x20", 4), (".data", 1, b"\0" * 8, 4)],
                                [{"name": "f", "section": ".text", "value": 0, "size": 4, "kind": "func",
                                  "bind": "global", "address": 0x80004000}], {}, path,
                                starts={".text": 0x80004000, ".data": 0x80100010})
            elf = Elf.load(path)
            note = elf.data(elf.section(".note.split"))
        cursor, found = 0, {}
        while cursor < len(note):
            size, length, kind = struct.unpack_from(">III", note, cursor)
            found[kind.to_bytes(4, "big")] = note[cursor + 20:cursor + 20 + length]
            cursor += 20 + length + (-length % 4)
        virt = struct.unpack(f">{len(found[b'VIRT']) // 4}I", found[b"VIRT"])
        self.assertEqual(virt, (0, 0x80004000, 0x80100010, 0x80004000))   # null, the two sections, f


class LabelLiteralTests(unittest.TestCase):
    def test_a_literal_another_unit_holds_is_compared_by_the_originals_bytes(self):
        """The original's object reaches a string only by a label another unit defines (the linker merged it
        there); the compiled object has it in its own string section. Read from the original, the bytes decide."""
        from zkit import objects
        code = bytes.fromhex("00000090" "00000091" "c0035fd6")   # adrp x0 / add x0, x0 / ret
        f = {"name": "f", "section": ".text", "value": 0, "size": 12, "kind": "func", "bind": "global", "address": 0}
        with tempfile.TemporaryDirectory() as folder:
            target, built = Path(folder) / "t.o", Path(folder) / "b.o"
            label = {"name": "lbl_7100001000", "section": None, "value": 0, "size": 0, "kind": "notype",
                     "bind": "global", "address": 0}
            delink.write_object(delink.AARCH64, [(".text", 1, code, 4)], [f, label],
                                {".text": [(0, 275, 1, 0), (4, 277, 1, 0)]}, target)
            text = {"name": ".str", "section": ".rodata.str1.1", "value": 0, "size": 0, "kind": "notype",
                    "bind": "local", "address": 0}
            delink.write_object(delink.AARCH64, [(".text", 1, code, 4), (".rodata.str1.1", 1, b"hi\0", 1)],
                                [f, text], {".text": [(0, 275, 1, 0), (4, 277, 1, 0)]}, built)
            same = objects.function_diff(target, built, "f", labels=lambda name: b"hi\0more")
            other = objects.function_diff(target, built, "f", labels=lambda name: b"ho\0")
            unread = objects.function_diff(target, built, "f")
        self.assertTrue(same["exact"], same)
        self.assertFalse(other["exact"])
        self.assertTrue(unread["reloc_only"] and not unread["exact"])

    def test_resolved_aarch64_jump_table_matches_a_relocated_one(self):
        """A split object holds an AArch64 jump table resolved (s32 entries relative to the table, no relocations);
        the compiled one relocates each entry (R_AARCH64_PREL32, clang's `.word .LBB - .LJTI`). Read at the
        original addresses `.note.split` records, the same case targets are the same table; one other target is a
        difference."""
        from zkit import objects
        code = bytes.fromhex("08000090" "08010091" "1fd61fd6" "c0035fd6" "c0035fd6" "c0035fd6")
        cases, fn, table = (0x0C, 0x10, 0x14), 0x7100001000, 0x7100002000
        f = {"name": "f", "section": ".text", "value": 0, "size": len(code), "kind": "func", "bind": "global",
             "address": fn}
        label = {"name": "lbl_7100002000", "section": ".rodata", "value": 0, "size": 12, "kind": "object",
                 "bind": "global", "address": table}
        entries = b"".join(struct.pack("<i", fn + case - table) for case in cases)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "t.o"
            delink.write_object(delink.AARCH64, [(".text", 1, code, 4), (".rodata", 1, entries, 4)], [f, label],
                                {".text": [(0, 275, 1, 0), (4, 277, 1, 0)]}, target)

            def compiled(name: str, targets: tuple) -> Path:
                g = dict(f, section=".text.f", address=0)
                jt = {"name": "jt", "section": ".rodata.f", "value": 0, "size": 0, "kind": "notype",
                      "bind": "local", "address": 0}
                path = Path(folder) / name
                delink.write_object(delink.AARCH64, [(".text.f", 1, code, 4), (".rodata.f", 1, bytes(12), 4)],
                                    [g, jt], {".text.f": [(0, 275, 1, 0), (4, 277, 1, 0)],
                                              ".rodata.f": [(4 * k, 261, 0, case + 4 * k)
                                                            for k, case in enumerate(targets)]}, path)
                return path
            same = objects.function_diff(target, compiled("b.o", cases), "f")
            other = objects.function_diff(target, compiled("c.o", (0x0C, 0x14, 0x14)), "f")
        self.assertTrue(same["exact"], same)
        self.assertTrue(other["reloc_only"] and not other["exact"], other)
        self.assertIn("jump table entries differ: +0x4 -> f+0x10 vs f+0x14", other["rows"][0].get("note", ""), other)


if __name__ == "__main__":
    unittest.main()
