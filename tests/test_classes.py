import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import classes, mwmap, score, vtables
from zkit.gc import Dol
from zkit.platform import GameCube
from zkit.program import DataObject, Function, Program

TEXT, DATA = 0x80003100, 0x80100000


def lis(rd, value): return (15 << 26) | (rd << 21) | (((value + 0x8000) >> 16) & 0xFFFF)
def addi(rd, ra, value): return (14 << 26) | (rd << 21) | (ra << 16) | (value & 0xFFFF)
def li(rd, value): return addi(rd, 0, value)
def stw(rs, offset, ra): return (36 << 26) | (rs << 21) | (ra << 16) | (offset & 0xFFFF)
def mr(ra, rs): return (31 << 26) | (rs << 21) | (ra << 16) | (rs << 11) | (444 << 1)
BLR = 0x4E800020


class Image:
    """A DOL assembled from functions (lists of words, `bl` written as ("bl", name)) and data tables."""

    def __init__(self):
        self.functions: dict[str, list] = {}
        self.tables: dict[str, list] = {}

    def build(self) -> tuple[Dol, list[Function], list[DataObject]]:
        addresses, cursor = {}, TEXT
        for name, body in self.functions.items():
            addresses[name] = cursor
            cursor += 4 * len(body)
        data_cursor = DATA
        for name, words in self.tables.items():
            addresses[name] = data_cursor
            data_cursor += 4 * len(words)
        text = bytearray()
        for name, body in self.functions.items():
            for word in body:
                pc = TEXT + len(text)
                if isinstance(word, tuple):
                    kind, target = word
                    value = addresses[target]
                    word = {"bl": lambda: (18 << 26) | ((value - pc) & 0x3FFFFFC) | 1,
                            "lis": lambda: lis(4, value), "addi": lambda: addi(4, 4, value)}[kind]()
                text += struct.pack(">I", word)
        data = b"".join(struct.pack(">I", addresses.get(w, w) if isinstance(w, str) else w)
                        for words in self.tables.values() for w in words)
        header = bytearray(0x100)
        struct.pack_into(">I", header, 0x00, 0x100)                 # text 0 offset
        struct.pack_into(">I", header, 0x1C, 0x100 + len(text))     # data 0 offset
        struct.pack_into(">I", header, 0x48, TEXT)
        struct.pack_into(">I", header, 0x64, DATA)
        struct.pack_into(">I", header, 0x90, len(text))
        struct.pack_into(">I", header, 0xAC, len(data))
        struct.pack_into(">I", header, 0xE0, TEXT)
        dol = Dol(bytes(header) + bytes(text) + data)
        functions = [Function(addresses[n], 4 * len(b), n) for n, b in self.functions.items()]
        objects = [DataObject(addresses[n], 4 * len(w), f"lbl_{addresses[n]:08X}", ".data")
                   for n, w in self.tables.items()]
        return dol, functions, objects


def install(table: str, offset: int = 0x18, this: int = 3) -> list:
    return [("lis", table), ("addi", table), stw(4, offset, this)]


class ClassRecoveryTests(unittest.TestCase):
    """A base and a derived class built the way CodeWarrior emits them, plus a dispatch table that is not a
    class: the tables, constructors, destructors, base, size and fields must all come back from the code."""

    def program(self) -> tuple[Program, dict]:
        image = Image()
        image.functions = {
            "Base_ct": install("vt_base") + [li(0, 0), stw(0, 0x1C, 3), BLR],
            "Base_dt": install("vt_base") + [BLR],
            "Base_get": [BLR],
            "Derived_ct": [mr(31, 3), ("bl", "Base_ct"), *install("vt_derived", this=31), BLR],
            "Derived_dt": [mr(31, 3), *install("vt_derived", this=31), mr(3, 31), ("bl", "Base_dt"), BLR],
            "Derived_run": [BLR],
            "new": [BLR],
            "handler_a": [BLR],
            "handler_b": [BLR],
            "uses_table": [("lis", "handlers"), ("addi", "handlers"), BLR],
        }
        for maker in ("make_a", "make_b", "make_c"):
            image.functions[maker] = [li(3, 0x40), ("bl", "new"), mr(31, 3), mr(3, 31), ("bl", "Derived_ct"), BLR]
        image.tables = {"vt_base": [0, 0, "Base_dt", "Base_get"],
                        "vt_derived": [0, 0, "Derived_dt", "Base_get", "Derived_run"],
                        "handlers": [0, 0, "handler_a", "handler_b"]}
        dol, functions, objects = image.build()
        program = Program(GameCube(), dol, functions, objects)
        return program, {f.name: f.address for f in functions} | {o.name: o.address for o in objects}

    def test_tables_are_classes_and_dispatch_tables_are_not(self):
        program, at = self.program()
        tables = vtables.find(program)
        self.assertEqual(sorted(tables), [DATA, DATA + 16])
        self.assertEqual(len(tables[DATA + 16].slots), 3)

    def test_constructors_destructors_base_size_fields(self):
        program, at = self.program()
        tables = vtables.find(program)
        found = classes.recover(program, tables)
        base, derived = found[DATA], found[DATA + 16]
        self.assertEqual(base.constructors, [at["Base_ct"]])
        self.assertEqual(base.destructor, at["Base_dt"])
        self.assertEqual(derived.constructors, [at["Derived_ct"]])
        self.assertEqual(derived.destructor, at["Derived_dt"])
        self.assertEqual(derived.base, DATA)
        self.assertEqual(derived.pointer, 0x18)
        self.assertEqual(derived.size, 0x40)
        self.assertIn(0x1C, base.fields)
        graph = classes.graph(program, tables, found)
        slots = next(c for c in graph["classes"] if c["vtable"] == f"0x{DATA + 16:08X}")["slots"]
        self.assertEqual([s["inherited"] for s in slots], [False, True, False])


class ScoreTests(unittest.TestCase):
    def test_reference_scores_itself_perfectly(self):
        reference = score.Split()
        reference.units["a.cpp"] = [(".text", 0x100, 0x200), (".data", 0x1000, 0x1010)]
        reference.units["b.cpp"] = [(".text", 0x200, 0x300)]
        reference.functions = {0x100: (0x100, "f"), 0x200: (0x80, "g"), 0x280: (0x80, "fn_00000280")}
        reference.objects = {0x1000: (0x10, "__vt__1A", ".data")}
        result = score.score(reference, reference, {"a.cpp"})
        self.assertEqual(result["unit_cuts"]["found"], 100.0)
        self.assertEqual(result["names"]["reference_named"], 2)
        self.assertEqual(result["data_ownership"]["owned_by_the_right_unit"], 100.0)

    def test_wrong_names_count_against_a_proposal(self):
        reference, proposal = score.Split(), score.Split()
        reference.functions = {0x100: (4, "real"), 0x104: (4, "other")}
        proposal.functions = {0x100: (4, "real"), 0x104: (4, "wrong")}
        names = score.score(reference, proposal)["names"]
        self.assertEqual((names["correct"], names["wrong"], names["precision"]), (1, 1, 50.0))


class MapTests(unittest.TestCase):
    MAP = """.text section layout
  Starting        Virtual
  address  Size   address
  -----------------------
  00000000 0000f4 800056c0  1 .text \tkartLocale.o
  00000000 0000f4 800056c0  4 localize__10KartLocaleFv \tkartLocale.o
  000000f4 000010 800057b4  1 .text \tJSystem.a J3DUDL.cpp
  000000f4 000008 800057b4  4 getUseMtxNum__11J3DShapeMtxCFv \tJSystem.a J3DUDL.cpp
  UNUSED   000024 ........ unusedFunction \tJSystem.a J3DUDL.cpp
.data section layout
  Starting        Virtual
  address  Size   address
  -----------------------
  00000000 000034 804273a0  1 .data \tkartLocale.o
  00000000 000018 804273a0  4 mscpaLanguageName__10KartLocale \tkartLocale.o
"""

    def test_units_functions_and_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "game.MAP"
            path.write_text(self.MAP, encoding="utf-8")
            split = mwmap.read(path)
        self.assertEqual(split.units["kartLocale.o"], [(".text", 0x800056C0, 0x800057B4),
                                                       (".data", 0x804273A0, 0x804273D4)])
        self.assertEqual(split.units["JSystem/J3DUDL.cpp"], [(".text", 0x800057B4, 0x800057C4)])
        self.assertEqual(split.functions[0x800057B4], (8, "getUseMtxNum__11J3DShapeMtxCFv"))
        self.assertEqual(split.objects[0x804273A0], (0x18, "mscpaLanguageName__10KartLocale", ".data"))


if __name__ == "__main__":
    unittest.main()


class AuditTests(unittest.TestCase):
    """The recovered classes against a decomp's names, through a project."""

    def test_audit_finds_misfiled_role_named_and_unnamed(self):
        import json
        from zkit.classes import audit_project
        from zkit.project import Project
        program, at = ClassRecoveryTests().program()
        names = {at["Base_ct"]: "Base__ct", at["Base_dt"]: "__dt__4BaseFv", at["Base_get"]: "get__4BaseFv",
                 at["Derived_ct"]: "__ct__7DerivedFv", at["Derived_dt"]: "Other__sub_8000312C",
                 at["Derived_run"]: "fn_80003134"}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "orig.dol").write_bytes(program.image.raw)
            lines = [f"{names.get(f.address, f.name)} = .text:0x{f.address:08X}; // type:function size:0x{f.size:X}"
                     for f in program.functions]
            lines.append(f"__vt__4Base = .data:0x{DATA:08X}; // type:object size:0x10")
            lines.append(f"lbl_{DATA + 16:08X} = .data:0x{DATA + 16:08X}; // type:object size:0x14")
            lines.append(f"__vt__8Handlers = .data:0x{DATA + 36:08X}; // type:object size:0x10")
            (root / "symbols.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (root / "project.json").write_text(json.dumps({
                "schema_version": 1, "id": "audit", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
                "targets": {"t": {"repository": "decomp", "module": "main", "original": "orig.dol",
                                  "symbols": "symbols.txt"}}}),
                encoding="utf-8")
            data = audit_project(Project.load(root / "project.json"))
        self.assertEqual([r["symbol"] for r in data["not_a_table"]], ["__vt__8Handlers"])
        self.assertEqual([r["current"] for r in data["role_named"]], ["Base__ct"])
        unnamed = data["unnamed_class"][0]
        self.assertEqual((unnamed["class"], unnamed["suggested_symbol"]), ("Derived", "__vt__7Derived"))
        wrong = data["wrong_class"][0]
        self.assertEqual((wrong["current"], wrong["class"], wrong["suggested"]),
                         ("Other__sub_8000312C", "Derived", "__dt__7DerivedFv"))
