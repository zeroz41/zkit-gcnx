import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import discover
from zkit.gc import Dol, read_symbols
from zkit.platform import GameCube
from zkit.program import Program

INIT, TEXT = 0x80003100, 0x80004000
CTORS, DTORS, RODATA, DATA = 0x80005000, 0x80005020, 0x80005040, 0x80005060
BSS, SDATA, SDATA2, BSS_END = 0x80005100, 0x80005200, 0x80005300, 0x80005400
R13, R2 = SDATA + 0x8000, SDATA2 + 0x8000


class Asm:
    """Words at consecutive addresses; an item is a word or a function of (pc, labels) for forward references."""

    def __init__(self, base: int, labels: dict):
        self.base, self.items, self.labels = base, [], labels

    @property
    def pc(self) -> int:
        return self.base + 4 * len(self.items)

    def at(self, name: str) -> "Asm":
        self.labels[name] = self.pc
        return self

    def emit(self, *items) -> "Asm":
        self.items.extend(items)
        return self

    def align(self, size: int) -> "Asm":
        while self.pc % size:
            self.items.append(0)
        return self

    def bytes(self) -> bytes:
        words = [w(self.base + 4 * i, self.labels) if callable(w) else w for i, w in enumerate(self.items)]
        return struct.pack(f">{len(words)}I", *words)


def d_form(op, rd, ra, imm): return (op << 26) | (rd << 21) | (ra << 16) | (imm & 0xFFFF)
def li(rd, value): return d_form(14, rd, 0, value)
def addi(rd, ra, value): return d_form(14, rd, ra, value)
def stw(rs, offset, ra): return d_form(36, rs, ra, offset)
def lwz(rd, offset, ra): return d_form(32, rd, ra, offset)
def stwu(offset): return d_form(37, 1, 1, offset)
def ori(ra, rs, value): return d_form(24, rs, ra, value)
def lis(rd, value): return d_form(15, rd, 0, value >> 16)
def cmplwi(ra, value): return d_form(10, 0, ra, value)
def mr(ra, rs): return (31 << 26) | (rs << 21) | (ra << 16) | (rs << 11) | (444 << 1)
def b(name): return lambda pc, labels: (18 << 26) | ((labels[name] - pc) & 0x03FFFFFC)
def bl(name, offset=0): return lambda pc, labels: (18 << 26) | ((labels[name] + offset - pc) & 0x03FFFFFC) | 1
def bgt(name): return lambda pc, labels: (16 << 26) | (12 << 21) | (1 << 16) | ((labels[name] - pc) & 0xFFFC)
def ha(name, rd): return lambda pc, labels: d_form(15, rd, 0, (labels[name] + 0x8000) >> 16)
def lo(name, rd, ra): return lambda pc, labels: d_form(14, rd, ra, labels[name])
def word(name): return lambda pc, labels: labels[name]


BLR, MFLR, MTLR, MTLR_R31, BCTR, MTCTR = 0x4E800020, 0x7C0802A6, 0x7C0803A6, 0x7FE803A6, 0x4E800420, 0x7C0903A6
SLWI_R0_R3_2 = (21 << 26) | (3 << 21) | (0 << 16) | (2 << 11) | (29 << 1)
LWZX_R0_R4_R0 = (31 << 26) | (4 << 16) | (23 << 1)
PROLOGUE = (stwu(-16), MFLR, stw(0, 20, 1))
EPILOGUE = (lwz(0, 20, 1), MTLR, addi(1, 1, 16), BLR)


def build() -> tuple[bytes, dict]:
    """A DOL whose code has each case discovery must handle; returns it and every label's address."""
    labels: dict = {}
    init = Asm(INIT, labels)
    init.at("start").emit(bl("init_registers"), bl("main")).at("hang").emit(b("hang"))   # the entry never returns
    init.at("init_registers").emit(lis(2, R2), ori(2, 2, R2 & 0xFFFF), lis(13, R13), ori(13, 13, R13 & 0xFFFF), BLR)
    text = Asm(TEXT, labels)
    text.at("main").emit(*PROLOGUE, *(bl(n) for n in ("a", "b_shared", "c_tail", "e_switch", "f_padded", "run",
                                                         "noreturn", "sled_user")), *EPILOGUE)
    text.at("a").emit(*PROLOGUE, bl("leaf")).at("a_epilogue").emit(*EPILOGUE)
    text.at("b_shared").emit(*PROLOGUE, bl("leaf"), b("a_epilogue"))   # tail branch into a's epilogue
    text.at("c_tail").emit(li(3, 0), b("d_tail"))                      # tail call to the next function
    text.at("d_tail").emit(*PROLOGUE, bl("leaf"), *EPILOGUE)
    text.at("e_switch").emit(cmplwi(3, 2), bgt("e_default"), ha("table", 4), lo("table", 4, 4), SLWI_R0_R3_2,
                             LWZX_R0_R4_R0, MTCTR, BCTR).at("e_default").emit(li(3, 0), BLR)
    for case in range(3):                                            # only the table reaches these
        text.at(f"e_case{case}").emit(li(3, case + 1), BLR)
    text.at("f_padded").emit(li(3, 5), BLR, 0).align(32)              # at least one word of padding
    text.at("g_unreferenced").emit(li(3, 6), BLR)                    # nothing calls it: after the padding
    text.at("run").emit(stwu(-24), MFLR, stw(0, 28, 1), stw(31, 20, 1), mr(31, 3), bl("leaf"), MTLR_R31, BLR)
    text.at("run_epilogue").emit(lwz(0, 28, 1), lwz(31, 20, 1), addi(1, 1, 24), MTLR, BLR)   # an unpaired epilogue
    text.at("noreturn").emit(*PROLOGUE, bl("forever"))                # falls into the next function
    text.at("virtual").emit(*PROLOGUE, bl("leaf"), *EPILOGUE)          # reached only through the vtable
    text.at("forever").emit(b("forever"))
    text.at("leaf").emit(li(3, 0), BLR)
    text.at("sled").emit(*(stw(register, -4 * (32 - register), 11) for register in range(14, 32)), BLR)
    text.at("sled_user").emit(stwu(-80), MFLR, stw(0, 84, 1), addi(11, 1, 80), bl("sled", 4 * 11), *EPILOGUE[:3],
                              BLR)
    data = Asm(DATA, labels)
    data.at("vtable").emit(0, 0, word("virtual")).at("table").emit(*(word(f"e_case{c}") for c in range(3)))
    sections = [(INIT, init), (TEXT, text), (CTORS, Asm(CTORS, labels).emit(0)), (DTORS, Asm(DTORS, labels).emit(0)),
                (RODATA, Asm(RODATA, labels).emit(0x3F800000, 0)), (DATA, data),
                (SDATA, Asm(SDATA, labels).emit(1, 2)), (SDATA2, Asm(SDATA2, labels).emit(0x3F000000, 0))]
    zero = [(BSS, SDATA - BSS), (SDATA + 8, SDATA2 - SDATA - 8), (SDATA2 + 8, BSS_END - SDATA2 - 8)]
    tables = 3 * len(sections) + 3 + 2 * len(zero) + 2                  # the linker's _rom_copy_info, _bss_init_info
    sizes = [4 * (len(s.items) + (tables if a == INIT else 0)) for a, s in sections]
    init.at("rom_copy_info").emit(*(v for (a, _), n in zip(sections, sizes) for v in (a, a, n)), 0, 0, 0,
                                  *(v for row in zero for v in row), 0, 0)
    blobs = [s.bytes() for _, s in sections]
    columns, cursor = [[0] * 18 for _ in range(3)], 0x100
    for slot, ((address, _), blob) in enumerate(zip(sections, blobs)):
        index = slot if slot < 2 else 7 + slot - 2                     # two text sections, then data sections
        columns[0][index], columns[1][index], columns[2][index] = cursor, address, len(blob)
        cursor += len(blob)
    header = struct.pack(">18I18I18I3I", *columns[0], *columns[1], *columns[2], BSS, BSS_END - BSS, INIT)
    return header.ljust(0x100, b"\0") + b"".join(blobs), labels


class DiscoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw, cls.labels = build()
        cls.dol = Dol(raw)
        cls.found = discover.discover(cls.dol)

    def size(self, first: str, end: str) -> int:
        return self.labels[end] - self.labels[first]

    def test_sections_and_small_data(self):
        self.assertEqual(self.found.sda, {2: R2, 13: R13})
        self.assertEqual([n for n, _, _ in self.found.sections],
                         [".init", ".text", ".ctors", ".dtors", ".rodata", ".data", ".bss", ".sdata", ".sbss",
                          ".sdata2", ".sbss2"])
        self.assertIn((".sbss", SDATA + 8, SDATA2), self.found.sections)        # from _bss_init_info

    def test_every_function_and_nothing_else(self):
        starts = ["start", "init_registers", "main", "a", "b_shared", "c_tail", "d_tail", "e_switch", "f_padded",
                  "g_unreferenced", "run", "noreturn", "virtual", "forever", "leaf", "sled", "sled_user"]
        self.assertEqual(sorted(self.found.functions), sorted(self.labels[n] for n in starts))
        self.assertEqual(self.found.functions[self.labels["init_registers"]], 0x14)   # the init tables are data
        self.assertIn((self.labels["rom_copy_info"], self.labels["rom_copy_info"] + 4 * (8 * 3 + 3 + 3 * 2 + 2)),
                      self.found.data_in_text)

    def test_shared_epilogue(self):
        # b_shared ends at its branch into a's epilogue; a keeps its own epilogue; no start inside a
        self.assertEqual(self.found.functions[self.labels["b_shared"]], self.size("b_shared", "c_tail"))
        self.assertEqual(self.found.functions[self.labels["a"]], self.size("a", "b_shared"))
        self.assertNotIn(self.labels["a_epilogue"], self.found.functions)

    def test_save_restore_sled(self):
        sled = self.labels["sled"]
        self.assertEqual(self.found.functions[sled], 0x4C)
        self.assertEqual(self.found.labels[sled + 4 * 11], sled)       # _savegpr_25: an entry, not a start
        self.assertEqual(self.found.functions[self.labels["sled_user"]], 0x24)

    def test_tail_call(self):
        self.assertEqual(self.found.functions[self.labels["c_tail"]], 8)
        self.assertIn("tail call", self.found.evidence[self.labels["d_tail"]])

    def test_jump_table(self):
        e = self.labels["e_switch"]
        self.assertEqual(self.found.functions[e], self.size("e_switch", "f_padded"))
        self.assertEqual(self.found.tables, {self.labels["table"]: 3})
        self.assertFalse({self.labels[f"e_case{c}"] for c in range(3)} & set(self.found.functions))
        names = {address: name for address, _, _, name in self.found.objects}
        self.assertEqual(names[self.labels["table"]], f"jumptable_{self.labels['table']:08X}")

    def test_padding(self):
        self.assertEqual(self.found.functions[self.labels["f_padded"]], 8)
        self.assertEqual(self.found.evidence[self.labels["g_unreferenced"]], {"after padding"})

    def test_unpaired_epilogue_is_the_tail_of_its_function(self):
        self.assertNotIn(self.labels["run_epilogue"], self.found.functions)
        self.assertEqual(self.found.functions[self.labels["run"]], self.size("run", "noreturn"))

    def test_function_reached_only_from_a_vtable(self):
        # `noreturn` falls into it; the vtable's word and its prologue make it a start
        self.assertEqual(self.found.functions[self.labels["noreturn"]], 0x10)
        self.assertEqual(self.found.evidence[self.labels["virtual"]], {"pointer"})
        self.assertEqual(self.found.functions[self.labels["virtual"]], self.size("virtual", "forever"))

    def test_symbols_file_and_program(self):
        with tempfile.TemporaryDirectory() as folder:
            path = discover.write_symbols(self.found, Path(folder) / "symbols.txt")
            symbols = read_symbols(path)
        functions = {s.address: s.size for s in symbols if s.type == "function"}
        self.assertEqual(functions, self.found.functions)
        main = next(s for s in symbols if s.address == self.labels["main"] and s.type == "function")
        self.assertEqual((main.name, main.section), (f"fn_{self.labels['main']:08X}", ".text"))
        vtable = next(s for s in symbols if s.address == self.labels["vtable"])
        self.assertEqual((vtable.section, vtable.type, vtable.size), (".data", "object", 12))
        program = Program.from_image(GameCube(), self.dol)
        self.assertEqual(len(program.functions), len(self.found.functions))
        self.assertEqual(program.sda, {2: R2, 13: R13})
        self.assertEqual(program.section_of(self.labels["table"]), ".data")
        self.assertIn(program.function_index[self.labels["leaf"]],
                      program.calls[program.function_index[self.labels["a"]]])

    def test_units_from_a_bare_dol_keep_to_one_code_section(self):
        from zkit import units
        proposal = units.propose(Program.from_image(GameCube(), self.dol))
        self.assertEqual({u["section"] for u in proposal["units"] if u["start_key"] < TEXT}, {".init"})
        self.assertTrue(all(u["end_key"] <= TEXT or u["start_key"] >= TEXT for u in proposal["units"]))
        with tempfile.TemporaryDirectory() as folder:
            text = units.write_splits(proposal, Path(folder) / "splits.txt").read_text()
        self.assertIn(f".init        start:0x{INIT:08X}", text)


class UnitNameTests(unittest.TestCase):
    def test_one_windows_tree_in_any_case_loses_its_checkout_and_drive(self):
        from zkit import units
        game = [f"C:/Monolithsoft/BF2/prog/application/BF2/gf/menu/menu_{i}.cpp" for i in range(9)]
        paths = game + ["C:/MonolithSoft/BF2/prog/libs/mcl/mm_lib/source/mm_math/mm_cube.cpp",
                        "C:/Monolithsoft/BF2/prog/application/BF2//../../libs/anmlib/src\\anmlib/base/anm_array.h",
                        "C:/MonolithSoft/BF2/prog/libs/mcl/mm_lib/project/win/../../source\\mm_math/mm_mat44.h"]
        roots = units._roots(paths)
        self.assertEqual([units._unit_name(p, roots) for p in paths[8:]],
                         ["application/BF2/gf/menu/menu_8.cpp", "libs/mcl/mm_lib/source/mm_math/mm_cube.cpp",
                          "libs/anmlib/src/anmlib/base/anm_array.h", "libs/mcl/mm_lib/source/mm_math/mm_mat44.h"])
        self.assertEqual(units._unit_name("D:/main.cpp", []), "main.cpp")     # a unit name never holds a drive


if __name__ == "__main__":
    unittest.main()
