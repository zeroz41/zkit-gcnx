import support  # noqa: F401  (isolates config, cache and state)
import tempfile
import unittest
from pathlib import Path

from zkit import delink, ppc
from zkit.elf import Elf

DATA = 0x80500000
IN_IMAGE = lambda address: 0x80003100 <= address < 0x80600000
SDA = {13: 0x805D8000, 2: 0x805E0000}


def lis(rd, value): return (15 << 26) | (rd << 21) | (((value + 0x8000) >> 16) & 0xFFFF)
def addi(rd, ra, value): return (14 << 26) | (rd << 21) | (ra << 16) | (value & 0xFFFF)
def addic(rd, ra, value): return (12 << 26) | (rd << 21) | (ra << 16) | (value & 0xFFFF)
def lwz(rd, offset, ra): return (32 << 26) | (rd << 21) | (ra << 16) | (offset & 0xFFFF)
def lfs(fd, offset, ra): return (48 << 26) | (fd << 21) | (ra << 16) | (offset & 0xFFFF)
def stfsx(fs, ra, rb): return (31 << 26) | (fs << 21) | (ra << 16) | (rb << 11) | (663 << 1)
def b(pc, target, link=False): return (18 << 26) | ((target - pc) & 0x03FFFFFC) | int(link)
def beq(pc, target): return (16 << 26) | (12 << 21) | (2 << 16) | ((target - pc) & 0xFFFC)
BLR = 0x4E800020
START = 0x80010000


def relocs(words, start=START):
    found, cleared = ppc.code_relocations(words, start, SDA, IN_IMAGE)
    return [(r.offset - start, r.kind, r.target) for r in found], cleared


class RelocationTests(unittest.TestCase):
    def test_pairs_and_small_data(self):
        words = [lis(3, DATA + 0x10), addi(3, 3, DATA + 0x10), lwz(4, -0x7FF0, 13), lfs(1, 8, 2), BLR]
        found, cleared = relocs(words)
        self.assertEqual(found, [(2, ppc.ADDR16_HA, DATA + 0x10), (6, ppc.ADDR16_LO, DATA + 0x10),
                                 (8, ppc.EMB_SDA21, SDA[13] - 0x7FF0), (12, ppc.EMB_SDA21, SDA[2] + 8)])
        self.assertEqual(cleared[START], lis(3, 0))
        self.assertEqual(cleared[START + 8], lwz(4, 0, 0))     # base register and offset cleared

    def test_no_pairing_on_a_path_the_lis_does_not_reach(self):
        # lis r3; b over; [r3 reloaded elsewhere] lwz r12,0(r3): the lwz follows a jump, not the lis
        words = [lis(3, DATA), b(START + 4, START + 12), lwz(12, 0, 3), BLR]
        found, _ = relocs(words)
        self.assertEqual(found, [])

    def test_merge_keeps_what_both_paths_agree_on(self):
        # lis r4 before a branch; both paths reach the use: paired. A lis on one path only: not paired.
        words = [lis(4, DATA + 0x40), beq(START + 4, START + 12), lis(5, DATA), lwz(6, DATA + 0x40, 4),
                 lwz(7, DATA, 5), BLR]
        found, _ = relocs(words)
        self.assertIn((14, ppc.ADDR16_LO, DATA + 0x40), found)
        self.assertNotIn((18, ppc.ADDR16_LO, DATA), [f for f in found])
        self.assertEqual([f for f in found if f[1] == ppc.ADDR16_HA], [(2, ppc.ADDR16_HA, DATA + 0x40)])

    def test_recursion_and_calls_out_keep_relocations_branches_inside_do_not(self):
        words = [b(START, START, link=True), beq(START + 4, START + 12), b(START + 8, 0x80020000, link=True), BLR]
        found, cleared = relocs(words)
        self.assertEqual(found, [(0, ppc.REL24, START), (8, ppc.REL24, 0x80020000)])
        self.assertEqual(cleared[START], 0x48000001)

    def test_addic_low_half_and_float_register_fields(self):
        # addic is a low half too; stfsx f2 writes no general register, so r2 stays the small-data base
        words = [lis(3, DATA + 0x0C30), addic(3, 3, DATA + 0x0C30), stfsx(2, 4, 5), lfs(1, 0x18, 2), BLR]
        found, _ = relocs(words)
        self.assertEqual(found, [(2, ppc.ADDR16_HA, DATA + 0x0C30), (6, ppc.ADDR16_LO, DATA + 0x0C30),
                                 (12, ppc.EMB_SDA21, SDA[2] + 0x18)])

    def test_absolute_branch_is_not_a_relocation(self):
        found, _ = relocs([(18 << 26) | 0x60 | 2, BLR])          # ba 0x60: a fixed vector
        self.assertEqual(found, [])

    def test_constant_lis_is_not_a_relocation(self):
        found, _ = relocs([lis(3, 0x43300000), addi(3, 3, 0x43300000), BLR])
        self.assertEqual(found, [])


class DataPointerTests(unittest.TestCase):
    def test_evidence(self):
        functions = [delink.Entry(START, 0x40, "f"), delink.Entry(START + 0x40, 0x20, "g")]
        data = [delink.Entry(DATA, 8, "table"), delink.Entry(DATA + 0x20, 0x10, "text", data="string")]
        symbols = delink.Symbols(functions, data, lambda a: f"{a:08X}")
        words = {DATA - 0x10: START, DATA - 0xC: START + 0x10, DATA - 8: START + 0x14, DATA - 4: DATA + 4,
                 DATA + 0x20: START + 0x40, DATA + 0x30: 0x80010003, DATA + 0x34: 0x80000000}
        blob = b"".join(words.get(DATA - 0x10 + i * 4, 0).to_bytes(4, "big") for i in range(0x14))
        read = lambda address, size: blob[address - (DATA - 0x10):address - (DATA - 0x10) + size]
        in_code = lambda address: 0x80003100 <= address < 0x80400000
        found = delink.data_pointers(read, DATA - 0x10, DATA + 0x40, symbols, IN_IMAGE, in_code)
        self.assertEqual(found, [(DATA - 0x10, START, "function"), (DATA - 0xC, START + 0x10, "jump table"),
                                 (DATA - 8, START + 0x14, "jump table"), (DATA - 4, DATA + 4, "inside object")])


class WriterTests(unittest.TestCase):
    def test_big_endian_object_reads_back(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unit.o"
            code = b"".join(w.to_bytes(4, "big") for w in (0x48000001, BLR))
            symbols = [{"name": "f", "section": ".text", "value": 0, "size": 8, "kind": "func", "bind": "global",
                        "address": START},
                       {"name": "callee", "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
                        "address": 0},
                       {"name": "vt", "section": ".data", "value": 0, "size": 4, "kind": "object", "bind": "local",
                        "address": DATA}]
            delink.write_object(delink.PPC, [(".text", 1, code, 4), (".data", 1, bytes(4), 8), (".bss", 8, 16, 8)],
                                symbols, {".text": [(0, ppc.REL24, 1, 0)], ".data": [(0, ppc.ADDR32, 0, 0)]}, path,
                                source="unit.cpp")
            elf = Elf.load(path)
            self.assertEqual((elf.bits, elf.endian, elf.machine_id), (32, ">", 20))
            text = elf.section(".text")
            self.assertEqual(elf.data(text), code)
            self.assertEqual(elf.section(".bss").size, 16)
            [call] = elf.relocations(text)
            self.assertEqual((call.offset, call.type, elf.symbols[call.symbol].name), (0, ppc.REL24, "callee"))
            [pointer] = elf.relocations(elf.section(".data"))
            self.assertEqual(elf.symbols[pointer.symbol].name, "f")
            self.assertEqual(elf.functions()["f"].size, 8)
            local = next(s for s in elf.symbols if s.name == "vt")
            self.assertEqual(local.bind, "local")


if __name__ == "__main__":
    unittest.main()
