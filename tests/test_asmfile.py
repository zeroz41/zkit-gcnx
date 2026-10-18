import support  # noqa: F401  (isolates config, cache and state)
import dataclasses
import os
import shutil
import struct
import unittest

from test_ppc import BLR, DATA, IN_IMAGE, SDA, START, addi, b, beq, lfs, lis
from zkit import asmfile, delink, ppc

OBJDUMP = os.environ.get("ZKIT_OBJDUMP") or shutil.which("powerpc-eabi-objdump")


def image(words: dict[int, int], data: dict[int, bytes]):
    """A delinker Image over hand-placed code and data."""
    def read(address: int, size: int) -> bytes:
        out = bytearray()
        for offset in range(0, size, 4):
            if address + offset in words:
                out += struct.pack(">I", words[address + offset])
            else:
                chunk = next((blob[address + offset - start:address + offset - start + 4]
                              for start, blob in data.items() if start <= address + offset < start + len(blob)), None)
                out += chunk if chunk is not None else bytes(4)
        return bytes(out[:size])
    functions = [delink.Entry(START, 0x20, "update"), delink.Entry(0x80020000, 4, "callee")]
    objects = [delink.Entry(DATA, 8, "table"), delink.Entry(SDA[2] + 8, 4, "scale")]
    symbols = delink.Symbols(functions, objects, lambda a: f"{a:08X}")

    def code(start, size, resolved):
        found, cleared = ppc.code_relocations(list(struct.unpack(f">{size // 4}I", read(start, size))), start, SDA,
                                              IN_IMAGE)
        return [(r.offset, r.kind, r.target, False) for r in found], cleared
    sections = lambda a: ".sdata2" if a >= SDA[2] - 0x8000 else ".data"
    return delink.Image(delink.PPC, 0, read, symbols, IN_IMAGE, code, lambda s, e: [], lambda a: f"{a:08X}", sections)


@unittest.skipUnless(OBJDUMP, "needs powerpc-eabi-objdump (or ZKIT_OBJDUMP)")
class AsmFileTests(unittest.TestCase):
    def test_references_become_symbols(self):
        body = [lis(3, DATA), addi(3, 3, DATA), lfs(1, 8, 2), beq(START + 12, START + 20),
                b(START + 16, 0x80020000, link=True), BLR, BLR, BLR]
        words = {START + 4 * i: w for i, w in enumerate(body)}
        words[0x80020000] = BLR
        img = image(words, {DATA: bytes(range(8)), SDA[2] + 8: struct.pack(">f", 1.5)})
        referenced: set[int] = set()
        lines = asmfile.function(img, OBJDUMP, START, 0x20, referenced)
        text = "\n".join(lines)
        self.assertIn(".fn update, global", text)
        self.assertIn("lis r3, table@ha", text)
        self.assertIn("addi r3, r3, table@l", text)
        self.assertIn("lfs f1, scale@sda21(r2)", text)
        self.assertIn("bl callee", text)
        self.assertIn(f".L_{START + 20:08X}:", text)
        self.assertRegex(text, r"beq\S* \.L_" + f"{START + 20:08X}")
        self.assertEqual(referenced, {DATA, SDA[2] + 8})
        block = asmfile.data(img, SDA[2] + 8, set())
        self.assertEqual(block, [".obj scale, global", "\t.4byte 0x3FC00000", ".endobj scale"])

    def test_switch_cases_are_labelled_from_their_jump_table(self):
        body = [lis(3, DATA), addi(3, 3, DATA), BLR, BLR, BLR, BLR, BLR, BLR]   # cases reached only by the table
        words = {START + 4 * i: w for i, w in enumerate(body)}
        img = dataclasses.replace(image(words, {DATA: struct.pack(">II", START + 12, START + 16)}),
                                  pointers=lambda s, e: [(DATA, START + 12, "code"), (DATA + 4, START + 16, "code")])
        text = "\n".join(asmfile.function(img, OBJDUMP, START, 0x20, set()))
        self.assertIn(f".L_{START + 12:08X}:", text)
        self.assertIn(f".L_{START + 16:08X}:", text)


if __name__ == "__main__":
    unittest.main()
