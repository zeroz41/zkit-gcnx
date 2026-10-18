import support  # noqa: F401  (isolates config, cache and state)
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import delink, link, ppc
from zkit.elf import Elf
from zkit.gc import Dol

BLR = 0x4E800020


def words(*values: int) -> bytes:
    return b"".join(v.to_bytes(4, "big") for v in values)


def executable(path: Path, sections: list[tuple[str, int, int, int, bytes | int]], entry: int) -> Path:
    """A linked big-endian PowerPC ELF: (name, sh_type, sh_flags, address, data or NOBITS size) per section."""
    names = b"\0" + b"".join(s[0].encode() + b"\0" for s in sections) + b".shstrtab\0"
    body, headers = bytearray(52), [bytes(40)]
    for name, kind, flags, address, data in sections:
        offset = len(body)
        size = data if kind == 8 else len(data)
        body += b"" if kind == 8 else data
        headers.append(struct.pack(">10I", names.index(name.encode() + b"\0"), kind, flags, address, offset, size,
                                   0, 0, 4, 0))
    headers.append(struct.pack(">10I", names.index(b".shstrtab\0"), 3, 0, 0, len(body), len(names), 0, 0, 1, 0))
    body += names
    shoff = len(body) + (-len(body) % 4)
    body += bytes(shoff - len(body)) + b"".join(headers)
    body[:52] = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 2, 20, 1, entry, 0, shoff,
                                                               0x80000000, 52, 0, 0, 40, len(headers),
                                                               len(headers) - 1)
    path.write_bytes(bytes(body))
    return path


def section(name, start, end, kind="data", content=None, tables=None):
    content = end if content is None else content
    return link.OutputSection(name, start, end, kind, content, content if tables is None else tables)


def names(*addresses):
    return delink.Symbols([], [delink.Entry(a, 4, f"d_{a:x}") for a in addresses], lambda a: f"{a:08X}")


def unit(name, **ranges):
    out = delink.Unit(name)
    for section_name, span in ranges.items():
        out.ranges["." + section_name].append(span)
    return out


class CommentTests(unittest.TestCase):
    def write(self, comment):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unit.o"
            symbols = [{"name": "f", "section": ".text", "value": 0, "size": 8, "kind": "func", "bind": "global",
                        "address": 0x80003100},
                       {"name": "w", "section": ".data", "value": 2, "size": 2, "kind": "object", "bind": "weak",
                        "address": 0x80004002},
                       {"name": "callee", "section": None, "value": 0, "size": 0, "kind": "notype",
                        "bind": "global", "address": 0}]
            delink.write_object(delink.PPC, [(".text", 1, words(0x48000001, BLR), 4), (".data", 1, bytes(8), 8)],
                                symbols, {".text": [(0, ppc.REL24, 2, 0)]}, path, source="unit.c", comment=comment)
            return Elf.load(path)

    def test_records_follow_the_symbol_table(self):
        elf = self.write(10)
        data = elf.data(elf.section(".comment"))
        self.assertEqual(data[:0x16], b"CodeWarrior\x0a\x02\x04\x07\x01\x01\x02\x00\x16\x2c\x00")
        self.assertEqual(len(data), 0x2C + 8 * len(elf.symbols))
        records = {s.name or s.kind + str(s.section): struct.unpack_from(">IBBH", data, 0x2C + 8 * s.index)[:3]
                   for s in elf.symbols}
        self.assertEqual(records["unit.c"], (1, 0, 0))
        self.assertEqual(records["section2"], (8, 0, 0))
        self.assertEqual(records["f"], (4, 0, 8))
        self.assertEqual(records["w"], (1, 0xD, 8))
        self.assertEqual(records["callee"], (0, 0, 0))
        self.assertEqual(elf.section(".note.split").type, delink.SHT_MWCATS)

    def test_newer_linkers_keep_the_note_and_plain_objects_carry_no_comment(self):
        self.assertEqual(self.write(14).section(".note.split").type, 7)
        plain = self.write(None)
        self.assertIsNone(plain.section(".comment"))
        self.assertEqual(plain.section(".note.split").type, 7)
        with self.assertRaises(ValueError):
            self.write(9)


class UnitTests(unittest.TestCase):
    def test_gaps_padding_and_linker_tables(self):
        image = bytearray(0x200)
        image[0x60:0x64] = b"\1\2\3\4"     # data no unit claims
        read = lambda address, size: bytes(image[address - 0x1000:address - 0x1000 + size])
        sections = [section(".data", 0x1000, 0x1100), section(".ctors", 0x1100, 0x1120, content=0x1108,
                                                               tables=0x110C)]
        units = [unit("a.c", data=(0x1000, 0x1014), ctors=(0x1100, 0x1104)),
                 unit("b.c", data=(0x1018, 0x1040)),        # 4 zero bytes before it: 8-byte alignment
                 unit("c.c", data=(0x1080, 0x10A0), ctors=(0x1104, 0x110C))]
        out = link.link_units(units, sections, read, names(0x1000, 0x1018, 0x10E0))
        by_name = {u.name: dict(u.ranges) for u in out}
        self.assertEqual(by_name["gap_data_00001040"], {".data": [(0x1040, 0x1064)]})   # data, then padding
        self.assertEqual(by_name["gap_data_000010A0"], {".data": [(0x10A0, 0x10E4)]})   # a symbol, then padding
        self.assertEqual(by_name["c.c"][".ctors"], [(0x1104, 0x1108)])     # the terminator is the linker's
        self.assertEqual(len(out), 5)
        pair = [unit("x.c", data=(0x1000, 0x1004)), unit("y.c", data=(0x1008, 0x1100), ctors=(0x1100, 0x1108))]
        self.assertEqual(len(link.link_units(pair, sections, read, names(0x1000, 0x1008))), 2)
        named = link.link_units(pair, sections, read, names(0x1000, 0x1004, 0x1008))  # a zero object, not padding
        self.assertEqual([u.name for u in named], ["x.c", "y.c", "gap_data_00001004"])
        with self.assertRaises(ValueError):
            link.link_units([unit("a.c", data=(0x1000, 0x1020)), unit("b.c", data=(0x1010, 0x1030))],
                            sections[:1], read, names())

    def test_order_agrees_with_every_section(self):
        sections = [section(".text", 0x1000, 0x1100, "code"), section(".ctors", 0x1100, 0x1110),
                    section(".data", 0x1200, 0x1300)]
        runtime = unit("runtime.c", text=(0x1080, 0x1100), ctors=(0x1100, 0x1104))
        units = [unit("b.c", text=(0x1040, 0x1080), data=(0x1240, 0x1300)), runtime,
                 unit("a.c", text=(0x1000, 0x1040), ctors=(0x1104, 0x1108), data=(0x1200, 0x1240))]
        self.assertEqual([u.name for u in link.link_order(units, sections)], ["a.c", "b.c", "runtime.c"])
        crossed = [unit("a.c", text=(0x1000, 0x1040), data=(0x1240, 0x1300)),
                   unit("b.c", text=(0x1040, 0x1080), data=(0x1200, 0x1240))]
        with self.assertRaises(ValueError):
            link.link_order(crossed, sections)

    def test_alignment_lands_each_part_on_its_start(self):
        sections = [section(".text", 0x1000, 0x1120, "code"), section(".data", 0x1120, 0x1200, content=0x1180)]
        order = [unit("a.c", text=(0x1000, 0x1034), data=(0x1120, 0x1130)),
                 unit("b.c", text=(0x1040, 0x1104), data=(0x1130, 0x1180))]
        sizes = {("a.c", ".text"): 0x34, ("a.c", ".data"): 0x10, ("b.c", ".text"): 0xC4, ("b.c", ".data"): 0x48}
        out, script, problems = link.alignments(order, sections, sizes, {})
        self.assertEqual(out["b.c"][".text"], 16)         # 0x1034 -> 0x1040
        self.assertEqual(out["b.c"][".data"], 8)
        self.assertEqual(script, [(".text", 4), (".data", 32)])
        self.assertEqual(problems, [])
        _, _, problems = link.alignments(order, sections, sizes, {("b.c", ".text"): 4})
        self.assertEqual(len(problems), 1)
        self.assertIn("would land at 0x1034", problems[0])


class ScriptAndDolTests(unittest.TestCase):
    def test_script(self):
        text = link.linker_script([(".init", 4), (".text", 32), (".sbss2", 16)], 0x80003100, 0x10004,
                                  ["keep_me", "@28@__dt__1AFv"])
        self.assertIn("text : origin = 0x80003100", text)
        self.assertIn(".text ALIGN(0x20):{}", text)
        self.assertIn("_stack_end = _f_sbss2 + SIZEOF(.sbss2);", text)
        self.assertIn("_stack_addr = (_stack_end + 0x10004 + 0x7) & ~0x7;", text)
        self.assertIn("FORCEACTIVE\n{\n    keep_me\n    @28@__dt__1AFv\n}", text)

    def test_dol_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            path = executable(Path(temp) / "main.elf", [
                (".init", 1, 6, 0x80003100, words(BLR)), (".text", 1, 6, 0x80003120, words(1, 2, 3, BLR)),
                (".data", 1, 3, 0x80003140, b"abc"), (".bss", 8, 3, 0x80003160, 0x10),
                (".sdata", 1, 3, 0x80003170, words(7)), (".sbss2", 8, 3, 0x80003180, 8)], 0x80003100)
            raw = link.dol_from_elf(Elf.load(path))
            dol = Dol(raw)
            self.assertEqual([(s.kind, s.address, s.size) for s in dol.sections],
                             [("text", 0x80003100, 32), ("text", 0x80003120, 32), ("data", 0x80003140, 32),
                              ("data", 0x80003170, 32)])
            self.assertEqual(dol.bss, (0x80003160, 0x28))
            self.assertEqual(dol.entry, 0x80003100)
            self.assertEqual(dol.read(0x80003120, 16), words(1, 2, 3, BLR))
            self.assertEqual(len(raw), 0x100 + 4 * 32)
            changed = bytearray(raw)
            changed[0x100 + 32 + 8] ^= 1
            self.assertEqual(link.first_difference(bytes(changed), raw), (0x100 + 40, 0x80003128))
            self.assertIsNone(link.first_difference(raw, raw))


class ProjectFileTests(unittest.TestCase):
    def test_link_command_from_build_ninja(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build/tools").mkdir(parents=True)
            (root / "build/tools/wibo").write_text("")
            (root / "build.ninja").write_text(
                "ldflags = -fp hardware -nodefaults\nmw_version = GC/2.6\n\nrule link\n"
                "  command = build/tools/wibo build/compilers/$mw_version/mwldeppc.exe $\n"
                "      $ldflags -o $out @$out.rsp\n  rspfile = $out.rsp\n\n"
                "build build/G/main.elf: link build/G/a.o $\n    build/G/b.o | build/G/ldscript.lcf\n"
                "  ldflags = $ldflags -lcf build/G/ldscript.lcf\n")
            argv = link.linker_command(root, root / "build.ninja", "main")
            self.assertEqual(argv, [str(root / "build/tools/wibo"), "build/compilers/GC/2.6/mwldeppc.exe", "-fp",
                                    "hardware", "-nodefaults"])
            with self.assertRaises(ValueError):
                link.linker_command(root, root / "build.ninja", "other")

    def test_dtk_config(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.yml"
            path.write_text('name: x\nmw_comment_version: 10\n# note\nforce_active:\n  - "@28@f"\n  - g\n'
                            "block_relocations:\n  - source: 0x80001000\n")
            self.assertEqual(link.dtk_config(path), {"force_active": ["@28@f", "g"], "mw_comment_version": 10})
            self.assertEqual(link.dtk_config(Path(temp) / "missing.yml"), {"force_active": []})


class CombineTests(unittest.TestCase):
    """A partly matched unit: the exact function's code and relocations come from the compiled object, global
    targets by name, its local constant where the original relocates the same field; a function whose compiled
    relocation reaches another address stays delinked."""

    def test_combine(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            code = words(0x3C600000, 0xC0230000, 0x48000001, BLR, 0x48000001, BLR)
            original = [{"name": "f", "section": ".text", "value": 0, "size": 16, "kind": "func", "bind": "global",
                         "address": 0x80003100},
                        {"name": "g", "section": ".text", "value": 16, "size": 8, "kind": "func", "bind": "global",
                         "address": 0x80003110},
                        {"name": "lbl_80004000", "section": ".sdata2", "value": 0, "size": 4, "kind": "object",
                         "bind": "local", "address": 0x80004000},
                        {"name": "callee", "section": None, "value": 0, "size": 0, "kind": "notype",
                         "bind": "global", "address": 0}]
            delink.write_object(delink.PPC, [(".text", 1, code, 4), (".sdata2", 1, words(0x3F800000), 8)], original,
                                {".text": [(2, ppc.ADDR16_HA, 2, 0), (6, ppc.ADDR16_LO, 2, 0), (8, ppc.REL24, 3, 0),
                                           (16, ppc.REL24, 3, 0)]}, temp / "d.o", source="u.c", comment=10)
            compiled = [{"name": "f", "section": ".text", "value": 0, "size": 16, "kind": "func", "bind": "global",
                         "address": 0},
                        {"name": "g", "section": ".text", "value": 16, "size": 8, "kind": "func", "bind": "global",
                         "address": 0},
                        {"name": "@12", "section": ".sdata2", "value": 0, "size": 4, "kind": "object", "bind": "local",
                         "address": 0},
                        {"name": "callee", "section": None, "value": 0, "size": 0, "kind": "notype",
                         "bind": "global", "address": 0},
                        {"name": "other", "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
                         "address": 0}]
            delink.write_object(delink.PPC, [(".text", 1, code, 4), (".sdata2", 1, words(0x3F800000), 8)], compiled,
                                {".text": [(2, ppc.ADDR16_HA, 2, 0), (6, ppc.ADDR16_LO, 2, 0), (8, ppc.REL24, 3, 0),
                                           (16, ppc.REL24, 4, 0)]}, temp / "c.o")
            address_of = {"f": 0x80003100, "g": 0x80003110, "callee": 0x80005000, "other": 0x80005100}
            taken, kept = link.combine(temp / "d.o", temp / "c.o", ["f", "g"], temp / "out.o", 10, address_of,
                                       {"f", "g", "callee", "other"})
            self.assertEqual(taken, ["f"])
            self.assertEqual(kept[0][0], "g")
            self.assertIn("reaches other", kept[0][1])
            elf = Elf.load(temp / "out.o")
            text = elf.section(".text")
            self.assertEqual(elf.data(text), code)
            self.assertEqual([(r.offset, r.type, elf.symbols[r.symbol].name) for r in elf.relocations(text)],
                             [(2, ppc.ADDR16_HA, "lbl_80004000"), (6, ppc.ADDR16_LO, "lbl_80004000"),
                              (8, ppc.REL24, "callee"), (16, ppc.REL24, "callee")])
            self.assertIsNotNone(elf.section(".comment"))


if __name__ == "__main__":
    unittest.main()
