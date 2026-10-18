import support  # noqa: F401  (isolates config, cache and state)
import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import cli, delink, ppc, signatures
from zkit.elf import Elf
from zkit.platform import GameCube
from zkit.program import Program

TEXT, DATA = 0x80003100, 0x80100000
BLR, PROLOGUE, EPILOGUE = 0x4E800020, [0x9421FFF0, 0x7C0802A6, 0x90010014], [0x80010014, 0x7C0803A6, 0x38210010]


def li(rd, value): return (14 << 26) | (rd << 21) | (value & 0xFFFF)
def add(rd, ra, rb): return (31 << 26) | (rd << 21) | (ra << 16) | (rb << 11) | (266 << 1)
def mullw(rd, ra, rb): return (31 << 26) | (rd << 21) | (ra << 16) | (rb << 11) | (235 << 1)
def stw(rs, offset, ra): return (36 << 26) | (rs << 21) | (ra << 16) | (offset & 0xFFFF)


# A function body: words, or ("bl", function), ("lis", register, symbol), ("addi", rd, ra, symbol), ("stw", rs, ra,
# symbol) whose fields the image builder fills in with the symbol's address.
HELPER = [("lis", 4, "gLib"), ("stw", 3, 4, "gLib"), BLR]
WORK = PROLOGUE + [li(3, 7), ("bl", "LibHelper"), add(3, 3, 3), mullw(4, 3, 3), add(5, 4, 3), mullw(6, 5, 4),
                   add(7, 6, 5), ("lis", 8, "gLib"), ("addi", 8, 8, "gLib"), stw(7, 0, 8), li(3, 0)] + EPILOGUE + [BLR]
SET = [stw(4, 8, 3), BLR]
PANIC = PROLOGUE + [("lis", 3, "msg"), ("addi", 3, 3, "msg"), ("bl", "LibHelper")] + EPILOGUE + [BLR]
PANIC_V2 = PROLOGUE + [li(4, 1), ("lis", 3, "msg"), ("addi", 3, 3, "msg"), ("bl", "LibHelper")] + EPILOGUE + [BLR]
STATIC_A = PROLOGUE + [li(3, 1)] + [add(3, 3, 3)] * 12 + EPILOGUE + [BLR]
STATIC_B = PROLOGUE + [li(3, 2)] + [mullw(3, 3, 3)] * 12 + EPILOGUE + [BLR]
GAME = PROLOGUE + [li(3, 9)] + [mullw(3, 3, 4), add(3, 3, 4)] * 8 + EPILOGUE + [BLR]
TEXTS = {"msg": b"LibPanic: failed!!\0\0"}


class Image:
    """A DOL assembled from (name, body, scope, unit) functions, a 4-byte global `gLib` and strings."""

    def __init__(self, functions):
        self.functions = functions

    def build(self, root: Path, stem: str, hide: bool = False) -> tuple[Path, Path]:
        addresses, cursor = {}, TEXT
        for name, body, _, _ in self.functions:
            addresses.setdefault(name, cursor)
            cursor += 4 * len(body)
        addresses["gLib"], data = DATA, bytearray(8)
        for name, raw in TEXTS.items():
            addresses[name] = DATA + len(data)
            data += raw
        text = bytearray()
        for name, body, _, _ in self.functions:
            for word in body:
                pc = TEXT + len(text)
                if isinstance(word, tuple):
                    kind, *rest = word
                    value = addresses[rest[-1]]
                    ha, lo = ((value + 0x8000) >> 16) & 0xFFFF, value & 0xFFFF
                    word = {"bl": lambda: (18 << 26) | ((value - pc) & 0x3FFFFFC) | 1,
                            "lis": lambda: (15 << 26) | (rest[0] << 21) | ha,
                            "addi": lambda: (14 << 26) | (rest[0] << 21) | (rest[1] << 16) | lo,
                            "stw": lambda: (36 << 26) | (rest[0] << 21) | (rest[1] << 16) | lo}[kind]()
                text += struct.pack(">I", word)
        header = bytearray(0x100)
        struct.pack_into(">I", header, 0x00, 0x100)
        struct.pack_into(">I", header, 0x1C, 0x100 + len(text))
        struct.pack_into(">I", header, 0x48, TEXT)
        struct.pack_into(">I", header, 0x64, DATA)
        struct.pack_into(">I", header, 0x90, len(text))
        struct.pack_into(">I", header, 0xAC, len(data))
        struct.pack_into(">I", header, 0xE0, TEXT)
        dol = root / f"{stem}.dol"
        dol.write_bytes(bytes(header) + bytes(text) + bytes(data))
        lines, splits, cursor = [], {}, TEXT
        for name, body, scope, unit in self.functions:
            shown = f"fn_{cursor:08X}" if hide else name
            lines.append(f"{shown} = .text:0x{cursor:08X}; // type:function size:0x{4 * len(body):X} scope:{scope}")
            splits.setdefault(unit, []).append((cursor, cursor + 4 * len(body)))
            cursor += 4 * len(body)
        lines.append(f"{'lbl_%08X' % DATA if hide else 'gLib'} = .data:0x{DATA:08X}; // type:object size:0x4")
        for name, raw in TEXTS.items():
            lines.append(f"lbl_{addresses[name]:08X} = .data:0x{addresses[name]:08X}; // type:object "
                         f"size:0x{len(raw):X} data:string")
        symbols = root / f"{stem}.symbols.txt"
        symbols.write_text("\n".join(lines) + "\n", encoding="utf-8")
        (root / f"{stem}.splits.txt").write_text("".join(
            f"{unit}:\n" + "".join(f"\t.text       start:0x{s:08X} end:0x{e:08X}\n" for s, e in rows)
            for unit, rows in splits.items()), encoding="utf-8")
        return dol, symbols


DONOR = [("LibHelper", HELPER, "global", "lib/helper.c"), ("LibWork", WORK, "global", "lib/work.c"),
         ("LibSet", SET, "global", "lib/work.c"), ("LibPanic", PANIC, "global", "lib/work.c"),
         ("Static", STATIC_A, "local", "lib/a.c"), ("Static", STATIC_B, "local", "lib/b.c")]
TARGET = [("GameCopy", SET, "global", "game.c"), ("GameBig", GAME, "global", "game.c"),
          ("LibHelper", HELPER, "global", "lib/helper.c"), ("LibWork", WORK, "global", "lib/work.c"),
          ("LibSet", SET, "global", "lib/work.c"), ("LibPanic", PANIC_V2, "global", "lib/work.c"),
          ("Static", STATIC_B, "local", "lib/b.c"), ("Static", STATIC_A, "local", "lib/a.c")]


class SignatureTests(unittest.TestCase):
    """A donor build names a target whose names are hidden: by shape, by what a matched function refers to, by
    layout, by the texts a changed function uses, and file-local names per file; a game function that merely
    looks like a library one stays unnamed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def donor(self) -> signatures.Donor:
        dol, symbols = Image(DONOR).build(self.root, "donor")
        return signatures.build("lib", dol, symbols, splits=self.root / "donor.splits.txt")

    def target(self, functions=TARGET) -> tuple[Program, dict[str, list[int]]]:
        dol, symbols = Image(functions).build(self.root, "target", hide=True)
        program = Program.from_symbols(GameCube(), dol, symbols)
        where: dict[str, list[int]] = {}
        cursor = TEXT
        for name, body, _, _ in functions:
            where.setdefault(name, []).append(cursor)
            cursor += 4 * len(body)
        return program, where

    def test_names_from_a_donor(self):
        program, at = self.target()
        found = {p.address: p for p in signatures.propose(program, [self.donor()])}
        named = {a: p.name for a, p in found.items()}
        self.assertEqual(named[at["LibWork"][0]], "LibWork")
        self.assertEqual(found[at["LibWork"][0]].evidence, "shape")
        self.assertEqual(named[at["LibHelper"][0]], "LibHelper")          # its caller's reference names it
        self.assertEqual(found[at["LibHelper"][0]].source, at["LibWork"][0])
        self.assertEqual(named[DATA], "gLib")
        self.assertEqual(found[DATA].kind, "object")
        self.assertEqual(named[at["LibSet"][0]], "LibSet")                # short: placed by its neighbour
        self.assertIn("layout", found[at["LibSet"][0]].evidence)
        self.assertEqual(named[at["LibPanic"][0]], "LibPanic")            # changed code, same texts
        self.assertEqual(found[at["LibPanic"][0]].evidence, "strings")
        self.assertEqual([named.get(a) for a in at["Static"]], ["Static", "Static"])   # one per file
        self.assertEqual({found[a].unit for a in at["Static"]}, {"lib/a.c", "lib/b.c"})
        self.assertNotIn(at["GameCopy"][0], named)                        # same code as LibSet, elsewhere
        self.assertNotIn(at["GameBig"][0], named)

    def test_two_copies_of_one_shape_stay_unnamed(self):
        program, at = self.target([("LibHelper", HELPER, "global", "a.c"), ("LibWork", WORK, "global", "a.c"),
                                   ("Other", GAME, "global", "a.c"), ("LibWork", WORK, "global", "b.c")])
        names = {p.name for p in signatures.propose(program, [self.donor()])}
        self.assertNotIn("LibWork", names)

    def test_contradicting_evidence_withdraws_the_name(self):
        """Two matched callers whose donors name their common callee differently: the callee is named by
        neither, nor afterwards by its own shape; the callers keep their names."""
        other = PROLOGUE + [li(3, 8), ("bl", "LibHelper")] + [add(3, 3, 3)] * 10 + EPILOGUE + [BLR]
        dol, symbols = Image(DONOR + [("LibOther", other, "global", "lib/other.c")]).build(self.root, "donor")
        donor = signatures.build("lib", dol, symbols, splits=self.root / "donor.splits.txt")
        for signature in donor.signatures:
            if signature.key == "LibOther":
                signature.references = tuple(signatures.Reference(r.offset, r.kind, ("n", "Renamed", 0))
                                             for r in signature.references)
        program, at = self.target(TARGET + [("LibOther", other, "global", "lib/other.c")])
        named = {p.address: p.name for p in signatures.propose(program, [donor])}
        self.assertNotIn(at["LibHelper"][0], named)
        self.assertEqual((named[at["LibWork"][0]], named[at["LibOther"][0]]), ("LibWork", "LibOther"))

    def test_cache_round_trip_and_own_image_left_out(self):
        donor = self.donor()
        signatures.save(donor)
        self.assertIn("lib", signatures.listed())
        loaded = signatures.load("lib")
        self.assertEqual([(s.key, s.shape, s.references, s.before, s.after) for s in loaded.signatures],
                         [(s.key, s.shape, s.references, s.before, s.after) for s in donor.signatures])
        program = Program.from_symbols(GameCube(), self.root / "donor.dol", self.root / "donor.symbols.txt")
        self.assertEqual(signatures.propose(program, [loaded]), [])        # the donor's own original
        self.assertTrue(signatures.remove("lib"))

    def test_objects_and_libraries_give_the_same_shape(self):
        """A relocatable object of LibWork (relocations to LibHelper and gLib, fields cleared) has the shape the
        linked function has, in a file or as an archive member."""
        image = self.donor()
        words = []
        relocations = []
        for index, word in enumerate(WORK):
            if isinstance(word, tuple):
                kind = {"bl": ppc.REL24, "lis": ppc.ADDR16_HA, "addi": ppc.ADDR16_LO}[word[0]]
                target = 1 if word[0] == "bl" else 2
                relocations.append((4 * index + (0 if kind == ppc.REL24 else 2), kind, target, 0))
                word = 0x48000001 if word[0] == "bl" else (15 << 26) | (word[1] << 21) if word[0] == "lis" \
                    else (14 << 26) | (word[1] << 21) | (word[2] << 16)
            words.append(word)
        path = self.root / "work.o"
        delink.write_object(delink.PPC, [(".text", 1, struct.pack(f">{len(words)}I", *words), 4)], [
            {"name": "LibWork", "section": ".text", "value": 0, "size": 4 * len(words), "kind": "func",
             "bind": "global", "address": 0},
            {"name": "LibHelper", "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
             "address": 0},
            {"name": "gLib", "section": None, "value": 0, "size": 0, "kind": "notype", "bind": "global",
             "address": 0}], {".text": [(o, k, s, a) for o, k, s, a in relocations]}, path)
        member = path.read_bytes()
        archive = self.root / "lib.a"
        archive.write_bytes(b"!<arch>\n" + f"{'work.o/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(member):<10}`\n"
                            .encode() + member + (b"\n" if len(member) % 2 else b""))
        linked = next(s for s in image.signatures if s.key == "LibWork")
        for source in (path, archive):
            donor = signatures.build("objects", objects=[source])
            compiled = next(s for s in donor.signatures if s.key == "LibWork")
            self.assertEqual(compiled.shape, linked.shape)
            self.assertEqual([r.token for r in compiled.references], [r.token for r in linked.references])

    def test_command_line_builds_lists_and_matches(self):
        dol, symbols = Image(DONOR).build(self.root, "donor")
        target_dol, target_symbols = Image(TARGET).build(self.root, "target", hide=True)
        manifest = self.root / "project.json"
        manifest.write_text(json.dumps({
            "schema_version": 1, "id": "signatures", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
            "targets": {"t": {"repository": "decomp", "module": "main", "original": target_dol.name,
                              "symbols": target_symbols.name}}}), encoding="utf-8")

        def run(*argv) -> str:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(list(argv)), 0)
            return out.getvalue()
        self.assertIn("6 function signatures", run("signatures", "build", "cli-lib", "--image", str(dol),
                                                   "--symbols", str(symbols)))
        self.assertIn("cli-lib", run("signatures", "list"))
        said = run("--project", str(manifest), "signatures", "match")
        self.assertIn("LibWork", said)
        self.assertIn("new", said)
        data = json.loads(run("--project", str(manifest), "--json", "names", "--signatures"))
        self.assertIn("LibWork", {row["name"] for row in data["rows"]})
        self.assertIn("removed", run("signatures", "remove", "cli-lib"))


if __name__ == "__main__":
    unittest.main()
