"""Twins: unmatched functions with the shape of a matched one, on hand-assembled AArch64 words and a synthetic
GameCube project. No game assets."""
import support  # noqa: F401  (isolates config, cache and state)
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from zkit import twins

TEXT = 0x80003000
WORDS = 20


def a64_function(pc: int, k: int, register: int = 0, changed: int = 0) -> list[int]:
    """stp/mov, then loads, adds and calls whose offsets, constants and targets depend on k; `register` moves the
    loads to another register, `changed` replaces that many adds with a register eor."""
    words = [0xA9BF7BFD, 0x910003FD]                                     # stp x29, x30, [sp, #-16]!; mov x29, sp
    for i in range(6):
        words.append(0xF9400000 | ((i + k) << 10) | (19 << 5) | (i + register) % 8)    # ldr xN, [x19, #8*(i+k)]
        words.append(0x4A020020 if i < changed else 0x11000021 | ((i * 3 + k) << 10))   # eor w0,w1,w2 / add w1,w1,#
        site = pc + 4 * len(words)
        words.append(0x94000000 | (((0x1000 * (k + 1) - site) >> 2) & 0x3FFFFFF))      # bl
    words.append(0x90000008 | ((k & 3) << 29) | (k << 5))                # adrp x8, page
    words += [0xA8C17BFD, 0xD65F03C0]                                    # ldp x29, x30, [sp], #16; ret
    return words


class MaskTests(unittest.TestCase):
    def test_immediates_and_targets_cleared_registers_kept(self):
        self.assertEqual(twins.masked(0x94000010, True), twins.masked(0x97FFFF00, True))          # bl anywhere
        self.assertEqual(twins.masked(0x90000008, True), twins.masked(0xF0001228, True))          # adrp x8
        self.assertNotEqual(twins.masked(0x90000008, True), twins.masked(0x90000009, True))       # adrp x8 / x9
        self.assertEqual(twins.masked(0xF9400660, True), twins.masked(0xF9401260, True))          # ldr offsets
        self.assertNotEqual(twins.masked(0xF9400660, True), twins.masked(0xF9400661, True))       # ldr x0 / x1
        self.assertEqual(twins.form(twins.masked(0xF9400660, True), True),
                         twins.form(twins.masked(0xF9400661, True), True))
        # PowerPC: bl targets and 16-bit immediates cleared, registers kept until the form
        self.assertEqual(twins.masked(0x48000011, False), twins.masked(0x4BFFF0C1, False))
        self.assertEqual(twins.masked(0x38630010, False), twins.masked(0x38637FF0, False))       # addi r3,r3,x
        self.assertNotEqual(twins.masked(0x38630010, False), twins.masked(0x38830010, False))    # addi r4,r3
        self.assertEqual(twins.form(0x38630000, False), twins.form(0x38830000, False))

    def test_exact_and_near_twins(self):
        functions = {0x1000: a64_function(0x1000, 1), 0x2000: a64_function(0x2000, 2),
                     0x3000: a64_function(0x3000, 3, changed=2), 0x4000: a64_function(0x4000, 4, register=3),
                     0x5000: [0xD503201F] * 20}
        shapes = {a: twins.shape(w, True) for a, w in functions.items()}
        forms = twins._forms(shapes, True)
        sketches = {a: twins.sketch(f) for a, f in forms.items()}
        index = twins.Index(shapes, forms, sketches, [0x1000])
        found = lambda a, count=1: index.near(shapes[a], forms[a], sketches[a], 0.85, count)
        self.assertEqual(found(0x2000), [(1.0, [0x1000])])                       # exact: the same shape
        (ratio, members), = found(0x3000)                                        # two adds became eors
        self.assertEqual(members, [0x1000])
        self.assertTrue(0.85 <= ratio < 1.0)
        (ratio, members), = found(0x4000)                                        # other registers: the same form
        self.assertEqual((ratio, members), (1.0, [0x1000]))
        self.assertNotEqual(shapes[0x4000], shapes[0x1000])
        self.assertEqual(found(0x5000), [])
        masked, raw = twins.differences(shapes[0x2000], shapes[0x1000], functions[0x2000], functions[0x1000])
        self.assertEqual(masked, 0)
        self.assertGreater(raw, 0)
        masked, raw = twins.differences(shapes[0x3000], shapes[0x1000], functions[0x3000], functions[0x1000])
        self.assertEqual(masked, 2)
        self.assertGreaterEqual(raw, masked)


def ppc_function(pc: int, k: int, changed: bool = False) -> list[int]:
    """mflr/stw, then lwz/addi/bl runs whose offsets, constants and callees depend on k; blr."""
    words = [0x7C0802A6, 0x90010004]                                     # mflr r0; stw r0,4(r1)
    for i in range(5):
        words.append((32 << 26) | (3 << 21) | (31 << 16) | (4 * (i + k)))            # lwz r3, 4*(i+k)(r31)
        words.append(0x7C632214 if changed and i == 2 else
                     (14 << 26) | (4 << 21) | (3 << 16) | (i + k))                   # add r3,r3,r4 / addi r4,r3,i+k
        site = pc + 4 * len(words)
        words.append((18 << 26) | ((TEXT + 0x400 * (k + 1) - site) & 0x03FFFFFC) | 1)  # bl
    words += [0x80010004, 0x4E800020, 0x60000000]                        # lwz r0,4(r1); blr; nop
    assert len(words) == WORDS
    return words


class ProjectTests(unittest.TestCase):
    """A GameCube project: one matched function, two unmatched copies of its shape (a family), one changed
    copy and one unrelated function."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from zkit.index import close_connections
        self.addCleanup(close_connections)
        base = Path(self.temp.name)
        for var in ("XDG_CACHE_HOME", "XDG_STATE_HOME"):
            os.environ[var] = str(base / var.lower())
        os.environ["ZKIT_REFRESH_TTL"] = "0"
        decomp = base / "decomp"
        (decomp / "build").mkdir(parents=True)
        bodies = [ppc_function(TEXT, 1), ppc_function(TEXT + 0x50, 2), ppc_function(TEXT + 0xA0, 3),
                  ppc_function(TEXT + 0xF0, 4, changed=True), [0x60000000] * (WORDS - 1) + [0x4E800020]]
        code = [w for body in bodies for w in body]
        self.at = [TEXT + 4 * WORDS * i for i in range(len(bodies))]
        text = struct.pack(f">{len(code)}I", *code)
        offsets, addresses, sizes = [0] * 18, [0] * 18, [0] * 18
        offsets[0], addresses[0], sizes[0] = 0x100, TEXT, len(text)
        header = struct.pack(">18I18I18I3I", *offsets, *addresses, *sizes, 0, 0, TEXT).ljust(0x100, b"\0")
        (decomp / "orig.dol").write_bytes(header + text)
        names = ["read__5TBearFv", "fn_80003050", "fn_800030A0", "read__5TBirdFv", "fn_80003140"]
        units = ["main/Bear", "main/Wolf", "main/Wolf", "main/Bird", "main/Bird"]
        report = {"units": [{"name": unit, "metadata": {"source_path": f"src/{unit[5:]}.cpp"}, "functions": [
            {"name": n, "size": str(4 * WORDS), "metadata": {"virtual_address": str(a)},
             **({"fuzzy_match_percent": 100.0} if i == 0 else {"fuzzy_match_percent": 40.0} if i == 3 else {})}
            for i, (n, a, u) in enumerate(zip(names, self.at, units)) if u == unit]}
            for unit in dict.fromkeys(units)]}
        (decomp / "build/report.json").write_text(json.dumps(report), encoding="utf-8")
        manifest = base / "project.json"
        manifest.write_text(json.dumps({
            "schema_version": 1, "id": "twins", "repositories": {"decomp": {"root": "decomp", "role": "decomp"}},
            "targets": {"t": {"repository": "decomp", "module": "main", "report": "build/report.json",
                              "original": "orig.dol"}}}), encoding="utf-8")
        from zkit.index import use_platform
        from zkit.project import Project
        self.project = Project.load(manifest)
        use_platform(self.project)

    def test_twins_families_and_queries(self):
        data = twins.find(self.project, "t", limit=0)
        rows = {e["address"]: e for e in data["entries"]}
        self.assertEqual(set(rows), {"0x80003050", "0x800030A0", "0x800030F0"})
        exact = rows["0x80003050"]["twin"]
        self.assertEqual((exact["address"], exact["similarity"], exact["differ_masked"], exact["source"]),
                         ("0x80003000", 1.0, 0, "src/Bear.cpp"))
        self.assertGreater(exact["differ_raw"], 0)
        near = rows["0x800030F0"]["twin"]
        self.assertEqual((near["address"], near["differ_masked"]), ("0x80003000", 1))
        self.assertTrue(0.85 <= near["similarity"] < 1.0)
        self.assertEqual(data["searched"], 4)
        self.assertEqual(twins.find(self.project, "t", minimum=0.999, limit=0)["functions"], 2)
        self.assertEqual(twins.find(self.project, "t", unit="main/Bird", limit=0)["functions"], 1)
        asked = twins.find(self.project, "t", ["0x800030F0"])
        self.assertEqual([t["address"] for t in asked["entries"][0]["twins"]], ["0x80003000"])

        families = twins.families(self.project, "t")
        self.assertEqual(families["families"], 1)
        family = families["entries"][0]
        self.assertEqual([m["address"] for m in family["members"]], ["0x80003050", "0x800030A0"])
        self.assertEqual(family["twin"]["address"], "0x80003000")
        self.assertIn("family 0: 2 x 20 words", twins.families_text(families))
        self.assertIn("0x80003000", twins.text(data))
        self.assertEqual(twins.find(self.project, "t", limit=0)["entries"], data["entries"])   # from the cache


if __name__ == "__main__":
    unittest.main()
