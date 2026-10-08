"""Ghidra decompile: the cache survives renames, a boundary change re-decompiles only that function, names are
substituted on read, and a missing install says how to fix it. The real-Ghidra test runs only where Ghidra,
pyghidra and the Gekko/Broadway language are installed."""

from pathlib import Path
import unittest
from unittest import mock

import test_bridge
from test_bridge import TEXT


class DecompileTests(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def fake(self):
        language = Path(self.temp.name) / "lang" / "gekko.ldefs"
        language.parent.mkdir(exist_ok=True)
        language.write_text("Gekko_Broadway", encoding="utf-8")
        calls = []

        def worker(info, dol, sda, boundaries, addresses, threads):
            calls.append(list(addresses))
            self.assertEqual(sda, {2: 0x80003100, 13: 0x80003100})  # decoded from __init_registers
            self.assertIn(TEXT + 0x10, dict(boundaries))
            return [{"address": a, "text": f"void fn_{a:08X}(void) {{ fn_80003000(); iRam80003104 = 1; "
                                           f"fRam80003106 = 2; DAT_80003100 = 3; f(0x80003104, 0x80000000); }}"} for a in addresses], {}

        info = {"install": "/ghidra", "version": "12.1.2 PUBLIC", "language": str(language), "python": "python"}
        return calls, mock.patch.multiple("gcn_zkit.decompile", status=lambda: info, _run_worker=worker)

    def test_cache_names_and_boundaries(self):
        from gcn_zkit.decompile import decompile
        calls, patched = self.fake()
        with patched:
            first = decompile(self.project, "t", [TEXT + 0x10, TEXT])
            self.assertEqual(calls, [[TEXT + 0x10, TEXT]])
            text = first["results"][0]["text"]
            self.assertIn("void TPlayer__sub_80003010(void)", text)
            self.assertIn("update__6TEnemyFv();", text)
            self.assertIn("enemyTable = 1", text)
            self.assertIn("enemyTable.unk2 = 2", text)  # interior of a sized object
            self.assertIn("lbl_80003100 = 3", text)
            self.assertIn("f(&enemyTable, 0x80000000)", text)  # a constant inside no symbol stays a number

            symbols = self.decomp / "config/symbols.txt"
            symbols.write_text(symbols.read_text(encoding="utf-8").replace("TPlayer__sub_80003010", "TPlayer_step")
                               .replace("enemyTable", "g_enemies"), encoding="utf-8")
            report = self.decomp / "build/report.json"
            report.write_text(report.read_text(encoding="utf-8").replace("TPlayer__sub_80003010", "TPlayer_step"),
                              encoding="utf-8")
            again = decompile(self.project, "t", [TEXT + 0x10])
            self.assertEqual(len(calls), 1, "a rename must not re-run Ghidra")
            self.assertTrue(again["results"][0]["cached"])
            self.assertIn("void TPlayer_step(void)", again["results"][0]["text"])
            self.assertIn("g_enemies.unk2 = 2", again["results"][0]["text"])

            report.write_text(report.read_text(encoding="utf-8").replace('"size": "16"', '"size": "12"'),
                              encoding="utf-8")
            decompile(self.project, "t", [TEXT + 0x10, TEXT])
            self.assertEqual(calls[1], [TEXT + 0x10], "only the function whose boundary changed re-runs")

            missing = decompile(self.project, "t", [TEXT + 4])
            self.assertIn("not a function start", missing["results"][0]["error"])

    def test_unavailable_says_how_to_fix(self):
        from gcn_zkit.decompile import decompile
        with mock.patch("gcn_zkit.decompile.status", return_value={"problem": "pyghidra is not installed",
                                                                  "fix": "pip install pyghidra"}):
            with self.assertRaisesRegex(ValueError, "pyghidra is not installed. Fix: pip install pyghidra"):
                decompile(self.project, "t", [TEXT])

    def test_real_ghidra(self):
        from gcn_zkit.decompile import decompile, status
        if status().get("problem"):
            self.skipTest(status()["problem"])
        data = decompile(self.project, "t", [TEXT, TEXT + 0x10])
        caller, callee = (r["text"] for r in data["results"])
        self.assertIn("TPlayer__sub_80003010()", caller)
        self.assertIn("fn_80003020()", caller)
        self.assertIn("TPlayer__sub_80003010(void)", callee)
        self.assertIn("enemyTable", callee)  # lis/addi address resolved and named
        self.assertNotIn("unaff_GQR", callee)


if __name__ == "__main__":
    unittest.main()
