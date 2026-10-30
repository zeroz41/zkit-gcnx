"""Ghidra decompile: the cache survives renames, a boundary change re-decompiles only that function, names are
substituted on read, and a missing install says how to fix it. The real-Ghidra test runs only where Ghidra,
pyghidra and the Gekko/Broadway language are installed."""

import support  # noqa: F401  (isolates config, cache and state)
import os
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

        def worker(info, dol, sda, boundaries, addresses, threads, platform="gamecube", base=0):
            calls.append(list(addresses))
            self.assertEqual(sda, {2: 0x80003100, 13: 0x80003100})  # decoded from __init_registers
            self.assertIn(TEXT + 0x10, dict(boundaries))
            return [{"address": a, "text": "/* WARNING: Removing unreachable block (ram,0x80003014) */\n"
                                           f"void fn_{a:08X}(void) {{ fn_80003000(); func_0x80003000(); iRam80003104 = 1; "
                                           f"fRam80003106 = 2; DAT_80003100 = 3; f(0x80003104, 0x80000000); }}"} for a in addresses], {}

        info = {"install": "/ghidra", "version": "12.1.2 PUBLIC", "language": str(language), "python": "python"}
        return calls, mock.patch.multiple("zkit.decompile", status=lambda platform="gamecube": info, _run_worker=worker)

    def test_cache_names_and_boundaries(self):
        from zkit.decompile import decompile
        calls, patched = self.fake()
        with patched:
            first = decompile(self.project, "t", [TEXT + 0x10, TEXT])
            self.assertEqual(calls, [[TEXT + 0x10, TEXT, TEXT + 0x20, TEXT + 0x40]])  # the rest of their unit too
            self.assertTrue(decompile(self.project, "t", [TEXT + 0x20])["results"][0]["cached"])
            self.assertEqual(len(calls), 1, "a prefetched function reads from the cache")
            text = first["results"][0]["text"]
            self.assertTrue(text.startswith("void TPlayer__sub_80003010(void)"))  # pruned-path notes dropped
            self.assertIn("update__6TEnemyFv();", text)
            self.assertNotIn("func_0x", text)  # a call target Ghidra had no function at is named too
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
        from zkit.decompile import decompile
        with mock.patch("zkit.decompile.status", return_value={"problem": "pyghidra is not installed",
                                                                  "fix": "pip install pyghidra"}):
            with self.assertRaisesRegex(ValueError, "pyghidra is not installed. Fix: pip install pyghidra"):
                decompile(self.project, "t", [TEXT])

    def test_low_memory_refuses_and_cache_still_reads(self):
        from zkit import decompile as module
        calls, patched = self.fake()
        with patched, mock.patch.object(module, "PREFETCH", 0):
            module.decompile(self.project, "t", [TEXT])
        language = Path(self.temp.name) / "lang" / "gekko.ldefs"
        info = {"install": "/ghidra", "version": "12.1.2 PUBLIC", "language": str(language), "python": "python"}
        with mock.patch.multiple(module, status=lambda platform="gamecube": info, _memory_mb=lambda: (65536, 7000),
                                 _agent_mb=lambda: 0, PREFETCH=0):
            self.assertTrue(module.decompile(self.project, "t", [TEXT])["results"][0]["cached"])
            with self.assertRaisesRegex(ValueError, "Not starting Ghidra: 7000 MB of 65536 MB available"):
                module.decompile(self.project, "t", [TEXT + 0x10])

    def test_budget_scales_with_total_and_available(self):
        from zkit.decompile import budget
        with mock.patch.dict("os.environ", {}, clear=False), mock.patch("os.cpu_count", return_value=20), \
                mock.patch("zkit.decompile._agent_mb", return_value=2000):
            for key in ("ZKIT_GHIDRA_HEAP", "ZKIT_GHIDRA_MIN_FREE_MB", "ZKIT_AGENT_RAM_MB"):
                os.environ.pop(key, None)
            with mock.patch("zkit.decompile._memory_mb", return_value=(65536, 30000)):
                roomy = budget()
            self.assertEqual((roomy["reserve_mb"], roomy["heap_mb"], roomy["threads"], roomy["workers"]),
                             (6553, 3750, 8, 4))
            # an 8 GB machine with two agent sessions open: one worker, small heap, still runs
            with mock.patch("zkit.decompile._memory_mb", return_value=(7800, 4500)), \
                    mock.patch("zkit.decompile._agent_mb", return_value=2500):
                small = budget()
            self.assertEqual((small["reserve_mb"], small["agent_cap_mb"], small["heap_mb"], small["workers"]),
                             (2048, 3900, 562, 1))
            self.assertNotIn("refuse", small)
            self.assertLessEqual(2500 + small["need_mb"], 3900)
            self.assertNotIn("refuse", roomy)
            with mock.patch("zkit.decompile._memory_mb", return_value=(65536, 8000)):
                tight = budget(16)  # fits one worker, with fewer threads, rather than refusing
            self.assertEqual((tight["workers"], tight["heap_mb"]), (1, 1000))
            self.assertLessEqual(tight["need_mb"], 8000 - tight["reserve_mb"])
            self.assertNotIn("refuse", tight)
            with mock.patch("zkit.decompile._memory_mb", return_value=(8192, 2500)):
                self.assertIn("refuse", budget())
            with mock.patch("zkit.decompile._memory_mb", return_value=(65536, None)):
                self.assertNotIn("refuse", budget())  # a platform that does not report available RAM
            # all agents together stay under half of total RAM (32 GB of 64), whatever else is free
            with mock.patch("zkit.decompile._memory_mb", return_value=(65536, 50000)), \
                    mock.patch("zkit.decompile._agent_mb", return_value=31000):
                capped = budget()
            self.assertEqual((capped["agent_cap_mb"], capped["workers"]), (32768, 1))
            self.assertLessEqual(31000 + capped["need_mb"], 32768)
            with mock.patch("zkit.decompile._memory_mb", return_value=(65536, 50000)), \
                    mock.patch("zkit.decompile._agent_mb", return_value=32000):
                self.assertIn("agent sessions already use 32000 MB", budget()["refuse"])
            with mock.patch.dict("os.environ", {"ZKIT_AGENT_RAM_MB": "40000"}), \
                    mock.patch("zkit.decompile._memory_mb", return_value=(65536, 50000)), \
                    mock.patch("zkit.decompile._agent_mb", return_value=32000):
                self.assertNotIn("refuse", budget())

    def test_agent_memory_is_measured(self):
        from zkit.decompile import _agent_mb
        used = _agent_mb()
        if used is None:
            self.skipTest("no /proc smaps_rollup")
        self.assertGreaterEqual(used, 0)

    def test_worker_slots_release(self):
        from zkit import decompile as module
        with module._WorkerLock(self.project, 2) as first, module._WorkerLock(self.project, 2) as second:
            self.assertNotEqual(first.handle.name, second.handle.name)  # two slots run side by side
        with module._WorkerLock(self.project, 1):  # released on exit
            pass

    def test_lookup_points_unmatched_functions_at_decompile(self):
        from zkit import bridge, render
        with mock.patch("zkit.decompile.available", return_value=True):
            data = bridge.lookup(self.project, "0x80003010", "t")
        self.assertEqual(data["decompile"], not data["function"]["exact"])
        if data["decompile"]:
            self.assertIn("zkit decompile 0x80003010", render.lookup(data))

    def test_subagents_learn_about_decompile(self):
        from zkit.session import SUBAGENT_CONTEXT
        self.assertIn("zkit decompile", SUBAGENT_CONTEXT)

    def test_real_ghidra(self):
        from zkit.decompile import decompile, status
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
