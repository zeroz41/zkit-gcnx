"""Regression tests for 0.3.1: measured speedups (planner stats, caches) and the argument shapes and waiting
patterns seen in real sessions after 0.3.0 landed."""

import support  # noqa: F401  (isolates config, cache and state)
import asyncio
import contextlib
import io
import json
import os
import re
import random
import shutil
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest import mock
from pathlib import Path

import test_bridge


def mcp_text(result) -> str:
    return "".join(getattr(b, "text", "") for b in (result[0] if isinstance(result, tuple) else result))


class Speed(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def test_refresh_keeps_planner_statistics(self):
        from zkit.index import cache_path, refresh
        refresh(self.project)
        db = sqlite3.connect(cache_path(self.project))
        tables = {row[0] for row in db.execute("SELECT DISTINCT tbl FROM sqlite_stat1")}
        self.assertTrue({"calls", "xrefs", "cites"} <= tables, tables)
        # Bulk rows so the planner has to choose between the sibling (target, X) indexes.
        db.executemany("INSERT INTO calls VALUES(?,?,?,?)", [("t", 0x80100000 + i * 4, 0, 0x80200000 + i % 7 * 4)
                                                          for i in range(5000)])
        db.commit()
        db.execute("ANALYZE")
        plan = " ".join(r[3] for r in db.execute(
            "EXPLAIN QUERY PLAN SELECT count(DISTINCT caller) FROM calls WHERE target=? AND callee=?", ("t", 1)))
        self.assertIn("calls_callee", plan)
        db.close()

    def test_refresh_restores_missing_statistics(self):
        from zkit.index import cache_path, connect, refresh
        refresh(self.project)
        connect(self.project).execute("DROP TABLE sqlite_stat1")
        self.assertTrue(refresh(self.project).get("analyzed"))
        self.assertFalse(refresh(self.project).get("analyzed"))  # nothing changed: no second ANALYZE

    def test_native_file_counts_match_a_python_count(self):
        from zkit.bridge import _native_file_counts
        from zkit.index import connect, refresh
        refresh(self.project)
        db = connect(self.project)
        rows = [{"address": a, "size": n} for a, n in ((0x80003000, 12), (0x80003010, 16), (0x80003020, 4))]
        expected = {}
        for r in rows:
            paths = {p for (p,) in db.execute("SELECT path FROM cites WHERE address>=? AND address<? AND repo='native'",
                                              (r["address"], r["address"] + r["size"]))}
            if paths:
                expected[r["address"]] = len(paths)
        self.assertTrue(expected)
        self.assertEqual(_native_file_counts(db, rows, ["native"]), expected)

    def test_concurrent_refresh_scans_once(self):
        from concurrent.futures import ThreadPoolExecutor
        from zkit import index
        os.environ["ZKIT_REFRESH_TTL"] = "60"
        self.addCleanup(os.environ.__setitem__, "ZKIT_REFRESH_TTL", "0")
        index._FRESH.clear()
        calls = []
        original = index._scan
        def counting(*args):
            calls.append(args[2])
            time.sleep(0.05)  # a slow tree walk
            return original(*args)
        index._scan = counting
        self.addCleanup(setattr, index, "_scan", original)
        with ThreadPoolExecutor(8) as pool:
            list(pool.map(lambda _: index.refresh(self.project), range(8)))
        self.assertEqual(sorted(calls), ["decomp", "native"])  # one walk per repo, not one per thread

    def test_name_scan_matches_the_definition_regex(self):
        from zkit.bridge import _name_call
        rng = random.Random(7)
        for _ in range(20000):
            name = rng.choice(["ab", "a", "b_x", "a~b"])
            text = "".join(rng.choice("ab_:~ (\t)x9é") for _ in range(rng.randint(0, 14)))
            m = re.compile(r"(?<![\w:~])" + re.escape(name) + r"\s*\(").search(text)
            self.assertEqual(_name_call(text, name), (m.start(), m.end()) if m else None, (text, name))

    def test_source_cache_evicts_least_recent_files(self):
        from zkit import bridge
        old = bridge.SOURCE_CACHE
        bridge.SOURCE_CACHE = 2
        self.addCleanup(setattr, bridge, "SOURCE_CACHE", old)
        bridge._SOURCES.clear()
        files = []
        for i in range(3):
            path = self.decomp / f"src/f{i}.cpp"
            path.write_text(f"void f{i}() {{\n}}\n", encoding="utf-8")
            files.append(path)
        bridge._source_text(files[0])
        bridge._source_text(files[1])
        bridge._source_text(files[0])  # most recent now
        bridge._source_text(files[2])
        self.assertEqual(sorted(Path(k).name for k in bridge._SOURCES), ["f0.cpp", "f2.cpp"])

    def test_symbols_cache_survives_processes_and_invalidates(self):
        from zkit import bridge
        from zkit.index import cache_path
        bridge._SYMBOLS.clear()
        first = bridge._symbol_table(self.project, "t")[0]
        stores = list(cache_path(self.project).parent.glob("symbols-*.marshal"))
        self.assertEqual(len(stores), 1)
        bridge._SYMBOLS.clear()  # a new process
        self.assertEqual(bridge._symbol_table(self.project, "t")[0], first)
        symbols = self.decomp / "config/symbols.txt"
        symbols.write_text(symbols.read_text(encoding="utf-8") + "newTable = .data:0x80003108; // type:object size:0x4\n")
        bridge._SYMBOLS.clear()
        self.assertEqual(bridge.symbol_named(self.project, "t", "newTable").address, 0x80003108)


class Arguments(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def call(self, name, args):
        from zkit.server import create_server
        if not hasattr(self, "_server"):
            self._server = create_server(self.project)
        return mcp_text(asyncio.run(self._server.call_tool(name, args)))

    def cli(self, *argv):
        from zkit import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cli.main(["--project", str(self.manifest), *argv])
        return code, out.getvalue()

    def test_xrefs_batch(self):
        text = self.call("zkit_xrefs", {"query": "enemyTable lbl_80003100"})
        self.assertIn("xrefs to [0x80003104, +0x4) enemyTable", text)
        self.assertIn("xrefs to [0x80003100, +0x4) lbl_80003100", text)
        code, text = self.cli("xrefs", "0x80003104", "0x80003100")
        self.assertEqual(code, 0)
        self.assertIn("xrefs to [0x80003100, +0x4) lbl_80003100", text)

    def test_data_batch_size_and_repo(self):
        text = self.call("zkit_data", {"repo": "decomp", "addresses": '["0x80003100","enemyTable"]', "type": "u8",
                                       "size": "2"})
        self.assertIn("0x80003100 lbl_80003100 as u8", text)
        self.assertIn("0x80003104 enemyTable as u8", text)
        self.assertIn("0x80003105:", text)
        self.assertNotIn("0x80003106:", text)  # size 2 bytes of u8 = 2 rows
        mixed = self.call("zkit_data", {"address": "0x80003104 0x80009000", "count": 1})
        self.assertIn("0x80009000: error:", mixed)  # one bad address does not sink the batch
        self.assertIn("0x80003104 enemyTable as u32", mixed)
        whole = self.call("zkit_data", {"address": "lbl_80003100", "type": "u8"})
        self.assertEqual(whole.count("\n  0x"), 4)  # the symbol's 4 bytes, not 16 rows past it
        self.assertIn("stopped after 8 values at the end of the section", self.call("zkit_data", {
            "address": "0x80003100", "type": "u8", "count": 12}))
        code, text = self.cli("data", "0x80003104", "0x80003100", "--size", "4")
        self.assertEqual(code, 0)
        self.assertEqual(text.count(" u32"), 2)

    def test_lookup_asm_addresses_and_impact_dot(self):
        self.assertIn("0x80003010", self.call("zkit_lookup", {"addresses": ["80003000", "80003010"], "repo": "decomp"}))
        self.assertIn("0x80003010", self.call("zkit_asm", {"addresses": '["0x80003010"]'}))
        from zkit.native import impact
        from zkit.project import Project
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["repositories"]["native"]["tests"] = {"build_dir": "build", "include_roots": ["src"], "scan": ["src"]}
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        data = impact(Project.load(self.manifest), "native", ["."])  # "." = the whole diff, not a file named "."
        self.assertEqual(data["changed"], [])
        self.assertIn("No changed source files", data["note"])

    def test_aliases_agents_used(self):
        self.assertIn("TEnemy::update", self.call("zkit_lookup", {"query": "0x80003000", "repo": "decomp"}))
        self.assertIn("0x80003010", self.call("zkit_names", {"start": "80003010", "end": "80003020"}))
        self.assertIn("Other.cpp", self.call("zkit_grounding", {"repo": "native", "folder": "src/actors/Other.cpp"}))
        self.assertIn("drift", self.call("zkit_drift", {"repo": "native"}))
        read = self.call("zkit_read", {"repo": "decomp", "path": "src/Enemy.cpp", "start": 2, "end": 3})
        self.assertIn("2:", read)
        self.assertIn("3:", read)
        self.assertNotIn("4:", read)
        code, text = self.cli("read", "decomp:src/Enemy.cpp", "--start", "1", "--end", "1")
        self.assertEqual((code, text.count("\n") <= 2), (0, True))
        code, text = self.cli("lessons", "lock).")
        self.assertEqual(code, 0)
        self.assertIn("Lock gotcha", text)


class SubagentHook(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def test_subagent_start_hook_payload_and_install(self):
        from zkit import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["--project", str(self.manifest), "hook", "subagent-start"]), 0)
        payload = json.loads(out.getvalue())["hookSpecificOutput"]
        self.assertEqual(payload["hookEventName"], "SubagentStart")
        self.assertIn("zkit lookup", payload["additionalContext"])
        self.assertLess(len(payload["additionalContext"]), 800)  # every subagent pays for it
        plugin = json.loads((Path(__file__).resolve().parents[1] / "hooks/hooks.json").read_text(encoding="utf-8"))
        self.assertIn("hook subagent-start", json.dumps(plugin["hooks"]["SubagentStart"]))
        codex = json.loads((Path(__file__).resolve().parents[1] / "hooks/codex-hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(set(codex["hooks"]), {"SessionStart"})  # Codex gets no event it may not know
        from zkit.install import install
        repo = Path(self.temp.name) / "repo"
        repo.mkdir()
        install(self.project, "claude", repo)
        install(self.project, "claude", repo)  # idempotent
        hooks = json.loads((repo / ".claude/settings.local.json").read_text(encoding="utf-8"))["hooks"]
        self.assertEqual(len(hooks["SubagentStart"]), 1)
        self.assertEqual(len(hooks["SessionStart"]), 1)
        self.assertTrue((repo / ".claude/agents/zkit-worker.md").is_file())

    def test_compact_window_set_once_and_never_over_a_choice(self):
        from zkit.install import AUTO_COMPACT_WINDOW, compact_window
        home, repo = Path(self.temp.name) / "home", Path(self.temp.name) / "repo2"
        home.mkdir()
        repo.mkdir()
        local = repo / ".claude/settings.local.json"
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            changed = []
            compact_window(repo, changed)
            compact_window(repo, changed)
            self.assertEqual(len(changed), 1)
            self.assertEqual(json.loads(local.read_text())["autoCompactWindow"], AUTO_COMPACT_WINDOW)
            local.write_text(json.dumps({"autoCompactWindow": 400000, "hooks": {}}))
            compact_window(repo, [])
            self.assertEqual(json.loads(local.read_text())["autoCompactWindow"], 400000)  # the user's choice
            local.unlink()
            (home / ".claude").mkdir()
            (home / ".claude/settings.json").write_text(json.dumps({"autoCompactWindow": "auto"}))
            compact_window(repo, [])
            self.assertFalse(local.exists())

    def test_own_worker_agent_gets_only_the_project(self):
        from zkit import session
        for agent in ("zkit:zkit-worker", "zkit-worker"):
            text = session.subagent_context(self.project, agent)
            self.assertNotIn("zkit lookup", text)
            self.assertLess(len(text), 120)
        self.assertIn("zkit lookup", session.subagent_context(self.project, "general-purpose"))
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(json.dumps({"agent_type": "zkit:zkit-worker"}))
            sys.stdin.isatty = lambda: False
            from zkit import cli
            with mock.patch("select.select", return_value=([sys.stdin], [], [])):
                self.assertEqual(cli._hook_agent(), "zkit:zkit-worker")
        finally:
            sys.stdin = stdin

    def test_worker_agent_definition(self):
        text = (Path(__file__).resolve().parents[1] / "agents/zkit-worker.md").read_text(encoding="utf-8")
        head = text.split("---")[1]
        self.assertIn("name: zkit-worker", head)
        tools = next(line for line in head.splitlines() if line.startswith("tools:"))
        self.assertEqual({t.strip() for t in tools[6:].split(",")}, {"Bash", "Read", "Edit", "Write", "Glob", "Grep"})
        self.assertLess(len(text), 6000)  # its whole prompt is in context on every one of its turns
        for rule in ("zkit contract decomp", "byte-identical", "evidence", "relocation", "zkit try --unit",
                     "--include", "zkit probe", "NOTES.md"):
            self.assertIn(rule, text)


@unittest.skipUnless(sys.platform.startswith("linux"), "process and lock detection reads /proc")
class Wait(unittest.TestCase):
    """Build detection. Rerun with ZKIT_PROCESSES=psutil (and psutil installed) for the macOS/Windows backend."""
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def spawn(self, argv, cwd):
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        return proc

    def fake(self, name):
        path = Path(self.temp.name) / "bin" / name
        path.parent.mkdir(exist_ok=True)
        shutil.copy(shutil.which("sleep"), path)
        return str(path)

    def test_waits_for_a_build_then_settles(self):
        from zkit.activity import wait_idle
        build = self.spawn([self.fake("ninja"), "1.2"], self.decomp)
        time.sleep(0.2)
        data = wait_idle(self.project, "decomp", timeout=20, settle=0.3, poll=0.1)
        self.assertTrue(data["idle"])
        self.assertIn(build.pid, [b["pid"] for b in data["waited_on"]])
        self.assertGreaterEqual(data["waited_s"], 1.0)
        self.assertEqual(data["locked_build"], "flock build/.lock <command>")

    def test_held_lock_blocks_and_times_out(self):
        from zkit.activity import wait_idle
        holder = self.spawn([sys.executable, "-c", "import fcntl,sys,time; f=open(sys.argv[1],'a'); "
                             "fcntl.flock(f, fcntl.LOCK_EX); time.sleep(30)", str(self.decomp / "build/.lock")], "/")
        time.sleep(0.4)
        data = wait_idle(self.project, "decomp", timeout=0.5, settle=0.2, poll=0.1)
        self.assertFalse(data["idle"])
        self.assertEqual(data["still_busy"][0]["pid"], holder.pid)
        self.assertEqual(data["still_busy"][0]["lock"], "build/.lock")

    def test_shell_wrappers_and_other_checkouts_do_not_block(self):
        from zkit.activity import wait_idle
        self.spawn(["sh", "-c", "sleep 5; echo ninja"], self.decomp)  # another agent's `wait && ninja` wrapper
        self.spawn([self.fake("ninja"), "5"], self.native)  # a build in a different repo
        time.sleep(0.2)
        started = time.monotonic()
        data = wait_idle(self.project, "decomp", timeout=10, settle=0.3, poll=0.1)
        self.assertTrue(data["idle"])
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(data["waited_on"], [])

    def test_cli_and_mcp(self):
        from zkit import cli
        from zkit.server import create_server
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--project", str(self.manifest), "wait", "decomp", "--settle", "0.1"])
        self.assertEqual(code, 0)
        self.assertIn("idle after", out.getvalue())
        self.spawn([self.fake("ninja"), "5"], self.decomp)
        time.sleep(0.2)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--project", str(self.manifest), "wait", "decomp", "--timeout", "0.3", "--settle", "0.1"])
        self.assertEqual(code, 1)
        self.assertIn("STILL BUSY", out.getvalue())
        text = mcp_text(asyncio.run(create_server(self.project).call_tool(
            "zkit_wait", {"repo": "decomp", "timeout": 0, "settle": 0})))
        self.assertIn("STILL BUSY", text)


if __name__ == "__main__":
    unittest.main()
