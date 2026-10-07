#!/usr/bin/env python3
"""Replay real agent calls against a gcn-zkit source tree and measure the answers.

The corpus is every distinct zkit MCP/CLI call that Claude Code and Codex sessions made on your
real repos, minus writes (handoff, drift accept). Build it with `extract` from your own transcripts.

  tools/replay.py run --src src --out new.json                 # one version, in-process
  tools/replay.py compare --old /tmp/zkit-old/src --new src    # both, isolated caches, table
  tools/replay.py load --src src --clients 8 --calls 80        # concurrent requests on one MCP stdio session
  tools/replay.py extract --since 2026-10-03T03:50 --merge     # add calls from newer transcripts to the corpus

Each version gets its own XDG_CACHE_HOME and a copy of the state directory, so nothing
written by one run (index, drift baseline) leaks into the other or into real sessions.
Measures: errors by kind (argument validation, exception, usage, soft "no match"),
latency, and output size in characters. Output size is only a token proxy: check the
sampled outputs (--show) before calling a smaller answer a better one.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
CORPUS = HERE / "evals" / "corpus.json"  # your own, from `extract`; not part of the repo
SOFT = ("no function matches", "no function for", "No function matches", "no lesson", "No changed source files",
        "No changed source or registered command files")

# Validate again at execution: corpora are data, including hand-edited/merged ones.
READS = {"brief", "lookup", "asm", "data", "xrefs", "names", "search", "read", "check", "impact",
         "grounding", "suspects", "consts", "drift", "demand", "tiers", "recipes", "recipe-preflight",
         "activity", "gate", "lessons", "doctor", "port-plan", "test-plan", "renamed", "reuse", "projects"}


def replayable(item: dict) -> bool:
    if item.get("kind") == "mcp":
        command = item.get("tool", "").removeprefix("zkit_").replace("_", "-")
        return command in READS and not item.get("args", {}).get("accept")
    if item.get("kind") != "cli":
        return False
    argv = item.get("argv", [])
    if any(a.split("=", 1)[0] in ("--accept", "--write") for a in argv):
        return False
    # Global flags may precede a command; unknown flags are rejected, not skipped.
    index = 0
    while index < len(argv):
        if argv[index] == "--json":
            index += 1
        elif argv[index] in ("--project", "--target"):
            index += 2
        else:
            return argv[index] in READS
    return False


def classify(text: str, raised: bool) -> str | None:
    if raised:
        if "validation error" in text:
            return "argument"
        return "exception"
    head = text[:300]
    if head.startswith("error:") or "Traceback" in head:
        return "exception"
    if any(s in head for s in SOFT):
        return "soft"
    return None


def run_mcp(server, tool: str, args: dict) -> tuple[str, bool]:
    from mcp.server.fastmcp.exceptions import ToolError
    try:
        result = asyncio.run(server.call_tool(tool, args))
    except ToolError as error:
        return str(error), True
    except Exception as error:  # noqa: BLE001 - any escape is a failure of the tool
        return f"{type(error).__name__}: {error}", True
    blocks = result[0] if isinstance(result, tuple) else result
    text = "\n".join(getattr(b, "text", "") for b in blocks) if isinstance(blocks, (list, tuple)) else str(blocks)
    raised = text.startswith("Error executing tool")
    return text, raised


def run_cli(argv: list[str], cwd: str) -> tuple[str, bool]:
    from gcn_zkit import cli
    if not Path(cwd).is_dir():
        return f"error: recorded working directory no longer exists: {cwd}", True
    out, err = io.StringIO(), io.StringIO()
    old = os.getcwd()
    code = 0
    try:
        os.chdir(cwd)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(argv)
            except SystemExit as stop:
                code = stop.code if isinstance(stop.code, int) else 2
    finally:
        os.chdir(old)
    text = out.getvalue() + err.getvalue()
    if code == 2 and ("usage:" in err.getvalue() or "error:" in err.getvalue()):
        return text, True
    return text, bool(code)


def run(args) -> int:
    from gcn_zkit.index import refresh
    from gcn_zkit.project import Project
    from gcn_zkit.server import create_server
    project = Project.load(args.project)
    refresh(project)  # warm the index once; per-call refresh cost is part of what is measured
    server = create_server(project)
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    if args.limit:
        corpus = corpus[:args.limit]
    rows = []
    for item in corpus:
        if not replayable(item):
            raise ValueError(f"Not a read-only replay call: {item.get('tool') or item.get('argv')}")
        start = time.perf_counter()
        if item["kind"] == "mcp":
            text, raised = run_mcp(server, item["tool"], item["args"])
        else:
            text, raised = run_cli(item["argv"], item.get("cwd", str(project.path.parent)))
        seconds = time.perf_counter() - start
        kind = classify(text, raised)
        if kind is None and item["kind"] == "cli" and raised:
            kind = "usage"
        rows.append({"kind": item["kind"], "tool": item.get("tool") or item["argv"][0],
                     "call": item.get("args") or item.get("argv"), "seen": item.get("seen", 1),
                     "error": kind, "seconds": round(seconds, 4), "chars": len(text), "head": text[:400]})
    Path(args.out).write_text(json.dumps(rows, indent=0), encoding="utf-8")
    return 0


def _isolated_env(src: Path, label: str, base: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src)
    cache = base / label / "cache"
    state = base / label / "state"
    cache.mkdir(parents=True, exist_ok=True)
    real_state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "gcn-zkit"
    if real_state.is_dir() and not (state / "gcn-zkit").exists():
        shutil.copytree(real_state, state / "gcn-zkit")
    config = base / label / "config"
    real_config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "gcn-zkit"
    if real_config.is_dir() and not (config / "gcn-zkit").exists():
        shutil.copytree(real_config, config / "gcn-zkit")  # init/use must never write the real config
    config.mkdir(parents=True, exist_ok=True)
    env["XDG_CACHE_HOME"], env["XDG_STATE_HOME"], env["XDG_CONFIG_HOME"] = str(cache), str(state), str(config)
    return env


def summarize(rows: list[dict]) -> dict:
    errors = {}
    for r in rows:
        if r["error"]:
            errors[r["error"]] = errors.get(r["error"], 0) + 1
    secs = sorted(r["seconds"] for r in rows)
    chars = [r["chars"] for r in rows]
    q = lambda xs, p: xs[min(len(xs) - 1, int(len(xs) * p))] if xs else 0
    return {"calls": len(rows), "ok": sum(1 for r in rows if not r["error"]), "errors": errors,
            "weighted_errors": sum(r["seen"] for r in rows if r["error"] and r["error"] != "soft"),
            "p50_s": round(q(secs, .5), 3), "p90_s": round(q(secs, .9), 3), "total_s": round(sum(secs), 1),
            "chars_total": sum(chars), "chars_p50": int(statistics.median(chars)) if chars else 0}


def compare(args) -> int:
    base = Path(tempfile.mkdtemp(prefix="zkit-replay-"))
    results = {}
    for label, src in (("old", Path(args.old)), ("new", Path(args.new))):
        out = base / f"{label}.json"
        project = (args.old_project or args.project) if label == "old" else args.project
        cmd = [sys.executable, __file__, "run", "--src", str(src), "--out", str(out), "--project", project,
               "--corpus", args.corpus] + (["--limit", str(args.limit)] if args.limit else [])
        started = time.time()
        subprocess.run(cmd, env=_isolated_env(src.resolve(), label, base), check=True)
        print(f"{label}: replayed in {time.time() - started:.1f} s", file=sys.stderr)
        results[label] = json.loads(out.read_text(encoding="utf-8"))
    old, new = results["old"], results["new"]
    by_tool: dict[str, dict] = {}
    for label, rows in results.items():
        for r in rows:
            by_tool.setdefault(r["tool"], {}).setdefault(label, []).append(r)
    report = {"overall": {k: summarize(v) for k, v in results.items()}, "by_tool": {}}
    for tool, versions in sorted(by_tool.items(), key=lambda kv: -len(kv[1].get("old", []))):
        report["by_tool"][tool] = {k: summarize(v) for k, v in versions.items()}
    fixed = [(o, n) for o, n in zip(old, new) if o["error"] and o["error"] != "soft" and not n["error"]]
    broke = [(o, n) for o, n in zip(old, new) if n["error"] and n["error"] != "soft" and not o["error"]]
    report["fixed"] = [{"call": o["call"], "tool": o["tool"], "old": o["head"][:200], "new": n["head"][:200]} for o, n in fixed]
    report["regressed"] = [{"call": o["call"], "tool": o["tool"], "old": o["head"][:200], "new": n["head"][:200]} for o, n in broke]
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=1), encoding="utf-8")
        (Path(args.report).with_suffix(".rows.json")).write_text(json.dumps(results, indent=0), encoding="utf-8")
    o, n = report["overall"]["old"], report["overall"]["new"]
    print(f"{'':24} {'old':>14} {'new':>14}")
    for key in ("calls", "ok", "weighted_errors", "p50_s", "p90_s", "total_s", "chars_total", "chars_p50"):
        print(f"{key:24} {o[key]!s:>14} {n[key]!s:>14}")
    print(f"{'errors':24} {json.dumps(o['errors']):>14} {json.dumps(n['errors']):>14}")
    print(f"fixed {len(fixed)}, regressed {len(broke)}")
    for tool, v in report["by_tool"].items():
        a, b = v.get("old"), v.get("new")
        if a and b:
            print(f"  {tool:<18} n={a['calls']:<4} err {sum(a['errors'].values()):>3}->{sum(b['errors'].values()):<3} "
                  f"p50 {a['p50_s']:>6}->{b['p50_s']:<6} chars_p50 {a['chars_p50']:>6}->{b['chars_p50']:<6}")
    for row in report["regressed"][:20]:
        print("REGRESSED", row)
    return 0 if not broke else 1


WRITES = {"zkit_handoff", "zkit_wait", "handoff", "wait", "setup", "init", "use", "install", "serve", "hook"}
CLI_CALL = re.compile(r"(?:^|[\s;&|(/])gcn-zkit\s+(.*)")


def _cli_argvs(command: str, cwd: str | None = None) -> list[tuple[list[str], str | None]]:
    """(argv, cwd) of each `gcn-zkit ...` inside a shell command; pipes, redirections and chains are cut off
    and a preceding `cd DIR` sets the cwd."""
    out = []
    for line in command.splitlines():
        for segment in re.split(r"\s*(?:&&|\|\||;|\|)\s*", line):
            if re.match(r"cd\s+\S", segment):
                target = segment.split(None, 1)[1].strip().strip("'\"")
                cwd = target if target.startswith("/") else (str(Path(cwd or ".") / target) if cwd else None)
                continue
            match = CLI_CALL.search(segment)
            if not match:
                continue
            try:
                argv = shlex.split(re.sub(r"\s\d?(?:>>?|<)&?\s*\S+", " ", " " + match.group(1)), comments=True)
            except ValueError:
                continue
            if argv and not any("$" in a or "`" in a for a in argv):
                out.append((argv, cwd))
    return out


def _js_args(text: str) -> dict | None:
    """A Codex `{repo:"decomp", limit:5}` object literal as a dict (best effort; None when it is not JSON-like)."""
    quoted = re.sub(r'([{,]\s*)([A-Za-z_]\w*)\s*:', r'\1"\2":', text)
    try:
        value = json.loads(quoted)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _entries(path: Path):
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                yield json.loads(line)
            except ValueError:
                continue


def extract(args) -> int:
    """Distinct zkit calls from Claude Code and Codex transcripts newer than --since."""
    sys.path.insert(0, str(HERE / "src"))
    from gcn_zkit.cli import build_parser
    commands = set(next(a for a in build_parser()._actions if a.dest == "command").choices)
    calls: dict[str, dict] = {}
    roots = [Path(p).expanduser().resolve() for p in args.repo_root]

    def eligible(when: str, cwd: str | None) -> bool:
        if when < args.since or (args.until and when >= args.until):
            return False
        return not roots or bool(cwd and any(Path(cwd).resolve().is_relative_to(r) for r in roots))

    def add(item: dict, when: str, src: str) -> None:
        if not replayable(item):
            return
        if item["kind"] == "cli" and not any(a in commands for a in item["argv"][:3]):
            return  # `git -C gcn-zkit reflog`, prose mentioning gcn-zkit
        key = json.dumps({k: v for k, v in item.items() if k in ("kind", "tool", "args", "argv", "cwd")}, sort_keys=True)
        row = calls.setdefault(key, {**item, "seen": 0, "first_seen": when, "src": src})
        row["seen"] += 1
        row["first_seen"] = min(row["first_seen"], when)

    for path in Path(args.claude).expanduser().glob("**/*.jsonl"):
        if path.stat().st_mtime < _epoch(args.since):
            continue
        cwd = None
        for entry in _entries(path):
            when = entry.get("timestamp") or ""
            cwd = entry.get("cwd") or cwd
            content = (entry.get("message") or {}).get("content")
            if not eligible(when, cwd) or not isinstance(content, list):
                continue
            for block in content:
                if block.get("type") != "tool_use":
                    continue
                name, given = block.get("name", ""), block.get("input") or {}
                if "gcn-zkit" in name and name.rsplit("__", 1)[-1].startswith("zkit_"):
                    add({"kind": "mcp", "tool": name.rsplit("__", 1)[-1], "args": given, "cwd": cwd}, when, "claude")
                elif name == "Bash":
                    for argv, where in _cli_argvs(given.get("command", ""), cwd):
                        add({"kind": "cli", "argv": argv, "cwd": where or str(HERE.parent)}, when, "claude")
    for path in Path(args.codex).expanduser().glob("**/*.jsonl"):
        if path.stat().st_mtime < _epoch(args.since):
            continue
        cwd = None
        for entry in _entries(path):
            when, payload = entry.get("timestamp") or "", entry.get("payload") or {}
            if entry.get("type") == "session_meta" and payload.get("thread_source") == "guardian_review":
                break  # approval-review transcripts quote other sessions; they are not agent tool use
            cwd = payload.get("cwd") or cwd
            if not eligible(when, cwd):
                continue
            if payload.get("type") == "function_call":
                name = payload.get("name", "")
                try:
                    given = json.loads(payload.get("arguments", "{}"))
                except ValueError:
                    continue
                if "gcn" in name and name.rsplit("__", 1)[-1].startswith("zkit_"):
                    add({"kind": "mcp", "tool": name.rsplit("__", 1)[-1], "args": given, "cwd": cwd}, when, "codex")
                elif name in ("exec_command", "functions.exec_command"):
                    for argv, where in _cli_argvs(given.get("cmd", ""), given.get("workdir") or cwd):
                        add({"kind": "cli", "argv": argv, "cwd": where or str(HERE.parent)}, when, "codex")
                continue
            if payload.get("type") != "custom_tool_call":
                continue
            source = payload.get("input") or ""
            for tool, body in re.findall(r"tools\.(?:mcp__\w+__)?(zkit_\w+)\((\{[^{}]*\})?\)", source):
                given = _js_args(body) if body else {}
                if given is not None:
                    add({"kind": "mcp", "tool": tool, "args": given, "cwd": cwd}, when, "codex")
            for command in re.findall(r"cmd:\s*\"((?:\\.|[^\"\\])*)\"", source):
                for argv, where in _cli_argvs(json.loads(f'"{command}"'), cwd):
                    add({"kind": "cli", "argv": argv, "cwd": where or str(HERE.parent)}, when, "codex")
    rows = sorted(calls.values(), key=lambda r: r["first_seen"])
    if args.merge:
        corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
        known = {json.dumps({k: v for k, v in r.items() if k in ("kind", "tool", "args", "argv", "cwd")}, sort_keys=True)
                 for r in corpus}
        fresh = [r for r in rows if json.dumps({k: v for k, v in r.items() if k in ("kind", "tool", "args", "argv", "cwd")},
                                               sort_keys=True) not in known]
        Path(args.corpus).write_text(json.dumps(corpus + fresh, indent=0, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{len(rows)} distinct calls since {args.since}; {len(fresh)} new, corpus now {len(corpus) + len(fresh)}")
    else:
        Path(args.out).write_text(json.dumps(rows, indent=0, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{len(rows)} distinct calls since {args.since} -> {args.out}")
    return 0


def _epoch(iso: str) -> float:
    from datetime import datetime, timezone
    stamp = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)).timestamp()


async def _load(args) -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    corpus = [c for c in json.loads(Path(args.corpus).read_text(encoding="utf-8")) if c["kind"] == "mcp"
              and c["tool"] in ("zkit_lookup", "zkit_asm", "zkit_data")][:args.calls]
    if not corpus:
        raise ValueError("Corpus has no lookup/asm/data MCP calls")
    params = StdioServerParameters(command=sys.executable, args=["-m", "gcn_zkit.cli", "--project", args.project, "serve"],
                                   env=dict(os.environ))
    latencies: list[float] = []
    errors: list[bool] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool(corpus[0]["tool"], corpus[0]["args"])  # warm with project-owned evidence
            queue = list(corpus)

            async def client():
                while queue:
                    item = queue.pop()
                    start = time.perf_counter()
                    result = await session.call_tool(item["tool"], item["args"])
                    latencies.append(time.perf_counter() - start)
                    errors.append(bool(result.isError))

            started = time.perf_counter()
            await asyncio.gather(*(client() for _ in range(args.clients)))
            wall = time.perf_counter() - started
    latencies.sort()
    q = lambda p: round(latencies[min(len(latencies) - 1, int(len(latencies) * p))], 2)
    return {"sessions": 1, "concurrent_requests": args.clients, "calls": len(latencies), "errors": sum(errors), "wall_s": round(wall, 1),
            "p50_s": q(.5), "p90_s": q(.9), "max_s": round(latencies[-1], 2)}


def load(args) -> int:
    env = _isolated_env(Path(args.src).resolve(), "load-" + Path(args.src).resolve().parent.name, Path(tempfile.gettempdir()) / "zkit-load")
    os.environ.update(env)
    sys.path.insert(0, env["PYTHONPATH"])
    print(json.dumps(asyncio.run(_load(args))))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    # The project the CLI uses (`gcn-zkit use`): a manifest inside a worktree resolves its relative repo roots
    # from the worktree, which made every MCP call in a replay fail against an empty index.
    configured = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "gcn-zkit" / "project"
    default_project = configured.read_text(encoding="utf-8").strip() if configured.is_file() else None
    for name in ("run", "compare", "load"):
        c = sub.add_parser(name)
        c.add_argument("--project", default=default_project, required=default_project is None)
        c.add_argument("--corpus", default=str(CORPUS))
        c.add_argument("--limit", type=int)
    sub.choices["run"].add_argument("--src", required=True)
    sub.choices["run"].add_argument("--out", required=True)
    sub.choices["compare"].add_argument("--old", required=True)
    sub.choices["compare"].add_argument("--new", default=str(HERE / "src"))
    sub.choices["compare"].add_argument("--report")
    sub.choices["compare"].add_argument("--old-project", help="project file for the old version (default: --project)")
    sub.choices["load"].add_argument("--src", default=str(HERE / "src"))
    sub.choices["load"].add_argument("--clients", type=int, default=8, help="concurrent requests on one stdio session")
    sub.choices["load"].add_argument("--calls", type=int, default=80)
    c = sub.add_parser("extract")
    c.add_argument("--since", required=True, help="ISO time (UTC), e.g. 2026-10-03T03:50")
    c.add_argument("--until", help="exclusive ISO upper bound (keep new benchmark sessions out)")
    c.add_argument("--repo-root", action="append", default=[], help="only sessions in this repo/folder (repeatable)")
    c.add_argument("--claude", default="~/.claude/projects")
    c.add_argument("--codex", default="~/.codex/sessions")
    c.add_argument("--corpus", default=str(CORPUS))
    c.add_argument("--out", default="corpus-new.json")
    c.add_argument("--merge", action="store_true", help="append calls the corpus does not have yet")
    args = parser.parse_args()
    if getattr(args, "src", None):
        sys.path.insert(0, str(Path(args.src).resolve()))
    return {"run": run, "compare": compare, "load": load, "extract": extract}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
