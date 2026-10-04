#!/usr/bin/env python3
"""A/B the toolkit on fixed tasks: the same model with and without gcn-zkit.

Each case is <suite>/<name>/prompt.md (the task) + <suite>/<name>/graders/truth.md (the ground truth), where
<suite> is a folder of cases you write for your own project (prompt.md may start with --- front matter ---).
Runs `claude -p` locally twice per case (baseline: shell/file tools only; zkit: plus the MCP
server), then asks a judge model to grade both answers against truth.md. Prints turns, time,
cost and verdicts, and writes everything to evals/runs/<timestamp>/. Nothing is published.

    python tools/ab_eval.py --suite ../my-evals --cwd ../my-decomp            # every case, model sonnet
    python tools/ab_eval.py --suite ../my-evals --case callers --model opus

Both arms run with any installed gcn-zkit plugin disabled; the zkit arm gets `gcn-zkit serve` from PATH.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_TOOLS = "Bash Read Grep Glob"
DENY = "Edit Write NotebookEdit Agent WebFetch WebSearch"
CLAUDE = os.environ.get("CLAUDE_BIN") or shutil.which("claude") or str(Path.home() / ".local/bin/claude")
# An installed gcn-zkit plugin would inject its brief into both arms; keep the arms clean.
SETTINGS = json.dumps({"enabledPlugins": {"gcn-zkit@gcn-zkit": False}})


def body(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text.split("---", 2)[2].strip() if text.startswith("---") else text.strip()


def claude(prompt: str, model: str, mcp: dict, tools: str, cwd: Path) -> dict:
    started = time.monotonic()
    result = subprocess.run([CLAUDE, "-p", prompt, "--model", model, "--output-format", "json",
                             "--settings", SETTINGS, "--strict-mcp-config", "--mcp-config", json.dumps(mcp),
                             "--allowedTools", tools, "--disallowedTools", DENY],
                            capture_output=True, text=True, cwd=cwd, timeout=1200, stdin=subprocess.DEVNULL)
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = {"result": result.stdout + result.stderr, "is_error": True}
    data.setdefault("duration_ms", int((time.monotonic() - started) * 1000))
    return data


def judge(answer: str, truth: str, model: str, cwd: Path, votes: int = 3) -> str:
    """Majority of independent judge calls; a single LLM grade is too noisy to trust."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=votes) as pool:
        verdicts = list(pool.map(lambda _: judge_once(answer, truth, model, cwd), range(votes)))
    passes = sum(final_verdict(v) == "PASS" for v in verdicts)
    head = "PASS" if passes * 2 > votes else "FAIL"
    return f"{head} ({passes}/{votes} judges)\n" + "\n---\n".join(verdicts)


def final_verdict(text: str) -> str:
    """Judges sometimes reconsider mid-reply; the last standalone PASS/FAIL is their decision."""
    words = re.findall(r"\b(PASS|FAIL)\b", text.upper())
    return words[-1] if words else "FAIL"


def judge_once(answer: str, truth: str, model: str, cwd: Path) -> str:
    prompt = ("You are grading factual correctness only. The ANSWER was written without seeing the GROUND TRUTH, "
              "so never penalise it for not mentioning or 'confirming' the ground truth, for extra detail, wording, "
              "hex formatting (0x805DA8E0 == 805DA8E0, -0x5420 == -21536) or ordering. PASS if every fact the "
              "ground truth requires is present and correct and nothing it forbids is claimed; otherwise FAIL. "
              "First check each ground-truth requirement in turn, then decide. "
              "Think it through, then end your reply with a final line that is exactly PASS or FAIL. Name any "
              f"wrong or missing fact.\n\nGROUND TRUTH:\n{truth}\n\nANSWER:\n{answer}")
    data = claude(prompt, model, {"mcpServers": {}}, "", cwd)
    return str(data.get("result", "")).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--suite", required=True, type=Path, help="folder holding the cases (one subfolder each)")
    parser.add_argument("--case", action="append", help="case name (repeatable); default all")
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--judge-model", default="sonnet")
    parser.add_argument("--zkit", default="gcn-zkit serve", help="MCP server command for the zkit arm")
    parser.add_argument("--arm", action="append", default=[], metavar="NAME=COMMAND",
                        help="another zkit arm, e.g. 'zkit-0.3=env XDG_CACHE_HOME=/x /old/python -m gcn_zkit.cli serve'")
    parser.add_argument("--no-baseline", action="store_true", help="only the zkit arms (compare versions)")
    parser.add_argument("--rejudge", type=Path, help="re-grade the answers saved in an evals/runs/<dir> without re-running")
    parser.add_argument("--cwd", type=Path, default=ROOT.parent, help="where the agents start (default: workspace)")
    args = parser.parse_args()
    suite = args.suite.resolve()
    cases = sorted(p.parent for p in suite.glob("*/prompt.md"))
    if args.case:
        cases = [c for c in cases if c.name in args.case]
    def server(command: str) -> dict:
        argv = shlex.split(command)
        return {"mcpServers": {"gcn-zkit": {"command": argv[0], "args": argv[1:]}}}
    hint = " You have the gcn-zkit MCP tools; prefer them."
    arms = {"baseline": ({"mcpServers": {}}, BASE_TOOLS, ""),
            "zkit": (server(args.zkit), BASE_TOOLS + " mcp__gcn-zkit", hint)}
    for extra in args.arm:
        name, _, command = extra.partition("=")
        arms[name] = (server(command), BASE_TOOLS + " mcp__gcn-zkit", hint)
    if args.no_baseline:
        arms.pop("baseline")
    if args.rejudge:
        out = args.rejudge
        results = {tuple(p.name[:-5].rsplit(".", 1)): json.loads(p.read_text(encoding="utf-8"))
                   for p in sorted(out.glob("*.*.json"))}
        cases = sorted({suite / name for name, _ in results})
    else:
        out = ROOT / "evals" / "runs" / f"{suite.name}-{time.strftime('%Y%m%dT%H%M%S')}"
        out.mkdir(parents=True)
        results = run_all(cases, arms, args)
    report(results, suite, cases, arms, args, out)
    return 0


def run_all(cases, arms, args) -> dict:
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for case in cases:
            prompt = body(case / "prompt.md")
            for arm, (mcp, tools, suffix) in arms.items():
                jobs[(case.name, arm)] = pool.submit(claude, prompt + suffix, args.model, mcp, tools, args.cwd)
        return {key: job.result() for key, job in jobs.items()}


def report(results, suite, cases, arms, args, out) -> None:
    rows, totals = [], {arm: [0, 0.0, 0.0, 0] for arm in arms}
    for (name, arm), data in sorted(results.items()):
        truth = body(suite / name / "graders" / "truth.md")
        verdict = judge(str(data.get("result", "")), truth, args.judge_model, args.cwd)
        passed = verdict.startswith("PASS")
        turns, seconds, cost = data.get("num_turns", 0), data.get("duration_ms", 0) / 1000, data.get("total_cost_usd", 0)
        t = totals[arm]
        t[0] += turns; t[1] += seconds; t[2] += cost; t[3] += passed
        rows.append((name, arm, turns, seconds, cost, "PASS" if passed else "FAIL"))
        (out / f"{name}.{arm}.json").write_text(json.dumps(data | {"verdict": verdict}, indent=1), encoding="utf-8")
    print(f"{'case':<18}{'arm':<12}{'turns':>6}{'secs':>8}{'cost $':>9}  verdict")
    for name, arm, turns, seconds, cost, verdict in rows:
        print(f"{name:<18}{arm:<12}{turns:>6}{seconds:>8.0f}{cost:>9.3f}  {verdict}")
    for arm, (turns, seconds, cost, passed) in totals.items():
        print(f"TOTAL {arm:<12}{turns:>6}{seconds:>8.0f}{cost:>9.3f}  {passed}/{len(cases)} pass")
    print(f"answers and verdicts: {out}")


if __name__ == "__main__":
    raise SystemExit(main())
