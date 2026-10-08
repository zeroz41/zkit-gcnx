#!/usr/bin/env python3
"""Run every gcn-zkit command against real projects and fail on crashes.

    python tools/smoke.py                          # every registered project (gcn-zkit projects)
    python tools/smoke.py --project path/to/project.json

Addresses and names come from each project's own index, so it works for any game. Checks: no Python traceback,
exit code in the allowed set, and a time limit per command. It only reads (no handoff is written and drift is
never accepted); outputs go to evals/smoke-last.txt.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMAND = [sys.executable, "-m", "gcn_zkit.cli"]
ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", ""))


def run(args, cwd, manifest=None, ok=(0, 1), limit=30.0):
    command = COMMAND + (["--project", str(manifest)] if manifest else []) + args
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=300, env=ENV,
                            encoding="utf-8", errors="replace")
    seconds = time.monotonic() - started
    problems = []
    if "Traceback" in result.stderr or "Traceback" in result.stdout:
        problems.append("traceback")
    if result.returncode not in ok:
        problems.append(f"exit {result.returncode}")
    if seconds > limit:
        problems.append(f"slow {seconds:.1f}s")
    return {"cmd": " ".join(args), "cwd": str(cwd), "exit": result.returncode, "seconds": round(seconds, 2),
            "problems": problems, "stderr": result.stderr[-400:], "stdout": result.stdout}


def sample(manifest: Path, cwd: Path) -> dict:
    """A few real names and addresses from the project's index."""
    out = {}
    rows = json.loads(run(["--json", "names", "--regex", ".", "--limit", "2000"], cwd, manifest)["stdout"] or "{}")
    functions = rows.get("rows", [])
    if functions:
        out["function"] = functions[len(functions) // 2]["address"]
        out["name"] = functions[len(functions) // 3]["name"]
        rel = [r for r in functions if "+0x" in r["address"]]
        if rel:
            out["rel"] = rel[0]["address"]
    return out


def project_rows(manifest: Path) -> list[dict]:
    config = json.loads(manifest.read_text(encoding="utf-8"))
    roots = {name: (manifest.parent / repo["root"]).resolve() for name, repo in config["repositories"].items()}
    decomp = next((roots[n] for n, r in config["repositories"].items() if r.get("role") == "decomp"),
                  next(iter(roots.values())))
    found = sample(manifest, decomp)
    rows = []
    commands = [["brief"], ["doctor"], ["activity"], ["lessons"], ["gate"], ["projects"],
                ["lookup", "no_such_symbol_zz"], ["search", "the"], ["--json", "brief"]]
    if found.get("function"):
        address = found["function"]
        commands += [["lookup", address], ["lookup", found["name"]], ["asm", address], ["xrefs", address],
                     ["names", "--range", f"{address[2:]}-{int(address, 16) + 0x100:08X}"] if address.startswith("0x") else [],
                     ["data", address, "--count", "4"], ["lookup", address, found["name"]], ["classes", "--limit", "5"]]
        if any(t.get("splits") for t in config.get("targets", {}).values()):
            commands += [["unit", address], ["unit", "--blocked", "--limit", "5"], ["unit", "--gaps", "--limit", "5"]]
    if found.get("rel"):
        commands += [["lookup", found["rel"]], ["asm", found["rel"]]]
    for args in [a for a in commands if a]:
        rows.append(run(args, decomp, manifest, ok=(0, 1, 2) if args[0] == "data" else (0, 1)))
    for name, repo in config["repositories"].items():
        if repo.get("architecture"):
            rows.append(run(["architecture", name], roots[name], manifest))
        for inventory in repo.get("coverage", {}):
            rows.append(run(["coverage", name, inventory], roots[name], manifest))
        if repo.get("role") == "native":
            build = roots[name] / repo.get("tests", {}).get("build_dir", "build")
            if repo.get("tests") and build.is_dir():
                catalog = subprocess.run(["ctest", "--test-dir", str(build), "--show-only=json-v1"],
                                         capture_output=True, text=True, encoding="utf-8", timeout=60)
                tests = json.loads(catalog.stdout).get("tests", []) if catalog.returncode == 0 else []
                candidates = [t["name"] for t in tests if not any(
                    p["name"] in ("DISABLED", "FIXTURES_SETUP", "FIXTURES_CLEANUP") and p["value"]
                    for p in t.get("properties", []))]
                if candidates:
                    rows.append(run(["test-plan", name, candidates[0]], roots[name], manifest, ok=(0,)))
            for args in [["check"], ["impact"], ["stale"], ["grounding"], ["suspects", "--limit", "5"], ["tiers"], ["drift"],
                         ["demand", "--limit", "5"], ["reuse"], ["brief"]]:
                rows.append(run(args, roots[name], manifest))
    rows.append(run(["check"], Path(tempfile.gettempdir()), manifest, ok=(2,)))  # outside any repo: clean error
    rows.append(run(["gate", "nonsense"], decomp, manifest, ok=(2,)))           # unknown repo: clean error
    return rows


def bare_rows() -> list[dict]:
    rows = []
    with tempfile.TemporaryDirectory() as temp:  # no git, no targets
        base = Path(temp)
        (base / "game").mkdir()
        (base / "game" / "NOTES.md").write_text("A plain project with no targets.\n", encoding="utf-8")
        manifest = base / "zkit.project.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "bare", "repositories": {
            "game": {"root": "game", "index_paths": ["NOTES.md"]}}}), encoding="utf-8")
        saved = {k: os.environ.get(k) for k in ("XDG_CACHE_HOME", "XDG_STATE_HOME")}
        ENV.update(XDG_CACHE_HOME=str(base / "c"), XDG_STATE_HOME=str(base / "s"))
        for args in [["brief"], ["search", "plain"], ["activity"], ["doctor"], ["lookup", "0x80001000"],
                     ["lessons"], ["gate", "game"]]:
            rows.append(run(args, base / "game", manifest, ok=(0, 1, 2)))
        for key, value in saved.items():
            ENV.pop(key, None) if value is None else ENV.__setitem__(key, value)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", type=Path, action="append", help="project file (repeatable); default: registered")
    args = parser.parse_args()
    manifests = args.project
    if not manifests:
        sys.path.insert(0, str(ROOT / "src"))
        from gcn_zkit.onboard import registered
        manifests = registered()
    rows = []
    for manifest in manifests:
        rows += project_rows(manifest.resolve())
    rows += bare_rows()
    bad = [r for r in rows if r["problems"]]
    (ROOT / "evals").mkdir(exist_ok=True)
    (ROOT / "evals" / "smoke-last.txt").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    for r in rows:
        mark = "FAIL" if r["problems"] else "ok  "
        print(f"{mark} {r['seconds']:>6.2f}s exit {r['exit']}  {r['cmd'][:52]:<52} @ {Path(r['cwd']).name}"
              + (f"  <- {', '.join(r['problems'])}: {r['stderr'].strip()[-160:]}" if r["problems"] else ""))
    print(f"\n{len(rows) - len(bad)}/{len(rows)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
