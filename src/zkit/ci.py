"""Continuous integration for a decomp hosted on GitHub.

- `check`: the pull request gate. It runs the build (which checks the relinked executable against the original),
  compares the new report with a baseline by original address, lints the lines the change adds and looks for files
  that must not be committed. With `out` it also writes each check's result and the report delta as JSON, which
  `comment` turns into the pull request comment.
- `comment`: that JSON as markdown. The JSON is written by the pull request's own code, so every value is checked
  and escaped; a missing or unreadable file renders as a run that stopped before the gate.
- `fetch_report`: the report CI already made for a commit, kept as the artifact `report-<tree hash>`, so master's
  progress page and the next pull request's baseline need no second build. Only reports from runs that can vouch
  for the commit count (see `trusted`).
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

from .project import Project

SCHEMA = 1
TAIL = 40                      # lines of a check's output kept in the result
MARKER = "<!-- zkit-ci -->"    # the comment's first line, which finds it again to update it
PASS, FAIL, SKIP = "✅", "❌", "➖"

CHECKS = {
    "build": "Build, executable identical to the original",
    "progress": "Nothing that matched or linked is lost (`zkit progress --check`)",
    "lint": "No decompiler leftovers in the added lines (`zkit check`)",
    "files": "No files that must not be committed (`zkit hygiene`)",
}
METRICS = (
    ("matched_code", "Matched code (bytes)"),
    ("complete_code", "Linked code (bytes)"),
    ("matched_data", "Matched data (bytes)"),
    ("complete_data", "Linked data (bytes)"),
    ("matched_functions", "Matched functions"),
    ("complete_units", "Linked units"),
)
COUNTS = (("new_exact", "new exact functions"), ("improved", "closer functions"),
          ("newly_linked", "newly linked functions"), ("regressed", "lost matches"), ("unlinked", "lost links"),
          ("renamed", "renamed functions"))
LISTED = 20                    # regressions named in the result and the comment


# The gate

def _tail(text: str, lines: int = TAIL) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def _entry(name: str, ok: bool | None, output: str = "", reason: str = "") -> dict[str, Any]:
    return {"name": name, "ok": ok, "reason": reason, "output": _tail(output)}


def _build(project: Project, target: str | None) -> tuple[bool, str]:
    """Run `zkit build --download-build-tools` in a child process, echoing its output and keeping it."""
    command = [sys.executable, "-m", "zkit.cli", "--project", str(project.path),
               *(["--target", target] if target else []), "build", "--download-build-tools"]
    print("== build", flush=True)
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace")
    kept: list[str] = []
    assert child.stdout is not None
    for line in child.stdout:
        print(line, end="", flush=True)
        kept.append(line)
        del kept[:-200]
    return child.wait() == 0, "".join(kept)


def delta_summary(compared: dict[str, Any]) -> dict[str, Any]:
    """The part of `progress.compare` the comment shows: metrics, counts, failures and the first regressions."""
    return {
        "metrics": {key: compared["metrics"][key] for key, _ in METRICS if key in compared["metrics"]},
        "counts": {key: len(compared.get(key) or []) for key, _ in COUNTS},
        "regressed": [f"{row['name']} ({row['address']})" for row in (compared.get("regressed") or [])[:LISTED]],
        "failures": list(compared.get("failures") or []),
    }


def outcome(checks: list[dict[str, Any]]) -> str:
    """pass when every check that ran passed and the build ran and passed."""
    ran = {c["name"]: c["ok"] for c in checks}
    return "pass" if ran.get("build") is True and all(ok is not False for ok in ran.values()) else "fail"


def check(project: Project, target: str, baseline: str | None, base: str, out: Path | None = None,
          steps: dict[str, Callable[..., Any]] | None = None) -> dict[str, Any]:
    """The pull request gate against `baseline` (a report file or saved baseline; default: the latest saved) and
    the lines added since `base`. `steps` replaces the build, lint or files step (for tests)."""
    from . import bridge, hygiene, progress, render
    steps = steps or {}
    checks: list[dict[str, Any]] = []
    delta = None

    built, output = (steps.get("build") or _build)(project, target)
    checks.append(_entry("build", built, output,
                         "" if built else "the build failed or the rebuilt executable differs from the original"))

    if built:
        print("== progress", flush=True)
        compared = progress.since(project, target, baseline)
        text = render.delta(compared)
        print(text, flush=True)
        delta = delta_summary(compared)
        checks.append(_entry("progress", compared["ok"], text,
                             "" if compared["ok"] else "something that matched or linked in the baseline is lost"))
    else:
        checks.append(_entry("progress", None, "", "the build did not finish"))

    repo = (bridge.role_repos(project, "decomp") or list(project.config["repositories"]))[0]
    print(f"== check --base {base}", flush=True)
    linted = (steps.get("lint") or bridge.check)(project, repo, base, None, target, False)
    errors = [f for f in linted["findings"] if f["severity"] == "error"]
    text = render.check({**linted, "findings": errors}) if errors else \
        f"no errors ({len(linted['findings'])} other findings: `zkit check --base {base}` lists them)"
    print(text, flush=True)
    checks.append(_entry("lint", not errors, text, "" if not errors else
                         f"{len(errors)} error(s) in the added lines"))

    print("== hygiene --only files", flush=True)
    files = (steps.get("files") or hygiene.audit)(project, repo, None, 30, ("files",))
    text = render.hygiene(files)
    print(text, flush=True)
    checks.append(_entry("files", files["ok"], text, "" if files["ok"] else "files that must not be committed"))

    result = {"schema": SCHEMA, "result": outcome(checks), "checks": checks, "delta": delta}
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return {**result, "ok": result["result"] == "pass"}


def render_check(result: dict[str, Any]) -> str:
    lines = []
    for c in result["checks"]:
        mark = "ok" if c["ok"] is True else "FAIL" if c["ok"] is False else "skipped"
        lines.append(f"{mark:<8} {c['name']}" + (f": {c['reason']}" if c.get("reason") else ""))
    lines.append("PASS" if result["result"] == "pass" else "FAIL")
    return "\n".join(lines)


# The comment

def _text(value: object, limit: int = 300) -> str:
    """One line of untrusted text, safe inside a table cell or list item."""
    value = re.sub(r"\s+", " ", str(value))[:limit]
    for raw, safe in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|"), ("`", "ˋ"),
                      ("@", "@​"), ("[", "\\["), ("]", "\\]")):
        value = value.replace(raw, safe)
    return value


def _block(value: object, limit: int = 6000) -> str:
    """Untrusted multi-line text, safe inside a fenced code block."""
    return str(value)[-limit:].replace("`", "ˋ").replace("@", "@​")


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _signed(value: int) -> str:
    return f"**{value:+,}**" if value else "0"


def comment(result: object, sha: str = "", run_url: str = "", marker: str = MARKER) -> str:
    """The pull request comment for a `check` result (None: the run stopped before the gate wrote one)."""
    result = result if isinstance(result, dict) else None
    checks = {c.get("name"): c for c in (result or {}).get("checks", []) if isinstance(c, dict)} \
        if isinstance((result or {}).get("checks"), list) else {}
    passed = result is not None and result.get("result") == "pass" and checks.get("build", {}).get("ok") is True \
        and all(c.get("ok") is not False for c in checks.values())
    sha = re.sub(r"[^0-9a-f]", "", sha.lower())[:10]
    run_url = run_url if re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/actions/runs/\d+(/attempts/\d+)?",
                                      run_url) else ""
    lines = [marker, f"### {PASS if passed else FAIL} CI {'passed' if passed else 'failed'}"
             + (f" · `{sha}`" if sha else "") + (f" · [run]({run_url})" if run_url else ""), ""]
    if result is None:
        lines.append("The run stopped before the gate wrote its results; see the run log.")
        return "\n".join(lines) + "\n"

    lines += ["| Check | Result |", "|---|:---:|"]
    for name, label in CHECKS.items():
        c = checks.get(name, {})
        ok = c.get("ok")
        mark = PASS if ok is True else FAIL if ok is False else SKIP
        reason = f" {_text(c['reason'])}" if ok is not True and c.get("reason") else ""
        lines.append(f"| {label} | {mark}{reason} |")

    delta = result.get("delta")
    if isinstance(delta, dict):
        metrics = delta.get("metrics") if isinstance(delta.get("metrics"), dict) else {}
        rows = []
        for key, label in METRICS:
            row = metrics.get(key) if isinstance(metrics.get(key), dict) else {}
            before, after, change = (_int(row.get(k)) for k in ("before", "after", "delta"))
            if None not in (before, after, change):
                rows.append(f"| {label} | {before:,} | {after:,} | {_signed(change)} |")
        if rows:
            lines += ["", "| Measure | Base | Pull request | Change |", "|---|---:|---:|---:|"] + rows
        counts = delta.get("counts") if isinstance(delta.get("counts"), dict) else {}
        said = [f"{_int(counts.get(key)):,} {label}" for key, label in COUNTS if _int(counts.get(key))]
        if said:
            lines += ["", ", ".join(said).capitalize() + "."]
        failures = [f for f in delta.get("failures") or [] if isinstance(f, str)] \
            if isinstance(delta.get("failures"), list) else []
        regressed = [r for r in delta.get("regressed") or [] if isinstance(r, str)] \
            if isinstance(delta.get("regressed"), list) else []
        if failures:
            lines += [""] + [f"- {FAIL} {_text(f)}" for f in failures[:LISTED]]
        if regressed:
            lines += ["", "Lost matches: " + ", ".join(f"`{_text(r, 120)}`" for r in regressed[:LISTED])]

    for name, c in checks.items():
        if c.get("ok") is False and c.get("output"):
            label = re.sub(r"\s*\(`[^`]*`\)", "", CHECKS.get(name, _text(name)))
            lines += ["", f"<details><summary>{label}: output</summary>", "", "```", _block(c["output"]), "```",
                      "</details>"]
    return "\n".join(lines) + "\n"


def read_result(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# Reports CI kept

API = "https://api.github.com"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _request(url: str, token: str | None, accept: str = "application/vnd.github+json", follow: bool = True):
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "zkit-ci"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if not follow and error.code in (301, 302, 303, 307, 308):
            return error.headers["Location"]
        raise


def _api(path: str, token: str | None) -> Any:
    return json.loads(_request(f"{API}/{path}", token))


def trusted(run: dict, sha: str, merged_heads: set[str], branch: str, ci_workflow: str, progress_workflow: str) -> bool:
    """Whether a run can vouch for its report being the build of commit `sha`: a successful pull request run of
    the CI workflow at the head of a pull request that merged as `sha` (its build of the merge commit is the
    branch's build when the pull request merged with the branch unchanged; the tree hash in the artifact's name
    checks that), or a successful push or manual run of the progress workflow on the branch at `sha` itself. Any
    other run, a fork's above all, could name an artifact after the tree."""
    if run.get("conclusion") != "success":
        return False
    if run.get("path") == ci_workflow:
        return run.get("event") == "pull_request" and run.get("head_sha") in merged_heads
    if run.get("path") == progress_workflow:
        return run.get("event") in ("push", "workflow_dispatch") and run.get("head_branch") == branch \
            and run.get("head_sha") == sha
    return False


def fetch_report(repo: str, sha: str, token: str | None, ci_workflow: str = ".github/workflows/ci.yml",
                 progress_workflow: str = ".github/workflows/progress.yml", api: Callable = _api,
                 request: Callable = _request) -> tuple[bytes | None, str]:
    """(report.json bytes, what was found) for commit `sha` of `repo` (owner/name); None when no trusted run kept
    one."""
    branch = api(f"repos/{repo}", token)["default_branch"]
    tree = api(f"repos/{repo}/commits/{sha}", token)["commit"]["tree"]["sha"]
    merged_heads = {pull["head"]["sha"] for pull in api(f"repos/{repo}/commits/{sha}/pulls", token)
                    if pull.get("merged_at")}
    artifacts = api(f"repos/{repo}/actions/artifacts?name=report-{tree}&per_page=100", token)["artifacts"]
    for artifact in artifacts:
        if artifact.get("expired") or artifact.get("name") != f"report-{tree}":
            continue
        run = api(f"repos/{repo}/actions/runs/{artifact['workflow_run']['id']}", token)
        if not trusted(run, sha, merged_heads, branch, ci_workflow, progress_workflow):
            continue
        # The archive URL redirects to signed storage, which must not see the token.
        location = request(f"{API}/repos/{repo}/actions/artifacts/{artifact['id']}/zip", token, follow=False)
        archive = request(location, None, accept="*/*") if isinstance(location, str) else location
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            report = zipped.read("report.json")
        json.loads(report)
        return report, f"report for {sha[:10]} (tree {tree[:10]}) from run {run['id']} ({run['path']}, {run['event']})"
    return None, f"no trusted report for {sha[:10]} (tree {tree[:10]})"


def report(sha: str, out: Path, repo: str | None = None, ci_workflow: str = ".github/workflows/ci.yml",
           progress_workflow: str = ".github/workflows/progress.yml") -> dict[str, Any]:
    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise ValueError("--repo or GITHUB_REPOSITORY is required")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    try:
        found, said = fetch_report(repo, sha, token, ci_workflow, progress_workflow)
    except (urllib.error.URLError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as error:
        return {"ok": False, "repo": repo, "sha": sha, "message": f"could not fetch a report: {error}"}
    if found is None:
        return {"ok": False, "repo": repo, "sha": sha, "message": said}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(found)
    return {"ok": True, "repo": repo, "sha": sha, "out": str(out), "message": said}
