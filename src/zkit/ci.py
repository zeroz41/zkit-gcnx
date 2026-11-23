"""Continuous integration for a decomp hosted on GitHub.

- `check`: the pull request gate. It runs the build (which checks the relinked executable against the original),
  compares the new report with a baseline by original address, lints the lines the change adds and looks for files
  that must not be committed. With `out` it also writes each check's result and the report delta as JSON, which
  `comment` turns into the pull request comment.
  It also measures source quality (`zkit quality --since`): advisory, never failing the gate.
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
QUALITY_NEW = 500              # added quality findings kept in the result
QUALITY_ROWS = 30              # added findings listed in the comment (grouped by check and text)
QUALITY_LINKS = 8              # lines linked per listed finding


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


def quality_summary(compared: dict[str, Any]) -> dict[str, Any]:
    """The part of `quality.compare` the comment shows: every check's counts, the total, the commit measured and
    the first added findings."""
    keys = ("key", "name", "example", "group", "category", "before", "after", "removed", "added")
    return {
        "rows": [{k: row[k] for k in keys}
                 for row in compared["rows"] + compared.get("advisory", []) + compared.get("ownership", [])],
        "total": {k: compared["total"][k] for k in ("before", "after", "removed", "added")},
        "files_changed": compared["files_changed"], "after_commit": compared.get("after_commit"),
        "new": compared["new"][:QUALITY_NEW], "new_total": len(compared["new"]),
    }


def _quality(project: Project, repo: str, base: str) -> dict[str, Any]:
    from . import quality, render
    print(f"== quality --since {base}", flush=True)
    try:
        compared = quality.compare(project, repo, base, "HEAD")
    except (ValueError, OSError) as error:
        print(f"not measured: {error}", flush=True)
        return {"error": str(error)}
    print(render.quality_compare(compared, new=1000), flush=True)
    return quality_summary(compared)


def outcome(checks: list[dict[str, Any]]) -> str:
    """pass when every check that ran passed and the build ran and passed."""
    ran = {c["name"]: c["ok"] for c in checks}
    return "pass" if ran.get("build") is True and all(ok is not False for ok in ran.values()) else "fail"


def check(project: Project, target: str, baseline: str | None, base: str, out: Path | None = None,
          steps: dict[str, Callable[..., Any]] | None = None) -> dict[str, Any]:
    """The pull request gate against `baseline` (a report file or saved baseline; default: the latest saved) and
    the lines added since `base`, and the source quality since `base` (advisory: it never fails the gate). `steps`
    replaces the build, lint, files or quality step (for tests)."""
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

    measured = (steps.get("quality") or _quality)(project, repo, base)
    result = {"schema": SCHEMA, "result": outcome(checks), "checks": checks, "delta": delta, "quality": measured}
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


def _code(value: object, limit: int = 120) -> str:
    """Untrusted text as an inline code span, safe inside a table cell (a code span shows `<` and `&` as they are,
    so only backticks and pipes need changing)."""
    value = re.sub(r"\s+", " ", str(value))[:limit].replace("`", "ˋ").replace("|", "\\|").strip()
    return f"`{value}`" if value else ""


def _counts(row: object, *keys: str) -> tuple[int, ...] | None:
    values = tuple(_int(row.get(k)) for k in keys) if isinstance(row, dict) else (None,)
    return None if None in values else values


def _listed(value: dict, key: str) -> list[dict]:
    items = value.get(key)
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _plural(n: int, one: str) -> str:
    return f"{n:,} {one if n == 1 else one + 's'}"


def _examples(value: object) -> str:
    """`a`, `b` for an example listing several spellings; one span when a comma is inside parentheses."""
    pieces = str(value or "")[:80].split(", ")
    if any(piece.count("(") != piece.count(")") for piece in pieces):
        pieces = [", ".join(pieces)]
    return ", ".join(filter(None, (_code(piece, 60) for piece in pieces)))


def _quality_table(rows: list[dict], categories: bool = True) -> list[str]:
    """One row per check: what it finds with an example, the tree's count before and after, and what the pull
    request removed and added. With categories, each category opens with a heading row."""
    out = ["| Check | Before → after | Removed | Added |", "|---|---|---:|---:|"]
    last = None
    for row in rows:
        before, after, removed, added = _counts(row, "before", "after", "removed", "added")
        category = _text(row.get("category") or row.get("group"), 60)
        if categories and category != last:
            out.append(f"| **{category}** | | | |")
        last = category
        example = _examples(row.get("example"))
        name = _text(row.get("name") or row.get("key"), 80) + (f" ({example})" if example else "")
        moved = f"{before:,} → **{after:,}**" if after != before else f"{after:,}"
        out.append(f"| {name} | {moved} | {removed:,} | {added:,} |")
    return out


def _moved(row: dict) -> bool:
    before, after, removed, added = _counts(row, "before", "after", "removed", "added")
    return bool(removed or added or after != before)


def quality_section(quality: object, run_url: str = "") -> list[str]:
    """The advisory source quality section for a `check` result's `quality` (untrusted, like the rest)."""
    lines = ["", "### Source quality"]
    quality = quality if isinstance(quality, dict) else {}
    total = _counts(quality.get("total"), "before", "after", "removed", "added")
    if total is None:
        return lines + ["", "Not measured for this run (see the run log). `zkit quality --since <base>` measures it "
                        "locally."]
    repo = re.match(r"https://github\.com/([\w.-]+/[\w.-]+)/actions/runs/\d+", run_url)
    commit = quality.get("after_commit")
    commit = commit if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) else ""

    def link(path: str, line: int, label: str) -> str:
        if repo and commit and re.fullmatch(r"[\w.+/-]+", path) and ".." not in path.split("/"):
            return f"[{_code(label)}](https://github.com/{repo[1]}/blob/{commit}/{path}#L{line})"
        return _code(label)

    rows = [r for r in _listed(quality, "rows") if _counts(r, "before", "after", "removed", "added")]
    debt = [r for r in rows if r.get("group") not in ("ownership", "advisory")]
    owned = [r for r in rows if r.get("group") == "ownership"]
    advisory = [r for r in rows if r.get("group") == "advisory"]
    before, after, removed, added = total
    files = _int(quality.get("files_changed")) or 0
    total_row = f"| **Total debt** | **{before:,} → {after:,}** | **{removed:,}** | **{added:,}** |"
    owned_title = "**Members in the wrong class**, read from the class declarations (not in the total):"
    advisory_title = "**Advisory checks**, signs worth a look that also fire on clean code (not in the total):"
    moved = [r for r in debt if _moved(r)]
    if not moved and not any(_moved(r) for r in owned + advisory):
        lines += ["", f"This section never fails a pull request. **No change in any check**; the tree stays at "
                  f"{after:,}."]
    else:
        lines += ["", f"This section never fails a pull request. **Debt {after - before:+,}**: this pull request "
                  f"removes {removed:,} and adds {added:,} across {_plural(files, 'changed source file')}; the tree "
                  f"goes from {before:,} to {after:,}."]
    if moved:   # what the pull request did, the largest change first
        lines += [""] + _quality_table(sorted(moved, key=lambda r: -sum(_counts(r, "removed", "added"))),
                                       categories=False) + [total_row]
    if any(_moved(r) for r in owned):
        lines += ["", owned_title, ""] + _quality_table([r for r in owned if _moved(r)], categories=False)
    if any(_moved(r) for r in advisory):
        lines += ["", advisory_title, ""] + _quality_table([r for r in advisory if _moved(r)], categories=False)
    if debt:   # every check with the tree's count, one click away
        lines += ["", f"<details><summary>All {len(debt) + len(owned) + len(advisory)} checks by category"
                  "</summary>", ""]
        lines += _quality_table(debt) + [total_row]
        if owned:
            lines += ["", owned_title, ""] + _quality_table(owned, categories=False)
        if advisory:
            lines += ["", advisory_title, ""] + _quality_table(advisory, categories=False)
        lines.append("</details>")

    new = _listed(quality, "new")
    if new:
        names = {r.get("key"): r.get("name") for r in rows}
        spots: dict[tuple[str, str], list[tuple[str, int]]] = {}
        for f in new:
            if isinstance(f.get("path"), str) and _int(f.get("line")):
                spots.setdefault((str(f.get("key")), str(f.get("text"))), []).append((f["path"], f["line"]))
        count = max(_int(quality.get("new_total")) or 0, len(new))
        lines += ["", f"<details><summary>{_plural(count, 'new finding')} on lines this pull request adds"
                  "</summary>", "", "| Check | Text | Where |", "|---|---|---|"]
        for (key, found), where in list(spots.items())[:QUALITY_ROWS]:
            places, path = [], None
            for spot, line in where[:QUALITY_LINKS]:
                places.append(link(spot, line, f"{spot.rsplit('/', 1)[-1]}:{line}" if spot != path else f":{line}"))
                path = spot
            more = f" … {len(where) - QUALITY_LINKS:,} more" if len(where) > QUALITY_LINKS else ""
            lines.append(f"| {_text(names.get(key) or key, 60)} | {_code(found, 80)} | {' '.join(places)}{more} |")
        if len(spots) > QUALITY_ROWS or count > len(new):
            lines.append("| … more in the run log | | |")
        lines.append("</details>")
    return lines + ["", "`zkit quality --since <base>` prints the same report locally."]


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
    if "quality" in result:
        lines += quality_section(result["quality"], run_url)
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
