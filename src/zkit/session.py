"""The start-of-session packet and the one canonical finish gate.

`brief` replaces the orientation every session repeats by hand: rules digest,
who else is working, what the last session left, the repository's own next
action, and where the port is waiting on the decomp. It summarizes; the
repository contracts it points to stay authoritative.
"""

from __future__ import annotations

import json
import subprocess
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .activity import activity, handoffs
from .project import Project


def _role_of(project: Project, repo: str) -> str:
    return project.config["repositories"][repo].get("role", repo)


def repo_for_cwd(project: Project, cwd: Path) -> str | None:
    cwd = cwd.resolve()
    best = None
    for name in project.config["repositories"]:
        root = project.root(name)
        if cwd == root or cwd.is_relative_to(root):
            if best is None or len(str(root)) > len(str(project.root(best))):
                best = name
    return best


def lessons(project: Project, role: str | None = None) -> list[dict]:
    rel = project.config.get("knowledge")
    if not rel:
        return []
    base = (project.path.parent / rel).resolve()
    rows = []
    for path in sorted(base.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = {}, text
        if text.startswith("---"):
            head, _, body = text[3:].partition("\n---")
            for line in head.strip().splitlines():
                key, _, value = line.partition(":")
                meta[key.strip()] = value.strip()
        applies = meta.get("applies", "all")
        if role and applies not in ("all", role):
            continue
        rows.append({"id": path.stem, "title": meta.get("title", path.stem), "kind": meta.get("kind", "note"),
                     "applies": applies, "path": str(path), "body": body.strip()})
    return rows


def _extract_section(text: str, after: str, until: str) -> str:
    if after:
        index = text.find(after)
        if index < 0:
            return ""
        text = text[index + len(after):]
    stop = re.search(until, text, re.M) if until else None
    return text[:stop.start()] if stop else text


TOOL_PATTERNS = (r"tools/[\w./-]+?\.(?:py|sh)(?:[ \t]+(?!-)[a-z][\w-]*)?(?:[ \t]+--write)?|\bninja\b|configure\.py|"
                 r"ctest[^\n`\"]*?(?<![\w-])-L\s*['\"]?[\w|]+|^-L\s*['\"]?[\w|]+$")
TOOL = re.compile(f"({TOOL_PATTERNS})", re.M)
FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
INLINE = re.compile(r"`([^`\n]+)`")


def _code_text(text: str, path: str) -> str:
    """Commands live in code: for Markdown use only fenced blocks and inline code spans."""
    if not path.endswith(".md"):
        return text
    blocks = FENCE.findall(text)
    rest = FENCE.sub("", text)
    return "\n".join(blocks + INLINE.findall(rest))


def _commands(text: str, extra: list[str] | None = None) -> set[str]:
    """Commands named in text; `extra` adds the repo's own command patterns (manifest `gate_commands`)."""
    pattern = re.compile("(" + "|".join([TOOL_PATTERNS, *extra]) + ")", re.M) if extra else TOOL
    found = set()
    for match in pattern.finditer(text):
        command = re.sub(r"\s+", " ", match.group(0)).strip()
        label = re.search(r"-L\s*['\"]?([\w|]+)", command) if "-L" in command else None
        found.add(f"ctest -L {label[1]}" if label else command)
    return found


def gate(project: Project, repo: str) -> dict[str, Any]:
    """The canonical finish gate for a repository and where its copies drift."""
    config = project.config["repositories"][repo]
    canonical = config.get("finish", [])
    patterns = config.get("gate_commands", [])
    reference = _commands("\n".join(canonical), patterns)
    drift = []
    for source in config.get("finish_sources", []):
        path = project.file(repo, source["path"])
        if not path.is_file():
            drift.append({"source": source["path"], "missing_file": True})
            continue
        section = _extract_section(path.read_text(encoding="utf-8", errors="replace"), source.get("after", ""), source.get("until", ""))
        found = _commands(_code_text(section, source["path"]), patterns)
        missing = sorted(reference - found)
        extra = sorted(found - reference)
        if missing or extra:
            drift.append({"source": source["path"], "missing": missing, "extra": extra})
    owning = None
    if config.get("tests"):
        from .native import impact
        try:  # the tests that compile or register this diff: what a "<owning checks>" gate line means
            found = impact(project, repo)
            direct = [n for names in found.get("groups", {}).get("direct", {}).values() for n in names]
            if direct:
                owning = {"tests": len(direct), "changed": len(found["changed"]),
                          "commands": [c for k, c in found["commands"].items() if k.startswith("direct/")]}
        except (OSError, ValueError, subprocess.SubprocessError):
            owning = None
    stale_apps = []
    if (config.get("tests") or {}).get("apps"):
        from .native import stale
        try:
            stale_apps = [r for r in stale(project, repo)["outputs"] if r["stale"]]
        except (OSError, ValueError):
            stale_apps = []
    try:
        review = session_review(project, repo)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        review = {"error": str(error)}
    return {"repo": repo, "finish": canonical, "drift": drift, "stale_apps": stale_apps, "owning_tests": owning,
            "session": review,
            "note": "The repository's own contract is authoritative; the manifest copy must be updated with it."}


def _decomp_next(project: Project, repo: str) -> dict | None:
    root = project.root(repo)
    rel = (project.config["repositories"][repo].get("router") or {}).get("brief")
    if not rel:  # optional: a repo's own work router that writes {next: {lane, commands}, progress}
        return None
    path = root / rel
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    age = (time.time() - path.stat().st_mtime) / 3600
    reports = [project.file(t["repository"], t["report"]) for t in project.config.get("targets", {}).values()
               if t.get("report") and t["repository"] == repo]
    stale = any(r.is_file() and r.stat().st_mtime > path.stat().st_mtime for r in reports)
    progress = data.get("progress", {})
    return {"lane": data.get("next", {}).get("lane"), "commands": data.get("next", {}).get("commands", []),
            "brief_age_h": round(age, 1), "stale_vs_report": stale,
            "progress": {k: progress.get(k) for k in ("functions", "code", "linked_code", "complete_functions")
                         if k in progress}}


def _lane_yield(project: Project, repo: str) -> dict | None:
    rel = (project.config["repositories"][repo].get("router") or {}).get("lane_stats")
    if not rel:
        return None
    path = project.root(repo) / rel
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    out = {}
    for lane, runs in data.items():
        if isinstance(runs, list) and runs:
            recent = runs[-3:]
            out[lane] = f"{sum(r.get('kept', 0) for r in recent)}/{sum(r.get('attempted', 0) for r in recent)}"
    return out


def _status_excerpt(project: Project, repo: str, lines: int = 16) -> str | None:
    config = project.config["repositories"][repo]
    rel = config.get("status_doc")
    if not rel or _role_of(project, repo) == "decomp":
        return None
    path = project.file(repo, rel)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    section = config.get("status_section", "## Active work")
    part = _extract_section(text, section, r"^## ") if section in text else text
    return "\n".join(l for l in part.strip().splitlines()[:lines])


def _report_measures(project: Project) -> dict:
    out = {}
    for name, target in project.config.get("targets", {}).items():
        if not target.get("report"):
            continue
        path = project.file(target["repository"], target["report"])
        if not path.is_file():
            continue
        try:
            with path.open("rb") as stream:
                head = stream.read(4096).decode(errors="replace")
            match = re.search(r'"measures"\s*:\s*(\{[^}]*\})', head)
            measures = json.loads(match.group(1)) if match else json.loads(path.read_bytes()).get("measures", {})
        except ValueError:
            continue
        out[name] = {k: measures.get(k) for k in ("matched_functions", "total_functions",
                                                  "matched_code_percent", "complete_code_percent",
                                                  "matched_data_percent") if k in measures}
        out[name]["report_age_h"] = round((time.time() - path.stat().st_mtime) / 3600, 1)
    return out


def brief(project: Project, repo: str | None = None, demand_rows: int = 5) -> dict[str, Any]:
    from .bridge import demand

    repos = [repo] if repo else list(project.config["repositories"])
    act = activity(project)
    result: dict[str, Any] = {
        "project": project.config["id"],
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "focus": repo, "repos": {}, "warnings": act["warnings"],
        "processes": act["processes"],
        "locks": [l for l in act["locks"] if l.get("held") or l.get("note")],
        "measures": _report_measures(project),
    }
    for name in repos:
        config = project.config["repositories"][name]
        role = _role_of(project, name)
        state = act["repositories"].get(name, {})
        entry = {
            "role": role, "root": str(project.root(name)),
            "git": {k: state.get(k) for k in ("branch", "head", "dirty_count", "stashes")},
            "dirty": state.get("dirty", [])[:8],
            "worktrees_with_changes": [w for w in state.get("worktrees", []) if w.get("dirty_files")],
            "unmerged_branches": state.get("unmerged_branches", []),
            "required_reading": [{"reference": f"{name}:{relative}",
                                  "exists": project.file(name, relative).is_file()}
                                 for relative in config.get("required_docs", [])],
            "rules": config.get("rules", []), "start": config.get("start", []),
            "finish": config.get("finish", []), "handoffs": handoffs(project, name, limit=2),
            "lessons": [{"id": l["id"], "title": l["title"]} for l in lessons(project, role)],
        }
        if config.get("architecture") or config.get("coverage"):
            entry["audits"] = {
                "architecture_rules": len(config.get("architecture", {}).get("rules", [])),
                "coverage_inventories": [{"name": key, "boundary": value["boundary"]}
                                         for key, value in config.get("coverage", {}).items()],
            }
        if role == "native":
            from .guidance import PORT_GUIDANCE
            entry['port_guidance'] = PORT_GUIDANCE
        if role == "decomp":
            entry["next"] = _decomp_next(project, name)
            entry["lane_yield_last3"] = _lane_yield(project, name)
        if role == "native" and config.get("fidelity_tiers"):
            from .tiers import summary
            entry["tiers"] = summary(project, name)["counts"]
        if role == "native" and project.config.get("targets"):
            try:
                from .native import grounding
                ground = grounding(project, name, limit=4)
                entry["grounding"] = {"total": ground["total"], "weakest": ground["folders"][:4]}
            except ValueError:
                pass
        if role == "native" and project.config.get("targets"):
            try:
                from .activity import state_dir
                from .bridge import default_target
                from .fidelity import drift
                if (state_dir(project) / f"drift-{default_target(project)}.json").is_file():
                    found = drift(project)
                    if found["changes"]:
                        entry["drift"] = {"changed": len(found["changes"]), "since": found["baseline"],
                                          "files": found["reverify_files"][:4]}
            except (ValueError, OSError):
                pass
        status = _status_excerpt(project, name)
        if status:
            entry["status"] = status
        result["repos"][name] = entry
    try:
        wanted = demand(project, limit=demand_rows)
        top = [{"address": r["address"], "name": r["name"], "need": r["need"], "native_files": r["native_files"]}
               for r in wanted["rows"]]
        result["port_demand"] = {"totals": wanted["totals"], "top": top, "unchanged_since": _unchanged_since(
            project, "demand", [r["address"] for r in top])}
    except ValueError:
        pass
    return result


def _unchanged_since(project: Project, key: str, value: list) -> str | None:
    """When the brief has shown the same list since: the brief then says so in one line instead of repeating it."""
    from .activity import state_dir
    path = state_dir(project) / "brief-seen.json"
    try:
        seen = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except ValueError:
        seen = {}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if seen.get(key, {}).get("value") != value:
        seen[key] = {"value": value, "since": now}
        path.write_text(json.dumps(seen) + "\n", encoding="utf-8")
        return None
    since = seen[key]["since"]
    age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(since)).total_seconds() / 86400
    return since[:10] if age_days >= 1 else None


SUBAGENT_CONTEXT = (
    "zkit is available for {project}. Use its CLI via Bash: `zkit lookup <addr|name ...>` (state, owning file:line, "
    "callers), `zkit asm <addr>`, `zkit decompile <addr ...>` (Ghidra's C; read it next to the decompiler seed), "
    "`zkit data <addr> --type f32 --count 8`, `zkit xrefs <addr>`, `zkit refs <addr|name>` (where the source "
    "defines and uses it), `zkit compiled <addr>` (built vs original), `zkit try <addr> <file>` (check a candidate "
    "with the unit's own compiler; four attempts per function). Several addresses per call. Don't grep symbol or "
    "split files or parse binaries with scripts. Edit only your own files, never build the tree, and report one "
    "line per address.")


def subagent_context(project: Project) -> str:
    """The short pointer a subagent gets at start (it never sees the session brief)."""
    return SUBAGENT_CONTEXT.format(project=project.config.get("id", "this project"))


# Session start records: what a session began from, so its finish gate judges what that session changed.

def record_start(project: Project) -> dict:
    """Save a report baseline per target and every repository's HEAD for the calling agent session."""
    from .activity import agent_identity, state_dir
    from .progress import save_baseline
    from .project import git
    who = agent_identity()
    heads = {}
    for name in project.config["repositories"]:
        result = git(project.root(name), "rev-parse", "HEAD")
        if result.returncode == 0:
            heads[name] = result.stdout.decode().strip()
    saved = {}
    for name, target in project.config.get("targets", {}).items():
        if target.get("report"):
            try:
                meta = save_baseline(project, name, f"session:{who}")
            except (OSError, ValueError):
                meta = None
            if meta:
                saved[name] = meta["name"]
    row = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "agent": who, "heads": heads,
           "baselines": saved}
    path = state_dir(project) / "sessions.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()[-199:] if path.is_file() else []
    path.write_text("\n".join(lines + [json.dumps(row)]) + "\n", encoding="utf-8")
    return row


def session_start(project: Project, agent: str | None = None) -> dict | None:
    """The newest start record of this agent session (or of `agent`), else None."""
    from .activity import agent_identity, state_dir
    path = state_dir(project) / "sessions.jsonl"
    if not path.is_file():
        return None
    who = agent or agent_identity()
    for line in reversed(path.read_text(encoding="utf-8").splitlines()):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("agent") == who:
            return row
    return None


def session_review(project: Project, repo: str) -> dict:
    """What this session changed in one repository: report delta, commit hygiene and the tree it leaves."""
    from . import hygiene, progress
    start = session_start(project)
    out: dict[str, Any] = {"start": start}
    head = (start or {}).get("heads", {}).get(repo)
    commits = f"{head}..HEAD" if head else None
    out["hygiene"] = hygiene.audit(project, repo, commits, parts=("commits", "tree")) if head else \
        hygiene.audit(project, repo, None, 5, parts=("commits", "tree"))
    if start:
        from .activity import processes
        started = datetime.fromisoformat(start["time"])
        age = (datetime.now(timezone.utc) - started).total_seconds() / 60
        mine = [p for p in processes(project) if p.get("repo") == repo and p["age_min"] < age
                and not re.search(r"(^|[/\\])(claude|codex)(\.exe)?(\s|$)", p["cmd"])]
        out["processes"] = [{"pid": p["pid"], "age_min": p["age_min"], "cmd": p["cmd"][:120]} for p in mine]
    if _role_of(project, repo) == "decomp" and start:
        deltas = {}
        for target, name in start.get("baselines", {}).items():
            if project.target(target).get("repository") != repo:
                continue
            try:
                deltas[target] = progress.since(project, target, name)
            except (OSError, ValueError) as error:
                deltas[target] = {"error": str(error)}
        out["progress"] = deltas
    return out
