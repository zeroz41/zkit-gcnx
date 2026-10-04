"""The start-of-session packet and the one canonical finish gate.

`brief` replaces the orientation every session repeats by hand: rules digest,
who else is working, what the last session left, the repository's own next
action, and where the port is waiting on the decomp. It summarizes; the
repository contracts it points to stay authoritative.
"""

from __future__ import annotations

import json
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
    return {"repo": repo, "finish": canonical, "drift": drift,
            "note": "The repository's AGENTS.md is the contract; the manifest copy must be updated with it."}


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
            "rules": config.get("rules", []), "start": config.get("start", []),
            "finish": config.get("finish", []), "handoffs": handoffs(project, name, limit=2),
            "lessons": [{"id": l["id"], "title": l["title"]} for l in lessons(project, role)],
        }
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
        result["port_demand"] = {"totals": wanted["totals"], "top": [
            {"address": r["address"], "name": r["name"], "need": r["need"], "native_files": r["native_files"]}
            for r in wanted["rows"]]}
    except ValueError:
        pass
    return result


SUBAGENT_CONTEXT = (
    "gcn-zkit is available for evidence on {project}. Use the CLI via Bash (MCP zkit_* tools may need loading): "
    "`gcn-zkit lookup <addr|name ...>` (match/name state, owning file:line, callers, cites), "
    "`gcn-zkit asm <addr> [--size 0x40]`, `gcn-zkit data <addr|symbol ...> --type f32 --size 64`, "
    "`gcn-zkit names --regex RE | --range A-B`, `gcn-zkit xrefs <addr|symbol ...>`, `gcn-zkit search <words>`, "
    "`gcn-zkit wait <repo>` before a build instead of pgrep/sleep. All take several addresses per call. "
    "Prefer these to grepping symbols.txt or parsing the executable/report.json with Python.")


def subagent_context(project: Project) -> str:
    """The short pointer a subagent gets at start (it never sees the session brief)."""
    return SUBAGENT_CONTEXT.format(project=project.config.get("id", "this project"))
