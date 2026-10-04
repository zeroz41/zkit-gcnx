"""Inspect project contracts and render native commands; never execute them."""

from __future__ import annotations

import json
import shlex
import shutil
from typing import Any

from .evidence import report_status, target_identity
from .project import Project, file_record, git, repository_state


def doctor(project: Project) -> dict[str, Any]:
    findings, repositories = [], {}
    for name, repo in project.config["repositories"].items():
        root = project.root(name)
        repositories[name] = {"root": str(root), **repository_state(root)}
        if not root.is_dir():
            findings.append({"severity": "error", "id": "missing-repository", "reference": name})
        for relative in repo.get("required_docs", []):
            path = project.file(name, relative)
            reference = f"{name}:{relative}"
            if not path.is_file():
                findings.append({"severity": "error", "id": "missing-required-doc", "reference": reference})
            elif git(root, "ls-files", "--error-unmatch", "--", relative).returncode:
                findings.append({"severity": "warning", "id": "required-doc-not-tracked", "reference": reference})
    targets = {}
    for name in project.config.get("targets", {}):
        targets[name] = target_identity(project, name)
        if not targets[name]["verified"]:
            findings.append({"severity": "warning", "id": "unverified-target", "reference": name})
    tools = {name: shutil.which(name) for name in project.config.get("tools", [])}
    return {"project": project.config["id"], "manifest_sha256": project.fingerprint,
            "repositories": repositories, "targets": targets,
            "tools": tools, "findings": findings,
            "ok": not any(x["severity"] == "error" for x in findings),
            "capabilities": {"text_evidence": True, "objdiff": bool(targets),
                             "execute_recipes": False, "dolphin_live_control": False,
                             "automatic_merging": False}}


def brief(project: Project) -> dict[str, Any]:
    result = doctor(project)
    result["intent"] = project.config.get("intent", {})
    result["required_reading"] = [
        {"reference": f"{name}:{relative}", **file_record(project.file(name, relative))}
        for name, repo in project.config["repositories"].items()
        for relative in repo.get("required_docs", [])
    ]
    result["reports"] = {}
    for name, target in project.config.get("targets", {}).items():
        if not target.get("report"):
            continue
        try:
            result["reports"][name] = report_status(project, name)
        except (OSError, ValueError) as error:
            result["reports"][name] = {"error": str(error)}
    result["known_conflicts"] = project.config.get("known_conflicts", [])
    result["commands"] = list(project.config.get("commands", {}))
    result["next"] = "Read current repo contracts and status; use the owning router/recipe, not an old brief"
    return result


def command_plan(project: Project, name: str) -> dict:
    commands = project.config.get("commands", {})
    if name not in commands:
        raise ValueError(f"Unknown command: {name}; choose from {', '.join(commands)}")
    command = commands[name]
    root = project.root(command["repository"])
    argv = command["argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        raise ValueError("Command argv must be a nonempty list of strings")
    return {"command": name, "cwd": str(root), "argv": argv,
            "shell_display": f"cd {shlex.quote(str(root))} && {shlex.join(argv)}",
            "effects": command.get("effects", "unclassified"),
            "requirements": command.get("requirements", []), "executed": False}


def recipe_inventory(project: Project, repository: str, query: str = "", limit: int = 20) -> dict:
    repo = project.config["repositories"].get(repository)
    if repo is None or not repo.get("recipes"):
        raise ValueError("Repository has no configured recipe directory")
    base = project.file(repository, repo["recipes"])
    rows = []
    for path in sorted(base.glob("*.json")):
        # All user-selected paths go through the same containment boundary.
        path = project.file(repository, path.relative_to(project.root(repository)).as_posix())
        data = json.loads(path.read_text(encoding="utf-8"))
        if query.lower() not in (path.stem + " " + data.get("boundary", "")).lower():
            continue
        rows.append({"reference": f"{repository}:{path.relative_to(project.root(repository)).as_posix()}",
                     "boundary": data.get("boundary"), "excluded": data.get("excluded", []),
                     "original_checks": len(data.get("original_checks", [])),
                     "required_tests": len(data.get("tests", []))})
    if not 1 <= limit <= 50:
        raise ValueError("Use limit 1..50")
    return {"total": len(rows), "recipes": rows[:limit]}
