"""Client configuration without the plugin. Prints by default; --write REPO edits that repo's files.

Everything calls `gcn-zkit` from PATH (installed with `uv tool install`), so the same text works on
Linux, macOS and Windows. The plugin (README) is the easier route and also brings the skills.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .project import Project

COMMAND = "gcn-zkit"
SKILLS = ["zkit-resume", "zkit-recover-function", "zkit-port-system", "zkit-finish"]


def skills_source() -> Path | None:
    """The skills folder of a source checkout (an editable install); a wheel install has none."""
    folder = Path(__file__).resolve().parents[2] / "skills"
    return folder if folder.is_dir() else None


def _server(project: Project) -> dict:
    return {"command": COMMAND, "args": ["--project", str(project.path), "serve"]}


def _hook(project: Project, event: str, timeout: int) -> dict:
    return {"type": "command", "timeout": timeout,
            "command": f'{COMMAND} --project "{project.path}" hook {event}'}


def _copy_skills(target: Path, changed: list[str]) -> None:
    source = skills_source()
    if source is None:
        changed.append(f"(skills not copied: install the plugin for them, or clone the repo and rerun)")
        return
    target.mkdir(parents=True, exist_ok=True)
    for name in SKILLS:
        destination = target / name
        if destination.exists() or destination.is_symlink():
            continue
        try:
            destination.symlink_to(source / name, target_is_directory=True)
        except OSError:  # Windows without developer mode cannot create symlinks
            shutil.copytree(source / name, destination)
        changed.append(str(destination))


def install(project: Project, client: str, write: Path | None) -> str:
    if client == "claude":
        mcp = {"mcpServers": {"gcn-zkit": _server(project)}}
        hook = {"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact",
                                            "hooks": [_hook(project, "session-start", 30)]}],
                          "SubagentStart": [{"hooks": [_hook(project, "subagent-start", 15)]}]}}
        if not write:
            return "\n".join([
                "# Easiest: the plugin (MCP server, session brief and skills together):",
                "#   claude plugin marketplace add <gcn-zkit repo or folder>",
                "#   claude plugin install gcn-zkit@gcn-zkit",
                "# Or per repository. .mcp.json:",
                json.dumps(mcp, indent=2),
                "# .claude/settings.local.json (merge into existing \"hooks\"):",
                json.dumps(hook, indent=2),
                "# or let gcn-zkit write both: gcn-zkit install claude --write <repo>"])
        root = write.resolve(strict=True)
        changed: list[str] = []
        path = root / ".mcp.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        data.setdefault("mcpServers", {})["gcn-zkit"] = _server(project)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        changed.append(str(path))
        path = root / ".claude" / "settings.local.json"
        path.parent.mkdir(exist_ok=True)
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        for event, ours in hook["hooks"].items():
            hooks = data.setdefault("hooks", {}).setdefault(event, [])
            hooks[:] = [h for h in hooks if "gcn-zkit" not in json.dumps(h)] + ours
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        changed.append(str(path))
        _copy_skills(root / ".claude" / "skills", changed)
        return "updated:\n  " + "\n  ".join(changed) + "\nrestart Claude Code in that repo; `/mcp` lists gcn-zkit"
    if client == "codex":
        toml = (f'[mcp_servers.gcn-zkit]\ncommand = "{COMMAND}"\n'
                f'args = ["--project", {json.dumps(str(project.path))}, "serve"]\n'
                'startup_timeout_sec = 20\ntool_timeout_sec = 120\n')
        if not write:
            return ("# ~/.codex/config.toml (or <repo>/.codex/config.toml):\n" + toml +
                    "# Prefer the Codex plugin (README), which also brings the skills and the session-start hook.")
        root = write.resolve(strict=True)
        path = root / ".codex" / "config.toml"
        path.parent.mkdir(exist_ok=True)
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        if "[mcp_servers.gcn-zkit]" not in text:
            path.write_text(text + ("\n" if text else "") + toml, encoding="utf-8")
        changed = [str(path)]
        _copy_skills(root / ".agents" / "skills", changed)
        return "updated:\n  " + "\n  ".join(changed)
    if client == "git-hook":
        hook_text = ("#!/bin/sh\n# gcn-zkit: lint the staged change against the repo contract (errors block the commit).\n"
                     f'exec {COMMAND} --project "{project.path}" check --staged\n')
        if not write:
            return "# <repo>/.git/hooks/pre-commit (git runs it with its own sh, also on Windows):\n" + hook_text + \
                "# or run: gcn-zkit install git-hook --write <repo>   (bypass once with git commit --no-verify)"
        root = write.resolve(strict=True)
        hooks = Path(subprocess.run(["git", "-C", str(root), "rev-parse", "--git-path", "hooks"], capture_output=True,
                                    text=True, encoding="utf-8", check=True).stdout.strip())
        hooks = hooks if hooks.is_absolute() else root / hooks
        target = hooks / "pre-commit"
        if target.exists() and "gcn-zkit" not in target.read_text(encoding="utf-8", errors="replace"):
            raise ValueError(f"{target} already exists and is not ours; merge it by hand")
        hooks.mkdir(parents=True, exist_ok=True)
        target.write_text(hook_text, encoding="utf-8", newline="\n")
        target.chmod(0o755)
        return f"installed {target}"
    source = skills_source()
    where = str(source) if source else "<gcn-zkit checkout>/skills"
    return "\n".join(f"copy or link {where}/{name} -> <repo>/.claude/skills/{name}" for name in SKILLS)
