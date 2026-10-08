"""`gcn-zkit doctor`: is everything set up, and if not, the exact command that fixes it.

Every check is local and read-only (it never starts a client, a build or the network).
"""

from __future__ import annotations

import importlib.util
import importlib.metadata
import json
import os
import shutil
import time
import tomllib
from pathlib import Path

from .project import Project, digest

CONFIG = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "gcn-zkit"


def _row(status: str, check: str, detail: str = "", fix: str = "") -> dict:
    return {"status": status, "check": check, "detail": detail, "fix": fix}


def _claude_plugin() -> tuple[bool | None, str]:
    settings = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
    enabled = {}
    for name in ("settings.json", "settings.local.json"):
        path = settings / name
        if path.is_file():
            try:
                enabled.update(json.loads(path.read_text(encoding="utf-8")).get("enabledPlugins", {}))
            except ValueError:
                continue
    found = [k for k, v in enabled.items() if k.startswith("gcn-zkit@") and v]
    if found:
        return True, ", ".join(found)
    return (False, "not enabled") if settings.is_dir() else (None, "Claude Code config not found")


def _codex_plugin() -> tuple[bool | None, str]:
    path = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "config.toml"
    if not path.is_file():
        return None, "Codex config not found"
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as error:
        return False, f"cannot read config: {error}"
    plugins = [v for k, v in config.get("plugins", {}).items() if k.startswith("gcn-zkit@")]
    if any(p.get("enabled", True) for p in plugins):
        return True, "plugin enabled in user config (restart to load updates)"
    if plugins:
        return False, "plugin disabled in user config"
    if "gcn-zkit" in config.get("mcp_servers", {}):
        enabled = config["mcp_servers"]["gcn-zkit"].get("enabled", True)
        return enabled, "MCP server entry (no plugin)" if enabled else "MCP server disabled"
    return False, "not configured"


def installation() -> dict:
    """On-disk provenance, not a claim about what an already-running client loaded."""
    from . import __version__
    package = Path(__file__).resolve().parent
    try:
        distribution_version = importlib.metadata.version("gcn-zkit")
    except importlib.metadata.PackageNotFoundError:
        distribution_version = None
    source = package.parent.parent
    checkout = source if (source / "pyproject.toml").is_file() else None
    clients = {}
    for client, base, marker in (
        ("claude", Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude")), ".claude-plugin"),
        ("codex", Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")), ".codex-plugin"),
    ):
        copies = []
        for path in sorted((base / "plugins" / "cache").glob(f"*/gcn-zkit/*/{marker}/plugin.json")):
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
                root = path.parent.parent
                differences = []
                if checkout:
                    for folder in ("skills", "hooks", marker):
                        for original in (checkout / folder).rglob("*"):
                            if original.is_file():
                                rel = original.relative_to(checkout)
                                installed = root / rel
                                if not installed.is_file() or installed.read_bytes() != original.read_bytes():
                                    differences.append(rel.as_posix())
                copies.append({"path": str(root), "version": manifest.get("version"),
                               "current": manifest.get("version") == __version__ and not differences,
                               "different_files": differences})
            except (OSError, ValueError):
                copies.append({"path": str(path.parent.parent), "current": False, "error": "unreadable manifest"})
        clients[client] = copies
    legacy = CONFIG / "home"
    return {"version": __version__, "distribution_version": distribution_version,
            "package": str(package), "checkout": str(checkout) if checkout else None,
            "launcher": shutil.which("gcn-zkit"), "plugin_caches": clients,
            "legacy_home": legacy.read_text(encoding="utf-8").strip() if legacy.is_file() else None,
            "limits": "Cache inventory and user config only; project overrides and running clients may differ. "
                      "Restart clients after updating. The legacy home setting is unused."}


from . import REPOSITORY

INSTALL = f"uv tool install --force git+https://github.com/{REPOSITORY}   (or from a clone: uv tool install --force ./gcn-zkit)"


def doctor(project: Project) -> dict:
    from . import __version__
    rows = [_row("ok", "gcn-zkit", f"{__version__} (Python {'.'.join(map(str, __import__('sys').version_info[:3]))})")]
    rows.append(_row("ok" if importlib.util.find_spec("mcp") else "fail", "MCP package",
                     "installed" if importlib.util.find_spec("mcp") else "missing (the plugin's MCP server needs it)",
                     INSTALL))
    on_path = shutil.which("gcn-zkit")
    rows.append(_row("ok" if on_path else "fail", "gcn-zkit on PATH", on_path or "not found (plugins call it by name)",
                     f"{INSTALL}   # then `uv tool update-shell` and reopen the terminal"))
    provenance = installation()
    rows.append(_row("info", "loaded Python package", provenance["package"]))
    rows.append(_row("ok" if provenance["distribution_version"] == provenance["version"] else "warn",
                     "installed distribution", str(provenance["distribution_version"] or "not installed"), INSTALL))
    for client, copies in provenance["plugin_caches"].items():
        if copies:
            current = [c for c in copies if c["current"]]
            detail = "; ".join(f"{c['path']} ({'current' if c['current'] else 'differs'})" for c in copies)
            rows.append(_row("ok" if current else "warn", f"{client}: plugin cache", detail,
                             "gcn-zkit setup <project.json> --refresh-agents --plugin-source <checkout>"))
    if provenance["legacy_home"]:
        rows.append(_row("info", "legacy home (unused)", provenance["legacy_home"]))
    claude, detail = _claude_plugin()
    rows.append(_row({True: "ok", False: "warn", None: "info"}[claude], "Claude Code plugin", detail,
                     f"claude plugin marketplace add {REPOSITORY} && claude plugin install gcn-zkit@gcn-zkit"))
    codex, detail = _codex_plugin()
    rows.append(_row({True: "ok", False: "warn", None: "info"}[codex], "Codex plugin", detail,
                     f"codex plugin marketplace add {REPOSITORY} && codex plugin add gcn-zkit@gcn-zkit"))
    for name, repo in project.config["repositories"].items():
        root = project.root(name)
        if not root.is_dir():
            rows.append(_row("fail", f"{name}: repository", str(root), f"fix `root` in {project.path}"))
            continue
        rows.append(_row("ok", f"{name}: repository", str(root)))
        missing = [d for d in repo.get("required_docs", []) if not project.file(name, d).is_file()]
        if missing:
            rows.append(_row("warn", f"{name}: required docs", "missing " + ", ".join(missing)))
        tests = repo.get("tests")
        if tests:
            build = root / tests.get("build_dir", "build")
            has_cc = (build / "compile_commands.json").is_file()
            has_ctest = (build / "CTestTestfile.cmake").is_file() or bool(tests.get("catalog"))
            rows.append(_row("ok" if has_cc and has_ctest else "warn", f"{name}: test build (impact)",
                             f"{build}: compile_commands {'yes' if has_cc else 'NO'}, ctest {'yes' if has_ctest else 'NO'}",
                             f"configure the native build with compile_commands.json in {build}"))
        if repo.get("role") == "native":
            rows.append(_row("ok" if repo.get("fidelity_tiers") else "warn", f"{name}: fidelity tiers",
                             f"{len(repo.get('fidelity_tiers', []))} configured" if repo.get("fidelity_tiers")
                             else "none: everything is judged as exact", "add `fidelity_tiers` to the manifest"))
    for name, target in project.config.get("targets", {}).items():
        repo = target["repository"]
        original = project.file(repo, target["original"]) if target.get("original") else None
        if original is None or not original.is_file():
            rows.append(_row("warn", f"{name}: original executable", str(original or "not configured"),
                             "put the disc image in orig/<GAMEID>/ and build once (dtk extracts sys/main.dol), "
                             "then rerun `gcn-zkit init`"))
        elif target.get("sha256") and original.suffix.lower() == ".dol":
            same = digest(original) == target["sha256"]
            rows.append(_row("ok" if same else "fail", f"{name}: original executable",
                             f"{original.name} sha256 {'matches' if same else 'DIFFERS — wrong revision?'}"))
        else:
            rows.append(_row("ok", f"{name}: original executable", original.name))
        report = project.file(repo, target["report"]) if target.get("report") else None
        if report and report.is_file():
            age = (time.time() - report.stat().st_mtime) / 3600
            rows.append(_row("ok" if age < 72 else "warn", f"{name}: objdiff report", f"{age:.1f} h old",
                             f"build the decomp (`ninja`) to refresh {target['report']}"))
        else:
            rows.append(_row("warn", f"{name}: objdiff report", "none yet; functions come from symbols.txt (no match "
                             "state, source files or REL functions)", "build the decomp once: `python configure.py` then `ninja`"))
        from .inspect_dol import _objdump
        tool = _objdump(project)
        asm_dir = project.file(repo, target["report"]).parent / "asm" if target.get("report") else None
        has_dtk_asm = bool(asm_dir and asm_dir.is_dir())
        rows.append(_row("ok" if tool or has_dtk_asm else "warn", "disassembly",
                         tool or ("decomp-toolkit asm output" if has_dtk_asm else "none: asm shows raw words"),
                         "build the decomp once (dtk writes build/<GAMEID>/asm), or set ZKIT_OBJDUMP to a "
                         "powerpc-eabi-objdump"))
        from .activity import state_dir
        if not any(r.get("role") == "native" for r in project.config["repositories"].values()):
            continue
        baseline = state_dir(project) / f"drift-{name}.json"
        rows.append(_row("ok" if baseline.is_file() else "info", f"{name}: drift baseline",
                         "recorded" if baseline.is_file() else "none yet", "gcn-zkit drift --accept   # records one"))
    if project.config.get("targets"):
        from .decompile import budget, status as ghidra_status
        ghidra = ghidra_status()
        detail = ghidra.get("problem") or f"{ghidra['version']} at {ghidra['install']}"
        if not ghidra.get("problem"):
            plan = budget()
            detail += (f"; now {plan['available_mb']}/{plan['total_mb']} MB available, agents {plan['agents_mb']}/"
                       f"{plan['agent_cap_mb']} MB: " +
                       (plan["refuse"].split(";")[0] + " (memory short)" if plan.get("refuse") else
                        f"up to {plan['workers']} worker(s), {plan['threads']} threads, heap <= {plan['heap_mb']} MB, "
                        f"keeps {plan['reserve_mb']} MB free"))
        rows.append(_row("info" if ghidra.get("problem") else "ok", "Ghidra decompile (optional)", detail,
                         ghidra.get("fix", "")))
    try:
        from .index import refresh
        stats = refresh(project)
        rows.append(_row("ok", "index", f"refreshed {stats['files_reindexed']} file(s) in {stats['seconds']} s"))
    except Exception as error:  # noqa: BLE001 - report any index failure with its message
        from .index import cache_path
        rows.append(_row("fail", "index", str(error), f"delete {cache_path(project)} and run `gcn-zkit index`"))
    from .session import gate
    for name, repo in project.config["repositories"].items():
        if repo.get("finish_sources"):
            drift = [d["source"] for d in gate(project, name)["drift"]]
            if drift:
                rows.append(_row("info", f"{name}: finish-gate copies disagree", ", ".join(drift),
                                 f"gcn-zkit gate {name}   # AGENTS.md is the contract"))
    return {"project": project.config["id"], "manifest": str(project.path), "checks": rows,
            "installation": provenance,
            "ok": not any(r["status"] == "fail" for r in rows)}


def render(data: dict) -> str:
    marks = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "info": "info"}
    out = [f"gcn-zkit doctor — {data['project']} ({data['manifest']})"]
    for row in data["checks"]:
        out.append(f"{marks[row['status']]}  {row['check']:<34} {row['detail']}")
        if row["status"] in ("warn", "fail") and row["fix"]:
            out.append(f"      fix: {row['fix']}")
    out.append("all good" if data["ok"] else "fix the FAIL lines above")
    return "\n".join(out)
