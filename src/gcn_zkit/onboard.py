"""`gcn-zkit init`: write a project manifest for a decomp-toolkit (dtk) repository, so nobody writes JSON by hand.

The manifest goes to the toolkit's own config directory (never into the repository) and is registered there,
so the CLI, the MCP server and the session hook pick the right project from the working directory.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .project import Project, git

DISC_SUFFIXES = (".iso", ".gcm")  # read in place; dtk extracts every other format on the first build
OTHER_DISCS = (".rvz", ".wia", ".wbfs", ".ciso", ".gcz", ".nfs", ".tgc")
DOCS = ["README.md", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "docs"]
DECOMP_CODE = ["include", "src", "libs"]
NATIVE_CODE = ["include", "src", "source", "tests", "tools", "CMakeLists.txt"]


def config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "gcn-zkit"


def projects_dir() -> Path:
    return config_home() / "projects"


def registered() -> list[Path]:
    """Every manifest `init`/`use` registered, newest first."""
    folder = projects_dir()
    found = []
    if folder.is_dir():
        for path in folder.glob("*.json"):
            if path.name.endswith(".link.json"):
                try:
                    found.append(Path(json.loads(path.read_text(encoding="utf-8"))["manifest"]))
                except (OSError, ValueError, KeyError):
                    continue
            else:
                found.append(path)
    return sorted({p for p in found if p.is_file()}, key=lambda p: -p.stat().st_mtime)


def register(manifest: Path) -> Path:
    """Remember a manifest kept elsewhere (`gcn-zkit use`) without copying it."""
    manifest = manifest.resolve()
    folder = projects_dir()
    if manifest.parent == folder:
        return manifest
    folder.mkdir(parents=True, exist_ok=True)
    data = Project.load(manifest).config
    link = folder / f"{_slug(data['id'])}.link.json"
    link.write_text(json.dumps({"manifest": str(manifest)}) + "\n", encoding="utf-8")
    return link


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", text.lower()).strip("-") or "project"


def _top_level_yaml(path: Path) -> dict[str, str]:
    """The flat top-level `key: value` pairs of a dtk config.yml (no YAML dependency needed for these)."""
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^([A-Za-z_]\w*):\s*(.*?)\s*(?:#.*)?$", line)
        if match and match[2]:
            out[match[1]] = match[2].strip("'\"")
    return out


def _repo_root(path: Path) -> Path:
    path = path.expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"Not a folder: {path}")
    top = git(path, "rev-parse", "--show-toplevel")
    return Path(top.stdout.decode().strip()).resolve() if top.returncode == 0 and top.stdout.strip() else path


def versions(root: Path) -> list[str]:
    """Game versions configured in a dtk project (config/<ID>/config.yml), default version first."""
    found = sorted(p.parent.name for p in root.glob("config/*/config.yml"))
    configure = root / "configure.py"
    if found and configure.is_file():
        text = configure.read_text(encoding="utf-8", errors="replace")
        listed = re.findall(r'^\s*"([A-Za-z0-9_]+)",', text.split("VERSIONS", 1)[1] if "VERSIONS" in text else "", re.M)
        default = re.search(r"^DEFAULT_VERSION\s*=\s*(\d+)", text, re.M)
        if listed and default and int(default[1]) < len(listed) and listed[int(default[1])] in found:
            found.remove(listed[int(default[1])])
            found.insert(0, listed[int(default[1])])
    return found


def _original(root: Path, config: dict[str, str]) -> tuple[str | None, str]:
    """(path relative to root, note) of the original executable zkit can read."""
    base = root / config["object_base"] if config.get("object_base") else root
    obj = config.get("object", "sys/main.dol")
    extracted = base / obj
    if extracted.is_file():
        return extracted.relative_to(root).as_posix(), "extracted DOL"
    if base.is_dir():
        for disc in sorted(base.iterdir()):
            if disc.suffix.lower() in DISC_SUFFIXES and disc.is_file():
                return disc.relative_to(root).as_posix(), "read from the disc image in place"
        others = [d.name for d in base.iterdir() if d.suffix.lower() in OTHER_DISCS]
        if others:
            return extracted.relative_to(root).as_posix(), (
                f"{others[0]} is not readable directly; build the decomp once so dtk extracts {obj}")
    return (extracted.relative_to(root).as_posix() if config.get("object_base") else None,
            "original executable not found; put the disc image in "
            f"{(config.get('object_base') or 'orig/<GAMEID>')} and build once")


def _existing(root: Path, names: list[str]) -> list[str]:
    return [n for n in names if (root / n).exists()]


def manifest_for(decomp: Path, version: str | None = None, native: Path | None = None,
                 name: str | None = None) -> tuple[dict[str, Any], list[str]]:
    """A manifest dict for a dtk decomp (plus an optional native port), and notes for the user."""
    root = _repo_root(decomp)
    notes: list[str] = []
    found = versions(root)
    if not found:
        raise ValueError(f"{root} does not look like a decomp-toolkit project (no config/<GAMEID>/config.yml). "
                         "Pass the decomp repository folder.")
    if version and version not in found:
        raise ValueError(f"No config/{version}/config.yml; versions here: {', '.join(found)}")
    if not version:
        built = [v for v in found if (root / "build" / v / "report.json").is_file()]
        version = found[0] if not built or found[0] in built else built[0]
        if len(found) > 1:
            notes.append(f"using version {version} (others: {', '.join(v for v in found if v != version)}; "
                         "pick one with --version)")
    config = _top_level_yaml(root / "config" / version / "config.yml")
    original, how = _original(root, config)
    notes.append(f"original executable: {original or 'none'} ({how})")
    report = f"build/{version}/report.json"
    if not (root / report).is_file():
        notes.append(f"no {report} yet: function names come from symbols.txt until you build the decomp "
                     "(`python configure.py` then `ninja`); match state, source files and REL functions appear after")
    symbols = config.get("symbols", f"config/{version}/symbols.txt")
    if not (root / symbols).is_file():
        notes.append(f"{symbols} does not exist yet: run the decomp's first build (dtk writes it)")
    project_id = name or _slug(f"{root.name}-{version}")
    decomp_paths = _existing(root, DOCS + DECOMP_CODE)
    repositories: dict[str, Any] = {
        "decomp": {
            "root": str(root), "role": "decomp",
            "index_paths": decomp_paths,
            "cite_paths": _existing(root, ["docs"]),
            "start": ["python configure.py", "ninja"],
            "finish": ["ninja"],
            "rules": [],
        }
    }
    if native is not None:
        native_root = _repo_root(native)
        repositories["native"] = {
            "root": str(native_root), "role": "native",
            "index_paths": _existing(native_root, DOCS + NATIVE_CODE),
            "cite_paths": _existing(native_root, ["docs", "src", "source", "include", "tests"]),
            "code_paths": _existing(native_root, ["src", "source", "include"]),
            "rules": [],
        }
        build = next((b for b in sorted(native_root.glob("build*/compile_commands.json"))), None)
        if build is not None:
            repositories["native"]["tests"] = {"build_dir": build.parent.relative_to(native_root).as_posix(),
                                               "include_roots": _existing(native_root, ["include", "src"])}
    target: dict[str, Any] = {"repository": "decomp", "platform": "gamecube", "revision": version,
                              "module": config.get("name", "main"), "symbols": symbols, "report": report}
    if config.get("splits"):
        target["splits"] = config["splits"]
    if original:
        target["original"] = original
    manifest = {"schema_version": 1, "id": project_id, "generated_by": "gcn-zkit init",
                "repositories": repositories, "targets": {version.lower(): target}}
    return manifest, notes


def init(decomp: Path, version: str | None = None, native: Path | None = None, name: str | None = None,
         write: bool = True) -> dict[str, Any]:
    manifest, notes = manifest_for(decomp, version, native, name)
    path = projects_dir() / f"{manifest['id']}.json"
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            # Keep anything the user added (rules, checks, finish gate) and refresh only what init detects.
            old = json.loads(path.read_text(encoding="utf-8"))
            for key, repo in manifest["repositories"].items():
                kept = old.get("repositories", {}).get(key, {})
                manifest["repositories"][key] = {**kept, **{k: v for k, v in repo.items()
                                                            if k not in ("rules", "start", "finish") or k not in kept}}
            targets = {k: {**old.get("targets", {}).get(k, {}), **t} for k, t in manifest["targets"].items()}
            manifest = {**old, **{k: v for k, v in manifest.items() if k not in ("repositories", "targets")},
                        "repositories": manifest["repositories"], "targets": targets}
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"manifest": str(path), "project": manifest, "notes": notes, "written": write}


def project_for(directory: Path, candidates: list[Path]) -> Path | None:
    """The manifest whose repository (or a git worktree of one) contains directory; the deepest root wins."""
    directory = directory.expanduser().resolve()
    best, depth = None, -1
    loaded = []
    for path in candidates:
        try:
            project = Project.load(path)
        except (OSError, ValueError):
            continue
        loaded.append((path, project))
        for name in project.config["repositories"]:
            root = project.index_root(name)
            if (directory == root or directory.is_relative_to(root)) and len(root.parts) > depth:
                best, depth = path, len(root.parts)
    if best is not None:
        return best
    from .project import git_dirs
    if git_dirs(directory)[1] is None:
        return None
    for path, project in loaded:  # a worktree outside the checkout shares its .git directory
        if project.locate(directory)[0] is not None:
            return path
    return None


def connect_agents(dry_run: bool = False, refresh: bool = False, source: str | None = None) -> list[str]:
    """Add and install the gcn-zkit plugin in Claude Code and Codex, for whichever is installed.

    Runs the same commands the README lists, by full path (works for .exe and .cmd shims on Windows)."""
    import shutil
    import subprocess
    from . import REPOSITORY
    from .health import _claude_plugin, _codex_plugin
    origin = source or REPOSITORY
    steps = {"claude": [["plugin", "marketplace", "add", origin], ["plugin", "install", "gcn-zkit@gcn-zkit"]],
             "codex": [["plugin", "marketplace", "add", origin], ["plugin", "add", "gcn-zkit@gcn-zkit"]]}
    already = {"claude": _claude_plugin()[0], "codex": _codex_plugin()[0]}
    said = []
    for client, commands in steps.items():
        program = shutil.which(client)
        if program is None:
            said.append(f"{client}: not installed, skipped")
            continue
        if already[client] and not refresh:
            said.append(f"{client}: plugin already set up")
            continue
        if refresh:
            commands = [["plugin", "marketplace", "add", origin],
                        ["plugin", "marketplace", "update" if client == "claude" else "upgrade", "gcn-zkit"],
                        ["plugin", "update" if client == "claude" and already[client] else
                         "install" if client == "claude" else "add", "gcn-zkit@gcn-zkit"]]
            if client == "codex" and Path(origin).expanduser().is_dir():
                commands.pop(1)  # local marketplaces have no Git snapshot to upgrade
        for args in commands:
            line = f"{client} {' '.join(args)}"
            if dry_run:
                said.append(f"would run: {line}")
                continue
            result = subprocess.run([program, *args], capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=300)
            ok = result.returncode == 0 or "already" in (result.stdout + result.stderr).lower()
            said.append(f"{'ran' if ok else 'FAILED'}: {line}" + ("" if ok else f"\n  {(result.stderr or result.stdout).strip()[:300]}"))
            if not ok:
                break
        else:
            said.append(f"{client}: restart it to load gcn-zkit" + (" (accept the startup-hook prompt once)"
                                                                    if client == "codex" else ""))
    return said
