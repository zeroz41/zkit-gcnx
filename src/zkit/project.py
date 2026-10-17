"""Explicit project roots and reproducible identities, independent of a game."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def digest(path: Path, algorithm: str = "sha256") -> str:
    result = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        capture_output=True, timeout=30, check=False,
    )


def repository_state(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        return {"available": False, "error": "Repository root is missing"}
    head = git(root, "rev-parse", "HEAD")
    top = git(root, "rev-parse", "--show-toplevel")
    # Do not accidentally identify an uninitialized nested project as its parent.
    if top.returncode or Path(top.stdout.decode().strip()).resolve() != root:
        return {"available": True, "git": False}
    status = git(root, "status", "--porcelain=v1", "-z")
    diff = git(root, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--") if not head.returncode else None
    changed = git(root, "ls-files", "--modified", "--others", "--exclude-standard", "-z")
    if status.returncode or changed.returncode or (diff is not None and diff.returncode):
        raise ValueError(f"Cannot fingerprint repository: {root}")
    # Hash contents too: dirty->dirty edits are invisible to status alone.
    hashes = {}
    for raw in sorted(set(changed.stdout.split(b"\0")) - {b""}):
        name = raw.decode("utf-8", errors="surrogateescape")
        path = root / name
        if path.is_symlink():
            hashes[name] = "symlink:" + str(path.readlink())
        elif path.is_file():
            hashes[name] = digest(path)
        else:
            hashes[name] = "missing"
    return {
        "available": True, "git": True,
        "head": head.stdout.decode().strip() if not head.returncode else None,
        "dirty": bool(status.stdout),
        "status_sha256": hashlib.sha256(status.stdout).hexdigest(),
        "diff_sha256": hashlib.sha256(diff.stdout if diff else b"").hexdigest(),
        "worktree_sha256": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
    }


_GIT_DIRS: dict[str, tuple[str | None, str | None]] = {}


def git_dirs(directory: Path) -> tuple[str | None, str | None]:
    """(worktree top level, shared .git directory) for a directory, or (None, None) outside git."""
    key = str(directory)
    if key not in _GIT_DIRS:
        result = git(directory, "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir") \
            if directory.is_dir() else None
        lines = result.stdout.decode().split("\n") if result is not None and result.returncode == 0 else []
        # git prints C:/x on Windows; Path() gives the native form every other path here uses.
        _GIT_DIRS[key] = (str(Path(lines[0])), str(Path(lines[1]).resolve())) if len(lines) >= 2 and lines[1] \
            else (None, None)
    return _GIT_DIRS[key]


@dataclass(frozen=True)
class Project:
    path: Path
    config: dict[str, Any]
    fingerprint: str
    # (repository, worktree root) pairs: this call reads that repo's working tree from a git worktree.
    # The index always stays on the configured checkout (index_root).
    overlays: tuple[tuple[str, str], ...] = ()

    @classmethod
    def load(cls, path: str | Path) -> "Project":
        path = Path(path).resolve(strict=True)
        raw = path.read_bytes()
        data = json.loads(raw)
        if data.get("schema_version") != 1 or not isinstance(data.get("id"), str):
            raise ValueError("Project needs schema_version=1 and an id")
        if not isinstance(data.get("repositories"), dict) or not data["repositories"]:
            raise ValueError("Project needs named repositories")
        for name, repo in data["repositories"].items():
            if not isinstance(repo.get("root"), str):
                raise ValueError(f"Repository {name} needs a root")
            for field in ("required_docs", "search_paths", "build_inputs"):
                values = repo.get(field, [])
                if not isinstance(values, list) or any(not isinstance(x, str) for x in values):
                    raise ValueError(f"{name}.{field} must be a list of paths")
        for name, target in data.get("targets", {}).items():
            if target.get("repository") not in data["repositories"] or not target.get("module"):
                raise ValueError(f"Target {name} needs a repository and module")
        return cls(path, data, hashlib.sha256(raw).hexdigest())

    def repo_key(self, value: str | None) -> str | None:
        """Accept a manifest key, the repo folder name (my-port) or the repo root path."""
        if value is None or value in self.config["repositories"]:
            return value
        lowered = value.strip().rstrip("/").lower()
        by_role = [n for n, r in self.config["repositories"].items() if r.get("role") == lowered]
        if len(by_role) == 1:
            return by_role[0]
        for name in self.config["repositories"]:
            root = self.root(name)
            if lowered in (root.name.lower(), str(root).lower()):
                return name
        candidate = Path(value).expanduser()
        if candidate.is_dir():
            candidate = candidate.resolve()
            for name in self.config["repositories"]:
                if candidate == self.index_root(name):  # a repo root; paths inside a repo are file arguments
                    return name
            name, worktree = self.locate(candidate)
            if name and worktree and Path(worktree) == candidate:
                return name  # a git worktree of a configured repo (use scope() to read it)
        choices = ", ".join(f"{n} ({self.root(n).name})" for n in self.config["repositories"])
        raise ValueError(f"Unknown repository {value!r}; use one of: {choices}")

    def index_root(self, repository: str) -> Path:
        """The configured checkout, which the shared index describes."""
        if repository not in self.config["repositories"]:
            raise ValueError(f"Unknown repository: {repository}")
        return (self.path.parent / self.config["repositories"][repository]["root"]).resolve()

    def root(self, repository: str) -> Path:
        """The working tree this call reads: a git worktree overlay, else the configured checkout."""
        for name, path in self.overlays:
            if name == repository:
                return Path(path)
        return self.index_root(repository)

    def worktree(self, repository: str) -> str | None:
        return next((path for name, path in self.overlays if name == repository), None)

    def with_overlay(self, repository: str, worktree: str | Path | None) -> "Project":
        if not worktree or Path(worktree).resolve() == self.index_root(repository):
            return self
        rest = tuple(o for o in self.overlays if o[0] != repository)
        return dataclasses.replace(self, overlays=rest + ((repository, str(Path(worktree).resolve())),))

    def locate(self, directory: str | Path) -> tuple[str | None, str | None]:
        """(repository, worktree root or None) for a directory inside a configured checkout or any git
        worktree of one. A worktree nested inside a checkout (build/.../snapshot) is not that checkout."""
        directory = Path(directory).expanduser().resolve()
        top, common = git_dirs(directory)
        best = None
        for name in self.config["repositories"]:
            root = self.index_root(name)
            if directory == root or directory.is_relative_to(root):
                if best is None or len(str(root)) > len(str(self.index_root(best))):
                    best = name
        if best and (top is None or Path(top) == self.index_root(best)):
            return best, None
        if common:
            for name in self.config["repositories"]:
                own = git_dirs(self.index_root(name))[1]
                if own and own == common:
                    return name, (top if Path(top) != self.index_root(name) else None)
        return best, None

    def file(self, repository: str, relative: str) -> Path:
        root = self.root(repository)
        path = Path(os.path.normpath(root / relative))
        if Path(relative).is_absolute() or not path.is_relative_to(root):
            raise ValueError(f"Path escapes repository {repository}: {relative}")
        # A symlink may point into any configured checkout (a worktree's orig/ link to the main
        # checkout's disc files), never outside them.
        resolved = path.resolve()
        if resolved != path and not any(resolved.is_relative_to(self.index_root(name)) or resolved.is_relative_to(root)
                                        for name in self.config["repositories"]):
            raise ValueError(f"Path escapes repository {repository}: {relative}")
        return path

    def scope(self, value: str | None) -> tuple["Project", str | None]:
        """A repo argument (key, folder name, root or worktree path) -> (project with overlay, key)."""
        key = self.repo_key(value)
        if value and key and value not in self.config["repositories"]:
            candidate = Path(value).expanduser()
            if candidate.is_dir():
                name, worktree = self.locate(candidate)
                if name == key and worktree:
                    return self.with_overlay(key, worktree), key
        return self, key

    def target(self, name: str) -> dict[str, Any]:
        if name not in self.config.get("targets", {}):
            raise ValueError(f"Unknown target: {name}")
        return self.config["targets"][name]

    def reference(self, reference: str) -> Path:
        repository, separator, relative = reference.partition(":")
        if not separator:
            raise ValueError("Use repository:relative/path for a file reference")
        return self.file(repository, relative)


def under(path: str, prefixes) -> bool:
    """path equals or lies inside one of the prefixes (folder boundaries respected)."""
    return any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"exists": False}
    before = path.stat()
    checksum = digest(path)
    after = path.stat()
    if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
        raise ValueError(f"File changed while reading: {path}")
    return {"exists": True, "sha256": checksum, "size": after.st_size}


def snapshot(project: Project, references: list[str] | None = None) -> dict[str, Any]:
    if digest(project.path) != project.fingerprint:
        raise ValueError("Project manifest changed; reload it before taking a snapshot")
    refs = set(references or [])
    for name, repo in project.config["repositories"].items():
        refs.update(f"{name}:{p}" for p in repo.get("required_docs", []))
    for target in project.config.get("targets", {}).values():
        refs.update(f"{target['repository']}:{target[field]}"
                    for field in ("report", "symbols", "splits", "original") if target.get(field))
    initial = {name: repository_state(project.root(name)) for name in project.config["repositories"]}
    files = {ref: file_record(project.reference(ref)) for ref in sorted(refs)}
    final = {name: repository_state(project.root(name)) for name in project.config["repositories"]}
    if initial != final or digest(project.path) != project.fingerprint:
        raise ValueError("Repository changed during snapshot; retry after the writer finishes")
    return {"schema_version": 1, "project": project.config["id"],
            "manifest_sha256": project.fingerprint, "repositories": final, "files": files,
            "scope": "Repository state and named files; not a build, test result, or full asset inventory"}


def check_snapshot(project: Project, previous: dict[str, Any]) -> dict[str, Any]:
    if previous.get("schema_version") != 1 or previous.get("project") != project.config["id"]:
        raise ValueError("Snapshot belongs to a different project or schema")
    if previous.get("manifest_sha256") != digest(project.path):
        return {"current": False, "changes": ["project manifest changed"]}
    current = snapshot(project, list(previous["files"]))
    changes = []
    for section in ("repositories", "files"):
        for key in sorted(previous[section].keys() | current[section].keys()):
            if previous[section].get(key) != current[section].get(key):
                changes.append(f"{section}:{key}")
    return {"current": not changes, "changes": changes}
