"""Who else is working, what is unfinished, and what the last session said.

Read-only. On Linux, processes and lock holders come from /proc (inspecting a lock never competes with a
real builder); on macOS and Windows processes come from psutil and lock holders are not shown.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .project import Project

# Programs worth reporting. Manifests add their own (`processes`: regexes over the program name).
PROGRAMS = r"claude|codex|ninja|wibo|mwcceppc\S*|mwldeppc\S*|cmake|ctest|dolphin-emu\S*|dolphin|python\S*|py"
SEP = r"(?:^|[/\\])"
END = r"(?:\.exe)?(?:\s|$)"
INTERESTING = re.compile(f"{SEP}({PROGRAMS}){END}", re.I)


def _interesting(project: Project) -> re.Pattern:
    extra = project.config.get("processes", [])
    return re.compile(f"{SEP}({PROGRAMS}{''.join('|' + p for p in extra)}){END}", re.I) if extra else INTERESTING
PYTHON_TOOLS = re.compile(r"(tools/[\w./-]+\.py|verify-[\w-]+\.py|permuter\.py)")
# This toolkit's own MCP servers and CLI calls are never "activity". Match the program, not any path that happens to
# contain the name (a decomp inside a folder called zkit-something is still a decomp).
OWN = re.compile(r"(?:^|[/\\])zkit(?:\.exe)?(?:\s|$)|-m zkit\.cli\b")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    return result.stdout if result.returncode == 0 else ""


def _parallel(fn, items: list) -> list:
    """fn over items in threads: the git calls are independent subprocesses (activity ran ~40 in series)."""
    if len(items) < 2:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(8, len(items))) as pool:
        return list(pool.map(fn, items))


def state_dir(project: Project) -> Path:
    from .paths import state_home
    base = state_home()
    path = base / re.sub(r"[^\w.-]", "_", project.config["id"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def _boot_time() -> float:
    try:
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except OSError:
        pass
    return time.time()


# Reported even when their cwd is outside every repo: other agent sessions and emulators.
ANYWHERE = re.compile(f"{SEP}(claude|codex|dolphin-emu\\S*){END}", re.I)


def _ancestors() -> set[int]:
    """This process and its parents: the session asking must not report itself."""
    if not Path("/proc/self").is_dir():
        try:
            import psutil
            me = psutil.Process()
            return {me.pid, *(p.pid for p in me.parents())}
        except (ImportError, Exception):  # noqa: BLE001 - best effort off Linux
            return {os.getpid()}
    chain, pid = set(), os.getpid()
    while pid > 1 and pid not in chain:
        chain.add(pid)
        try:
            pid = int(Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            break
    return chain


def processes(project: Project) -> list[dict]:
    """User processes inside a configured repository, plus agents/emulators anywhere."""
    roots = {name: project.root(name) for name in project.config["repositories"]}
    anywhere = bool(project.config.get("agents_anywhere"))
    interesting = _interesting(project)
    located: dict[str, tuple[str | None, str | None]] = {}

    def keep(cmd: str, cwd: Path) -> tuple[str | None, str | None] | None:
        """(repo, worktree) when a process is worth reporting, else None."""
        if not cmd or not interesting.search(cmd.split(" -c ")[0][:400]) or OWN.search(cmd[:300]):
            return None
        program = re.split(r"[/\\]", cmd.split()[0])[-1].lower()
        if program.startswith(("python", "py")) and not PYTHON_TOOLS.search(cmd):
            return None
        key = str(cwd)
        if key not in located:
            try:
                located[key] = project.locate(cwd) if cwd.is_dir() else (None, None)
            except (OSError, ValueError):
                located[key] = (None, None)
        repo, worktree = located[key]
        if repo is None:
            if not ANYWHERE.search(cmd.split(" -c ")[0][:400]) or "--type=" in cmd or "node_modules" in cmd:
                return None
            # An agent outside the repos counts when it runs from a folder holding them (a workspace), or
            # anywhere when the manifest says so ("agents_anywhere": sessions launched from $HOME on this project).
            if not anywhere and not any(r.is_relative_to(cwd) for r in roots.values()
                                        if cwd not in (Path.home(), Path(cwd.anchor))):
                return None
            repo = "(outside repos)"
        return repo, worktree

    use_proc = Path("/proc/self").is_dir() and hasattr(os, "getuid") and os.environ.get("ZKIT_PROCESSES") != "psutil"
    out = _processes_proc(keep) if use_proc else _processes_psutil(keep)
    out.sort(key=lambda p: (p["repo"], -p["age_min"]))
    return out


def _processes_proc(keep) -> list[dict]:
    """Linux: read /proc directly (fast, no dependency)."""
    me, out = os.getuid(), []
    ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    boot, now = _boot_time(), time.time()
    mine = _ancestors()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) in mine:
            continue
        try:
            if entry.stat().st_uid != me:
                continue
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            cwd = Path(os.readlink(entry / "cwd"))
            stat = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        found = keep(cmd, cwd)
        if found is None:
            continue
        started = boot + int(stat[19]) / ticks
        cpu_seconds = (int(stat[11]) + int(stat[12])) / ticks
        age = max(now - started, 1)
        out.append({"pid": int(entry.name), "repo": found[0], "worktree": found[1], "age_min": round(age / 60, 1),
                    "cpu_pct": round(100 * cpu_seconds / age), "cmd": cmd[:160]})
    return out


def _processes_psutil(keep) -> list[dict]:
    """macOS and Windows: the same view through psutil (processes whose cwd is unreadable are skipped)."""
    try:
        import psutil
    except ImportError:
        return []
    out, now, mine = [], time.time(), _ancestors()
    try:
        user = psutil.Process().username()
    except psutil.Error:
        user = None
    for proc in psutil.process_iter(["pid", "username"]):
        if proc.pid in mine or (user and proc.info.get("username") != user):
            continue
        try:
            cmd = " ".join(proc.cmdline()).strip()
            cwd = Path(proc.cwd())
            started, times = proc.create_time(), proc.cpu_times()
        except (psutil.Error, OSError, ValueError):
            continue
        found = keep(cmd, cwd)
        if found is None:
            continue
        age = max(now - started, 1)
        out.append({"pid": proc.pid, "repo": found[0], "worktree": found[1], "age_min": round(age / 60, 1),
                    "cpu_pct": round(100 * (times.user + times.system) / age), "cmd": cmd[:160]})
    return out


def _has_open(pid: int, path: Path) -> bool:
    target = path.resolve()
    try:
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                if Path(os.readlink(fd)) == target:
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def lock_holders(project: Project) -> list[dict]:
    """Configured lock files and the pid holding a POSIX/flock lock on them."""
    rows = []
    try:
        table = Path("/proc/locks").read_text(encoding="utf-8").splitlines()
    except OSError:
        table = []
    for name, repo in project.config["repositories"].items():
        for rel in repo.get("locks", []):
            path = project.file(name, rel)
            if not path.exists():
                rows.append({"repo": name, "lock": rel, "held": False})
                continue
            stat = path.stat()
            holder = None
            for line in table:
                parts = line.split()
                # Match the inode only: on btrfs subvolumes st_dev differs from the device /proc/locks
                # prints. Confirm by checking that the pid really has this file open.
                if len(parts) >= 6 and parts[5].rsplit(":", 1)[-1] == str(stat.st_ino) and parts[4].lstrip("-").isdigit():
                    pid = int(parts[4])
                    if pid > 0 and _has_open(pid, path):
                        holder = pid
            alive_cmd = None
            if holder:
                try:
                    alive_cmd = Path(f"/proc/{holder}/cmdline").read_bytes().replace(b"\0", b" ").decode()[:120]
                except OSError:
                    pass
            content = path.read_text(encoding="utf-8", errors="replace").strip()[:120] if stat.st_size < 4096 else ""
            rows.append({"repo": name, "lock": rel, "held": bool(holder), "holder_pid": holder,
                         "holder_cmd": alive_cmd, "file_says": content,
                         "note": None if holder or not content else "file content is stale; nobody holds the lock"})
    return rows


# Processes that write a checkout's build outputs (of those `processes` reports: compilers run under wibo).
# Repositories add their own build tools with "builders" (regexes over `tools/x.py ...` command lines).
BUILDERS = [r"(?:^|/)(ninja|cmake|ctest|wibo|mwcceppc\S*)(?:\s|$)"]


def builders(project: Project, repo: str, worktree: str | None = None) -> list[dict]:
    """Build processes running in one checkout (the main one, or `worktree`) and the locks held on it.

    Only a process's own program and arguments are matched, never a `sh -c` script: two agents both running
    `zkit wait && ninja` must not see each other's wrapper shell and wait forever."""
    patterns = [re.compile(p) for p in BUILDERS + project.config["repositories"][repo].get("builders", [])]
    busy = []
    for proc in processes(project):
        if proc["repo"] != repo or (proc["worktree"] or None) != (worktree or None):
            continue
        if any(p.search(proc["cmd"].split(" -c ")[0]) for p in patterns):
            busy.append({"pid": proc["pid"], "cmd": proc["cmd"], "age_min": proc["age_min"]})
    scoped = project.with_overlay(repo, worktree) if worktree else project
    mine = _ancestors()
    for lock in lock_holders(scoped):
        if lock["repo"] == repo and lock["held"] and lock["holder_pid"] not in mine:
            if not any(b["pid"] == lock["holder_pid"] for b in busy):
                busy.append({"pid": lock["holder_pid"], "cmd": lock.get("holder_cmd") or "?", "lock": lock["lock"]})
            else:
                next(b for b in busy if b["pid"] == lock["holder_pid"])["lock"] = lock["lock"]
    return busy


def wait_idle(project: Project, repo: str, worktree: str | None = None, timeout: float = 600, settle: float = 3,
              poll: float = 0.5) -> dict[str, Any]:
    """Block until no builder runs and no configured lock is held in the checkout for `settle` seconds in a row.

    Read-only and advisory: it replaces pgrep/sleep loops, it does not reserve anything. Two sessions that both
    see "idle" can still start together, so take the repository's build lock for the build itself."""
    started = time.monotonic()
    seen: dict[int, dict] = {}
    quiet_since = None
    while True:
        busy = builders(project, repo, worktree)
        for b in busy:
            seen.setdefault(b["pid"], b)
        now = time.monotonic()
        if busy:
            quiet_since = None
        elif quiet_since is None:
            quiet_since = now
        if quiet_since is not None and now - quiet_since >= settle:
            idle, current = True, []
            break
        if now - started >= timeout:
            idle, current = False, busy
            break
        time.sleep(poll)
    locks = project.config["repositories"][repo].get("locks", [])
    return {"repo": repo, "worktree": worktree, "idle": idle, "ok": idle, "waited_s": round(time.monotonic() - started, 1),
            "waited_on": list(seen.values()), "still_busy": current,
            "locked_build": f"flock {locks[0]} <command>" if locks else None,
            "limits": "advisory: nothing is reserved; run the build itself under the repository's lock"}


def repository(project: Project, name: str, dirty_limit: int = 12) -> dict[str, Any]:
    root = project.root(name)
    if not (root / ".git").exists():
        return {"repo": name, "git": False}
    branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD").strip()
    head = _git(root, "log", "-1", "--format=%h %cr %s").strip()
    now = time.time()
    dirty = []
    for line in _git(root, "status", "--porcelain=v1").splitlines():
        rel = line[3:].split(" -> ")[-1].strip('"')
        path = root / rel
        try:
            age = (now - path.stat().st_mtime) / 60
        except OSError:
            age = None
        dirty.append({"path": rel, "state": line[:2].strip(), "age_min": round(age, 1) if age is not None else None})
    dirty.sort(key=lambda d: d["age_min"] if d["age_min"] is not None else 1e9)
    main = project.config["repositories"][name].get("main_branch") or next(
        (b for b in ("main", "master") if _git(root, "rev-parse", "--verify", "--quiet", f"refs/heads/{b}")), branch)
    branches = []
    refs = [line for line in _git(root, "for-each-ref", "--format=%(refname:short) %(committerdate:relative)",
                                  "refs/heads").splitlines() if line.split(" ", 1)[0] not in (main, branch)]
    aheads = _parallel(lambda line: _git(root, "rev-list", "--count", f"{main}..{line.split(' ', 1)[0]}").strip(), refs)
    for line, ahead in zip(refs, aheads):
        if ahead and ahead != "0":
            branches.append({"branch": line.split(" ", 1)[0], "unmerged_commits": int(ahead), "last": line.split(" ", 1)[1]})
    worktrees, current = [], {}
    for line in _git(root, "worktree", "list", "--porcelain").splitlines() + [""]:
        if not line:
            if current and Path(current.get("worktree", "")).resolve() != root:
                worktrees.append(current)
            current = {}
        elif " " in line:
            key, value = line.split(" ", 1)
            current[key] = value
        else:
            current[line] = True
    noise = re.compile(project.config["repositories"][name].get(
        "untracked_noise", r"^(\.venv|venv|build|node_modules|__pycache__|\.cache)(/|$)"))
    for tree in worktrees:
        tree["exists"] = Path(tree["worktree"]).is_dir()
    statuses = _parallel(lambda tree: _git(Path(tree["worktree"]), "status", "--porcelain") if tree["exists"] else "",
                         worktrees)
    for tree, status in zip(worktrees, statuses):
        path = Path(tree["worktree"])
        modified, untracked = [], []
        for line in status.splitlines():
            rel = line[3:].strip('"')
            if line.startswith("??"):
                if not noise.search(rel):
                    untracked.append(rel)
            else:
                modified.append(rel)
        tree["modified"], tree["untracked"] = modified[:20], untracked[:20]
        tree["dirty_files"] = len(modified) + len(untracked) if path.is_dir() else None
    stashes = len(_git(root, "stash", "list").splitlines())
    return {"repo": name, "git": True, "branch": branch, "main": main, "head": head,
            "dirty_count": len(dirty), "dirty": dirty[:dirty_limit],
            "recently_touched": sum(1 for d in dirty if d["age_min"] is not None and d["age_min"] < 20),
            "unmerged_branches": branches[:12], "worktrees": worktrees, "stashes": stashes}


def handoffs(project: Project, repo: str | None = None, limit: int = 3) -> list[dict]:
    path = state_dir(project) / "handoff.jsonl"
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if repo:
        rows = [r for r in rows if r.get("repo") in (repo, None)]
    return rows[-limit:][::-1]


def agent_identity() -> str:
    """Which client session is asking: $ZKIT_AGENT, else the nearest claude/codex ancestor and its pid."""
    if os.environ.get("ZKIT_AGENT"):
        return os.environ["ZKIT_AGENT"]
    for pid in sorted(_ancestors()):
        try:
            name = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0", 1)[0].decode(errors="replace")
        except OSError:
            continue
        base = re.split(r"[/\\]", name)[-1].removesuffix(".exe")
        if base in ("claude", "codex"):
            return f"{base}:{pid}"
    return "agent"


REPLACE_WITHIN_S = 1800


def write_handoff(project: Project, repo: str, text: str, author: str | None = None) -> dict:
    """Leave a short note for the next session; the repo state is captured automatically. A session's newer
    note within half an hour replaces its previous one, so checkpoints do not bury the real handoff."""
    if not text.strip() or len(text) > 4000:
        raise ValueError(f"Handoff text must be 1..4000 characters (got {len(text)}); keep the next command, "
                         "commit ids and blockers, and point at a file for the rest")
    state = repository(project, repo, dirty_limit=30)
    who = author or agent_identity()
    now = datetime.now(timezone.utc)
    row = {"time": now.isoformat(timespec="seconds"), "repo": repo, "author": who, "text": text.strip(),
           "head": state.get("head"), "branch": state.get("branch"), "worktree": project.worktree(repo),
           "dirty": [d["path"] for d in state.get("dirty", [])]}
    path = state_dir(project) / "handoff.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] \
        if path.is_file() else []
    last = next((r for r in reversed(rows) if r.get("repo") == repo), None)
    if last and last.get("author") == who and who != "agent" and \
            (now - datetime.fromisoformat(last["time"])).total_seconds() < REPLACE_WITHIN_S:
        rows.remove(last)
        row["replaced"] = last["time"]
    rows.append(row)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows[-500:]), encoding="utf-8")
    return row


def activity(project: Project) -> dict:
    procs = processes(project)
    long_running = re.compile("|".join([r"dolphin", r"\bctest\b", *project.config.get("long_running", [])]), re.I)
    names = [name for name in project.config["repositories"] if project.root(name).is_dir()]
    repos = dict(zip(names, _parallel(lambda name: repository(project, name), names)))
    warnings = []
    for p in procs:
        if p["age_min"] > 45 and long_running.search(p["cmd"]):
            hours = p["age_min"] / 60
            warnings.append(f"pid {p['pid']} ({p['cmd'][:50]}) has run {hours:.1f} h ({p['repo']}); "
                            "stale check or emulator? Kill it if no session owns it.")
    for name, state in repos.items():
        if state.get("recently_touched"):
            warnings.append(f"{name}: {state['recently_touched']} uncommitted file(s) changed in the last 20 min "
                            "(yours, or another live session's — check before committing files you did not edit).")
        missing = [t["worktree"] for t in state.get("worktrees", []) if not t["exists"]]
        if missing:
            warnings.append(f"{name}: {len(missing)} registered worktree(s) are missing ({', '.join(missing[:2])}"
                            + (" ..." if len(missing) > 2 else "") + "): `git worktree prune`.")
    return {"processes": procs, "locks": lock_holders(project), "repositories": repos,
            "handoffs": handoffs(project, limit=4), "warnings": warnings}
