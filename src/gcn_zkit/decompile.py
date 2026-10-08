"""Ghidra's decompilation of ORIGINAL functions: a second reading of every function next to m2c.

Measured on a 27.5k-function decomp (docs/validation.md): overall its structure ties m2c's; m2c is closer on
switch, return and call shape, Ghidra on loops and gotos, and where m2c fails or emits goto Ghidra's control flow
is closer to the matched source in 111 of 160 functions that differ. Agents read both and take whichever shape fits.

The cache never goes stale on renames or data re-layouts: the worker sees only bytes and function boundaries
(address names, undefined data) and current names are substituted on read. A row is keyed by the decompiler
environment plus the function's own (address, size); `gcn-zkit decompile --all` fills a 27k-function DOL in ~40 s.

Memory is sized from the machine's total and currently available RAM when a worker starts (`budget`). Two hard
rules: all agent sessions together (every claude/codex process tree: builds, tests, other workers) stay under
GCN_ZKIT_AGENT_RAM_MB (default half of total RAM), and a worker never starts if it would leave less than 10% of
total RAM (at least 2 GB) available. Within those, the JVM heap ceiling is 1/8 of available RAM (512 MB-4 GB; the JVM takes what it uses),
threads are min(8, CPUs) trimmed to what fits, and as many workers run at once as fit (up to 4, one slot lock each
in the cache directory); the rest wait for a slot and then reuse rows another worker just wrote. Measured on a
27.5k-function DOL: ~1.0 GB peak per worker (JVM 860 MB, four decompiler processes 140 MB on the largest
functions); with a 512 MB heap the whole DOL decompiles in 163 s at 850 MB peak, so an 8 GB machine can run it.
A call decompiles only the functions it names; nothing ever decompiles the whole DOL unless asked (`--all`). GCN_ZKIT_GHIDRA_HEAP (e.g. 3g) and GCN_ZKIT_GHIDRA_MIN_FREE_MB override the heap and the reserve.
Cached reads never start Ghidra.
"""

from __future__ import annotations

import glob
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import REPOSITORY
from .index import MODULE_SHIFT, address_text, cache_path, connect, function_at, refresh
from .project import Project, digest

WORKER_VERSION = 1
EXTENSION = "https://github.com/Cuyler36/Ghidra-GameCube-Loader/releases"
INSTALL = (f"uv tool install --force 'gcn-zkit[ghidra] @ git+https://github.com/{REPOSITORY}'   (from a checkout: "
           "uv tool install --force --editable '<checkout>[ghidra]')")
LIMITS = ("Ghidra's reading of the original bytes at decomp-toolkit's boundaries, without auto-analysis or types. "
          "Read it next to m2c for any unmatched function and start from whichever shape fits: its loops and "
          "branches are closer where m2c fails or emits goto, m2c's switches and calls usually are elsewhere. "
          "Retype it before compiling (undefined4, param_N); it is not evidence of runtime parity.")
DEFAULT_THREADS = 8
HEAP_MB = (512, 4096)
# Estimates for the budget, above the measured peaks: JVM 750-860 MB (512 MB-2 GB heap ceilings), each decompiler
# thread <= 35 MB, on the 400 largest functions and on all 27.5k (163 s at 512 MB and 2 threads).
JVM_MB, THREAD_MB = 1000, 64
MAX_WORKERS = 4


def install_dir() -> Path | None:
    """GHIDRA_INSTALL_DIR, else the install behind ghidraRun/pyghidra on PATH, else the usual locations."""
    candidates: list[Path] = []
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        candidates.append(Path(os.environ["GHIDRA_INSTALL_DIR"]))
    for name in ("ghidraRun", "pyghidra", "analyzeHeadless", "ghidra"):
        found = shutil.which(name)
        if found:
            real = Path(found).resolve()
            candidates += [real.parent, real.parent.parent]
    candidates += [Path(p) for p in ("/opt/ghidra", "/usr/share/ghidra", "/usr/local/share/ghidra", "/usr/lib/ghidra")]
    candidates += [Path(p) for p in sorted(glob.glob("/opt/homebrew/Caskroom/ghidra/*/ghidra_*"), reverse=True)]
    return next((c for c in candidates if (c / "Ghidra" / "application.properties").is_file()), None)


def _properties(install: Path) -> dict[str, str]:
    lines = (install / "Ghidra" / "application.properties").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))


def _user_settings(version: str, release: str) -> Path:
    name = f"ghidra_{version}_{release}"
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home()) / "ghidra" / name
    if sys.platform == "darwin":
        return Path.home() / "Library" / "ghidra" / name
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "ghidra" / name


def gekko_language(install: Path) -> Path | None:
    """The .ldefs that defines PowerPC:BE:32:Gekko_Broadway (paired singles), installed or per user."""
    props = _properties(install)
    roots = [install / "Ghidra" / "Extensions",
             _user_settings(props.get("application.version", ""), props.get("application.release.name", "")) / "Extensions"]
    for root in roots:
        for ldefs in sorted(root.glob("*/data/languages/*.ldefs")):
            if "Gekko_Broadway" in ldefs.read_text(encoding="utf-8", errors="replace"):
                return ldefs
    return None


def _memory_mb() -> tuple[int | None, int | None]:
    """(total, available) RAM in MB; None where the platform does not say."""
    try:
        info = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines())
        return int(info["MemTotal"].split()[0]) // 1024, int(info["MemAvailable"].split()[0]) // 1024
    except (OSError, KeyError, ValueError):
        pass
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1 << 20), None
    except (AttributeError, ValueError, OSError):
        return None, None


AGENTS = ("claude", "codex")


def _agent_mb() -> int | None:
    """Proportional RAM (PSS) of every live agent session's process tree, or None off Linux."""
    proc = Path("/proc")
    if not (proc / "self" / "smaps_rollup").exists():
        return None
    parent: dict[int, int] = {}
    roots = set()
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            argv0 = (entry / "cmdline").read_bytes().split(b"\0", 1)[0].decode(errors="replace")
        except OSError:
            continue
        pid = int(entry.name)
        parent[pid] = int(stat.rsplit(")", 1)[1].split()[1])
        if stat[stat.index("(") + 1:stat.rindex(")")] in AGENTS or Path(argv0).name in AGENTS:
            roots.add(pid)
    children: dict[int, list[int]] = {}
    for pid, ppid in parent.items():
        children.setdefault(ppid, []).append(pid)
    members, todo = set(), list(roots)
    while todo:
        pid = todo.pop()
        if pid not in members:
            members.add(pid)
            todo += children.get(pid, [])
    total = 0
    for pid in members:
        try:
            for line in (proc / str(pid) / "smaps_rollup").read_text(encoding="utf-8").splitlines():
                if line.startswith("Pss:"):
                    total += int(line.split()[1])
                    break
        except (OSError, ValueError):
            continue
    return total // 1024


def _heap_mb(text: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([gGmM]?)\s*", text)
    if not match:
        raise ValueError(f"GCN_ZKIT_GHIDRA_HEAP={text!r}: use a size like 1g or 1536m")
    return int(match[1]) * (1024 if match[2] in "gG" and match[2] else 1)


def budget(threads: int | None = None) -> dict:
    """Heap, threads and concurrent worker slots from total and available RAM and what agent sessions already
    use, or `refuse` with the reason."""
    total, available = _memory_mb()
    agents = _agent_mb()
    cap = (int(os.environ["GCN_ZKIT_AGENT_RAM_MB"]) if os.environ.get("GCN_ZKIT_AGENT_RAM_MB")
           else (total // 2 if total else None))
    room = None if available is None else available  # what a new worker may take without breaking a rule
    reserve = (int(os.environ["GCN_ZKIT_GHIDRA_MIN_FREE_MB"]) if os.environ.get("GCN_ZKIT_GHIDRA_MIN_FREE_MB")
               else max(2048, (total or 0) // 10))
    if os.environ.get("GCN_ZKIT_GHIDRA_HEAP"):
        heap = _heap_mb(os.environ["GCN_ZKIT_GHIDRA_HEAP"])
    else:
        heap = HEAP_MB[1] if available is None else max(HEAP_MB[0], min(HEAP_MB[1], available // 8))
    if room is not None:
        room -= reserve
    if agents is not None and cap is not None:
        room = cap - agents if room is None else min(room, cap - agents)
    threads = max(1, min(threads or DEFAULT_THREADS, os.cpu_count() or DEFAULT_THREADS))
    if room is not None:
        threads = max(1, min(threads, (room - JVM_MB) // THREAD_MB))
    need = JVM_MB + THREAD_MB * threads
    result = {"total_mb": total, "available_mb": available, "reserve_mb": reserve, "agents_mb": agents,
              "agent_cap_mb": cap, "heap_mb": heap, "threads": threads, "need_mb": need,
              "workers": MAX_WORKERS if room is None else max(1, min(MAX_WORKERS, room // need))}
    if available is not None and available - need < reserve:
        result["refuse"] = (f"Not starting Ghidra: {available} MB of {total} MB available; a worker needs ~{need} MB "
                            f"and must leave {reserve} MB (GCN_ZKIT_GHIDRA_MIN_FREE_MB). Cached functions still read "
                            "instantly; retry when memory frees up.")
    elif agents is not None and cap is not None and agents + need > cap:
        result["refuse"] = (f"Not starting Ghidra: agent sessions already use {agents} MB; a worker needs ~{need} MB "
                            f"and all agents stay under {cap} MB (GCN_ZKIT_AGENT_RAM_MB). Cached functions still read "
                            "instantly; retry when a build or session finishes.")
    return result


class _WorkerLock:
    """A worker slot: as many Ghidra workers run at once as available RAM fits (`budget`); the rest wait here
    instead of each starting a JVM the machine cannot hold."""

    def __init__(self, project: Project, slots: int = 1):
        self.base = cache_path(project).parent / "ghidra-worker"
        self.slots = max(1, slots)
        self.handle = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:  # Windows: no flock, run unguarded
            return self
        for slot in range(self.slots):
            handle = open(f"{self.base}-{slot}.lock", "a+")
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.handle = handle
                return self
            except OSError:
                handle.close()
        self.handle = open(f"{self.base}-{os.getpid() % self.slots}.lock", "a+")
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        if self.handle:
            self.handle.close()  # releases the lock


def _python() -> str | None:
    configured = os.environ.get("GCN_ZKIT_GHIDRA_PYTHON")
    if configured:
        return configured
    return sys.executable if importlib.util.find_spec("pyghidra") else None


def status() -> dict:
    """What `doctor` reports; `problem`/`fix` are set when decompilation cannot run."""
    install = install_dir()
    if install is None:
        return {"problem": "Ghidra not found", "fix": "install Ghidra 11.3+ or set GHIDRA_INSTALL_DIR"}
    props = _properties(install)
    version = f"{props.get('application.version')} {props.get('application.release.name')}"
    language = gekko_language(install)
    python = _python()
    info = {"install": str(install), "version": version, "language": str(language) if language else None,
            "python": python}
    if language is None:
        info.update(problem="Ghidra lacks the Gekko/Broadway language (paired singles)",
                    fix=f"unzip the GameCube Loader for Ghidra {props.get('application.version')} from {EXTENSION} into "
                        f"{_user_settings(props.get('application.version', ''), props.get('application.release.name', '')) / 'Extensions'}"
                        " (only its language is used; its DOL loader, which opens dialogs, never runs)")
    elif python is None:
        info.update(problem="pyghidra is not installed", fix=INSTALL)
    return info


_AVAILABLE: list = [0.0, False]


def available() -> bool:
    """Whether `decompile` can run, rechecked every 5 minutes (cheap enough for every lookup)."""
    if time.monotonic() - _AVAILABLE[0] > 300:
        _AVAILABLE[:] = [time.monotonic(), not status().get("problem")]
    return _AVAILABLE[1]


_DOL_DIGESTS: dict[str, tuple[tuple[int, int], str]] = {}


def _dol_digest(path: Path) -> str:
    info = path.stat()
    stamp = (info.st_mtime_ns, info.st_size)
    cached = _DOL_DIGESTS.get(str(path))
    if cached is None or cached[0] != stamp:
        cached = (stamp, digest(path))
        _DOL_DIGESTS[str(path)] = cached
    return cached[1]


def _environment(info: dict, dol: Path, sda: dict[int, int]) -> str:
    language = Path(info["language"])
    sources = (".ldefs", ".sinc", ".slaspec", ".pspec", ".cspec")  # not .sla: Ghidra compiles it on first use
    stamp = [f"{p.name}:{p.stat().st_size}" for p in sorted(language.parent.iterdir()) if p.suffix in sources]
    key = json.dumps([WORKER_VERSION, info["version"], stamp, _dol_digest(dol), sorted(sda.items())])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _store(project: Project) -> sqlite3.Connection:
    base = cache_path(project)
    db = sqlite3.connect(base.with_name(f"{base.stem}-ghidra.sqlite"), timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS decompiled(env TEXT, address INTEGER, size INTEGER, text TEXT, error TEXT,"
               " PRIMARY KEY(env, address, size))")
    return db


def _run_worker(info: dict, dol: Path, sda: dict[int, int], boundaries: list[tuple[int, int]],
                addresses: list[int], threads: int | None) -> tuple[list[dict], dict]:
    plan = budget(threads)
    if plan.get("refuse"):
        raise ValueError(plan["refuse"])
    with tempfile.TemporaryDirectory(prefix="gcn-zkit-ghidra-") as work:
        request, output = Path(work) / "request.json", Path(work) / "out.jsonl"
        request.write_text(json.dumps({"install_dir": info["install"], "dol": str(dol), "sda": sda,
                                       "functions": boundaries, "addresses": addresses,
                                       "threads": plan["threads"], "heap": f"{plan['heap_mb']}m",
                                       "output": str(output)}), encoding="utf-8")
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [str(Path(__file__).resolve().parents[1]),
                                                                         os.environ.get("PYTHONPATH")])))
        result = subprocess.run([info["python"], "-m", "gcn_zkit.ghidra_worker", str(request)], env=env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=180 + len(addresses) // 4)
        rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()] if output.exists() else []
    if rows and "error" in rows[0] and "address" not in rows[0]:
        raise ValueError(rows[0]["error"])
    if result.returncode != 0 or not rows or "timing" not in rows[-1]:
        tail = "\n".join(result.stderr.strip().splitlines()[-6:])
        raise ValueError(f"Ghidra worker failed (exit {result.returncode}): {tail}")
    return rows[:-1], rows[-1]["timing"]


FN_NAME = re.compile(r"\bfn_([0-9A-F]{8})\b")
DATA_NAME = re.compile(r"\b(?:PTR_\w*?_|DAT_|[a-z]{1,6}Ram)([0-9a-fA-F]{8})\b")
# Ghidra notes dead paths it pruned; with GQR0 pinned these are paired-single dequantization paths, never source.
UNREACHABLE = re.compile(r"^/\* WARNING: Removing unreachable block \(ram,0x[0-9a-f]+\) \*/\n", re.M)
POINTER = re.compile(r"\b0x(8[01][0-9a-fA-F]{6})\b")  # lis/addi addresses Ghidra did not type as pointers


def _namer(project: Project, target: str, db):
    """Current names for Ghidra's address names: functions exactly, data as symbol or symbol.unkOFFSET, and
    image constants that land inside a symbol as its address. Constants outside every symbol stay numbers."""
    from .bridge import _symbol_lookup
    seen: dict[tuple[str, int], str | None] = {}

    def function(match: re.Match) -> str:
        address = int(match[1], 16)
        if ("fn", address) not in seen:
            row = function_at(db, target, address)
            seen["fn", address] = row["name"] if row and row["address"] == address else None
        return seen["fn", address] or match[0]

    def data(match: re.Match) -> str:
        address = int(match[1], 16)
        if ("data", address) not in seen:
            symbol = _symbol_lookup(project, target, address)
            name = None
            if symbol:
                name = symbol["name"] + (f".unk{symbol['offset']:X}" if symbol["offset"] else "")
            seen["data", address] = name
        return seen["data", address] or match[0]

    def pointer(match: re.Match) -> str:
        address = int(match[1], 16)
        if ("ptr", address) not in seen:
            symbol = _symbol_lookup(project, target, address)
            name = None
            if symbol and symbol["type"] == "function" and not symbol["offset"]:
                name = symbol["name"]
            elif symbol and symbol["type"] != "function":
                name = "&" + symbol["name"] + (f".unk{symbol['offset']:X}" if symbol["offset"] else "")
            seen["ptr", address] = name
        return seen["ptr", address] or match[0]

    return lambda text: POINTER.sub(pointer, DATA_NAME.sub(data, FN_NAME.sub(function, UNREACHABLE.sub("", text))))


def decompile(project: Project, target: str, addresses: list[int] | None, threads: int | None = None) -> dict:
    """Decompile DOL functions (None: every function not cached yet). Cached rows return instantly; misses run
    one Ghidra worker for all of them."""
    info = status()
    if info.get("problem"):
        raise ValueError(f"Ghidra decompilation is unavailable: {info['problem']}. Fix: {info['fix']}")
    from .inspect_dol import _dol, sda_bases
    config = project.target(target)
    dol_path = project.file(config["repository"], config["original"]) if config.get("original") else None
    if dol_path is None or not dol_path.is_file():
        raise ValueError(f"Target {target} has no original executable on disk")
    refresh(project, [])
    db = connect(project)
    sda = sda_bases(project, target, _dol(project, target))
    env = _environment(info, dol_path, sda)
    boundaries = [(r[0], r[1]) for r in db.execute(
        "SELECT address, size FROM functions WHERE target=? AND address<? ORDER BY address",
        (target, 1 << MODULE_SHIFT))]
    sizes = dict(boundaries)
    every = addresses is None
    wanted = [a for a, _ in boundaries] if every else list(dict.fromkeys(addresses))
    store = _store(project)

    def read_cache(candidates: list[int]) -> dict:
        found = {}
        for address in candidates:
            row = store.execute("SELECT text, error FROM decompiled WHERE env=? AND address=? AND size=?",
                                (env, address, sizes.get(address, -1))).fetchone()
            if row:
                found[address] = row
        return found

    cached = read_cache(wanted)
    missing = [a for a in wanted if a not in cached and a in sizes]
    timing, started = None, time.monotonic()
    if missing:
        with _WorkerLock(project, budget(threads)["workers"]):
            cached.update(read_cache(missing))  # another agent's worker may have filled them while we waited
            missing = [a for a in missing if a not in cached]
            if missing:
                rows, timing = _run_worker(info, dol_path, sda, boundaries, missing, threads)
                with store:
                    store.execute("DELETE FROM decompiled WHERE env<>?", (env,))  # rows of an older Ghidra or DOL
                    store.executemany("INSERT OR REPLACE INTO decompiled VALUES(?,?,?,?,?)",
                                      [(env, r["address"], sizes[r["address"]], r.get("text"), r.get("error"))
                                       for r in rows])
                cached.update({r["address"]: (r.get("text"), r.get("error")) for r in rows})
    store.close()
    if every:
        return {"target": target, "functions": len(wanted), "decompiled_now": len(missing),
                "seconds": round(time.monotonic() - started, 1), "worker": timing, "limits": LIMITS}
    rename = _namer(project, target, db)
    results = []
    for address in wanted:
        row = function_at(db, target, address)
        if address >= 1 << MODULE_SHIFT:
            results.append({"address": address_text(address), "error": "REL module functions are not supported"})
        elif address not in sizes or row is None or row["address"] != address:
            results.append({"address": address_text(address), "error": "not a function start in the decomp's symbols"})
        else:
            text, error = cached[address]
            results.append({"address": address_text(address), "name": row["name"], "size": row["size"],
                            "match": row["match"], "text": rename(text) if text else None, "error": error,
                            "cached": address not in missing})
    return {"target": target, "engine": f"Ghidra {info['version']} decompiler, {Path(info['language']).stem}",
            "results": results, "decompiled_now": len(missing), "seconds": round(time.monotonic() - started, 2),
            "limits": LIMITS}
