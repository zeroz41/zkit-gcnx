"""Near-misses kept, never thrown away: every candidate `zkit try` (one function or a whole unit) and `zkit sweep`
compiles is stored with the header copies it was compiled against, keyed by the original function's address.

`zkit misses` lists the best kept candidate of each function the tree has not matched, `--restore` writes one out
to start from (a new attempt starts where the last one stopped, not from the tree's source), `--retry` compiles
the kept candidates again against today's tree: a candidate that waited on a callee, a type or a header that has
landed since is found without anyone writing it again. `--import` stores candidates left as files by earlier work.

The store lives in the project's state directory: `misses/blobs/` holds each text once (by its SHA-256), and
`misses/index.jsonl` one row per (function, candidate, headers, result). A retry adds rows; nothing is deleted.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .project import Project

KEEP = 2                     # candidates retried per function: the closest two
MAX_HEADER_FILES = 400       # a header folder larger than this is not a set of copies: it is not stored
MAX_HEADER_BYTES = 8 << 20


def _home(project: Project) -> Path:
    from .activity import state_dir
    path = state_dir(project) / "misses"
    (path / "blobs").mkdir(parents=True, exist_ok=True)
    return path


def _put(home: Path, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    path = home / "blobs" / digest[:2] / digest
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(f".{os.getpid()}.tmp")
        temp.write_bytes(data)
        temp.replace(path)
    return digest


def _get(home: Path, digest: str) -> bytes:
    return (home / "blobs" / digest[:2] / digest).read_bytes()


def _headers(home: Path, includes: list[Path] | None) -> tuple[list[dict[str, str]], bool]:
    """(one {relative path: blob} per header folder in search order, whether every folder was stored)."""
    folders, whole = [], True
    for folder in includes or []:
        files = [p for p in sorted(Path(folder).rglob("*")) if p.is_file()] if Path(folder).is_dir() else []
        if len(files) > MAX_HEADER_FILES or sum(p.stat().st_size for p in files) > MAX_HEADER_BYTES:
            whole = False
            continue
        folders.append({p.relative_to(folder).as_posix(): _put(home, p.read_bytes()) for p in files})
    return folders, whole


_HEADS: dict[str, str] = {}


def _head(root: Path) -> str:
    """The repository's commit, the tree a candidate was compiled against."""
    key = str(root)
    if key not in _HEADS:
        done = subprocess.run(["git", "-C", key, "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        _HEADS[key] = done.stdout.strip() if done.returncode == 0 else ""
    return _HEADS[key]


def rows(project: Project) -> list[dict]:
    path = _home(project) / "index.jsonl"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _append(project: Project, new: list[dict]) -> None:
    if not new:
        return
    with (_home(project) / "index.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("".join(json.dumps(row) + "\n" for row in new))


def _result(row: dict) -> dict:
    return {"exact": bool(row.get("exact")), "differences": row.get("differences"),
            "reloc_only": bool(row.get("reloc_only"))}


def rank(row: dict) -> tuple:
    """Closest first: identical, then relocations only, then the fewest differing words; newest on a tie."""
    words = row.get("differences")
    return (not row.get("exact"), not row.get("reloc_only"), words if words is not None else 10**9,
            -(datetime.fromisoformat(row["time"]).timestamp() if row.get("time") else 0))


def record(project: Project, target: str, text: str, includes: list[Path] | None, results: Iterable[dict],
           origin: str, source: str | None = None) -> int:
    """Keep one candidate text and its header copies for every function in `results` ({address, function, unit,
    exact, differences, reloc_only}). Returns the rows written."""
    results = [r for r in results if r.get("address")]
    if not results:
        return 0
    home = _home(project)
    blob = _put(home, text.encode())
    headers, whole = _headers(home, includes)
    root = project.root(project.target(target)["repository"])
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    candidate = hashlib.sha256((blob + json.dumps(headers, sort_keys=True)).encode()).hexdigest()[:16]
    new = [{"address": r["address"], "function": r.get("function"), "unit": r.get("unit"), "target": target,
            "candidate": candidate, "text": blob, "headers": headers, "headers_whole": whole,
            "with_headers": bool(headers), **_result(r), "origin": origin, "source": source,
            "base": _head(root), "time": stamp} for r in results]
    _append(project, new)
    return len(new)


def record_quietly(*args, **kwargs) -> None:
    """record(), never failing the command that called it: keeping a candidate is a side effect."""
    try:
        record(*args, **kwargs)
    except Exception:  # noqa: BLE001 - a full disk or an odd folder must not fail a try
        pass


def record_unit(project: Project, target: str, unit: str, text: str, includes: list[Path] | None,
                functions: list[dict], origin: str, source: str | None = None) -> int:
    """Keep a unit candidate for each function it defines that the tree has not matched."""
    from .index import address_text, connect
    db = connect(project)
    results = []
    for row in functions:
        if row.get("missing"):
            continue
        found = db.execute("SELECT address, match FROM functions WHERE target = ? AND name = ?",
                           (target, row["function"])).fetchone()
        if found is None or (found["match"] is not None and found["match"] >= 100):
            continue
        results.append({"address": address_text(found["address"]), "function": row["function"], "unit": unit,
                        "exact": row.get("exact"), "differences": row.get("differences"),
                        "reloc_only": row.get("reloc_only")})
    return record(project, target, text, includes, results, origin, source)


def record_unit_quietly(*args, **kwargs) -> None:
    try:
        record_unit(*args, **kwargs)
    except Exception:  # noqa: BLE001 - keeping candidates is a side effect
        pass


def kept_summary(project: Project, target: str, address: str) -> dict | None:
    """What is already kept for one function, for `zkit try` to show before it starts again."""
    try:
        kept = [r for r in rows(project) if r.get("address") == address and r.get("target", target) == target]
    except Exception:  # noqa: BLE001
        return None
    if not kept:
        return None
    top = min(kept, key=rank)
    return {"candidates": len({r["candidate"] for r in kept}), "best": _state(top), "candidate": top["candidate"],
            "base": top.get("base"), "restore": f"zkit misses {address} --restore DIR"}


def unmatched(project: Project, target: str) -> dict[str, dict]:
    """{address text: {name, unit, match}} of every function the tree's last report does not match."""
    from .index import address_text, connect, refresh
    refresh(project)
    db = connect(project)
    return {address_text(r["address"]): {"name": r["name"], "unit": r["unit"], "match": r["match"]}
            for r in db.execute("SELECT address, name, unit, match FROM functions WHERE target = ? AND "
                                "(match IS NULL OR match < 100)", (target,))}


def addresses_by_name(project: Project, target: str, names: Iterable[str]) -> dict[str, str]:
    from .index import address_text, connect
    db = connect(project)
    out = {}
    for name in set(names):
        row = db.execute("SELECT address FROM functions WHERE target = ? AND name = ?", (target, name)).fetchone()
        if row is not None:
            out[name] = address_text(row["address"])
    return out


def _select(project: Project, target: str, query: str | None, unit: str | None) -> set[str] | None:
    """The addresses a query or unit names (None: every function)."""
    if unit:
        from .candidate import _unit_for
        name = _unit_for(project, target, unit)["name"]
        from .index import address_text, connect
        return {address_text(r["address"]) for r in connect(project).execute(
            "SELECT address FROM functions WHERE target = ? AND unit = ?", (target, name))} | {
            r["address"] for r in rows(project) if r.get("unit") == name}
    if query:
        from . import bridge
        from .index import address_text, connect, containing
        found = bridge.resolve(project, query, target, limit=2)
        if len(found) != 1:
            raise ValueError(f"{query} names {'no' if not found else 'more than one'} function; use its address")
        row = containing(connect(project), target, found[0])
        return {address_text(row["address"])} if row is not None else set()
    return None


def best(project: Project, target: str, address: str) -> dict | None:
    """The closest kept candidate of one function, or None."""
    kept = [r for r in rows(project) if r.get("address") == address and r.get("target", target) == target]
    return min(kept, key=rank) if kept else None


def listing(project: Project, target: str, query: str | None = None, unit: str | None = None,
            everything: bool = False, limit: int = 40) -> dict[str, Any]:
    """The best kept candidate of each function (default: only functions the tree has not matched), closest
    first."""
    chosen = _select(project, target, query, unit)
    open_ = unmatched(project, target)
    groups: dict[str, list[dict]] = {}
    for row in rows(project):
        if row.get("target", target) != target or (chosen is not None and row["address"] not in chosen):
            continue
        if not everything and row["address"] not in open_:
            continue
        groups.setdefault(row["address"], []).append(row)
    entries = []
    for address, kept in groups.items():
        top = min(kept, key=rank)
        entries.append({"address": address, "function": top.get("function"), "unit": top.get("unit"),
                        "best": _state(top), "candidate": top["candidate"], "with_headers": top.get("with_headers"),
                        "origin": top.get("origin"), "base": top.get("base"), "time": top.get("time"),
                        "kept": len({r["candidate"] for r in kept}), "tree_matched": address not in open_,
                        "_rank": rank(top)})
    entries.sort(key=lambda e: e.pop("_rank"))
    return {"functions": len(entries), "candidates": len({r["candidate"] for g in groups.values() for r in g}),
            "entries": entries[:limit] if limit else entries}


def _state(row: dict) -> str:
    if row.get("exact"):
        return "identical"
    if row.get("reloc_only"):
        return "relocations only"
    words = row.get("differences")
    return f"{words} word(s)" if words is not None else "?"


def _materialize(home: Path, row: dict, out: Path, name: str = "candidate.cpp") -> tuple[Path, list[Path]]:
    out.mkdir(parents=True, exist_ok=True)
    source = out / name
    source.write_bytes(_get(home, row["text"]))
    folders = []
    for index, folder in enumerate(row.get("headers") or []):
        base = out / ("include" if index == 0 else f"include{index + 1}")
        for rel, digest in folder.items():
            path = base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(_get(home, digest))
        folders.append(base)
    return source, folders


def restore(project: Project, target: str, key: str, out: Path) -> dict[str, Any]:
    """Write a kept candidate (a function's best, or the candidate id `zkit misses` lists) and its header copies
    to `out`, with the command that tries it."""
    kept = rows(project)
    chosen = [r for r in kept if r.get("candidate") == key]
    if not chosen:
        addresses = _select(project, target, key, None) or set()
        chosen = [r for r in kept if r["address"] in addresses]
    if not chosen:
        raise ValueError(f"nothing kept for {key}")
    top = min(chosen, key=rank)
    source, folders = _materialize(_home(project), top, out, Path(top.get("source") or "candidate.cpp").name)
    include = "".join(f" --include {f}" for f in folders)
    return {"address": top["address"], "function": top.get("function"), "unit": top.get("unit"),
            "state": _state(top), "base": top.get("base"), "written": str(source), "includes": [str(f) for f in folders],
            "try": f"zkit try {top['address']} {source}{include}",
            "try_unit": f"zkit try --unit {top['address']} {source}{include}"}


def _check(manifest: str, target: str, unit: str, text: bytes, headers: list[dict], home: str,
           with_headers: bool) -> dict[str, Any]:
    """One compile of a kept candidate in a worker process: check_unit's rows, or its errors."""
    from .candidate import check_unit
    project = Project.load(manifest)
    with tempfile.TemporaryDirectory(prefix="zkit-misses-") as work:
        root = Path(work)
        source = root / "candidate.cpp"
        source.write_bytes(text)
        folders = []
        if with_headers:
            for index, folder in enumerate(headers):
                base = root / f"include{index}"
                for rel, digest in folder.items():
                    path = base / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(_get(Path(home), digest))
                folders.append(base)
        try:
            data = check_unit(project, target, unit, source, folders or None, link=False, keep_misses=False)
        except Exception as error:  # noqa: BLE001 - one unusable candidate must not stop the rest
            return {"compiled": False, "errors": str(error)}
    return {"compiled": data.get("compiled", False), "functions": data.get("functions", []),
            "tree": data.get("tree"), "debt": data.get("debt", []), "errors": (data.get("errors") or "")[-400:]}


def _jobs(jobs: int | None) -> int:
    return max(1, jobs or (os.cpu_count() or 2) // 2)


def retry(project: Project, target: str, query: str | None = None, unit: str | None = None,
          jobs: int | None = None, max_words: int | None = None, seconds: float | None = None) -> dict[str, Any]:
    """Compile the closest kept candidates of every function the tree has not matched (or those a query or unit
    names) against today's tree, once with the header copies they were kept with and once with the tree's own
    headers, and keep what each compile gives. A candidate is compiled as a unit candidate: every function it
    defines is compared, so one text can close several functions."""
    started = time.monotonic()
    chosen = _select(project, target, query, unit)
    open_ = unmatched(project, target)
    kept = [r for r in rows(project) if r.get("target", target) == target and r["address"] in open_
            and (chosen is None or r["address"] in chosen)]
    groups: dict[str, list[dict]] = {}
    for row in kept:
        groups.setdefault(row["address"], []).append(row)
    work: dict[tuple[str, str, bool], dict] = {}
    recorded: dict[str, dict] = {}
    for address, group in groups.items():
        top = sorted(group, key=rank)
        recorded[address] = top[0]
        if max_words is not None and not top[0].get("exact") and (top[0].get("differences") or 10**9) > max_words:
            continue
        seen = []
        for row in top:
            if row["candidate"] in seen:
                continue
            seen.append(row["candidate"])
            for with_headers in ([True, False] if row.get("headers") else [False]):
                work.setdefault((row["candidate"], row.get("unit") or "", with_headers), row)
            if len(seen) >= KEEP:
                break
    home = _home(project)
    manifest = str(project.path)
    findings: dict[str, dict] = {}
    compiled = failed = 0
    new_rows: list[dict] = []
    candidates: list[dict] = []
    names: dict[str, str] = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=_jobs(jobs)) as pool:
        futures = {}
        for (candidate, unit_name, with_headers), row in work.items():
            if not unit_name:
                continue
            futures[pool.submit(_check, manifest, target, unit_name, _get(home, row["text"]),
                                row.get("headers") or [], str(home), with_headers)] = (row, with_headers)
        for future in concurrent.futures.as_completed(futures):
            row, with_headers = futures[future]
            if seconds is not None and time.monotonic() - started > seconds:
                for other in futures:
                    other.cancel()
            try:
                data = future.result()
            except (concurrent.futures.CancelledError, Exception):  # noqa: BLE001
                failed += 1
                continue
            if not data.get("compiled"):
                failed += 1
                continue
            compiled += 1
            tree = data.get("tree") or {}
            written = written_in_tree(project, target, row.get("unit") or "")
            dropped = sorted(f["function"] for f in data["functions"] if f.get("missing") and f["function"] in written)
            if tree.get("gained"):
                candidates.append({"candidate": row["candidate"], "unit": row.get("unit"), "source": row.get("source"),
                                   "headers": "kept copies" if with_headers else "tree's",
                                   "gained": [g["function"] for g in tree["gained"]],
                                   "lost": [g["function"] for g in tree.get("lost", [])],
                                   "dropped": len(dropped), "debt": data.get("debt", [])})
            functions = [f for f in data["functions"] if not f.get("missing")]
            names.update(addresses_by_name(project, target, (f["function"] for f in functions
                                                             if f["function"] not in names)))
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for f in functions:
                address = names.get(f["function"])
                if address is None or address not in open_:
                    continue
                result = {"exact": bool(f.get("exact")), "differences": f.get("differences"),
                          "reloc_only": bool(f.get("reloc_only"))}
                new_rows.append({"address": address, "function": f["function"], "unit": row.get("unit"),
                                 "target": target, "candidate": row["candidate"], "text": row["text"],
                                 "headers": row.get("headers") if with_headers else [],
                                 "headers_whole": row.get("headers_whole", True), "with_headers": with_headers,
                                 **result, "origin": "retry", "source": row.get("source"),
                                 "base": _head(project.root(project.target(target)["repository"])), "time": stamp})
                current = findings.get(address)
                if current is None or rank(result) < rank(current["result"]):
                    findings[address] = {"result": result, "candidate": row["candidate"],
                                         "with_headers": with_headers, "function": f["function"],
                                         "unit": row.get("unit")}
    _append(project, new_rows)
    identical, improved = [], []
    for address, found in findings.items():
        before = recorded.get(address)
        entry = {"address": address, "function": found["function"], "unit": found["unit"],
                 "now": _state(found["result"]), "kept_as": _state(before) if before else "new",
                 "candidate": found["candidate"],
                 "headers": "kept copies" if found["with_headers"] else "tree's"}
        if found["result"]["exact"] or found["result"]["reloc_only"]:
            identical.append(entry)
        elif before is not None and rank(found["result"]) < rank(before):
            improved.append(entry)
    identical.sort(key=lambda e: e["address"])
    improved.sort(key=lambda e: e["address"])
    # whole candidates worth merging: what each gains against the tree's build, loses, and leaves out of what the
    # tree has written (a fragment leaves out most of its unit: its functions are spliced in, not the file)
    candidates.sort(key=lambda c: (bool(c["lost"]), c["dropped"] > 0, -len(c["gained"]), c["headers"] != "tree's"))
    return {"functions": len(groups), "compiles": len(work), "compiled": compiled, "failed": failed,
            "identical": identical, "improved": improved, "candidates": candidates,
            "seconds": round(time.monotonic() - started, 1)}


_WRITTEN: dict[tuple[str, str], set[str]] = {}


def written_in_tree(project: Project, target: str, unit: str) -> set[str]:
    """The functions of a unit the tree's report measures (written in the tree's source, matched or not)."""
    key = (target, unit)
    if key not in _WRITTEN:
        from .index import connect
        _WRITTEN[key] = {r["name"] for r in connect(project).execute(
            "SELECT name FROM functions WHERE target = ? AND unit = ? AND match IS NOT NULL", (target, unit))}
    return _WRITTEN[key]


def _unit_of_file(project: Project, target: str, text: str) -> str | None:
    """The unit most of a file's definitions belong to."""
    from . import bridge
    from .index import connect, containing
    db = connect(project)
    votes: dict[str, int] = {}
    for qualified in list(bridge._qualified_definitions(text))[:8]:
        try:
            found = bridge.resolve(project, qualified, target, limit=2)
        except Exception:  # noqa: BLE001 - a name the index does not know
            continue
        if len(found) != 1:
            continue
        row = containing(db, target, found[0])
        if row is not None and row["unit"]:
            votes[row["unit"]] = votes.get(row["unit"], 0) + 1
    return max(votes, key=votes.get) if votes else None


def _unit_by_path(path: Path, sources: dict[str, str], stop: int = 3) -> str | None:
    """The unit a work file's place names: a copy at the unit's own source path (`.../src/a/b.cpp`), or a file in
    a work folder whose `src/` holds one unit's copy."""
    parts = path.resolve().parts
    for start in range(len(parts)):
        unit = sources.get("/".join(parts[start:]))
        if unit:
            return unit
    folder = path.parent
    for _ in range(stop):
        if (folder / "src").is_dir():
            found = {sources.get(f"src/{p.relative_to(folder / 'src').as_posix()}")
                     for p in (folder / "src").rglob("*") if p.suffix in (".c", ".cpp", ".cc")} - {None}
            if len(found) == 1:
                return found.pop()
        folder = folder.parent
    return None


def _sources(project: Project, target: str) -> dict[str, str]:
    """{a unit's source path, also without its first folder: unit name} of every objdiff unit."""
    from . import objects
    out = {}
    for name, unit in objects.objdiff_units(project, target).items():
        source = (unit.get("metadata") or {}).get("source_path")
        if source:
            out[source] = name
            out[source.split("/", 1)[1] if "/" in source else source] = name
    return out


def _header_folders(path: Path, stop: int = 3) -> list[Path]:
    """Header copies a candidate left in a work folder was compiled against: `include/` beside it or in a parent
    (the nearest first)."""
    out, folder = [], path.parent
    for _ in range(stop):
        if (folder / "include").is_dir():
            out.append(folder / "include")
        folder = folder.parent
    return out


def import_files(project: Project, target: str, paths: list[Path], jobs: int | None = None) -> dict[str, Any]:
    """Store candidates earlier work left as files (.c/.cpp/.cc under each path): each file's unit is the one its
    place names (a copy at the unit's source path, or a work folder whose src/ copies one unit), else the one most
    of its definitions belong to; the file is compiled with the header copies beside it, every function it
    defines compared, and the functions the tree has not matched are kept."""
    started = time.monotonic()
    files = []
    for path in paths:
        files += [p for p in sorted(path.rglob("*")) if p.suffix in (".c", ".cpp", ".cc")] if path.is_dir() \
            else [path]
    open_ = unmatched(project, target)
    home = _home(project)
    manifest = str(project.path)
    known = {(r.get("source"), r["text"]) for r in rows(project)}
    sources = _sources(project, target)
    stored = skipped = failed = submitted = 0
    names: dict[str, str] = {}

    def collect(future, path, text, unit, includes) -> int:
        try:
            data = future.result()
        except Exception:  # noqa: BLE001
            return -1
        if not data.get("compiled"):
            return -1
        functions = [f for f in data["functions"] if not f.get("missing")]
        names.update(addresses_by_name(project, target, (f["function"] for f in functions
                                                         if f["function"] not in names)))
        results = [{**f, "address": names.get(f["function"]), "unit": unit}
                   for f in functions if names.get(f["function"]) in open_]
        return record(project, target, text, includes, results, "import", str(path))

    with concurrent.futures.ProcessPoolExecutor(max_workers=_jobs(jobs)) as pool:
        pending: dict = {}
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            if (str(path), hashlib.sha256(text.encode()).hexdigest()) in known:
                skipped += 1
                continue
            unit = _unit_by_path(path, sources) or _unit_of_file(project, target, text)
            if unit is None:
                skipped += 1
                continue
            includes = _header_folders(path)
            headers, _ = _headers(home, includes)
            pending[pool.submit(_check, manifest, target, unit, text.encode(), headers, str(home), bool(headers))] \
                = (path, text, unit, includes)
            submitted += 1
            while len(pending) >= 4 * _jobs(jobs):       # bounded: results are kept as they come
                done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    got = collect(future, *pending.pop(future))
                    failed, stored = failed + (got < 0), stored + max(got, 0)
        for future in concurrent.futures.as_completed(list(pending)):
            got = collect(future, *pending.pop(future))
            failed, stored = failed + (got < 0), stored + max(got, 0)
    return {"files": len(files), "compiled": submitted - failed, "failed": failed, "skipped": skipped,
            "rows": stored, "seconds": round(time.monotonic() - started, 1)}
