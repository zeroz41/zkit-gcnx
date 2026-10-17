"""One incremental SQLite index joining every configured repository.

Tables:
  functions  original functions per target (objdiff report, else symbols.txt)
  calls      direct `bl` edges decoded from the original executable
  refs       pointer-sized words in the original's data sections that point into the image
             (vtable slots, callback/jump tables, pointers to strings and objects)
  xrefs      code -> address references decoded from the original (loads, stores, address
             computations through lis/addi or r2/r13), the "who reads/writes this global" table
  cites      every original address mentioned in configured cite paths (native code, docs)
  mentions   addresses mentioned in the other indexed files (decomp sources, harnesses, tests)
  lines      FTS5 text of configured paths, in small line windows

Files are re-read only when their size or mtime changes, so a query after an edit in
another session sees that edit. A refresh first checks without the write lock and takes it
only when something changed; within one process it is skipped for ZKIT_REFRESH_TTL seconds
(default 3). Nothing here writes to a repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat as statmod
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterable, Iterator

from .gc import asm_functions, asm_references, read_symbols
from .platform import GameCube, Platform, for_target
from .project import Project

SCHEMA = 7
TEXT_SUFFIXES = {".md", ".txt", ".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".inc", ".json", ".py",
                 ".s", ".cmake", ".toml", ".yaml", ".yml", ".lua", ".rs", ".cs", ".glsl", ".hlsl"}
SKIP_DIRS = {"__pycache__", "node_modules"}
MAX_FILE = 2 * 1024 * 1024
WINDOW = 6
def _ttl() -> float:
    return float(os.environ.get("ZKIT_REFRESH_TTL", "3"))
# Cited addresses follow the platform (GameCube main RAM 8[01]xxxxxx, Switch 71xxxxxxxx); repositories may override
# with "address_pattern". Hex-delimited, so glued forms such as Original801977D4 or Foo_80011824 count.
DEFAULT_PROVISIONAL = r"^(fn|FUN|func|sub|lbl|text)_[0-9A-Fa-f]{8,16}$|__sub_[0-9A-Fa-f]{8,16}$|^zz_|^@"
# REL modules have no fixed load address. Their functions are keyed (module_id << 32) | module-relative address,
# so DOL addresses (module 0) keep their plain values and every module gets its own range.
MODULE_SHIFT = 32
MODULE_ADDRESS = re.compile(r"^([A-Za-z_][\w.-]*?)[+:](?:0x)?([0-9A-Fa-f]{1,8})$")
_MODULE_NAMES: dict[int, str] = {}
# The platform of the project this process is answering for; address text and parsing follow it.
_PLATFORM: Platform = GameCube()


def use_platform(project: Project) -> Platform:
    """Make the project's (first target's) platform the one addresses are written and read in."""
    global _PLATFORM
    targets = list(project.config.get("targets", {}).values())
    _PLATFORM = for_target(targets[0]) if targets else GameCube()
    return _PLATFORM


def platform() -> Platform:
    return _PLATFORM


def parse_address(text: str) -> int | None:
    """An address as written (0x80012345, 80012345, 0x7100123456, mymodule+0x1D0) -> its key, or None."""
    keyed = module_address(text)
    if keyed is not None:
        return keyed
    return _PLATFORM.parse(text)


def is_dol_unit(meta: dict, module: str | None) -> bool:
    """An objdiff unit that belongs to the main executable (module id 0) rather than a REL."""
    if meta.get("module_id") is not None:
        return int(meta["module_id"]) == 0
    return not module or meta.get("module_name") in (None, module)


def address_text(value: int) -> str:
    """0x80012345 for the DOL, mymodule+0x124 for a REL function, 0x7100123456 on Switch."""
    if value < 1 << MODULE_SHIFT:
        return _PLATFORM.text(value)
    module = value >> MODULE_SHIFT
    return f"{_MODULE_NAMES.get(module, f'module{module}')}+0x{value & 0xFFFFFFFF:X}"


def module_address(text: str) -> int | None:
    """`mymodule+0x124` / `mymodule:124` -> its key, when the module is known."""
    match = MODULE_ADDRESS.match(text.strip())
    if not match:
        return None
    for module, name in _MODULE_NAMES.items():
        if name == match[1]:
            return (module << MODULE_SHIFT) | int(match[2], 16)
    return None


def _remember_modules(db: sqlite3.Connection) -> None:
    for (value,) in db.execute("SELECT value FROM meta WHERE key LIKE 'modules:%'"):
        try:
            _MODULE_NAMES.update({int(k): v for k, v in json.loads(value).items()})
        except ValueError:
            continue


def cache_path(project: Project) -> Path:
    from .paths import cache_home
    base = cache_home()
    key = hashlib.sha256(str(project.path).encode()).hexdigest()[:12]
    safe = re.sub(r"[^\w.-]", "_", project.config["id"])
    path = base / f"{safe}-{key}.sqlite"
    if _writable(base, path):
        return path
    # Sandboxed clients (Codex) may only write the workspace and /tmp: fall back to a private temp cache.
    user = os.getuid() if hasattr(os, "getuid") else re.sub(r"\W", "_", os.environ.get("USERNAME", "user"))
    fallback = Path(tempfile.gettempdir()) / f"zkit-{user}" / f"{safe}-{key}.sqlite"
    return fallback


def _writable(base: Path, path: Path) -> bool:
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    target = path if path.exists() else base
    return os.access(target, os.W_OK) and os.access(base, os.W_OK)


_CONNECTIONS: dict[tuple[str, int, int], sqlite3.Connection] = {}
_FRESH: dict[tuple[str, str], float] = {}
_LOCK = threading.Lock()
_SCAN = threading.RLock()
_DDL = """
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE files(repo TEXT, path TEXT, mtime INTEGER, size INTEGER, first_row INTEGER, last_row INTEGER,
                PRIMARY KEY(repo, path));
            CREATE TABLE functions(target TEXT, address INTEGER, size INTEGER, name TEXT, demangled TEXT,
                match REAL, unit TEXT, source TEXT, linked INTEGER, provisional INTEGER,
                PRIMARY KEY(target, address));
            CREATE INDEX functions_name ON functions(name);
            CREATE INDEX functions_demangled ON functions(demangled);
            CREATE TABLE calls(target TEXT, caller INTEGER, site INTEGER, callee INTEGER);
            CREATE INDEX calls_caller ON calls(target, caller);
            CREATE INDEX calls_callee ON calls(target, callee);
            CREATE TABLE refs(target TEXT, pointee INTEGER, holder INTEGER);
            CREATE INDEX refs_pointee ON refs(target, pointee);
            CREATE INDEX refs_holder ON refs(target, holder);
            CREATE TABLE xrefs(target TEXT, function INTEGER, pc INTEGER, address INTEGER, kind TEXT);
            CREATE INDEX xrefs_address ON xrefs(target, address);
            CREATE INDEX xrefs_function ON xrefs(target, function);
            CREATE TABLE cites(address INTEGER, repo TEXT, path TEXT, line INTEGER, text TEXT);
            CREATE INDEX cites_address ON cites(address);
            CREATE INDEX cites_file ON cites(repo, path);
            CREATE TABLE mentions(address INTEGER, repo TEXT, path TEXT, line INTEGER, text TEXT);
            CREATE INDEX mentions_address ON mentions(address);
            CREATE INDEX mentions_file ON mentions(repo, path);
            CREATE VIRTUAL TABLE lines USING fts5(repo UNINDEXED, path, line UNINDEXED, body,
                tokenize="unicode61 tokenchars '_:'");
"""
TABLES = ("functions", "calls", "cites", "mentions", "lines", "files", "meta", "refs", "xrefs")


def connect(project: Project) -> sqlite3.Connection:
    """One connection per cache file, process and thread (the MCP server answers calls in threads)."""
    use_platform(project)
    path = cache_path(project)
    key = (str(path), os.getpid(), threading.get_ident())
    if key in _CONNECTIONS:
        return _CONNECTIONS[key]
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Autocommit; transactions are explicit so concurrent sessions serialize their writes.
        db = sqlite3.connect(path, timeout=60, check_same_thread=False, isolation_level=None)
    except sqlite3.OperationalError as error:
        raise sqlite3.OperationalError(
            f"{error}: {path}. Set XDG_CACHE_HOME to a writable directory (the sandbox may forbid ~/.cache).") from error
    db.row_factory = sqlite3.Row
    for attempt in range(200):  # the WAL switch on a fresh file does not wait on the busy handler
        try:
            _prepare(db)
            break
        except sqlite3.OperationalError as error:
            if "locked" not in str(error) and "busy" not in str(error) or attempt == 199:
                raise
            time.sleep(0.05)
    _CONNECTIONS[key] = db
    try:
        _remember_modules(db)  # module+0xOFFSET queries resolve before any refresh in this process
    except sqlite3.Error:
        pass
    return db


def close_connections() -> None:
    """Close this process's cached connections (Windows cannot delete or replace an open database file)."""
    with _LOCK:
        for db in _CONNECTIONS.values():
            try:
                db.close()
            except sqlite3.Error:
                pass
        _CONNECTIONS.clear()
        _FRESH.clear()


def _prepare(db: sqlite3.Connection) -> None:
    db.execute("PRAGMA busy_timeout=60000")
    db.execute("PRAGMA journal_mode=WAL")
    if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA:
        db.execute("BEGIN EXCLUSIVE")
        try:
            if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA:  # another process may have won
                for table in TABLES:
                    db.execute(f"DROP TABLE IF EXISTS {table}")
                for statement in _DDL.split(";"):
                    if statement.strip():
                        db.execute(statement)
                db.execute(f"PRAGMA user_version={SCHEMA}")
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise


def _has_stats(db: sqlite3.Connection) -> bool:
    """Planner statistics exist for the big tables. Without them SQLite picks the wrong sibling of the
    (target, X) indexes (calls by callee through calls_caller: ~1000x slower), so refresh keeps them."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_stat1'").fetchone():
        return False
    found = {row[0] for row in db.execute("SELECT DISTINCT tbl FROM sqlite_stat1 WHERE tbl IN ('calls','xrefs','cites')")}
    empty = {t for t in ("calls", "xrefs", "cites") if not db.execute(f"SELECT 1 FROM {t} LIMIT 1").fetchone()}
    return found | empty >= {"calls", "xrefs", "cites"}


def _meta(db: sqlite3.Connection, key: str) -> str | None:
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def _set_meta(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, value))


def _stamp(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_size}:{stat.st_mtime_ns}"


CW_MEMBER = re.compile(r"^(?P<name>[A-Za-z_]\w*?)__(?P<length>\d+)(?P<rest>\w+)$")
CW_OPERATORS = {"__ct": "{c}", "__dt": "~{c}"}


def cw_demangle(symbol: str) -> str | None:
    """CodeWarrior `method__9TClassFv` -> `TClass::method` (arguments omitted).

    Enough to look a function up by Class::method when no report supplies
    full demangled names. Nested/template classes are left alone."""
    match = CW_MEMBER.match(symbol)
    if not match or match["name"].startswith("_") and match["name"] not in ("__ct", "__dt"):
        return None
    length, rest = int(match["length"]), match["rest"]
    if len(rest) < length or not rest[length:].startswith(("F", "C")):
        return None
    cls = rest[:length]
    name = CW_OPERATORS.get(match["name"], match["name"]).format(c=cls)
    return f"{cls}::{name}"


def provisional_pattern(project: Project, target: str) -> re.Pattern:
    return re.compile(project.target(target).get("provisional_name_pattern", DEFAULT_PROVISIONAL))


def is_provisional(project: Project, target: str, name: str) -> bool:
    return bool(provisional_pattern(project, target).search(name or ""))


def _target_file(project: Project, target: dict, field: str) -> Path | None:
    if not target.get(field):
        return None
    root = project.index_root(target["repository"])
    return Path(os.path.normpath(root / target[field]))


def _function_source(project: Project, target: dict) -> tuple[Path | None, Path | None, Path | None]:
    """Where function boundaries and names come from, best first: the objdiff report, a function list (dtk
    symbols.txt, or a CSV such as nx-decomp-tools'), or the original executable itself (its symbols, or its
    unwind table when stripped)."""
    report = _target_file(project, target, "report")
    symbols = _target_file(project, target, "symbols") or _target_file(project, target, "functions")
    original = _target_file(project, target, "original")
    for candidate in (report, symbols):
        if candidate and candidate.is_file():
            return candidate, report, symbols
    if original and original.is_file() and for_target(target).name == "switch":
        return original, report, symbols
    return None, report, symbols


def _functions_csv(path: Path, target: str, platform: Platform, pattern: re.Pattern) -> list[tuple]:
    """A function list in CSV: address, then (optionally) status, size and name columns, as nx-decomp-tools
    writes (`Address,Quality,Size,Name`). Rows without a size or name are skipped."""
    import csv
    rows = []
    with path.open(encoding="utf-8", errors="replace", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, [])
        columns = {name.strip().lower(): index for index, name in enumerate(header)}
        if "address" not in columns:
            stream.seek(0)
            reader = csv.reader(stream)
            columns = {"address": 0, "quality": 1, "size": 2, "name": 3}
        for row in reader:
            try:
                address = platform.parse(row[columns["address"]])
                size = int(row[columns.get("size", 2)], 0)
            except (IndexError, ValueError, TypeError):
                continue
            if address is None or not size:
                continue
            fname = row[columns["name"]].strip() if columns.get("name") is not None and len(row) > columns["name"] else ""
            fname = fname or f"fn_{platform.text(address)[2:]}"
            quality = row[columns["quality"]].strip() if columns.get("quality") is not None and len(row) > columns["quality"] else ""
            match = {"O": 100.0, "m": 99.0, "M": 50.0}.get(quality)
            rows.append((target, address, size, fname, None, match, None, None, 0, int(bool(pattern.search(fname)))))
    return rows


def _functions_from_image(path: Path, target: str, platform: Platform, pattern: re.Pattern) -> list[tuple]:
    """Boundaries from the executable: its symbols where it has them, else the unwind table (every function
    clang compiled), named fn_<address> until a decomp names them."""
    image = platform.open(path)
    rows = []
    starts = dict(image.functions()) if hasattr(image, "functions") else {}
    stubs = image.stubs() if hasattr(image, "stubs") else {}
    for start, size in sorted(starts.items()):
        fname = image.symbols.get(start) or stubs.get(start) or f"fn_{platform.text(start)[2:]}"
        rows.append((target, start, size, fname, None, None, None, None, 0, int(bool(pattern.search(fname)))))
    return rows


def _functions_changed(project: Project, db: sqlite3.Connection, name: str, target: dict) -> bool:
    source, _, _ = _function_source(project, target)
    return source is not None and _meta(db, f"functions:{name}") != f"{source}:{_stamp(source)}"


def _load_functions(project: Project, db: sqlite3.Connection, name: str, target: dict) -> bool:
    """Reload one target's function table when its report/symbols changed."""
    source, report, symbols = _function_source(project, target)
    if source is None:
        return False
    stamp = f"{source}:{_stamp(source)}"
    if _meta(db, f"functions:{name}") == stamp:
        return False
    pattern = provisional_pattern(project, name)
    platform = for_target(target)
    rows = []
    modules: dict[int, str] = {}
    if source is None:
        return False
    if source == report:
        try:
            data = json.loads(report.read_bytes())
        except ValueError:  # half-written during a rebuild: keep the previous table until it is complete
            return False
        module = target.get("module")
        for unit in data.get("units", []):
            meta = unit.get("metadata", {})
            base = 0
            if not is_dol_unit(meta, module):
                number = int(meta.get("module_id") or 0)
                if not number or target.get("rels") is False:
                    continue
                modules[number] = meta.get("module_name") or f"module{number}"
                base = number << MODULE_SHIFT
            for function in unit.get("functions") or []:
                info = function.get("metadata", {})
                if info.get("virtual_address") is None:
                    continue
                fname = function["name"]
                value = int(info["virtual_address"])
                if not base and platform.base and value >= platform.base:
                    value -= platform.base
                rows.append((name, base + value, int(function.get("size", 0)), fname,
                             info.get("demangled_name") or (cw_demangle(fname) if platform.name == "gamecube" else None),
                             function.get("fuzzy_match_percent"),
                             unit["name"], meta.get("source_path"), int(bool(meta.get("complete"))),
                             int(bool(pattern.search(fname)))))
    elif source.suffix.lower() == ".csv":
        rows = _functions_csv(source, name, platform, pattern)
    elif source == _target_file(project, target, "original"):
        rows = _functions_from_image(source, name, platform, pattern)
    else:
        best: dict[int, object] = {}
        for symbol in read_symbols(symbols):
            if symbol.type == "function" and (symbol.address not in best or symbol.size > best[symbol.address].size):
                best[symbol.address] = symbol
        for symbol in best.values():
            rows.append((name, symbol.address, symbol.size, symbol.name, cw_demangle(symbol.name), None, None,
                         None, 0, int(bool(pattern.search(symbol.name)))))
    if platform.name == "switch":  # Itanium names: demangle the ones the source did not
        from .platform import demangle_itanium
        wanted = [i for i, r in enumerate(rows) if r[4] is None and r[3].startswith("_Z")]
        for i, text in zip(wanted, demangle_itanium([rows[i][3] for i in wanted])):
            if text:
                rows[i] = rows[i][:4] + (text,) + rows[i][5:]
    db.execute("DELETE FROM functions WHERE target=?", (name,))
    db.executemany("INSERT OR REPLACE INTO functions VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
    _set_meta(db, f"functions:{name}", stamp)
    _set_meta(db, f"functions_source:{name}", "objdiff-report" if source == report else
              "functions-csv" if source.suffix.lower() == ".csv" else
              "symbols.txt" if source == symbols else "original executable")
    _set_meta(db, f"functions_loaded:{name}", str(time.time()))
    _set_meta(db, f"modules:{name}", json.dumps(modules))
    _MODULE_NAMES.update(modules)
    bounds = hashlib.sha256(",".join(f"{r[1]:x}:{r[2]:x}" for r in sorted(rows, key=lambda r: r[1])).encode())
    _set_meta(db, f"bounds:{name}", bounds.hexdigest()[:16])
    return True


def _calls_stamp(project: Project, db: sqlite3.Connection, name: str, target: dict) -> str | None:
    original = _target_file(project, target, "original")
    if original is None or not original.is_file():
        return None
    # Edges depend on the executable and the function boundaries, not on match percentages:
    # a rebuild that only changes match state does not re-decode the image.
    return f"{_stamp(original)}:{_meta(db, f'bounds:{name}')}"


def _load_calls(project: Project, db: sqlite3.Connection, name: str, target: dict) -> None:
    stamp = _calls_stamp(project, db, name, target)
    if stamp is None or _meta(db, f"calls:{name}") == stamp:
        return
    original = _target_file(project, target, "original")
    platform = for_target(target)
    try:
        image = platform.open(original)
    except ValueError:
        return
    context = {}
    if platform.name == "gamecube":
        from .inspect_dol import sda_bases
        context["sda"] = sda_bases(project, name, image)
    calls, xrefs = [], []
    functions = db.execute("SELECT address, size FROM functions WHERE target=? AND address<?",
                           (name, 1 << MODULE_SHIFT)).fetchall()
    for address, size in functions:
        calls.extend((name, address, site, callee) for site, callee in platform.calls(image, address, size))
        for pc, value, kind in platform.addresses(image, address, size, context):
            if platform.in_image(image, value) and not address <= value < address + size:
                xrefs.append((name, address, pc, value, kind))
    db.execute("DELETE FROM calls WHERE target=? AND caller<?", (name, 1 << MODULE_SHIFT))
    db.executemany("INSERT INTO calls VALUES(?,?,?,?)", calls)
    db.execute("DELETE FROM xrefs WHERE target=? AND function<?", (name, 1 << MODULE_SHIFT))
    db.executemany("INSERT INTO xrefs VALUES(?,?,?,?,?)", xrefs)
    # Pointer-sized words in data sections that point into the image: vtable slots, callback and
    # jump tables, pointers to strings and objects.
    refs = [(name, pointee, holder) for holder, pointee in platform.data_pointers(image)]
    db.execute("DELETE FROM refs WHERE target=?", (name,))
    db.executemany("INSERT INTO refs VALUES(?,?,?)", refs)
    _set_meta(db, f"calls:{name}", stamp)


def unit_asm(project: Project, target: dict, unit: str | None, module_key: bool) -> Path | None:
    """dtk's asm file for an objdiff unit (`module/path/to/tu`): build/<ver>/asm/... for the DOL,
    build/<ver>/<module>/asm/... for a REL."""
    report = _target_file(project, target, "report")
    if not unit or report is None or "/" not in unit:
        return None
    module, _, rest = unit.partition("/")
    path = report.parent / module / "asm" / f"{rest}.s" if module_key else report.parent / "asm" / f"{rest}.s"
    return path if path.is_file() else None


def _modules_stamp(project: Project, db: sqlite3.Connection, name: str, target: dict) -> str | None:
    """REL call/xref edges come from dtk's asm, rewritten whenever dtk splits (which rewrites config.json)."""
    report = _target_file(project, target, "report")
    if report is None or not db.execute("SELECT 1 FROM functions WHERE target=? AND address>=? LIMIT 1",
                                        (name, 1 << MODULE_SHIFT)).fetchone():
        return None
    marker = report.parent / "config.json"
    return f"{_meta(db, f'bounds:{name}')}:{_stamp(marker) if marker.is_file() else ''}"


def _load_module_edges(project: Project, db: sqlite3.Connection, name: str, target: dict) -> None:
    """Direct calls and symbol references made by REL functions, read from dtk's relocated asm.

    REL code reaches the DOL only through relocations, so this is where `who calls this DOL function`
    learns about actors and other module code."""
    stamp = _modules_stamp(project, db, name, target)
    if stamp is None or _meta(db, f"modcalls:{name}") == stamp:
        return
    top = 1 << MODULE_SHIFT
    dol_names: dict[str, int] = {}
    local: dict[tuple[int, str], int] = {}
    units: dict[str, list] = {}
    for address, size, fname, unit in db.execute("SELECT address, size, name, unit FROM functions WHERE target=?",
                                                 (name,)):
        if address < top:
            dol_names.setdefault(fname, address)
        else:
            local[(address >> MODULE_SHIFT, fname)] = address
            units.setdefault(unit, []).append((address, size, fname))
    symbols = _target_file(project, target, "symbols")
    if symbols is not None and symbols.is_file():
        for symbol in read_symbols(symbols):
            dol_names.setdefault(symbol.name, symbol.address)
    calls, xrefs = [], []
    for unit, functions in units.items():
        path = unit_asm(project, target, unit, True)
        if path is None:
            continue
        try:
            bodies = asm_functions(path)
        except OSError:
            continue
        for address, size, fname in functions:
            module = address >> MODULE_SHIFT
            base = module << MODULE_SHIFT
            for instruction in bodies.get(fname, ()):
                callee, refs = asm_references(instruction)
                pc = base | instruction.address
                if callee:
                    found = local.get((module, callee), dol_names.get(callee))
                    if found is not None:
                        calls.append((name, address, pc, found))
                for symbol, kind in refs:
                    found = dol_names.get(symbol)
                    if found is not None:
                        xrefs.append((name, address, pc, found, kind))
    db.execute("DELETE FROM calls WHERE target=? AND caller>=?", (name, top))
    db.executemany("INSERT INTO calls VALUES(?,?,?,?)", calls)
    db.execute("DELETE FROM xrefs WHERE target=? AND function>=?", (name, top))
    db.executemany("INSERT INTO xrefs VALUES(?,?,?,?,?)", xrefs)
    _set_meta(db, f"modcalls:{name}", stamp)


def _walk(root: str, paths: list[str], exclude: list[re.Pattern]) -> Iterator[tuple[str, os.stat_result]]:
    """(relative path, lstat) of indexable regular files. Plain os calls: this runs before every query."""
    seen: set[str] = set()
    cut = len(root) + 1
    for relative in paths:
        base = os.path.join(root, relative)
        try:
            info = os.lstat(base)
        except OSError:
            continue
        if statmod.S_ISREG(info.st_mode):
            candidates: Iterable[tuple[str, os.stat_result | None]] = [(base, info)]
        elif statmod.S_ISDIR(info.st_mode):
            def tree(base=base):
                for directory, dirs, files in os.walk(base):
                    dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS]
                    for file in files:
                        dot = file.rfind(".")
                        if dot > 0 and file[dot:].lower() in TEXT_SUFFIXES:
                            yield os.path.join(directory, file), None
            candidates = tree()
        else:
            continue
        for full, known in candidates:
            if os.path.splitext(full)[1].lower() not in TEXT_SUFFIXES:
                continue
            rel = full[cut:].replace(os.sep, "/")  # stored and matched with "/" on every OS
            if rel in seen or any(x.search(rel) for x in exclude):
                continue
            try:
                info = known or os.lstat(full)
            except OSError:
                continue
            if not statmod.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                continue
            seen.add(rel)
            yield rel, info


def _cite_paths(project: Project, repo: str) -> list[str]:
    config = project.config["repositories"][repo]
    return config.get("cite_paths", config.get("index_paths", config.get("search_paths", [])))


def _forget(db: sqlite3.Connection, repo: str, rel: str) -> None:
    # FTS5 cannot index repo/path, so delete by the rowid range recorded at insert.
    row = db.execute("SELECT first_row, last_row FROM files WHERE repo=? AND path=?", (repo, rel)).fetchone()
    if row and row[0] is not None:
        db.execute("DELETE FROM lines WHERE rowid BETWEEN ? AND ?", (row[0], row[1]))
    db.execute("DELETE FROM cites WHERE repo=? AND path=?", (repo, rel))
    db.execute("DELETE FROM mentions WHERE repo=? AND path=?", (repo, rel))
    db.execute("DELETE FROM files WHERE repo=? AND path=?", (repo, rel))


def _index_file(db: sqlite3.Connection, repo: str, rel: str, path: str, cite: bool,
                address: re.Pattern) -> tuple[int | None, int | None]:
    with open(path, "rb") as stream:
        raw = stream.read()
    _forget(db, repo, rel)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    lines = text.splitlines()
    hint = _PLATFORM.cite_hint
    # Overlapping windows let a phrase that spans a line break still match.
    step = WINDOW // 2
    first = (db.execute("SELECT max(rowid) FROM lines").fetchone()[0] or 0) + 1
    windows = [(first + n, repo, rel, i + 1, "\n".join(lines[i:i + WINDOW]))
               for n, i in enumerate(range(0, max(len(lines), 1), step))]
    db.executemany("INSERT INTO lines(rowid, repo, path, line, body) VALUES(?,?,?,?,?)", windows)
    rows = []
    for number, line in enumerate(lines, 1):
        if hint not in line:
            continue
        for match in address.finditer(line):
            rows.append((_PLATFORM.cite_value(match.group(1)), repo, rel, number, line.strip()[:240]))
    db.executemany(f"INSERT INTO {'cites' if cite else 'mentions'} VALUES(?,?,?,?,?)", rows)
    return (first, first + len(windows) - 1) if windows else (None, None)


def _scan(project: Project, db: sqlite3.Connection, repo: str) -> tuple[list, list]:
    """(changed [(rel, stat)], removed [rel]) for one repository; read-only."""
    config = project.config["repositories"][repo]
    root = str(project.index_root(repo))
    exclude = [re.compile(x) for x in config.get("index_exclude", [])]
    paths = config.get("index_paths", config.get("search_paths", []))
    known = {row[0]: (row[1], row[2]) for row in
             db.execute("SELECT path, mtime, size FROM files WHERE repo=?", (repo,))}
    changed, present = [], set()
    for rel, info in _walk(root, paths, exclude):
        present.add(rel)
        if known.get(rel) != (info.st_mtime_ns, info.st_size):
            changed.append((rel, info))
    return changed, sorted(set(known) - present)


def refresh(project: Project, repos: Iterable[str] | None = None, force: bool = False) -> dict:
    """Bring the index up to date. Cheap when nothing changed (stat only, no write lock)."""
    started = time.monotonic()
    with _SCAN:
        # Single flight: threads that arrive during a scan wait for it, then find the index fresh. Without this,
        # every concurrent MCP call past the TTL walked the 10k-file tree at once.
        return _refresh(project, repos, force, started)


def _refresh(project: Project, repos: Iterable[str] | None, force: bool, started: float) -> dict:
    names = list(project.config["repositories"]) if repos is None else list(repos)
    base = str(cache_path(project))
    stats = {"files_reindexed": 0, "files_removed": 0, "functions_reloaded": [], "skipped": []}
    now = time.monotonic()
    ttl = _ttl()
    fresh = lambda key: not force and now - _FRESH.get((base, key), -1e9) < ttl
    names = [n for n in names if project.index_root(n).is_dir()]
    due = [n for n in names if not fresh(n)]
    stats["skipped"] = [n for n in names if n not in due]
    targets_due = not fresh("@targets")
    db = connect(project)
    targets = project.config.get("targets", {})
    plan = {repo: _scan(project, db, repo) for repo in due}
    work = any(c or r for c, r in plan.values()) or (targets_due and any(
        _functions_changed(project, db, n, t) or _calls_stamp(project, db, n, t) not in (None, _meta(db, f"calls:{n}"))
        or _modules_stamp(project, db, n, t) not in (None, _meta(db, f"modcalls:{n}"))
        for n, t in targets.items()))
    analyze = not _has_stats(db)
    if work:
        with _LOCK:
            db.execute("BEGIN IMMEDIATE")
            try:
                for name, target in targets.items():
                    if _load_functions(project, db, name, target):
                        stats["functions_reloaded"].append(name)
                    _load_calls(project, db, name, target)
                    _load_module_edges(project, db, name, target)
                for repo, (changed, removed) in plan.items():
                    _apply(project, db, repo, changed, removed, stats)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        analyze = analyze or bool(stats["functions_reloaded"])
    if analyze:
        with _LOCK:
            db.execute("ANALYZE")  # ~0.15 s on a 10k-file index; stats are ratios, so they stay valid as data grows
        stats["analyzed"] = True
    if not _MODULE_NAMES:
        _remember_modules(db)
    if work or analyze:
        _checkpoint(db, base)
    mark = time.monotonic()
    for key in due + (["@targets"] if targets_due else []):
        _FRESH[(base, key)] = mark
    stats["seconds"] = round(time.monotonic() - started, 2)
    stats["cache"] = base
    return stats


def _apply(project: Project, db: sqlite3.Connection, repo: str, changed: list, removed: list, stats: dict) -> None:
    config = project.config["repositories"][repo]
    root = str(project.index_root(repo))
    address = re.compile(config.get("address_pattern", _PLATFORM.cite_pattern()))
    cite_prefixes = [p.rstrip("/") for p in _cite_paths(project, repo)]
    current = {row[0]: (row[1], row[2]) for row in
               db.execute("SELECT path, mtime, size FROM files WHERE repo=?", (repo,))}
    for rel, info in changed:
        if current.get(rel) == (info.st_mtime_ns, info.st_size):
            continue  # another process indexed it while we waited for the lock
        cite = any(rel == p or rel.startswith(p + "/") for p in cite_prefixes)
        try:
            first, last = _index_file(db, repo, rel, os.path.join(root, *rel.split("/")), cite, address)
        except OSError:
            continue
        db.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?)",
                   (repo, rel, info.st_mtime_ns, info.st_size, first, last))
        stats["files_reindexed"] += 1
    for rel in removed:
        _forget(db, repo, rel)
        stats["files_removed"] += 1


WAL_LIMIT = 64 << 20


def _checkpoint(db: sqlite3.Connection, base: str) -> None:
    """Fold a large write-ahead log back into the database (readers in other sessions can hold it open, so a
    WAL that is never truncated grows to the size of every rewrite since)."""
    wal = Path(base + "-wal")
    try:
        if wal.stat().st_size > WAL_LIMIT:
            with _LOCK:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except (OSError, sqlite3.Error):
        pass


def _cache_base() -> Path:
    from .paths import cache_home
    return cache_home()


def cache_inventory() -> dict:
    """The toolkit's cache files, grouped per index, and whether a registered project still uses each."""
    from .onboard import registered
    base = _cache_base()
    live = {hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:12] for path in registered()}
    groups: dict[str, dict] = {}
    if base.is_dir():
        for path in base.iterdir():
            if not path.is_file():
                continue
            stem = re.sub(r"(-ghidra)?\.sqlite(-wal|-shm|-journal)?$|\.marshal$|\.partial$", "", path.name)
            entry = groups.setdefault(stem, {"name": stem, "files": [], "bytes": 0, "modified": 0.0})
            info = path.stat()
            entry["files"].append(path.name)
            entry["bytes"] += info.st_size
            entry["modified"] = max(entry["modified"], info.st_mtime)
    now = time.time()
    for entry in groups.values():
        key = entry["name"].rsplit("-", 1)[-1]
        if entry["name"].startswith("symbols-"):
            entry["live"] = now - entry["modified"] < 30 * 86400  # keyed by a symbols path: keep while recently used
        else:
            entry["live"] = key in live
        entry["age_days"] = round((now - entry["modified"]) / 86400, 1)
    rows = sorted(groups.values(), key=lambda e: (e["live"], -e["bytes"]))
    return {"cache": str(base), "entries": rows, "bytes": sum(e["bytes"] for e in rows),
            "stale_bytes": sum(e["bytes"] for e in rows if not e["live"])}


def prune_cache(dry_run: bool = False) -> dict:
    """Delete caches no registered project uses (old manifest locations, test runs, retired projects)."""
    inventory = cache_inventory()
    base = Path(inventory["cache"])
    removed = []
    close_connections()
    for entry in inventory["entries"]:
        if entry["live"]:
            continue
        for name in entry["files"]:
            if not dry_run:
                (base / name).unlink(missing_ok=True)
            removed.append(name)
    return {"removed": removed, "bytes": inventory["stale_bytes"], "dry_run": dry_run}


def report_age_hours(project: Project, target: str) -> float | None:
    """Age of the match data the index holds (objdiff report mtime), or None without a report."""
    config = project.target(target)
    report = _target_file(project, config, "report")
    if report is None or not report.is_file():
        return None
    return round((time.time() - report.stat().st_mtime) / 3600, 2)


SOURCE_PATH = re.compile(r"\.(c|cc|cp|cpp|cxx|h|hh|hpp|inc|inl|s)$", re.I)


def report_staleness(project: Project, target: str) -> dict | None:
    """How many indexed source files of the target's repository changed after its report was written."""
    config = project.target(target)
    report = _target_file(project, config, "report")
    if report is None or not report.is_file():
        return None
    written = report.stat().st_mtime_ns
    db = connect(project)
    newer = [path for path, mtime in db.execute("SELECT path, mtime FROM files WHERE repo=? AND mtime>?",
                                                (config["repository"], written)) if SOURCE_PATH.search(path)]
    return {"age_h": round((time.time() - report.stat().st_mtime) / 3600, 1), "sources_newer": len(newer),
            "examples": sorted(newer)[:3]}


def function_at(db: sqlite3.Connection, target: str, address: int) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM functions WHERE target=? AND address<=? ORDER BY address DESC LIMIT 1",
                      (target, address)).fetchone() if address is not None else None


def containing(db: sqlite3.Connection, target: str, address: int) -> sqlite3.Row | None:
    row = function_at(db, target, address)
    if row and row["address"] <= address < row["address"] + max(row["size"], 4):
        return row
    return None


def fts_query(text: str, any_term: bool = False) -> str:
    """Plain words to an FTS5 AND (or OR) query; punctuation cannot inject syntax."""
    terms = re.findall(r"[A-Za-z0-9_:]+", text)
    if not terms:
        raise ValueError("Search needs at least one word")
    return (" OR " if any_term else " ").join('"' + t.replace('"', "") + '"' for t in terms[:12])
