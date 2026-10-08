"""Cross-repository answers built on the index.

Every function takes the project and returns plain data; formatting for agents
lives in render.py. Addresses are the join key between a decomp and a port,
because they survive renames, TU merges and file moves.
"""

from __future__ import annotations

import bisect
import collections
import hashlib
import json
import marshal
import os
import re
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Any

from .gc import Symbol, read_symbols
from .index import address_text, cache_path, connect, containing, fts_query, module_address, refresh, report_age_hours
from .project import Project

HEX = re.compile(r"^(?:0x)?([0-9A-Fa-f]{8})$")
QUERY_SPLIT = re.compile(r"[\s,]+")
MODULE_TOKEN = re.compile(r"[A-Za-z_][\w.-]*\+0x[0-9A-Fa-f]+")  # a REL function address, e.g. mymodule+0x124
CALLER_ROWS = 400


def role_repos(project: Project, role: str) -> list[str]:
    return [name for name, repo in project.config["repositories"].items() if repo.get("role") == role]


def default_target(project: Project, target: str | None = None) -> str:
    targets = list(project.config.get("targets", {}))
    if target:
        project.target(target)
        return target
    if not targets:
        raise ValueError("Project has no targets")
    return targets[0]


def split_queries(text: str) -> list[str]:
    """Several addresses (or several plain symbol names) in one query -> separate queries.

    `0x8013E990 0x8013E998`, `8013E990,8013E998` and `lbl_805DE138 lbl_805DE13C` are batches;
    `TEnemy::update` or a phrase with spaces that is not all names stays one query."""
    tokens = [t for t in QUERY_SPLIT.split(text.strip()) if t]
    if len(tokens) > 1 and all(HEX.match(t) or MODULE_TOKEN.fullmatch(t) or re.fullmatch(r"[A-Za-z_][\w:~]*", t)
                               for t in tokens):
        # Addresses and plain symbol names (lbl_*, fn_*, mangled) split, mixed or not; a `Class::method` phrase stays whole.
        if not any("::" in t for t in tokens):
            return tokens
    return [text.strip()]


def query_list(value: str | list | None) -> list[str]:
    """Addresses/symbols given as a list, a JSON list in a string ('["0x80434A20","0x80434A38"]'),
    or one string separated by spaces/commas -> separate queries."""
    if value is None:
        return []
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            value = json.loads(value)
        except ValueError:
            value = value.strip("[]")
    if isinstance(value, (list, tuple)):
        return [q for item in value for q in split_queries(str(item))] if value else []
    return split_queries(value) if value.strip() else []


DATA_TYPES = ("u8", "s8", "u16", "s16", "u32", "s32", "f32", "f64", "ptr", "str")


def typed_query(query: str, kind: str, count: int) -> tuple[str, str, int]:
    """`ADDR:type[:count]` (as agents write it) -> (ADDR, type, count); anything else unchanged."""
    match = re.fullmatch(rf"(.+?):({'|'.join(DATA_TYPES)})(?::(\d+))?", query.strip())
    if not match:
        return query, kind, count
    return match[1], match[2], int(match[3]) if match[3] else count


def batch(queries: list[str], answer, limit: int = 20) -> dict[str, Any]:
    """answer(query) for each query; one result as is, several as {"batch": [...]} where a failing query
    becomes {"query", "error"} instead of failing the whole call."""
    if len(queries) == 1:
        return answer(queries[0])
    results = []
    for query in queries[:limit]:
        try:
            results.append(answer(query))
        except ValueError as error:
            results.append({"query": query, "error": str(error)})
    out: dict[str, Any] = {"batch": results}
    if len(queries) > limit:
        out["note"] = f"first {limit} of {len(queries)} queries answered; split the rest into another call"
    return out


def class_of(name: str | None, demangled: str | None = None) -> str | None:
    """Class part of a function name: `TClass::m`, `m__6TClassFv`, or a `TClass__sub_ADDR` vote."""
    if demangled and "::" in demangled:
        return demangled.split("(")[0].rsplit("::", 1)[0]
    if not name:
        return None
    match = re.match(r"^[A-Za-z_]\w*?__(\d+)(\w+)$", name)
    if match and len(match[2]) >= int(match[1]):
        return match[2][:int(match[1])]
    match = re.match(r"^([A-Za-z_]\w*?)__(?:sub|vt\d*|data)_?[0-9A-Fa-f]*", name)
    return match[1] if match else None


def _status(row) -> dict[str, Any]:
    if row is None:
        return {}
    match = row["match"]
    return {
        "address": address_text(row['address']), "size": row["size"], "name": row["name"],
        "demangled": row["demangled"], "unit": row["unit"], "source": row["source"],
        "match": match, "exact": match == 100, "linked": bool(row["linked"]),
        "provisional_name": bool(row["provisional"]),
    }


def status_word(info: dict) -> str:
    if not info:
        return "unknown"
    if info.get("match") is None:
        state = "no-report" if info.get("unit") is None else "unmatched"  # objdiff omits a 0% match
    elif info.get("exact", info.get("match") == 100):
        state = "exact+linked" if info.get("linked") else "exact"
    else:
        state = f"{info['match']:.1f}%"
    return state + (" provisional-name" if info.get("provisional_name") else "")


def _symbol_lookup(project: Project, target: str, address: int) -> dict | None:
    """Data objects and anything objdiff does not list come from symbols.txt."""
    symbols, starts = _symbol_table(project, target)
    if not symbols:
        return None
    index = bisect.bisect_right(starts, address) - 1
    best = None
    while index >= 0 and starts[index] > address - 0x100000:
        symbol = symbols[index]
        if symbol.address <= address < symbol.address + max(symbol.size, 1):
            best = symbol
            break
        if symbol.size and symbol.address + symbol.size <= address and symbol.type == "object":
            break
        index -= 1
    if best is None:
        return None
    return {"address": address_text(best.address), "name": best.name, "section": best.section,
            "type": best.type, "size": best.size, "offset": address - best.address}


_SYMBOLS: dict[str, tuple[str, tuple]] = {}
SYMBOLS_CACHE_VERSION = 1


def _parsed_symbols(project: Project, path: Path, stamp: str) -> list[Symbol]:
    """symbols.txt sorted by address. Parsing 59k lines costs ~0.4 s, which every CLI process (most subagent
    calls) paid; a marshal copy next to the index, keyed by mtime and size, loads in a few ms."""
    store = cache_path(project).with_name(f"symbols-{hashlib.sha1(str(path).encode()).hexdigest()[:12]}.marshal")
    try:
        version, saved, rows = marshal.loads(store.read_bytes())
        if version == SYMBOLS_CACHE_VERSION and saved == stamp:
            return [Symbol(*row) for row in rows]
    except (OSError, EOFError, ValueError, TypeError):
        pass
    symbols = sorted(read_symbols(path), key=lambda s: (s.address, -s.size))
    try:
        partial = store.with_name(f"{store.name}.{os.getpid()}.tmp")
        partial.write_bytes(marshal.dumps((SYMBOLS_CACHE_VERSION, stamp, [tuple(s) for s in symbols])))
        os.replace(partial, store)
    except OSError:
        pass
    return symbols


def _symbol_table(project: Project, target: str) -> tuple[list, list[int]]:
    config = project.target(target)
    if not config.get("symbols"):
        return [], []
    path = project.file(config["repository"], config["symbols"])
    if not path.is_file():
        return [], []
    info = path.stat()
    stamp = f"{info.st_mtime_ns}:{info.st_size}"
    cached = _SYMBOLS.get(str(path))
    if not cached or cached[0] != stamp:
        symbols = _parsed_symbols(project, path, stamp)
        by_name = {}
        for s in symbols:
            by_name.setdefault(s.name, s)
        _SYMBOLS[str(path)] = (stamp, (symbols, [s.address for s in symbols], by_name))
    symbols, starts, _ = _SYMBOLS[str(path)][1]
    return symbols, starts


def symbol_named(project: Project, target: str, name: str):
    _symbol_table(project, target)
    config = project.target(target)
    if not config.get("symbols"):
        return None
    cached = _SYMBOLS.get(str(project.file(config["repository"], config["symbols"])))
    return cached[1][2].get(name) if cached else None


def resolve(project: Project, query: str, target: str | None = None, limit: int = 8) -> list[int]:
    """Address, mangled name, demangled name, data symbol or Class::method fragment -> addresses.

    An address inside a function resolves to the function start (see resolve_address for the
    exact address)."""
    target = default_target(project, target)
    db = connect(project)
    match = HEX.match(query.strip())
    keyed = None if match else module_address(query)
    if match or keyed is not None:
        value = int(match[1], 16) if match else keyed
        row = containing(db, target, value)
        return [row["address"]] if row else [value]
    text = query.strip()
    rows = db.execute("SELECT address FROM functions WHERE target=? AND (name=? OR demangled=?) LIMIT ?",
                      (target, text, text, limit)).fetchall()
    if not rows:
        symbol = symbol_named(project, target, text)
        if symbol is not None:
            return [symbol.address]
        like = f"%{text}%"
        rows = db.execute("SELECT address FROM functions WHERE target=? AND (demangled LIKE ? OR name LIKE ?) "
                          "ORDER BY length(coalesce(demangled,name)) LIMIT ?",
                          (target, like, like, limit)).fetchall()
    return [r[0] for r in rows]


def resolve_address(project: Project, query: str, target: str | None = None) -> int | None:
    """The exact address a query names: a hex address as given, else the symbol/function start."""
    match = HEX.match(query.strip())
    if match:
        return int(match[1], 16)
    keyed = module_address(query)
    if keyed is not None:
        return keyed
    found = resolve(project, query, target, limit=2)
    return found[0] if len(found) == 1 else None


# ----------------------------------------------------------------------------
# Source definitions: comment-proof, call-site-proof, brace matched.

_STRINGS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_CALL_CONTEXT = re.compile(r"(?:\b(?:if|while|for|switch|return|case|sizeof)\b|[=(,!?:+\-*/%&|<>^]\s*)\s*$")
# `Type* name(` / `const Foo& Class::name(`: a * or & after nothing but type words starts a declaration.
_TYPE_PREFIX = re.compile(r"^\s*(?:[A-Za-z_][\w:]*(?:<[^;(){}]*>)?\s+)*[A-Za-z_][\w:]*(?:<[^;(){}]*>)?\s*[*&]+\s*(?:const\s+)?$")
_STATEMENT = re.compile(r"\b(?:if|while|for|switch|return|case|sizeof|delete|new|throw|else|do)\b")


def _code_lines(lines: list[str]) -> list[str]:
    """Lines with comments and string literals blanked (block comments may span lines)."""
    out, block = [], False
    for line in lines:
        text, i, result = line, 0, []
        while i < len(text):
            if block:
                end = text.find("*/", i)
                if end < 0:
                    i = len(text)
                    break
                block, i = False, end + 2
                continue
            start_block = text.find("/*", i)
            start_line = text.find("//", i)
            stop = min([p for p in (start_block, start_line) if p >= 0], default=len(text))
            result.append(text[i:stop])
            if stop == len(text):
                break
            if stop == start_line:
                break
            block, i = True, stop + 2
        out.append(_STRINGS.sub('""', "".join(result)))
    return out


def _name_call(text: str, name: str) -> tuple[int, int] | None:
    """(start, end past the '(') of the first `name (` in text not preceded by an identifier char, ':' or '~'.

    Same match as the regex (?<![\\w:~])NAME\\s*\\( without compiling one per name (thousands per drift pass)."""
    at = text.find(name)
    while at >= 0:
        before = text[at - 1] if at else ""
        if not before or not (before.isalnum() or before in "_:~"):
            end = at + len(name)
            while end < len(text) and text[end].isspace():
                end += 1
            if end < len(text) and text[end] == "(":
                return at, end + 1
        at = text.find(name, at + 1)
    return None


def find_definition(lines: list[str], names: list[str], code: list[str] | None = None) -> tuple[int, int] | None:
    """(first, last) 0-based line indexes of the first real definition of any of names.

    Skips comments, declarations (`...;`), extern lines and call sites; the body is brace matched."""
    code = code if code is not None else _code_lines(lines)
    plain = [n for n in names if n]
    for i, text in enumerate(code):
        if "(" not in text or not any(n in text for n in plain):
            continue
        hit = next((m for n in plain for m in [_name_call(text, n)] if m), None)
        if hit is None:
            continue
        before = text[:hit[0]]
        declares = bool(_TYPE_PREFIX.match(before)) and not _STATEMENT.search(before)
        if (not declares and _CALL_CONTEXT.search(before)) or text.lstrip().startswith(("#", "extern ")) or "extern \"C\"" in before:
            continue
        # The definition opens a body before any ';' (signature may span a few lines).
        joined, j = text[hit[1]:], i
        while "{" not in joined and ";" not in joined and j < min(len(code) - 1, i + 6):
            j += 1
            joined += code[j]
        brace, semi = joined.find("{"), joined.find(";")
        if brace < 0 or (0 <= semi < brace):
            continue
        depth, seen = 0, False
        for k in range(i, min(len(code), i + 4000)):
            segment = code[k][hit[1]:] if k == i else code[k]
            for ch in segment:
                if ch == "{":
                    depth += 1
                    seen = True
                elif ch == "}":
                    depth -= 1
                    if seen and depth == 0:
                        return i, k
        return i, min(len(code) - 1, i + 4000)
    return None


_SOURCES: collections.OrderedDict[str, tuple[tuple[int, int], list[str], list[str]]] = collections.OrderedDict()
_SOURCES_LOCK = threading.Lock()
SOURCE_CACHE = 512  # files; least recently used are evicted (clearing all made bulk passes re-parse every file)


def _source_text(path: Path) -> tuple[list[str], list[str]]:
    try:
        info = path.stat()
    except OSError:
        return [], []
    stamp, key = (info.st_mtime_ns, info.st_size), str(path)
    with _SOURCES_LOCK:
        cached = _SOURCES.get(key)
        if cached and cached[0] == stamp:
            _SOURCES.move_to_end(key)
            return cached[1], cached[2]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cached = (stamp, lines, _code_lines(lines))
    with _SOURCES_LOCK:
        _SOURCES[key] = cached
        _SOURCES.move_to_end(key)
        while len(_SOURCES) > SOURCE_CACHE:
            _SOURCES.popitem(last=False)
    return cached[1], cached[2]


def definition_names(name: str | None, demangled: str | None) -> list[str]:
    names = [name] if name else []
    if demangled:
        base = demangled.split("(")[0].strip()
        if base and base not in names:
            names.append(base)
    return names


def source_definition(project: Project, repo: str, source: str | None, name: str,
                      demangled: str | None) -> dict | None:
    """{line, end, body} of a decomp function's definition in its source file."""
    if not source:
        return None
    try:
        path = project.file(repo, source)
    except ValueError:  # absolute or escaping source_path in the report
        return None
    if not path.is_file():
        return None
    lines, code = _source_text(path)
    found = find_definition(lines, definition_names(name, demangled), code)
    if not found:
        return None
    first, last = found
    start = first
    stops = project.config.get("definition_comment_stops", [])  # marker comments that belong to the previous code
    while start > 0 and lines[start - 1].strip().startswith(("//", "/*", "*", "template", "[[")) \
            and not any(marker in lines[start - 1] for marker in stops):
        start -= 1
    return {"line": first + 1, "end": last + 1, "body": "\n".join(lines[start:last + 1])}


HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".inc")


def header_definition(project: Project, repo: str, name: str | None, demangled: str | None) -> dict | None:
    """An inline method defined in a class body in a header (lookup only; drift keeps using the TU source).

    Candidates are indexed headers that mention both the class and the method; the definition must come after
    the class declaration line."""
    owner = class_of(name, demangled)
    base = (demangled or "").split("(")[0].strip()
    db = connect(project)
    if not owner and re.fullmatch(r"[A-Za-z_]\w*", base):  # a free inline function in a header
        try:
            paths = {r[0] for r in db.execute("SELECT DISTINCT path FROM lines WHERE repo=? AND lines MATCH ?",
                                              (repo, fts_query(base)))}
        except sqlite3.Error:
            return None
        for path in sorted(p for p in paths if p.endswith(HEADER_SUFFIXES)):
            lines, code = _source_text(project.file(repo, path))
            found = find_definition(lines, [base], code)
            if found:
                return {"path": path, "line": found[0] + 1, "end": found[1] + 1,
                        "body": "\n".join(lines[found[0]:found[1] + 1])}
        return None
    method = base.rsplit("::", 1)[-1] if "::" in base else None
    if not owner or not method or not re.fullmatch(r"~?[A-Za-z_]\w*", method):
        return None
    owner_name = owner.rsplit("::", 1)[-1]
    def files(word: str) -> set[str]:  # search windows are 6 lines, so each word is matched on its own
        return {r[0] for r in db.execute("SELECT DISTINCT path FROM lines WHERE repo=? AND lines MATCH ?",
                                         (repo, fts_query(word)))}
    try:
        paths = files(owner_name) & files(method.lstrip("~"))
    except sqlite3.Error:
        return None
    declaration = re.compile(rf"^\s*(?:class|struct)\s+(?:\w+\s+)*{re.escape(owner_name)}\b(?!\s*;)")
    # An out-of-line definition in another file (a TU's #included .inc fragment): `Class::method(` anywhere.
    qualified = f"{owner}::{method}"
    try:
        elsewhere = files(qualified) if "<" not in owner else set()
    except sqlite3.Error:
        elsewhere = set()
    for path in sorted(elsewhere):
        lines, code = _source_text(project.file(repo, path))
        found = find_definition(lines, [qualified], code)
        if found:
            return {"path": path, "line": found[0] + 1, "end": found[1] + 1,
                    "body": "\n".join(lines[found[0]:found[1] + 1])}
    for path in sorted(p for p in paths if p.endswith(HEADER_SUFFIXES)):
        lines, code = _source_text(project.file(repo, path))
        start = next((i for i, line in enumerate(code) if declaration.match(line)), None)
        if start is None:
            continue
        found = find_definition(lines[start:], [method], code[start:])
        if found:
            first, last = found[0] + start, found[1] + start
            return {"path": path, "line": first + 1, "end": last + 1, "body": "\n".join(lines[first:last + 1])}
    return None


def _source_line(project: Project, repo: str, source: str | None, name: str, demangled: str | None) -> int | None:
    found = source_definition(project, repo, source, name, demangled)
    return found["line"] if found else None


# ----------------------------------------------------------------------------

def _cites(db, address: int, size: int, exclude_repo: str | None = None, limit: int = 30,
           table: str = "cites") -> list[dict]:
    rows = db.execute(f"SELECT * FROM {table} WHERE address>=? AND address<? "
                      "ORDER BY repo, path NOT LIKE 'src/%', path, line",
                      (address, address + max(size, 4))).fetchall()
    out, seen = [], set()
    for r in rows:
        if r["repo"] == exclude_repo or (r["repo"], r["path"], r["line"]) in seen:
            continue
        seen.add((r["repo"], r["path"], r["line"]))
        out.append(dict(r) | {"address": address_text(r['address'])})
    return out[:limit]


def _native_file_counts(db, rows: list, native: list[str]) -> dict[int, int]:
    """Distinct native files citing each function (one query per batch instead of per edge)."""
    if not rows or not native:
        return {}
    marks = ",".join("?" * len(native))
    spans = sorted({(r["address"], r["address"] + max(r["size"], 4)) for r in rows})
    out: dict[int, int] = {}
    # SQLite counts per span and returns one row per function. Streaming every cite between the lowest and
    # highest caller to Python (tens of thousands of rows for a popular function) made each row a GIL
    # hand-off, and 8 concurrent lookups ran 10x slower than one at a time.
    for chunk in range(0, len(spans), 400):
        part = spans[chunk:chunk + 400]
        values = ",".join("(?,?)" for _ in part)
        query = (f"WITH spans(lo, hi) AS (VALUES {values}) SELECT spans.lo, count(DISTINCT cites.path) "
                 f"FROM spans JOIN cites ON cites.address >= spans.lo AND cites.address < spans.hi "
                 f"WHERE cites.repo IN ({marks}) GROUP BY spans.lo")
        for start, count in db.execute(query, (*[v for span in part for v in span], *native)):
            out[start] = count
    return out


def _cite_count(db, address: int, size: int, repos: list[str]) -> int:
    if not repos:
        return 0
    marks = ",".join("?" * len(repos))
    return db.execute(f"SELECT count(DISTINCT path) FROM cites WHERE address>=? AND address<? AND repo IN ({marks})",
                      (address, address + max(size, 4), *repos)).fetchone()[0]


def _holders(project: Project, target: str, db, pointee: int) -> list[dict]:
    """Data words pointing at an address, named by holder symbol, slot and the table's owner."""
    out = []
    for (holder,) in db.execute("SELECT holder FROM refs WHERE target=? AND pointee=? ORDER BY holder",
                                (target, pointee)):
        symbol = _symbol_lookup(project, target, holder)
        entry: dict[str, Any] = {"address": address_text(holder)}
        if symbol:
            table = int(symbol["address"], 16)
            entry.update(symbol=symbol["name"], table=symbol["address"], offset=symbol["offset"],
                         table_size=symbol["size"])
            is_vtable = symbol["name"].startswith("__vt__")
            if is_vtable or symbol["name"].startswith("lbl_"):
                entry["vtable_slot"] = symbol["offset"] // 4
            if not is_vtable:
                owners = _table_owners(project, target, db, table)
                if owners:
                    entry["owners"] = owners
        out.append(entry)
    return out


def _table_owners(project: Project, target: str, db, table: int) -> list[str]:
    """Functions that take the address of a data table (a constructor storing its vtable)."""
    names = []
    for (function,) in db.execute("SELECT DISTINCT function FROM xrefs WHERE target=? AND address=? AND kind='addr' "
                                  "LIMIT 4", (target, table)):
        row = containing(db, target, function)
        if row:
            names.append(row["demangled"] or row["name"])
    return names


def _slot_summary(refs: list[dict]) -> list[dict]:
    """Group pointer holders by slot offset with a verdict on what sharing means."""
    groups: dict[int, list[dict]] = collections.defaultdict(list)
    for ref in refs:
        if ref.get("vtable_slot") is not None:
            groups[ref["offset"]].append(ref)
    out = []
    for offset, holders in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        named = sorted({h["symbol"] for h in holders if h["symbol"].startswith("__vt__")})
        tables = [{"table": h["table"], "symbol": h["symbol"], "owners": h.get("owners", [])} for h in holders]
        classes = sorted({re.sub(r"^__vt__\d*", "", n) for n in named})
        verdict = ("shared by %d tables: an inherited base-class virtual — do not name it after one subclass"
                   % len(holders)) if len(holders) > 1 else "one table: the class owning that table defines it"
        out.append({"offset": offset, "slot": offset // 4, "tables": len(holders), "classes": classes,
                    "holders": tables[:12], "verdict": verdict})
    return out


def lookup(project: Project, query: str, target: str | None = None, fresh: bool = True,
           body: bool = False) -> dict[str, Any]:
    target = default_target(project, target)
    if fresh:
        refresh(project)
    queries = split_queries(query)
    if len(queries) > 1:
        return {"query": query, "batch": [lookup(project, q, target, fresh=False, body=body) for q in queries[:60]],
                "truncated": max(0, len(queries) - 60)}
    db = connect(project)
    addresses = resolve(project, query, target)
    if not addresses:
        near = _near_names(db, target, query)
        return {"query": query, "found": False, "suggestions": near,
                "hint": "No function or symbol matched; try an address, the mangled name, `names --regex`, or `search`."}
    if len(addresses) > 1:
        rows = [_status(containing(db, target, a)) for a in addresses]
        return {"query": query, "found": True, "ambiguous": True, "candidates": rows}
    address = addresses[0]
    exact = HEX.match(query.strip())
    requested = int(exact[1], 16) if exact else (module_address(query) or address)
    row = containing(db, target, address)
    repo = project.target(target)["repository"]
    native = role_repos(project, "native")
    if row is None:
        return data_lookup(project, requested, target, query)
    info = _status(row)
    definition = source_definition(project, repo, row["source"], row["name"], row["demangled"])
    if definition is None:
        definition = header_definition(project, repo, row["name"], row["demangled"])
        if definition is not None:
            info["defined_in"] = definition["path"]
        elif row["source"] and re.match(r"^(__dt__|__ct__|__as__|@\d+@__dt__|__sinit_)", row["name"] or ""):
            info["defined_in"] = "compiler-generated (no source text)"
    info["source_line"] = definition["line"] if definition else None
    callers = db.execute("SELECT DISTINCT caller FROM calls WHERE target=? AND callee=? ORDER BY caller",
                         (target, row["address"])).fetchall()
    callees = db.execute("SELECT callee, count(*) n FROM calls WHERE target=? AND caller=? GROUP BY callee "
                         "ORDER BY min(site)", (target, row["address"])).fetchall()
    caller_rows = [containing(db, target, r[0]) for r in callers[:CALLER_ROWS]]
    callee_rows = [containing(db, target, r[0]) for r in callees]
    counts = _native_file_counts(db, [r for r in caller_rows + callee_rows if r], native)

    def edge(other, address: int) -> dict:
        data = _status(other) if other else {"address": address_text(address), "name": None}
        if other:
            data["native_files"] = counts.get(other["address"], 0)
        return data

    by_class = collections.Counter(class_of(r["name"], r["demangled"]) or "(free/unknown)"
                                   for r in caller_rows if r)
    data_refs = _holders(project, target, db, row["address"])
    cites = _cites(db, row["address"], row["size"], limit=400)
    recipe_dirs = {name: cfg["recipes"].rstrip("/") + "/" for name, cfg in project.config["repositories"].items()
                   if cfg.get("recipes")}
    is_recipe = lambda c: c["repo"] in recipe_dirs and c["path"].startswith(recipe_dirs[c["repo"]])
    recipes = sorted({c["path"] for c in cites if is_recipe(c)})
    mentions = _cites(db, row["address"], row["size"], limit=40, table="mentions")
    result = {
        "query": query, "found": True, "target": target, "function": info,
        "offset": requested - row["address"],
        "report_age_h": report_age_hours(project, target),
        "callers": {"count": len(callers), "rows": [edge(r, c[0]) for r, c in zip(caller_rows, callers)],
                    "by_class": by_class.most_common(12)},
        "callees": [edge(r, c[0]) for r, c in zip(callee_rows, callees)],
        "data_refs": data_refs,
        "slots": _slot_summary(data_refs),
        "has_native": bool(native),
        "native_cites": [c for c in cites if c["repo"] in native and not is_recipe(c)],
        "decomp_cites": [c for c in cites if c["repo"] not in native],
        "mentions": mentions,
        "recipes": recipes,
        "limits": "Callers are direct `bl` calls; data_refs are pointers in data (vtable slots, tables). Match/link "
                  "state is the current report (report_age_h); a cite means the address is mentioned, not that "
                  "behavior was verified.",
    }
    if body and definition:
        result["body"] = definition["body"]
        result["body_lines"] = [definition["line"], definition["end"]]
    return result


def _near_names(db, target: str, query: str, limit: int = 6) -> list[str]:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", query) if len(w) >= 4]
    if not words:
        return []
    like = "%" + "%".join(words[:3]) + "%"
    return [r[0] for r in db.execute("SELECT coalesce(demangled, name) FROM functions WHERE target=? AND "
                                     "(name LIKE ? OR demangled LIKE ?) LIMIT ?", (target, like, like, limit))]


def data_lookup(project: Project, address: int, target: str, query: str | None = None) -> dict[str, Any]:
    """An address that is not inside a function: its symbol, who reads/writes it, who points at it."""
    db = connect(project)
    symbol = _symbol_lookup(project, target, address)
    start = int(symbol["address"], 16) if symbol else address
    size = max(symbol["size"], 1) if symbol else 4
    refs = xrefs(project, start, target, size=size, fresh=False)
    from .structure import split_owner, splits
    return {"query": query or address_text(address), "found": False, "address": address_text(address),
            "symbol": symbol, "owner_unit": split_owner(project, target, address),
            "has_splits": bool(splits(project, target)[0]), "slots": _pointer_slots(project, target, db, start, size) if symbol else [],
            "readers_writers": refs["code"], "pointed_from": refs["data"],
            "cites": _cites(db, start, size), "mentions": _cites(db, start, size, limit=20, table="mentions"),
            "hint": "Not inside a known function; the symbol above (if any) is the data/object owner."}


def _pointer_slots(project: Project, target: str, db, start: int, size: int, cap: int = 256) -> list[dict]:
    """Words inside a data object that point at code or data in the original (a vtable's methods, a callback or
    jump table's targets). Read from the original executable; nothing for .bss or without one."""
    from .inspect_dol import _dol
    try:
        dol = _dol(project, target)
        words = dol.words(start, min(size, cap * 4))
    except ValueError:
        return []
    out = []
    for index, word in enumerate(words):
        if not 0x80000000 <= word < 0x81800000:
            continue
        row = containing(db, target, word)
        if row is not None:
            name = row["demangled"] or row["name"]
            label = name + (f"+0x{word - row['address']:X}" if word != row["address"] else "")
            out.append({"offset": index * 4, "target": f"{address_text(word)} {label}", "status": status_word(_status(row))})
        else:
            symbol = _symbol_lookup(project, target, word)
            label = (symbol["name"] + (f"+0x{symbol['offset']:X}" if symbol["offset"] else "")) if symbol else ""
            out.append({"offset": index * 4, "target": f"{address_text(word)} {label}".strip()})
    return out


def xrefs(project: Project, address: int | str, target: str | None = None, size: int | None = None,
          fresh: bool = True, limit: int = 200) -> dict[str, Any]:
    """Code that loads, stores or takes the address of [address, address+size), and data words pointing there."""
    target = default_target(project, target)
    if fresh:
        refresh(project, [])
    db = connect(project)
    if isinstance(address, str):
        found = resolve_address(project, address, target)
        if found is None:
            raise ValueError(f"No address or symbol matches {address}")
        address = found
    symbol = _symbol_lookup(project, target, address)
    if size is None:
        row = containing(db, target, address)
        size = (row["size"] if row and row["address"] == address else
                max(symbol["size"], 1) if symbol and int(symbol["address"], 16) == address else 4)
    code = []
    kinds = collections.Counter()
    per_function: collections.Counter = collections.Counter()
    modules: collections.Counter = collections.Counter()
    for function, pc, value, kind in db.execute(
            "SELECT function, pc, address, kind FROM xrefs WHERE target=? AND address>=? AND address<? ORDER BY pc",
            (target, address, address + max(size, 1))):
        kinds[kind] += 1
        per_function[function] += 1
        if function >= 1 << 32:
            modules[address_text(function).split("+", 1)[0]] += 1
        if len(code) < limit:
            row = containing(db, target, function)
            code.append({"pc": address_text(pc), "kind": kind, "address": address_text(value),
                         "offset": value - address, **({"function": row["demangled"] or row["name"],
                                                         "function_address": address_text(row['address']),
                                                         "status": status_word(_status(row))} if row else {})})
    data = []
    for holder, pointee in db.execute("SELECT holder, pointee FROM refs WHERE target=? AND pointee>=? AND pointee<? "
                                      "ORDER BY holder LIMIT ?", (target, address, address + max(size, 1), limit)):
        owner = _symbol_lookup(project, target, holder)
        data.append({"holder": address_text(holder), "pointee": address_text(pointee),
                     **({"symbol": owner["name"], "offset": owner["offset"]} if owner else {})})
    functions = collections.Counter()
    for function, n in per_function.most_common(40):  # over every reference, not just the rows shown
        row = containing(db, target, function)
        functions[(row["demangled"] or row["name"]) if row else address_text(function)] += n
    return {"address": address_text(address), "size": size, "symbol": symbol, "code": code, "data": data,
            "kinds": dict(kinds), "functions": functions.most_common(40), "total": sum(kinds.values()),
            "modules": modules.most_common(),
            "limits": "Code refs are straight-line lis/addi and r2/r13 forms decoded from the original; pointers "
                      "passed in registers from elsewhere and indexed accesses past the symbol are not followed."}


def names(project: Project, queries: list[str] | None = None, target: str | None = None, regex: str | None = None,
          unit: str | None = None, start: int | None = None, end: int | None = None, limit: int = 200,
          provisional: bool | None = None,
          below: float | None = None, sort: str = "address") -> dict[str, Any]:
    """One line per function (or data symbol): the live name, size, match, unit. Replaces symbols.txt greps."""
    target = default_target(project, target)
    refresh(project, [])
    db = connect(project)
    rows: list[dict] = []
    if queries:
        for query in queries:
            for q in split_queries(query):
                match = HEX.match(q)
                row = containing(db, target, int(match[1], 16)) if match else None
                if row is None and not match:
                    found = resolve(project, q, target, limit=2)
                    row = containing(db, target, found[0]) if len(found) == 1 else None
                if row is not None:
                    rows.append(_status(row) | {"query": q})
                    continue
                address = int(match[1], 16) if match else (resolve_address(project, q, target) or 0)
                symbol = _symbol_lookup(project, target, address) if address else None
                rows.append({"query": q, "address": address_text(address) if address else None,
                             "name": symbol["name"] if symbol else None, "symbol": symbol, "data": True})
        return {"target": target, "rows": rows}
    sql, args = "SELECT * FROM functions WHERE target=?", [target]
    if start is not None:
        sql, args = sql + " AND address>=?", args + [start]
    if end is not None:
        sql, args = sql + " AND address<?", args + [end]
    if unit:
        sql, args = sql + " AND (unit LIKE ? OR source LIKE ?)", args + [f"%{unit}%", f"%{unit}%"]
    if provisional is not None:
        sql, args = sql + " AND provisional=?", args + [int(provisional)]
    if below is not None:  # objdiff omits a 0% match, so a missing value counts as 0
        sql, args = sql + " AND coalesce(match, 0) < ?", args + [below]
    order = {"address": "address", "match": "coalesce(match, 0) DESC, address", "size": "size DESC, address"}
    if sort not in order:
        raise ValueError(f"sort must be one of {', '.join(order)}")
    pattern = re.compile(regex) if regex else None
    matched = []
    for row in db.execute(sql + " ORDER BY " + order[sort], args):
        if pattern and not (pattern.search(row["name"]) or (row["demangled"] and pattern.search(row["demangled"]))):
            continue
        matched.append(row)
    if (start is not None and end is not None and not matched
            and not (unit or provisional is not None or below is not None)):
        # A range over data has no functions: list its data symbols, which agents otherwise grep for.
        symbols, starts = _symbol_table(project, target)
        extra = [{"query": address_text(s.address), "address": address_text(s.address), "name": s.name, "data": True,
                  "symbol": {"name": s.name, "section": s.section, "size": s.size, "offset": 0}}
                 for s in symbols[bisect.bisect_left(starts, start):bisect.bisect_left(starts, end)]
                 if s.type not in ("function", "label") and (not pattern or pattern.search(s.name))]
        return {"target": target, "rows": extra[:limit], "total": len(extra), "truncated": max(0, len(extra) - limit)}
    rows = [_status(row) for row in matched[:limit]]
    return {"target": target, "rows": rows, "total": len(matched), "truncated": max(0, len(matched) - len(rows))}


def renamed(project: Project, since: str, target: str | None = None) -> dict[str, Any]:
    """Symbols whose name changed at the same address between a git revision and the working tree."""
    target = default_target(project, target)
    config = project.target(target)
    if not config.get("symbols"):
        raise ValueError("Target has no symbols file")
    root = project.root(config["repository"])
    commit = _resolve_base(root, since)
    shown = _git_run(root, "show", f"{commit}:{config['symbols']}")
    if shown.returncode:
        raise ValueError(shown.stderr.strip() or f"{config['symbols']} not in {since}")
    from .gc import SYMBOL_LINE
    def table(text: str) -> dict[int, str]:
        out = {}
        for line in text.splitlines():
            match = SYMBOL_LINE.match(line.strip())
            if match:
                out.setdefault(int(match["address"], 16), match["name"])
        return out
    old = table(shown.stdout)
    new = table(project.file(config["repository"], config["symbols"]).read_text(encoding="utf-8", errors="replace"))
    rows = [{"address": address_text(a), "old": old[a], "new": new[a]} for a in sorted(old.keys() & new.keys())
            if old[a] != new[a]]
    return {"since": since, "commit": commit[:12], "renamed": rows, "count": len(rows),
            "hint": "Rewrite staged candidates with the map (old -> new) before banking them."}


def _is_code(project: Project, path: str) -> bool:
    """Native implementation files, as opposed to docs/recipes/reference drivers that mention an address."""
    roots = [r for repo in project.config["repositories"].values() if repo.get("role") == "native"
             for r in repo.get("code_paths", ["src/"])]
    return any(path.startswith(r) for r in roots)


def port_plan(project: Project, query: str, depth: int = 2, target: str | None = None,
              max_nodes: int = 80) -> dict:
    """The original call tree under a function, joined with native coverage.

    Tells an agent what to REUSE (callees the port already cites), what to
    PORT, and what to DECOMPILE first (callees the decomp has not matched)."""
    target = default_target(project, target)
    refresh(project)
    db = connect(project)
    queries = split_queries(query)
    if len(queries) > 1:
        return {"query": query, "batch": [port_plan(project, q, depth, target, max_nodes) for q in queries[:12]]}
    addresses = resolve(project, query, target)
    if len(addresses) != 1:
        return lookup(project, query, target, fresh=False)
    native = role_repos(project, "native")
    root = containing(db, target, addresses[0])
    if root is None:
        return {"query": query, "found": False}
    seen, nodes, frontier = {root["address"]}, [], [(root["address"], 0, None)]
    truncated = 0
    while frontier:
        address, level, parent = frontier.pop(0)
        if len(nodes) >= max_nodes:
            truncated += 1
            continue
        row = containing(db, target, address)
        info = _status(row)
        files = [f[0] for f in db.execute(
            "SELECT DISTINCT path FROM cites WHERE address>=? AND address<? AND repo IN (%s)"
            % ",".join("?" * len(native)), (row["address"], row["address"] + max(row["size"], 4), *native))] \
            if native else []
        code = [f for f in files if _is_code(project, f)]
        info.update(depth=level, parent=address_text(parent) if parent else None, native_files=code[:6],
                    native_docs=len(files) - len(code))
        callers = db.execute("SELECT count(DISTINCT caller) FROM calls WHERE target=? AND callee=?",
                             (target, row["address"])).fetchone()[0]
        info["original_callers"] = callers
        if info["native_files"]:
            info["action"] = "reuse" if info["exact"] else "reuse-unverified"
        elif not info["exact"]:
            info["action"] = "decompile-first"
        elif callers >= 8:
            info["action"] = "shared-port"
        else:
            info["action"] = "port"
        info["indirect_calls"] = _indirect_calls(project, target, row)
        nodes.append(info)
        if level < depth:
            for (callee,) in db.execute("SELECT callee FROM calls WHERE target=? AND caller=? GROUP BY callee "
                                        "ORDER BY min(site)", (target, row["address"])):
                child = containing(db, target, callee)
                if child and child["address"] not in seen:
                    seen.add(child["address"])
                    frontier.append((child["address"], level + 1, address))
    counts = collections.Counter(n["action"] for n in nodes)
    return {"query": query, "found": True, "root": nodes[0], "nodes": nodes, "summary": dict(counts),
            "truncated_nodes": truncated,
            "legend": {"reuse": "the port already cites this; extend that owner instead of writing a copy",
                       "reuse-unverified": "the port implements it but the decomp is not exact; recover it before "
                                           "trusting the native semantics",
                       "decompile-first": "decomp is not exact yet; recover it before trusting semantics",
                       "shared-port": "many original callers: port once into a shared owner, not per feature",
                       "port": "exact in the decomp and not yet cited natively"},
            "limits": "Direct calls only; `indirect_calls` counts bctrl sites (vtable/pointer dispatch) whose "
                      "targets are not in the tree — read them with asm. Check `lookup` on the root for callers."}


_DOL_CACHE: dict[str, tuple[str, Any]] = {}


def _dol_for(project: Project, target: str):
    from .inspect_dol import _dol
    config = project.target(target)
    key = f"{config['repository']}:{config.get('original')}"
    path = project.file(config["repository"], config["original"]) if config.get("original") else None
    stamp = f"{path.stat().st_mtime_ns}" if path and path.is_file() else ""
    if key not in _DOL_CACHE or _DOL_CACHE[key][0] != stamp:
        _DOL_CACHE[key] = (stamp, _dol(project, target))
    return _DOL_CACHE[key][1]


def _indirect_calls(project: Project, target: str, row) -> int:
    try:
        words = _dol_for(project, target).words(row["address"], row["size"])
    except (ValueError, OSError):
        return 0
    return sum(1 for w in words if w == 0x4E800421)  # bctrl


def demand(project: Project, target: str | None = None, limit: int = 40, include_exact_provisional: bool = True,
           need: str | None = None, offset: int = 0, exclude: set[int] | None = None) -> dict:
    """Decomp work the port is waiting on, ranked by how many native files cite it.

    need: "match" (not exact), "name" (provisional name), "link" (exact, not linked) filters rows."""
    target = default_target(project, target)
    refresh(project)
    db = connect(project)
    native = role_repos(project, "native")
    if not native:
        raise ValueError("Project has no repository with role=native")
    marks = ",".join("?" * len(native))
    cited = db.execute(f"SELECT address, path FROM cites WHERE repo IN ({marks})", native).fetchall()
    per_function: dict[int, set] = collections.defaultdict(set)
    unresolved = collections.Counter()
    for address, path in cited:
        row = containing(db, target, address)
        if row is None:
            unresolved[address] += 1
            continue
        per_function[row["address"]].add(path)
    rows, totals = [], collections.Counter()
    for address, paths in per_function.items():
        row = containing(db, target, address)
        info = _status(row)
        totals["cited_functions"] += 1
        totals["exact"] += info["exact"]
        totals["linked"] += info["linked"]
        totals["provisional_name"] += info["provisional_name"]
        wants = []
        if not info["exact"]:
            wants.append("match")
        if info["provisional_name"]:
            wants.append("name")
        if info["exact"] and not info["linked"]:
            wants.append("link")
        if not wants or wants == ["link"]:
            continue
        if not include_exact_provisional and "match" not in wants:
            continue  # --match-only: rows that need no match (name/link only) are not decomp-matching work
        if need and need not in wants:
            continue
        if exclude and row["address"] in exclude:
            continue
        rows.append(info | {"native_files": len(paths), "need": wants, "example_file": sorted(paths)[0]})
    rows.sort(key=lambda r: (-r["native_files"], "match" not in r["need"], r["address"]))
    return {"target": target, "totals": dict(totals), "unresolved_native_addresses": len(unresolved),
            "rows": rows[offset:offset + limit], "matching_rows": len(rows), "offset": offset,
            "report_age_h": report_age_hours(project, target),
            "meaning": "Functions the native port cites whose decomp is not exact or still has a provisional "
                       "name. Recovering these first converts decomp progress directly into port evidence."}


def unresolved_cites(project: Project, target: str | None = None, limit: int = 50) -> list[dict]:
    target = default_target(project, target)
    db = connect(project)
    native = role_repos(project, "native")
    marks = ",".join("?" * len(native))
    out = []
    for row in db.execute(f"SELECT * FROM cites WHERE repo IN ({marks}) ORDER BY path, line", native):
        if containing(db, target, row["address"]) is None:
            symbol = _symbol_lookup(project, target, row["address"])
            if symbol is None:
                out.append(dict(row) | {"address": address_text(row['address'])})
                if len(out) >= limit:
                    break
    return out


def search(project: Project, query: str, repo: str | None = None, path_filter: str | None = None,
           limit: int = 12) -> dict:
    refresh(project)
    db = connect(project)
    tokens = [t for t in QUERY_SPLIT.split(query.strip()) if t]
    if tokens and all(HEX.match(t) for t in tokens):
        # Addresses inside identifiers (Foo__data_80434080) are not FTS tokens: use the address tables.
        rows = []
        for token in tokens:
            value = int(HEX.match(token)[1], 16)
            for table in ("cites", "mentions"):
                for r in _cites(db, value, 1, limit=limit * 2, table=table):
                    if repo and r["repo"] != repo or path_filter and path_filter not in r["path"]:
                        continue
                    rows.append({"ref": f"{r['repo']}:{r['path']}:{r['line']}", "excerpt": r["text"]})
        return {"query": query, "mode": "address", "results": rows[:limit], "total": len(rows)}
    rows = _search(db, fts_query(query), repo, path_filter, limit)
    mode = "all words"
    if not rows and len(query.split()) > 1:
        rows, mode = _search(db, fts_query(query, any_term=True), repo, path_filter, limit), "any word (no file had all)"
    return {"query": query, "mode": mode, "results": rows}


def _search(db, match: str, repo: str | None, path_filter: str | None, limit: int) -> list[dict]:
    sql = "SELECT repo, path, line, snippet(lines, 3, '[', ']', ' … ', 18) AS excerpt, bm25(lines) AS rank " \
          "FROM lines WHERE lines MATCH ?"
    args: list[Any] = [match]
    if repo:
        sql += " AND repo=?"
        args.append(repo)
    if path_filter:
        sql += " AND path LIKE ?"
        args.append(f"%{path_filter}%")
    sql += " ORDER BY rank LIMIT ?"
    args.append(limit * 3)
    rows, seen = [], collections.defaultdict(list)
    for row in db.execute(sql, args):
        key = (row["repo"], row["path"])
        # Overlapping windows: keep at most two hits per file, and not adjacent ones.
        if len(seen[key]) >= 2 or any(abs(row["line"] - other) <= 6 for other in seen[key]):
            continue
        seen[key].append(row["line"])
        rows.append({"ref": f"{row['repo']}:{row['path']}:{row['line']}", "excerpt": row["excerpt"]})
        if len(rows) >= limit:
            break
    return rows


def read(project: Project, reference: str, start: int = 1, lines: int = 120) -> dict:
    repository, _, rest = reference.partition(":")
    if not rest and repository and "/" in repository:
        raise ValueError("Use repo:path[:line], e.g. native:src/game/GameSession.cpp:120")
    path_part, _, line_part = rest.partition(":")
    if line_part.isdigit() and start == 1:
        start = max(1, int(line_part) - 10)
    repository = project.repo_key(repository) or repository
    path = project.file(repository, path_part)
    if not path.is_file():
        hint = _similar_paths(project, repository, path_part)
        raise ValueError(f"No such file: {reference}" + (f"; did you mean {', '.join(hint)}?" if hint else ""))
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("File exceeds the 4 MiB read limit")
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lines = max(1, min(lines, 400))
    start = max(1, start)
    body = "\n".join(f"{i}: {l}" for i, l in enumerate(content[start - 1:start - 1 + lines], start))
    more = len(content) - (start - 1 + lines)
    if more > 0:
        body += f"\n… {more} more lines (start={start + lines})"
    return {"ref": f"{repository}:{path_part}", "start": start, "total_lines": len(content), "text": body}


def _similar_paths(project: Project, repo: str, wanted: str, limit: int = 4) -> list[str]:
    db = connect(project)
    stem = Path(wanted).stem
    pieces = [p for p in re.split(r"[_\W]+", stem) if len(p) >= 4] or [stem]
    rows = db.execute("SELECT path FROM files WHERE repo=? AND path LIKE ? LIMIT ?",
                      (repo, f"%{pieces[0]}%", limit * 4)).fetchall()
    ranked = sorted((r[0] for r in rows), key=lambda p: -sum(piece in p for piece in pieces))
    return [f"{repo}:{p}" for p in ranked[:limit]]


# ----------------------------------------------------------------------------
# Diff checks: catch "slightly off" integrations before they are committed.

DEFINITION = re.compile(r"^(?!\s*(?:if|for|while|switch|return|else|case|do)\b)\s*(?:[\w:<>,\*&\s]+?)\s+"
                        r"(?P<name>[A-Za-z_]\w*(?:::[~A-Za-z_]\w*)*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{?\s*$")


def _git_run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.quotePath=false", "-C", str(root), *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)


def _resolve_base(root: Path, base: str) -> str:
    """A commit-ish only: never let a caller-supplied value reach git as an option."""
    if not base or base.startswith("-") or any(c in base for c in "\0\n"):
        raise ValueError(f"Invalid base revision: {base!r}")
    result = _git_run(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}")
    if result.returncode:
        raise ValueError(f"Unknown base revision {base!r} in {root}")
    return result.stdout.strip()


def _diff_hunks(root: Path, base: str = "HEAD", staged: bool = False) -> dict[str, list[tuple[set[int], list[str]]]]:
    """{path: [(added line numbers, removed line texts)]} per hunk vs base; untracked files map to []."""
    out: dict[str, list] = {}
    commit = _resolve_base(root, base)
    args = ["diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-renames"]
    args += ["--cached", commit, "--"] if staged else [commit, "--"]
    diff = _git_run(root, *args)
    if diff.returncode:
        raise ValueError(diff.stderr.strip() or f"git diff {base} failed")
    current, header, hunk = None, False, None
    for line in diff.stdout.splitlines():
        if line.startswith("diff --git "):
            current, header, hunk = None, True, None
        elif header and line.startswith("+++ "):
            name = line[4:]
            current = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            if current:
                out.setdefault(current, [])
        elif line.startswith("@@"):
            header = False
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if current and match:
                begin, count = int(match[1]), int(match[2] or 1)
                hunk = (set(range(begin, begin + count)), [])
                out[current].append(hunk)
        elif hunk is not None and line.startswith("-") and not header:
            hunk[1].append(line[1:])
    if not staged:
        untracked = _git_run(root, "ls-files", "-z", "--others", "--exclude-standard")
        for name in untracked.stdout.split("\0"):
            if name:
                out[name] = None
    return out


def _changed_files(root: Path, base: str = "HEAD", staged: bool = False) -> dict[str, set[int] | None]:
    """{path: added line numbers} vs base (working tree, or the index when staged), plus new files."""
    return {path: (None if hunks is None else set().union(*[h[0] for h in hunks]) if hunks else set())
            for path, hunks in _diff_hunks(root, base, staged).items()}


def _normalize(root: Path, path: str) -> str:
    """Accept repo-relative, ./-prefixed, absolute or cwd-relative paths."""
    candidate = Path(path)
    for option in ([candidate] if candidate.is_absolute() else [Path.cwd() / candidate, root / candidate]):
        try:
            resolved = option.resolve()
            if resolved.is_relative_to(root):
                return resolved.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
    return str(Path(path))


def _content(root: Path, rel: str, staged: bool) -> str | None:
    if staged:
        shown = subprocess.run(["git", "-C", str(root), "show", f":{rel}"], capture_output=True, timeout=60)
        return shown.stdout.decode("utf-8", errors="replace") if shown.returncode == 0 else None
    path = root / rel
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None


def check(project: Project, repo: str, base: str = "HEAD", paths: list[str] | None = None,
          target: str | None = None, staged: bool = False) -> dict:
    """Lint the working-tree change of one repository against its contract rules.

    Rules come from the repository's manifest `checks` block, so another
    project configures its own. Only added/changed lines are judged; a violation
    that the same hunk already had before the edit is reported as debt, not an error."""
    target = default_target(project, target)
    refresh(project, [repo])
    db = connect(project)
    root = project.root(repo)
    config = project.config["repositories"][repo]
    rules = config.get("checks", {})
    address = re.compile(config.get("address_pattern", r"(?<![0-9A-Fa-f])(?:0x)?(8[01][0-9A-Fa-f]{6})(?![0-9A-Fa-f])"))
    if paths is None:
        hunks = _diff_hunks(root, base, staged)
        changed = {p: (None if h is None else set().union(*[x[0] for x in h]) if h else set()) for p, h in hunks.items()}
    else:
        hunks = {}
        changed = {_normalize(root, p): None for p in paths}
    texts = {rel: _content(root, rel, staged) for rel in changed}
    scope = [re.compile(x) for x in rules.get("source_globs", [r"^src/.*\.(cpp|hpp|h|cc)$"])]
    forbidden = [(re.compile(r["pattern"]), r["message"], re.compile(r.get("paths", ".*")))
                 for r in rules.get("forbidden", [])]
    findings = []
    stats = collections.Counter()
    for rel, added in sorted(changed.items()):
        if texts.get(rel) is None:
            continue
        text_lines = texts[rel].splitlines()
        wanted = (lambda n: True) if added is None else (lambda n, a=added: n in a)
        removed_by_line: dict[int, list[str]] = {}
        for lines_added, removed in (hunks.get(rel) or []):
            for n in lines_added:
                removed_by_line[n] = removed
        for pattern, message, where in forbidden:
            if not where.search(rel):
                continue
            for number, line in enumerate(text_lines, 1):
                if wanted(number) and pattern.search(line):
                    debt = any(pattern.search(old) for old in removed_by_line.get(number, []))
                    stats["debt" if debt else "violations"] += 1
                    findings.append({"severity": "info" if debt else "error",
                                     "rule": "forbidden-existing" if debt else "forbidden", "ref": f"{rel}:{number}",
                                     "message": ("pre-existing violation on an edited line (debt, not new): "
                                                 if debt else "") + message, "line": line.strip()[:160]})
        if not any(s.search(rel) for s in scope):
            continue
        stats["files"] += 1
        for number, line in enumerate(text_lines, 1):
            if not wanted(number):
                continue
            for match in address.finditer(line):
                value = int(match.group(1), 16)
                stats["citations"] += 1
                row = containing(db, target, value)
                if row is None:
                    if _symbol_lookup(project, target, value) is None and rules.get("resolve_citations", True):
                        findings.append({"severity": "warning", "rule": "citation-unresolved",
                                         "ref": f"{rel}:{number}", "address": address_text(value),
                                         "message": "Address is not a function or symbol in the target; typo, "
                                                    "flag constant, or stale address?"})
                    continue
                info = _status(row)
                if not info["exact"]:
                    findings.append({"severity": "info", "rule": "citation-unmatched", "ref": f"{rel}:{number}",
                                     "address": info["address"], "name": info["name"],
                                     "message": f"Cited decomp function is {status_word(info)}; its semantics "
                                                "are unverified. Note the gap; recover it only if this change "
                                                "depends on the unverified part."})
                if match.group(0).lower().startswith("0x") and rules.get("bare_citations"):
                    findings.append({"severity": "warning", "rule": "citation-format", "ref": f"{rel}:{number}",
                                     "message": rules["bare_citations"]})
        if rules.get("require_citation") and rel.endswith((".cpp", ".cc")):
            for number, line in enumerate(text_lines, 1):
                if not wanted(number):
                    continue
                definition = DEFINITION.match(line)
                if not definition or line.startswith((" ", "\t")):
                    continue
                stats["new_definitions"] += 1
                from .tiers import tier_of
                tier = tier_of(project, repo, rel) if config.get("role") == "native" else "exact"
                if tier not in ("exact", "equivalent"):
                    continue  # liberty/infrastructure code has no original to cite
                end = number
                while end < len(text_lines) and not text_lines[end].startswith("}"):
                    end += 1
                if end - number < rules.get("citation_min_lines", 6):
                    continue  # trivial accessors/constructors need no citation of their own
                # The function's own comment block (directly above it) and its body.
                lo = number - 1
                while lo > 0 and text_lines[lo - 1].strip().startswith(("//", "/*", "*", "template", "[[")):
                    lo -= 1
                nearby = "\n".join(text_lines[lo:min(len(text_lines), end + 1)])
                exempt = rules.get("citation_exempt", "INTENTIONAL-DIVERGENCE|NATIVE:")
                if not address.search(nearby) and not re.search(exempt, nearby):
                    findings.append({"severity": "warning" if tier == "exact" else "info",
                                     "rule": "citation-missing", "ref": f"{rel}:{number}",
                                     "name": definition["name"],
                                     "message": f"New {tier}-tier function with no original address. Cite the "
                                                "original, or mark it as a native-only addition."})
    if config.get("role") == "native" and project.config.get("targets"):
        from .fidelity import constant_audit
        scoped = {rel: added for rel, added in changed.items() if any(g.search(rel) for g in scope)}
        try:
            audit = constant_audit(project, repo, None, target, only_lines=scoped)["findings"] if scoped else []
        except (OSError, ValueError) as error:  # e.g. no original DOL on this machine: lint the rest anyway
            audit = []
            findings.append({"severity": "info", "rule": "constants-skipped", "ref": repo,
                             "message": f"Constant audit unavailable: {error}"})
        for f in audit:
            if f["tier"] not in ("exact", "equivalent"):
                continue
            if f["kind"] == "near":
                stats["near_constants"] += 1
                findings.append({"severity": f["severity"], "rule": "constant-near-miss", "ref": f["ref"],
                                 "message": f"{f['value']} is within 2% of original constant(s) {f['near']} the "
                                            "cited code loads. Check `zkit asm` first: folded arithmetic (two "
                                            "adds) or rounding can be the real cause; do not just copy the value."})
            elif f["kind"] == "folded":
                stats["folded_constants"] += 1
                findings.append({"severity": "warning", "rule": "constant-folded", "ref": f["ref"],
                                 "message": f"{f['value']} equals {f['folded']} of original constants loaded "
                                            "separately: the original does the operations one by one (float "
                                            "rounding differs). Keep them as separate operations."})
            elif f["tier"] == "exact":
                stats["unsourced_constants"] += 1
                findings.append({"severity": "info", "rule": "constant-unsourced", "ref": f["ref"],
                                 "message": f"{f['value']} is not loaded by any cited original: cite the "
                                            "function/data it comes from, or mark it native."})
    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["ref"]))
    return {"repo": repo, "base": base, "worktree": project.worktree(repo), "stats": dict(stats),
            "findings": findings, "ok": not any(f["severity"] == "error" for f in findings)}


# ----------------------------------------------------------------------------
# Reuse: find what already exists before writing another copy.

FREE_FUNCTION = re.compile(r"^(?:static\s+|inline\s+|constexpr\s+|\[\[nodiscard\]\]\s+)*"
                           r"(?:[\w:<>]+[\s\*&]+)(?P<name>[a-z_]\w*)\s*\((?P<args>[^;{}]*)\)\s*(?:noexcept\s*)?\{")


def reuse(project: Project, repo: str, terms: list[str] | None = None, min_files: int = 3, limit: int = 25) -> dict:
    """Two views of missing sharing in one repository.

    duplicates: the same small helper (name + normalized body) defined in
      several files, which should be one shared function.
    enumerations: files that name several sibling variants together (for
      example enemy families). These are the central dispatch sites a new
      variant must edit; a growing list means the variant is not data-driven.
    """
    refresh(project, [repo])
    root = project.root(repo)
    config = project.config["repositories"][repo]
    globs = [re.compile(x) for x in config.get("checks", {}).get("source_globs", [r"^src/.*\.(cpp|hpp|h|cc)$"])]
    defs: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    by_name: dict[str, set[str]] = collections.defaultdict(set)
    sites = []
    term_res = [(t, re.compile(rf"\b{re.escape(t)}", re.I)) for t in (terms or [])]
    db = connect(project)
    files = [r[0] for r in db.execute("SELECT path FROM files WHERE repo=?", (repo,))]
    for rel in files:
        if not any(g.search(rel) for g in globs):
            continue
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if term_res:
            hit = sorted({t for t, r in term_res if r.search(text)})
            if len(hit) >= max(2, min(len(term_res), 3)):
                sites.append({"path": rel, "variants": hit, "count": len(hit)})
        lines = text.splitlines()
        for i, line in enumerate(lines):
            match = FREE_FUNCTION.match(line)
            if not match or match["name"] in ("main", "operator"):
                continue
            depth, body = 0, []
            for j in range(i, min(i + 40, len(lines))):
                depth += lines[j].count("{") - lines[j].count("}")
                body.append(lines[j])
                if depth <= 0 and j > i or (depth == 0 and "}" in lines[j]):
                    break
            if depth > 0:
                continue
            normalized = re.sub(r"\s+", " ", re.sub(r"//.*", "", " ".join(body[1:]))).strip()
            defs[(match["name"], normalized)].append(f"{rel}:{i + 1}")
            by_name[match["name"]].add(rel)
    duplicates = [{"name": name, "copies": len(places), "places": places[:8]}
                  for (name, _), places in defs.items() if len({p.rsplit(':', 1)[0] for p in places}) >= min_files]
    duplicates.sort(key=lambda d: -d["copies"])
    same_name = [{"name": n, "files": len(f), "examples": sorted(f)[:5]}
                 for n, f in by_name.items() if len(f) >= min_files + 2]
    same_name.sort(key=lambda d: -d["files"])
    sites.sort(key=lambda s: (-s["count"], s["path"]))
    return {"repo": repo, "identical_helpers": duplicates[:limit],
            "same_name_helpers": same_name[:limit],
            "enumeration_sites": {"terms": terms or [], "files": len(sites), "rows": sites[:limit]},
            "limits": "Textual: identical normalized bodies of free functions up to 40 lines, and files naming "
                      "several variants. It finds candidates for sharing, not proof that sharing is correct."}
