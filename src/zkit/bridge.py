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
import math
import os
import re
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Any

from .gc import Symbol, read_symbols
from .index import (MODULE_SHIFT, address_text, cache_path, connect, containing, fts_query, module_address, refresh,
                    report_age_hours, report_staleness, use_platform)
from .project import Project

class _Address:
    """`HEX.match(text)[1]` is the hex of the key an address token names, for the active platform: 80012345 and
    0x80012345 on GameCube, 0x7100123456 or 0x123456 on Switch (stored relative to the module base)."""

    class _Found:
        def __init__(self, value: int):
            self.value = value

        def __getitem__(self, index: int) -> str:
            return f"{self.value:X}"

    def match(self, text: str):
        from .index import platform
        value = platform().parse(text) if text else None
        return self._Found(value) if value is not None else None


HEX = _Address()
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


QUOTES = "`'\";,"  # pasted around or after a query: `0x8000FFA4`, "TEnemy::update", 8000FFA4,


def split_queries(text: str) -> list[str]:
    """Several addresses (or several plain symbol names or unit paths) in one query -> separate queries.

    `0x8013E990 0x8013E998`, `8013E990,8013E998` and `lbl_805DE138 lbl_805DE13C` are batches;
    `TEnemy::update`, `operator new` or a phrase with spaces that is not all names stays one query. Quotes,
    backticks and trailing commas pasted around a query are dropped."""
    tokens = [t.strip(QUOTES) for t in QUERY_SPLIT.split(text.strip()) if t.strip(QUOTES)]
    if len(tokens) > 1 and "operator" not in tokens and all(
            HEX.match(t) or MODULE_TOKEN.fullmatch(t) or re.fullmatch(r"[A-Za-z_~][\w:~./-]*", t) for t in tokens):
        return tokens  # addresses, symbols and Class::method names, mixed or not, are looked up one by one
    return [text.strip().strip(QUOTES).strip()]


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


DATA_TYPES = ("u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "f32", "f64", "ptr", "str")
TYPE_ALIASES = {"string": "str", "char": "str", "hex": "u8", "bytes": "u8", "byte": "u8", "short": "s16",
                "ushort": "u16", "int": "s32", "uint": "u32", "word": "u32", "long": "s32", "float": "f32",
                "double": "f64", "pointer": "ptr", "addr": "ptr", "address": "ptr", "quad": "u64"}


def data_type(kind: str) -> str:
    """A data type name as agents write it (string, hex, float, ...) -> one of DATA_TYPES."""
    kind = (kind or "u32").strip().lower()
    kind = TYPE_ALIASES.get(kind, kind)
    if kind not in DATA_TYPES:
        raise ValueError(f"Unknown type {kind!r}; use one of {', '.join(DATA_TYPES)}")
    return kind


def typed_query(query: str, kind: str, count: int | None) -> tuple[str, str, int | None]:
    """`ADDR:type[:count]` (as agents write it) -> (ADDR, type, count); anything else unchanged."""
    names = "|".join([*DATA_TYPES, *TYPE_ALIASES])
    match = re.fullmatch(rf"(.+?):({names})(?::(\d+))?", query.strip(), re.I)
    if not match:
        return query, data_type(kind), count
    return match[1], data_type(match[2]), int(match[3]) if match[3] else count


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


_VTABLE_CLASSES: dict[str, str] = {}


def vtable_class(symbol: str) -> str:
    """The class a vtable symbol belongs to: __vt__6TEnemy -> TEnemy, _ZTVN2mp6LayoutE -> mp::Layout."""
    if symbol.startswith("__vt__"):
        return re.sub(r"^__vt__\d*", "", symbol)
    if symbol not in _VTABLE_CLASSES:
        from .platform import demangle_itanium
        text = demangle_itanium([symbol])[0] or symbol
        _VTABLE_CLASSES[symbol] = text.removeprefix("vtable for ")
    return _VTABLE_CLASSES[symbol]


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


def _decompile_available() -> bool:
    from .decompile import available
    return available()


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
        state = f"{math.floor(info['match'] * 10) / 10:.1f}%"  # never rounds a near miss up to "100.0%"
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
    return {"address": address_text(best.address), "key": best.address, "name": best.name, "section": best.section,
            "type": best.type, "size": best.size, "offset": address - best.address}


_SYMBOLS: dict[str, tuple[str, tuple]] = {}
SYMBOLS_CACHE_VERSION = 2


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


def _module_symbols(project: Project, target: str) -> list[Symbol]:
    """Switch: data and function symbols from the module itself (dynamic symbols, and vtables, typeinfos and
    typeinfo names from RTTI), plus a project data-symbol CSV (`data_symbols`: address,name), cached like
    symbols.txt."""
    from .inspect_dol import _dol
    from .platform import for_target
    config = project.target(target)
    platform = for_target(config)
    original = project.file(config["repository"], config["original"])
    extra = project.file(config["repository"], config["data_symbols"]) if config.get("data_symbols") else None
    stamp = f"{original.stat().st_mtime_ns}:{original.stat().st_size}" + (
        f":{extra.stat().st_mtime_ns}" if extra and extra.is_file() else "")
    store = cache_path(project).with_name(f"symbols-{target}-{hashlib.sha1(str(original).encode()).hexdigest()[:12]}.marshal")
    try:
        version, saved, rows = marshal.loads(store.read_bytes())
        if version == SYMBOLS_CACHE_VERSION and saved == stamp:
            return [Symbol(*row) for row in rows]
    except (OSError, EOFError, ValueError, TypeError):
        pass
    module = _dol(project, target)
    section = lambda offset: (module.segment_at(offset).name if module.segment_at(offset) else "?")
    found: dict[int, Symbol] = {}
    for offset, name in module.symbols.items():
        kind = "function" if module.kinds.get(offset) == "func" else "object"
        found[offset] = Symbol(name, section(offset), offset, kind, module.sizes.get(offset, 0), "global")
    from . import rtti
    for info in rtti.classes(module).values():
        size = {"class": 16, "single": 24}.get(info.kind, 24 + 16 * len(info.bases))
        found.setdefault(info.typeinfo, Symbol(f"_ZTI{info.mangled}", section(info.typeinfo), info.typeinfo,
                                               "object", size, "global"))
        if info.vtables:
            top = min(v["address"] for v in info.vtables) - 16
            end = max(v["address"] + 8 * len(v["slots"]) for v in info.vtables)
            found.setdefault(top, Symbol(f"_ZTV{info.mangled}", section(top), top, "object", end - top, "global"))
    if extra and extra.is_file():
        import csv
        with extra.open(encoding="utf-8", errors="replace", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) < 2:
                    continue
                address = platform.parse(row[0])
                if address is not None:
                    found[address] = Symbol(row[1].strip(), section(address), address, "object",
                                            int(row[2], 0) if len(row) > 2 and row[2].strip() else 0, "global")
    symbols = sorted(found.values(), key=lambda s: (s.address, -s.size))
    try:
        store.write_bytes(marshal.dumps((SYMBOLS_CACHE_VERSION, stamp, [tuple(s) for s in symbols])))
    except OSError:
        pass
    return symbols


def _symbol_table(project: Project, target: str) -> tuple[list, list[int]]:
    """A target's symbols by address: its symbols.txt, and a Switch module's own symbols (exports, RTTI) where the
    file has none at their address, in the file's dotted sections."""
    entry = _symbol_entry(project, target)
    return (entry[0], entry[1]) if entry else ([], [])


def _symbol_entry(project: Project, target: str) -> tuple | None:
    config = project.target(target)
    path = project.file(config["repository"], config["symbols"]) if config.get("symbols") else None
    path = path if path is not None and path.is_file() else None
    original = None
    if (config.get("platform") or "").lower() in ("switch", "nx") and config.get("original"):
        original = project.file(config["repository"], config["original"])
        original = original if original.is_file() else None
    if path is None and original is None:
        return None
    own = f"{path.stat().st_mtime_ns}:{path.stat().st_size}" if path else ""
    stamp = own + (f":{original.stat().st_mtime_ns}" if original else "")
    key = f"{target}:{path}:{original}"
    cached = _SYMBOLS.get(key)
    if not cached or cached[0] != stamp:
        symbols = _parsed_symbols(project, path, own) if path else []
        if original is not None:
            taken = {s.address for s in symbols}
            symbols = sorted(symbols + [s._replace(section=f".{s.section}") for s in _module_symbols(project, target)
                                        if s.address not in taken], key=lambda s: (s.address, -s.size))
        by_name = {}
        for s in symbols:
            by_name.setdefault(s.name, s)
        _SYMBOLS[key] = (stamp, (symbols, [s.address for s in symbols], by_name))
    return _SYMBOLS[key][1]


def symbol_named(project: Project, target: str, name: str):
    entry = _symbol_entry(project, target)
    return entry[2].get(name) if entry else None


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
    if not rows and "(" not in text:  # Class::method without its parameters: every overload, nothing else
        rows = db.execute("SELECT address FROM functions WHERE target=? AND substr(demangled, 1, ?)=? LIMIT ?",
                          (target, len(text) + 1, text + "(", limit)).fetchall()
    if not rows:
        symbol = symbol_named(project, target, text)
        if symbol is not None:
            return [symbol.address]
        like = f"%{text}%"
        rows = db.execute("SELECT address FROM functions WHERE target=? AND (demangled LIKE ? OR name LIKE ?) "
                          "ORDER BY length(coalesce(demangled,name)) LIMIT ?",
                          (target, like, like, limit)).fetchall()
    return [r[0] for r in rows]


CANDIDATES = 8


def _ambiguous(project: Project, query: str, target: str | None, found: list[int]) -> ValueError:
    db = connect(project)
    target = default_target(project, target)
    names = [f"{address_text(a)} {r['demangled'] or r['name']}" if r else address_text(a)
             for a in found[:CANDIDATES] for r in [containing(db, target, a)]]
    more = " (and more)" if len(found) > CANDIDATES else ""
    return ValueError(f"{query} matches {len(found[:CANDIDATES])}{more} functions: {'; '.join(names)}. Use an "
                      "address or the full name")


def resolve_address(project: Project, query: str, target: str | None = None) -> int | None:
    """The exact address a query names: a hex address as given, else the symbol/function start; None when nothing
    matches. A name several functions match is an error that lists them."""
    match = HEX.match(query.strip())
    if match:
        return int(match[1], 16)
    keyed = module_address(query)
    if keyed is not None:
        return keyed
    found = resolve(project, query, target, limit=CANDIDATES + 1)
    if len(found) > 1:
        raise _ambiguous(project, query, target, found)
    return found[0] if found else None


def resolve_one(project: Project, query: str, target: str | None = None) -> int:
    """The one function (or data) address a query names, or an error saying nothing or several match."""
    found = resolve(project, query, target, limit=CANDIDATES + 1)
    if not found:
        raise ValueError(f"No function or symbol matches {query}")
    if len(found) > 1:
        raise _ambiguous(project, query, target, found)
    return found[0]


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


LIBRARY_CATEGORIES = ("sdk", "runtime", "msl")
_LIBRARY: dict[str, tuple[str, frozenset]] = {}
_LIBRARY_PATHS: dict[tuple, Path] = {}


def library_units(project: Project, target: str) -> frozenset[str]:
    """Units the original links from libraries (SDK, C runtime): objdiff.json units whose progress categories are
    in the target's `library_categories` (default sdk, runtime, msl). A port replaces those with platform code."""
    config = project.target(target)
    wanted = sorted(config.get("library_categories", LIBRARY_CATEGORIES))
    try:
        where = (str(project.path), target, project.worktree(config["repository"]))
        if where not in _LIBRARY_PATHS:
            _LIBRARY_PATHS[where] = project.file(config["repository"], config.get("objdiff", "objdiff.json"))
        path = _LIBRARY_PATHS[where]
        stamp = f"{path.stat().st_mtime_ns}:{wanted}"
    except (OSError, ValueError):
        return frozenset()
    if _LIBRARY.get(str(path), ("",))[0] != stamp:
        try:
            units = json.loads(path.read_text(encoding="utf-8")).get("units", [])
        except (OSError, ValueError):
            units = []
        _LIBRARY[str(path)] = (stamp, frozenset(
            u["name"] for u in units if u.get("name")
            and set((u.get("metadata") or {}).get("progress_categories") or []) & set(wanted)))
    return _LIBRARY[str(path)][1]


_DEFINE = re.compile(r"^\s*#\s*(define|undef)\s+([A-Za-z_]\w*)(?:\s+(.+))?$")


def _placeholder_macros(lines: list[str], last: int, body: str, catalog) -> list[str]:
    """`#define NAME ((Obj_80012345 *)self)`-style macros in effect at the function (defined in the file up to
    its last line and not #undef'd) whose expansion is address-named or casts, and which the body uses."""
    from . import quality
    active: dict[str, str] = {}
    for text in lines[:last]:
        match = _DEFINE.match(text) if "#" in text else None
        if match and match[1] == "define":
            active[match[2]] = match[3] or ""
        elif match:
            active.pop(match[2], None)
    return [f"{name} = {expansion.strip()[:40]}" for name, expansion in active.items()
            if re.search(rf"\b{re.escape(name)}\b", body) and any(
                f["blocks"] and f["group"] in ("names", "types") for f in quality.findings(expansion, catalog))]


_READY: dict[tuple, tuple] = {}


def _file_stamp(path: Path) -> tuple:
    try:
        info = path.stat()
        return info.st_mtime_ns, info.st_size
    except OSError:
        return ()


def readiness(project: Project, target: str, row) -> dict[str, Any]:
    """readiness_of(), remembered per function until its row, the file holding its definition, the manifest's
    quality patterns or the library units change (a pass over thousands of cited functions reads them once)."""
    repo = project.target(target)["repository"]
    key = (str(project.path), target, row["address"])
    stamp = (row["name"], row["demangled"], row["match"], row["provisional"], row["unit"], row["source"],
             json.dumps(project.config["repositories"][repo].get("quality", {}), sort_keys=True),
             project.target(target).get("library_categories"), len(library_units(project, target)))
    cached = _READY.get(key)
    if cached and cached[0] == stamp and all(_file_stamp(path) == when for path, when in cached[1]):
        return cached[2]
    result = readiness_of(project, target, row)
    if result["definition"]:  # an unfound definition may appear in any file later: never remembered
        try:
            files = {project.file(repo, p) for p in {result["definition"].rsplit(":", 1)[0], row["source"]} if p}
        except ValueError:
            return result
        _READY[key] = (stamp, [(path, _file_stamp(path)) for path in files], result)
    return result


def readiness_of(project: Project, target: str, row) -> dict[str, Any]:
    """Whether an original function's decomp is a behavior reference a port may follow yet.

    Ready means byte-exact, named on evidence (its own name and class are not placeholders: no address-named
    class, vtable-slot name or offset-named accessor), and a definition whose body reads as source: no raw
    offsets, decompiler temporaries, placeholder callees or data, also behind a `#define` of the same file.
    Anything less is the decomp being unclear, and a port holds that behavior until the decomp is cleaned.
    Spelling debt that names its target in full (a hand-mangled call) is listed in `spelling` and does not hold.
    A library function (see library_units) written as assembly is ready with reference "assembly": that
    assembly is the original's own source."""
    from . import quality
    info = _status(row)
    reasons, spelling, reference = [], [], None
    if not info.get("exact"):
        reasons.append("not byte-exact")
    repo = project.target(target)["repository"]
    catalog = quality.patterns(project, repo)
    if info.get("provisional_name"):
        reasons.append("placeholder name")
    else:
        shaped = [f"{f['label'].split(' (')[0]} {f['text']}" for f in quality.findings(row["demangled"] or row["name"] or "", catalog)
                  if f["blocks"] and f["group"] != "linkage"]
        if shaped:
            reasons.append("placeholder-shaped name (" + "; ".join(dict.fromkeys(shaped)) + ")")
    library = bool(row["unit"]) and row["unit"] in library_units(project, target)
    found = source_definition(project, repo, row["source"], row["name"], row["demangled"]) \
        or header_definition(project, repo, row["name"], row["demangled"])
    if found is None:
        if info.get("exact"):
            reasons.append("definition not found in the source")
    else:
        reference = "source"
        found_debt = quality.findings(found["body"], catalog)
        blocking = [f for f in found_debt if f["blocks"]]
        if library and blocking and {f["group"] for f in blocking} == {"asm"}:
            reference, blocking = "assembly", []
        counts = collections.Counter(f["label"].split(" (")[0] for f in blocking)
        debt = [f"{label} x{n}" for label, n in counts.most_common(4)]
        if debt:
            reasons.append("source still reads as decompiler output (" + ", ".join(debt) + ")")
        spelling = [f"{label} x{n}" for label, n in collections.Counter(
            f["label"].split(" (")[0] for f in found_debt if not f["blocks"] and f["key"] != "extern_c").most_common(3)]
        try:
            lines = _source_text(project.file(repo, found.get("path", row["source"])))[0] \
                if reference == "source" else []
        except ValueError:
            lines = []
        aliases = _placeholder_macros(lines, found["end"], quality._strip_comments(found["body"]), catalog)
        if aliases:
            reasons.append("a #define re-types or aliases names the body uses (" + ", ".join(aliases[:3]) + ")")
    return {"ready": not reasons, "reasons": reasons, "spelling": spelling, "reference": reference,
            "library": library, "definition": f"{found.get('path', row['source'])}:{found['line']}" if found else None}


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
            table = symbol["key"]
            entry.update(symbol=symbol["name"], table=symbol["address"], offset=symbol["offset"],
                         table_size=symbol["size"])
            itanium = symbol["name"].startswith("_ZTV")
            is_vtable = symbol["name"].startswith("__vt__") or itanium
            if itanium:
                entry["vtable_slot"] = (symbol["offset"] - 16) // 8
            elif is_vtable or symbol["name"].startswith("lbl_"):
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
        named = sorted({h["symbol"] for h in holders if h["symbol"].startswith(("__vt__", "_ZTV"))})
        tables = [{"table": h["table"], "symbol": h["symbol"], "owners": h.get("owners", [])} for h in holders]
        classes = sorted({vtable_class(n) for n in named})
        verdict = ("shared by %d tables: an inherited base-class virtual — do not name it after one subclass"
                   % len(holders)) if len(holders) > 1 else "one table: the class owning that table defines it"
        out.append({"offset": offset, "slot": holders[0]["vtable_slot"], "tables": len(holders), "classes": classes,
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
    addresses = resolve(project, query, target, limit=CANDIDATES + 1)
    if not addresses:
        near = _near_names(db, target, query)
        return {"query": query, "found": False, "suggestions": near,
                "hint": "No function or symbol matched; try an address, the mangled name, names with a regex, or "
                        "search."}
    if len(addresses) > 1:
        rows = [_status(containing(db, target, a)) for a in addresses[:CANDIDATES]]
        return {"query": query, "found": True, "ambiguous": True, "candidates": rows,
                "more": len(addresses) > CANDIDATES}
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
        "report_stale": report_staleness(project, target),
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
        "decompile": not info["exact"] and row["address"] < 1 << MODULE_SHIFT and _decompile_available(),
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
    start = symbol["key"] if symbol else address
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
    from .platform import for_target
    platform = for_target(project.target(target))
    try:
        dol = _dol(project, target)
        if platform.pointer_size == 8:
            words = [dol.pointers.get(start + i * 8, 0) or 0 for i in range(min(size, cap * 8) // 8)]
        else:
            words = dol.words(start, min(size, cap * 4))
    except ValueError:
        return []
    out = []
    for index, word in enumerate(words):
        if not word or not platform.in_image(dol, word):
            continue
        row = containing(db, target, word)
        if row is not None:
            name = row["demangled"] or row["name"]
            label = name + (f"+0x{word - row['address']:X}" if word != row["address"] else "")
            out.append({"offset": index * platform.pointer_size, "target": f"{address_text(word)} {label}", "status": status_word(_status(row))})
        else:
            symbol = _symbol_lookup(project, target, word)
            label = (symbol["name"] + (f"+0x{symbol['offset']:X}" if symbol["offset"] else "")) if symbol else ""
            out.append({"offset": index * platform.pointer_size, "target": f"{address_text(word)} {label}".strip()})
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
                max(symbol["size"], 1) if symbol and symbol["key"] == address else 4)
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
    span = (target, address, address + max(size, 1))
    pointers = db.execute("SELECT count(*), sum(pointee=?) FROM refs WHERE target=? AND pointee>=? AND pointee<?",
                          (address, *span)).fetchone()
    for holder, pointee in db.execute("SELECT holder, pointee FROM refs WHERE target=? AND pointee>=? AND pointee<? "
                                      "ORDER BY pointee!=?, holder LIMIT ?", (*span, address, limit)):
        owner = _symbol_lookup(project, target, holder)
        data.append({"holder": address_text(holder), "pointee": address_text(pointee), "into": pointee - address,
                     **({"symbol": owner["name"], "offset": owner["offset"]} if owner else {})})
    functions = collections.Counter()
    for function, n in per_function.most_common(40):  # over every reference, not just the rows shown
        row = containing(db, target, function)
        functions[(row["demangled"] or row["name"]) if row else address_text(function)] += n
    row = containing(db, target, address)
    return {"address": address_text(address), "size": size, "symbol": symbol, "code": code, "data": data,
            "data_total": pointers[0], "data_to_start": pointers[1] or 0,
            "function": (row["demangled"] or row["name"]) if row and row["address"] == address else None,
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
                hex_match = HEX.match(q)
                value = int(hex_match[1], 16) if hex_match else module_address(q)
                found = [value] if value is not None else resolve(project, q, target, limit=CANDIDATES + 1)
                if len(found) > 1:
                    rows.append({"query": q, "ambiguous": [_status(containing(db, target, a)) for a in found[:CANDIDATES]],
                                 "more": len(found) > CANDIDATES})
                    continue
                row = containing(db, target, found[0]) if found else None
                if row is not None:
                    rows.append(_status(row) | {"query": q, "offset": found[0] - row["address"]})
                    continue
                symbol = _symbol_lookup(project, target, found[0]) if found else None
                rows.append({"query": q, "address": address_text(found[0]) if found else None,
                             "name": symbol["name"] if symbol else None, "symbol": symbol, "data": bool(symbol),
                             "found": bool(symbol)})
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
    try:
        pattern = re.compile(regex) if regex else None
    except re.error as error:
        raise ValueError(f"regex {regex!r} is not a valid regular expression: {error}") from None
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


PLAN_DEPTH = 4
SHARED_CALLERS = 8  # this many original callers: one shared owner in the port, not a copy per feature
PLAN_LEGEND = {
    "reuse": "the port already cites it and the decomp is ready: extend that owner instead of writing a copy",
    "reuse-unverified": "the port cites it but the decomp is not ready (reasons shown): the native semantics are "
                        "unproven until the decomp is cleaned",
    "decompile-first": "not byte-exact in the decomp: match it before porting what depends on it (`decompile` "
                       "reads it meanwhile; that is not proof)",
    "clean-first": "exact, but the decomp is not ready (reasons shown): clean and name it in the decomp, then port",
    "shared-port": f"ready, with {SHARED_CALLERS}+ original callers: port once into a shared owner, not per feature",
    "port": "ready in the decomp and not cited natively yet",
    "platform": "SDK/runtime library code (the target's library_categories): the port uses its own platform "
                "code, not a port of this",
}


def port_plan(project: Project, query: str, depth: int = 2, target: str | None = None,
              max_nodes: int = 80) -> dict:
    """The original call tree under a function, joined with native coverage and decomp readiness.

    Tells an agent what to REUSE (callees the port already cites), what to PORT, what is decomp work first
    (DECOMPILE-FIRST / CLEAN-FIRST) and what is PLATFORM code the port replaces."""
    target = default_target(project, target)
    refresh(project)
    db = connect(project)
    queries = split_queries(query)
    if len(queries) > 1:
        return {"query": query, "batch": [port_plan(project, q, depth, target, max_nodes) for q in queries[:12]],
                "legend": PLAN_LEGEND}
    note = f"depth {depth} is capped at {PLAN_DEPTH}; plan a callee for deeper levels" if depth > PLAN_DEPTH else None
    depth = max(0, min(depth, PLAN_DEPTH))
    addresses = resolve(project, query, target)
    root = containing(db, target, addresses[0]) if len(addresses) == 1 else None
    if root is None:  # ambiguous, unknown, or data: the lookup answer says which, with candidates or the symbol
        return lookup(project, query, target, fresh=False) | {
            "note": "port_plan needs one function; pick a candidate or use a function address"}
    native = role_repos(project, "native")
    from .index import platform as active_platform
    gamecube = active_platform().name == "gamecube"
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
        ready = readiness(project, target, row)
        info.update(ready=ready["ready"], not_ready=ready["reasons"], spelling=ready["spelling"],
                    reference=ready["reference"])
        if ready["library"]:
            info["action"] = "platform"
        elif not info["exact"]:
            info["action"] = "decompile-first"
        elif info["native_files"]:
            info["action"] = "reuse" if ready["ready"] else "reuse-unverified"
        elif not ready["ready"]:
            info["action"] = "clean-first"
        elif callers >= SHARED_CALLERS:
            info["action"] = "shared-port"
        else:
            info["action"] = "port"
        info["indirect_calls"] = _indirect_calls(project, target, row) if gamecube else None
        nodes.append(info)
        if level < depth and info["action"] != "platform":
            for (callee,) in db.execute("SELECT callee FROM calls WHERE target=? AND caller=? GROUP BY callee "
                                        "ORDER BY min(site)", (target, row["address"])):
                child = containing(db, target, callee)
                if child and child["address"] not in seen:
                    seen.add(child["address"])
                    frontier.append((child["address"], level + 1, address))
    counts = collections.Counter(n["action"] for n in nodes)
    return {"query": query, "found": True, "root": nodes[0], "nodes": nodes, "summary": dict(counts),
            "truncated_nodes": truncated, "depth": depth, **({"note": note} if note else {}),
            "legend": PLAN_LEGEND,
            "limits": "Direct calls only" + ("; `indirect_calls` counts bctrl sites (vtable/pointer dispatch) whose "
                      "targets are not in the tree: read them with asm" if gamecube else "; vtable/pointer dispatch "
                      "is not followed: read the callers' asm") + ". `lookup` on the root lists its callers. Hold "
                      "rule: port only nodes marked port, shared-port or reuse; everything else is decomp work first, "
                      "platform code, or an explicitly unsupported boundary."}


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

def _git_run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.quotePath=false", "-C", str(root), *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)


def _resolve_base(root: Path, base: str) -> str:
    """A commit-ish only: never let a caller-supplied value reach git as an option."""
    if not base or base.startswith("-") or any(c in base for c in "\0\n"):
        raise ValueError(f"Invalid base revision: {base!r}")
    result = _git_run(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}")
    if result.returncode and base == "HEAD" and not _git_run(root, "symbolic-ref", "--quiet", "HEAD").returncode:
        # a branch with no commits yet (the first commit): everything is new, so compare with the empty tree
        empty = subprocess.run(["git", "-C", str(root), "hash-object", "-t", "tree", "--stdin"], input=b"",
                               capture_output=True, timeout=60)
        if not empty.returncode:
            return empty.stdout.decode().strip()
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


def expand_paths(root: Path, paths: list[str]) -> list[str]:
    """Repo-relative files for paths given as files or folders (./, absolute or cwd-relative spellings too).
    A path that does not exist is an error, not an empty answer."""
    out, missing = [], []
    for value in paths:
        rel = _normalize(root, value)
        path = root / rel
        if path.is_dir():
            for directory, folders, names in os.walk(path):
                folders[:] = sorted(d for d in folders if not d.startswith(".") and d != "build")
                out.extend((Path(directory) / name).relative_to(root).as_posix() for name in sorted(names))
        elif path.is_file():
            out.append(rel)
        else:
            missing.append(value)
    if missing:
        raise ValueError(f"No such file or folder in {root}: {', '.join(missing)}")
    return list(dict.fromkeys(out))


_DECLARATIONS: dict[str, tuple[tuple, dict[str, list[str]]]] = {}


def _declared(header: Path) -> dict[str, list[str]]:
    """name -> the comment block and line of every `name(` in a header (cached per file stamp)."""
    from .cxx import comment_start
    stamp = _file_stamp(header)
    cached = _DECLARATIONS.get(str(header))
    if cached and cached[0] == stamp:
        return cached[1]
    lines = header.read_text(encoding="utf-8", errors="replace").splitlines() if stamp else []
    found: dict[str, list[str]] = collections.defaultdict(list)
    for index, line in enumerate(lines):
        for name in set(re.findall(r"~?\b([A-Za-z_]\w*)\s*\(", line)):
            found[name].extend(lines[comment_start(lines, index):index + 1])
    _DECLARATIONS[str(header)] = (stamp, dict(found))
    return _DECLARATIONS[str(header)][1]


def _companion_declarations(root: Path, rel: str, name: str) -> str:
    """Comment blocks and lines declaring `name` (Class::method or a free function) in the source's own header
    (X.cpp -> X.hpp/X.h): a port often cites the original at the declaration instead of the definition."""
    method = name.rsplit("::", 1)[-1].lstrip("~")
    stem = root / rel.rsplit(".", 1)[0]
    return "\n".join(line for suffix in HEADER_SUFFIXES
                     for line in _declared(Path(f"{stem}{suffix}")).get(method, []))


CHECK_HELP = {
    "hold-until-clean": "a citation claims the behavior follows that original, but its decomp is not ready: match "
                        "and clean it in the decomp first (`port-plan` lists why), or mark the behavior explicitly "
                        "unsupported; never port a guess",
    "hold-existing": "the replaced lines already cited this not-ready original: debt, not new",
    "citation-missing": "a new exact/equivalent-tier function with no original address: cite the original, or "
                        "mark it with the repo's citation_exempt marker",
    "citation-unresolved": "the address is no function or symbol of the target: a typo, a flag constant, or a "
                           "stale address",
    "include-boundary": "an include crosses one of the repo's architecture rules (reason shown)",
    "constant-near-miss": "check `zkit asm` first: folded arithmetic or rounding can be the real cause; do not just "
                          "copy the value",
}


def check(project: Project, repo: str, base: str = "HEAD", paths: list[str] | None = None,
          target: str | None = None, staged: bool = False) -> dict:
    """Lint the working-tree change of one repository against its contract rules.

    Rules come from the repository's manifest `checks` block (and `architecture` rules, `quality` for a
    decomp), so another project configures its own. Only added/changed lines are judged (all lines of files given
    as paths); a violation that the same hunk already had before the edit is reported as debt, not an error.
    Without a target (no original configured) citations are not judged."""
    target = default_target(project, target) if project.config.get("targets") else None
    refresh(project, [repo])
    db = connect(project)
    root = project.root(repo)
    config = project.config["repositories"][repo]
    rules = config.get("checks", {})
    from .index import platform as active_platform
    address = re.compile(config.get("address_pattern", active_platform().cite_pattern()))
    if paths is None:
        hunks = _diff_hunks(root, base, staged)
        changed = {p: (None if h is None else set().union(*[x[0] for x in h]) if h else set()) for p, h in hunks.items()}
    else:
        hunks = {}
        changed = {rel: None for rel in expand_paths(root, paths)}
    texts = {rel: _content(root, rel, staged) for rel in changed}
    scope = [re.compile(x) for x in rules.get("source_globs", [r"^src/.*\.(cpp|hpp|h|cc)$"])]
    forbidden = [(re.compile(r["pattern"]), r["message"], re.compile(r.get("paths", ".*")))
                 for r in rules.get("forbidden", [])]
    findings = []
    stats = collections.Counter()
    from .tiers import tier_of
    native = config.get("role") == "native"
    hold = rules.get("hold_rule", "error")  # citing decomp that is not ready: error, warning or off
    ready_cache: dict[int, dict] = {}
    found_cache: dict[int, Any] = {}

    def function_at(value: int):
        if value not in found_cache:
            found_cache[value] = containing(db, target, value)
        return found_cache[value]

    def resolves(value: int) -> bool:
        return function_at(value) is not None or _symbol_lookup(project, target, value) is not None

    def cited_functions(lines: list[str]) -> set[int]:
        return {row["address"] for text in lines for m in address.finditer(text)
                for row in [function_at(active_platform().cite_value(m.group(1)))] if row}

    decomp_gate = None
    if config.get("role") == "decomp":
        from . import quality
        quality_config = config.get("quality", {})
        decomp_gate = quality_config.get("gate", "warning")
        catalog = quality.patterns(project, repo)
        roots, exclude = quality._paths(project, repo, None)
    for rel, added in sorted(changed.items()):
        if texts.get(rel) is None:
            continue
        text_lines = texts[rel].splitlines()
        if decomp_gate and decomp_gate != "off" and quality._keep(rel, exclude) and any(
                rel == r or rel.startswith(r.rstrip("/") + "/") for r in roots):
            removed_text = "\n".join(old for lines_added, removed in (hunks.get(rel) or []) for old in removed)
            header = Path(rel).suffix.lower() in quality.HEADER_SUFFIXES
            had = quality.count(removed_text, catalog, header=header)
            externs = collections.defaultdict(list)   # read against the whole file: a forward declaration is fine
            if not header and any(p.key == "extern_c" for p in catalog):
                label = next(p.label for p in catalog if p.key == "extern_c")
                for number, name in quality.extern_c_debt(texts[rel]):
                    externs[number].append({"key": "extern_c", "label": label, "text": f'extern "C" {name}'})
            for number, line in enumerate(text_lines, 1):
                if added is not None and number not in added:
                    continue
                for found in quality.findings(line, catalog, header=header, skip=("extern_c",)) + externs[number]:
                    stats["debt_added"] += 1
                    old = had[found["key"]] > 0
                    if old:
                        had[found["key"]] -= 1
                    findings.append({"severity": "info" if old else decomp_gate, "rule": "decomp-debt" if old
                                     else "decomp-debt-added", "ref": f"{rel}:{number}",
                                     "message": ("carried over from the replaced lines: " if old else "adds ")
                                     + found["label"], "line": found["text"]})
        tier = tier_of(project, repo, rel) if native else "exact"
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
        if not any(s.search(rel) for s in scope) or target is None:
            continue
        stats["files"] += 1
        replaced: dict[int, set[int]] = {}  # id(removed lines) -> functions they cited
        for number, line in enumerate(text_lines, 1):
            if not wanted(number):
                continue
            for match in address.finditer(line):
                value = active_platform().cite_value(match.group(1))
                stats["citations"] += 1
                row = function_at(value)
                if row is None:
                    if _symbol_lookup(project, target, value) is None and rules.get("resolve_citations", True):
                        findings.append({"severity": "warning", "rule": "citation-unresolved",
                                         "ref": f"{rel}:{number}", "address": address_text(value),
                                         "message": "not a function or symbol of the target"})
                    continue
                info = _status(row)
                if native and hold != "off":  # every tier: a citation claims behavior follows that original
                    if row["address"] not in ready_cache:
                        ready_cache[row["address"]] = readiness(project, target, row)
                    ready = ready_cache[row["address"]]
                    if not ready["ready"]:
                        removed = removed_by_line.get(number, [])
                        if id(removed) not in replaced:
                            replaced[id(removed)] = cited_functions(removed)
                        carried = row["address"] in replaced[id(removed)]
                        stats["hold_existing" if carried else "not_ready_citations"] += 1
                        findings.append({"severity": "info" if carried else hold,
                                         "rule": "hold-existing" if carried else "hold-until-clean",
                                         "ref": f"{rel}:{number}", "address": info["address"],
                                         "name": info["demangled"] or info["name"],
                                         "message": "decomp not ready: " + "; ".join(ready["reasons"])})
                elif not info["exact"]:
                    findings.append({"severity": "info", "rule": "citation-unmatched", "ref": f"{rel}:{number}",
                                     "address": info["address"], "name": info["demangled"] or info["name"],
                                     "message": f"cited decomp function is {status_word(info)}; its semantics "
                                                "are unverified"})
                if match.group(0).lower().startswith("0x") and rules.get("bare_citations"):
                    findings.append({"severity": "warning", "rule": "citation-format", "ref": f"{rel}:{number}",
                                     "message": rules["bare_citations"]})
        if rules.get("require_citation") and rel.endswith((".cpp", ".cc", ".cxx", ".c")):
            from .cxx import comment_start, definitions
            exempt = rules.get("citation_exempt")
            for definition in definitions(texts[rel]):
                if not any(wanted(n + 1) for n in range(definition.start, definition.open + 1)):
                    continue
                stats["new_definitions"] += 1
                if tier not in ("exact", "equivalent"):
                    continue  # liberty/infrastructure code has no original to cite
                if definition.end - definition.line < rules.get("citation_min_lines", 6):
                    continue  # trivial accessors/constructors need no citation of their own
                nearby = "\n".join(text_lines[comment_start(text_lines, definition.start):definition.end + 1])
                nearby += "\n" + _companion_declarations(root, rel, definition.name)
                cited = any(resolves(active_platform().cite_value(m.group(1))) for m in address.finditer(nearby))
                if not cited and not (exempt and re.search(exempt, nearby)):
                    findings.append({"severity": "warning" if tier == "exact" else "info",
                                     "rule": "citation-missing", "ref": f"{rel}:{definition.line + 1}",
                                     "name": definition.name,
                                     "message": f"new {tier}-tier function with no original address"})
    if native and config.get("architecture", {}).get("rules"):
        findings += _include_findings(project, repo, changed, hunks, texts, stats)
    if native and target is not None:
        findings += _constant_findings(project, repo, changed, scope, target, stats)
    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["rule"], f.get("address", ""), f["ref"]))
    return {"repo": repo, "base": base, "worktree": project.worktree(repo), "stats": dict(stats),
            "findings": findings, "ok": not any(f["severity"] == "error" for f in findings),
            "help": {rule: CHECK_HELP[rule] for rule in dict.fromkeys(f["rule"] for f in findings) if rule in CHECK_HELP}}


def _include_findings(project: Project, repo: str, changed: dict, hunks: dict, texts: dict, stats) -> list[dict]:
    """Architecture include rules on the changed lines; an include the replaced lines already had is debt."""
    from .architecture import audit
    files = [rel for rel, text in texts.items() if text is not None]
    if not files:
        return []
    result = audit(project, repo, files)
    out = []
    for finding in result["findings"]:
        rel, _, number = finding["reference"].removeprefix(f"{repo}:").rpartition(":")
        added = changed.get(rel)
        if added is not None and int(number) not in added:
            continue
        removed = next((r for lines, r in (hunks.get(rel) or []) if int(number) in lines), [])
        carried = any(finding["include"] in old and "include" in old for old in removed)
        stats["include_debt" if carried else "include_violations"] += 1
        out.append({"severity": "info" if carried else "error",
                    "rule": "include-boundary-existing" if carried else "include-boundary",
                    "ref": f"{rel}:{number}", "name": finding["rule"],
                    "message": f"#include {finding['include']}: {finding['reason']}", "line": finding["include"]})
    return out


def _constant_findings(project: Project, repo: str, changed: dict, scope: list, target: str, stats) -> list[dict]:
    from .fidelity import constant_audit
    from .index import platform as active_platform
    scoped = {rel: added for rel, added in changed.items() if any(g.search(rel) for g in scope)}
    if not scoped:
        return []
    if active_platform().name != "gamecube":
        return [{"severity": "info", "rule": "constants-skipped", "ref": repo,
                 "message": "the constant audit decodes PowerPC loads; it does not run for this platform"}]
    try:
        audit = constant_audit(project, repo, None, target, only_lines=scoped)["findings"]
    except (OSError, ValueError) as error:  # e.g. no original DOL on this machine: lint the rest anyway
        return [{"severity": "info", "rule": "constants-skipped", "ref": repo,
                 "message": f"constant audit unavailable: {error}"}]
    out = []
    for f in audit:
        if f["tier"] not in ("exact", "equivalent"):
            continue
        if f["kind"] == "near":
            stats["near_constants"] += 1
            out.append({"severity": f["severity"], "rule": "constant-near-miss", "ref": f["ref"],
                        "message": f"{f['value']} is within 2% of original constant(s) {f['near']} the cited code "
                                   "loads", "line": f["line"]})
        elif f["kind"] == "folded":
            stats["folded_constants"] += 1
            out.append({"severity": "warning", "rule": "constant-folded", "ref": f["ref"],
                        "message": f"{f['value']} equals {f['folded']} of constants the cited code loads separately: "
                                   "if the original computes it at run time, keep the operations (float rounding "
                                   "differs)", "line": f["line"]})
        elif f["tier"] == "exact":
            stats["unsourced_constants"] += 1
            out.append({"severity": "info", "rule": "constant-unsourced", "ref": f["ref"],
                        "message": f"{f['value']} is not loaded by any cited original: cite the function/data it "
                                   "comes from, or mark it native", "line": f["line"]})
    return out


# ----------------------------------------------------------------------------
# Reuse: find what already exists before writing another copy.

def variant_terms(project: Project, variants: str | None, terms: str | list[str] | None) -> list[str] | None:
    """Sibling names for reuse: explicit terms (comma separated), or a manifest `variants` group by name."""
    if terms:
        return [t.strip() for t in (terms.split(",") if isinstance(terms, str) else terms) if t.strip()]
    if not variants:
        return None
    groups = project.config.get("variants", {})
    if variants not in groups:
        raise ValueError(f"No variant group {variants!r} in the manifest; configured: {', '.join(groups) or 'none'} "
                         "(or pass terms)")
    return groups[variants]


def reuse(project: Project, repo: str, terms: list[str] | None = None, min_files: int = 3, limit: int = 25) -> dict:
    """Two views of missing sharing in one repository.

    duplicates: the same small free function (name + body without comments) defined in several files, which
      should be one shared function; the same body over different parameter types is a template or interface
      candidate instead.
    enumerations: files that name several sibling variants together (for example enemy families). These are
      the central dispatch sites a new variant must edit; a growing list means the variant is not data-driven.
    """
    from .cxx import definitions
    refresh(project, [repo])
    root = project.root(repo)
    config = project.config["repositories"][repo]
    globs = [re.compile(x) for x in config.get("checks", {}).get("source_globs", [r"^src/.*\.(cpp|hpp|h|cc)$"])]
    defs: dict[tuple[str, str], list[tuple[str, str]]] = collections.defaultdict(list)
    by_name: dict[str, set[str]] = collections.defaultdict(set)
    sites = []
    term_res = [(t, re.compile(rf"\b{re.escape(t)}", re.I)) for t in (terms or [])]
    needed = min(len(term_res), 3)  # files naming this many of the variants (all of them when fewer than 3)
    db = connect(project)
    files = [r[0] for r in db.execute("SELECT path FROM files WHERE repo=?", (repo,))]
    for rel in sorted(files):
        if not any(g.search(rel) for g in globs):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if term_res:
            hit = sorted({t for t, r in term_res if r.search(text)})
            if len(hit) >= needed:
                sites.append({"path": rel, "variants": hit, "count": len(hit)})
        for definition in definitions(text):
            if definition.in_class or "::" in definition.name or definition.name in ("main",) \
                    or definition.name.startswith("operator") or definition.end - definition.line > 40:
                continue
            defs[(definition.name, definition.body)].append((f"{rel}:{definition.line + 1}", definition.params))
            by_name[definition.name].add(rel)
    duplicates = []
    for (name, _), places in defs.items():
        if len({p.rsplit(":", 1)[0] for p, _ in places}) < min_files:
            continue
        types = {params for _, params in places}
        duplicates.append({"name": name, "copies": len(places), "places": [p for p, _ in places][:8],
                           "kind": "identical" if len(types) == 1 else "same body, different parameter types",
                           "signatures": sorted(types)[:4]})
    duplicates.sort(key=lambda d: (-d["copies"], d["name"]))
    same_name = [{"name": n, "files": len(f), "examples": sorted(f)[:5]}
                 for n, f in by_name.items() if len(f) >= min_files + 2]
    same_name.sort(key=lambda d: (-d["files"], d["name"]))
    sites.sort(key=lambda s: (-s["count"], s["path"]))
    return {"repo": repo, "identical_helpers": duplicates[:limit],
            "same_name_helpers": same_name[:limit],
            "enumeration_sites": {"terms": terms or [], "needed": needed, "files": len(sites), "rows": sites[:limit]},
            "limits": "Textual: free functions up to 40 lines with the same name and body (comments and spacing "
                      "ignored), and files naming several variants. Candidates for sharing, not proof that sharing "
                      "is correct; a family boundary the design documents is a reason to keep copies."}


# ----------------------------------------------------------------------------
# References in source: where a function or global is defined, declared and used.

def refs(project: Project, query: str, target: str | None = None, repo: str | None = None,
         limit: int = 60) -> dict[str, Any]:
    """Every source line that spells a function or data symbol (mangled name, Class::method, the bare method name
    beside its class, or the address in a placeholder name), classified as definition, declaration or use."""
    target = default_target(project, target) if project.config.get("targets") else None
    repos = [repo] if repo else list(project.config["repositories"])
    spellings: set[str] = set()
    function = None
    if target:
        refresh(project)
        db = connect(project)
        found = resolve(project, query, target, limit=2)
        if len(found) == 1:
            row = containing(db, target, found[0])
            if row is not None:
                function = _status(row)
                spellings.add(row["name"])
                base = (row["demangled"] or "").split("(")[0].strip()
                if base:
                    spellings.add(base)
                    spellings.add(base.rsplit("::", 1)[-1])
            else:
                symbol = _symbol_lookup(project, target, found[0])
                if symbol:
                    spellings.add(symbol["name"])
            spellings.add(address_text(found[0])[2:] if found[0] < 1 << 32 else f"{found[0] & 0xFFFFFFFF:X}")
    if not spellings:
        spellings.add(query.strip())
    method = next((s.rsplit("::", 1)[-1] for s in spellings if "::" in s), None)
    owner = next((s.rsplit("::", 1)[0].rsplit("::", 1)[-1] for s in spellings if "::" in s), None)
    rows, total = [], 0
    for name in repos:
        config = project.config["repositories"][name]
        root = project.root(name)
        paths = config.get("index_paths", config.get("search_paths", []))
        if not paths:
            continue
        args = ["grep", "-n", "-I", "--no-color", "-F"] + [x for s in sorted(spellings) for x in ("-e", s)] + ["--", *paths]
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=60)
        for line in result.stdout.splitlines():
            path, _, rest = line.partition(":")
            number, _, text = rest.partition(":")
            words = set(re.findall(r"[A-Za-z_~][\w:~]*|[0-9A-Fa-f]{8,16}", text))
            hit = [s for s in spellings if s in words or any(w.endswith(s) and s[:1].isdigit() for w in words)
                   or s in text and "::" in s]
            if not hit:
                continue
            if method and hit == [method] and owner and owner not in text and "->" not in text and "." not in text:
                continue  # the bare method name, with no sign of its class: another class's member
            total += 1
            stripped = text.strip()
            kind = "use"
            if re.search(r"\)\s*(const\s*)?\{?\s*$", stripped) and not stripped.endswith(";") and \
                    not re.match(r"(if|while|for|switch|return)\b", stripped):
                kind = "definition"
            elif stripped.endswith(";") and re.search(r"\w[\w\s\*&:<>,]*\s+[\w:~]+\s*\([^)]*\)\s*(const\s*)?;$", stripped) \
                    and "=" not in stripped and "return" not in stripped:
                kind = "declaration"
            if len(rows) < limit:
                rows.append({"ref": f"{name}:{path}:{number}", "kind": kind, "text": stripped[:200]})
    order = {"definition": 0, "declaration": 1, "use": 2}
    rows.sort(key=lambda r: (order[r["kind"]], r["ref"]))
    return {"query": query, "function": function, "spellings": sorted(spellings), "rows": rows, "total": total,
            "limits": "Text matches in tracked files (git grep), classified by line shape. Calls through pointers, "
                      "macros and vtables are not seen; `lookup` lists the original's direct callers."}


# ----------------------------------------------------------------------------
# Compiled objects against the original's split objects.

def compiled(project: Project, query: str, target: str | None = None, limit: int = 24) -> dict[str, Any]:
    """A function's compiled bytes and relocations against the original's, from the unit's objects in objdiff.json;
    a unit name (or its source path) gives every function of the unit. Several queries give a batch."""
    from . import objects
    target = default_target(project, target)
    refresh(project)
    queries = query_list(query)
    if len(queries) > 1:
        return batch(queries, lambda q: compiled(project, q, target, limit))
    query = queries[0] if queries else query
    db = connect(project)
    units = objects.objdiff_units(project, target)
    root = project.root(project.target(target)["repository"])
    named = query.strip("/")
    by_source = {(u.get("metadata") or {}).get("source_path"): n for n, u in units.items()}
    name = query if query in units else next((n for n in units if n.endswith("/" + named)), None) or by_source.get(named)
    if name:
        unit = units[name]
        if not unit.get("base_path"):
            raise ValueError(f"Unit {name} has no compiled object in objdiff.json (no source for it yet)")
        if not (root / unit["base_path"]).is_file() or not (root / unit["target_path"]).is_file():
            raise ValueError(f"{unit['base_path']} or {unit['target_path']} is not built yet: build the project first")
        data = objects.unit_diff(root / unit["target_path"], root / unit["base_path"])
        data["unit"] = name
        return data | _compiled_age(root, unit)
    found = resolve(project, query, target, limit=2)
    if len(found) != 1:
        raise ValueError(f"{query} names {'no' if not found else 'more than one'} function; use an address, or a unit "
                         "name or source path")
    row = containing(db, target, found[0])
    if row is None or not row["unit"]:
        raise ValueError(f"{query} is not a function of any objdiff unit")
    unit = units.get(row["unit"])
    if not unit or not unit.get("base_path"):
        raise ValueError(f"Unit {row['unit']} has no compiled object yet (no source, or not built)")
    target_path, base_path = root / unit["target_path"], root / unit["base_path"]
    if not base_path.is_file():
        raise ValueError(f"{unit['base_path']} is not built yet: build the project first")
    data = objects.function_diff(target_path, base_path, row["name"], limit=limit)
    data.update(unit=row["unit"], address=address_text(row["address"]), report_match=row["match"])
    if data.get("missing"):
        data["message"] = (f"the compiled object defines no function {row['name']}: not written yet, or written "
                           "under another name or signature")
    if not data.get("exact") and not data.get("missing"):
        data["original_asm"] = objects.disassembly(project, target, target_path, row["name"], data["machine"])
        data["compiled_asm"] = objects.disassembly(project, target, base_path, row["name"], data["machine"])
    return data | _compiled_age(root, unit)


def _compiled_age(root: Path, unit: dict) -> dict:
    """A note when the compiled object is older than the unit's source (the answer is about the last build)."""
    source = (unit.get("metadata") or {}).get("source_path")
    try:
        if source and (root / source).stat().st_mtime > (root / unit["base_path"]).stat().st_mtime:
            return {"stale": f"{unit['base_path']} is older than {source}: this compares the last build; rebuild"}
    except OSError:
        pass
    return {}
