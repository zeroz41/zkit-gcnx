"""Find native behavior that is probably slightly off, and say when to go back.

grounding Per folder and per native unit (a source file with its own header): how many of the original
          functions it cites are byte-exact and ready references in the decomp (bridge.readiness), its constants,
          whether a test program compiles or links it and a fidelity recipe cites its originals -> one ranked
          list with the next action. Exact-tier units that cite no original at all are a signal of their own.
consts    Every float literal inside a native function that cites original functions (at the definition or at
          its declaration in the unit's header) is compared with the constants those originals (and their direct
          callees) load (lfs/lfd/psq_l via r2/r13 or lis+offset) and with cited data words. verified = found,
          after folding literal arithmetic such as 65536.0F/360.0F; folded = equals two loaded constants
          combined; near = within 2% of one; unsourced = loaded by no cited original. GameCube only: the loads are
          decoded from PowerPC code.
drift     Remembers the decomp state of every cited function (match, name, readiness, body hash) and reports
          what changed since: newly exact or ready, regressed, body edited. Those are the moments native code
          written against the old state must be re-verified.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .activity import state_dir
from .bridge import (_companion_declarations, _is_code, _normalize, _status, default_target, expand_paths, readiness,
                     role_repos)
from .gc import direct_calls, track_addresses
from .index import address_text, connect, containing, is_dol_unit, refresh
from .project import Project, under as _under

NUMBER = r"(?:\d+\.\d*(?:[eE][-+]?\d+)?|\d*\.\d+(?:[eE][-+]?\d+)?|\d+[eE][-+]?\d+)"
LITERAL = re.compile(rf"(?<![\w.])({NUMBER})[fF]?(?![\w.])")
FOLD = re.compile(rf"(?<![\w.])({NUMBER}[fF]?|\d+)\s*([*/+-])\s*({NUMBER}[fF]?|\d+)(?![\w.])")
TRIVIAL = {0.0, 1.0, 0.5, 2.0, 0.25, 10.0, 100.0}
PAIR_POOL = 120  # pools larger than this are not searched for two-constant combinations


def _cited(text: str) -> list[int]:
    """Original addresses cited in text, for the active platform."""
    from .index import platform
    current = platform()
    return [current.cite_value(a) for a in re.findall(current.cite_pattern(), text)]


def _f32(value: float) -> float:
    try:
        return struct.unpack(">f", struct.pack(">f", value))[0]
    except (OverflowError, struct.error):
        return value


class Constants:
    """Float constants an original function loads, decoded from the DOL without a disassembler."""

    def __init__(self, project: Project, target: str):
        from .inspect_dol import _dol, sda_bases
        self.project, self.target = project, target
        self.dol = _dol(project, target)
        self.sda = sda_bases(project, target, self.dol)
        self.db = connect(project)
        self.cache: dict[int, set[float]] = {}

    def _own(self, start: int, size: int) -> set[float]:
        out = set()
        try:
            words = self.dol.words(start, size)
        except ValueError:  # a report function extending past its DOL section
            return out
        for pc, (address, kind) in track_addresses(words, start, self.sda).items():
            if kind not in ("f32", "f64", "psq"):
                continue
            try:
                if kind == "f64":
                    out.add(struct.unpack(">d", self.dol.read(address, 8))[0])
                else:
                    out.add(struct.unpack(">f", self.dol.read(address, 4))[0])
                    if kind == "psq":
                        out.add(struct.unpack(">f", self.dol.read(address + 4, 4))[0])
            except ValueError:
                pass
        return out

    def _data(self, address: int) -> set[float]:
        """Every f32 (and aligned f64) in the cited data object, e.g. a whole table."""
        from .bridge import _symbol_lookup
        if address in self.cache:
            return self.cache[address]
        symbol = _symbol_lookup(self.project, self.target, address)
        start = symbol["key"] if symbol else address
        size = min(max(symbol["size"], 4) if symbol else 4, 0x2000)
        out: set[float] = set()
        try:
            raw = self.dol.read(start, size - size % 4)
        except ValueError:
            raw = b""
        for offset in range(0, len(raw) - 3, 4):
            out.add(struct.unpack(">f", raw[offset:offset + 4])[0])
            if offset % 8 == 0 and offset + 8 <= len(raw):
                out.add(struct.unpack(">d", raw[offset:offset + 8])[0])
        self.cache[address] = {c for c in out if math.isfinite(c)}
        return self.cache[address]

    def of(self, address: int) -> set[float] | None:
        """Constants of the function containing address plus its direct callees; None if not code."""
        row = containing(self.db, self.target, address)
        if row is None:
            return self._data(address)
        if row["address"] not in self.cache:
            pool = self._own(row["address"], row["size"])
            for _, callee in direct_calls(self.dol, row["address"], row["size"]):
                other = containing(self.db, self.target, callee)
                if other and other["size"] < 0x2000:
                    pool |= self._own(other["address"], other["size"])
            self.cache[row["address"]] = {c for c in pool if math.isfinite(c)}
        return self.cache[row["address"]]


CONSTANT_DECL = re.compile(r"\bconstexpr\b|\bconst\s+(?:float|double|f32|f64)\b")


def _constant_blocks(lines: list[str], inside: set[int]):
    """Constant declarations outside functions: a `constexpr`/`const float` line plus its comment block."""
    for i, line in enumerate(lines):
        if i in inside or not CONSTANT_DECL.search(line) or not LITERAL.search(line.split("//")[0]):
            continue
        lo = i
        while lo > 0 and lines[lo - 1].strip().startswith(("//", "/*", "*")):
            lo -= 1
        yield lo, i, i, ""


def _is_power_of_two(value: float) -> bool:
    return value > 0 and math.log2(value).is_integer()


def _same(a: float, b: float) -> bool:
    return math.isclose(_f32(a), _f32(b), rel_tol=1e-6, abs_tol=1e-12)


def _folds(code: str) -> list[tuple[int, int, float]]:
    """(start, end, value) of `literal op literal` expressions whose operator binds them (C precedence), evaluated
    in float when either side is float-suffixed, as the compiler folds them."""
    out = []
    for match in FOLD.finditer(code):
        left, op, right = match[1], match[2], match[3]
        before = code[:match.start()].rstrip()[-1:]
        after = code[match.end():].lstrip()[:1]
        if before in ("*", "/", "%") or (op in "+-" and (before in ("+", "-") or after in ("*", "/", "%"))):
            continue
        single = left[-1] in "fF" or right[-1] in "fF"
        a, b = float(left.rstrip("fF")), float(right.rstrip("fF"))
        if single:
            a, b = _f32(a), _f32(b)
        if op == "/" and b == 0:
            continue
        value = {"*": a * b, "/": a / b if b else 0.0, "+": a + b, "-": a - b}[op]
        out.append((match.start(), match.end(), _f32(value) if single else value))
    return out


_PAIRS: dict[frozenset, dict[float, str]] = {}


def _pairs(pool: set[float]) -> dict[float, str]:
    """f32 value -> `a op b` for every two non-trivial constants of a pool (cached per pool)."""
    key = frozenset(pool)
    if key not in _PAIRS:
        values = sorted(c for c in pool if c not in (0.0, 1.0, -1.0) and math.isfinite(c))
        found: dict[float, str] = {}
        if len(values) <= PAIR_POOL:
            for a in values:
                for b in values:
                    for op, value in (("*", a * b), ("/", a / b), ("+", a + b), ("-", a - b)):
                        if value and math.isfinite(value):
                            found.setdefault(_f32(value), f"{a:g}{op}{b:g}")
        _PAIRS[key] = found
    return _PAIRS[key]


def constant_audit(project: Project, repo: str, paths: list[str] | None = None, target: str | None = None,
                   only_lines: dict[str, set[int] | None] | None = None) -> dict[str, Any]:
    from .cxx import comment_start, definitions
    from .index import platform
    from .tiers import tier_of
    target = default_target(project, target)
    if platform().name != "gamecube":
        raise ValueError("The constant audit decodes PowerPC loads from a GameCube executable; this target is "
                         f"{platform().name}")
    refresh(project, [repo])
    consts = Constants(project, target)
    root = project.root(repo)
    files = sorted(only_lines) if only_lines is not None else sorted(
        r[0] for r in connect(project).execute("SELECT path FROM files WHERE repo=?", (repo,))
        if r[0].endswith((".cpp", ".cc", ".hpp", ".h")) and _is_code(project, r[0]))
    if paths:
        wanted_files = set(expand_paths(root, paths))
        files = [f for f in files if f in wanted_files]
    counts, findings = collections.Counter(), []
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        tier = tier_of(project, repo, rel)
        if tier not in ("exact", "equivalent"):
            counts["not_judged_files"] += 1  # liberty/infrastructure: the owner's own values
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        wanted = (only_lines or {}).get(rel)
        blocks = [(comment_start(lines, d.start), d.line, d.end, d.name) for d in definitions(text)]
        inside = {n for lo, _, end, _ in blocks for n in range(lo, end + 1)}
        for lo, _, end, name in blocks + list(_constant_blocks(lines, inside)):
            block = lines[lo:end + 1]
            if not any(LITERAL.search(line) for line in block):
                continue
            cited = _cited("\n".join(block))
            if not cited and name:  # cited at the declaration in the unit's own header
                cited = _cited(_companion_declarations(root, rel, name))
            pool: set[float] = set()
            code_cites = 0
            for address in cited:
                found = consts.of(address)
                if found is not None:
                    pool |= found
                    code_cites += containing(consts.db, target, address) is not None
            for k, line_text in enumerate(block):
                number = lo + k + 1
                if wanted is not None and number not in wanted:
                    continue
                code = re.sub(r'"(?:\\.|[^"\\])*"', '""', re.sub(r"/\*.*?\*/", "", line_text)).split("//")[0]
                if not code_cites:
                    counts["uncited_literals"] += len(LITERAL.findall(code))
                    continue
                folded = [(s, e, v) for s, e, v in _folds(code) if any(_same(v, abs(c)) for c in pool)]
                for match in LITERAL.finditer(code):
                    if any(s <= match.start() < e for s, e, _ in folded):
                        counts["verified"] += 1  # part of literal arithmetic that folds to a loaded constant
                        continue
                    value = float(match.group(1))
                    counts["literals"] += 1
                    if value in TRIVIAL or _is_power_of_two(value) or (value.is_integer() and value < 4):
                        counts["trivial"] += 1
                        continue
                    if any(_same(value, abs(c)) for c in pool):
                        counts["verified"] += 1
                        continue
                    pair = _pairs(pool).get(_f32(value))
                    near = sorted({abs(c) for c in pool if c and abs(value - abs(c)) / abs(c) < 0.02})
                    kind = "folded" if pair else "near" if near else "unsourced"
                    counts[kind] += 1
                    findings.append({
                        "kind": kind, "ref": f"{rel}:{number}", "value": value, "near": near[:3],
                        "folded": pair, "pool_size": len(pool), "tier": tier, "gameplay": tier == "exact",
                        "severity": "warning" if kind in ("near", "folded") else "info",
                        "line": line_text.strip()[:140]})
    order = {"near": 0, "folded": 1, "unsourced": 2}
    findings.sort(key=lambda f: (order[f["kind"]], f["tier"] != "exact", f["ref"]))
    return {"repo": repo, "counts": dict(counts), "findings": findings,
            "scope": "exact and equivalent tiers only; liberty/infrastructure values are the owner's",
            "meaning": "verified = the literal (or literal arithmetic folded as the compiler does) is a constant the "
                       "cited original or a direct callee loads. folded = it equals two loaded constants combined: "
                       "if the original computes it at run time, keep the operations (float rounding). near = within "
                       "2% of one: likely a transcription slip unless intentional. unsourced = loaded by no cited "
                       "original: derived, from an uncited callee, or invented. uncited_literals are in functions "
                       "that cite no original (at the definition or its header declaration) and are not judged."}


# ----------------------------------------------------------------------------

UNIT_SOURCES = (".cpp", ".cc", ".cxx", ".c")
UNIT_HEADERS = (".hpp", ".h", ".hh", ".hxx", ".inl")


def _unit(rel: str) -> str:
    """A native source and its own header are one unit, keyed by the path without suffix."""
    return rel.rsplit(".", 1)[0] if rel.endswith(UNIT_SOURCES + UNIT_HEADERS) else rel


def _tested_units(project: Project, repo: str) -> set[str] | None:
    """Units a test program compiles or links (build.ninja link closures of executables built from a test
    source), plus headers a test source reaches within two include levels; None without a test build."""
    from .native import IncludeGraph, _companions, link_closures
    config = project.config["repositories"][repo].get("tests")
    if not config:
        return None
    root = project.root(repo)
    build = root / config.get("build_dir", "build")
    if not (build / "compile_commands.json").is_file():
        return None
    test_prefix = tuple(config.get("test_paths", ["tests/"]))
    reached: set[str] = set()
    tests = []
    for sources in link_closures(build, root).values():
        if any(s.startswith(test_prefix) for s in sources):
            reached |= sources
            tests.extend(s for s in sources if s.startswith(test_prefix))
    graph = IncludeGraph(root, config.get("include_roots", ["src", "tests", "."]), config.get("scan", ["src", "tests"]))
    known = set(graph.files)
    includes: dict[str, set[str]] = collections.defaultdict(set)
    for child, parents in graph.includers.items():
        for parent in parents:
            includes[parent].add(child)
    if not tests:  # no Ninja link graph: the compiled test sources themselves
        from .native import _targets
        tests = [s for s in _targets(build, root) if s.startswith(test_prefix)]
    frontier = set(tests)
    for _ in range(2):
        frontier = {c for node in frontier for child in includes.get(node, ()) for c in _companions(child, known)}
        reached |= frontier
    return {_unit(rel) for rel in reached}


def grounding(project: Project, repo: str, paths: list[str] | None = None, target: str | None = None,
              limit: int = 25, detail: bool = True) -> dict[str, Any]:
    """How much of the original behavior a native port rests on is a usable reference, per folder and per unit,
    and the units most likely to behave slightly off, ranked, each with the next action. detail=False skips the
    constant audit, tests and recipes (the brief's summary)."""
    from .tiers import WEIGHT, tier_of
    target = default_target(project, target)
    refresh(project, [repo])
    db = connect(project)
    root = project.root(repo)
    config = project.config["repositories"][repo]
    code_prefix = tuple(config.get("code_paths", ["src/"]))
    notes = []
    if paths:
        expand_paths(root, paths)  # a path that does not exist is an error
        prefixes = tuple(_normalize(root, p).rstrip("/") for p in paths)
        outside = [p for p in prefixes if not any(_under(p, [c]) or c.startswith(p + "/") for c in code_prefix)]
        if outside:
            notes.append(f"outside code_paths ({', '.join(code_prefix)}): {', '.join(outside)} — not ported code, "
                         "not judged")
    else:
        prefixes = tuple(c.rstrip("/") for c in code_prefix)
    in_scope = lambda rel: rel.startswith(code_prefix) and _under(rel, prefixes)
    rows = db.execute("SELECT address, path FROM cites WHERE repo=?", (repo,)).fetchall()
    function_of: dict[int, Any] = {}
    ready_of: dict[int, dict] = {}
    units: dict[str, dict] = collections.defaultdict(lambda: {"files": set(), "functions": set(), "cites": 0,
                                                               "not_function": 0})
    for address, path in rows:
        if not in_scope(path):
            continue
        if address not in function_of:
            function_of[address] = containing(db, target, address)
        unit = units[_unit(path)]
        unit["files"].add(path)
        unit["cites"] += 1
        row = function_of[address]
        if row is None:
            unit["not_function"] += 1
            continue
        unit["functions"].add(row["address"])
        if row["address"] not in ready_of:
            ready_of[row["address"]] = readiness(project, target, row) | {"info": _status(row)}
    tier = {key: tier_of(project, repo, sorted(u["files"])[0]) for key, u in units.items()}

    def score(functions: set[int], cites: int, not_function: int) -> dict:
        n = len(functions)
        exact = sum(ready_of[f]["info"]["exact"] for f in functions)
        ready = sum(ready_of[f]["ready"] for f in functions)
        named = sum(not any(r.startswith("placeholder") for r in ready_of[f]["reasons"]) for f in functions)
        pct = lambda k: round(100 * k / n, 1) if n else None
        reasons = collections.Counter(r.split(" (")[0] for f in functions for r in ready_of[f]["reasons"]
                                      if r != "not byte-exact")
        return {"cites": cites, "functions": n, "exact": exact, "ready": ready, "named": named,
                "unmatched": n - exact, "not_function": not_function, "exact_pct": pct(exact),
                "ready_pct": pct(ready), "named_pct": pct(named), "top_reasons": reasons.most_common(3)}

    total = score(set().union(*(u["functions"] for u in units.values())) if units else set(),
                  sum(u["cites"] for u in units.values()), sum(u["not_function"] for u in units.values()))
    folders: dict[str, dict] = collections.defaultdict(lambda: {"functions": set(), "cites": 0, "not_function": 0})
    for key, unit in units.items():
        folder = folders[str(Path(key).parent)]
        folder["functions"] |= unit["functions"]
        folder["cites"] += unit["cites"]
        folder["not_function"] += unit["not_function"]
    folder_rows = sorted(({"folder": k, "tier": tier_of(project, repo, k + "/x.cpp"),
                           **score(v["functions"], v["cites"], v["not_function"])} for k, v in folders.items()),
                         key=lambda r: (r["ready_pct"] if r["ready_pct"] is not None else 101, -r["functions"]))
    result: dict[str, Any] = {"repo": repo, "scope": list(prefixes), "notes": notes, "total": total,
                              "units_with_cites": len(units), "folders": folder_rows[:limit]}
    if not detail:
        return result
    per_const: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    try:
        for f in constant_audit(project, repo, list(paths) if paths else None, target)["findings"]:
            per_const[_unit(f["ref"].rsplit(":", 1)[0])][f["kind"]] += 1
    except (OSError, ValueError) as error:  # no original executable here, or not a GameCube target
        notes.append(f"constants not judged: {error}")
    recipes = {name: c["recipes"].rstrip("/") + "/" for name, c in project.config["repositories"].items()
               if c.get("recipes")}
    recipe_functions = set()
    if recipes:
        for (address,) in db.execute("SELECT address FROM cites WHERE " + " OR ".join(
                "(repo=? AND path LIKE ?)" for _ in recipes), [x for n, d in recipes.items() for x in (n, d + "%")]):
            row = containing(db, target, address)
            if row:
                recipe_functions.add(row["address"])
    tested = _tested_units(project, repo)
    ranked = []
    for key, unit in units.items():
        if tier[key] not in ("exact", "equivalent"):
            continue  # liberty/infrastructure behavior is the owner's design, not a fidelity suspect
        functions = unit["functions"]
        n = max(len(functions), 1)
        unmatched = [f for f in functions if not ready_of[f]["info"]["exact"]]
        unready = [f for f in functions if ready_of[f]["info"]["exact"] and not ready_of[f]["ready"]]
        consts = per_const.get(key, collections.Counter())
        covered = (key in tested) if tested is not None else None
        has_recipe = bool(functions & recipe_functions) if recipe_functions else None
        value = 3 * len(unmatched) / n + 2 * len(unready) / n + min(consts["near"], 3) + min(consts["folded"], 3) \
            + 0.5 * min(consts["unsourced"], 4) + (1 if covered is False else 0) + (0.5 if has_recipe is False else 0)
        value = round(value * WEIGHT.get(tier[key], 1.0), 2)
        if not value:
            continue
        reasons = collections.Counter(r.split(" (")[0] for f in unready for r in ready_of[f]["reasons"])
        actions = []
        if unmatched:
            actions.append(f"decompile-first: {len(unmatched)} of {len(functions)} cited original(s) not byte-exact "
                           f"({', '.join(_label(ready_of[f]['info']) for f in sorted(unmatched)[:2])})")
        if unready:
            actions.append(f"clean-first: {len(unready)} exact original(s) not ready in the decomp ("
                           + ", ".join(f"{r} x{c}" for r, c in reasons.most_common(2)) + f"; e.g. {_label(ready_of[min(unready)]['info'])})")
        if consts["near"] or consts["folded"]:
            actions.append(f"check {consts['near'] + consts['folded']} near-miss/folded constant(s) (`zkit consts "
                           f"{sorted(unit['files'])[0]}`)")
        if consts["unsourced"]:
            actions.append(f"source {consts['unsourced']} constant(s) not loaded by any cited original")
        if covered is False:
            actions.append("no test program compiles or links it: add a check that drives it")
        if has_recipe is False:
            actions.append("no fidelity recipe cites its originals")
        ranked.append({"path": next((f for f in sorted(unit["files"]) if f.endswith(UNIT_SOURCES)),
                                    sorted(unit["files"])[0]),
                       "files": sorted(unit["files"]), "score": value, "tier": tier[key],
                       "functions": len(functions), "unmatched": len(unmatched), "not_ready": len(unready),
                       "near_constants": consts["near"], "folded_constants": consts["folded"],
                       "unsourced_constants": consts["unsourced"], "tested": covered, "recipe": has_recipe,
                       "actions": actions})
    ranked.sort(key=lambda r: (-r["score"], -r["functions"], r["path"]))
    result.update(units_ranked=len(ranked), rows=ranked[:limit], uncited=_uncited(project, repo, units, in_scope),
                  weights="score = (3 x share of cited originals not byte-exact + 2 x share exact but not ready "
                          "+ near/folded constants (max 3 each) + 0.5 x unsourced (max 4) + 1 untested + 0.5 no "
                          "recipe) x tier weight (exact 1.5, equivalent 1.0); liberty/infrastructure excluded",
                  meaning="ready = byte-exact, named and clean in the decomp: what a port may follow (`port-plan` "
                          "explains each function). A citation is not a behavior check; uncited exact-tier units "
                          "have no original reference at all.")
    return result


def _label(info: dict) -> str:
    return f"{info['address']} {info['demangled'] or info['name']}"


def _uncited(project: Project, repo: str, cited_units: dict, in_scope, limit: int = 20) -> dict:
    """Exact-tier units with function definitions that cite no original in the source or its header."""
    from .cxx import definitions
    from .tiers import tier_of
    root = project.root(repo)
    exempt = project.config["repositories"][repo].get("checks", {}).get("citation_exempt")
    files = [r[0] for r in connect(project).execute("SELECT path FROM files WHERE repo=?", (repo,))
             if in_scope(r[0]) and r[0].endswith(UNIT_SOURCES)]
    rows = []
    for rel in sorted(files):
        if _unit(rel) in cited_units or tier_of(project, repo, rel) != "exact":
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if exempt and re.search(exempt, text):
            continue
        size = sum(d.end - d.line + 1 for d in definitions(text))
        if size:
            rows.append({"path": rel, "definition_lines": size})
    rows.sort(key=lambda r: -r["definition_lines"])
    return {"units": len(rows), "rows": rows[:limit],
            "meaning": "exact-tier sources whose functions cite no original address (nor does their header) and "
                       "carry no exemption marker: their behavior has no reference to be checked against"}


# ----------------------------------------------------------------------------

BODY_HASH_VERSION = 2


def _body_hash(project: Project, target: str, row) -> str | None:
    """Hash of the decomp function's real definition (comments, declarations and call sites skipped)."""
    from .bridge import source_definition
    found = source_definition(project, project.target(target)["repository"], row["source"], row["name"],
                              row["demangled"])
    return hashlib.sha256(found["body"].encode()).hexdigest()[:16] if found else None


def _cited_state(project: Project, target: str) -> dict[str, dict]:
    db = connect(project)
    native = role_repos(project, "native")
    marks = ",".join("?" * len(native))
    citing: dict[int, set[str]] = collections.defaultdict(set)
    for address, path in db.execute(f"SELECT address, path FROM cites WHERE repo IN ({marks})", native):
        if _is_code(project, path):
            row = containing(db, target, address)
            if row:
                citing[row["address"]].add(path)
    rows = [containing(db, target, address) for address in citing]
    state = {}
    # Grouped by source file so each file is read and comment-stripped once.
    for row in sorted(rows, key=lambda r: (r["source"] or "", r["address"])):
        ready = readiness(project, target, row)
        state[address_text(row['address'])] = {"name": row["name"], "match": row["match"], "linked": bool(row["linked"]),
                                                "body": _body_hash(project, target, row), "ready": ready["ready"],
                                                "reasons": ready["reasons"], "native": sorted(citing[row["address"]])}
    return dict(sorted(state.items()))


def _functions_source(project: Project, target: str) -> str | None:
    row = connect(project).execute("SELECT value FROM meta WHERE key=?", (f"functions_source:{target}",)).fetchone()
    return row[0] if row else None


def _report_state(report: Path, module: str | None) -> dict[str, dict]:
    data = json.loads(report.read_bytes())
    out = {}
    for unit in data.get("units", []):
        if not is_dol_unit(unit.get("metadata", {}), module):
            continue
        for function in unit.get("functions") or []:
            va = function.get("metadata", {}).get("virtual_address")
            if va is not None:
                out[address_text(int(va))] = {"name": function["name"], "match": function.get("fuzzy_match_percent")}
    return out


REVERIFY = ("now-exact", "now-ready", "body-changed", "regressed", "no-longer-ready")


def drift(project: Project, target: str | None = None, accept: bool = False,
          since: Path | None = None) -> dict[str, Any]:
    """Compare cited functions' decomp state with the accepted baseline, or with an old report.json (`since`:
    match state only, so readiness changes are not judged against it)."""
    target = default_target(project, target)
    refresh(project)
    path = state_dir(project) / f"drift-{target}.json"
    current = _cited_state(project, target)
    if since is not None:
        if not since.is_file():
            raise ValueError(f"No report at {since}")
        previous = {"accepted": f"{since} ({datetime.fromtimestamp(since.stat().st_mtime).date()})",
                    "functions": _report_state(since, project.target(target).get("module"))}
    elif accept:
        if _functions_source(project, target) != "objdiff-report":
            raise ValueError("drift needs the decomp's objdiff report (match state); build the decomp first")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"accepted": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                         "hash": BODY_HASH_VERSION, "functions": current}), encoding="utf-8")
        os.replace(temporary, path)
        return {"baseline": "accepted", "functions": len(current), "changes": [],
                "note": "Baseline saved. Later runs list cited functions whose decomp state changed; "
                        "re-verify their native code, then accept again (`zkit drift --accept`)."}
    elif not path.is_file():
        return {"baseline": "none", "functions": len(current), "changes": [],
                "note": "No baseline yet (nothing written). Record one with `zkit drift --accept` (CLI), or "
                        "compare with an old decomp report via since=<report.json>."}
    else:
        previous = json.loads(path.read_text(encoding="utf-8"))
    if _functions_source(project, target) != "objdiff-report":
        return {"baseline": previous["accepted"], "functions": len(current), "changes": [], "reverify_files": [],
                "note": "The objdiff report is missing or unreadable (functions come from symbols.txt), so match "
                        "state is unknown; drift is not judged. Rebuild the decomp."}
    old = previous["functions"]
    changes = []
    quiet = collections.Counter()
    same_hash = previous.get("hash") == BODY_HASH_VERSION  # older baselines hashed declarations/comments too
    for address, now in current.items():
        before = old.get(address)
        if before is None:
            continue  # newly cited: not drift
        kinds = []
        if before["match"] != 100 and now["match"] == 100:
            kinds.append("now-exact")
        elif before["match"] == 100 and now["match"] != 100:
            kinds.append("regressed")
        if "ready" in before:  # baselines from before readiness was recorded cannot judge it
            if now["ready"] and not before["ready"]:
                kinds.append("now-ready")
            elif before["ready"] and not now["ready"]:
                kinds.append("no-longer-ready")
        if before["name"] != now["name"]:
            quiet["renamed"] += 1  # a name says nothing new about behavior; counted, not listed
        if same_hash and before.get("body") and now.get("body") and before["body"] != now["body"]:
            if before["match"] == 100 and now["match"] == 100:
                quiet["edited-but-still-exact"] += 1  # same bytes before and after: native code unaffected
            else:
                kinds.append("body-changed")
        if kinds:
            changes.append({"address": address, "name": now["name"], "changes": kinds, "ready": now["ready"],
                            "not_ready": now["reasons"], "native": now["native"]})
    order = {kind: index for index, kind in enumerate(REVERIFY)}
    changes.sort(key=lambda c: (min(order.get(k, 9) for k in c["changes"]), c["address"]))
    files = collections.Counter(p for c in changes for p in c["native"])
    not_listed = dict(quiet)
    if not same_hash:
        not_listed["body-compare-off (baseline from older zkit: re-accept)"] = 1
    if since is None and old and "ready" not in next(iter(old.values())):
        not_listed["readiness-off (baseline from older zkit: re-accept)"] = 1
    return {"baseline": previous["accepted"], "functions": len(current), "changes": changes,
            "not_listed": not_listed,
            "reverify_files": [{"path": p, "functions": n} for p, n in files.most_common(30)],
            "note": "now-exact/now-ready/body-changed: the native code was written against an unverified or "
                    "different decomp; regressed/no-longer-ready: the reference it follows is no longer proven. "
                    "Re-check those files against the current decomp (and their constants), then accept the new "
                    "state with `zkit drift --accept`."}
