"""Find native behavior that is probably slightly off, and say when to go back.

consts    Every float literal inside a native function that cites original functions is
          compared with the constants those originals (and their direct callees) actually
          load (lfs/lfd/psq_l via r2/r13 or lis+offset) and with cited data words.
          verified = found; near = within 2% of a real constant (transcription slip?);
          unsourced = not loaded anywhere cited (invented, derived, or from elsewhere).
suspects  Per native file: unmatched cited originals + near/unsourced constants + no
          covering test + no fidelity recipe -> one ranked list with the next action.
drift     Remembers the decomp state of every cited function (match, name, body hash) and
          reports what changed since: newly exact, renamed, or body edited. Those are the
          moments native code written against the old state must be re-verified.
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
from .bridge import _changed_files, _is_code, default_target, role_repos
from .gc import Dol, direct_calls, track_addresses
from .index import address_text, connect, containing, is_dol_unit, refresh
from .project import Project, under as _under

LITERAL = re.compile(r"(?<![\w.])(\d+\.\d*(?:[eE][-+]?\d+)?|\d*\.\d+(?:[eE][-+]?\d+)?|\d+[eE][-+]?\d+)[fF]?(?![\w.])")
def _cited(text: str) -> list[int]:
    """Original addresses cited in text, for the active platform."""
    from .index import platform
    current = platform()
    return [current.cite_value(a) for a in re.findall(current.cite_pattern(), text)]
DEFINITION = re.compile(r"^[A-Za-z_][\w:<>,\s\*&~]*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{?\s*$")
TRIVIAL = {0.0, 1.0, 0.5, 2.0, 0.25, 10.0, 100.0}


def _f32(value: float) -> float:
    try:
        return struct.unpack(">f", struct.pack(">f", value))[0]
    except (OverflowError, struct.error):
        return value


def _sext(value: int, bits: int = 16) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


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
        out, high = set(), {}
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
        start = int(symbol["address"], 16) if symbol else address
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
        yield lo, i, i


def _functions(lines: list[str]):
    """(start_line_of_comment_block, definition_line, end_line) for top-level definitions."""
    i = 0
    while i < len(lines):
        if DEFINITION.match(lines[i]) and not lines[i].startswith((" ", "\t", "#", "}")):
            lo = i
            while lo > 0 and lines[lo - 1].strip().startswith(("//", "/*", "*")):
                lo -= 1
            j = i
            while j < len(lines) and not lines[j].startswith("}"):
                j += 1
            yield lo, i, j
            i = j
        i += 1


def _is_power_of_two(value: float) -> bool:
    return value > 0 and math.log2(value).is_integer()


def constant_audit(project: Project, repo: str, paths: list[str] | None = None, target: str | None = None,
                   only_lines: dict[str, set[int] | None] | None = None) -> dict[str, Any]:
    target = default_target(project, target)
    refresh(project, [repo])
    consts = Constants(project, target)
    root = project.root(repo)
    from .tiers import tier_of
    files = sorted(only_lines) if only_lines is not None else sorted(
        r[0] for r in connect(project).execute("SELECT path FROM files WHERE repo=?", (repo,))
        if r[0].endswith((".cpp", ".cc", ".hpp", ".h")) and _is_code(project, r[0]))
    if paths:
        files = [f for f in files if _under(f, paths)]
    counts, findings = collections.Counter(), []
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        tier = tier_of(project, repo, rel)
        if tier not in ("exact", "equivalent"):
            counts["not_judged_files"] += 1  # liberty/infrastructure: the owner's own values
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        wanted = (only_lines or {}).get(rel)
        blocks = list(_functions(lines))
        inside = {n for lo, _, end in blocks for n in range(lo, end + 1)}
        for lo, _, end in blocks + list(_constant_blocks(lines, inside)):
            block = lines[lo:end + 1]
            cited = _cited("\n".join(block))
            pool: set[float] = set()
            code_cites = 0
            for address in cited:
                found = consts.of(address)
                if found is not None:
                    pool |= found
                    code_cites += containing(consts.db, target, address) is not None
            if not code_cites:
                continue
            for k, text in enumerate(block):
                number = lo + k + 1
                if wanted is not None and number not in wanted:
                    continue
                code = re.sub(r'"(?:\\.|[^"\\])*"', '""', re.sub(r"/\*.*?\*/", "", text)).split("//")[0]
                for match in LITERAL.finditer(code):
                    value = float(match.group(1))
                    counts["literals"] += 1
                    if value in TRIVIAL or _is_power_of_two(value) or (value.is_integer() and value < 4):
                        counts["trivial"] += 1
                        continue
                    if any(math.isclose(_f32(value), _f32(abs(c)), rel_tol=1e-6, abs_tol=1e-12) for c in pool):
                        counts["verified"] += 1
                        continue
                    near = sorted({abs(c) for c in pool if c and abs(value - abs(c)) / abs(c) < 0.02})
                    kind = "near" if near else "unsourced"
                    counts[kind] += 1
                    findings.append({
                        "kind": kind, "ref": f"{rel}:{number}", "value": value, "near": near[:3],
                        "pool_size": len(pool), "tier": tier, "gameplay": tier == "exact",
                        "severity": "warning" if kind == "near" else "info",
                        "line": text.strip()[:140]})
    findings.sort(key=lambda f: (f["kind"] != "near", f["tier"] != "exact", f["ref"]))
    return {"repo": repo, "counts": dict(counts), "findings": findings,
            "scope": "exact and equivalent tiers only; liberty/infrastructure values are the owner's",
            "meaning": "verified = the literal is a constant the cited original (or a direct callee) loads. "
                       "near = within 2% of one: likely a transcription slip unless intentional. unsourced = "
                       "not loaded by any cited original: derived, from an uncited callee, or invented."}


# ----------------------------------------------------------------------------

def suspects(project: Project, repo: str, paths: list[str] | None = None, target: str | None = None,
             limit: int = 25) -> dict[str, Any]:
    """Rank native files by how likely their behavior is slightly off, with the next action."""
    from .native import grounding
    target = default_target(project, target)
    ground = grounding(project, repo, paths, target, limit=10000)
    unmatched = {w["path"]: w for w in ground["weakest_files"]}
    audit = constant_audit(project, repo, paths, target)
    per_const: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for f in audit["findings"]:
        per_const[f["ref"].rsplit(":", 1)[0]][f["kind"]] += 1
    db = connect(project)
    recipes = {name: repo_cfg["recipes"].rstrip("/") + "/" for name, repo_cfg in project.config["repositories"].items()
               if repo_cfg.get("recipes")}
    recipe_functions = set()
    if recipes:
        for (address,) in db.execute("SELECT address FROM cites WHERE " + " OR ".join(
                "(repo=? AND path LIKE ?)" for _ in recipes), [x for n, d in recipes.items() for x in (n, d + "%")]):
            row = containing(db, target, address)
            if row:
                recipe_functions.add(row["address"])
    from .tiers import WEIGHT, tier_of
    tested = _tested_files(project, repo)
    rows = []
    files = sorted(set(unmatched) | set(per_const))
    for rel in files:
        cites = [r[0] for r in db.execute("SELECT DISTINCT address FROM cites WHERE repo=? AND path=?", (repo, rel))]
        functions = {containing(db, target, a)["address"] for a in cites if containing(db, target, a)}
        has_recipe = bool(functions & recipe_functions) if recipe_functions else None
        u = unmatched.get(rel, {}).get("unmatched", 0)
        c = per_const.get(rel, collections.Counter())
        covered = tested.get(rel) if tested is not None else None
        score = 3 * u + 4 * c["near"] + 1 * c["unsourced"] + (2 if covered is False else 0) + (1 if has_recipe is False else 0)
        tier = tier_of(project, repo, rel)
        gameplay = tier == "exact"
        score = round(score * WEIGHT.get(tier, 1.0), 1)
        if tier not in ("exact", "equivalent"):
            continue  # liberty/infrastructure behavior is the owner's design, not a fidelity suspect
        if score == 0:
            continue
        actions = []
        if u:
            actions.append(f"decompile-first: {u} cited original(s) not exact ({', '.join(unmatched[rel]['examples'][:2])})")
        if c["near"]:
            actions.append(f"check {c['near']} near-miss constant(s) (`zkit consts {rel}`)")
        if c["unsourced"]:
            actions.append(f"source {c['unsourced']} constant(s) not loaded by any cited original")
        if covered is False:
            actions.append("no direct/near test compiles it: add or register one")
        if has_recipe is False:
            actions.append("no original-execution recipe cites its originals")
        rows.append({"path": rel, "score": score, "tier": tier, "gameplay": gameplay, "unmatched": u, "near_constants": c["near"],
                     "unsourced_constants": c["unsourced"], "tested": covered, "recipe": has_recipe,
                     "actions": actions})
    rows.sort(key=lambda r: -r["score"])
    return {"repo": repo, "rows": rows[:limit], "files_ranked": len(rows),
            "weights": "3×unmatched cited original, 4×near-miss constant, 1×unsourced constant, "
                       "2×untested, 1×no recipe; ×1.5 exact tier, ×1.0 equivalent; liberty/infrastructure excluded",
            "meaning": "Where slightly-off behavior most likely lives. decompile-first items cannot be "
                       "trusted until the decomp proves them; after recovering them run `zkit drift`."}


def _tested_files(project: Project, repo: str) -> dict[str, bool] | None:
    """native file -> has a direct/near test (via the impact machinery), or None if unavailable."""
    from .native import IncludeGraph, _companions, _targets
    config = project.config["repositories"][repo].get("tests")
    if not config:
        return None
    root = project.root(repo)
    build = root / config.get("build_dir", "build")
    if not (build / "compile_commands.json").is_file():
        return None
    graph = IncludeGraph(root, config.get("include_roots", ["src", "tests", "."]), config.get("scan", ["src", "tests"]))
    targets = _targets(build, root)
    test_prefix = tuple(config.get("test_paths", ["tests/"]))
    known = set(graph.files)
    includes: dict[str, set[str]] = collections.defaultdict(set)
    for child, parents in graph.includers.items():
        for parent in parents:
            includes[parent].add(child)
    # Forward from every compiled test source, two include levels, cpp/hpp pairs as one unit.
    reached: set[str] = set()
    for source in (s for s in targets if s.startswith(test_prefix)):
        frontier = _companions(source, known)
        for _ in range(2):
            nxt = set()
            for node in frontier:
                for child in includes.get(node, ()):
                    nxt |= _companions(child, known)
            reached |= nxt
            frontier = nxt
    return {rel: rel in reached for rel in graph.files if _is_code(project, rel)}


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
        state[address_text(row['address'])] = {"name": row["name"], "match": row["match"], "linked": bool(row["linked"]),
                                            "body": _body_hash(project, target, row),
                                            "native": sorted(citing[row["address"]])}
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


def drift(project: Project, target: str | None = None, accept: bool = False,
          since: Path | None = None) -> dict[str, Any]:
    """Compare cited functions' decomp state with the accepted baseline, or with an old report.json."""
    target = default_target(project, target)
    refresh(project)
    path = state_dir(project) / f"drift-{target}.json"
    current = _cited_state(project, target)
    if since is not None:
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
                        "re-verify their native code, then `zkit drift --accept` again."}
    elif not path.is_file():
        return {"baseline": "none", "functions": len(current), "changes": [],
                "note": "No baseline yet (nothing written). Record one with `zkit drift --accept`, or compare "
                        "with an old decomp report via `--since <report.json>`."}
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
        if before["name"] != now["name"]:
            quiet["renamed"] += 1  # a name says nothing new about behavior; counted, not listed
        if same_hash and before.get("body") and now.get("body") and before["body"] != now["body"]:
            if before["match"] == 100 and now["match"] == 100:
                quiet["edited-but-still-exact"] += 1  # same bytes before and after: native code unaffected
            else:
                kinds.append("body-changed")
        if kinds:
            changes.append({"address": address, "name": now["name"], "changes": kinds, "native": now["native"]})
    order = {"now-exact": 0, "body-changed": 1, "regressed": 2}
    changes.sort(key=lambda c: (min(order.get(k.split()[0], 3) for k in c["changes"]), c["address"]))
    files = collections.Counter(p for c in changes for p in c["native"] if "now-exact" in c["changes"]
                                or "body-changed" in c["changes"])
    return {"baseline": previous["accepted"], "functions": len(current), "changes": changes,
            "not_listed": dict(quiet) | ({} if same_hash else {"body-compare-off (baseline from older zkit: re-accept)": 1}),
            "reverify_files": [{"path": p, "functions": n} for p, n in files.most_common(30)],
            "note": "now-exact / body-changed: the native code was written against an unverified or different "
                    "decomp body; re-check it (and its constants) against the current decomp, then accept."}
