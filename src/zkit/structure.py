"""Program structure from the decomp's own files: split units, the data they own, and class evidence.

unit     a split unit's section ranges, its functions, its data symbols and the data references that
         cross unit boundaries (what keeps a unit from linking on its own, and what a fold or merge would
         move), with the neighbouring units of each section.
classes  function class names that the original vtables contradict, and virtuals that sit in exactly one
         named class's vtables without a class in their name.

Everything is read from splits.txt, symbols.txt, the objdiff report and references decoded from the
original executable. Nothing here edits splits or names.
"""

from __future__ import annotations

import bisect
import collections
import json
import re
from typing import Any

from .bridge import HEX, _status, _symbol_table, default_target, resolve, status_word
from .gc import read_splits
from .index import address_text, connect, containing, refresh
from .project import Project

CODE_SECTIONS = {".text", ".init"}
LITERAL_SECTIONS = {".sdata2", ".rodata", ".sbss2"}  # compiler-pooled constants: a unit's own copy, not a shared global
_SPLITS: dict[str, tuple[str, list, list[int]]] = {}


def splits(project: Project, target: str) -> tuple[list[tuple[str, str, int, int]], list[int]]:
    """(unit, section, start, end) rows sorted by start, and their starts. Empty without a splits file."""
    config = project.target(target)
    if not config.get("splits"):
        return [], []
    path = project.file(config["repository"], config["splits"])
    if not path.is_file():
        return [], []
    info = path.stat()
    stamp = f"{info.st_mtime_ns}:{info.st_size}"
    cached = _SPLITS.get(str(path))
    if not cached or cached[0] != stamp:
        rows = sorted(read_splits(path), key=lambda r: r[2])
        cached = _SPLITS[str(path)] = (stamp, rows, [r[2] for r in rows])
    return cached[1], cached[2]


def split_owner(project: Project, target: str, address: int) -> dict | None:
    """The split unit and section range holding an address, or None for bytes no split claims."""
    rows, starts = splits(project, target)
    index = bisect.bisect_right(starts, address) - 1
    if index >= 0 and rows[index][2] <= address < rows[index][3]:
        unit, section, start, end = rows[index]
        return {"unit": unit, "section": section, "start": address_text(start), "end": address_text(end)}
    return None


def _norm(unit: str) -> str:
    return re.sub(r"\.(c|cc|cp|cpp|cxx|s)$", "", unit, flags=re.I)


def _resolve_unit(project: Project, target: str, query: str) -> tuple[str | None, list[str]]:
    rows, _ = splits(project, target)
    units = list(dict.fromkeys(r[0] for r in rows))
    q = query.strip()
    match = HEX.match(q)
    if match:
        owner = split_owner(project, target, int(match[1], 16))
        return (owner["unit"], []) if owner else (None, [])
    wanted = _norm(q).replace("\\", "/")
    exact = [u for u in units if _norm(u) == wanted or u == q]
    if not exact:  # report/unit names carry a module prefix (main/game/X) that splits.txt does not
        exact = [u for u in units if wanted.endswith("/" + _norm(u))]
    if not exact:
        exact = [u for u in units if _norm(u).endswith("/" + wanted)]
    if len(exact) == 1:
        return exact[0], []
    if not exact:
        found = resolve(project, q, target, limit=2)
        if len(found) == 1:
            owner = split_owner(project, target, found[0])
            if owner:
                return owner["unit"], []
        exact = [u for u in units if wanted.lower() in u.lower()]
        if len(exact) == 1:
            return exact[0], []
    return None, exact[:30]


def _symbols_in(project: Project, target: str, start: int, end: int) -> list:
    symbols, starts = _symbol_table(project, target)
    lo, hi = bisect.bisect_left(starts, start), bisect.bisect_left(starts, end)
    return [s for s in symbols[lo:hi] if s.type != "label"]


def _owner_name(project: Project, target: str, db, address: int) -> str:
    owner = split_owner(project, target, address)
    if owner:
        return owner["unit"]
    row = containing(db, target, address)
    return f"(unsplit {row['unit']})" if row is not None and row["unit"] else "(unsplit)"


def unit(project: Project, query: str, target: str | None = None, limit: int = 40) -> dict[str, Any]:
    """A split unit: ranges, functions, data and every data reference that crosses its boundary."""
    target = default_target(project, target)
    refresh(project, [])
    rows, _ = splits(project, target)
    if not rows:
        raise ValueError(f"Target {target} has no `splits` file in the manifest (a splits.txt)")
    name, candidates = _resolve_unit(project, target, query)
    if name is None:
        match = HEX.match(query.strip())
        if match:
            symbols, starts = _symbol_table(project, target)
            index = bisect.bisect_right(starts, int(match[1], 16)) - 1
            symbol = symbols[index] if index >= 0 else None
            return {"query": query, "found": False, "candidates": [],
                    "hint": f"No split claims {address_text(int(match[1], 16))}"
                            + (f" (nearest symbol {symbol.name}, {symbol.section})" if symbol else "")
                            + ": the build gives unsplit bytes to an auto-generated unit."}
        return {"query": query, "found": False, "candidates": candidates,
                "hint": "Give a unit path from splits.txt (with or without extension), an address, or a function."}
    db = connect(project)
    ranges = [r for r in rows if r[0] == name]
    sections = [{"section": s, "start": address_text(a), "end": address_text(b), "size": b - a} for _, s, a, b in ranges]
    functions: list[dict] = []
    for _, section, start, end in ranges:
        if section in CODE_SECTIONS:
            functions += [_status(r) for r in db.execute(
                "SELECT * FROM functions WHERE target=? AND address>=? AND address<? ORDER BY address",
                (target, start, end))]
    counts = collections.Counter()
    for f in functions:
        counts["total"] += 1
        counts["exact"] += f["exact"]
        counts["linked"] += f["linked"]
        counts["provisional"] += f["provisional_name"]
    pending = [f for f in functions if not f["exact"] or f["provisional_name"]]

    data = []
    for _, section, start, end in ranges:
        if section in CODE_SECTIONS:
            continue
        for symbol in _symbols_in(project, target, start, end):
            size = max(symbol.size, 1)
            users: collections.Counter = collections.Counter()
            for (function,) in db.execute("SELECT function FROM xrefs WHERE target=? AND address>=? AND address<?",
                                          (target, symbol.address, symbol.address + size)):
                users[_owner_name(project, target, db, function)] += 1
            for (holder,) in db.execute("SELECT holder FROM refs WHERE target=? AND pointee>=? AND pointee<?",
                                        (target, symbol.address, symbol.address + size)):
                users[_owner_name(project, target, db, holder) + " (pointer)"] += 1
            outside = {u: n for u, n in users.items() if u.removesuffix(" (pointer)") != name}
            data.append({"address": address_text(symbol.address), "name": symbol.name, "section": section,
                         "size": symbol.size, "refs_inside": sum(users.values()) - sum(outside.values()),
                         "refs_outside": sorted(outside.items(), key=lambda kv: -kv[1])})

    outgoing: dict[tuple[str, str], dict] = {}
    symbols, starts = _symbol_table(project, target)
    for _, section, start, end in ranges:
        if section not in CODE_SECTIONS:
            continue
        for function, address in db.execute(
                "SELECT function, address FROM xrefs WHERE target=? AND function>=? AND function<?",
                (target, start, end)):
            owner = split_owner(project, target, address)
            if owner and owner["unit"] == name:
                continue
            index = bisect.bisect_right(starts, address) - 1
            symbol = symbols[index] if index >= 0 else None
            key = (owner["unit"] if owner else "(unsplit)",
                   owner["section"] if owner else (symbol.section if symbol else "?"))
            entry = outgoing.setdefault(key, {"unit": key[0], "section": key[1], "refs": 0, "symbols": collections.Counter()})
            entry["refs"] += 1
            entry["symbols"][symbol.name if symbol else address_text(address)] += 1
    out_rows = []
    rank = lambda e: (0 if e["section"] in LITERAL_SECTIONS else 2 if e["section"] in CODE_SECTIONS else 1, -e["refs"])
    for entry in sorted(outgoing.values(), key=rank):
        out_rows.append({"unit": entry["unit"], "section": entry["section"], "refs": entry["refs"],
                         "literal": entry["section"] in LITERAL_SECTIONS,
                         "symbols": [n for n, _ in entry["symbols"].most_common(8)],
                         "symbol_count": len(entry["symbols"])})

    neighbours = []
    for _, section, start, end in ranges:
        same = [r for r in rows if r[1] == section]
        index = same.index((name, section, start, end))
        before = same[index - 1] if index else None
        after = same[index + 1] if index + 1 < len(same) else None
        neighbours.append({"section": section,
                           "before": before[0] if before else None, "gap_before": start - before[3] if before else None,
                           "after": after[0] if after else None, "gap_after": after[2] - end if after else None})

    shared = [d for d in data if d["refs_outside"]]
    return {"query": query, "found": True, "target": target, "unit": name, "sections": sections,
            "functions": dict(counts), "pending": pending[:limit], "pending_total": len(pending),
            "data": data[:limit * 3], "data_total": len(data), "shared_data": len(shared),
            "outgoing": out_rows[:limit], "neighbours": neighbours,
            "limits": "Ranges are splits.txt; references are straight-line lis/addi and r2/r13 forms decoded from the "
                      "original plus data pointers, so register-passed and indexed accesses are missed. A literal in "
                      "another unit's .sdata2/.rodata used by this unit's code usually means the compiled source will "
                      "emit its own copy there; whether to fold, merge or move the boundary is the decomp's own rule. "
                      "Link state comes from the current objdiff report."}


def blocked(project: Project, target: str | None = None, limit: int = 40) -> dict[str, Any]:
    """Units whose functions are all exact but not all linked, with the cross-unit references of each."""
    target = default_target(project, target)
    refresh(project, [])
    rows, _ = splits(project, target)
    if not rows:
        raise ValueError(f"Target {target} has no `splits` file in the manifest (a splits.txt)")
    db = connect(project)
    per_unit: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0, 0])
    for name, section, start, end in rows:
        if section not in CODE_SECTIONS:
            continue
        total, exact, linked = db.execute(
            "SELECT count(*), coalesce(sum(match >= 100), 0), coalesce(sum(linked), 0) FROM functions "
            "WHERE target=? AND address>=? AND address<?", (target, start, end)).fetchone()
        counts = per_unit[name]
        counts[0] += total
        counts[1] += exact
        counts[2] += linked
    candidates = [name for name, (total, exact, linked) in per_unit.items() if total and exact == total and linked < total]
    linked_units = sum(1 for total, exact, linked in per_unit.values() if total and linked == total)
    from .build import layout
    config = project.target(target)
    record = project.root(config["repository"]) / layout(target, config).dir / "link" / "link.json"
    attempt = {}   # a Switch link's own reasons, unit by unit: what only a link attempt shows
    if record.is_file():
        attempt = {row["unit"]: row["why"] for row in json.loads(record.read_text(encoding="utf-8")).get("not_linked", [])}
    out = []
    for name in candidates:
        view = unit(project, name, target, limit=200)
        incoming = [{"symbol": d["name"], "section": d["section"], "from": [u for u, _ in d["refs_outside"][:4]]}
                    for d in view["data"] if d["refs_outside"]]
        literals = [o for o in view["outgoing"] if o["literal"]]
        reasons = [f"the last link: {why}" for why in attempt.get(name, [])[:4]]
        if incoming and not attempt:
            reasons.append(f"{len(incoming)} data symbol(s) used by other units")
        if literals and not attempt:
            reasons.append(f"uses {sum(o['symbol_count'] for o in literals)} literal(s) stored outside the unit")
        out.append({"unit": name, "functions": view["functions"], "incoming": incoming[:8],
                    "literals": [{"unit": o["unit"], "section": o["section"], "symbols": o["symbols"][:6]}
                                 for o in literals[:4]],
                    "reasons": reasons or ["no cross-unit data reference found (order, alignment or a missing symbol?)"]})
    out.sort(key=lambda u: (len(u["incoming"]) + len(u["literals"]), -u["functions"]["total"]))
    return {"target": target, "units": out[:limit], "total": len(out), "linked_units": linked_units,
            "limits": "Candidates are split units whose functions are all exact in the report but not all linked. "
                      "Reasons are cross-unit data references decoded from the original; a unit with none may be "
                      "blocked by function order, alignment, section padding or a missing runtime symbol, which "
                      "only a link attempt shows."}


def gaps(project: Project, target: str | None = None, section: str | None = None, limit: int = 40) -> dict[str, Any]:
    """Per section: how much splits.txt claims, and each unclaimed range with its symbols and the units whose code
    uses it (a range used by one unit is that unit's to claim)."""
    target = default_target(project, target)
    refresh(project, [])
    rows, _ = splits(project, target)
    if not rows:
        raise ValueError(f"Target {target} has no `splits` file in the manifest (a splits.txt)")
    db = connect(project)
    symbols, starts = _symbol_table(project, target)
    bounds: dict[str, list[int]] = {}
    for s in symbols:
        if s.type == "label":
            continue
        lo_hi = bounds.setdefault(s.section, [s.address, s.address + s.size])
        lo_hi[0], lo_hi[1] = min(lo_hi[0], s.address), max(lo_hi[1], s.address + s.size)
    sections, ranges = [], []
    for name, (lo, hi) in sorted(bounds.items(), key=lambda kv: kv[1][0]):
        if section and name != section:
            continue
        claimed = sorted((r[2], r[3]) for r in rows if r[1] == name)
        holes, cursor = [], lo
        for start, end in claimed:
            if start > cursor:
                holes.append((cursor, start))
            cursor = max(cursor, end)
        if cursor < hi:
            holes.append((cursor, hi))
        covered = sum(min(e, hi) - max(s, lo) for s, e in claimed if e > lo and s < hi)
        sections.append({"section": name, "start": address_text(lo), "end": address_text(hi), "size": hi - lo,
                         "claimed": covered, "gaps": len(holes), "unclaimed": sum(e - s for s, e in holes)})
        for start, end in holes:
            inside = [s for s in symbols[bisect.bisect_left(starts, start):bisect.bisect_left(starts, end)]
                      if s.type != "label"]
            if not inside:
                continue  # alignment padding
            users: collections.Counter = collections.Counter()
            if name in CODE_SECTIONS:
                for (caller,) in db.execute("SELECT caller FROM calls WHERE target=? AND callee>=? AND callee<?",
                                            (target, start, end)):
                    users[_owner_name(project, target, db, caller)] += 1
            else:
                for (function,) in db.execute("SELECT function FROM xrefs WHERE target=? AND address>=? AND address<?",
                                              (target, start, end)):
                    users[_owner_name(project, target, db, function)] += 1
            split_users = [(u, n) for u, n in users.most_common() if not u.startswith("(unsplit")]
            ranges.append({"section": name, "start": address_text(start), "end": address_text(end), "size": end - start,
                           "symbols": len(inside), "names": [s.name for s in inside[:5]],
                           "used_by": users.most_common(5),
                           "sole_user": split_users[0][0] if len(split_users) == 1 and len(users) == 1 else None})
    ranges.sort(key=lambda r: (r["sole_user"] is None, r["section"] in CODE_SECTIONS, -r["size"]))
    return {"target": target, "sections": sections, "ranges": ranges[:limit], "total": len(ranges),
            "ready": sum(r["sole_user"] is not None for r in ranges),
            "limits": "Section extents come from symbols.txt; unclaimed bytes belong to auto-generated units. "
                      "Users are code references decoded from the original (direct calls for code); a range with one "
                      "split user is a claim candidate, not proof: check alignment and the decomp's split rules."}
