"""Translation-unit boundaries and function names proposed from evidence in the original executable.

Evidence, strongest first:
- a source path a function references (assert and log messages carry `__FILE__`): that function belongs to that
  file's unit;
- a `Class::method(...)` string a function references (logs and `__PRETTY_FUNCTION__` name the function they are
  in): a name for that function, unless it references several (an inlined callee's string);
- between two functions of the same file, functions with no evidence of their own: the linker keeps one object's
  functions together, so they belong to it;
- a function called only from one unit's functions (a static helper): that unit.
Everything is a proposal with its evidence and confidence; the project's own tools apply what it accepts.
"""

from __future__ import annotations

import collections
import re
from pathlib import Path
from typing import Any

from .project import Project

SOURCE = re.compile(r"\.(c|cc|cp|cpp|cxx|h|hh|hpp|inl|inc)$", re.I)
HEADER = re.compile(r"\.(h|hh|hpp|inl|inc)$", re.I)
FILL_FUNCTIONS, FILL_BYTES = 48, 0x8000  # between two functions of one file, fill only a gap this small
SIGNATURE = re.compile(r"^(?P<name>(?:[A-Za-z_][\w<>,*& ]*::)+~?[A-Za-z_]\w*)\s*\(")


def strings(project: Project, target: str, minimum: int = 4) -> dict[int, str]:
    """Printable NUL-terminated strings in the original's data sections, by address."""
    from .inspect_dol import _dol
    from .platform import for_target
    platform = for_target(project.target(target))
    image = _dol(project, target)
    out = {}
    pattern = re.compile(rb"[\x20-\x7e]{%d,}\x00" % minimum)
    for section in platform.sections(image):
        if section.kind != "data":
            continue
        try:
            raw = platform.read(image, section.address, section.size)
        except ValueError:
            continue
        for match in pattern.finditer(raw):
            out[section.address + match.start()] = match.group(0)[:-1].decode("ascii")
    return out


def _roots(paths: list[str]) -> list[str]:
    """Checkout folders to drop from unit names, one per source tree (a game's own tree and each third-party
    tree usually come from different machines): per group of paths sharing their first two folders, the longest
    directory prefix 80% of the group shares, keeping at least two folders of each path."""
    groups: dict[tuple, list[list[str]]] = collections.defaultdict(list)
    for path in paths:
        parts = path.replace("\\", "/").split("/")[:-1]
        if len(parts) >= 2:
            groups[tuple(parts[:2])].append(parts)
    roots = []
    for members in groups.values():
        prefix: list[str] = []
        while True:
            depth = len(prefix)
            counts = collections.Counter(tuple(p[:depth + 1]) for p in members if len(p) > depth + 1
                                         and p[:depth] == prefix)
            if not counts:
                break
            best, count = counts.most_common(1)[0]
            if count < 0.8 * len(members):
                break
            prefix = list(best)
        if prefix:
            roots.append("/".join(prefix) + "/")
    return sorted(roots, key=len, reverse=True)


def propose(project: Project, target: str | None = None) -> dict[str, Any]:
    from .bridge import default_target
    from .index import address_text, connect, refresh
    target = default_target(project, target)
    refresh(project)
    db = connect(project)
    found = strings(project, target)
    files = {a: s for a, s in found.items() if SOURCE.search(s) and ("/" in s or "\\" in s)}
    signatures = {a: m["name"] for a, s in found.items() if (m := SIGNATURE.match(s))}
    rows = db.execute("SELECT address, size, name, provisional FROM functions WHERE target=? AND address<? "
                      "ORDER BY address", (target, 1 << 32)).fetchall()
    function_files: dict[int, set] = collections.defaultdict(set)
    function_names: dict[int, set] = collections.defaultdict(set)
    for function, address in db.execute("SELECT function, address FROM xrefs WHERE target=? AND kind='addr'",
                                        (target,)):
        if address in files:
            function_files[function].add(files[address])
        if address in signatures:
            function_names[function].add(signatures[address])
    roots = _roots(list(files.values()))

    def unit_of(path: str) -> str:
        path = path.replace("\\", "/")
        root = next((r for r in roots if path.startswith(r)), "")
        path = path[len(root):] if root else path
        parts = []
        for part in path.split("/"):  # resolve a/b/../c
            if part == ".." and parts:
                parts.pop()
            elif part not in (".", ""):
                parts.append(part)
        return "/".join(parts)

    # 1. anchors: a function citing exactly one source file. A header path is an inline from that header, compiled
    # into whichever unit used it: recorded, never an anchor.
    owner: dict[int, tuple[str, str]] = {}  # function -> (unit, how)
    inlines: dict[int, str] = {}
    for function, paths in function_files.items():
        sources = {p for p in paths if not HEADER.search(p)}
        if len(sources) == 1:
            owner[function] = (unit_of(next(iter(sources))), "file string")
        elif not sources and len(paths) == 1:
            inlines[function] = unit_of(next(iter(paths)))
    order = [r[0] for r in rows]
    sizes = {r[0]: r[1] for r in rows}
    # 2. same file on both sides: the functions between belong to it
    previous = None
    for index, address in enumerate(order):
        if address in owner and owner[address][1] == "file string":
            span = order[previous + 1:index] if previous is not None else []
            if previous is not None and owner[order[previous]][0] == owner[address][0] and \
                    len(span) <= FILL_FUNCTIONS and address - order[previous] <= FILL_BYTES:
                for between in span:
                    owner.setdefault(between, (owner[address][0], "between"))
            previous = index
    # 3. static helpers: called only from one unit's functions and placed beside that unit's code
    callers: dict[int, set] = collections.defaultdict(set)
    for caller, callee in db.execute("SELECT caller, callee FROM calls WHERE target=?", (target,)):
        callers[callee].add(caller)
    for _ in range(3):
        added = 0
        for index, address in enumerate(order):
            if address in owner or not callers.get(address):
                continue
            units = {owner[c][0] for c in callers[address] if c in owner}
            if len(units) != 1 or not all(c in owner for c in callers[address]):
                continue
            unit = next(iter(units))
            near = [order[k] for k in range(max(0, index - 8), min(len(order), index + 9))
                    if order[k] in owner and owner[order[k]][0] == unit and abs(order[k] - address) <= FILL_BYTES]
            if near:
                owner[address] = (unit, "only caller unit")
                added += 1
        if not added:
            break
    # units as runs in address order: functions without evidence between two of the same unit do not break it
    runs: list[dict] = []
    for address in order:
        if address not in owner:
            continue
        unit, how = owner[address]
        if not runs or runs[-1]["unit"] != unit or address - runs[-1]["end"] > FILL_BYTES:
            runs.append({"unit": unit, "start": address, "functions": 0, "evidence": collections.Counter()})
        run = runs[-1]
        run["functions"] += 1
        run["evidence"][how] += 1
        run["end"] = address + sizes[address]
    per_unit = collections.Counter(r["unit"] for r in runs)
    gaps = []
    for left, right in zip(runs, runs[1:]):
        if right["start"] > left["end"] and left["unit"] != right["unit"]:
            inside = [a for a in order if left["end"] <= a < right["start"]]
            if inside:
                gaps.append({"start": address_text(left["end"]), "end": address_text(right["start"]),
                             "functions": len(inside), "between": [left["unit"], right["unit"]]})
    names = []
    by_address = {r[0]: r for r in rows}
    for function, candidates in function_names.items():
        if len(candidates) != 1:
            continue
        row = by_address.get(function)
        name = next(iter(candidates))
        names.append({"address": address_text(function), "current": row[2] if row else None,
                      "proposed": name, "provisional": bool(row[3]) if row else None,
                      "confidence": "high" if function in owner and owner[function][1] == "file string" else "medium"})
    covered = sum(sizes[a] for a in owner)
    total = sum(sizes.values()) or 1
    return {"target": target, "roots": roots, "files": len(set(files.values())), "strings": len(found),
            "functions": len(order), "assigned": len(owner), "assigned_bytes_percent": round(100 * covered / total, 2),
            "evidence": dict(collections.Counter(how for _, how in owner.values())),
            "units": [{"unit": r["unit"], "start": address_text(r["start"]), "end": address_text(r["end"]),
                       "start_key": r["start"], "end_key": r["end"], "functions": r["functions"],
                       "evidence": dict(r["evidence"]), "pieces": per_unit[r["unit"]]} for r in runs],
            "gaps": gaps, "names": sorted(names, key=lambda n: n["address"]),
            "inlined_name_strings": sum(1 for v in function_names.values() if len(v) > 1),
            "header_inlines": len(inlines),
            "limits": "Proposals from strings the code references and call structure. Files whose code shows up "
                      "in several pieces are usually header-defined inlines and templates; gaps between different "
                      "files need other evidence (data, vtables, compiler changes). Names from log strings can "
                      "name a caller's subject; check them against vtables and this-flow before renaming."}


def write_splits(data: dict, path: Path, section: str = ".text") -> Path:
    """The proposal as a splits.txt (decomp-toolkit's format): one block per unit, its ranges in address order."""
    from .index import platform
    blocks: dict[str, list[tuple[int, int]]] = collections.defaultdict(list)
    for unit in data["units"]:
        blocks[unit["unit"]].append((unit["start_key"], unit["end_key"]))
    base = platform().base
    lines = []
    for unit, ranges in sorted(blocks.items(), key=lambda kv: min(r[0] for r in kv[1])):
        lines.append(f"{unit}:")
        for start, end in sorted(ranges):
            lines.append(f"\t{section:<12} start:0x{base + start:08X} end:0x{base + end:08X}")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
