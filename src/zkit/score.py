"""How close a proposed split (a splits.txt and symbols.txt) comes to a reference one.

The reference is a decomp's own configuration. Where its objdiff report marks a unit complete, that unit's bytes
are proven to compile and link from one source file; elsewhere its boundaries are the decomp's best reading.
A complete unit does not prove its edges are the original file boundaries (one file split in two still links),
so unit scores are agreement with the decomp, and a proposed cut inside a complete unit is counted on its own:
it contradicts proven evidence.

Scores: function starts and sizes, names (a wrong name counts against a proposal, an absent one does not),
data object starts per section, vtables, unit cuts between consecutive functions, units reproduced exactly, and
the data each unit owns.
"""

from __future__ import annotations

import bisect
import collections
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gc import read_splits, read_symbols

CODE_SECTIONS = (".init", ".text")
PLACEHOLDER = re.compile(r"^(?:@|\$|\.L)|^(?:fn|lbl|func|FUN|sub|LAB|DAT|PTR|zz|unk|jumptable|switch|gap|pad)_"
                         r"[0-9A-Fa-f_]*$|[_@][0-9A-Fa-f]{8}(?:$|_)")


def placeholder(name: str) -> bool:
    """A generated name (an address label, a compiler local, an address-named unit) rather than a recovered one."""
    return bool(PLACEHOLDER.search(name))


@dataclass
class Split:
    units: dict[str, list[tuple[str, int, int]]] = field(default_factory=lambda: collections.defaultdict(list))
    functions: dict[int, tuple[int, str]] = field(default_factory=dict)        # start -> (size, name)
    objects: dict[int, tuple[int, str, str]] = field(default_factory=dict)     # start -> (size, name, section)

    def unit_ranges(self, sections: tuple[str, ...] | None = None) -> list[tuple[int, int, str]]:
        return sorted((start, end, unit) for unit, rows in self.units.items() for section, start, end in rows
                      if sections is None or section in sections)


def load(folder: Path) -> Split:
    """A configuration folder (splits.txt and symbols.txt), or the folder of a proposal written the same way."""
    split = Split()
    splits, symbols = folder / "splits.txt", folder / "symbols.txt"
    if splits.is_file():
        for unit, section, start, end in read_splits(splits):
            split.units[unit].append((section, start, end))
    if symbols.is_file():
        for symbol in read_symbols(symbols):
            if symbol.type == "function" and symbol.section in CODE_SECTIONS:
                split.functions.setdefault(symbol.address, (symbol.size, symbol.name))
            elif symbol.type == "object":
                split.objects.setdefault(symbol.address, (symbol.size, symbol.name, symbol.section))
    return split


def complete_units(report: Path, module: str | None = None) -> set[str]:
    """Source paths of the units an objdiff report marks complete (linked byte-exact)."""
    data = json.loads(report.read_text(encoding="utf-8"))
    out = set()
    for unit in data.get("units", []):
        meta = unit.get("metadata") or {}
        if meta.get("complete") and (module is None or meta.get("module_name") == module):
            path = meta.get("source_path") or unit["name"]
            out.add(path)
    return out


def _matches(unit: str, paths: set[str]) -> bool:
    return any(path == unit or path.endswith("/" + unit) for path in paths)


def _rate(hit: int, total: int) -> float | None:
    return round(100 * hit / total, 2) if total else None


def _owner(ranges: list[tuple[int, int, str]]):
    starts = [r[0] for r in ranges]

    def at(address: int) -> str | None:
        index = bisect.bisect_right(starts, address) - 1
        return ranges[index][2] if index >= 0 and ranges[index][0] <= address < ranges[index][1] else None
    return at


def score(reference: Split, proposal: Split, proven: set[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # functions
    truth, ours = reference.functions, proposal.functions
    found = set(truth) & set(ours)
    out["functions"] = {"reference": len(truth), "proposed": len(ours), "starts_found": _rate(len(found), len(truth)),
                        "starts_correct": _rate(len(found), len(ours)),
                        "sizes_exact": _rate(sum(1 for a in found if truth[a][0] == ours[a][0]), len(truth))}
    # names
    named = {a: n for a, (_, n) in truth.items() if not placeholder(n)}
    offered = {a: n for a, (_, n) in ours.items() if not placeholder(n) and a in truth}
    right = sum(1 for a, n in offered.items() if named.get(a) == n)
    wrong = sum(1 for a, n in offered.items() if a in named and named[a] != n)
    out["names"] = {"reference_named": len(named), "proposed_named": len(offered), "correct": right, "wrong": wrong,
                    "recall": _rate(right, len(named)), "precision": _rate(right, right + wrong)}
    # data objects per section
    sections: dict[str, dict] = {}
    by_section = collections.defaultdict(set)
    for address, (_, _, section) in reference.objects.items():
        by_section[section].add(address)
    proposed_by_section = collections.defaultdict(set)
    for address, (_, _, section) in proposal.objects.items():
        proposed_by_section[section].add(address)
    for section in sorted(set(by_section) | set(proposed_by_section)):
        a, b = by_section[section], proposed_by_section[section]
        sections[section] = {"reference": len(a), "proposed": len(b), "found": _rate(len(a & b), len(a)),
                             "correct": _rate(len(a & b), len(b))}
    out["data_objects"] = sections
    # vtables
    vtables = {a: n for a, (_, n, _) in reference.objects.items() if n.startswith("__vt__")}
    proposed_vtables = {a: n for a, (_, n, _) in proposal.objects.items() if n.startswith("__vt__")}
    out["vtables"] = {"reference": len(vtables), "proposed": len(proposed_vtables),
                      "found": _rate(len(set(vtables) & set(proposed_vtables)), len(vtables)),
                      "named_correctly": _rate(sum(1 for a, n in proposed_vtables.items() if vtables.get(a) == n),
                                               len(vtables))}
    # unit cuts between consecutive reference functions
    reference_text = reference.unit_ranges(CODE_SECTIONS)
    proposal_text = proposal.unit_ranges(CODE_SECTIONS)
    owner, proposed_owner = _owner(reference_text), _owner(proposal_text)
    order = sorted(truth)
    cuts = agreed = offered_cuts = agreed_offered = inside_complete = 0
    proven = proven or set()
    for left, right_function in zip(order, order[1:]):
        a, b = owner(left), owner(right_function)
        if a is None or b is None:
            continue
        x, y = proposed_owner(left), proposed_owner(right_function)
        reference_cut = a != b
        proposed_cut = x != y or x is None
        cuts += reference_cut
        offered_cuts += proposed_cut
        if reference_cut and proposed_cut:
            agreed += 1
        if proposed_cut and reference_cut:
            agreed_offered += 1
        if proposed_cut and not reference_cut and _matches(a, proven):
            inside_complete += 1
    out["unit_cuts"] = {"reference": cuts, "proposed": offered_cuts, "found": _rate(agreed, cuts),
                        "correct": _rate(agreed_offered, offered_cuts),
                        "inside_complete_units": inside_complete}
    # units reproduced exactly (their code ranges), all and complete
    proposal_sets = {frozenset((s, e) for s, e, _ in group) for group in _grouped(proposal_text).values()}
    reference_groups = _grouped(reference_text)
    exact = [u for u, group in reference_groups.items() if frozenset((s, e) for s, e, _ in group) in proposal_sets]
    complete = [u for u in reference_groups if _matches(u, proven)]
    out["units"] = {"reference": len(reference_groups), "proposed": len(_grouped(proposal_text)),
                    "exact": _rate(len(exact), len(reference_groups)),
                    "complete": len(complete),
                    "complete_exact": _rate(sum(1 for u in exact if _matches(u, proven)), len(complete))}
    # data ownership: each proposed unit stands for the reference unit it shares the most bytes with
    stands_for = {x: counts.most_common(1)[0][0] for x, counts in _overlaps(proposal.unit_ranges(),
                                                                             reference.unit_ranges()).items()}
    text_rows = set(reference_text)
    proposal_data = _owner([r for r in proposal.unit_ranges() if r not in set(proposal_text)])
    total = owned = 0
    for start, end, unit in reference.unit_ranges():
        if (start, end, unit) in text_rows:
            continue
        for address in range(start, end, 4):
            total += 4
            x = proposal_data(address)
            if x is not None and stands_for.get(x) == unit:
                owned += 4
    out["data_ownership"] = {"reference_bytes": total, "owned_by_the_right_unit": _rate(owned, total)}
    return out


def _overlaps(ours: list[tuple[int, int, str]], theirs: list[tuple[int, int, str]]) -> dict[str, collections.Counter]:
    """{our unit: Counter(their unit: shared bytes)} over two sorted range lists."""
    out: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    j = 0
    for start, end, unit in ours:
        while j < len(theirs) and theirs[j][1] <= start:
            j += 1
        k = j
        while k < len(theirs) and theirs[k][0] < end:
            shared = min(end, theirs[k][1]) - max(start, theirs[k][0])
            if shared > 0:
                out[unit][theirs[k][2]] += shared
            k += 1
    return out


def _grouped(ranges: list[tuple[int, int, str]]) -> dict[str, list[tuple[int, int, str]]]:
    groups: dict[str, list] = collections.defaultdict(list)
    for row in ranges:
        groups[row[2]].append(row)
    return groups
