"""Translation units from evidence in the original's code and data, proposed fresh or checked against a decomp's
existing splits. Each kind of evidence states the compiler or format fact it rests on, and applies only where
that fact holds:

- **file strings** (every platform): code citing one source path (`__FILE__` in asserts and logs) belongs to that
  file's unit; functions between two of the same file belong to it too; a function only one unit calls, placed
  beside it, is that unit's static helper. A header path is an inline compiled into its user, never an anchor.
- **separation** (compilers that give every unit its own literals: CodeWarrior): two copies of one constant are
  in two units, so a boundary lies between the functions using them.
- **join**: data only a tight run of functions uses belongs to one unit, so no boundary falls inside that run.
  Writable statics count everywhere; literals only where they are per unit (clang shares them across units).
- **order**: a boundary between functions is one in each data section too, so it goes where the fewest
  references would land on the wrong side; among equal places, where it splits the fewest classes' own
  functions and the fewest short calls (a static helper sits beside its callers).
- **classes**: a unit with no file string is named after the class its functions belong to.
On a decomp in progress, the same evidence finds folds (two units using one copy of a unit's data), splits (one
unit holding two copies of one literal) and claims (data in no unit that one unit's code alone uses, a class's
table whose constructors are in one unit). Everything is a proposal with its evidence.
"""

from __future__ import annotations

import bisect
import collections
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .program import DataObject, Program

TIGHT = 60          # functions: data used across a wider run is shared (a global), not one unit's
LITERAL_SIZES = range(1, 65)
LITERAL_SECTIONS = (".sdata2", ".rodata", ".data")
WRITABLE_SECTIONS = (".data", ".bss", ".sdata", ".sbss")
WINDOW = 24         # functions on each side of a boundary whose references decide where it goes
FILL_FUNCTIONS, FILL_BYTES = 48, 0x8000  # between two functions of one file, fill only a gap this small
SOURCE = re.compile(r"\.(c|cc|cp|cpp|cxx|h|hh|hpp|inl|inc)$", re.I)
HEADER = re.compile(r"\.(h|hh|hpp|inl|inc)$", re.I)
SIGNATURE = re.compile(r"^(?P<name>(?:[A-Za-z_][\w<>,*& ]*::)+~?[A-Za-z_]\w*)\s*\(")


# Evidence

@dataclass
class Evidence:
    local: dict[DataObject, list[int]]                 # data a tight run of functions uses -> those functions
    joins: list[tuple[int, int, str]]                  # (first, last) function index that one unit holds, why
    separations: list[tuple[int, int, str]]            # a boundary lies before a function index in [lo, hi], why
    files: dict[int, str] = field(default_factory=dict)        # function index -> source file it cites
    inlines: dict[int, str] = field(default_factory=dict)      # function index -> header it cites (inline)
    names: dict[int, str] = field(default_factory=dict)        # function index -> `Class::method` it cites
    roots: list[str] = field(default_factory=list)

    def joined(self, count: int) -> list[bool]:
        """joined[p]: a boundary before function p would split one unit."""
        cover = [0] * (count + 2)
        for lo, hi, _ in self.joins:
            if hi > lo:
                cover[lo + 1] += 1
                cover[hi + 1] -= 1
        out, running = [False] * (count + 1), 0
        for p in range(1, count + 1):
            running += cover[p]
            out[p] = running > 0
        return out


def evidence(program: Program) -> Evidence:
    users = program.users()
    local = {o: sorted(fs) for o, fs in users.items() if fs and max(fs) - min(fs) <= TIGHT}
    per_unit = program.platform.literals_per_unit
    text = program.platform.text
    joins = [(fs[0], fs[-1], f"{o.name} ({o.section}) is one unit's") for o, fs in local.items()
             if fs[-1] > fs[0] and (o.section in WRITABLE_SECTIONS or per_unit)]
    separations = []
    if per_unit:
        copies: dict[tuple[str, bytes], list[DataObject]] = collections.defaultdict(list)
        for o in local:
            if o.section in LITERAL_SECTIONS and o.size in LITERAL_SIZES:
                try:
                    copies[(o.section, program.read(o.address, o.size))].append(o)
                except ValueError:
                    continue
        for group in copies.values():
            group.sort(key=lambda o: local[o][0])
            for a, b in zip(group, group[1:]):
                if local[b][0] > local[a][-1]:
                    separations.append((local[a][-1] + 1, local[b][0],
                                        f"two copies of one constant: {text(a.address)} and {text(b.address)}"))
    ev = Evidence(local, joins, separations)
    _file_evidence(program, ev)
    return ev


def _file_evidence(program: Program, ev: Evidence) -> None:
    """Source paths and `Class::method` names the code cites; file runs become joins, file changes separations."""
    strings = program.strings()
    files = {a: s for a, s in strings.items() if SOURCE.search(s) and ("/" in s or "\\" in s)}
    signatures = {a: m["name"] for a, s in strings.items() if (m := SIGNATURE.match(s))}
    cited: dict[int, set[str]] = collections.defaultdict(set)
    named: dict[int, set[str]] = collections.defaultdict(set)
    for index, rows in program.refs.items():
        for _, address, kind in rows:
            if kind == "addr" and address in files:
                cited[index].add(files[address])
            if kind == "addr" and address in signatures:
                named[index].add(signatures[address])
    ev.roots = _roots(list(files.values()))
    for index, paths in cited.items():
        sources = {p for p in paths if not HEADER.search(p)}
        if len(sources) == 1:
            ev.files[index] = _unit_name(next(iter(sources)), ev.roots)
        elif not sources and len(paths) == 1:
            ev.inlines[index] = _unit_name(next(iter(paths)), ev.roots)
    for index, candidates in named.items():
        if len(candidates) == 1:                       # several: an inlined callee's string, not this function's
            ev.names[index] = next(iter(candidates))
    anchors = sorted(ev.files.items())
    starts = [f.address for f in program.functions]
    for (a, file_a), (b, file_b) in zip(anchors, anchors[1:]):
        if file_a == file_b:
            if b - a <= FILL_FUNCTIONS and starts[b] - starts[a] <= FILL_BYTES:
                ev.joins.append((a, b, f"both cite {file_a}"))
        else:
            ev.separations.append((a + 1, b, f"{file_a} then {file_b}"))


def _roots(paths: list[str]) -> list[str]:
    """Checkout folders to drop from unit names, one per source tree: per group of paths sharing their first two
    folders, the longest directory prefix 80% of the group shares, keeping at least two folders of each path."""
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


def _unit_name(path: str, roots: list[str]) -> str:
    path = path.replace("\\", "/")
    root = next((r for r in roots if path.startswith(r)), "")
    parts: list[str] = []
    for part in path[len(root):].split("/"):
        if part == ".." and parts:
            parts.pop()
        elif part not in (".", ""):
            parts.append(part)
    return "/".join(parts)


# Placing boundaries

def _minimal(intervals: list[tuple]) -> list[tuple]:
    """Intervals no other interval lies inside: a boundary in each of these is one in every interval."""
    out = []
    for row in sorted(intervals, key=lambda r: (r[1], -r[0])):
        if out and out[-1][0] >= row[0]:
            continue
        out.append(row)
    return out


def _by_function(ev: Evidence) -> dict[int, list[DataObject]]:
    cached = getattr(ev, "_by_function", None)
    if cached is None:
        cached = collections.defaultdict(list)
        for o, fs in ev.local.items():
            for index in fs:
                cached[index].append(o)
        ev._by_function = cached
    return cached


def _crossings(program: Program, ev: Evidence, p: int) -> int:
    """References that would land on the wrong side of a boundary before function p: per data section, the
    fewest misplaced references over every split point of that section."""
    refs: dict[str, list[tuple[int, bool]]] = collections.defaultdict(list)
    by_function = _by_function(ev)
    for index in range(max(0, p - WINDOW), min(len(program.functions), p + WINDOW)):
        for o in by_function.get(index, ()):
            refs[o.section].append((o.address, index < p))
    total = 0
    for rows in refs.values():
        rows.sort()
        lefts = sum(1 for _, left in rows if left)
        best, after_left, before_right = lefts, lefts, 0
        for _, left in rows:
            if left:
                after_left -= 1
            else:
                before_right += 1
            best = min(best, after_left + before_right)
        total += best
    return total


@dataclass
class Boundary:
    position: int                   # before this function index
    window: tuple[int, int]         # the positions the evidence allows
    crossings: int
    because: str


SHORT_CALL = 16     # functions: a call this close is usually to a static helper of the same unit
CLASS_SPAN = 200    # functions: a class whose own functions spread wider is split across units anyway


def boundaries(program: Program, ev: Evidence | None = None) -> list[Boundary]:
    """The boundaries the evidence requires, each where the fewest references, classes and short calls cross."""
    ev = ev or evidence(program)
    count = len(program.functions)
    joined = ev.joined(count)
    calls = _cover(((min(i, j), max(i, j)) for i, callees in program.calls.items() for j in callees
                    if 0 < abs(i - j) <= SHORT_CALL), count)
    members: dict[str, list[int]] = collections.defaultdict(list)
    for index, cls in _function_classes(program).items():
        members[cls].append(index)
    classes = _cover(((min(f), max(f)) for f in members.values() if max(f) - min(f) <= CLASS_SPAN), count)
    crossings: dict[int, int] = {}

    def cost(p: int) -> tuple:
        if p not in crossings:
            crossings[p] = _crossings(program, ev, p)
        return crossings[p], classes[p], calls[p], p
    chosen: list[Boundary] = []
    for lo, hi, because in _minimal(ev.separations):
        if any(lo <= c.position <= hi for c in chosen):
            continue
        candidates = [p for p in range(lo, hi + 1) if not joined[p]]
        if not candidates:
            continue
        best = min(candidates, key=cost)
        chosen.append(Boundary(best, (candidates[0], candidates[-1]), crossings[best], because))
    return sorted(chosen, key=lambda c: c.position)


def _cover(spans, count: int) -> list[int]:
    """cover[p]: how many (lo, hi) spans a boundary before function p would cut."""
    diff = [0] * (count + 2)
    for lo, hi in spans:
        diff[lo + 1] += 1
        diff[hi + 1] -= 1
    out, running = [0] * (count + 1), 0
    for p in range(1, count + 1):
        running += diff[p]
        out[p] = running
    return out


# A fresh proposal

def propose_project(project, target: str | None = None) -> dict[str, Any]:
    from .bridge import default_target
    target = default_target(project, target)
    return {"target": target, **propose(Program.from_project(project, target))}


def check_project(project, target: str | None = None, limit: int = 60) -> dict[str, Any]:
    from .bridge import default_target
    from .gc import read_splits
    target = default_target(project, target)
    config = project.target(target)
    if not config.get("splits"):
        raise ValueError(f"Target {target} has no `splits` file to check (decomp-toolkit splits.txt)")
    rows = read_splits(project.file(config["repository"], config["splits"]))
    return {"target": target, **check(Program.from_project(project, target), rows, limit)}


def propose(program: Program) -> dict[str, Any]:
    """Units for every function from the evidence: boundaries, a name per unit, and the data each unit owns."""
    ev = evidence(program)
    cuts = boundaries(program, ev)
    text = program.platform.text
    functions = program.functions
    edges = [0] + [c.position for c in cuts] + [len(functions)]
    class_of = _function_classes(program)
    units = []
    taken: collections.Counter = collections.Counter()
    for first, end in zip(edges, edges[1:]):
        if first >= end:
            continue
        span = range(first, end)
        files = collections.Counter(ev.files[i] for i in span if i in ev.files)
        classes = collections.Counter(class_of[i] for i in span if i in class_of)
        if files:
            name, how = files.most_common(1)[0][0], "file string"
        elif classes:
            name, how = classes.most_common(1)[0][0] + ".cpp", "class"
        else:
            name, how = f"unit_{text(functions[first].address)[2:]}.cpp", "placeholder"
        taken[name] += 1
        if taken[name] > 1:                           # one file in several pieces keeps one name per piece
            stem, dot, ext = name.rpartition(".")
            name = f"{stem}_{text(functions[first].address)[2:]}.{ext}"
        last = functions[end - 1]
        units.append({"unit": name, "named_by": how, "first": first, "end": end,
                      "start": text(functions[first].address), "stop": text(last.address + last.size),
                      "start_key": functions[first].address, "end_key": last.address + last.size,
                      "functions": end - first})
    owner = {}
    for u in units:
        for i in range(u["first"], u["end"]):
            owner[i] = u["unit"]
    data = _data_ownership(program, ev, owner)
    by_unit = collections.defaultdict(list)
    for row in data:
        by_unit[row[2]].append(row)
    for u in units:
        u["data"] = [{"section": s, "start": text(a), "end": text(b), "start_key": a, "end_key": b}
                     for a, b, _, s in sorted(by_unit.get(u["unit"], []))]
    named = collections.Counter(u["named_by"] for u in units)
    return {"units": units, "boundaries": [{"before": text(functions[c.position].address),
                                            "window": [text(functions[c.window[0]].address),
                                                       text(functions[c.window[1]].address)],
                                            "crossings": c.crossings, "because": c.because} for c in cuts],
            "names": [{"address": text(functions[i].address), "current": functions[i].name, "proposed": n}
                      for i, n in sorted(ev.names.items())],
            "counts": {"units": len(units), "named_by": dict(named), "boundaries": len(cuts),
                       "data_ranges": len(data), "data_bytes": sum(b - a for a, b, _, _ in data),
                       "functions": len(functions)},
            "limits": "Boundaries need evidence: a run with none stays one unit (the coarsest split the evidence "
                      "allows), so a proposed unit can hold several original files. A boundary's window is where it "
                      "may go; compiling decides the exact place."}


def _function_classes(program: Program) -> dict[int, str]:
    """Function index -> the recovered class it belongs to (CodeWarrior tables; nothing elsewhere yet)."""
    if program.platform.name != "gamecube":
        return {}
    from .classes import recover
    from .vtables import find
    tables = find(program)
    found = recover(program, tables)
    out = {}
    for address, info in found.items():
        name = tables[address].name or f"TUnk_{program.platform.text(address)[2:]}"
        base = tables.get(info.base) if info.base else None
        own = [s for i, s in enumerate(tables[address].slots)
               if s and not (base and i < len(base.slots) and base.slots[i] == s)]
        for function in [*info.constructors, info.destructor, *own]:
            index = program.function_index.get(function)
            if index is not None:
                out.setdefault(index, name)
    return out


def _data_ownership(program: Program, ev: Evidence, owner: dict[int, str]) -> list[tuple[int, int, str, str]]:
    """(start, end, unit, section): data only one unit's code uses, and class tables whose constructors are all in
    one unit; neighbouring objects of one unit merge into one range."""
    owned: list[tuple[int, int, str, str]] = []
    for o, fs in ev.local.items():
        homes = {owner.get(i) for i in fs} - {None}
        if len(homes) == 1:
            owned.append((o.address, o.address + max(o.size, 1), next(iter(homes)), o.section))
    if program.platform.name == "gamecube":
        from .classes import recover
        from .vtables import find
        tables = find(program)
        for address, info in recover(program, tables).items():
            homes = {owner.get(program.function_index.get(c)) for c in info.constructors} - {None}
            if len(homes) == 1:
                owned.append((address, address + tables[address].size, next(iter(homes)), ".data"))
    owned.sort()
    merged: list[list] = []
    for start, end, unit, section in owned:
        if merged and merged[-1][2] == unit and merged[-1][3] == section and start - merged[-1][1] < 0x40 \
                and not any(s < start and e > merged[-1][1] for s, e, u, _ in owned if u != unit):
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, unit, section])
    return [tuple(m) for m in merged]


def write_splits(data: dict, path: Path) -> Path:
    """The proposal as a splits.txt (decomp-toolkit's format): one block per unit, code then its data."""
    lines = []
    for unit in data["units"]:
        lines.append(f"{unit['unit']}:")
        lines.append(f"\t{'.text':<12} start:0x{unit['start_key']:08X} end:0x{unit['end_key']:08X}")
        for row in unit.get("data", []):
            lines.append(f"\t{row['section']:<12} start:0x{row['start_key']:08X} end:0x{row['end_key']:08X}")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# A decomp in progress: its units against the evidence

@dataclass
class Units:
    """A decomp's units as ranges, with lookups by address."""
    ranges: list[tuple[int, int, str, str]]            # (start, end, unit, section)
    starts: list[int] = field(default_factory=list)

    def __post_init__(self):
        self.ranges.sort()
        self.starts = [r[0] for r in self.ranges]

    def at(self, address: int) -> str | None:
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0 and self.ranges[index][0] <= address < self.ranges[index][1]:
            return self.ranges[index][2]
        return None


def check(program: Program, splits: list[tuple[str, str, int, int]], limit: int = 60) -> dict[str, Any]:
    """Folds, splits and data claims the evidence proposes for an existing splits.txt."""
    ev = evidence(program)
    units = Units([(start, end, unit, section) for unit, section, start, end in splits])
    text = program.platform.text
    unit_of = [units.at(f.address) for f in program.functions]
    folds: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for lo, hi, because in ev.joins:
        homes = sorted({unit_of[i] for i in range(lo, hi + 1)} - {None})
        if len(homes) == 2:
            folds[tuple(homes)].append(because)
    splits_needed: dict[str, list] = collections.defaultdict(list)
    for lo, hi, because in ev.separations:
        inside = {unit_of[i] for i in range(lo - 1, hi + 1)}
        if len(inside) == 1 and None not in inside:
            splits_needed[next(iter(inside))].append((lo, hi, because))
    claims = []
    for o, fs in ev.local.items():
        homes = {unit_of[i] for i in fs} - {None}
        if len(homes) == 1 and units.at(o.address) is None:
            claims.append({"object": o.name, "address": text(o.address), "section": o.section, "size": o.size,
                           "unit": next(iter(homes)), "used_by": len(fs)})
    if program.platform.name == "gamecube":
        from .classes import recover
        from .vtables import find
        tables = find(program)
        names = {o.address: o.name for o in program.objects}
        for address, info in recover(program, tables).items():
            if units.at(address) is not None or not info.constructors:
                continue
            homes = {unit_of[program.function_index[c]] for c in info.constructors if c in program.function_index}
            homes.discard(None)
            if len(homes) == 1:
                claims.append({"object": names.get(address, "vtable"), "address": text(address), "section": ".data",
                               "size": tables[address].size, "unit": next(iter(homes)),
                               "used_by": len(info.constructors), "vtable": True})
    fold_rows = sorted(({"units": list(pair), "shared": len(why), "examples": why[:3]}
                        for pair, why in folds.items()), key=lambda r: -r["shared"])
    split_rows = sorted(({"unit": unit, "evidence": len(rows),
                          "window": [text(program.functions[rows[0][0] - 1].address),
                                     text(program.functions[rows[0][1]].address)],
                          "example": rows[0][2]} for unit, rows in splits_needed.items()),
                        key=lambda r: -r["evidence"])
    claims.sort(key=lambda c: (c["unit"], c["address"]))
    return {"folds": fold_rows[:limit], "folds_total": len(fold_rows), "splits": split_rows[:limit],
            "splits_total": len(split_rows), "claims": claims[:limit], "claims_total": len(claims),
            "claimed_bytes": sum(c["size"] for c in claims),
            "limits": "A fold means two units hold one unit's data (a literal, a static, a pool base, one file's "
                      "strings); a split means one unit holds two copies of one literal or code citing two files. "
                      "Claims are data in no unit that only one unit's code uses, and class tables in no unit whose "
                      "constructors are all in one unit. A claim that crosses another unit's range is a fold or a "
                      "data-only unit instead; the link order decides."}
