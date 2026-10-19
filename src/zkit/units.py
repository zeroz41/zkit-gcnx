"""Translation units from evidence in the original's code and data, proposed fresh or checked against a decomp's
existing splits. Each kind of evidence states the compiler or format fact it rests on, and applies only where
that fact holds:

- **file strings** (every platform): code citing one source path (`__FILE__` in asserts and logs) belongs to that
  file's unit; functions between two of the same file belong to it too; a function only one unit calls, placed
  beside it, is that unit's static helper. A header path is an inline compiled into its user, never an anchor.
- **another build** (the signatures of a build of the same code with units): a function matched there is in the
  unit that build put it in, where it cites no file itself, and counts like a file string. The linker keeps one
  order, so its units come out as runs here too.
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

from .program import CODE_SECTIONS, DataObject, Program

TIGHT = 60          # functions: data used across a wider run is shared (a global), not one unit's
LITERAL_SIZES = range(1, 65)
LITERAL_SECTIONS = (".sdata2", ".rodata", ".data")
WRITABLE_SECTIONS = (".data", ".bss", ".sdata", ".sbss")
WINDOW = 24         # functions on each side of a boundary whose references decide where it goes
FILL_FUNCTIONS, FILL_BYTES = 48, 0x8000  # between two functions of one file, fill only a gap this small
SOURCE = re.compile(r"\.(c|cc|cp|cpp|cxx|h|hh|hpp|inl|inc)$", re.I)
HEADER = re.compile(r"\.(h|hh|hpp|inl|inc)$", re.I)
BARE_SOURCE = re.compile(r"^[A-Za-z_][\w.+-]*\.(c|cc|cp|cpp|cxx)$", re.I)   # `__FILE__` compiled from its folder
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
    placed: set[int] = field(default_factory=set)              # function indexes whose file is another build's unit
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


def evidence(program: Program, placed: dict[int, str] | None = None) -> Evidence:
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
    _file_evidence(program, ev, placed)
    return ev


PIECE = re.compile(r"_[0-9A-Fa-f]{8,16}(?=\.\w+$)")   # `file_<address>.cpp`: a later piece of one file


def _file_evidence(program: Program, ev: Evidence, placed: dict[int, str] | None = None) -> None:
    """Source paths and `Class::method` names the code cites, and the unit another build of the same code put
    a function in (`placed`, by address: the signatures' donor unit) where it cites no file itself; file runs
    become joins, file changes separations. A donor's piece of a file (`file_<its address>.cpp`) counts as the
    file, so the pieces here take this build's addresses."""
    strings = program.strings()
    files = {a: s for a, s in strings.items() if SOURCE.search(s) and ("/" in s or "\\" in s or BARE_SOURCE.match(s))}
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
    for address, unit in (placed or {}).items():
        index = program.function_index.get(address)
        if index is not None and unit and index not in ev.files:
            ev.files[index] = PIECE.sub("", unit)
            ev.placed.add(index)
    # A unit's code is one run in the link: one function another build put in X between two that agree on Y is
    # no evidence for X there (an inline that build kept from X, code that moved, other code that compiles alike).
    anchors = sorted(ev.files.items())
    for (_, before), (index, unit), (_, after) in zip(anchors, anchors[1:], anchors[2:]):
        if index in ev.placed and before == after != unit:
            del ev.files[index]
            ev.placed.discard(index)
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
    folders (in any case: Windows paths spell one folder several ways), the longest directory prefix 80% of the
    group shares, and the one all of it shares for the paths outside that, keeping a folder of each path."""
    groups: dict[tuple, list[list[str]]] = collections.defaultdict(list)
    for path in paths:
        parts = _normalized(path).split("/")[:-1]
        if len(parts) >= 2:
            groups[tuple(p.casefold() for p in parts[:2])].append(parts)
    roots = []
    for members in groups.values():
        for share in (0.8, 1.0):
            prefix: list[str] = []
            while True:
                depth = len(prefix)
                counts = collections.Counter(tuple(q.casefold() for q in p[:depth + 1]) for p in members
                                             if len(p) > depth + 1 and [q.casefold() for q in p[:depth]] == prefix)
                if not counts:
                    break
                best, count = counts.most_common(1)[0]
                if count < share * len(members):
                    break
                prefix = list(best)
            spelled = next((p[:len(prefix)] for p in members if [q.casefold() for q in p[:len(prefix)]] == prefix),
                           [])
            if prefix and "/".join(spelled) + "/" not in roots:
                roots.append("/".join(spelled) + "/")
    return sorted(roots, key=len, reverse=True)


DRIVE = re.compile(r"^[A-Za-z]:$")


def _normalized(path: str) -> str:
    """A cited path with forward slashes and its `.` and `..` folders resolved (leading `..` kept)."""
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part == ".." and parts and parts[-1] != ".." and not DRIVE.match(parts[-1]):
            parts.pop()
        elif part not in (".", ""):
            parts.append(part)
    return "/".join(parts)


def _unit_name(path: str, roots: list[str]) -> str:
    path = _normalized(path)
    root = next((r for r in roots if path.casefold().startswith(r.casefold())), "")
    parts = [part for part in path[len(root):].split("/") if part]
    return "/".join(parts[1:] if parts and DRIVE.match(parts[0]) else parts)   # a drive letter is never a folder


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
        raise ValueError(f"Target {target} has no `splits` file to check (a splits.txt)")
    rows = read_splits(project.file(config["repository"], config["splits"]))
    return {"target": target, **check(Program.from_project(project, target), rows, limit)}


def propose(program: Program, fixed: list[dict[str, Any]] | None = None,
            placed: dict[int, str] | None = None) -> dict[str, Any]:
    """Units for every function from the evidence: boundaries, a name per unit, and the data each unit owns.
    `fixed` units ({unit, how, ranges: [(section, start, end)]}, from a linker map: mapalign.py) are taken as
    they are, code and data; the evidence decides the rest around them. `placed` ({function address: unit},
    from another build's units) counts like a source file a function cites."""
    ev = evidence(program, placed)
    cuts = boundaries(program, ev)
    text = program.platform.text
    functions = program.functions
    sections = [program.section_of(f.address) or "" for f in functions]
    held: dict[tuple[int, int], dict[str, Any]] = {}  # (first, end) function index -> the fixed unit
    for unit in fixed or ():
        for section, start, stop in unit["ranges"]:
            if section in CODE_SECTIONS:
                first = bisect.bisect_left(program._function_starts, start)
                end = bisect.bisect_left(program._function_starts, stop)
                if first < end:
                    held[(first, end)] = unit
    inside = {p for first, end in held for p in range(first + 1, end)}
    edges = sorted({0, len(functions), *(c.position for c in cuts if c.position not in inside),
                    *(p for p in range(1, len(functions)) if sections[p] != sections[p - 1]),   # a unit never
                    *(p for span in held for p in span)})                                       # spans two
    class_of = _function_classes(program)
    units = []
    reserved = {u["unit"] for u in held.values()}     # a fixed unit keeps its name in every code section
    taken: collections.Counter = collections.Counter()
    for first, end in zip(edges, edges[1:]):
        if first >= end:
            continue
        span = range(first, end)
        files = collections.Counter(ev.files[i] for i in span if i in ev.files)
        classes = collections.Counter(class_of[i] for i in span if i in class_of)
        if (first, end) in held:
            name, how = held[(first, end)]["unit"], held[(first, end)]["how"]
        else:
            if files:
                name = files.most_common(1)[0][0]
                how = "file string" if any(ev.files.get(i) == name and i not in ev.placed for i in span) \
                    else "another build"
            elif classes:
                name, how = classes.most_common(1)[0][0] + ".cpp", "class"
            else:
                name, how = f"unit_{text(functions[first].address)[2:]}.cpp", "placeholder"
            taken[name] += 1
            if taken[name] > 1 or name in reserved:   # one file in several pieces keeps one name per piece
                stem, dot, ext = name.rpartition(".")
                name = f"{stem}_{text(functions[first].address)[2:]}.{ext}"
        last = functions[end - 1]
        units.append({"unit": name, "named_by": how, "first": first, "end": end,
                      "section": sections[first] if sections[first].startswith(".") else ".text",
                      "start": text(functions[first].address), "stop": text(last.address + last.size),
                      "start_key": functions[first].address, "end_key": last.address + last.size,
                      "functions": end - first})
    owner = {}
    for u in units:
        for i in range(u["first"], u["end"]):
            owner[i] = u["unit"]
    spans = {(functions[first].address, functions[end - 1].address + functions[end - 1].size)
             for first, end in held}
    fixed_data = [(start, stop, unit["unit"], section) for unit in fixed or ()   # code with no functions in it
                  for section, start, stop in unit["ranges"]                   # (tables, entry labels) is data
                  if section not in CODE_SECTIONS or not any(a < stop and start < b for a, b in spans)]
    firm = {unit["unit"] for unit in fixed or () if unit["how"] == "source"}
    data = _data_ownership(program, ev, owner, fixed_data, firm)
    by_unit = collections.defaultdict(list)
    for row in data:
        by_unit[row[2]].append(row)
    for u in units:
        u["data"] = [{"section": s, "start": text(a), "end": text(b), "start_key": a, "end_key": b}
                     for a, b, _, s in sorted(by_unit.get(u["unit"], []))]
    coded = {u["unit"] for u in units}
    for unit in fixed or ():                          # a fixed unit with no functions: its ranges only
        rows = sorted(by_unit.get(unit["unit"], [])) if unit["unit"] not in coded else []
        if rows:
            units.append({"unit": unit["unit"], "named_by": unit["how"], "functions": 0, "start": text(rows[0][0]),
                          "stop": text(rows[0][1]), "data": [{"section": s, "start": text(a), "end": text(b),
                                                              "start_key": a, "end_key": b} for a, b, _, s in rows]})
    named = collections.Counter(u["named_by"] for u in units)
    return {"units": units, "boundaries": [{"before": text(functions[c.position].address),
                                            "window": [text(functions[c.window[0]].address),
                                                       text(functions[c.window[1]].address)],
                                            "crossings": c.crossings, "because": c.because} for c in cuts],
            "names": [{"address": text(functions[i].address), "current": functions[i].name, "proposed": n}
                      for i, n in sorted(ev.names.items())],
            "counts": {"units": len({u["unit"] for u in units}), "named_by": dict(named), "boundaries": len(cuts),
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


TABLES = (".ctors", ".dtors")      # pointer tables: one entry per unit's static initializer (finalizer)
LEADING = 4                        # .dtors entries the runtime's own can lead with


FIXED, FIRM = 8, 1 << 30   # a linker map's placement against claims of one object each; a unit with a source


def _data_ownership(program: Program, ev: Evidence, owner: dict[int, str],
                    fixed: list[tuple[int, int, str, str]] = (), firm: set[str] = frozenset()
                    ) -> list[tuple[int, int, str, str]]:
    """(start, end, unit, section): data only one unit's code uses, data only that data points to (a table of
    strings), and class tables whose constructors are all in one unit. The linker lays out every section in link
    order, one contiguous block per object, so in each section a unit owns one range, and the units' ranges come
    in the order of their code: a claim against that order is a reference from another unit, not ownership, and is
    dropped (the fewest claims that restore the order). A range always covers whole symbols. `fixed` ranges (a
    linker map's) take part in that order as `FIXED` claims each (the `firm` units' never give way: they have a
    source); one that stands is kept as given, and no claim crosses it or adds to its unit in its section."""
    from .link import LINKER_OBJECTS
    claims: list[tuple[int, int, str, str]] = []
    for o, fs in ev.local.items():
        homes = {owner.get(i) for i in fs} - {None}
        if o.name in LINKER_OBJECTS or o.section in TABLES:   # the linker's, or a table entry (below)
            continue
        if len(homes) == 1 and not program.in_code(o.address):      # data in code is in its unit's code range
            claims.append((o.address, o.address + max(o.size, 1), next(iter(homes)), o.section))
    if program.platform.name == "gamecube":
        from .classes import recover
        from .vtables import find
        tables = find(program)
        for address, info in recover(program, tables).items():
            homes = {owner.get(program.function_index.get(c)) for c in info.constructors} - {None}
            if len(homes) == 1:
                claims.append((address, address + tables[address].size, next(iter(homes)), ".data"))
        claims += _exception_tables(program, owner)
    claims += _through_data(program, ev, claims)
    order: dict[str, int] = {}                         # unit -> its place in link order (its first code)
    ordered = set()                                    # .init code says nothing of where its unit is linked
    for index in sorted(owner):
        if owner[index] not in order:
            order[owner[index]] = len(order)
            if program.section_of(program.functions[index].address) != ".init":
                ordered.add(owner[index])
    out: list[tuple[int, int, str, str]] = []
    if program.platform.name == "gamecube":
        claims += _initializer_tables(program, owner)
    by_section: dict[tuple[str, int], list] = collections.defaultdict(list)
    for claim in claims:
        by_section[(claim[3], _instance(program, claim[0]))].append(claim)
    pinned = {row: FIRM if row[2] in firm else FIXED for row in fixed}
    for row in pinned:
        by_section[(row[3], _instance(program, row[0]))].append(row)
    for (section, _), rows in by_section.items():
        rows = sorted(r if r in pinned else _whole_symbols(program, [r])[0] for r in rows)
        if section in TABLES and len(rows) > 1 and rows[0] not in pinned and rows[0][2] in order and \
                order[rows[0][2]] > min(order.get(r[2], 0) for r in rows[1:]):
            lead = rows.pop(0)                        # the runtime's leading entries: one range of their own
            while rows and rows[0][2] == lead[2] and rows[0][0] == lead[1] and rows[0] not in pinned:
                lead = (lead[0], rows.pop(0)[1], lead[2], section)
            out.append(lead)
        kept = _in_link_order([r for r in rows if r[2] in ordered], order, pinned) + \
            [r for r in rows if r[2] not in ordered]
        stand = [r for r in kept if r in pinned]      # a fixed range that agrees with the order stands as given
        fixed_units = {r[2] for r in stand}
        kept = [r for r in kept if r not in pinned and r[2] not in fixed_units
                and not any(a < r[1] and r[0] < b for a, b, _, _ in stand)]
        spans: dict[str, list[int]] = {}
        for start, stop, unit, _ in kept:
            span = spans.setdefault(unit, [start, stop])
            span[0], span[1] = min(span[0], start), max(span[1], stop)
        ranges = [(*_word_bounds(program, start, stop), unit, section) for unit, (start, stop) in spans.items()]
        last = None
        for row in sorted(ranges + stand):
            if last is not None and row[0] < last[1]:
                continue                               # overlaps the previous unit's range: no claim is safe
            out.append(row)
            last = row
    out.sort()
    return out


def _instance(program: Program, address: int) -> int:
    """Where the loaded range of the section holding an address starts. One name can be several ranges (an ELF's
    relro and data segments are both `.data`); a unit's range in one never reaches into another."""
    return next((start for _, start, end in program.sections if start <= address < end), 0)


def _through_data(program: Program, ev: Evidence, claims: list[tuple[int, int, str, str]]
                  ) -> list[tuple[int, int, str, str]]:
    """Data no code uses that only data one unit owns points to (the strings of a table, the entries of a table of
    tables) belongs to that unit too, as far as the pointers reach."""
    used = {o.address for o in program.users()}
    claimed = sorted((start, stop, unit) for start, stop, unit, _ in claims)
    starts = [c[0] for c in claimed]

    def claim_at(address: int) -> str | None:
        index = bisect.bisect_right(starts, address) - 1
        return claimed[index][2] if index >= 0 and address < claimed[index][1] else None
    holders: dict[DataObject, set[str | None]] = collections.defaultdict(set)
    pointed = [(h, program.object_at(p)) for h, p in program.pointers]
    out: list[tuple[int, int, str, str]] = []
    found = True
    while found:
        found = False
        holders.clear()
        for holder, target in pointed:
            if target is not None and target.address not in used and not program.in_code(target.address):
                holders[target].add(claim_at(holder))
        for target, units in holders.items():
            if len(units) == 1 and None not in units and claim_at(target.address) is None:
                row = (target.address, target.address + max(target.size, 1), next(iter(units)), target.section)
                out.append(row)
                index = bisect.bisect_left(starts, row[0])
                starts.insert(index, row[0])
                claimed.insert(index, row[:3])
                found = True
    return out


def _initializer_tables(program: Program, owner: dict[int, str]) -> list[tuple[int, int, str, str]]:
    """.ctors and .dtors entries, each the unit's whose function it points to (its static initializer or
    finalizer), not the unit of code that walks the table. The C++ runtime's entries lead the tables although its
    unit links late: the linker puts them first itself (see link.RUNTIME_MEMBER). That unit is the one the first
    `.ctors` entry points into, and the `.dtors` entries before the first that points into it are its own too
    (CodeWarrior's runtime: `__destroy_global_chain_reference`, then `__fini_cpp_exceptions_reference`)."""
    entries: dict[str, list[tuple[int, str | None]]] = collections.defaultdict(list)
    for o in program.objects:
        if o.section not in TABLES:
            continue
        for at in range(o.address, o.address + o.size - 3, 4):
            entries[o.section].append(
                (at, owner.get(program.function_index.get(int.from_bytes(program.read(at, 4), "big"), -1))))
    for rows in entries.values():
        rows.sort()
    runtime = entries[".ctors"][0][1] if entries.get(".ctors") else None
    lead = next((k for k, (_, unit) in enumerate(entries.get(".dtors", [])[:LEADING]) if unit == runtime), None)
    if runtime is not None and lead:                # its .dtors entries lead too, wherever they point (its
        rows = entries[".dtors"]                    # reference to the global destructor chain's code)
        rows[:lead] = [(at, runtime) for at, _ in rows[:lead]]
    return [(at, at + 4, unit, section) for section, rows in entries.items() for at, unit in rows if unit is not None]


def _exception_tables(program: Program, owner: dict[int, str]) -> list[tuple[int, int, str, str]]:
    """CodeWarrior writes a function's exception tables into its own object: each `extabindex` entry (function,
    size, `extab` record) and the record it points to belong to the function's unit."""
    from .link import LINKER_OBJECTS
    out = []
    for o in program.objects:
        if o.section != "extabindex" or o.size < 12:
            continue
        if o.name in LINKER_OBJECTS:
            continue
        for at in range(o.address, o.address + o.size - 11, 12):
            function, _, record = (int.from_bytes(program.read(at + 4 * k, 4), "big") for k in range(3))
            unit = owner.get(program.function_index.get(function, -1))
            if unit is None:
                continue
            out.append((at, at + 12, unit, "extabindex"))
            held = program.object_at(record)
            if held is not None and held.section == "extab":
                out.append((held.address, held.address + held.size, unit, "extab"))
    return out


def _whole_symbols(program: Program, rows: list[tuple[int, int, str, str]]) -> list[tuple[int, int, str, str]]:
    """Each claim widened to the data objects it touches: a unit's range never cuts a symbol."""
    out = []
    for start, stop, unit, section in rows:
        first, last = program.object_at(start), program.object_at(stop - 1)
        start = min(start, first.address) if first else start
        stop = max(stop, last.address + last.size) if last else stop
        out.append((start, stop, unit, section))
    return out


def _word_bounds(program: Program, start: int, stop: int) -> tuple[int, int]:
    """A unit's data range on word boundaries: no object's section starts off one (none of 4,001 in a CodeWarrior
    link map), so the objects up to the next word-aligned one are this unit's, and so is a start back to one."""
    starts = program._object_starts
    if start % 4:
        index = bisect.bisect_right(starts, start) - 1
        while index >= 0 and program.objects[index].address % 4:
            index -= 1
        start = program.objects[index].address if index >= 0 else start - start % 4
    if stop % 4:
        index = bisect.bisect_left(starts, stop)
        while index < len(starts) and program.objects[index].address % 4:
            index += 1
        same = index < len(starts) and program.objects[index].section == program.object_at(stop - 1).section \
            if program.object_at(stop - 1) else False
        stop = program.objects[index].address if same else stop  # a section's own end need not be a word's
    return start, stop


def _in_link_order(rows: list[tuple[int, int, str, str]], order: dict[str, int],
                   weights: dict[tuple, int] | None = None) -> list[tuple[int, int, str, str]]:
    """The heaviest run of claims (by address) whose units never go back in link order: each claim weighs 1
    unless `weights` says otherwise."""
    weights = weights or {}
    places = sorted({order[r[2]] for r in rows})
    rank = {place: k + 1 for k, place in enumerate(places)}
    tree: list[tuple[int, int]] = [(0, -1)] * (len(places) + 1)   # max (weight, row) over ranks up to k
    best, links = [], []
    for position, row in enumerate(rows):
        k, found = rank[order[row[2]]], (0, -1)
        while k > 0:
            found = max(found, tree[k])
            k -= k & -k
        total = found[0] + weights.get(row, 1)
        best.append(total)
        links.append(found[1])
        k = rank[order[row[2]]]
        while k < len(tree):
            tree[k] = max(tree[k], (total, position))
            k += k & -k
    kept, position = [], max(range(len(rows)), key=lambda i: (best[i], -i)) if rows else -1
    while position >= 0:
        kept.append(rows[position])
        position = links[position]
    return kept[::-1]


def write_splits(data: dict, path: Path) -> Path:
    """The proposal as a splits.txt: one block per unit (a unit with code in two sections, `.init` and `.text`,
    is one block), code then its data."""
    blocks: dict[str, list[tuple[str, int, int]]] = {}
    for unit in sorted(data["units"], key=lambda u: u.get("start_key", u["data"][0]["start_key"] if u.get("data")
                                                              else 0)):
        rows = blocks.setdefault(unit["unit"], [])
        if "start_key" in unit:                       # a unit with no functions has its data ranges only
            rows.append((unit.get("section", ".text"), unit["start_key"], unit["end_key"]))
        rows += [(row["section"], row["start_key"], row["end_key"]) for row in unit.get("data", [])]
    lines = []
    for name, rows in blocks.items():
        lines.append(f"{name}:")
        seen = set()
        for section, start, end in rows:
            if (section, start) not in seen:
                seen.add((section, start))
                lines.append(f"\t{section:<12} start:0x{start:08X} end:0x{end:08X}")
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
