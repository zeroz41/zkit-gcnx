"""Units, names and sizes from a linker map of another build of the same code (a debug build's map shipped on the
disc, an earlier or regional build's), wherever that build lines up with the original.

A map of the original itself would be the truth. A map of another build is truth only where the two builds hold
the same object: there the linker laid out the same functions and data in the same order with the same sizes,
and only the addresses moved. Where an object differs (assertions compiled in, code added or removed) the map
says nothing about the original, so everything here is decided per object, from the original's own bytes:

- **code**: both builds link their objects in one order, so the map's functions and the original's are aligned
  in order by size and by the space between consecutive functions. A run's evidence is the sum of -log2 of each
  size's frequency among the original's functions, less log2 of the places the search tried: the whole section
  first, then again between the runs found, where a run right after (or before) a found one in both builds has
  its place given. A run counts with `MARGIN` bits to spare (under 1% by chance). An object lines up when
  every function of its code lies in such runs, consecutively, and either every run has `SURE` bits to spare
  or its data confirms it (below: `CONFIRMING` references landing on its symbols' starts); its functions take
  the map's names, and its code range is the original's span of them. A function in a run with `SURE` bits
  to spare inside an object that does not line up as a whole still takes its name.
- **bounds**: an edge between two consecutive objects of the map is known in the original where the earlier
  one's last function or the later one's first lines up (a function in a run with `SURE` bits to spare, or
  in an object that lines up). An object with both edges known holds the original's code between them even
  where its code differs (assertions compiled in): it takes its name and that range, and its functions only
  the names their own runs prove.
- **data**: an object that lines up in code places each of its data pieces where the original's references put
  them: every address its code forms in that section, and every word its already placed data holds that points
  there, must fall inside the piece, and the piece goes at the one offset that lands the most of them on the
  starts of the map's symbols, and among those, the most on where the original's analysis starts an object (a
  tie, an offset that overlaps a placed piece, or one outside the section, places nothing). Data reached only
  through other data (a table of strings) is placed through the table. A placed piece's symbols take the map's
  names, sizes and scopes, so a symbol's size is its own and the alignment padding after it stays in the gap. An
  object whose edges are known but whose code differs places no data: its data may differ too (on Double Dash,
  such pieces placed by their references alone put a class table on zeros and another on a table of a different
  size). `.ctors` and `.dtors` entries
  are left to units.py, which gives each to the code it points to.

What does not line up is left to the evidence in the original (units.py).
"""

from __future__ import annotations

import bisect
import collections
import difflib
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import mwmap
from .program import CODE_SECTIONS, DataObject, Function, Program

MARGIN = 7.0            # bits a run of aligned functions needs beyond the places tried: under 1% by chance
SURE = 20.0             # bits beyond them that name a function, or line up an object, with no other evidence
CONFIRMING = 2          # references landing on the map's symbol starts that confirm an object with less
TABLES = (".ctors", ".dtors")
MANGLED = re.compile(r"__(?:\d|F|C[FV]|Q\d)|^__(?:ct|dt|vt|RTTI|sinit)")


@dataclass
class Unit:
    unit: str                                    # the source path it takes in splits.txt
    map_unit: str                                # the object as the map names it
    how: str                                     # "map" (lines up whole) or "bounds" (its edges do)
    ranges: list[tuple[str, int, int]] = field(default_factory=list)          # (section, start, end)
    unplaced: list[str] = field(default_factory=list)                          # data sections the map has for it


@dataclass
class Aligned:
    units: list[Unit]
    functions: dict[int, tuple[str, str, int]]   # address -> (name, scope, size)
    objects: dict[str, list[DataObject]]         # section -> the map's symbols where pieces are placed
    stats: dict[str, Any]


def source_name(unit: str, symbols: list[mwmap.Symbol]) -> str:
    """A map object as a source path: an archive member keeps its file name; a bare `x.o` is C++ when a symbol
    it defines has a C++ name, else C."""
    if not unit.endswith(".o"):
        return unit
    cxx = any(MANGLED.search(s.name) for s in symbols)
    return unit[:-2] + (".cpp" if cxx else ".c")


def _scope(scope: str) -> str:
    return "local" if scope == "local" else "global"


# Code

@dataclass
class _Run:
    first: int                  # map function index
    ours: int                   # our function index
    length: int
    margin: float               # bits of evidence beyond the placements the search tried


def _runs(map_functions: list[tuple[int, int]], ours: list[Function], bits_of) -> list[_Run]:
    """The runs that line up (equal sizes, equal spacing, `margin` >= `MARGIN`), searched first over the whole
    section, then again between the runs found, where the search tries fewer places: a run that starts right
    after a run in both builds (or at the section's start), or ends right before one, has its place given."""
    a = [s for _, s in map_functions]
    b = [f.size for f in ours]
    out: list[_Run] = []
    stack = [(0, len(a), 0, len(b))]
    while stack:
        i0, i1, j0, j1 = stack.pop()
        if i0 >= i1 or j0 >= j1:
            continue
        space = math.log2((i1 - i0) * (j1 - j0))
        found = []
        for block in difflib.SequenceMatcher(None, a[i0:i1], b[j0:j1], autojunk=False).get_matching_blocks():
            start = 0
            for k in range(1, block.size + 1):           # a run breaks where the space between functions differs
                x, y = i0 + block.a, j0 + block.b
                if k < block.size and map_functions[x + k][0] - map_functions[x + k - 1][0] == \
                        ours[y + k].address - ours[y + k - 1].address:
                    continue
                first, mine, length = x + start, y + start, k - start
                bits = sum(bits_of(b[mine + i]) for i in range(length))
                anchored = (first == i0 and mine == j0) or (first + length == i1 and mine + length == j1)
                margin = bits - (0.0 if anchored else space)
                if margin >= MARGIN:
                    found.append(_Run(first, mine, length, margin))
                start = k
        out += found
        edges = [(i0, j0)] + [(r.first + r.length, r.ours + r.length) for r in found]
        ends = [(r.first, r.ours) for r in found] + [(i1, j1)]
        if found:
            for (x0, y0), (x1, y1) in zip(edges, ends):
                stack.append((x0, x1, y0, y1))
    return sorted(out, key=lambda r: r.first)


def _bits(ours: list[Function]):
    counts = collections.Counter(f.size for f in ours)
    total = len(ours)
    return lambda size: -math.log2(max(counts.get(size, 0), 1) / total)


# Data

class _Placer:
    """Data pieces placed so far, and the words of the original that point somewhere."""

    def __init__(self, program: Program):
        self.program = program
        self.sections = {name: (start, end) for name, start, end in program.sections}
        self.held = dict(program.pointers)
        self.holders = sorted(self.held)
        self.object_starts = set(program._object_starts)
        self.placed: dict[str, list[tuple[int, int, str]]] = collections.defaultdict(list)   # section -> ranges

    def starts_on(self, start: int, offsets: list[int]) -> int:
        """How many of the map's symbol starts, placed at `start`, are where the original's own analysis starts an
        object (an address something forms or points to): what decides between places the references tie on."""
        return sum(1 for offset in offsets if start + offset in self.object_starts)

    def free(self, section: str, start: int, end: int) -> bool:
        return not any(a < end and start < b for a, b, _ in self.placed[section])

    def pointers_in(self, start: int, end: int) -> list[int]:
        lo, hi = bisect.bisect_left(self.holders, start), bisect.bisect_left(self.holders, end)
        return [self.held[h] for h in self.holders[lo:hi]]

    def place(self, piece: mwmap.Piece, known: set[int]) -> tuple[int, int] | None:
        """(start, references on symbol starts) of the piece in the original, from the addresses known to be in
        it: the one start that keeps all of them inside and lands the most on the map's symbols."""
        section = piece.section
        bounds = self.sections.get(section)
        if bounds is None or not known or not piece.symbols:
            return None
        offsets = sorted({s.address - piece.address for s in piece.symbols})
        size = piece.size + -piece.size % 4         # every object's section starts on a word: the rest is padding
        scores: collections.Counter = collections.Counter()
        for target in known:
            for offset in offsets:
                if (target - offset) % 4 == 0:
                    scores[target - offset] += 1
        ranked = sorted(((hits, self.starts_on(start, offsets), start) for start, hits in scores.items()
                         if all(start <= t < start + size for t in known)
                         and bounds[0] <= start and start + size <= bounds[1]), reverse=True)
        if not ranked or (len(ranked) > 1 and ranked[1][:2] == ranked[0][:2]):
            return None
        hits, _, start = ranked[0]
        if not self.free(section, start, start + size):
            return None
        self.placed[section].append((start, start + size, piece.unit))
        return start, hits


@dataclass
class _Code:
    section: str
    pieces: list[mwmap.Piece]                        # the map's objects with code here, in link order
    ours: list[Function]
    members: dict[int, list[int]]                    # piece index -> its map function indices
    symbols: list[mwmap.Symbol]                      # map function index -> its symbol
    partner: dict[int, tuple[int, float]]            # map function index -> (our function index, its run's margin)
    owner: dict[int, int] = field(default_factory=dict)   # map function index -> its piece index

    def whole(self, index: int) -> tuple[int, int, bool] | None:
        """(our first, our end, every run sure) when every function of a piece lines up, consecutively."""
        ms = self.members[index]
        if not all(m in self.partner for m in ms) or \
                any(self.partner[ms[k + 1]][0] != self.partner[ms[k]][0] + 1 for k in range(len(ms) - 1)):
            return None
        return self.partner[ms[0]][0], self.partner[ms[-1]][0] + 1, min(self.partner[m][1] for m in ms) >= SURE

    def bounds(self, trusted: dict[int, int]) -> dict[int, tuple[int, int]]:
        """piece index -> our (start, end) address where both its edges are known: an edge between two pieces is
        the end of the earlier one's last function or the start of the later one's first, where that function
        lines up (both, where both do, must agree), and the section's own edges."""
        count = len(self.pieces)
        edge: list[int | None] = [None] * (count + 1)
        edge[0], edge[count] = self.ours[0].address, self.ours[-1].address + self.ours[-1].size
        for index in range(count):
            ms = self.members[index]
            for at, m, end in ((index, ms[0], False), (index + 1, ms[-1], True)):
                if m not in trusted:
                    continue
                function = self.ours[trusted[m]]
                value = function.address + function.size if end else function.address
                if edge[at] is None:
                    edge[at] = value
                elif edge[at] != value and 0 < at < count:
                    edge[at] = -1                    # the two sides disagree: something lies between them
        out = {}
        for index in range(count):
            start, end = edge[index], edge[index + 1]
            if start is None or end is None or start < 0 or end < 0 or start >= end:
                continue
            inside = [self.ours[trusted[m]].address for m in self.members[index] if m in trusted]
            if all(start <= a < end for a in inside):
                out[index] = (start, end)
        return out


def _code(program: Program, layout: mwmap.Layout, section: str) -> _Code | None:
    pieces = [p for p in layout.pieces.get(section, []) if any(s.size and s.kind in ("func", "") for s in p.symbols)]
    ours = [f for f in program.functions if program.section_of(f.address) == section]
    if not pieces or not ours:
        return None
    map_functions, members, symbols = [], collections.defaultdict(list), []
    for index, piece in enumerate(pieces):
        seen = set()
        for symbol in piece.symbols:
            if symbol.size and symbol.address not in seen and symbol.kind in ("func", ""):
                seen.add(symbol.address)
                members[index].append(len(map_functions))
                map_functions.append((symbol.address, symbol.size))
                symbols.append(symbol)
    partner: dict[int, tuple[int, float]] = {}
    for run in _runs(map_functions, ours, _bits(ours)):
        for k in range(run.length):
            partner[run.first + k] = (run.ours + k, run.margin)
    owner = {m: index for index, ms in members.items() for m in ms}
    return _Code(section, pieces, ours, dict(members), symbols, partner, owner)


def _place_data(program: Program, pieces_by_unit: dict[str, dict[str, mwmap.Piece]],
                code: dict[str, list[tuple[str, int, int]]]):
    """Every data piece of the given objects that the original's references place: {map unit: [(section, start,
    end)]}, {map unit: references on symbol starts}, the map's symbols at their places, and the pieces left.
    `.ctors` and `.dtors` are left to units.py: their entries belong to the unit whose code they point to, except
    the runtime's references the linker puts first."""
    placer = _Placer(program)
    for map_unit, ranges in code.items():
        for section, start, end in ranges:
            placer.placed[section].append((start, end, map_unit))
    known: dict[tuple[str, str], set[int]] = collections.defaultdict(set)     # (map unit, our section) -> addresses
    owner = sorted((start, end, map_unit) for map_unit, ranges in code.items() for _, start, end in ranges)
    starts = [r[0] for r in owner]
    for index, function in enumerate(program.functions):
        at = bisect.bisect_right(starts, function.address) - 1
        if at < 0 or function.address >= owner[at][1]:
            continue
        for _, address, _ in program.refs.get(index, ()):
            held = program.section_of(address)
            if held and held not in CODE_SECTIONS:
                known[(owner[at][2], held)].add(address)
    placed: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    hits: collections.Counter = collections.Counter()
    objects: dict[str, list[DataObject]] = collections.defaultdict(list)
    pending = sorted((pieces_by_unit[u][s].address, u, s) for u in code for s in pieces_by_unit[u]
                     if s not in CODE_SECTIONS and s not in TABLES)
    progress = True
    while progress:
        progress = False
        for row in list(pending):
            _, map_unit, section = row
            piece = pieces_by_unit[map_unit][section]
            found = placer.place(piece, known.get((map_unit, section), set()))
            if found is None:
                continue
            start, landed = found
            hits[map_unit] += landed
            for symbol in piece.symbols:
                at = start + symbol.address - piece.address
                objects[section].append(DataObject(at, symbol.size, symbol.name, section, _scope(symbol.scope),
                                                   _data_kind(program, at, symbol.size, section)))
            for pointee in placer.pointers_in(start, start + piece.size):
                held_in = program.section_of(pointee)
                if held_in and held_in not in CODE_SECTIONS:
                    known[(map_unit, held_in)].add(pointee)
            placed[map_unit].append((section, start, start + piece.size + -piece.size % 4))
            pending.remove(row)
            progress = True
    return placed, hits, objects, [(u, s) for _, u, s in pending]


def align(program: Program, layout: mwmap.Layout) -> Aligned:
    """The map's objects that line up with the program, with their ranges, names and sizes."""
    pieces_by_unit: dict[str, dict[str, mwmap.Piece]] = collections.defaultdict(dict)
    for section, rows in layout.pieces.items():
        for piece in rows:
            pieces_by_unit[piece.unit].setdefault(section, piece)
    sections = [c for c in (_code(program, layout, s) for s in CODE_SECTIONS) if c is not None]
    candidates: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    sure: dict[str, bool] = collections.defaultdict(lambda: True)
    for c in sections:
        for index in range(len(c.pieces)):
            whole = c.whole(index)
            if whole is not None:
                first, end, all_sure = whole
                unit = c.pieces[index].unit
                candidates[unit].append((c.section, c.ours[first].address,
                                         c.ours[end - 1].address + c.ours[end - 1].size))
                sure[unit] = sure[unit] and all_sure
    _, hits, _, _ = _place_data(program, pieces_by_unit, candidates)
    lined = {u: ranges for u, ranges in candidates.items() if sure[u] or hits[u] >= CONFIRMING}

    functions: dict[int, tuple[str, str, int]] = {}
    bounded: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    for c in sections:
        trusted = {m: o for m, (o, margin) in c.partner.items()
                   if margin >= SURE or c.pieces[c.owner[m]].unit in lined}
        for m, o in trusted.items():
            symbol = c.symbols[m]
            functions[c.ours[o].address] = (symbol.name, _scope(symbol.scope), symbol.size)
        for index, (start, end) in c.bounds(trusted).items():
            unit = c.pieces[index].unit
            if unit not in lined:
                bounded[unit].append((c.section, start, end))
    placed, hits, objects, unplaced = _place_data(program, pieces_by_unit, lined)
    units: list[Unit] = []
    for how, found in (("map", lined), ("bounds", bounded)):
        for map_unit, ranges in found.items():
            symbols = [s for p in pieces_by_unit[map_unit].values() for s in p.symbols]
            units.append(Unit(source_name(map_unit, symbols), map_unit, how,
                              sorted(ranges + placed.get(map_unit, []), key=lambda r: r[1])))
    for map_unit, section in unplaced:
        next(u for u in units if u.map_unit == map_unit).unplaced.append(section)
    stats: dict[str, Any] = {"map_units": len(pieces_by_unit)}
    for c in sections:
        stats[f"{c.section} functions"] = {"map": len(c.symbols), "original": len(c.ours), "aligned": len(c.partner)}
    stats.update({"functions_named": len(functions), "units_lined_up": len(lined),
                  "units_confirmed_by_data": sum(1 for u in lined if not sure[u]), "units_bounded": len(bounded),
                  "data_pieces_placed": sum(len(v) for v in placed.values()), "data_pieces_unplaced": len(unplaced),
                  "data_symbols": sum(len(v) for v in objects.values())})
    return Aligned(sorted(units, key=lambda u: min(r[1] for r in u.ranges)), functions, dict(objects), stats)


def _data_kind(program: Program, address: int, size: int, section: str) -> str:
    """`string` when the bytes are printable text ending in its NUL exactly at the symbol's end."""
    if section in (".bss", ".sbss", ".sbss2") or size < 2:
        return ""
    try:
        raw = program.read(address, size)
    except ValueError:
        return ""
    if raw[-1] == 0 and raw[:-1] and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in raw[:-1]):
        return "string"
    return ""


def apply(program: Program, aligned: Aligned) -> Program:
    """The program with the map's names on the functions that line up, and the map's symbols in place of what
    the original's analysis found inside each placed data piece. An object the analysis found that starts before
    a piece and runs into it ends where the piece begins; one that starts inside and runs past it leaves its rest
    to an object at the piece's end, unless that rest is zero padding in initialized data."""
    pieces = sorted((start, end) for u in aligned.units for section, start, end in u.ranges
                    if section not in CODE_SECTIONS and section not in TABLES and section in aligned.objects)
    placed = {o.address: o for objects in aligned.objects.values() for o in objects}
    starts = [a for a, _ in pieces]

    def piece_at(address: int) -> tuple[int, int] | None:
        index = bisect.bisect_right(starts, address) - 1
        return pieces[index] if index >= 0 and address < pieces[index][1] else None
    objects: list[DataObject] = []
    for o in program.objects:
        held = piece_at(o.address)
        if held is not None:
            if o.address + o.size > held[1] and not any(held[1] <= p.address < o.address + o.size
                                                        for p in program.objects) \
                    and (o.section in (".bss", ".sbss", ".sbss2")
                         or any(program.read(held[1], o.address + o.size - held[1]))):
                objects.append(DataObject(held[1], o.address + o.size - held[1], f"lbl_{held[1]:08X}", o.section,
                                          "global"))
            continue
        index = bisect.bisect_left(starts, o.address + 1)
        if index < len(pieces) and pieces[index][0] < o.address + o.size:
            o = DataObject(o.address, pieces[index][0] - o.address, o.name, o.section, o.scope, o.data)
        objects.append(o)
    objects += placed.values()
    functions = [Function(f.address, f.size, *aligned.functions[f.address][:2])
                 if f.address in aligned.functions and aligned.functions[f.address][2] == f.size else f
                 for f in program.functions]
    out = Program(program.platform, program.image, functions, objects, program.sda)
    out.labels = [label for label in program.labels if piece_at(label.address) is None]
    out.sections = list(program.sections)
    out._refs, out._calls, out._pointers = program._refs, program._calls, program._pointers   # same functions
    out.cache.update({k: v for k, v in program.cache.items() if k == "discovered"})
    return out


def fixed(aligned: Aligned) -> list[dict[str, Any]]:
    """The units as units.propose takes them."""
    return [{"unit": u.unit, "how": u.how, "ranges": list(u.ranges)} for u in aligned.units]


def find_maps(folder: Path) -> list[Path]:
    """CodeWarrior linker maps under a folder (a disc's files): any `.map` whose first line is a link map's."""
    out = []
    for path in sorted(folder.rglob("*")):
        if path.suffix.lower() != ".map" or not path.is_file():
            continue
        with path.open("rb") as stream:
            head = stream.read(64)
        if head.lstrip().startswith(b"Link map of"):
            out.append(path)
    return out


def project_maps(project, target: str) -> list[Path]:
    """The linker maps that came with a target's original: under the folder its disc was extracted to."""
    config = project.target(target)
    original = project.file(config["repository"], config["original"])
    folder = original.parent.parent if original.parent.name == "sys" else original.parent
    return find_maps(folder)


def best(program: Program, maps: list[Path]) -> tuple[Path, Aligned] | None:
    """The map that lines up the most objects with the program, and its alignment."""
    found = [(path, align(program, mwmap.layout(path))) for path in maps]
    found = [f for f in found if f[1].stats["units_lined_up"]]
    return max(found, key=lambda f: f[1].stats["units_lined_up"]) if found else None


def _with_sources(project, config: dict, units: set[str]) -> set[str]:
    """The units that have a source in the repository: `src/<unit>`, or the source objdiff's project file gives."""
    root = project.root(config["repository"])
    out = {unit for unit in units if (root / "src" / unit).is_file()}
    objdiff = root / config["objdiff"] if config.get("objdiff") else None
    if objdiff is not None and objdiff.is_file():
        import json
        for row in json.loads(objdiff.read_text(encoding="utf-8")).get("units", []):
            source = (row.get("metadata") or {}).get("source_path")
            if source and (root / source).is_file():
                out |= {unit for unit in units if source == unit or source.endswith("/" + unit)}
    return out


def adopt_project(project, target: str, map_path: Path | None = None, write: bool = False) -> dict[str, Any]:
    """A target's units, names and sizes with a linker map of another build applied where it lines up; `write`
    rewrites the target's splits.txt and symbols.txt.

    Work in progress stays as it is. A unit that has a source keeps its ranges, and its symbols keep their names
    and sizes (its source spells them; the map's names there are only listed); a map object that overlaps it is
    left out. Elsewhere a name the symbols file already gives (not a placeholder) is kept, and listed where the
    map names the place otherwise. Units with no source are configuration only and give way to the evidence."""
    from . import units
    from .gc import read_splits
    from .new import write_symbols
    from .score import placeholder
    config = project.target(target)
    program = Program.from_project(project, target)
    maps = [map_path] if map_path else project_maps(project, target)
    if not maps:
        raise ValueError(f"No linker map given or found next to {config['original']}: pass --map FILE")
    chosen = best(program, maps)
    if chosen is None:
        raise ValueError(f"Nothing in {', '.join(str(m) for m in maps)} lines up with the original")
    path, aligned = chosen
    splits = project.file(config["repository"], config["splits"]) if config.get("splits") else None
    before: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    if splits is not None and splits.is_file():
        for unit, section, start, end in read_splits(splits):
            before[unit].append((section, start, end))
    worked = [{"unit": u, "how": "source", "ranges": before[u]} for u in sorted(_with_sources(project, config,
                                                                                             set(before)))]
    held = sorted((start, end) for u in worked for _, start, end in u["ranges"])
    starts = [h[0] for h in held]

    def in_work(address: int) -> bool:
        index = bisect.bisect_right(starts, address) - 1
        return index >= 0 and address < held[index][1]
    named = {f.address: f.name for f in program.functions} | {o.address: o.name for o in program.objects}
    offered = sum(1 for a, (name, _, _) in aligned.functions.items() if in_work(a) and named.get(a) != name) + \
        sum(1 for objects in aligned.objects.values() for o in objects
            if in_work(o.address) and named.get(o.address) != o.name)
    aligned.functions = {a: v for a, v in aligned.functions.items() if not in_work(a)}
    aligned.objects = {s: [o for o in objects if not in_work(o.address)] for s, objects in aligned.objects.items()}
    names = {u["unit"] for u in worked}
    aligned.units = [u for u in aligned.units if u.unit not in names and not any(
        start < h_end and h_start < end for _, start, end in u.ranges for h_start, h_end in held)]
    kept = {}
    for f in program.functions:
        if f.address in aligned.functions and not placeholder(f.name) and f.name != aligned.functions[f.address][0]:
            kept[f.address] = (f.name, aligned.functions[f.address][0])
            aligned.functions[f.address] = (f.name, f.scope, f.size)
    current = {o.address: o for o in program.objects}
    for section, objects in aligned.objects.items():
        for index, o in enumerate(objects):
            mine = current.get(o.address)
            if mine is not None and not placeholder(mine.name) and mine.name != o.name:
                kept[o.address] = (mine.name, o.name)
                objects[index] = DataObject(o.address, o.size, mine.name, o.section, mine.scope, o.data)
    adopted = apply(program, aligned)
    proposal = units.propose(adopted, worked + fixed(aligned))
    out: dict[str, Any] = {"target": target, "map": str(path), **aligned.stats,
                           "units": proposal["counts"]["units"], "named_by": proposal["counts"]["named_by"],
                           "kept_names": [{"address": f"0x{a:08X}", "kept": k, "map": m}
                                          for a, (k, m) in sorted(kept.items())],
                           "units_with_source": len(worked), "map_names_in_units_with_source": offered}
    if write:
        symbols = project.file(config["repository"], config["symbols"])
        if symbols.is_file():
            update_symbols(symbols, adopted)
        else:
            write_symbols(adopted, symbols)
        units.write_splits(proposal, splits)
        out["written"] = [str(symbols), str(splits)]
    return out


def update_symbols(path: Path, program: Program) -> Path:
    """A symbols.txt brought to a program's names, sizes and scopes line by line, so attributes zkit does not
    model (alignment, `hidden`, `noreloc`, ...) stay: an object the program no longer has (the map's symbols
    replaced it) goes, one it adds is appended, and every other line is kept as it is."""
    from .gc import SYMBOL_LINE
    functions = {f.address: f for f in program.functions}
    objects = {o.address: o for o in program.objects}
    lines, seen = [], set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = SYMBOL_LINE.match(line.strip())
        attrs = dict(part.split(":", 1) for part in match["attrs"].split() if ":" in part) if match else {}
        kind = attrs.get("type")
        if not match or kind not in ("function", "object"):
            lines.append(line)
            continue
        address = int(match["address"], 16)
        found = functions.get(address) if kind == "function" else objects.get(address)
        if found is None:
            if kind == "object" and attrs.get("size"):
                continue                                # replaced by what the program places here
            lines.append(line)
            continue
        seen.add((kind, address))
        rest = match["attrs"]
        for key, value in (("size", f"0x{found.size:X}"), ("scope", found.scope)):
            rest = re.sub(rf"\b{key}:\S+", f"{key}:{value}", rest) if f"{key}:" in rest else f"{rest} {key}:{value}"
        if kind == "object" and found.data and "data:" not in rest:
            rest += f" data:{found.data}"
        lines.append(f"{found.name} = {match['section']}:0x{address:08X}; //{rest}")
    for o in program.objects:
        if ("object", o.address) not in seen:
            lines.append(f"{o.name} = {o.section}:0x{o.address:08X}; // type:object size:0x{o.size:X} "
                         f"scope:{o.scope}" + (f" data:{o.data}" if o.data else ""))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

