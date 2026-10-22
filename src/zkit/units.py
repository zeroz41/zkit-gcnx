"""Translation units from evidence in the original's code and data, proposed fresh or checked against a decomp's
existing splits. Each kind of evidence states the compiler or format fact it rests on, and applies only where
that fact holds:

- **file strings** (every platform): code citing one source path (`__FILE__` in asserts and logs) belongs to that
  file's unit; functions between two of the same file belong to it too; a function only one unit calls, placed
  beside it, is that unit's static helper. A header path is an inline compiled into its user, never an anchor.
- **classes** (a module whose symbol table marks inlines and template instances weak): a class's strong functions
  are compiled in the one file its cited functions cite, so they count like that file's string beside its
  citations.
- **another build** (the signatures of a build of the same code with units): a function matched there is in the
  unit that build put it in, where it cites no file itself, and counts like a file string. The linker keeps one
  order, so its units come out as runs here too. Its boundaries yield to the code's own between the same two
  files, never where it puts a third file between them; its unit for a function yields where the code joins that
  function to another file's.
- **reach**: a file's evidence reaches through the data its code shares and a short way past it; a longer run tied
  to neither of two files is a unit of its own (a library no string names), not either file's.
- **separation** (compilers that give every unit its own literals: CodeWarrior): two copies of one constant are
  in two units, so a boundary lies between the functions using them.
- **join**: data only a tight run of functions uses belongs to one unit, so no boundary falls inside that run.
  Writable statics count everywhere; literals only where they are per unit (clang shares them across units).
  A global holds its users together wrongly where several files use it: two functions citing different files
  themselves are in different units whatever data joins them, unless the files' citations interleave (one file
  includes the other).
- **merged literals** (a linker keeping one copy of each literal for the module: clang's strings and constants):
  each kind is one block, the first unit's copy of each literal in it, so a literal is its first user's and a
  unit owns a range in each block (strings, constants, other read-only data).
- **first use** (an ELF module marking inlines and template instances weak): every unit using one compiles it
  after its first use there and the linker keeps the first unit's copy, so it is in its earliest user's unit.
- **order**: a boundary between functions is one in each data section too, so it goes where the fewest
  references would land on the wrong side; among equal places, where it splits the fewest classes' own
  functions and the fewest short calls (a static helper sits beside its callers).
- **names**: a unit with no file string is named after the class its functions belong to.
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
    cited: list[tuple[int, int, str]] = field(default_factory=list)   # joins of runs whose code cites one file
    firsts: list[tuple[int, int, str]] = field(default_factory=list)  # joins of a weak function and its first user
    direct: set[tuple[int, int, str]] = field(default_factory=set)    # separations the code itself states
    borrowed: set[tuple[int, int, str]] = field(default_factory=set)  # separations only another build gives
    inlines: dict[int, str] = field(default_factory=dict)      # function index -> header it cites (inline)
    names: dict[int, str] = field(default_factory=dict)        # function index -> `Class::method` it cites
    placed: set[int] = field(default_factory=set)              # function indexes whose file is another build's unit
    classed: set[int] = field(default_factory=set)             # function indexes whose file is their class's
    pairs: dict[tuple[int, int, str], tuple[str, str]] = field(default_factory=dict)  # separation -> its files
    edges: dict[tuple[int, int, str], int] = field(default_factory=dict)   # where a file's evidence ends or
                                                                           # starts -> the side it is on
    roots: list[str] = field(default_factory=list)
    apart: list[tuple[int, int, str]] = field(default_factory=list)   # separations placed after all the others:
                                                                      # only where those left none

    def joined(self, count: int, joins: list[tuple[int, int, str]] | None = None) -> list[bool]:
        """joined[p]: a boundary before function p would split one unit (by `joins`, default all of them)."""
        cover = [0] * (count + 2)
        for lo, hi, _ in self.joins if joins is None else joins:
            if hi > lo:
                cover[lo + 1] += 1
                cover[hi + 1] -= 1
        out, running = [False] * (count + 1), 0
        for p in range(1, count + 1):
            running += cover[p]
            out[p] = running > 0
        return out


def _initialized(program: Program) -> set[int]:
    """Switch: the data objects some unit's own static initializer stores into (`_initializers`): globals that unit
    defines (a class's `m_rtti`), which other units' code (their initializers' parent tables, a type test)
    reaches through the GOT, so the functions near each other that use one are no one unit's for it."""
    from .aarch64 import global_stores
    out: set[int] = set()
    initializers = _initializers(program)
    load64 = program.image.pointers.get if initializers else None
    for index in initializers:
        function = program.functions[index]
        words = program.platform.words(program.image, function.address, function.size)
        for address in global_stores(words, function.address, load64):
            found = program.object_at(address)
            if found is not None:
                out.add(found.address)
    return out


def evidence(program: Program, placed: dict[int, str] | None = None) -> Evidence:
    users = program.users()
    local = {o: sorted(fs) for o, fs in users.items() if fs and max(fs) - min(fs) <= TIGHT}
    initialized = _initialized(program)
    per_unit = program.platform.literals_per_unit
    text = program.platform.text
    joins = [(fs[0], fs[-1], f"{o.name} ({o.section}) is one unit's") for o, fs in local.items()
             if fs[-1] > fs[0] and (o.section in WRITABLE_SECTIONS or per_unit) and o.address not in initialized]
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
    firsts = _first_users(program)
    ev = Evidence(local, joins + firsts, separations, firsts=firsts)
    _file_evidence(program, ev, placed)
    ev.joins += _table_joins(program, ev)
    _out_of_line_calls(program, ev)
    _initializer_ends(program, ev)
    _start_up_object(program, ev)
    return ev


def _table_joins(program: Program, ev: Evidence) -> list[tuple[int, int, str]]:
    """Itanium (Switch): the functions only one class table holds (its class's own virtuals, not a base's or an
    inline another table shares) are one unit's: the class's file defines its methods, and clang emits the table and
    the inline virtuals only it holds in one unit. For a table no symbol names (a class an update added, whose
    functions no name ties to a class either), as far as a tight run reaches, never across two files the code
    itself cites (a method defined in another file). A named class's functions go by their class (`_class_files`).
    A table with a key function is emitted with it, and the code forming its address (the class's constructors and
    destructors, or the enclosing class's code they are inlined in) is there too: with the functions only that
    table holds, inlines included, it is one unit's, as far as a tight run reaches where no file the code cites or
    another build places changes within it (a nested listener's one virtual after its owner's code)."""
    if program.platform.name != "switch":
        return []
    from .itanium import _groups
    from .score import placeholder
    weak = set(getattr(program.image, "weak", ())) | {f.address for f in program.functions if f.scope == "weak"}
    formed = {address for rows in program.refs.values() for _, address, kind in rows if kind == "addr"}
    holders: dict[int, list[int]] = {}
    for o in program.objects:                          # a table's start: its name, or code forming its address
        if o.section != ".data":                       # point, 16 bytes in (one object, or two at that point)
            continue
        if o.name.startswith("_ZTV") or o.size >= 24 and o.address + 16 in formed:
            start, size = o.address, o.size
        elif o.address in formed and o.address - 16 not in holders and \
                (head := program.object_at(o.address - 16)) is not None and head.address == o.address - 16:
            start, size = head.address, 16 + o.size
        else:
            continue
        groups = _groups(program, start, size)
        if groups:
            holders[start] = [s for g in groups for s in g.slots if isinstance(s, int)]
    count = collections.Counter(s for slots in holders.values() for s in set(slots))
    index = program.function_index
    own_files = {i: f for i, f in ev.files.items() if i not in ev.placed}
    text = program.platform.text
    users = program.users()
    out = []
    # an inline virtual several tables with key functions hold: each of their units emits a copy, and the link
    # keeps the first, so it is in the earliest unit's code that forms one of those tables' addresses
    earliest: dict[int, tuple[int, int]] = {}
    for address, slots in holders.items():
        table = program.object_at(address)
        if table.scope == "weak" or table.address in weak:
            continue
        formers = set().union(*(users.get(o, ()) for o in {table, program.object_at(address + 16)} if o))
        for s in set(slots):
            if formers and s in weak and count[s] > 1 and s in index and \
                    min(formers) < earliest.get(index[s], (len(program.functions), 0))[0]:
                earliest[index[s]] = (min(formers), address)
    for target, (first, address) in sorted(earliest.items()):
        if first < target and target - first <= TIGHT and \
                len({ev.files[i] for i in range(first, target + 1) if i in ev.files}) <= 1:
            out.append((first, target, f"{program.functions[target].name} is first emitted with the table at "
                                       f"{text(address)}"))
    for address, slots in holders.items():
        table = program.object_at(address)
        run = set()
        if table.scope != "weak" and table.address not in weak:
            formers = set().union(*(users.get(o, ()) for o in {table, program.object_at(address + 16)} if o))
            held = {index[s] for s in slots if count[s] == 1 and s in index}
            if formers and held:
                run = formers | held
        if run and max(run) - min(run) <= TIGHT and \
                len({ev.files[i] for i in range(min(run), max(run) + 1) if i in ev.files}) <= 1:
            out.append((min(run), max(run), f"the table at {text(address)}, the code forming its address and "
                                            "the functions only it holds"))
            continue
        if not placeholder(table.name) or \
                not placeholder(getattr(program.object_at(address + 16), "name", "lbl_")):
            continue                                   # a named class: its functions go by their class
        own = sorted({index[s] for s in slots if count[s] == 1 and s in index and s not in weak})
        if len(own) < 2 or own[-1] - own[0] > TIGHT:
            continue
        if len({own_files[i] for i in range(own[0], own[-1] + 1) if i in own_files}) > 1:
            continue
        out.append((own[0], own[-1], f"the functions only the table at {text(address)} holds"))
    return out


INLINE_INSTRUCTION, INLINE_CALL = 5, 25    # LLVM's inline cost of an instruction and of a call it makes
INLINED = 150       # well under the -O2/-O3 threshold (225/250): a callee this cheap is always inlined


def _out_of_line_calls(program: Program, ev: Evidence) -> None:
    """Switch (clang -O3): a direct call to a cheap function the same file defines is always inlined, so a call to
    one that stayed a call is to another file's (a base class's constructor, a utility's accessor): a boundary
    lies between the two, placed after every other boundary and only where those left none. Cheap is LLVM's
    inline cost, not size: a short function making several calls stays a call within its file. Not for a
    function a class table holds, whose call may have been a virtual one the optimizer turned direct after
    inlining."""
    if program.platform.name != "switch":
        return
    held = {pointee for _, pointee in program.pointers}
    functions = program.functions
    for caller, callees in program.calls.items():
        for callee in callees:
            function = functions[callee]
            made = len(program.calls.get(callee, ()))
            cost = INLINE_INSTRUCTION * max(function.size // 4 - made, 0) + INLINE_CALL * made
            if callee == caller or cost > INLINED or function.address in held or abs(callee - caller) > TIGHT:
                continue
            lo, hi = min(caller, callee) + 1, max(caller, callee)
            ev.apart.append((lo, hi, f"{functions[caller].name} calls {function.name} "
                                     f"({function.size} bytes) without inlining it"))


def _first_users(program: Program) -> list[tuple[int, int, str]]:
    """An ELF module whose symbols mark inlines and template instances weak: clang compiles one into every unit
    whose code still calls it or takes its address, or that emits a weak table holding it, after the code that
    first refers to it there, and the linker keeps the copy of the unit it links first. So a weak function is in
    the unit of the earliest code referring to it: no boundary falls between the two. A table with a key function
    is emitted in that function's unit alone, and so are the inline virtuals only it holds: only weak tables
    count. Code after the function (a global's constructor run by its unit's static initializer) says nothing."""
    if program.platform.name != "switch":
        return []
    functions, index = program.functions, program.function_index
    weak = set(getattr(program.image, "weak", ())) | {f.address for f in functions if f.scope == "weak"}
    if not weak:
        return []
    first: dict[int, int] = {}

    def use(target: int, user: int) -> None:
        if user < first.get(target, target) and functions[target].address in weak:
            first[target] = user
    for user, callees in program.calls.items():
        for target in callees:
            use(target, user)
    for user, rows in program.refs.items():
        for _, address, _ in rows:
            target = index.get(address)
            if target is not None:
                use(target, user)
    held: dict[DataObject, set[int]] = collections.defaultdict(set)    # weak table -> the weak functions in it
    for holder, pointee in program.pointers:
        target = index.get(pointee)
        if target is not None and functions[target].address in weak:
            table = program.object_at(holder)
            if table is not None and (table.scope == "weak" or table.address in weak):
                held[table].add(target)
    if held:
        for table, users in program.users().items():
            for target in held.get(table, ()):
                for user in users:
                    use(target, user)
    text = program.platform.text
    return [(user, target, f"{functions[target].name} is first used by {functions[user].name} "
                           f"({text(functions[user].address)})") for target, user in sorted(first.items())]


SDK_MARKER = "__nnDetailNintendoSdk"   # NintendoSDK's own objects: `__nnDetailNintendoSdkRuntimeObjectFile`, ...


def _start_up_object(program: Program, ev: Evidence) -> None:
    """A NintendoSDK module starts with the SDK's start-up object (`_init`, `_fini`, their stubs), which ends with
    the marker functions the SDK gives its objects (`__nnDetailNintendoSdkRuntimeObjectFile` and its `...Refer`):
    the game's first unit starts after them."""
    if program.platform.name != "switch":
        return
    last = None
    for index, function in enumerate(program.functions[:32]):
        if function.name.startswith(SDK_MARKER):
            last = index
        elif last is not None:
            break
    if last is not None and last + 1 < len(program.functions):
        row = (last + 1, last + 1, f"{program.functions[last].name} ends the SDK's start-up object")
        ev.separations.append(row)
        ev.direct.add(row)


def _initializer_ends(program: Program, ev: Evidence) -> None:
    """An ELF's static initializers: clang compiles a unit's own one (no guard to test) after its other code, so a
    unit ends right after it. One that tests a guard first initializes a template's static member, kept from
    whichever unit came first, and ends nothing."""
    for index in _initializers(program):
        ev.separations.append((index + 1, index + 1,
                               f"{program.platform.text(program.functions[index].address)} is its unit's static "
                               "initializer"))
        ev.direct.add(ev.separations[-1])


def _constructed(program: Program, owner: dict[int, str]) -> dict[int, set[str]]:
    """{object address: the units whose own static initializer (`_initializers`) stores into it}."""
    from .aarch64 import global_stores
    out: dict[int, set[str]] = collections.defaultdict(set)
    initializers = _initializers(program)                # the Switch's only
    load64 = program.image.pointers.get if initializers else None
    for index in initializers:
        unit = owner.get(index)
        if unit is None:
            continue
        function = program.functions[index]
        words = program.platform.words(program.image, function.address, function.size)
        for address in global_stores(words, function.address, load64):
            found = program.object_at(address)
            if found is not None:
                out[found.address].add(unit)
    return out


def _initializers(program: Program) -> list[int]:
    """The function indexes of the units' own static initializers (`_initializer_ends`), each its unit's last."""
    if program.platform.name != "switch":
        return []
    from .aarch64 import guarded
    out = []
    for address in getattr(program.image, "init_array", ()):
        index = program.function_index.get(address)
        if index is None or index + 1 >= len(program.functions):
            continue
        function = program.functions[index]
        if not guarded(program.platform.words(program.image, address, min(function.size, 64))):
            out.append(index)
    return sorted(out)


PIECE = re.compile(r"_[0-9A-Fa-f]{8,16}(?=\.\w+$)")   # `file_<address>.cpp`: a later piece of one file
UNNAMED = re.compile(r"^unit_[0-9A-Fa-f]+\.\w+$")      # a placeholder: a unit no file or class names


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
            ev.files[index] = unit if UNNAMED.match(unit) else PIECE.sub("", unit)   # its address is no piece's
            ev.placed.add(index)
    # One file named two ways: a path relative to an include folder (or another build's unit name) is the one
    # full path that ends in it.
    spelled, full = set(ev.files.values()), {}
    for short in spelled:
        longer = [name for name in spelled if name.casefold().endswith("/" + short.casefold())]
        if len(longer) == 1:
            full[short] = longer[0]
    ev.files = {index: full.get(name, name) for index, name in ev.files.items()}
    alias = _included(ev)                              # files one compiles inside another: the unit's one name
    ev.files = {index: alias.get(name, name) for index, name in ev.files.items()}
    _class_files(program, ev)
    # A unit's code is one run in the link: one function another build put in X between two that agree on Y is
    # no evidence for X there (an inline that build kept from X, code that moved, other code that compiles alike).
    anchors = sorted(ev.files.items())
    for (_, before), (index, unit), (_, after) in zip(anchors, anchors[1:], anchors[2:]):
        if index in ev.placed and before == after != unit:
            del ev.files[index]
            ev.placed.discard(index)
    _joined_placements(ev, _initializers(program))
    _wide_statics(program, ev)
    # One file's own citations around another's: that one is compiled inside it (included), and the run between
    # is one unit, whatever else says otherwise.
    own = sorted((i, f) for i, f in ev.files.items() if i not in ev.placed and i not in ev.classed)
    last: dict[str, int] = {}
    for position, (index, file) in enumerate(own):
        if file in last and own[last[file] + 1][1] != file:
            row = (own[last[file]][0], index, f"{file}'s citations around another file's: it includes it")
            ev.joins.append(row)
            ev.cited.append(row)
        last[file] = position
    anchors = sorted(ev.files.items())
    starts = [f.address for f in program.functions]
    for (a, file_a), (b, file_b) in zip(anchors, anchors[1:]):
        if file_a == file_b:
            if b - a <= FILL_FUNCTIONS and starts[b] - starts[a] <= FILL_BYTES:
                ev.joins.append((a, b, f"both cite {file_a}"))
                if a not in ev.placed and b not in ev.placed:   # the code's own citations, not another build's
                    ev.cited.append(ev.joins[-1])
        else:
            ev.separations.append((a + 1, b, f"{file_a} then {file_b}"))
            ev.pairs[ev.separations[-1]] = (file_a, file_b)
            if a not in ev.placed and b not in ev.placed:
                ev.direct.add(ev.separations[-1])
            else:
                ev.borrowed.add(ev.separations[-1])
    # Two functions citing different files themselves are in different units even where another build's units lie
    # between them: a boundary the joins of data alone do not move. Not where the two files' citations interleave:
    # one file includes the other, and both are one unit.
    own = sorted((i, f) for i, f in ev.files.items() if i not in ev.placed and i not in ev.classed)
    first_of: dict[str, int] = {}
    last_of: dict[str, int] = {}
    for i, f in own:
        first_of.setdefault(f, i)
        last_of[f] = i
    for (a, file_a), (b, file_b) in zip(own, own[1:]):
        row = (a + 1, b, f"{file_a} then {file_b}")
        if file_a != file_b and row not in ev.pairs and last_of[file_a] == a and first_of[file_b] == b:
            ev.separations.append(row)
            ev.pairs[row] = (file_a, file_b)
            ev.direct.add(row)
    _untied(program, ev, anchors)


def _included(ev: Evidence) -> dict[str, str]:
    """{file: the name of the unit it is compiled in} for files whose own citations interleave with another's
    (`a.cpp`, then `b.cpp`, then `a.cpp` again): one includes the other, and they are one unit, named after the one
    citing most (another build may name it after the other: its units take this name too)."""
    own = sorted((i, f) for i, f in ev.files.items() if i not in ev.placed)
    parent: dict[str, str] = {}

    def root(f: str) -> str:
        while parent.get(f, f) != f:
            f = parent[f]
        return f
    last: dict[str, int] = {}
    for position, (_, file) in enumerate(own):
        if file in last:
            for _, other in own[last[file] + 1:position]:
                if other != file:
                    a, b = root(file), root(other)
                    if a != b:
                        parent[b] = a
        last[file] = position
    counts = collections.Counter(f for _, f in own)
    groups: dict[str, list[str]] = collections.defaultdict(list)
    for f in {f for _, f in own} | set(parent):
        groups[root(f)].append(f)
    out = {}
    for members in groups.values():
        if len(members) > 1:
            name = max(members, key=lambda f: (counts[f], f))
            out.update({f: name for f in members if f != name})
    return out


def _wide_statics(program: Program, ev: Evidence) -> None:
    """A static no symbol names (a file's own, in no symbol table) whose users spread wider than a tight run, but
    over no evidence of another file than one: its users are that file's, and the run between them one unit."""
    from .score import placeholder
    anchors = sorted(ev.files.items())
    keys = [i for i, _ in anchors]
    for o, fs in program.users().items():
        if o.section not in WRITABLE_SECTIONS or not placeholder(o.name) or not fs:
            continue
        lo, hi = min(fs), max(fs)
        if hi - lo <= TIGHT:
            continue                                   # a tight run's: a join already
        files = {f for _, f in anchors[bisect.bisect_left(keys, lo):bisect.bisect_right(keys, hi)]}
        if len(files) == 1:
            ev.joins.append((lo, hi, f"{o.name} ({o.section}) is {next(iter(files))}'s only"))


def _joined_placements(ev: Evidence, ends: list[int]) -> None:
    """Nor is another build's unit evidence for a function the code joins to another file's (data only that run
    of code uses, a weak function and its earliest user): the run is one unit, of the one file its own citations
    name, else of the file that build gives most of it. Where its own citations name several files (one file
    including another), the run says nothing about which; nor does one with a unit's static initializer (`ends`)
    before its last function: data that run uses is shared by several units (a class's static member its
    subclasses' initializers refer to)."""
    for lo, hi, _ in list(ev.joins):            # the code's joins: no file run has been joined yet
        if bisect.bisect_left(ends, lo) < bisect.bisect_left(ends, hi):
            continue
        inside = [i for i in range(lo, hi + 1) if i in ev.files]
        if len({ev.files[i] for i in inside}) < 2:
            continue
        own = {ev.files[i] for i in inside if i not in ev.placed}
        if len(own) > 1:
            continue
        votes = collections.Counter(ev.files[i] for i in inside if i in ev.placed)
        keep = next(iter(own)) if own else max(votes, key=lambda f: (votes[f], -min(i for i in inside
                                                                                if ev.files[i] == f)))
        for i in inside:
            if i in ev.placed and ev.files[i] != keep:
                del ev.files[i]
                ev.placed.discard(i)


def _untied(program: Program, ev: Evidence, anchors: list[tuple[int, str]]) -> None:
    """A file's evidence reaches through the data its code shares with the code after it, and a short way past
    that (`FILL_*`, as far as a gap between two of its citations is filled). Between two files, a longer run of
    code tied to neither is neither's: a library no string names, or files that cite nothing. It is a unit of its
    own, with a boundary within reach of each file's evidence, until evidence names it. Where the module (or the
    build a name came from) marks inlines and template instances weak, clang emits each after the code that
    first uses it, so the code before a run of them reaches over it, and over code of unknown binding (no
    symbol, a placeholder name) between two of them."""
    from .score import placeholder
    count, starts = len(program.functions), [f.address for f in program.functions]
    weak = set(getattr(program.image, "weak", ())) | {f.address for f in program.functions if f.scope == "weak"}
    bound = getattr(program.image, "symbols", None) or {}
    inline = [f.address in weak for f in program.functions]
    unknown = [not inline[i] and f.address not in bound and placeholder(f.name)
               for i, f in enumerate(program.functions)]
    right, left = list(range(count)), list(range(count))   # the furthest function a join reaches from each one
    for lo, hi, _ in ev.joins:
        right[lo], left[hi] = max(right[lo], hi), min(left[hi], lo)
    for p in range(1, count):
        right[p] = max(right[p], right[p - 1])
    for p in range(count - 2, -1, -1):
        left[p] = min(left[p], left[p + 1])
    if not anchors:
        return
    starts.append(program.functions[-1].address + program.functions[-1].size)
    bounded = [(-1, None), *anchors, (count, None)]     # the module's start and end bound the first and last files
    for (a, file_a), (b, file_b) in zip(bounded, bounded[1:]):
        if file_a == file_b:
            continue
        end = a                                     # the last function tied to file_a's
        while file_a is not None and end < b - 1:
            if right[end] > end:
                end = min(right[end], b - 1)
                continue
            following = end + 1
            while inline[end] and following < b - 1 and unknown[following]:
                following += 1
            if not inline[following]:
                break
            end = following
        start = b                                   # the first tied to file_b's
        while file_b is not None and left[start] < start and start > end + 1:
            start = max(left[start], end + 1)
        first = end + 1
        if start - first <= FILL_FUNCTIONS and starts[start] - starts[first] <= FILL_BYTES:
            continue
        hi = first
        while hi + 1 < start and hi + 1 - first <= FILL_FUNCTIONS and starts[hi + 1] - starts[first] <= FILL_BYTES:
            hi += 1
        lo = start
        while lo - 1 > first and start - (lo - 1) <= FILL_FUNCTIONS and starts[start] - starts[lo - 1] <= FILL_BYTES:
            lo -= 1
        for row, side in (((first, hi, f"{file_a}'s evidence ends"), first),
                          ((lo, start, f"{file_b}'s evidence starts"), start)):
            if row[0] <= 0 or row[1] >= count:       # at the module's start or end: no boundary there
                continue
            ev.separations.append(row)
            ev.pairs[row], ev.edges[row] = (file_a, file_b), side
            (ev.direct if a not in ev.placed and b not in ev.placed else ev.borrowed).add(row)


def _class_files(program: Program, ev: Evidence) -> None:
    """A class's own functions are compiled in its file: where the module marks its inlines and template
    instances weak, a strong function of a class whose cited functions cite one file is that file's, ahead of
    another build's unit, when the citation nearest it on either side is that file's too. A class can define a
    method in another file (`GfComBehaviorPc::callbackBattle`, among the battle code): there the citations around
    it are that other file's, and the class says nothing; nor does it across another class's functions whose own
    citations name another file (one file including another: their classes' functions alternate), nor further
    than a file's evidence reaches (`FILL_FUNCTIONS`). A class nested in another (`Menu::Listener`) whose own
    functions cite nothing is its enclosing class's file's, on the same terms."""
    from .score import placeholder
    weak, bound = set(getattr(program.image, "weak", ())), getattr(program.image, "symbols", None) or {}
    weak |= {f.address for f in program.functions if f.scope == "weak"}
    # the module's own symbol table tells a class's own functions from the inlines other units kept, and so do the
    # bindings that came with names from a build that has one; a function neither lists is either
    strong = {f.address for f in program.functions if f.address not in weak and
              (f.address in bound or f.scope == "global" and not placeholder(f.name))}
    if not weak or not strong:
        return
    folded = _folded_destructors(program)
    members: dict[str, list[int]] = collections.defaultdict(list)
    for index, cls in _function_classes(program, qualifiers=True).items():
        if program.functions[index].address in strong and index not in folded:
            members[cls].append(index)
    cited = sorted((i, name) for i, name in ev.files.items() if i not in ev.placed)
    keys = [i for i, _ in cited]
    file_of: dict[str, str] = {}                        # class -> the one file its own functions cite
    for cls, indexes in members.items():
        files = {ev.files[i] for i in indexes if i in ev.files and i not in ev.placed}
        if len(files) == 1:
            file_of[cls] = files.pop()
    for cls, indexes in members.items():                # a nested class citing nothing: its enclosing class's
        enclosing = cls
        while cls not in file_of and "/" in enclosing and not any(i in ev.files and i not in ev.placed
                                                                   for i in indexes):
            enclosing = enclosing.rsplit("/", 1)[0]
            if enclosing in file_of:
                file_of[cls] = file_of[enclosing]
    owner = {i: file_of[cls] for cls, indexes in members.items() if cls in file_of for i in indexes}
    for cls, indexes in members.items():
        if cls not in file_of:
            continue
        file = file_of[cls]
        clear = lambda lo, hi: hi - lo <= FILL_FUNCTIONS and all(owner.get(i, file) == file for i in range(lo + 1, hi))
        for index in indexes:
            if index in ev.files and index not in ev.placed:
                continue
            at = bisect.bisect_left(keys, index)
            if (at and cited[at - 1][1] == file and clear(cited[at - 1][0], index)) or \
                    (at < len(cited) and cited[at][1] == file and clear(index, cited[at][0])):
                ev.files[index] = file
                ev.placed.discard(index)
                ev.classed.add(index)


def _folded_destructors(program: Program) -> set[int]:
    """Destructors several classes' tables hold: no class inherits another's destructor, so the linker folded
    identical ones into one function, and the name it carries is any of theirs, not its file's evidence."""
    tables: dict[int, set[str]] = collections.defaultdict(set)
    for holder, pointee in getattr(program, "pointers", ()):
        index = program.function_index.get(pointee)
        found = program.object_at(holder) if index is not None else None
        if found is not None and found.name.startswith(("_ZTV", "__vt__")):
            tables[index].add(found.name)
    return {index for index, names in tables.items() if len(names) > 1
            and re.search(r"D[012]Ev$", program.functions[index].name)}


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
    cited = ev.joined(count, ev.cited)
    first = ev.joined(count, ev.firsts)
    index = program.function_index
    taken = ((i, index[address]) for i, rows in program.refs.items() for _, address, kind in rows
             if kind == "addr" and address in index)     # a callback whose address the code takes, like a call
    calls = _cover(((min(i, j), max(i, j)) for i, j in
                    [(i, j) for i, callees in program.calls.items() for j in callees] + list(taken)
                    if 0 < abs(i - j) <= SHORT_CALL), count)
    members: dict[str, list[int]] = collections.defaultdict(list)
    for index, cls in _function_classes(program).items():
        members[cls].append(index)
    classes = _cover(((min(f), max(f)) for f in members.values() if max(f) - min(f) <= CLASS_SPAN), count)
    crossings: dict[int, int] = {}

    def cost(p: int) -> tuple:
        if p not in crossings:
            crossings[p] = _crossings(program, ev, p)
        return crossings[p], classes[p], calls[p]
    chosen: list[Boundary] = []
    rows = _stated(ev)
    stated = _minimal(rows)             # where a file's evidence ends: met by any boundary within its reach
    # then the others, narrowest first: one an inner one did not meet (it had no place the joins allow) still
    # needs its boundary
    rest = sorted(set(rows) - set(stated), key=lambda r: (r[1] - r[0], r[0]))
    apart = sorted(set(ev.apart), key=lambda r: (r[1] - r[0], r[0]))
    apart_rows = set(apart)
    owner = _function_classes(program, qualifiers=True) if apart else {}
    for row in [r for r in stated if r not in ev.edges] + [r for r in stated if r in ev.edges] + rest + apart:
        lo, hi, because = row
        toward = ev.edges.get(row, lo)  # among equal places, the one nearest the evidence (else the earliest)
        if any(lo <= c.position <= hi for c in chosen):
            continue
        candidates = [p for p in range(lo, hi + 1) if not joined[p]]
        if not candidates and (lo, hi, because) in ev.direct:   # data one run uses across what the code itself
            candidates = [p for p in range(lo, hi + 1) if not cited[p] and not first[p]]   # separates is shared
            # (a template's table, an inline's static, a class's static member); a weak function is in its first
            # user's unit whatever the files between cite (one file including another)
        if not candidates:
            continue
        if row in apart_rows:           # a call says nothing of a class's or namespace's run of functions
            whole = [p for p in candidates if not (owner.get(p - 1) and owner.get(p - 1) == owner.get(p))]
            if not whole:
                continue
            candidates = whole
        best = min(candidates, key=lambda p: (*cost(p), abs(p - toward)))
        chosen.append(Boundary(best, (candidates[0], candidates[-1]), crossings[best], because))
    return sorted(chosen, key=lambda c: c.position)


def _stated(ev: Evidence) -> list[tuple[int, int, str]]:
    """The separations, less those only another build's units give (`borrowed`) between the same two files as the
    citations around them where the code itself states a boundary (another cited file, a static initializer)
    between those citations: that build's units are evidence where the code says nothing, not against it. One
    that puts a third file between them stands: the code's boundary can be that file's end."""
    cited = sorted(i for i in ev.files if i not in ev.placed)
    direct = sorted(lo for lo, _, _ in ev.direct)
    out = []
    for row in ev.separations:
        lo, hi, _ = row
        if row in ev.borrowed:
            left = bisect.bisect_left(cited, lo)
            after = cited[left - 1] if left else -1                      # the last citation before the window
            right = bisect.bisect_left(cited, hi)
            before = cited[right] if right < len(cited) else len(ev.files) + (1 << 30)   # the first after it
            first = bisect.bisect_right(direct, after)
            around = {ev.files.get(after), ev.files.get(before)}
            if first < len(direct) and direct[first] <= before and set(ev.pairs.get(row, around)) == around:
                continue
        out.append(row)
    return out


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
    qualified = _function_classes(program, qualifiers=True)  # a unit no class names: what its names qualify
    qualified = {i: q for i, q in qualified.items() if re.fullmatch(r"[A-Za-z_][\w/]*", q)}
    units = []
    reserved = {u["unit"] for u in held.values()}     # a fixed unit keeps its name in every code section
    taken: collections.Counter = collections.Counter()
    named: list[tuple[int, int, str, str]] = []
    for first, end in zip(edges, edges[1:]):
        if first >= end:
            continue
        span = range(first, end)
        files = collections.Counter(ev.files[i] for i in span if i in ev.files and i not in ev.placed) or \
            collections.Counter(ev.files[i] for i in span if i in ev.files)    # its own citations first
        if (first, end) in held:
            name, how = held[(first, end)]["unit"], held[(first, end)]["how"]
        elif files:
            name = files.most_common(1)[0][0]
            own = [i for i in span if ev.files.get(i) == name and i not in ev.placed]
            how = "file string" if any(i not in ev.classed for i in own) else "class's file" if own \
                else "another build"
        else:
            name, how = _unnamed(program, class_of, first, end, qualified)
        if UNNAMED.match(name):                  # another build's placeholder: this build's address names it
            name, how = f"unit_{text(functions[first].address)[2:]}.cpp", "placeholder"
        named.append((first, end, name, how))
    # A file's code is one run: a unit only another build names after the file its neighbour's own code cites is
    # another file, which that build had not told apart.
    for k, (first, end, name, how) in enumerate(named):
        if how == "another build" and any(0 <= j < len(named) and named[j][2] == name and
                                          named[j][3] == "file string" for j in (k - 1, k + 1)):
            named[k] = (first, end, *_unnamed(program, class_of, first, end, qualified))
    named = _in_neighbours_folder(named, held)
    for first, end, name, how in named:
        if (first, end) not in held:
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


SORTED_PAIRS = 20        # file pairs a folder-sorted link must show before its order places other units
SORTED_SHARE = 0.95      # the share of them in name order it needs


def _sort_key(name: str) -> str:
    """A file name as a Windows build orders a folder's files: case folded to upper, so `_` sorts after letters."""
    return name.upper()


def _in_neighbours_folder(named: list, held: dict) -> list:
    """Units no file names (named after their class or address), placed in the folder of the files around them,
    where the files link in name order within a folder (a build that globs each folder): one between two files of
    a folder is that folder's. The files' own order is the evidence, so only a link whose consecutive files of one
    folder are almost all in name order counts; a hand-ordered link (a CodeWarrior project's) places nothing."""
    files = [k for k, (_, _, name, how) in enumerate(named)
             if how not in ("class", "placeholder") and "/" in name and not UNNAMED.match(name.rsplit("/", 1)[1])]
    pairs = [(named[a][2], named[b][2]) for a, b in zip(files, files[1:])
             if named[a][2].rpartition("/")[0] == named[b][2].rpartition("/")[0]]
    ordered = sum(_sort_key(a) < _sort_key(b) for a, b in pairs)
    if len(pairs) < SORTED_PAIRS or ordered < SORTED_SHARE * len(pairs):
        return named
    out = list(named)
    for k, (first, end, name, how) in enumerate(named):
        if how not in ("class", "placeholder") or (first, end) in held:
            continue
        before = [j for j in files if j < k]
        after = [j for j in files if j > k]
        if not before or not after:
            continue
        folder = named[before[-1]][2].rpartition("/")[0]
        if folder and folder == named[after[0]][2].rpartition("/")[0]:
            out[k] = (first, end, f"{folder}/{name.rsplit('/', 1)[-1]}", how)
    return out


def _unnamed(program: Program, class_of: dict[int, str], first: int, end: int,
             qualified: dict[int, str] | None = None) -> tuple[str, str]:
    """A name for a unit no file names: the class most of its functions belong to, else the class (or namespace)
    most of their names qualify them with when no class has a constructor here (`gf::GfAssetUtil`'s static
    functions), else its address."""
    classes = collections.Counter(class_of[i] for i in range(first, end) if i in class_of) or \
        collections.Counter((qualified or {})[i] for i in range(first, end) if i in (qualified or {}))
    if classes:
        return classes.most_common(1)[0][0] + ".cpp", "class"
    return f"unit_{program.platform.text(program.functions[first].address)[2:]}.cpp", "placeholder"


def _function_classes(program: Program, qualifiers: bool = False) -> dict[int, str]:
    """Function index -> the class it belongs to: the recovered class of a CodeWarrior table, or the class an
    Itanium name qualifies (`_itanium_classes`)."""
    if program.platform.name == "switch":
        return _itanium_classes(program, qualifiers)
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


def _itanium_classes(program: Program, qualifiers: bool = False) -> dict[int, str]:
    """Function index -> the class its Itanium name qualifies it with, where some function is that class's
    constructor or destructor (a namespace has neither) and the class is no template's instance (the linker keeps
    one of those from whichever unit comes first). The class is spelled as a path: `fw::Camera` is `fw/Camera`.
    With `qualifiers`, also a qualifier that qualifies nothing else's (a class whose constructor every caller
    inlined, `gf::GfMoveBrakeControler`; a namespace holds classes or namespaces)."""
    from .platform import demangle_itanium
    named = [(i, f.name) for i, f in enumerate(program.functions) if f.name.startswith("_Z")]
    owners: dict[int, str] = {}
    classes: set[str] = set()
    for (index, _), text in zip(named, demangle_itanium([n for _, n in named])):
        parts = _qualified(text) if text else None
        if not parts or len(parts) < 2:
            continue
        owner, method = "::".join(parts[:-1]), parts[-1]
        if "<" in owner:
            continue
        owners[index] = owner
        if method.lstrip("~") == parts[-2]:
            classes.add(owner)
    if qualifiers:
        outer = {"::".join(o.split("::")[:k]) for o in set(owners.values()) for k in range(1, o.count("::") + 1)}
        classes |= set(owners.values()) - outer
    return {index: owner.replace("::", "/") for index, owner in owners.items() if owner in classes}


def _qualified(text: str) -> list[str] | None:
    """The `::` parts of a demangled function's name, up to its parameters (None for a thunk, a guard variable, a
    table, or an operator whose name holds a bracket)."""
    if text.startswith("{") or " thunk to " in text or " for " in text:
        return None
    depth, parts, start = 0, [], 0
    for at, c in enumerate(text):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif depth == 0 and c == "(":
            parts.append(text[start:at])
            return [p for p in parts if p]
        elif depth == 0 and text.startswith("::", at):
            parts.append(text[start:at])
            start = at + 2
    return None


TABLES = (".ctors", ".dtors")      # pointer tables: one entry per unit's static initializer (finalizer)
ARRAYS = (".init_array", ".fini_array")   # an ELF's: one pointer per unit's initializer (finalizer)
# what an ELF linker makes itself: no unit's data, whatever code refers to it (the runtime's start-up code does)
LINKER_SECTIONS = (".dynamic", ".dynsym", ".dynstr", ".hash", ".gnu.hash", ".rela.dyn", ".rela.plt", ".relr.dyn",
                   ".eh_frame", ".eh_frame_hdr", ".got", ".got.plt", ".plt")
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
    source); one that stands is kept as given, and no claim crosses it or adds to its unit in its section. Weak
    data (an inline's static, a template's member or table) is in every unit using it, and the linker keeps the
    copy of the first in link order: it is that unit's. Data several units use is the unit's whose own static
    initializer stores into it, when only one does: the unit defining a global runs its constructor (a class's
    runtime type, a file's static vectors), however many others read it."""
    from .link import LINKER_OBJECTS
    order: dict[str, int] = {}                         # unit -> its place in link order (its first code)
    ordered = set()                                    # .init code says nothing of where its unit is linked
    for index in sorted(owner):
        if owner[index] not in order:
            order[owner[index]] = len(order)
            if program.section_of(program.functions[index].address) != ".init":
                ordered.add(owner[index])
    weak = set(getattr(program.image, "weak", ()))
    merged = not program.platform.literals_per_unit   # one copy of each literal for the whole module
    claims: list[tuple[int, int, str, str]] = []
    soft: list[tuple[int, int, str, str]] = []       # weak data, merged literals: the first unit using it, where
                                                     # the order allows
    constructed = _constructed(program, owner)
    keyed = _key_function_tables(program, owner, weak) if program.platform.name == "switch" else []
    keyed_at = {row[0] for row in keyed}               # where the order of the others allows (below): a table
                                                       # out of its key function's order says the units are wrong
    for o, fs in program.users().items():              # however far apart its users are: they are one unit's
        homes = {owner.get(i) for i in fs} - {None}
        if o.name in LINKER_OBJECTS or o.section in TABLES + ARRAYS + LINKER_SECTIONS:   # the linker's, or a
            continue                                                                    # table entry (below)
        if o.address in keyed_at:                                       # its key function's unit (above)
            continue
        if program.in_code(o.address):                                  # data in code is in its unit's code range
            continue
        definers = constructed.get(o.address, set())
        if len(homes) == 1:
            claims.append((o.address, o.address + max(o.size, 1), next(iter(homes)), o.section))
        elif len(definers) == 1 and definers <= homes and o.scope != "weak" and o.address not in weak:
            claims.append((o.address, o.address + max(o.size, 1), next(iter(definers)), o.section))
        elif homes and (o.scope == "weak" or o.address in weak or merged and o.section in MERGED_SECTIONS) \
                and homes <= ordered:
            soft.append((o.address, o.address + max(o.size, 1), min(homes, key=order.__getitem__), o.section))
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
    if merged:
        claims += _dropped_files(program, ev, order)
    out: list[tuple[int, int, str, str]] = []
    if program.platform.name == "gamecube":
        claims += _initializer_tables(program, owner)
    claims += _initializer_arrays(program, owner)
    blocks = _literal_blocks(program, claims + soft, order, ordered) if merged else {}

    def place(row) -> tuple:
        key = (row[3], _instance(program, row[0]))
        return (*key, bisect.bisect_right(blocks.get(key, ()), row[0]))
    by_section: dict[tuple, list] = collections.defaultdict(list)
    for claim in claims:
        by_section[place(claim)].append(claim)
    pinned = {row: FIRM if row[2] in firm else FIXED for row in fixed}
    for row in pinned:
        by_section[place(row)].append(row)
    by_soft: dict[tuple, list] = collections.defaultdict(list)
    by_keyed: dict[tuple, list] = collections.defaultdict(list)
    for claim in soft:
        by_soft[place(claim)].append(claim)
        by_section.setdefault(place(claim), [])
    for claim in keyed:
        by_keyed[place(claim)].append(claim)
        by_section.setdefault(place(claim), [])
    for (section, instance, _block), rows in by_section.items():
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
        for group in (by_keyed, by_soft):              # a key function's table before the first users' copies
            kept += _fitting(kept, _whole_symbols(program, group.get((section, instance, _block), [])), order,
                             ordered, fixed_units, stand)
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


def _dropped_files(program: Program, ev: Evidence, order: dict[str, int]) -> list[tuple[int, int, str, str]]:
    """A source file's own path that no code or data refers to is that file's: the `__FILE__` of code the linker
    dropped (`--gc-sections` removes unreferenced functions, while their file's literals stay where its object's
    went, in link order between its neighbours' literals). Only a path naming a unit; a header's is no file's."""
    referred = {address for rows in program.refs.values() for _, address, _ in rows}
    referred.update(pointee for _, pointee in program.pointers)
    out = []
    for address, text in program.strings().items():
        if not SOURCE.search(text) or HEADER.search(text) or address in referred:
            continue
        found = program.object_at(address)
        if found is None or found.section not in MERGED_SECTIONS:
            continue
        unit = _unit_name(text, ev.roots)
        if unit not in order:                          # a unit its own code names by a shorter path
            tails = [u for u in order if unit.casefold().endswith("/" + u.casefold())]
            unit = tails[0] if len(tails) == 1 else None
        if unit is not None:
            out.append((address, address + len(text) + 1, unit, found.section))
    return out


MERGED_SECTIONS = (".rodata",)   # where a linker merging literals keeps one copy of each, the first unit's


def _literal_blocks(program: Program, rows: list[tuple[int, int, str, str]], order: dict[str, int],
                    ordered: set[str]) -> dict[tuple[str, int], list[int]]:
    """{(section, instance): addresses where a block starts}. A linker that merges literals (clang's strings and
    4, 8 and 16-byte constants: one copy for the module) puts each kind in one block where the first unit's goes,
    the first unit's copy of each, so in a block the units come in link order again: a unit owns a range in each
    block (its strings, its constants, its other read-only data). A block starts where the claims' units go
    back in link order and a cut there lets at least half the claims on its smaller side stand in that order (a
    claim out of place, data another unit defines, lets a few)."""
    groups: dict[tuple[str, int], list[tuple[int, int]]] = collections.defaultdict(list)
    for start, _, unit, section in rows:
        if section in MERGED_SECTIONS and unit in ordered:
            groups[(section, _instance(program, start))].append((start, order[unit]))
    out = {}
    for key, seq in groups.items():
        seq.sort()
        values = [v for _, v in seq]
        cuts = _cuts(values)
        if cuts:
            out[key] = [seq[k][0] for k in cuts]
    return out


def _cuts(values: list[int]) -> list[int]:
    """Indexes where `values` (units' places in link order) start again: cut greedily, the best gain first."""
    def run(part: list[int]) -> int:             # the longest run that never goes back
        tails: list[int] = []
        for v in part:
            k = bisect.bisect_right(tails, v)
            tails[k:k + 1] = [v]
        return len(tails)
    top = max(values, default=0) + 1
    candidates = [k for k in range(1, len(values)) if values[k - 1] - values[k] > top // 4]
    cuts: list[int] = []
    while True:
        bounds = [0, *sorted(cuts), len(values)]
        best = None
        for k in candidates:
            if k in cuts:
                continue
            i = bisect.bisect_right(bounds, k)
            s, e = bounds[i - 1], bounds[i]
            gain = run(values[s:k]) + run(values[k:e]) - run(values[s:e])
            if gain >= max(4, (min(k - s, e - k) + 1) // 2) and (best is None or gain > best[0]):
                best = (gain, k)
        if best is None:
            return sorted(cuts)
        cuts.append(best[1])


def _fitting(kept: list[tuple[int, int, str, str]], soft: list[tuple[int, int, str, str]], order: dict[str, int],
             ordered: set[str], fixed_units: set[str], stand: list) -> list[tuple[int, int, str, str]]:
    """The `soft` claims that fit the link order of the `kept` ones where they lie: never one that would displace a
    claim, since the unit that kept a weak object's copy may be one whose code no longer refers to it (its copy
    of the inline using it was dropped for another unit's)."""
    places = sorted((r[0], order[r[2]]) for r in kept if r[2] in ordered)
    out = []
    for row in sorted(soft):
        if row[2] not in ordered or row[2] in fixed_units or any(a < row[1] and row[0] < b for a, b, _, _ in stand):
            continue
        at = bisect.bisect_left(places, (row[0], -1))
        low = places[at - 1][1] if at else -1
        high = places[at][1] if at < len(places) else 1 << 30
        if low <= order[row[2]] <= high:
            places.insert(at, (row[0], order[row[2]]))
            out.append(row)
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


def _key_function_tables(program: Program, owner: dict[int, str], weak: set[int]) -> list[tuple[int, int, str, str]]:
    """Itanium class tables with a key function (the class's first virtual defined out of line): clang emits such
    a table in that function's unit alone, whatever other code refers to it (a template instance in another file
    that builds the class). So a strong table whose class's own strong methods in its slots are all in one unit
    is that unit's. A weak table (no key function) goes by its users."""
    from .itanium import methods, recover
    named = methods(program)
    out = []
    for cls in recover(program).values():
        table = program.object_at(cls.table) if cls.table is not None else None
        if table is None or table.address != cls.table or table.scope == "weak" or table.address in weak:
            continue
        homes = set()
        for group in cls.groups:
            for slot in group.slots:
                index = program.function_index.get(slot) if isinstance(slot, int) else None
                method = named.get(slot)
                if index is None or method is None or method.thunk or method.owner != cls.name:
                    continue
                if program.functions[index].scope == "weak" or slot in weak:
                    continue
                homes.add(owner.get(index))
        homes.discard(None)
        if len(homes) == 1:
            out.append((table.address, table.address + max(table.size, 1), homes.pop(), table.section))
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


def _initializer_arrays(program: Program, owner: dict[int, str]) -> list[tuple[int, int, str, str]]:
    """`.init_array` and `.fini_array` entries, each the unit's whose function it points to (its static
    initializer or finalizer), read through the module's relocations."""
    pointers = getattr(program.image, "pointers", {})
    out = []
    for o in program.objects:
        if o.section in ARRAYS:
            for at in range(o.address, o.address + o.size - 7, 8):
                unit = owner.get(program.function_index.get(pointers.get(at), -1))
                if unit is not None:
                    out.append((at, at + 8, unit, o.section))
    return out


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
    """A unit's data range on word boundaries where the platform aligns each object's sections to one (none of
    4,001 starts off a word in a CodeWarrior link map), so the objects up to the next word-aligned one are this
    unit's, and so is a start back to one. Elsewhere the range stays as claimed (`Platform.unit_alignment`)."""
    if program.platform.unit_alignment < 4:
        return start, stop
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
        if (lo, hi, because) in ev.edges:     # where evidence stops reaching, not what contradicts a unit
            continue
        inside = {unit_of[i] for i in range(lo - 1, hi + 1)}
        if len(inside) == 1 and None not in inside:
            splits_needed[next(iter(inside))].append((lo, hi, because))
    claims = []
    for o, fs in ev.local.items():
        homes = {unit_of[i] for i in fs} - {None}
        if len(homes) == 1 and units.at(o.address) is None and o.section not in LINKER_SECTIONS:
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
