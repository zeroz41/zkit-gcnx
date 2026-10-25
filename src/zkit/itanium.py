"""Switch classes from a module's Itanium class tables, with or without RTTI (a table's typeinfo word is zero
under -fno-rtti, else a pointer to its typeinfo object): each `_ZTV` table's groups (a primary one, a secondary one per further base with a vtable), the
functions in their slots and what their names say, each class's bases, and a declaration per class that makes
the compiler emit the same table.

- **groups**: a table is groups of [offset-to-top, typeinfo, slots...], every group with the same typeinfo; a group's offset-to-top is minus
  the offset of the base subobject it is for.
- **bases**: a primary base's table is a prefix of the class's own: every slot the class does not override holds
  the same function, and an override keeps the method's name (a pure slot fits anything, either way). Of the
  classes that fit and whose own functions the class inherits (a sibling that overrides the
  same slots inherits the same functions, but none of its own: it is no candidate). Of the candidates, the
  longest is the nearest ancestor, then the one whose own functions it inherits most, then sharing most slots. A secondary group is matched the same way. A base the module has no table for (its constructor
  inlined everywhere) is the class owning the functions its derived classes all inherit, its slots rebuilt from
  them.
- **stored bases**: constructors, destructors and new-expressions store the tables of a class's primary ancestors
  at offset 0 of the object, in order. The nearest ancestor they prove is the primary base where the table prefix
  finds none or a farther one, if it fits the class's table and no class proven to derive from it could stand
  between (clang drops an intermediate's store nothing can read). Each base keeps the evidence that proved it.
- **names**: one inherited virtual has one name across every override (a pure slot takes its overrides' name);
  a slot no function names is `vf<slot>`. Return types are not in the names: `void` until code proves one.
"""

from __future__ import annotations

import collections
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .program import Program

PURE = ("__cxa_pure_virtual", "__cxa_deleted_virtual")


@dataclass
class Group:
    address: int                       # the group's offset-to-top word
    offset: int                        # the base subobject's offset in the class
    slots: list[int | str]             # a function's address, or the import a slot holds (a pure virtual)
    typeinfo: int = 0                  # the typeinfo object's address (0: built without RTTI)


@dataclass
class ItClass:
    name: str                          # qualified, as demangled (`ns::Widget`)
    table: int | None                  # its `_ZTV` start (None: a base known only from its derived classes)
    groups: list[Group]
    bases: list[tuple[int, str]] = field(default_factory=list)       # (offset, base) per group, primary first
    unresolved: list[tuple[int, list[str]]] = field(default_factory=list)   # (offset, tied candidates)
    constructors: list[int] = field(default_factory=list)
    destructors: list[int] = field(default_factory=list)
    evidence: dict[int, list[tuple[str, int | None]]] = field(default_factory=dict)  # offset -> (how, function)


@dataclass
class Method:
    owner: str | None                  # the class (or namespace) its name qualifies it with
    name: str                          # `update`, `~Camera`
    params: str                        # the parameter list as demangled, without parentheses
    const: bool
    thunk: bool                        # a this-adjusting thunk (`_ZThn...`)
    symbol: str


def methods(program: Program) -> dict[int, Method]:
    """Function address -> what its Itanium name says."""
    from .platform import demangle_itanium
    named = [f for f in program.functions if f.name.startswith("_Z")]
    out = {}
    for function, text in zip(named, demangle_itanium([f.name for f in named])):
        if not text:
            continue
        thunk = False
        for prefix in ("non-virtual thunk to ", "virtual thunk to "):
            if text.startswith(prefix):
                text, thunk = text[len(prefix):], True
        parsed = _split(text)
        if parsed is None:
            continue
        qualified, params, const = parsed
        parts = _parts(qualified)
        if len(parts) < 2:
            out[function.address] = Method(None, parts[0], params, const, thunk, function.name)
            continue
        out[function.address] = Method("::".join(parts[:-1]), parts[-1], params, const, thunk, function.name)
    for address, m in list(out.items()):               # a thunk names the function it adjusts `this` for
        if not m.thunk:
            continue
        target = _thunk_target(program, address)
        if target is not None and target not in out and target in program.function_index:
            symbol = re.sub(r"^_ZTh[nv]-?\d+_(?:-?\d+_)?", "_Z", m.symbol)
            out[target] = Method(m.owner, m.name, m.params, m.const, False, symbol)
    return out


def _thunk_target(program: Program, address: int) -> int | None:
    """The function a this-adjusting thunk branches to (`sub x0, x0, #n` or `add`, then `b`)."""
    function = program.functions[program.function_index[address]]
    try:
        words = program.platform.words(program.image, address, min(function.size, 32))
    except ValueError:
        return None
    for index, word in enumerate(words):
        if word & 0xFC000000 == 0x14000000:            # b
            offset = word & 0x03FFFFFF
            offset = offset - (1 << 26) if offset >> 25 else offset
            return address + 4 * index + 4 * offset
    return None


def _split(text: str) -> tuple[str, str, bool] | None:
    """(qualified name, parameters, const) of a demangled function name."""
    depth = 0
    for at, c in enumerate(text):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif c == "(" and depth == 0:
            end = text.rfind(")")
            if end < at:
                return None
            return text[:at], text[at + 1:end], text[end + 1:].strip() == "const"
    return None


def _parts(qualified: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for at, c in enumerate(qualified):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif depth == 0 and qualified.startswith("::", at):
            parts.append(qualified[start:at])
            start = at + 2
    parts.append(qualified[start:])
    return [p for p in parts if p]


def typeinfo_word(image, at: int) -> int | None:
    """A class table group's typeinfo word: 0 without RTTI, else the address of the typeinfo object it points to
    (a relocated pointer into data); None where the word is neither, so no class table is there."""
    if at in image.pointers:
        segment = image.section_at(image.pointers[at])
        return image.pointers[at] if segment is not None and segment.kind == "data" else None
    return None if image.u64(at) else 0


def _groups(program: Program, address: int, size: int) -> list[Group]:
    """A table's groups. Its symbol's size can stop short (an address inside it started another object), so
    slots run on while they are functions, and groups while their offset-to-top is not zero: the next table's
    first group has a zero one. Past its end, never into another object, one a symbol names or something refers
    to (a table of function pointers after it holds functions too), except at a group's first slot, where code
    takes the group's address; a label nothing refers to is no object."""
    from .score import placeholder
    from .signatures import itanium_slots
    image, starts = program.image, program.function_index
    objects = program.cache.get("referred object starts")
    if objects is None:
        pointed = set(image.pointers.values())
        objects = {o.address for o in program.objects if not placeholder(o.name) or o.address in pointed}
        objects |= {o.address for o in program.users()}
        program.cache["referred object starts"] = objects
    out, at = [], 0
    while True:
        start = address + 8 * at
        if image.section_at(start) is None or image.section_at(start + 16) is None:
            break
        if 8 * at >= size and start in objects:
            break                                      # another object's start
        typeinfo = typeinfo_word(image, start + 8)
        if start in image.pointers or typeinfo is None or out and typeinfo != out[0].typeinfo:
            break                                      # every group of one table names one typeinfo
        top = image.u64(start)
        top = top - (1 << 64) if top >> 63 else top
        if out and top == 0 or not out and top != 0 or 8 * at >= size and top == 0:
            break
        slots: list[int | str] = []
        index = at + 2
        while True:
            if 8 * index >= size and index > at + 2 and address + 8 * index in objects:
                break                                  # another object's start, not a group's first slot
            slot = itanium_slots(image, address + 8 * (index - 2), 1, starts)
            if not slot or slot[0][0] == "other":
                break
            slots.append(slot[0][1])
            index += 1
        if not slots:
            break
        out.append(Group(start, -top, slots, typeinfo))
        at = index
    return out


def recover(program: Program) -> dict[str, ItClass]:
    """Every class with a named table, its bases, constructors and destructors."""
    from .platform import demangle_itanium
    tables = [o for o in program.objects if o.name.startswith("_ZTV") and o.size >= 24]
    classes: dict[str, ItClass] = {}
    for table, text in zip(tables, demangle_itanium([o.name for o in tables])):
        if not text or not text.startswith("vtable for "):
            continue
        groups = _groups(program, table.address, table.size)
        if groups:
            classes[text[len("vtable for "):]] = ItClass(text[len("vtable for "):], table.address, groups)
    named = methods(program)
    stored = _stored(program, classes, named)
    _bases(classes, named, stored)
    for _ in range(4):                                 # bases the module has no table for, then bases again
        if not (_tableless(classes, named) | _intermediates(classes, named)):
            break
        _bases(classes, named, stored)
    for address, m in named.items():
        if m.owner in classes and not m.thunk:
            if m.name == _plain(m.owner):
                classes[m.owner].constructors.append(address)
            elif m.name == "~" + _plain(m.owner):
                classes[m.owner].destructors.append(address)
    return classes


def destructor_names(program: Program, classes: dict[str, ItClass] | None = None,
                     every: bool = False) -> dict[int, str]:
    """{function address: Itanium name} for destructors no name says are one: a class whose primary base has a
    virtual destructor has its own in the same two slots of its table (the complete object's, then the deleting
    one), and so does every instance of a template where one instance has it. A function only one class's
    destructor slot holds is that class's (`D1`, or `D2` where the template's other instances are named so, and
    `D0`); one several tables hold (a destructor folded into an identical one) is left. A further base's group
    holds the thunks to them (`_ZThn<offset>_`), each branching to its destructor. `every`: also functions that
    have a name (to check the rule against a build that names them all)."""
    from .score import placeholder
    classes = classes if classes is not None else recover(program)
    named = methods(program)
    names = {f.address: f.name for f in program.functions}

    def kind(slot) -> str | None:
        m = named.get(slot) if isinstance(slot, int) else None
        if m is None or not m.name.startswith("~"):
            return None
        return "D0" if names[slot].endswith("D0Ev") else "D2" if names[slot].endswith("D2Ev") else "D1"
    slots: dict[str, dict[int, str]] = {name: {k: d for k, s in enumerate(cls.groups[0].slots) if (d := kind(s))}
                                        for name, cls in classes.items()}
    stems: dict[str, list[str]] = collections.defaultdict(list)
    for name in classes:
        if "<" in name:
            stems[name.split("<", 1)[0]].append(name)
    for _ in range(8):
        changed = False
        for name, cls in classes.items():
            base = next((b for o, b in cls.bases if o == 0), None)
            for k, d in (slots.get(base, {}) if base else {}).items():
                if k < len(cls.groups[0].slots) and k not in slots[name]:
                    slots[name][k] = "D0" if d == "D0" else "D1"
                    changed = True
        for members in stems.values():
            union: dict[int, str] = {}
            for name in members:
                union.update(slots[name])
            for name in members:
                for k, d in union.items():
                    if k < len(classes[name].groups[0].slots) and k not in slots[name]:
                        slots[name][k] = d
                        changed = True
        if not changed:
            break
    holders: dict[int, set] = collections.defaultdict(set)
    for cls in classes.values():
        for group in cls.groups:
            for s in group.slots:
                if isinstance(s, int):
                    holders[s].add(cls.name)
    objects = {o.address: o for o in program.objects}
    out = {}
    for name, cls in classes.items():
        table = objects.get(cls.table) if cls.table is not None else None
        if table is None or not table.name.startswith("_ZTV"):
            continue
        complete = next((cls.groups[0].slots[k] for k, d in slots[name].items() if d != "D0"), None)
        for k, d in slots[name].items():
            s = cls.groups[0].slots[k]
            if not isinstance(s, int) or holders[s] != {name} or not (every or placeholder(names.get(s, ""))):
                continue
            # its code says so too: it stores its class's table, or (deleting) calls the complete one, or the
            # base's own destructor is another function: a base's destructor folded into this class's identical
            # one (the base's table dropped) does none of these
            index = program.function_index.get(s)
            refers = index is not None and any(table.address <= a < table.address + table.size
                                               for _, a, _ in program.refs.get(index, ()))
            calls = index is not None and d == "D0" and program.function_index.get(complete) in \
                program.calls.get(index, ())
            base = next((b for o, b in cls.bases if o == 0), None)
            theirs = classes[base].groups[0].slots[k] if base in classes and \
                k < len(classes[base].groups[0].slots) else None
            other = isinstance(theirs, int) and theirs != s   # the base's own is another function: not folded
            if not (refers or calls or other):
                continue
            nested = table.name[4:]
            out[s] = f"_Z{nested[:-1]}{d}Ev" if nested.startswith("N") else f"_ZN{nested}{d}Ev"
        # a further base's group holds, in its base's destructor slots, the thunks that adjust `this` and branch to
        # this class's destructors
        own = {d: cls.groups[0].slots[k] for k, d in slots[name].items() if isinstance(cls.groups[0].slots[k], int)}
        for group in cls.groups[1:]:
            base = next((b for o, b in cls.bases if o == group.offset), None)
            for k, d in (slots.get(base, {}) if base else {}).items():
                if k >= len(group.slots) or not isinstance(group.slots[k], int):
                    continue
                s = group.slots[k]
                target = own.get("D0" if d == "D0" else "D1", own.get("D2"))
                index = program.function_index.get(s)
                if target is None or index is None or holders[s] != {name} or \
                        not (every or placeholder(names.get(s, ""))) or \
                        program.function_index.get(target) not in program.calls.get(index, ()):
                    continue
                kind_name = names.get(target, "")
                letter = "D0" if d == "D0" else ("D2" if kind_name.endswith("D2Ev") else "D1")
                nested = table.name[4:]
                body = f"{nested[:-1]}{letter}Ev" if nested.startswith("N") else f"N{nested}{letter}Ev"
                out[s] = f"_ZThn{group.offset}_{body}"
    return out


def override_names(program: Program, classes: dict[str, ItClass] | None = None,
                   every: bool = False) -> dict[int, str]:
    """{function address: Itanium name} for the overrides no name says are one: a primary slot keeps one method
    across the class that declares it and every class below it, so a function only one class's table holds, in a
    slot where the others' names all agree, is that class's method of that name and parameters. The name is a
    named member's with its class replaced, kept only where it demangles to the same method of this class and no
    part of this class's name that the other's lacks recurs in the parameters (where a mangler would substitute
    it). Destructors are `destructor_names`'. `every`: also functions that have a name."""
    from .platform import demangle_itanium
    from .score import placeholder
    classes = classes if classes is not None else recover(program)
    named = methods(program)
    names = {f.address: f.name for f in program.functions}
    objects = {o.address: o for o in program.objects}
    holders: dict[int, set] = collections.defaultdict(set)
    for cls in classes.values():
        for group in cls.groups:
            for s in group.slots:
                if isinstance(s, int):
                    holders[s].add(cls.name)
    nested: dict[str, list[str]] = {}                 # class -> its name's source names, from its table's symbol
    for name, cls in classes.items():
        table = objects.get(cls.table) if cls.table is not None else None
        if table is not None and table.name.startswith("_ZTV"):
            text = table.name[4:]
            tokens = _source_names(text[1:-1] if text.startswith("N") and text.endswith("E") else text)
            if tokens:
                nested[name] = tokens
    family: dict[tuple[str, int], list[int]] = collections.defaultdict(list)
    for name, cls in classes.items():
        for index, slot in enumerate(cls.groups[0].slots):
            if isinstance(slot, int):
                family[(_introducer(classes, name, index), index)].append(slot)
    candidates: dict[int, set[tuple[str, str]]] = collections.defaultdict(set)   # address -> (name, demangled)
    for (_, index), slots in family.items():
        members = {s: named[s] for s in set(slots) if s in named and not named[s].thunk}
        signatures = {_signature(m) for m in members.values()}
        if len(signatures) != 1 or next(iter(signatures))[0].startswith("~"):
            continue
        sources = [(s, m) for s, m in sorted(members.items()) if m.owner in nested]
        for name, cls in classes.items():
            s = cls.groups[0].slots[index] if index < len(cls.groups[0].slots) else None
            if not isinstance(s, int) or s not in slots or holders[s] != {name} or name not in nested or \
                    not (every or placeholder(names.get(s, ""))):
                continue
            for _, m in sorted(sources, key=lambda row: -_common(nested[row[1].owner], nested[name])):
                symbol = _swapped(m.symbol, nested[m.owner], nested[name])
                if symbol:
                    candidates[s].add((symbol, f"{name}::{m.name}({m.params}){' const' if m.const else ''}"))
                    break
    rows = [(s, *next(iter(c))) for s, c in candidates.items() if len(c) == 1]
    demangled = demangle_itanium([symbol for _, symbol, _ in rows])
    return {s: symbol for (s, symbol, want), text in zip(rows, demangled) if text == want}


def _source_names(text: str) -> list[str] | None:
    """`2gf6Camera` -> ['2gf', '6Camera']; None for anything but a plain sequence of source names."""
    out, at = [], 0
    while at < len(text):
        digits = re.match(r"[1-9]\d*", text[at:])
        if not digits:
            return None
        end = at + len(digits.group()) + int(digits.group())
        if end > len(text):
            return None
        out.append(text[at:end])
        at = end
    return out or None


def _common(a: list[str], b: list[str]) -> int:
    n = 0
    while n < min(len(a), len(b)) and a[n] == b[n]:
        n += 1
    return n


def _swapped(symbol: str, own: list[str], other: list[str]) -> str | None:
    """A method symbol of the class named `own` as the same method of the class named `other`, or None where
    the method or its parameters are not plainly spelled or would spell differently there."""
    match = re.match(r"_ZN([rVK]*)", symbol)
    body = symbol[match.end():] if match else ""
    prefix = "".join(own)
    if not match or not body.startswith(prefix):
        return None
    method = re.match(r"([1-9]\d*)", body[len(prefix):])
    if not method:
        return None
    end = len(prefix) + len(method.group()) + int(method.group())
    if not body[end:].startswith("E") or len(body) == end + 1:
        return None
    params = body[end + 1:]
    if any(token in params for token in other[_common(own, other):]):
        return None
    return f"_ZN{match.group(1)}{''.join(other)}{body[len(prefix):end]}E{params}"


def _plain(qualified: str) -> str:
    """A class's own name, less its qualifiers and template arguments."""
    last = _parts(qualified)[-1]
    return last.split("<", 1)[0]


def _same_method(a: str, b: str) -> bool:
    return a == b or (a.startswith("~") and b.startswith("~"))


def _bases(classes: dict[str, ItClass], named: dict[int, Method], stored: list | None = None) -> None:
    by_slot: dict[tuple[int, int], set[str]] = collections.defaultdict(set)
    for name, cls in classes.items():
        for index, slot in enumerate(cls.groups[0].slots):
            if isinstance(slot, int):
                by_slot[(index, slot)].add(name)
    chosen: dict[str, list] = {}
    for name, cls in classes.items():
        rows = []
        for group in cls.groups:
            candidates = set()
            for index, slot in enumerate(group.slots):
                if isinstance(slot, int) and (m := named.get(slot)) is not None and m.owner != name:
                    candidates |= by_slot.get((index, slot), set())
            candidates.discard(name)
            scored = []
            for candidate in candidates:
                base = classes[candidate].groups[0].slots
                fit = _fits_as(cls, group.slots, base, named, candidate)
                if fit is not None and fit[0]:             # it inherits one of the candidate's own functions
                    scored.append((len(base), *fit, candidate))   # of the ancestors that fit, the nearest
            scored.sort(reverse=True)
            top = [s for s in scored if s[:3] == scored[0][:3]] if scored else []
            rows.append((group.offset, top))
        chosen[name] = rows
    for name, rows in chosen.items():                 # ties: the one every other tied candidate derives from
        cls = classes[name]
        cls.bases, cls.unresolved, cls.evidence = [], [], {}
        for offset, top in rows:
            if len(top) == 1:
                cls.bases.append((offset, top[0][3]))
            elif top:
                tied = [t[3] for t in top]
                roots = [c for c in tied if all(c == o or c in _ancestors(chosen, o) for o in tied)]
                if len(roots) == 1:
                    cls.bases.append((offset, roots[0]))
                else:
                    cls.unresolved.append((offset, tied))
        for offset, _ in cls.bases:
            cls.evidence[offset] = [("table prefix", None)]
    _stored_bases(classes, named, stored or [])


def _fits_as(cls: ItClass, slots: list, base: list, named: dict[int, Method], candidate: str):
    if len(base) > len(slots):
        return None
    own = shared = 0
    for index, theirs in enumerate(base):
        mine = slots[index]
        if mine == theirs:
            if isinstance(theirs, int):
                shared += 1
                m = named.get(theirs)
                own += m is not None and m.owner == candidate and not m.name.startswith("~")
            continue
        if isinstance(mine, str) or isinstance(theirs, str):
            continue
        mm, tm = named.get(mine), named.get(theirs)
        if mm is None or tm is None:
            continue
        if mm.name.startswith("~") and tm.name.startswith("~"):
            continue                                   # every class has its own; identical ones fold anywhere
        if mm.owner != cls.name or not _same_method(mm.name, tm.name):
            return None
    return own, shared


def _ancestors(chosen: dict[str, list], name: str, seen: frozenset = frozenset()) -> list[str]:
    rows = chosen.get(name)
    if not rows or len(rows[0][1]) != 1:
        return []
    base = rows[0][1][0][3]
    if base in seen:
        return []
    return [base] + _ancestors(chosen, base, seen | {base})


NEW = ("_Znw", "_Zna")                                 # operator new and new[], the module's own overloads too


def _role(m: Method | None, classes: dict[str, ItClass]) -> str | None:
    if m is None or m.thunk or m.owner not in classes:
        return None
    return {_plain(m.owner): "constructor", "~" + _plain(m.owner): "destructor"}.get(m.name)


def _stored(program: Program, classes: dict[str, ItClass], named: dict[int, Method]) -> list[tuple]:
    """(class, its primary ancestors nearest last, how, function) from the table address points (a table's start
    + 16) code stores at offset 0 of one object, in order: a constructor (C1/C2) stores its bases' tables before
    its own; a destructor (D0/D1/D2) its own (not at all when its body is empty: clang skips it), then its bases';
    a new-expression its class's bases' tables, then its class's own (the last one) into what `new` returned. A
    call passing the object adds the tables its callee stores into its own `this` (a base's constructor or
    destructor, not inlined). An object with a table stored twice, or a constructor whose last table is not its
    own, proves nothing."""
    from .aarch64 import THIS, object_stores
    points = {cls.table + 16: name for name, cls in classes.items() if cls.table is not None}
    events = {}
    for function in program.functions:
        try:
            words = program.platform.words(program.image, function.address, function.size)
        except ValueError:
            continue
        events[function.address] = object_stores(words, function.address, program.image.pointers.get)
    own = {address: [points[e[4]] for e in rows
                     if e[0] == "store" and e[2] == THIS and e[3] == 0 and e[4] in points]
           for address, rows in events.items()}
    new = {f.address for f in program.functions if f.name.startswith(NEW)}
    out = []
    for address, rows in events.items():
        role = _role(named.get(address), classes)
        objects, made = collections.defaultdict(list), {}
        for e in rows:
            if e[0] == "store" and e[3] == 0 and e[4] in points:
                objects[e[2]].append(points[e[4]])
            elif e[0] == "call":
                made[e[1]] = e[2]
                if e[3] is not None and e[4] == 0:
                    objects[e[3]] += own.get(e[2], [])
        for origin, tables in objects.items():
            tables = [t for i, t in enumerate(tables) if not i or tables[i - 1] != t]
            if len(set(tables)) != len(tables):
                continue
            if origin == THIS and role == "constructor":
                name, chain, how = named[address].owner, tables, "constructor"
            elif origin == THIS and role == "destructor":
                name, how = named[address].owner, "destructor"
                chain = tables[:0:-1] if tables[:1] == [name] else tables[::-1]
                chain.append(name)
            elif origin != THIS and made.get(origin) in new and tables:
                name, chain, how = tables[-1], tables, "new-expression"
            else:
                continue
            if len(chain) >= 2 and chain[-1] == name and name not in chain[:-1]:
                out.append((name, chain[:-1], how, address))
    return out


def _stored_bases(classes: dict[str, ItClass], named: dict[int, Method], stored: list[tuple]) -> None:
    """Primary bases from the tables code stores (`_stored`). Each chain proves its tables ancestors of its class,
    in order; so do the bases the table prefixes found. A class's base is its nearest proven ancestor: the one
    every other candidate (each chain's nearest, the table prefix's base) is a proven ancestor of. It must fit the
    class's table as a base, close no cycle, and no class proven to derive from it may fit between them (an
    intermediate whose stores the compiler dropped: an empty body, or a store overwritten before anything reads
    it). Anything else leaves the table prefix's reading as it is."""
    above: dict[str, set[str]] = collections.defaultdict(set)
    for name, ancestors, _, _ in stored:
        for lower, upper in zip(ancestors[1:] + [name], ancestors):
            above[lower].add(upper)
    for name, cls in classes.items():
        above[name] |= {b for o, b in cls.bases if o == 0}
    proven: dict[str, set[str]] = {}
    for name in list(above):
        seen, stack = set(), list(above[name])
        while stack:
            current = stack.pop()
            if current not in seen:
                seen.add(current)
                stack.extend(above.get(current, ()))
        proven[name] = seen - {name}
    below: dict[str, set[str]] = collections.defaultdict(set)
    for name, ancestors in proven.items():
        for ancestor in ancestors:
            below[ancestor].add(name)
    near: dict[str, dict[str, list]] = collections.defaultdict(dict)
    for name, ancestors, how, function in stored:
        near[name].setdefault(ancestors[-1], []).append((how, function))
    for name, found in near.items():
        cls = classes[name]
        slot = next((b for o, b in cls.bases if o == 0), None)
        candidates = set(found) | ({slot} if slot else set())
        nearest = [c for c in candidates if all(o == c or o in proven.get(c, ()) for o in candidates)]
        if len(nearest) != 1 or nearest[0] not in found:
            continue                                   # contradictory, or the table prefix's base is nearer
        base = nearest[0]
        if base != slot:
            if name in proven.get(base, ()) or not _fits(cls, classes[base], named):
                continue
            if any(m != name and name not in proven.get(m, ()) and _fits(cls, classes[m], named)
                   for m in below[base]):
                continue                               # a class between them, its stores dropped
            cls.bases = [(0, base)] + [(o, b) for o, b in cls.bases if o != 0]
            cls.unresolved = [(o, t) for o, t in cls.unresolved if o != 0]
            cls.evidence[0] = []
        cls.evidence[0] = cls.evidence.get(0, []) + found[base]


def _fits(cls: ItClass, base: ItClass, named: dict[int, Method]) -> bool:
    return _fits_as(cls, cls.groups[0].slots, base.groups[0].slots, named, base.name) is not None


def _tableless(classes: dict[str, ItClass], named: dict[int, Method]) -> bool:
    """Bases the module has no table for: classes with no primary base whose inherited functions (any but their
    own, destructors aside: identical ones fold across classes) all belong to one class with no table. That class's primary slots are the prefix
    up to its last function: its own function where its derived classes hold one, the one they all inherit
    otherwise, pure where they differ."""
    families: dict[str, list[ItClass]] = collections.defaultdict(list)
    for cls in classes.values():
        if not any(o == 0 for o, _ in cls.bases):
            group = cls.groups[0]
            owners = {named[s].owner for s in group.slots if isinstance(s, int) and s in named
                      and named[s].owner != cls.name and not named[s].name.startswith("~") and not named[s].thunk}
            owners = {o for o in owners if o is not None and o not in classes}   # known ancestors aside
            if len(owners) == 1:
                families[next(iter(owners))].append(cls)
    secondary: dict[str, list[Group]] = collections.defaultdict(list)
    for cls in classes.values():
        for group in cls.groups[1:]:
            if any(o == group.offset for o, _ in cls.bases):
                continue
            owners = {named[s].owner for s in group.slots if isinstance(s, int) and s in named
                      and not named[s].thunk and not named[s].name.startswith("~")}
            owners.discard(None)
            if len(owners) == 1 and (owner := next(iter(owners))) not in classes and owner not in families:
                secondary[owner].append(group)
    added = False
    for owner, groups in secondary.items():          # its functions where the groups hold them, else pure
        slots: list[int | str] = []
        for index in range(max(len(g.slots) for g in groups)):
            own = {g.slots[index] for g in groups if index < len(g.slots) and isinstance(g.slots[index], int)
                   and g.slots[index] in named and named[g.slots[index]].owner == owner}
            slots.append(next(iter(own)) if len(own) == 1 else PURE[0])
        classes[owner] = ItClass(owner, None, [Group(0, 0, slots)])
        added = True
    for owner, children in families.items():
        last = max(i for c in children for i, s in enumerate(c.groups[0].slots)
                   if isinstance(s, int) and s in named and named[s].owner == owner)
        slots: list[int | str] = []
        for index in range(last + 1):
            seen = {c.groups[0].slots[index] for c in children if index < len(c.groups[0].slots)}
            own = {s for s in seen if isinstance(s, int) and s in named and named[s].owner == owner}
            inherited = len(seen) == 1 and not any(isinstance(s, int) and s in named and named[s].owner in
                                                   {c.name for c in children} for s in seen)
            slots.append(next(iter(own)) if len(own) == 1 else next(iter(seen)) if inherited else PURE[0])
        classes[owner] = ItClass(owner, None, [Group(0, 0, slots)])
        added = True
    return added


def _intermediates(classes: dict[str, ItClass], named: dict[int, Method]) -> bool:
    """A class between a class and its base that the module has no table for: the slots the class neither
    inherits from its base nor overrides itself hold one other class's functions. That class derives from the
    base, its slots the base's with its own functions where its derived classes hold them."""
    families: dict[str, list[ItClass]] = collections.defaultdict(list)
    for cls in classes.values():
        primary = next((b for o, b in cls.bases if o == 0), None)
        if primary is None:
            continue
        base = classes[primary].groups[0].slots
        foreign = set()
        for index, slot in enumerate(cls.groups[0].slots):
            if index < len(base) and slot == base[index] or not isinstance(slot, int) or slot not in named:
                continue
            owner = named[slot].owner
            if owner != cls.name and owner is not None and not named[slot].thunk \
                    and not named[slot].name.startswith("~"):
                foreign.add(owner)
        foreign = {o for o in foreign if o not in classes}                   # known ancestors aside
        if len(foreign) == 1 and (owner := next(iter(foreign))) != primary:
            families[owner].append(cls)
    added = False
    for owner, children in families.items():
        bases = {next(b for o, b in c.bases if o == 0) for c in children}
        if len(bases) != 1:
            continue
        primary = next(iter(bases))
        base = classes[primary].groups[0].slots
        last = max(i for c in children for i, s in enumerate(c.groups[0].slots)
                   if isinstance(s, int) and s in named and named[s].owner == owner)
        slots: list[int | str] = []
        for index in range(max(last + 1, len(base))):
            seen = {c.groups[0].slots[index] for c in children if index < len(c.groups[0].slots)}
            own = {s for s in seen if isinstance(s, int) and s in named and named[s].owner == owner}
            mine = len(seen) == 1 and any(isinstance(s, int) and s in named and named[s].owner in
                                          {c.name for c in children} for s in seen)
            if len(own) == 1:
                slots.append(next(iter(own)))
            elif index < len(base):
                slots.append(base[index])
            else:
                slots.append(next(iter(seen)) if len(seen) == 1 and not mine else PURE[0])
        classes[owner] = ItClass(owner, None, [Group(0, 0, slots)], bases=[(0, primary)])
        added = True
    return added


# Declarations

BUILTIN = {"void", "bool", "char", "signed char", "unsigned char", "wchar_t", "char16_t", "char32_t", "short",
           "unsigned short", "int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long",
           "float", "double", "long double", "__int128", "unsigned __int128", "decltype(nullptr)", "std::nullptr_t"}
LITERAL = re.compile(r"^-?\d+(u|ul|l|ull|ll|ul)?$|^(true|false)$")
LITERAL_TYPES = {"": "int", "u": "unsigned int", "l": "long", "ul": "unsigned long", "ll": "long long",
                 "ull": "unsigned long long"}
ENUM_LIKE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ENUM_VALUE = re.compile(r"^\(((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\)-?\d+$")   # `(ns::E)24`: an enum's value


@dataclass
class Declared:
    name: str                          # qualified
    header: str                        # its path under the include folder
    text: str                          # the class definition
    namespaces: list[str]              # the namespaces it is defined in
    includes: set[str]                 # headers it needs whole (bases, enclosing classes)
    types: set[str]                    # qualified types its signatures name (declared ahead)
    defines: list[str]                 # out-of-class definitions that make the compiler emit its table
    problems: list[str] = field(default_factory=list)
    instances: list[str] = field(default_factory=list)   # a class template: the instances the module has


def _signature(m: Method) -> tuple[str, str, bool]:
    return m.name, m.params, m.const


def _introducer(classes: dict[str, ItClass], name: str, index: int, seen: frozenset = frozenset()) -> str:
    """The class that declares primary slot `index` first: the topmost primary ancestor that has the slot."""
    cls = classes[name]
    base = next((b for o, b in cls.bases if o == 0), None)
    if base in classes and base not in seen and index < len(classes[base].groups[0].slots):
        return _introducer(classes, base, index, seen | {name})
    return name


def _slot_signatures(classes: dict[str, ItClass], named: dict[int, Method]) -> dict[tuple[str, int], tuple]:
    """(introducing class, slot) -> (method, params, const): its own function's name, else the name its overrides
    agree on (a pure slot), else `vf<slot>`."""
    votes: dict[tuple[str, int], collections.Counter] = collections.defaultdict(collections.Counter)
    for name, cls in classes.items():
        for index, slot in enumerate(cls.groups[0].slots):
            m = named.get(slot) if isinstance(slot, int) else None
            if m is not None and not m.thunk:
                votes[(_introducer(classes, name, index), index)][_signature(m)] += 1 + 99 * (
                    _introducer(classes, name, index) == name)       # the class's own function decides
        for group in cls.groups[1:]:                  # a secondary base's slots, from what overrides them
            base = next((b for o, b in cls.bases if o == group.offset), None)
            if base not in classes:
                continue
            for index, slot in enumerate(group.slots):
                m = named.get(slot) if isinstance(slot, int) else None
                if m is not None and index < len(classes[base].groups[0].slots):
                    votes[(_introducer(classes, base, index), index)][_signature(m)] += 1
    out = {}
    for key, counter in votes.items():
        signature = counter.most_common(1)[0][0]
        if signature[0].startswith("~"):
            signature = ("~", "", False)
        out[key] = signature
    return out


def _kinds(classes: dict[str, ItClass], named: dict[int, Method]) -> set[str]:
    """The classes: a qualifier with a table, a constructor or a destructor is a class; any other qualifier is a
    namespace (an enclosing namespace mangles as a class would)."""
    classy = set(classes)
    for m in named.values():
        if m.owner and not m.thunk and (m.name == _plain(m.owner) or m.name == "~" + _plain(m.owner)):
            classy.add(m.owner)
    return classy


def _split_namespaces(qualified: str, classy: set[str]) -> tuple[list[str], list[str]]:
    """(namespaces, class path) of a qualified name: everything from the first class prefix is class scope."""
    parts = _parts(qualified)
    for k in range(1, len(parts)):
        if "::".join(parts[:k]) in classy:
            return parts[:k - 1], parts[k - 1:]
    return parts[:-1], parts[-1:]


def _header_path(qualified: str, classy: set[str]) -> str:
    namespaces, path = _split_namespaces(qualified, classy)
    return "classes/" + "/".join(namespaces + path) + ".h"


NAME = re.compile(r"(?<![\w:])(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*")
WORDS = {"const", "volatile", "unsigned", "signed", "long", "short", "char", "int", "float", "double", "bool",
         "void", "wchar_t", "true", "false"}


def _types(params: str) -> set[str]:
    """The class and enum types a parameter list names: a template's instance whole (`ns::T<a, b>`), and the
    types in its arguments too."""
    out, at = set(), 0
    while (match := NAME.search(params, at)) is not None:
        text, at = match.group(0), match.end()
        if at < len(params) and params[at] == "<":     # a template's arguments, balanced
            depth, end = 0, at
            while end < len(params):
                depth += {"<": 1, ">": -1}.get(params[end], 0)
                if depth == 0:
                    break
                end += 1
            inner = params[at + 1:end]
            out.add(text + params[at:end + 1])
            out |= _types(inner)
            at = end + 1
            continue
        if text in WORDS or text in BUILTIN or LITERAL.match(text):
            continue
        out.add(text)
    return out


def _template(name: str) -> tuple[str, list[str]]:
    """(the template, its arguments) of a class template's instance; (name, []) for any other class."""
    last = _parts(name)[-1]
    if "<" not in last or not last.endswith(">"):
        return name, []
    stem = name[:len(name) - len(last)] + last.split("<", 1)[0]
    inner = last[last.index("<") + 1:-1]
    args, depth, start = [], 0, 0
    for at, c in enumerate(inner):
        depth += {"<": 1, "(": 1, ">": -1, ")": -1}.get(c, 0)
        if c == "," and depth == 0:
            args.append(inner[start:at].strip())
            start = at + 1
    args.append(inner[start:].strip())
    return stem, args


def _header_of(name: str, classy: set[str]) -> str:
    return _header_path(_template(name)[0], classy)


def _layout(program: Program, classes: dict[str, ItClass], named: dict[int, Method]
            ) -> tuple[dict[str, list[tuple[int, str]]], dict[str, ItClass], dict[str, int], list[str]]:
    """Each class's bases in layout order, as the declarations spell them, with a placeholder (`TUnk_<address>`)
    for a base no evidence names: a class with secondary bases always has a primary one (its table pointer is
    the primary base's), and a secondary group no base explains still needs a base with a table there. A group
    the primary base has at the same offset is the primary base's, not another base. Sizes follow: a base ends
    where the next one starts, so each base before another one is exactly as large as the gap."""
    placeholders: dict[str, ItClass] = {}
    bases: dict[str, list[tuple[int, str]]] = {}
    problems: list[str] = []
    for name, cls in classes.items():
        primary = next((b for o, b in cls.bases if o == 0), None)
        inherited = {g.offset for g in classes[primary].groups} if primary in classes else set()
        rows = []
        for group in cls.groups:
            if group.offset in inherited and group.offset:
                continue
            base = next((b for o, b in cls.bases if o == group.offset), None)
            if base is None and (group.offset or len(cls.groups) > 1):
                base = f"TUnk_{group.address:X}"
                slots = [s if isinstance(s, int) and s in named and named[s].thunk is False
                         and named[s].owner != name else PURE[0] for s in group.slots]
                if group.offset == 0:                  # a primary placeholder: every slot, the class overrides
                    slots = [PURE[0]] * len(group.slots)   # them all (which are its base's no evidence says)
                placeholders[base] = ItClass(base, None, [Group(0, 0, slots)])
                placeholders[base]._thunks = (name, group)          # whose overrides name its slots
            if base is not None:
                rows.append((group.offset, base))
        bases[name] = rows
    needs: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)   # base -> (derived, row, size)
    for name, rows in bases.items():
        for k, ((offset, base), (following, _)) in enumerate(zip(rows, rows[1:])):
            needs[base].append((name, k, following - offset))
    exact = {}
    for base, rows in needs.items():
        smallest = min(size for _, _, size in rows)
        exact[base] = smallest
        for derived, k, size in rows:                 # a larger primary base: a class between them with fields
            if size == smallest:                       # and no virtuals of its own
                continue
            if k != 0 or base not in classes:
                problems.append(f"{derived}: {base} would be 0x{size:X} bytes there, 0x{smallest:X} elsewhere")
                continue
            between = f"TUnk_{classes[derived].groups[0].address:X}"
            placeholders[between] = ItClass(between, None, classes[base].groups, bases=[(0, base)])
            placeholders[between]._between = base
            bases[between] = [(0, base)]
            bases[derived][0] = (0, between)
            exact[between] = size
    return bases, placeholders, exact, problems


def declarations(program: Program, classes: dict[str, ItClass]) -> dict[str, Declared]:
    """A declaration for every class that is no template instance: bases in layout order (placeholders where no
    evidence names one), the virtuals it introduces or overrides in slot order (an inherited slot is not
    redeclared), one destructor for a pair of destructor slots, padding to the size its derived classes prove."""
    named = methods(program)
    signatures = _slot_signatures(classes, named)
    classy = _kinds(classes, named)
    layout, placeholders, sizes, problems = _layout(program, classes, named)
    out: dict[str, Declared] = {}
    every = {**classes, **placeholders}
    instances: dict[str, list] = collections.defaultdict(list)
    for name in _base_first(classes):
        stem, args = _template(name)
        if name.startswith("std::"):
            continue
        if any("<" in part for part in _parts(name)[:-1]):
            problems.append(f"{name}: a member class of a template's instance (not declared yet)")
            continue
        cls = classes[name]
        namespaces, path = _split_namespaces(stem, classy)
        includes, types, before = set(), set(), []
        local = []
        for offset, base in layout.get(name, []):
            if base in placeholders and hasattr(placeholders[base], "_between"):
                parent = placeholders[base]._between
                includes.add(_header_of(parent, classy))
                pad = _padding(base, layout, sizes, every)
                before.append("\n".join([f"// between {name} and {parent}: fields, no virtuals of its own",
                                         f"class {base} : public ::{parent} {{", "public:", *pad, "};"]))
                continue
            if base in placeholders:
                text, defines = _placeholder(placeholders[base], named, signatures, classes, sizes.get(base, 8))
                before.append(text)
                local.append(base)
                types |= set().union(*(_types(named[s].params) for s in placeholders[base]._thunks[1].slots
                                       if isinstance(s, int) and s in named))
            else:
                includes.add(_header_of(base, classy))
                types |= _types(base) - {base}            # a template base's arguments
        if len(path) > 1:
            includes.add(_header_path("::".join(namespaces + path[:-1]), classy))
        primary = next((b for o, b in layout.get(name, []) if o == 0), None)
        base_slots = every[primary].groups[0].slots if primary in every else []
        lines, defines, done_dtor = [], [], False
        declared_here = set()
        unknown_primary = primary in placeholders and not hasattr(placeholders[primary], "_between")
        for index, slot in enumerate(cls.groups[0].slots):
            introducer = name if unknown_primary else _introducer(classes, name, index)
            method, params, const = signatures.get((introducer, index), (f"vf{index}", "", False))
            if index < len(base_slots) and slot == base_slots[index] and method != "~":
                continue                                # inherited (a destructor never is: identical ones fold)
            declared_here.add((method, params, const))
            pure = isinstance(slot, str)
            if method == "~":
                if not done_dtor:
                    lines.append(f"    virtual ~{path[-1]}();  // slot {index}")
                    defines.append(f"{name}::~{path[-1]}() {{}}")
                    done_dtor = True
                continue
            types |= _types(params)
            suffix = " const" if const else ""
            lines.append(f"    virtual void {method}({params}){suffix}{' = 0' if pure else ''};  // slot {index}")
            if not pure:
                defines.append(f"void {name}::{method}({params}){suffix} {{}}")
        for group in cls.groups[1:]:                  # overrides of a secondary base's virtuals: thunks only
            for slot in group.slots:
                m = named.get(slot) if isinstance(slot, int) else None
                if m is None or not m.thunk or m.owner != name or m.name.startswith("~"):
                    continue
                if (m.name, m.params, m.const) in declared_here:
                    continue
                declared_here.add((m.name, m.params, m.const))
                types |= _types(m.params)
                suffix = " const" if m.const else ""
                lines.append(f"    virtual void {m.name}({m.params}){suffix};  // overrides a secondary base's")
                defines.append(f"void {name}::{m.name}({m.params}){suffix} {{}}")
        lines += _padding(name, layout, sizes, every)
        head = f"class {'::'.join(path)}" + (" : " + ", ".join(
            f"public {b if b in placeholders else _rooted(b)}" for _, b in layout.get(name, [])) if layout.get(name)
            else "") + " {"
        table = program.platform.text(cls.table) if cls.table is not None else "none (its derived classes')"
        unknown = [f"base at 0x{o:X} unknown ({b})" for o, b in layout.get(name, []) if b in placeholders]
        if args:                                       # an instance: its template, voted from every instance
            instances[stem].append((name, args, before, head, lines, includes, types, unknown))
            continue
        text = "\n".join([*before, f"// table {table}" + (f"; {', '.join(unknown)}" if unknown else ""), head,
                          "public:", *lines, "};"])
        out[name] = Declared(name, _header_path(name, classy), text, namespaces,
                             includes - {_header_path(name, classy)}, types, defines, unknown)
    for stem, rows in instances.items():
        declared = _template_declaration(stem, rows, classy)
        if isinstance(declared, str):
            problems.append(declared)
        else:
            out[stem] = declared
    if out:
        next(iter(out.values())).problems += problems
    return out


def _rooted(name: str) -> str:
    """A class's name as a base clause spells it: from the global namespace, its template arguments too (inside
    `game::shop`, `game::shop::game` would name the class's own member)."""
    rooted = re.sub(r"(?<![\w:])(?=[A-Za-z_]\w*::)", "::", name)
    return ("::" + rooted if not rooted.startswith("::") else rooted).replace("<::", "< ::")


def _generalize(text: str, args: list[str]) -> str:
    """An instance's text with its template arguments spelled as the template's parameters (a type nested in
    one is a dependent name: `typename T0::Inner`)."""
    for index, arg in sorted(enumerate(args), key=lambda row: -len(row[1])):
        text = re.sub(r"(?<![\w:])(?:::)?" + re.escape(arg) + r"(?![\w])", f"T{index}", text)
    return re.sub(r"(?<![\w:])(T\d+::[A-Za-z_]\w*)", r"typename \1", text)


def _template_declaration(stem: str, rows: list, classy: set[str]) -> Declared | str:
    """A class template from its instances: the parameter kinds every instance's arguments agree on, and the
    declaration most instances generalize to."""
    kinds = {tuple(_template_kinds(", ".join(args)) or []) for _, args, *_ in rows}
    if len(kinds) != 1:
        return f"template {stem}: its instances' arguments are of different kinds"
    kind = next(iter(kinds))
    namespaces, path = _split_namespaces(stem, classy)
    plain = path[-1]
    votes = collections.Counter()
    bodies = {}
    for row in rows:
        name, args, before, head, lines, includes, types, unknown = row
        instance = _parts(name)[-1]
        own, _, bases = head.partition(" : ")      # its bases name the instance in full: no injected name yet
        head = own.replace(instance, plain) + (" : " + bases if bases else "")
        body = _generalize("\n".join([*(b.replace(instance, plain) for b in before), head, "public:",
                                      *(line.replace(instance, plain) for line in lines), "};"]), args)
        votes[body] += 1
        bodies.setdefault(body, []).append(row)
    body = votes.most_common(1)[0][0]
    winners = bodies[body]                             # the instances that agree: their includes and types
    parameters = ", ".join(f"{k} T{i}" for i, k in enumerate(kind))
    text = f"// a template: {len(rows)} instances in the module\ntemplate <{parameters}>\n" + body
    includes = set().union(*(r[5] for r in winners)) - {_header_path(stem, classy)}
    types = {t for r in winners for t in _types(_generalize(" ".join(sorted(r[6])), r[1]))
             if not re.fullmatch(r"T\d+", t) and not re.search(r"(?<![\w:])T\d+(?![\w])", t)}
    types |= {k for k in kind if k not in BUILTIN and k != "typename"}   # an enum a parameter's values are of
    return Declared(stem, _header_path(stem, classy), text, namespaces, includes, types, [], [],
                    instances=[r[0] for r in rows])


def _placeholder(cls: ItClass, named: dict[int, Method], signatures: dict, classes: dict,
                 size: int = 8) -> tuple[str, list]:
    """A base no evidence names: a destructor and the virtuals its derived class overrides there (from the
    thunks), pure; any other slot `vf<slot>`."""
    owner, group = cls._thunks
    lines, done = [], False
    slots = group.slots
    dtor_pair = len(slots) >= 2 and all(not isinstance(s, int) or s not in named or named[s].name.startswith("~")
                                        for s in slots[:2]) and (group.offset == 0 or any(
        isinstance(s, int) and s in named and named[s].name.startswith("~") for s in slots[:2])
        or all(isinstance(s, int) and s not in named for s in slots[:2]))
    for index, slot in enumerate(slots):
        m = named.get(slot) if isinstance(slot, int) else None
        if dtor_pair and index < 2:
            if not done:
                lines.append(f"    virtual ~{cls.name}();")
                done = True
            continue
        if m is not None and m.name.startswith("~"):
            if not done:
                lines.append(f"    virtual ~{cls.name}();")
                done = True
        elif m is not None and (m.thunk or group.offset == 0):
            lines.append(f"    virtual void {m.name}({m.params}){' const' if m.const else ''} = 0;")
        elif m is not None:
            lines.append(f"    virtual void {m.name}({m.params}){' const' if m.const else ''};")
        else:
            lines.append(f"    virtual void vf{index}();")
    if size > 8:
        lines.append(f"    unsigned char pad_8[0x{size - 8:X}];  // fields: size from where the next base starts")
    return "\n".join([f"// a base of {owner} no evidence names yet", f"class {cls.name} {{", "public:", *lines,
                      "};"]), []


def _padding(name: str, layout: dict, sizes: dict[str, int], every: dict) -> list[str]:
    """A member padding the class to the size its derived classes prove, after its bases and table pointer."""
    if name not in sizes:
        return []
    rows = layout.get(name, [])
    if rows:
        offset, last = rows[-1]
        start = offset + sizes.get(last, 8)
    else:
        start = 8                                      # its own table pointer
    if sizes[name] <= start:
        return []
    return [f"    unsigned char pad_{start:X}[0x{sizes[name] - start:X}];  // fields: size from its derived classes"]


def _relative(qualified: str, namespaces: list[str]) -> str:
    """A name spelled from inside `namespaces` (fully qualified: always unambiguous)."""
    return "::" + qualified


def _base_first(classes: dict[str, ItClass]) -> list[str]:
    order, seen = [], set()

    def visit(name: str) -> None:
        if name in seen or name not in classes:
            return
        seen.add(name)
        for _, base in classes[name].bases:
            visit(base)
        order.append(name)
    for name in sorted(classes):
        visit(name)
    return order


# Headers

def _by_value(params: str, typename: str) -> bool:
    return re.search(re.escape(typename) + r"(?:\s+const)?\s*(?:,|$)", params) is not None


def _template_kinds(arguments: str) -> list[str] | None:
    """`template <...>` parameter kinds for one use's arguments (a literal's type, else `typename`)."""
    out, depth, start = [], 0, 0
    pieces = []
    for at, c in enumerate(arguments):
        if c in "<(":
            depth += 1
        elif c in ">)":
            depth -= 1
        elif c == "," and depth == 0:
            pieces.append(arguments[start:at].strip())
            start = at + 1
    pieces.append(arguments[start:].strip())
    for piece in pieces:
        match = LITERAL.match(piece)
        cast = ENUM_VALUE.match(piece)
        if match:
            out.append("bool" if piece in ("true", "false") else LITERAL_TYPES[match.group(1) or ""])
        elif cast:
            out.append(cast.group(1))                  # an enumerator's value: the enum is the parameter's type
        else:
            out.append("typename")
    return out


@dataclass
class Headers:
    files: dict[str, str]                       # header path -> text
    forward: dict[str, str]                     # type -> its forward declaration (inside its namespaces)
    complete: dict[str, str]                    # type -> an empty definition (for a proof's translation unit)
    declared: dict[str, Declared]
    problems: list[str]


def headers(program: Program, classes: dict[str, ItClass]) -> Headers:
    """One header per class declaration (bases and enclosing classes included, the types its signatures name
    declared ahead), and one per enclosing class that has no table (its nested types declared)."""
    named = methods(program)
    classy = _kinds(classes, named)
    declared = declarations(program, classes)
    params_of: dict[str, list[str]] = collections.defaultdict(list)
    for d in declared.values():
        for t in d.types:
            params_of[t].append(d.name)
    uses = collections.defaultdict(list)
    for m in named.values():
        for t in _types(m.params):
            uses[t].append(m.params)
    enums = set()                                      # types a template argument casts a number to
    for name in list(classes) + [t for d in declared.values() for t in d.types]:
        enums |= set(re.findall(r"\(((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\)-?\d+", name))
    for name in classes:                               # the types in instances' arguments need declaring too
        if "<" in name and not name.startswith("std::"):
            for t in _types(name) - {name}:
                if "<" not in t and t not in classes:
                    params_of[t].append(name)
    problems, forward, complete = [], {}, {}
    nested: dict[str, set[str]] = collections.defaultdict(set)     # enclosing class -> nested declarations
    templates: dict[str, list[list[str]]] = collections.defaultdict(list)
    for t in params_of:
        if "<" in t:
            stem, arguments = t.split("<", 1)
            kinds = _template_kinds(arguments[:-1])
            if kinds:
                templates[stem].append(kinds)
    for stem, kinds in templates.items():
        if stem in declared:                           # a template with a header: included, not declared ahead
            continue
        if len({tuple(k) for k in kinds}) == 1:
            namespaces, path = _split_namespaces(stem, classy)
            parameters = ", ".join(k for k in kinds[0])
            if len(path) == 1:
                forward[stem] = f"template <{parameters}> class {path[0]};"
                complete[stem] = f"template <{parameters}> class {path[0]} {{}};"
        else:
            problems.append(f"template {stem} is used with different parameter kinds")
    for t in sorted(params_of):
        if "<" in t:
            continue
        namespaces, path = _split_namespaces(t, classy)
        enum = t in enums or ENUM_LIKE.match(path[-1]) and t not in classy and all(
            _by_value(p, t) or t not in p for p in uses[t])
        kind = f"enum {path[-1]} : int;" if enum else f"class {path[-1]};"
        if len(path) > 1:                              # nested: its enclosing class declares it
            nested["::".join(namespaces + path[:-1])].add(kind)
            if not enum:
                complete[t] = f"class {'::'.join(path)} {{}};"
            continue
        forward[t] = kind
        if not enum and t not in declared:
            complete[t] = f"class {path[0]} {{}};"
    for d in declared.values():                       # a nested class with a table: its enclosing class says so
        namespaces, path = _split_namespaces(d.name, classy)
        if len(path) > 1:
            nested["::".join(namespaces + path[:-1])].add(f"class {path[-1]};")
    files: dict[str, str] = {}
    shells = {e for e in nested if e not in declared}
    pending = list(shells)
    while pending:                                    # a nested enclosing class: its own enclosing declares it
        enclosing = pending.pop()
        namespaces, path = _split_namespaces(enclosing, classy)
        if len(path) > 1:
            outer = "::".join(namespaces + path[:-1])
            nested[outer].add(f"class {path[-1]};")
            if outer not in declared and outer not in shells:
                shells.add(outer)
                pending.append(outer)
    for enclosing in sorted(shells):
        if "<" in enclosing:                           # a template's instance encloses it: not declared yet
            continue
        namespaces, path = _split_namespaces(enclosing, classy)
        body = ["// a class with no table: what is declared inside it", f"class {'::'.join(path)} {{", "public:",
                *(f"    {n}" for n in sorted(nested[enclosing])), "};"]
        includes = {_header_path("::".join(namespaces + path[:-1]), classy)} if len(path) > 1 else set()
        files[_header_path(enclosing, classy)] = _file(_header_path(enclosing, classy), namespaces, "\n".join(body),
                                                       includes, [])
    for d in declared.values():
        text = d.text
        if d.name in nested:                          # into its own class, the last in the text
            inner = [f"    {n}" for n in sorted(nested[d.name])]
            head, mark, tail = text.rpartition("public:")
            text = head + mark + "\n" + "\n".join(inner) + tail
        includes = set(d.includes)
        ahead = []
        for t in sorted(d.types):
            stem = t.split("<", 1)[0]
            namespaces, path = _split_namespaces(stem, classy)
            if stem in declared and "<" in t:
                includes.add(declared[stem].header)
            elif len(path) > 1:
                includes.add(_header_path("::".join(namespaces + path[:-1]), classy))
            elif stem in forward:
                ahead.append((namespaces, forward[stem]))
        files[d.header] = _file(d.header, d.namespaces, text, includes - {d.header}, ahead)
    return Headers(files, forward, complete, declared, problems)


def _file(path: str, namespaces: list[str], text: str, includes: set[str], ahead: list) -> str:
    guard = re.sub(r"\W", "_", path).upper()
    lines = [f"#ifndef {guard}", f"#define {guard}", ""]
    lines += [f'#include "{i}"' for i in sorted(includes)]
    if includes:
        lines.append("")
    for spaces, declaration in sorted(set((tuple(n), d) for n, d in ahead)):
        lines.append(_in(list(spaces), declaration))
    if ahead:
        lines.append("")
    lines += [_open(namespaces), text, _close(namespaces), "", "#endif"]
    return "\n".join(line for line in lines if line is not None) + "\n"


def _open(namespaces: list[str]) -> str | None:
    return " ".join(f"namespace {n} {{" for n in namespaces) if namespaces else None


def _close(namespaces: list[str]) -> str | None:
    return "}" * len(namespaces) + f"  // namespace {'::'.join(namespaces)}" if namespaces else None


def _in(namespaces: list[str], declaration: str) -> str:
    return (" ".join(f"namespace {n} {{" for n in namespaces) + f" {declaration} " + "}" * len(namespaces)
            if namespaces else declaration)


def audit(program: Program, class_filter: str | None = None, limit: int = 60) -> dict[str, Any]:
    """What the tables say: classes, bases found, tied or unknown, bases rebuilt from derived classes."""
    classes = recover(program)
    text = program.platform.text
    counts: collections.Counter = collections.Counter()
    rows = []
    for name, cls in sorted(classes.items()):
        counts["rebuilt from derived classes" if cls.table is None else "with a table"] += 1
        primary = next((b for o, b in cls.bases if o == 0), None)
        counts["primary base found" if primary else "primary base tied" if any(o == 0 for o, _ in cls.unresolved)
               else "no primary base"] += 1
        if primary:
            kinds = {"table prefix" if how == "table prefix" else "code" for how, _ in cls.evidence.get(0, [])}
            counts["primary base by " + " and ".join(sorted(kinds, reverse=True))] += 1
        for group in cls.groups[1:]:
            counts["secondary base found" if any(o == group.offset for o, _ in cls.bases)
                   else "secondary base unknown"] += 1
        if not class_filter or name.lower() == class_filter.lower():
            rows.append({"class": name, "table": text(cls.table) if cls.table is not None else None,
                         "bases": [{"offset": o, "base": b, "evidence": _evidence(cls.evidence.get(o, []), text)}
                                   for o, b in cls.bases],
                         "tied": [{"offset": o, "candidates": t[:4]} for o, t in cls.unresolved],
                         "slots": [len(g.slots) for g in cls.groups]})
    return {"classes": len(classes), "counts": dict(counts), "rows": rows[:limit]}


def _evidence(rows: list[tuple[str, int | None]], text) -> list[str]:
    """What proved a base, one line per kind: the table prefix, or the first function of each kind that stores
    its table (and how many more do)."""
    out: dict[str, list] = {}
    for how, function in rows:
        out.setdefault(how, []).append(function)
    return [how if functions == [None] else f"{how} {text(functions[0])}"
            + (f" (+{len(functions) - 1})" if len(functions) > 1 else "") for how, functions in out.items()]


def write_headers(program: Program, folder: Path, unproven: dict[str, str] | None = None) -> dict[str, Any]:
    """Every class's header into `folder` (the include root: headers land under `classes/`), each one a proof
    (`check`) found wanting saying why at its top."""
    built = headers(program, recover(program))
    reasons = {built.declared[n].header: r for n, r in (unproven or {}).items() if n in built.declared}
    for path, text in built.files.items():
        target = folder / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if path in reasons:
            text = f"// not proven yet: {reasons[path]}\n" + text
        target.write_text(text, encoding="utf-8")
    return {"folder": str(folder), "headers": len(built.files), "classes": len(built.declared),
            "problems": built.problems}


# Proof

def compile_argv(project, target: str, source: Path, obj: Path, includes: list[Path]) -> list[str]:
    """The target's own compiler and flags (its build settings over the platform's defaults) compiling one file."""
    from . import build
    config = project.target(target)
    settings = build.settings(config)
    if settings is None:
        raise ValueError(f"Target {target} has no `build` settings to compile with")
    root = project.root(config["repository"])
    compiler, wanted = build.compiler(root, settings)
    if compiler is None:
        raise ValueError(f"No compiler {wanted} for target {target}")
    argv = [str(compiler), *build.words(settings.get("cflags")), *build.words(settings.get("extra_cflags"))]
    argv += [f"-I{p}" for p in includes] + [f"-I{root / i}" for i in settings.get("includes", [])]
    return argv + ["-c", str(source), "-o", str(obj)]


def _compiled_table(obj: Path, symbol: str) -> list[str] | None:
    """A compiled table's words: a relocation's symbol (a slot, the typeinfo object), else `=<value>`
    (offset-to-top, a typeinfo word built without RTTI)."""
    import struct
    from .elf import Elf
    elf = Elf.load(obj)
    table = next((s for s in elf.symbols if s.name == symbol and 0 < s.section < 0xFF00), None)
    if table is None:
        return None
    section = elf.sections[table.section]
    data = elf.data(section)
    aliases: dict[tuple[int, int], set[str]] = collections.defaultdict(set)
    for s in elf.symbols:
        if 0 < s.section < 0xFF00 and s.kind == "func":
            aliases[(s.section, s.value)].add(s.name)
    relocations = {}
    for r in elf.relocations(section):
        target = elf.symbols[r.symbol]
        relocations[r.offset] = frozenset(aliases.get((target.section, target.value), set()) | {target.name})
    out: list = []
    for at in range(table.value, table.value + table.size, 8):
        if at in relocations:
            out.append(relocations[at])
        else:
            out.append(f"={struct.unpack_from('<q', data, at)[0]}")
    return out


def _original_table(program: Program, cls: ItClass) -> list[str]:
    names = {f.address: f.name for f in program.functions}
    objects = {o.address: o.name for o in program.objects}
    out = []
    for group in cls.groups:
        typeinfo = objects.get(group.typeinfo, f"lbl_{group.typeinfo:X}") if group.typeinfo else "=0"
        out += [f"={-group.offset}", typeinfo]
        out += [s if isinstance(s, str) else names.get(s, f"fn_{s:X}") for s in group.slots]
    return out


def _folded(want: str, got: frozenset) -> bool:
    """The original slot holds another class's destructor of the same variant (the linker kept one copy of a
    derived destructor identical to its base's). Other folded code can carry any name: never assumed."""
    variant = want[-4:]
    if variant not in ("D0Ev", "D1Ev", "D2Ev") or "D" not in want:
        return False
    complete = variant in ("D1Ev", "D2Ev")
    return any(n[-4:] in (("D1Ev", "D2Ev") if complete else ("D0Ev",)) for n in got)


def prove(project, target: str | None = None, program: Program | None = None, class_filter: str | None = None,
          limit: int = 60, folder: Path | None = None) -> dict[str, Any]:
    """`check` with the target's own compiler and flags, in `build/zkit-classes`."""
    import subprocess
    from .bridge import default_target
    target = default_target(project, target)
    program = program or Program.from_project(project, target)
    scratch = folder or project.root(project.target(target)["repository"]) / "build" / "zkit-classes"

    def compile(source: Path, obj: Path, include: Path) -> subprocess.CompletedProcess:
        argv = compile_argv(project, target, source, obj, [include])
        argv.insert(len(argv) - 4, "-O0")             # keep the constructor that stores its table (no key function)
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=300)
    return {"target": target, "platform": "switch", **check(program, compile, scratch, class_filter, limit)}


def check(program: Program, compile, scratch: Path, class_filter: str | None = None,
          limit: int = 60) -> dict[str, Any]:
    """Compile every class's header (`compile(source, object, include folder)`), defining the virtuals it
    declares, using its constructor (a table with no key function is emitted where it is used) and an empty
    definition of every type it only declares ahead; compare the table the compiler emits with the original's,
    word by word: offsets-to-top, typeinfo, each slot's symbol."""
    classes = recover(program)
    built = headers(program, classes)
    include = scratch / "include"
    for path, text in built.files.items():
        (include / path).parent.mkdir(parents=True, exist_ok=True)
        (include / path).write_text(text, encoding="utf-8")
    counts: collections.Counter = collections.Counter()
    differences = []
    unproven: dict[str, str] = {}                     # declaration -> why its table is not proven
    tables = {o.address: o.name for o in program.objects if o.name.startswith("_ZTV")}
    work = scratch / "proof"
    work.mkdir(parents=True, exist_ok=True)
    classy = _kinds(classes, methods(program))
    jobs = []
    for d in built.declared.values():
        for name in d.instances or [d.name]:
            jobs.append((name, d))
    for name, d in sorted(jobs, key=lambda job: job[0]):
        if class_filter and name.lower() != class_filter.lower() and d.name.lower() != class_filter.lower():
            continue
        cls = classes[name]
        if cls.table is None:
            counts["no table to compare"] += 1
            continue
        needed = set(d.types) | (_types(name) - {name} if d.instances else set())
        lines = [f'#include "{d.header}"']
        for t in sorted(needed):
            stem = t.split("<", 1)[0]
            if stem in built.declared:
                lines.append(f'#include "{built.declared[stem].header}"')
        stems = set()                                  # one template, two instances: declared once
        for t in sorted(needed):
            stem = t.split("<", 1)[0]
            if stem in stems:
                continue
            stems.add(stem)
            namespaces, path = _split_namespaces(stem, classy)
            if len(path) > 1:                          # a nested type: its enclosing class declares it
                enclosing = "::".join(namespaces + path[:-1])
                lines.append(f'#include "{_header_path(enclosing, classy)}"')
            if stem in built.complete and stem not in built.declared:
                lines.append(_in(namespaces, built.complete[stem]))
            elif stem in built.forward and stem not in built.declared:
                lines.append(_in(namespaces, built.forward[stem]))
            elif stem not in built.declared and "<" not in t and len(path) == 1:
                lines.append(_in(namespaces, f"class {path[0]} {{}};"))   # no header declares it
        lines += d.defines
        if d.instances:
            lines.append(f"template class {name};")
        lines += [f"struct zkit_use : {name} {{ zkit_use(); }};", "zkit_use::zkit_use() {}"]   # its table, always
        stem = re.sub(r"[^A-Za-z0-9]+", "_", name)
        if len(stem) > 80:                             # a deep template instance: a short, unique name
            import hashlib
            stem = stem[:60] + "_" + hashlib.sha1(name.encode()).hexdigest()[:12]
        source = work / f"{stem}.cpp"
        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
        obj = source.with_suffix(".o")
        result = compile(source, obj, include)
        if result.returncode or not obj.is_file():
            counts["does not compile"] += 1
            unproven.setdefault(d.name, "does not compile: " + next(
                (line.split("error: ", 1)[1] for line in (result.stderr or "").splitlines() if "error: " in line), "?"))
            differences.append({"class": name, "problem": "does not compile",
                                "output": (result.stderr or result.stdout).strip().splitlines()[:3]})
            continue
        got = _compiled_table(obj, tables[cls.table])
        want = _original_table(program, cls)
        if got is None:
            counts["no table emitted"] += 1
            unproven.setdefault(d.name, "the compiler emits no table from it")
            differences.append({"class": name, "problem": "the compiler emitted no table"})
            continue
        wrong, folded, unnamed = [], 0, 0
        for index in range(max(len(got), len(want))):
            g = got[index] if index < len(got) else None
            w = want[index] if index < len(want) else None
            if g == w or (isinstance(g, frozenset) and w in g):
                continue
            if isinstance(g, frozenset) and w is not None and w.startswith("fn_"):
                unnamed += 1                           # a slot the module's names do not reach: shape only
                continue
            if isinstance(g, frozenset) and w is not None and _folded(w, g):
                folded += 1                            # the linker kept one copy of identical code
                continue
            wrong.append((index, sorted(g)[0] if isinstance(g, frozenset) else g, w))
        if wrong:
            counts["table differs"] += 1
            index, g, w = wrong[0]
            unproven.setdefault(d.name, f"its table differs from the original's (word {index}: {g} where the "
                                        f"original has {w})")
            differences.append({"class": name, "problem": "table differs", "words": wrong[:4],
                                "lengths": (len(got), len(want))})
        elif unnamed:
            counts["table equal where named"] += 1
        else:
            counts["table equal (identical code folded)" if folded else "table equal"] += 1
    return {"classes": len(built.declared), "headers": len(built.files), "counts": dict(counts), "unproven": unproven,
            "differences": differences[:limit], "problems": built.problems[:limit], "folder": str(scratch),
            "limits": "A table equal word for word proves the declaration's bases, virtual block and the offsets "
                      "of its bases; return types and fields are not in the table (padding stands for fields a "
                      "derived class's layout proves). `TUnk_` classes are bases no evidence names yet."}


_SCALAR = re.compile(r"^(?:const\s+)?(?:bool|char|signed char|unsigned char|short|unsigned short|int|unsigned int|long|"
                     r"unsigned long|long long|unsigned long long|wchar_t|char16_t|char32_t)(?:\s+const)?$")


def parameters(demangled: str) -> tuple[str, list[str], bool] | None:
    """(qualified name, parameter types, const) of a demangled function name, by its outermost parameter list."""
    text, const = (demangled[:-6], True) if demangled.endswith(" const") else (demangled, False)
    if not text.endswith(")"):
        return None
    depth = 0
    for index in range(len(text) - 1, -1, -1):
        if text[index] in ")>":
            depth += 1
        elif text[index] in "(<":
            depth -= 1
            if depth == 0:
                if text[index] != "(":
                    return None
                head, inner = text[:index], text[index + 1:-1]
                break
    else:
        return None
    params, depth, current = [], 0, ""
    for ch in inner:
        depth += ch in "<(" and 1 or ch in ">)" and -1 or 0
        if ch == "," and depth == 0:
            params.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        params.append(current.strip())
    return head, ([] if params == ["void"] else params), const


def argument_registers(demangled: str) -> tuple[int, int] | None:
    """The most AAPCS64 argument registers a C++ function's parameters can fill: (general, SIMD/FP). A member
    function may take `this` in x0 (its name does not say whether it is static), a class passed by value up to
    two general or four SIMD/FP registers (its size is unknown here); None for a variadic or unreadable name."""
    parsed = parameters(demangled)
    if parsed is None:
        return None
    head, params, _ = parsed
    if "..." in params:
        return None
    general = vector = 0
    for param in params:
        if re.search(r"\(\S*::\*\)", param):                  # a pointer to member function: two words
            general += 2
        elif param.endswith(("*", "&", "* const", "& const")) or re.search(r"\((?:\*|&)\)", param):
            general += 1
        elif param in ("float", "double", "float const", "double const"):
            vector += 1
        elif _SCALAR.match(param):
            general += 1
        else:
            general, vector = general + 2, vector + 4
    bare = head
    while re.search(r"<[^<>]*>", bare):
        bare = re.sub(r"<[^<>]*>", "", bare)
    bare = bare.split("operator")[0] if "operator" in bare else bare.split(" ")[-1]
    return general + ("::" in bare), vector
