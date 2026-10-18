"""Classes recovered from the code: constructors, destructor, base, members, size and fields, from the virtual
tables (`vtables.find`) and where `this` goes (`ppcflow`).

The evidence, all of it in the original's code:
- A constructor stores its class's table pointer into the object after constructing the base and the members, so
  the last table it stores is its own; tables it stored before at the same offset are inlined bases.
- A destructor is one of its class's slots and stores its own table first, then (inlined) its bases' tables.
- A constructor calling another class's constructor with `this` is calling its base's; with `this + k`, a member's
  at offset k. Destructors call base and member destructors the same way.
- `new` is a call with a constant size whose result reaches a constructor: that size is the class's size.
- Loads and stores through `this` in a class's own functions give its fields (offset, width, integer or float).
Each fact carries the evidence that proved it, and a class's name comes only from symbols that already exist.
"""

from __future__ import annotations

import collections
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import ppcflow
from .program import Program
from . import cwnames, vtables
from .vtables import VTable, find

ALLOCATOR_EVIDENCE = 3  # constant-size calls whose result reaches a constructor before a function counts as `new`
DOMINANT = 0.8          # share of a slot family's names one name needs before it is proposed for the rest


@dataclass
class ClassInfo:
    vtable: int
    pointer: int | None = None                        # offset of the table pointer in the object
    constructors: list[int] = field(default_factory=list)
    destructor: int | None = None
    base: int | None = None                           # the base class's table
    base_evidence: str | None = None
    members: dict[int, int] = field(default_factory=dict)   # offset -> member class table
    sizes: collections.Counter = field(default_factory=collections.Counter)
    fields: dict[int, collections.Counter] = field(default_factory=lambda: collections.defaultdict(
        collections.Counter))                         # offset -> Counter((width, float))

    @property
    def size(self) -> int | None:
        return self.sizes.most_common(1)[0][0] if self.sizes else None


def recover(program: Program, tables: dict[int, VTable] | None = None) -> dict[int, ClassInfo]:
    tables = find(program) if tables is None else tables
    flows = ppcflow.flows(program)
    allocators = _allocators(program, flows, tables)
    if allocators:
        flows = ppcflow.flows(program, frozenset(allocators))
    classes = {address: ClassInfo(address) for address in tables if not tables[address].offset}
    own: dict[int, int] = {}                          # function index -> its class's table
    ancestors: dict[int, list[int]] = {}              # function index -> tables of inlined bases, nearest first
    slot_of = collections.defaultdict(set)
    for address, table in tables.items():
        for slot in table.slots:
            if slot:
                slot_of[slot].add(address)
    for index, flow in flows.items():
        installs = [(s.base.amount + s.offset, s.value.amount) for s in flow.stores
                    if s.base.kind == ppcflow.THIS and s.value is not None and s.value.kind == ppcflow.ADDR
                    and s.value.amount in classes and s.width == 4]
        if not installs:
            continue
        address = program.functions[index].address
        destroyed = [(o, t) for o, t in installs if t in slot_of.get(address, ())]
        if destroyed:                                 # a destructor: its own table first, then its bases'
            offset, mine = destroyed[0]
            info = classes[mine]
            info.destructor = address
            later = [t for o, t in installs[installs.index((offset, mine)) + 1:] if o == offset and t != mine]
        else:                                         # a constructor: its own table last, its bases' before
            offset, mine = installs[-1]
            info = classes[mine]
            info.constructors.append(address)
            later = [t for o, t in reversed(installs[:-1]) if o == offset and t != mine]
        info.pointer = offset if info.pointer is None else info.pointer
        own[index] = mine
        ancestors[index] = list(dict.fromkeys(later))
        for o, t in installs:                         # tables stored at another offset: inlined member objects
            if o != offset and t != mine and o not in info.members:
                info.members[o] = t
    roles = {program.functions[i].address: classes[t] for i, t in own.items()}
    for index, flow in flows.items():
        caller = roles.get(program.functions[index].address)
        for call in flow.calls:
            this = call.args.get(3)
            callee = roles.get(call.target)
            if this is None or callee is None:
                continue
            if this.kind == ppcflow.NEW and call.target in callee.constructors:
                callee.sizes[this.amount] += 1
            if caller is None or callee is caller or this.kind != ppcflow.THIS:
                continue
            same_kind = (call.target in callee.constructors and program.functions[index].address in
                         caller.constructors) or (call.target == callee.destructor and
                                                  program.functions[index].address == caller.destructor)
            if not same_kind:
                continue
            if this.amount == 0 and caller.base is None:
                caller.base, caller.base_evidence = callee.vtable, "calls its constructor or destructor with this"
            elif this.amount > 0:
                caller.members.setdefault(this.amount, callee.vtable)
    for index, nearest in ancestors.items():          # inlined bases, when no call named one
        info = classes[own[index]]
        if info.base is None and nearest:
            info.base, info.base_evidence = nearest[0], "stores its table before its own (inlined)"
    for info in classes.values():
        base = classes.get(info.base)
        if base is None:
            continue
        if base.pointer is not None and info.pointer is not None and base.pointer != info.pointer:
            # single inheritance shares the table pointer: a table stored elsewhere is a member's, not a base's
            info.base, info.base_evidence = None, None
            continue
        own, inherited = tables[info.vtable], tables[info.base]
        if len(own.slots) < len(inherited.slots):    # a derived table is never shorter than its base's
            _extend(program, own, len(inherited.slots))
    for address, info in classes.items():             # fields from the class's own code
        functions = set(info.constructors) | {info.destructor} | {s for s in _own_slots(tables, classes, address)}
        for function in functions:
            index = program.function_index.get(function)
            if index is None or index not in flows:
                continue
            for access in flows[index].accesses:
                if access.base.kind == ppcflow.THIS and access.base.amount == 0:
                    if access.offset != info.pointer:
                        info.fields[access.offset][(access.width, access.float)] += 1
    return classes


def _extend(program: Program, table: VTable, slots: int) -> None:
    """Read a table on to its base's length when the words there are functions (or pure-virtual zeros)."""
    starts = {f.address for f in program.functions}
    cursor = table.address + 8 + 4 * len(table.slots)
    while len(table.slots) < slots:
        try:
            word = int.from_bytes(program.read(cursor, 4), "big")
        except ValueError:
            return
        if word and word not in starts:
            return
        table.slots.append(word)
        cursor += 4


def _own_slots(tables: dict[int, VTable], classes: dict[int, ClassInfo], address: int) -> list[int]:
    """Slots a class defines itself: not the same function as its base's slot at that index."""
    table = tables[address]
    base = tables.get(classes[address].base) if classes[address].base else None
    return [slot for i, slot in enumerate(table.slots)
            if slot and not (base and i < len(base.slots) and base.slots[i] == slot)]


def _allocators(program: Program, flows: dict[int, ppcflow.Flow], tables: dict[int, VTable]) -> set[int]:
    """Functions whose result, after a call with a constant first argument, reaches a constructor as `this`."""
    installers = {program.functions[i].address for t in tables.values() for i in t.installers}
    sized: set[tuple[int, int]] = set()
    counts: collections.Counter = collections.Counter()
    for index, flow in flows.items():
        constant_calls = {call.pc: call.target for call in flow.calls
                          if (arg := call.args.get(3)) is not None and arg.kind == ppcflow.CONST}
        for call in flow.calls:
            this = call.args.get(3)
            if this is not None and this.kind == ppcflow.RESULT and call.target in installers:
                if this.amount in constant_calls.values() and (index, this.amount) not in sized:
                    sized.add((index, this.amount))
                    counts[this.amount] += 1
    return {target for target, count in counts.items() if count >= ALLOCATOR_EVIDENCE}


def graph(program: Program, tables: dict[int, VTable], classes: dict[int, ClassInfo]) -> dict[str, Any]:
    """The class graph as data, one entry per class, every address written the platform's way."""
    text = program.platform.text
    names = {f.address: f.name for f in program.functions}

    def label(address: int | None) -> str | None:
        if address is None:
            return None
        return tables[address].name or f"TUnk_{text(address)[2:]}"
    out = []
    for address, info in sorted(classes.items()):
        table = tables[address]
        base = tables.get(info.base) if info.base else None
        out.append({
            "class": label(address), "vtable": text(address), "base": label(info.base),
            "base_evidence": info.base_evidence, "pointer_offset": info.pointer, "size": info.size,
            "constructors": [text(a) for a in info.constructors],
            "destructor": text(info.destructor) if info.destructor else None,
            "members": {f"0x{o:X}": label(t) for o, t in sorted(info.members.items())},
            "fields": {f"0x{o:X}": [f"{'f' if fl else 'u'}{w * 8}" for (w, fl), _ in c.most_common()]
                       for o, c in sorted(info.fields.items())},
            "slots": [{"index": i, "function": text(slot) if slot else None, "name": names.get(slot),
                       "inherited": bool(base and i < len(base.slots) and base.slots[i] == slot and slot)}
                      for i, slot in enumerate(table.slots)]})
    return {"classes": out, "count": len(out), "with_base": sum(1 for c in classes.values() if c.base),
            "with_constructor": sum(1 for c in classes.values() if c.constructors),
            "with_destructor": sum(1 for c in classes.values() if c.destructor),
            "with_size": sum(1 for c in classes.values() if c.size)}


# Auditing a decomp's names against the recovered classes

ROLE_PLACEHOLDER = re.compile(r"^(?:fn|sub|func|vfunc|vf|virtual|slot|unk)_?[0-9A-Fa-f]*$|_[0-9A-Fa-f]{8}$")


def class_named(name: str | None) -> str | None:
    """The class a function name places it in: a mangled member, `Class__sub_ADDR`, `Class__ct`, `Class::m`."""
    if not name:
        return None
    if "::" in name:
        return name.split("(")[0].rsplit("::", 1)[0]
    parsed = cwnames.parse(name)
    if parsed is not None and parsed.scope:
        return parsed.qualified
    match = re.match(r"^([A-Za-z_]\w*?)__(?:sub_[0-9A-Fa-f]+|ct|dt|vt\d*|data_[0-9A-Fa-f]+)$", name)
    return match[1] if match else None


def _method(name: str | None) -> cwnames.Name | None:
    parsed = cwnames.parse(name or "")
    return parsed if parsed is not None and parsed.scope else None


def _placeholder(name: str | None) -> bool:
    from .score import placeholder
    if not name:
        return True
    parsed = _method(name)
    return placeholder(name) or bool(ROLE_PLACEHOLDER.search(parsed.method if parsed else name))


def audit_project(project, target: str | None = None, class_filter: str | None = None,
                  limit: int = 60) -> dict[str, Any]:
    """`audit` for a project target (its original and its symbols file)."""
    from .bridge import default_target
    target = default_target(project, target)
    config = project.target(target)
    if (config.get("platform") or "gamecube").lower() not in ("gamecube", "wii", "gc"):
        raise ValueError("Class recovery reads CodeWarrior tables (GameCube and Wii); Switch classes come from "
                         "RTTI (`zkit lookup` on _ZTV/_ZTI names)")
    return {"target": target, **audit(Program.from_project(project, target), class_filter, limit)}


def audit(program: Program, class_filter: str | None = None, limit: int = 60) -> dict[str, Any]:
    """What the recovered classes say about the current names: tables that are not tables, classes without a
    name, constructors and destructors named for another class or for a role, methods filed under the wrong class,
    and names one override proves for every other function in its slot."""
    tables = find(program)
    found = recover(program, tables)
    names = {f.address: f.name for f in program.functions}
    text = program.platform.text
    labelled = {o.address: o.name for o in program.objects if o.name.startswith("__vt__")}
    class_of = _class_names(program, tables, found, names, labelled)

    def label(address: int | None) -> str | None:
        if address is None:
            return None
        return class_of.get(address, (None, ""))[0] or f"TUnk_{text(address)[2:]}"

    def keep(cls: str | None) -> bool:
        return not class_filter or (cls or "").lower() == class_filter.lower()

    findings: dict[str, list] = collections.defaultdict(list)
    for address, name in sorted(labelled.items()):
        if address not in tables and keep(name[6:]):
            findings["not_a_table"].append({"symbol": name, "address": text(address),
                                            "words": _peek(program, address, 8).hex()})
    for address, info in sorted(found.items()):
        cls, how = class_of[address]
        if not keep(label(address)):
            continue
        if address not in labelled:
            findings["unnamed_class"].append({
                "vtable": text(address), "class": cls, "evidence": how,
                "suggested_symbol": f"__vt__{len(cls)}{cls}" if cls else None,
                "constructors": [names.get(f) for f in info.constructors], "destructor": names.get(info.destructor)})
        if not cls:
            continue
        for function, role in [(f, "constructor") for f in info.constructors] + \
                              ([(info.destructor, "destructor")] if info.destructor else []):
            current = names.get(function, "")
            parsed = _method(current)
            wanted = "__ct" if role == "constructor" else "__dt"
            if parsed and parsed.method == wanted and parsed.qualified == cls:
                continue
            named = class_named(current)
            if role == "destructor":                  # CodeWarrior destructors take no declared parameters
                suggested = cwnames.mangle(cwnames.Name("__dt", [cls], False, [cwnames.Type("v", "void")]))
            elif parsed and parsed.params is not None:
                suggested = cwnames.member("__ct", cls, parsed)
            else:
                suggested = f"{cls}::{cls}"
            findings["wrong_class" if named and named != cls else "role_named"].append({
                "address": text(function), "current": current, "role": role, "class": cls,
                "named_class": named, "suggested": suggested})
    # methods: the class that defines a slot function is the one whose table has it first in its hierarchy
    defined_by: dict[int, set[int]] = collections.defaultdict(set)
    for address, table in tables.items():
        base = tables.get(found[address].base) if address in found and found[address].base else None
        for index, slot in enumerate(table.slots):
            if slot and not (base and index < len(base.slots) and base.slots[index] == slot):
                defined_by[slot].add(address)
    special = {f for info in found.values() for f in info.constructors + [info.destructor] if f}
    for function, owners in sorted(defined_by.items()):
        if function in special or len(owners) != 1:
            continue
        owner = next(iter(owners))
        cls = class_of.get(owner, (None, ""))[0]
        named = class_named(names.get(function))
        if cls and named and named != cls and keep(cls):
            findings["wrong_class"].append({"address": text(function), "current": names.get(function),
                                            "role": "virtual method", "class": cls, "named_class": named,
                                            "suggested": _rehome(names.get(function), cls)})
    # one name per slot family: a root's slot and every override below it
    children: dict[int, list[int]] = collections.defaultdict(list)
    for address, info in found.items():
        if info.base:
            children[info.base].append(address)
    for root in [a for a, info in found.items() if not info.base or info.base not in found]:
        for index in range(len(tables[root].slots)):
            family = _family(tables, children, root, index)
            methods = collections.Counter(_method(names.get(f)).method for _, f in family
                                          if f not in special and not _placeholder(names.get(f)) and
                                          _method(names.get(f)))
            if not methods:
                continue
            method, votes = methods.most_common(1)[0]
            if len(methods) > 1 and votes < DOMINANT * sum(methods.values()):
                findings["slot_name_conflict"].append({
                    "root": label(root), "slot": index, "names": dict(methods.most_common(6))})
                continue
            like = next((_method(names.get(f)) for _, f in family if _method(names.get(f)) and
                         _method(names.get(f)).method == method), None)
            for owner, function in family:
                current = _method(names.get(function))
                if function in special or (current and current.method == method):
                    continue
                cls = class_of.get(owner, (None, ""))[0]
                if keep(cls):
                    findings["spread"].append({
                        "address": text(function), "current": names.get(function), "class": cls or label(owner),
                        "slot": index, "slot_name": f"{method} ({votes} of {sum(methods.values())} named)",
                        "suggested": cwnames.member(method, cls or label(owner), like)})
    real_table = {cls: address for address, (cls, _) in class_of.items() if cls}
    for row in findings.get("not_a_table", []):
        cls = vtables._class_from_vtable(row["symbol"])
        if cls in real_table and real_table[cls] not in labelled:
            row["real_table"] = text(real_table[cls])        # the class's table is elsewhere, unnamed
    counts = {key: len(rows) for key, rows in findings.items()}
    return {"classes": len(found), "named_tables": sum(1 for a in found if a in labelled), "counts": counts,
            **{key: rows[:limit] for key, rows in findings.items()},
            "limits": "Tables, constructors, destructors and bases are read from the code (CodeWarrior's table "
                      "layout, `this` in r3); class names only from existing symbols. Suggested names keep the "
                      "current parameter suffix when it is known; a constructor's parameters are not inferred."}


def _class_names(program: Program, tables: dict[int, VTable], found: dict[int, ClassInfo], names: dict[int, str],
                 labelled: dict[int, str]) -> dict[int, tuple[str | None, str]]:
    """A class name for every table, strongest evidence first: its __vt__ symbol; a real class its proper
    constructor and destructor names agree on; a real class its own functions' names agree on (a name another
    table already carries is a misfiled function, not evidence); a placeholder class from those names."""
    from .score import placeholder
    out: dict[int, tuple[str | None, str]] = {}
    for address in found:
        if tables[address].name:
            out[address] = (tables[address].name, "vtable symbol")
    taken = {name for name, _ in out.values()}
    for address, info in found.items():
        if address in out:
            continue
        special = [names.get(f) for f in info.constructors + [info.destructor] if f]
        strong = collections.Counter(_method(n).qualified for n in special
                                     if _method(n) and _method(n).method in ("__ct", "__dt"))
        weak = collections.Counter(class_named(n) for n in special + [names.get(f) for f in
                                   _own_slots(tables, found, address)])
        weak.pop(None, None)
        real = lambda votes: {c: k for c, k in votes.items() if not placeholder(c) and c not in taken}
        choice = None
        if len(real(strong)) == 1:
            choice = (next(iter(real(strong))), "constructor and destructor names")
        elif real(weak):
            name, votes = max(real(weak).items(), key=lambda kv: kv[1])
            if votes >= DOMINANT * sum(real(weak).values()) and votes >= 2:
                choice = (name, f"its own functions' names ({votes} of {sum(real(weak).values())} naming a "
                                f"real class without its own table)")
        if choice is None and len(strong) == 1:
            choice = (next(iter(strong)), "constructor and destructor names (a placeholder class)")
        out[address] = choice or (None, "no name evidence" if not weak else
                                  "conflicting names: " + ", ".join(sorted(weak)[:4]))
    return out


def _family(tables: dict[int, VTable], children: dict[int, list[int]], root: int, index: int) -> list[tuple[int, int]]:
    """(class table, function) for slot `index` from a root down every derived class, one entry per distinct
    function (an inherited slot repeats its base's function)."""
    out, seen, stack = [], set(), [root]
    while stack:
        address = stack.pop()
        table = tables[address]
        if index < len(table.slots) and table.slots[index] and table.slots[index] not in seen:
            seen.add(table.slots[index])
            out.append((address, table.slots[index]))
        stack.extend(children.get(address, ()))
    return out


def _peek(program: Program, address: int, size: int) -> bytes:
    """Up to `size` bytes at an address, fewer at the end of a section."""
    for length in range(size, 0, -1):
        try:
            return program.read(address, length)
        except ValueError:
            continue
    return b""


def _rehome(name: str | None, cls: str) -> str:
    parsed = _method(name)
    return cwnames.member(parsed.method, cls, parsed) if parsed else f"{cls}::{name}"


# Declarations: a header the compiler emits the same tables from

FIELD_TYPES = {(1, False): "u8", (2, False): "u16", (4, False): "u32", (8, False): "u64", (4, True): "f32",
               (8, True): "f64"}


@dataclass
class Declared:
    """One class as a header declares it."""
    name: str
    text: str
    methods: list[str | None]                           # symbols the virtuals mangle to, slot order (None: pure)


def declarations(program: Program, tables: dict[int, VTable], found: dict[int, ClassInfo],
                 class_names: dict[int, str] | None = None) -> dict[int, Declared]:
    """A declaration for every class, bases before derived classes: virtuals in slot order (an inherited slot is
    not redeclared, an override reuses its base's name), the table pointer where the compiler places it (at the
    first virtual a class declares, after the fields before it), fields from the class's own loads and stores,
    padding to its size. Names come from `class_names` and the current symbols; the rest are placeholders."""
    names = {f.address: f.name for f in program.functions}
    class_names = class_names or {}

    def label(address: int) -> str:
        return class_names.get(address) or tables[address].name or f"TUnk_{program.platform.text(address)[2:]}"
    slot_names = _slot_names(tables, found, names)
    out: dict[int, Declared] = {}
    for address in _base_first(found):
        info, table = found[address], tables[address]
        base = found.get(info.base) if info.base in found else None
        base_slots = tables[info.base].slots if base else []
        cls = label(address)
        lines = [f"// vtable {program.platform.text(address)}"
                 + (f", constructors {', '.join(program.platform.text(c) for c in info.constructors)}"
                    if info.constructors else "")
                 + ("" if info.pointer is not None or base else "; table pointer offset not seen (assumed 0)")]
        lines.append(f"class {cls}" + (f" : public {label(info.base)}" if base else "") + " {")
        lines.append("public:")
        start = _size(base, tables, found) if base else 0
        members = _members(info, start, info.size, None if base else info.pointer)
        before = [m for m in members if m[0] < (info.pointer or 0)] if not base else []
        after = [m for m in members if m not in before]
        lines += [f"    {m[1]}" for m in before]
        lines.append(f"    {cls}();")
        methods = []
        for index, slot in enumerate(table.slots):
            inherited = index < len(base_slots) and base_slots[index] == slot
            method = slot_names.get((_root(found, address), index)) or f"vf{index}"
            if slot and slot == info.destructor:
                symbol = cwnames.mangle(cwnames.Name("__dt", [cls], False, [cwnames.Type("v", "void")]))
                if not inherited:
                    lines.append(f"    virtual ~{cls}();" + f"  // slot {index}")
            else:
                symbol = cwnames.mangle(cwnames.Name(method, [cls], False, [cwnames.Type("v", "void")]))
                if not inherited:
                    lines.append(f"    virtual void {method}(){'' if slot else ' = 0'};  // slot {index}")
            methods.append(None if not slot else symbol if not inherited else out[info.base].methods[index])
        lines += [f"    {m[1]}" for m in after]
        lines.append("};")
        out[address] = Declared(cls, "\n".join(lines), methods)
    return out


def _base_first(found: dict[int, ClassInfo]) -> list[int]:
    order, seen = [], set()

    def visit(address: int) -> None:
        if address in seen or address not in found:
            return
        seen.add(address)
        if found[address].base:
            visit(found[address].base)
        order.append(address)
    for address in sorted(found):
        visit(address)
    return order


def _root(found: dict[int, ClassInfo], address: int) -> int:
    while found[address].base in found:
        address = found[address].base
    return address


def _slot_names(tables: dict[int, VTable], found: dict[int, ClassInfo], names: dict[int, str]) -> dict:
    """(root, slot) -> the method name the slot family's real names agree on."""
    votes: dict[tuple[int, int], collections.Counter] = collections.defaultdict(collections.Counter)
    for address, table in tables.items():
        if address not in found:
            continue
        root = _root(found, address)
        for index, slot in enumerate(table.slots):
            parsed = _method(names.get(slot))
            if parsed and parsed.method not in ("__ct", "__dt") and not _placeholder(names.get(slot)):
                votes[(root, index)][parsed.method] += 1
    return {key: c.most_common(1)[0][0] for key, c in votes.items()
            if c.most_common(1)[0][1] >= DOMINANT * sum(c.values())}


def _size(info: ClassInfo, tables: dict[int, VTable], found: dict[int, ClassInfo]) -> int:
    """A class's size: from `new`, else the end of its last known field (or of the table pointer)."""
    if info.size:
        return info.size
    ends = [o + max(w for (w, _), _ in c.items()) for o, c in info.fields.items()]
    if info.pointer is not None:
        ends.append(info.pointer + 4)
    if info.base in found:
        ends.append(_size(found[info.base], tables, found))
    end = max(ends, default=0)
    return (end + 3) & ~3


def _members(info: ClassInfo, start: int, size: int | None, pointer: int | None) -> list[tuple[int, str]]:
    """(offset, declaration) for a class's own fields from `start`, padding the gaps; the table pointer's word is
    skipped (the compiler places it)."""
    out, cursor = [], start
    fields = sorted((o, max(c.items(), key=lambda kv: (kv[1], kv[0][0]))[0]) for o, c in info.fields.items()
                    if o >= start)
    for offset, (width, is_float) in fields:
        if offset < cursor or offset % width or (pointer is not None and pointer <= offset < pointer + 4):
            continue
        if pointer is not None and cursor <= pointer < offset:
            if pointer > cursor:
                out.append((cursor, f"u8 pad_{cursor:X}[0x{pointer - cursor:X}];"))
            cursor = pointer + 4
        if offset > cursor:
            out.append((cursor, f"u8 pad_{cursor:X}[0x{offset - cursor:X}];"))
        out.append((offset, f"{FIELD_TYPES[(width, is_float)]} m_{offset:X};"))
        cursor = offset + width
    if pointer is not None and cursor <= pointer:
        if pointer > cursor:
            out.append((cursor, f"u8 pad_{cursor:X}[0x{pointer - cursor:X}];"))
        cursor = pointer + 4
    if size and size > cursor:
        out.append((cursor, f"u8 pad_{cursor:X}[0x{size - cursor:X}];"))
    return out


# Proving declarations with the project's compiler

TYPES = ("typedef unsigned char u8; typedef unsigned short u16; typedef unsigned long u32; "
         "typedef unsigned long long u64; typedef float f32; typedef double f64;")


def source(found: dict[int, ClassInfo], tables: dict[int, VTable], declared: dict[int, Declared],
           members: list[int]) -> str:
    """A translation unit declaring `members` (bases first) and defining what makes the compiler emit their tables:
    constructors, destructors, every virtual a class defines itself; and each class's size as data."""
    out = [TYPES]
    out += [declared[a].text for a in members]
    for address in members:
        info, table, cls = found[address], tables[address], declared[address].name
        base = tables[info.base].slots if info.base in found else []
        out.append(f"{cls}::{cls}() {{}}")
        for index, slot in enumerate(table.slots):
            if not slot or (index < len(base) and base[index] == slot):
                continue
            if slot == info.destructor:
                out.append(f"{cls}::~{cls}() {{}}")
            else:
                out.append(f"void {cls}::{cwnames.parse(declared[address].methods[index]).method}() {{}}")
        out.append(f"unsigned long zkit_size_{cls} = sizeof({cls});")
    return "\n".join(out) + "\n"


def prove(project, target: str | None = None, class_filter: str | None = None, limit: int = 60) -> dict[str, Any]:
    """Compile every recovered class's declaration with the project's own compile command and compare what the
    compiler emits with the original: the table (each slot's function, its size), where the constructor stores
    the table pointer, and the class's size."""
    import subprocess
    from .bridge import default_target
    from .candidate import _restage, compile_command
    from .elf import Elf
    from .objects import objdiff_units
    target = default_target(project, target)
    program = Program.from_project(project, target)
    tables = find(program)
    found = recover(program, tables)
    declared = declarations(program, tables, found)
    unit = next((u for u in objdiff_units(project, target).values()
                 if str((u.get("metadata") or {}).get("source_path", "")).endswith((".cpp", ".cp", ".cc"))), None)
    if unit is None:
        raise ValueError("No C++ unit in objdiff.json to borrow a compile command from")
    argv, workdir, source_arg = compile_command(project, target, unit)
    scratch = project.root(project.target(target)["repository"]) / "build" / "zkit-classes"
    scratch.mkdir(parents=True, exist_ok=True)
    families: dict[int, list[int]] = collections.defaultdict(list)
    for address in _base_first(found):
        if not class_filter or declared[address].name.lower() == class_filter.lower():
            families[_root(found, address)].append(address)
    if class_filter:                                   # a class needs its bases declared too
        for root, members in families.items():
            chain = []
            for address in members:
                while address in found and address not in chain:
                    chain.insert(0, address)
                    address = found[address].base
            members[:] = [a for a in _base_first(found) if a in chain]
    counts: collections.Counter = collections.Counter()
    differences = []
    for root, members in sorted(families.items()):
        path = scratch / f"family_{root:08X}.cpp"
        path.write_text(source(found, tables, declared, members), encoding="utf-8")
        command, obj = _restage(argv, source_arg, path, scratch, scratch, workdir)
        result = subprocess.run(command, cwd=workdir, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=300)
        if result.returncode or not obj.is_file():
            counts["family_failed_to_compile"] += 1
            differences.append({"class": declared[root].name, "problem": "does not compile",
                                "output": (result.stdout + result.stderr)[-400:]})
            continue
        compiled = _compiled_classes(Elf.load(obj), program)
        for address in members:
            name = declared[address].name
            got = compiled.get(name)
            if got is None:
                counts["table_missing"] += 1
                differences.append({"class": name, "problem": "the compiler emitted no table"})
                continue
            want_slots = declared[address].methods
            if got["slots"] != want_slots:
                counts["table_differs"] += 1
                differences.append({"class": name, "problem": "table differs",
                                    "slots": [(i, g, w) for i, (g, w) in enumerate(
                                        zip(got["slots"] + [None] * len(want_slots), want_slots)) if g != w][:4]})
            else:
                counts["table_equal"] += 1
            info = found[address]
            if info.pointer is not None and got.get("pointer") is not None:
                counts["pointer_equal" if got["pointer"] == info.pointer else "pointer_differs"] += 1
                if got["pointer"] != info.pointer:
                    differences.append({"class": name, "problem": "table pointer offset differs",
                                        "compiled": got["pointer"], "original": info.pointer})
            if info.size and got.get("size") is not None:
                counts["size_equal" if got["size"] == info.size else "size_differs"] += 1
                if got["size"] != info.size:
                    differences.append({"class": name, "problem": "size differs", "compiled": got["size"],
                                        "original": info.size})
    return {"target": target, "classes": sum(len(m) for m in families.values()), "counts": dict(counts),
            "differences": differences[:limit], "scratch": str(scratch),
            "limits": "Each family is compiled standalone with one C++ unit's command; equal tables, pointer "
                      "offsets and sizes prove the declarations' virtual blocks and layout, not field types."}


def _compiled_classes(elf, program: Program) -> dict[str, dict]:
    """{class: {slots, pointer, size}} from a compiled object: its __vt__ tables' relocations, the offset its
    constructor stores the table at (read with the object's relocations applied), and zkit_size_ data."""
    import struct
    from .elf import Elf  # noqa: F401  (the object is an Elf)
    symbols = elf.symbols
    relocations: dict[tuple[int, int], str] = {}
    for section in elf.sections:
        for reloc in elf.relocations(section):
            relocations[(section.index, reloc.offset)] = symbols[reloc.symbol].name
    out: dict[str, dict] = {}
    for symbol in symbols:
        if symbol.name.startswith("__vt__") and 0 < symbol.section < len(elf.sections):
            cls = vtables._class_from_vtable(symbol.name)
            count = max(0, (symbol.size - 8) // 4)
            out[cls] = {"slots": [relocations.get((symbol.section, symbol.value + 8 + 4 * i)) for i in range(count)]}
    fake = {s.index: 0x81000000 + (s.section << 16) + s.value for s in symbols if 0 < s.section < 0xFF00}
    for section in elf.sections:
        if not section.flags & 0x4:
            continue
        words = list(struct.unpack(f">{section.size // 4}I", elf.data(section)))
        for reloc in elf.relocations(section):
            value = fake.get(reloc.symbol, 0) + reloc.addend
            i = reloc.offset // 4
            if reloc.type == 6:                       # R_PPC_ADDR16_HA
                words[i] = (words[i] & ~0xFFFF) | (((value + 0x8000) >> 16) & 0xFFFF)
            elif reloc.type == 4:                     # R_PPC_ADDR16_LO
                words[i] = (words[i] & ~0xFFFF) | (value & 0xFFFF)
        for symbol in symbols:
            if symbol.section != section.index or symbol.kind != "func":
                continue
            parsed = cwnames.parse(symbol.name)
            if not parsed or parsed.method != "__ct" or parsed.qualified not in out:
                continue
            body = words[symbol.value // 4:(symbol.value + symbol.size) // 4]
            table = next((s for s in symbols if s.name == f"__vt__{len(parsed.qualified)}{parsed.qualified}"), None)
            if table is None:
                continue
            for store in ppcflow.flow(body, 0x81F00000 + symbol.value).stores:
                if store.value is not None and store.value.kind == ppcflow.ADDR and \
                        store.value.amount == fake.get(table.index) and store.base.kind == ppcflow.THIS:
                    out[parsed.qualified]["pointer"] = store.base.amount + store.offset
    for symbol in symbols:
        if symbol.name.startswith("zkit_size_") and 0 < symbol.section < len(elf.sections):
            data = elf.data(elf.sections[symbol.section])
            cls = symbol.name[len("zkit_size_"):]
            if cls in out and len(data) >= symbol.value + 4:
                out[cls]["size"] = struct.unpack(">I", data[symbol.value:symbol.value + 4])[0]
    return out


def write_headers(project, target: str | None, folder: Path, types_include: str = "types.h") -> dict[str, Any]:
    """One header per recovered class (its base's header included), for a decomp that has none yet."""
    from .bridge import default_target
    target = default_target(project, target)
    program = Program.from_project(project, target)
    tables = find(program)
    found = recover(program, tables)
    declared = declarations(program, tables, found)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for address in _base_first(found):
        info, entry = found[address], declared[address]
        includes = [f'#include "{types_include}"']
        if info.base in declared:
            includes.append(f'#include "{declared[info.base].name}.h"')
        guard = re.sub(r"\W", "_", entry.name).upper() + "_H"
        path = folder / f"{entry.name}.h"
        path.write_text("\n".join([f"#ifndef {guard}", f"#define {guard}", "", *includes, "", entry.text, "",
                                   f"#endif"]) + "\n", encoding="utf-8")
        written.append(str(path))
    return {"target": target, "folder": str(folder), "headers": len(written)}
