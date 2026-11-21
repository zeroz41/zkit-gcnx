"""A fresh analysis of an original, written as a project configuration: a splits.txt with every
unit's code and data, a symbols.txt, and a header per recovered class, plus the evidence behind each.

Names are only what evidence proves. Functions and data other builds name (the signature cache: libraries every
game links, another build of this one) take those names where the evidence admits one, and data they name that
the symbols lack is added with the donors' size, up to the next symbol. A function a donor with units names is
evidence for the units too: it is in the unit that build put it in. A class table is `__vt__` of its class
and a CodeWarrior destructor is `__dt__<class>Fv` (destructors never declare parameters), so both are named; a
constructor or a virtual method keeps its `fn_` placeholder until its parameters are known, because a mangled
name claims a signature. Classes are recovered from CodeWarrior's tables only; a Switch module's names come from
the signatures, then the destructors and overrides its class tables' slots prove (the method of a slot's other
named functions, whose parameters it shares).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import classes, cwnames, units, vtables
from .program import Program


def analyze(program: Program, fixed: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from . import signatures
    donors = signatures.donors() if signatures.listed() else []
    proposals = signatures.propose(program, donors) if donors else []
    # a donor read from compiled objects (no original) names its units after the files of the sources
    sources = {s.unit for d in donors if not d.images for s in d.signatures if s.unit}
    initializers = units.initializers(program)
    # the donors' units; an initializer's only from another build's initializer (a constructor's shape is no file)
    placed = {p.address: p.unit for p in proposals if p.kind == "function" and p.unit
              and (p.address not in initializers or p.name.startswith("_GLOBAL__sub_I_"))}
    if initializers:                                # what an initializer array calls is named by its file alone
        program = _unnamed(program, initializers)
    misplaced = _misplaced(program, proposals) if program.platform.name != "gamecube" else {}
    if misplaced:                                   # the copies of a name the donors place elsewhere are labels
        from dataclasses import replace
        program = program.derived(objects=[replace(o, name=misplaced[o.address]) if o.address in misplaced else o
                                           for o in program.objects])
    current = {f.address: f.name for f in program.functions} | {o.address: o.name for o in program.objects}
    named = [p for p in proposals if p.kind != "label" and _placeholder(current.get(p.address))
             and p.address not in initializers]
    if program.platform.name != "gamecube":
        named += _slot_names(program, named)
        named = _thunk_offsets(program, named)
        symbols = {address: (name, "object", 0) for address, name in misplaced.items()}
        symbols |= {p.address: (p.name, "function" if p.kind == "function" else "object", 0) for p in named}
        sizes = {p.address: p.size for p in named if p.kind == "object" and p.size}
        # a table no base object starts at (only data points into it) is sized by the module's own words
        tables = {p.address: _table_size(program, p.address) for p in named if p.kind == "object"
                  and p.name.startswith("_ZTV") and (not p.size or p.address not in current)}
        tables = {address: size for address, size in tables.items() if size}
        sizes.update(tables)
        absorbed, resized = _room_for(program, tables)
        more, grown = _grown(program, proposals, {p.address for p in named} | set(tables))
        absorbed |= more
        resized |= {address: size for address, size in grown.items() if address not in resized}
        weak = {p.address for p in named if p.weak}
        with_data = _with_objects(program, _new_objects(program, symbols, sizes, set(current) - absorbed, weak))
        named_program = signatures.renamed(with_data, named)       # the names say which class owns a function
        proposal = units.propose(named_program, fixed, placed, sources)
        own = _initializer_names(program, proposal, initializers)
        named += own
        symbols |= {p.address: (p.name, "function", 0) for p in own}
        return {"units": proposal, "classes": None, "symbols": symbols,
                "sizes": sizes, "signatures": named,     # the data named counts for the units' data
                "weak": weak, "local": {p.address for p in own}, "absorbed": absorbed, "resized": resized}
    proposal = units.propose(program, fixed, placed, sources)
    result: dict[str, Any] = {"units": proposal, "classes": None, "symbols": {}, "signatures": named,
                              "weak": {p.address for p in named if p.weak}}
    program = signatures.renamed(program, named)
    tables = vtables.find(program)
    found = classes.recover(program, tables)
    declared = classes.declarations(program, tables, found)
    names = {f.address: f.name for f in program.functions}
    symbols: dict[int, tuple[str, str, int]] = {      # address -> (name, type, size)
        p.address: (p.name, "function" if p.kind == "function" else "object", 0) for p in named}
    for address, info in found.items():
        cls = declared[address].name
        symbols[address] = (f"__vt__{len(cls)}{cls}", "object", tables[address].size)
        if info.destructor and _placeholder(names.get(info.destructor)):
            symbols[info.destructor] = (cwnames.mangle(cwnames.Name("__dt", [cls], False,
                                                                    [cwnames.Type("v", "void")])), "function", 0)
    result["classes"] = {"graph": classes.graph(program, tables, found), "declared": declared, "found": found}
    result["symbols"] = symbols
    return result


def _slot_names(program: Program, named: list) -> list:
    """Itanium destructors and overrides the class tables name (`itanium.destructor_names`, then
    `itanium.override_names` with the destructors' names in) once the signatures' names are in: weak where their
    class's table is (an inline, a template's; a strong table's inline virtuals are not told apart, and keep the
    binding they had)."""
    from . import itanium, signatures
    if program.platform.name != "switch":
        return []
    out: list = []
    for kind, find in (("destructor slot", itanium.destructor_names), ("override slot", itanium.override_names)):
        renamed = signatures.renamed(program, named + out)
        weak = {o.address for o in renamed.objects if o.scope == "weak"} | set(getattr(program.image, "weak", ()))
        classes = itanium.recover(renamed)
        table_of = {}
        for cls in classes.values():
            for group in cls.groups[:1]:
                for slot in group.slots:
                    if isinstance(slot, int):
                        table_of.setdefault(slot, cls.table)
        out += [signatures.Proposal(address, name, "function", kind, weak=table_of.get(address) in weak)
                for address, name in find(renamed, classes).items()]
    return out


def _thunk_offsets(program: Program, named: list) -> list:
    """The proposals with each `_ZThn<offset>_` name's offset the module's own (`itanium.thunk_offsets`), and a
    proposal for each thunk the symbols already name with another offset: a donor's thunk matches by its shape,
    which leaves out the offset its class's layout in that build gave it, so a name carried over from another build
    can state that build's."""
    import re
    from dataclasses import replace
    from . import itanium, signatures
    thunk = re.compile(r"_ZThn\d+_")
    renamed = signatures.renamed(program, named)
    if not any(thunk.match(f.name) for f in renamed.functions):
        return named
    offsets = itanium.thunk_offsets(renamed)

    def fixed(address: int, name: str) -> str:
        offset = offsets.get(address)
        return name if offset is None or not thunk.match(name) else thunk.sub(f"_ZThn{offset}_", name, count=1)
    out = [replace(p, name=fixed(p.address, p.name)) if p.kind == "function" and thunk.match(p.name) else p
           for p in named]
    proposed = {p.address for p in named}
    out += [signatures.Proposal(f.address, fixed(f.address, f.name), "function", "thunk offset")
            for f in program.functions if f.address not in proposed and thunk.match(f.name)
            and fixed(f.address, f.name) != f.name]
    return out


def _unnamed(program: Program, addresses) -> Program:
    """The program with the functions at `addresses` back to their placeholders."""
    from dataclasses import replace
    return program.derived([replace(f, name=f"fn_{program.platform.text(f.address)[2:]}") if f.address in addresses
                            and not _placeholder(f.name) else f for f in program.functions])


FILE_NAMED = ("file string", "class's file", "another build")    # the `named_by` of a unit its source file names


def _initializer_names(program: Program, proposal: dict[str, Any], initializers: dict[int, bool]) -> list:
    """Each unit's own static initializer named as clang names it: `_GLOBAL__sub_I_` and the file's name, every
    character but letters, digits, `_` and `.` made `_`. Only where the unit has exactly one, and only for a unit
    named by its source file (a file string, its class's cited file, another build's file), whole: a name from a
    class, a placeholder or a piece's address suffix is no file name clang saw."""
    from . import signatures
    found: dict[str, list[int]] = {}
    for unit in proposal["units"]:
        if unit.get("named_by") not in FILE_NAMED or re.search(r"_[0-9A-Fa-f]{8,}\.[^./]+$", unit["unit"]):
            continue
        for index in range(unit.get("first", 0), unit.get("end", 0)):
            address = program.functions[index].address
            if address in initializers and not initializers[address]:
                found.setdefault(unit["unit"], []).append(address)
    out = []
    for unit, addresses in found.items():
        if len(addresses) == 1:
            file = re.sub(r"[^A-Za-z0-9_.]", "_", unit.rsplit("/", 1)[-1])
            out.append(signatures.Proposal(addresses[0], f"_GLOBAL__sub_I_{file}", "function",
                                           "static initializer", unit=unit))
    return out


def _table_size(program: Program, address: int) -> int:
    """The extent of a Switch class table no donor sizes, read from the module: its offset-to-top (zero) and
    typeinfo words (`itanium.typeinfo_word`) and then each slot holding a function or an import."""
    from .itanium import typeinfo_word
    from .signatures import itanium_slots
    image = program.image
    if not hasattr(image, "pointers") or address in image.pointers:
        return 0
    try:
        if image.u64(address) or typeinfo_word(image, address + 8) is None:
            return 0
    except (ValueError, IndexError):
        return 0
    starts = {f.address: f.size for f in program.functions}
    count = 0
    while True:
        slot = itanium_slots(image, address + 8 * count, 1, starts)
        if not slot or slot[0][0] == "other":
            break
        count += 1
    return 16 + 8 * count if count else 0


def _room_for(program: Program, tables: dict[int, int]) -> tuple[set[int], dict[int, int]]:
    """Placeholder data labels a newly sized table covers: those starting inside it (its own slots, a label the
    code's pointer to them made) go; named objects inside are kept. Any object running into its start, named or
    not, ends there: objects never overlap, and a size the base found by the gap to the next start takes in the
    header of a table no object started at."""
    absorbed: set[int] = set()
    resized: dict[int, int] = {}
    for address, size in tables.items():
        for o in program.objects:
            if o.address < address < o.address + o.size:
                resized[o.address] = min(resized.get(o.address, o.size), address - o.address)
            elif _placeholder(o.name) and address < o.address < address + size:
                absorbed.add(o.address)
    return absorbed, resized


def _grown(program: Program, proposals: list, named: set[int]) -> tuple[set[int], dict[int, int]]:
    """(absorbed, resized) for the named objects the base symbols cut short: each grows to the donors' size
    where only placeholder labels (the code's accesses to its members, which the base made labels of) lie inside,
    wholly, none of them named or sized by this analysis (`named`) and no function. A class table grows only as
    far as the module's own slot words reach (`_table_size`): a table can gain slots between builds. On builds
    with real symbols an older build's object size never overran a newer build's object, nor did a table's
    where the words reached it."""
    import bisect
    objects = sorted(program.objects, key=lambda o: o.address)
    starts = [o.address for o in objects]
    at = {o.address: o for o in objects}
    code = sorted(f.address for f in program.functions)
    segment = getattr(program.image, "segment_at", lambda _: None)
    absorbed: set[int] = set()
    resized: dict[int, int] = {}
    for p in proposals:
        o = at.get(p.address)
        if p.kind != "object" or not p.size or o is None or _placeholder(o.name) or o.name != p.name \
                or p.size <= o.size:
            continue
        end = p.address + p.size
        if p.name.startswith("_ZTV") and _table_size(program, p.address) < p.size:
            continue
        if segment(p.address) != segment(end - 1):
            continue
        k = bisect.bisect_right(starts, p.address)
        inside = []
        while k < len(starts) and starts[k] < end:
            inside.append(objects[k])
            k += 1
        f = bisect.bisect_right(code, p.address)
        if f < len(code) and code[f] < end or any(not _placeholder(x.name) or x.address in named
                                                    or x.address + x.size > end for x in inside):
            continue
        resized[p.address] = p.size
        absorbed.update(x.address for x in inside)
    return absorbed, resized


def _misplaced(program: Program, proposals: list) -> dict[int, str]:
    """Placeholder labels for the base objects that share an external name with another (a linked module holds
    one object per external name; a strong one is defined once, the copies of a weak one are folded into one)
    where the donors place that name at exactly one of them: the others had the name put on a wrong address.
    Names of internal linkage (a file's own statics, which each file may have) are left alone."""
    by_name: dict[str, list[int]] = {}
    for o in program.objects:
        if not _placeholder(o.name) and o.scope != "local" and not _internal(o.name):
            by_name.setdefault(o.name, []).append(o.address)
    copies = {name: set(addresses) for name, addresses in by_name.items() if len(addresses) > 1}
    placed: dict[str, set[int]] = {}
    for p in proposals:
        if p.kind == "object" and p.address in copies.get(p.name, ()):
            placed.setdefault(p.name, set()).add(p.address)
    return {address: f"lbl_{program.platform.text(address)[2:]}" for name, at in placed.items() if len(at) == 1
            for address in copies[name] - at}


def _internal(name: str) -> bool:
    """Whether an Itanium data name has internal linkage: `_ZL`, or an `L` before a source name of its nested
    name (`_ZN2gfL7s_tableE`)."""
    if name.startswith("_ZL"):
        return True
    if not name.startswith("_ZN"):
        return False
    i = 3
    while i < len(name):
        if name[i] == "L" and name[i + 1:i + 2].isdigit():
            return True
        length = re.match(r"\d+", name[i:])
        if not length:
            return False
        i += len(length.group()) + int(length.group())
    return False


def _placeholder(name: str | None) -> bool:
    from .score import placeholder
    return not name or placeholder(name)


def write(program: Program, result: dict[str, Any], symbols_in: Path, folder: Path,
          types_include: str = "types.h") -> dict[str, Any]:
    """splits.txt, symbols.txt (the base symbols with the evidence's names and sizes applied, and the data it
    names that they lack), include/classes/, and analysis.json with the evidence."""
    from .gc import SYMBOL_LINE
    folder.mkdir(parents=True, exist_ok=True)
    units.write_splits(result["units"], folder / "splits.txt")
    renamed, weak, local = result["symbols"], result.get("weak", set()), result.get("local", set())
    absorbed, resized = result.get("absorbed", set()), result.get("resized", {})
    lines, seen, starts = [], set(), set()
    for line in symbols_in.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYMBOL_LINE.match(line.strip())
        if not match:
            lines.append(line)
            continue
        address = int(match["address"], 16)
        if address in absorbed:                   # inside a table this analysis sized
            continue
        if address in resized:
            line = f"{match['name']} = {match['section']}:0x{address:08X}; //{_with_size(match['attrs'], resized[address])}"
        starts.add(address)
        if address in renamed and address not in seen:
            name, kind, size = renamed[address]
            seen.add(address)
            attrs = match["attrs"]
            if size:
                attrs = _with_size(attrs, size)
            if address in resized:
                attrs = _with_size(attrs, resized[address])
            if address in weak:                   # the donors' copy is an inline or a template instance
                attrs = re.sub(r"\bscope:\w+", "scope:weak", attrs)
            if address in local:                  # a file's own, like its static initializer
                attrs = re.sub(r"\bscope:\w+", "scope:local", attrs) if "scope:" in attrs else attrs + " scope:local"
            lines.append(f"{name} = {match['section']}:0x{address:08X}; //{attrs}")
        else:
            lines.append(line)
    added = _added_objects(program, renamed, result.get("sizes", {}), starts, weak)
    if added:                                     # in address order among the others
        keyed = [(int(m["address"], 16) if (m := SYMBOL_LINE.match(line.strip())) else -1, line) for line in lines]
        lines = [line for _, line in sorted(keyed + added, key=lambda row: row[0])]
    (folder / "symbols.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    headers = 0
    if result["classes"]:
        include = folder / "include" / "classes"
        include.mkdir(parents=True, exist_ok=True)
        declared, found = result["classes"]["declared"], result["classes"]["found"]
        for address in classes._base_first(found):
            entry = declared[address]
            guard = "".join(c if c.isalnum() else "_" for c in entry.name).upper() + "_H"
            parent = f'#include "{declared[found[address].base].name}.h"\n' if found[address].base in declared else ""
            (include / f"{entry.name}.h").write_text(
                f"#ifndef {guard}\n#define {guard}\n\n#include \"{types_include}\"\n{parent}\n{entry.text}\n\n"
                f"#endif\n", encoding="utf-8")
            headers += 1
    summary = {"units": result["units"]["counts"], "named_symbols": len(renamed), "class_headers": headers,
               "signature_names": len(result["signatures"]),
               "classes": {k: v for k, v in (result["classes"] or {}).get("graph", {}).items() if k != "classes"}}
    (folder / "analysis.json").write_text(json.dumps({
        "summary": summary, "boundaries": result["units"]["boundaries"], "names": result["units"]["names"],
        "signatures": [{"address": f"0x{p.address:08X}", "name": p.name, "kind": p.kind, "evidence": p.evidence,
                        "donors": list(p.donors), "unit": p.unit} for p in result["signatures"]],
        "classes": (result["classes"] or {}).get("graph", {}).get("classes", [])}, indent=1) + "\n",
        encoding="utf-8")
    return {"folder": str(folder), **summary}


def _added_objects(program: Program, renamed: dict[int, tuple[str, str, int]], sizes: dict[int, int],
                   starts: set[int], weak: set[int] = frozenset()) -> list[tuple[int, str]]:
    """(address, line) for each named data object the base symbols lack that the donors size."""
    return [(o.address, f"{o.name} = {o.section}:0x{o.address:08X}; // type:object size:0x{o.size:X} "
                        f"scope:{'weak' if o.address in weak else 'global'}")
            for o in _new_objects(program, renamed, sizes, starts, weak)]


def _with_objects(program: Program, added: list) -> Program:
    """The program with more data objects (its functions, labels and sections as they are)."""
    return program.derived(objects=list(program.objects) + added)


def _new_objects(program: Program, renamed: dict[int, tuple[str, str, int]], sizes: dict[int, int],
                 starts: set[int], weak: set[int] = frozenset()) -> list:
    """Each named data object the base symbols lack that the donors size: that size, cut at the next symbol and
    at the end of its section."""
    import bisect
    import re
    from .program import DataObject
    wanted = sorted(a for a in sizes if a in renamed and a not in starts)
    if not wanted:
        return []
    every = sorted(starts | set(renamed))
    bounds = [(s.address, s.address + s.size) for s in program.platform.sections(program.image)]
    out = []
    for address in wanted:
        name, size = renamed[address][0], sizes[address]
        if not re.fullmatch(r"[^\s=;]+", name):
            continue
        end = next((b for a, b in bounds if a <= address < b), None)
        if end is None:                           # zero-initialized: the program's section names it
            end = address + size
        after = bisect.bisect_right(every, address)
        following = every[after] if after < len(every) else end
        size = min(size, following - address, end - address)
        section = program.section_of(address) or "data"
        segment = getattr(program.image, "segment_at", lambda _: None)(address)
        if segment is not None:                   # a module's segment names the section
            section = segment.name
        section = section if section.startswith(".") else f".{section}"
        out.append(DataObject(address, size, name, section, "weak" if address in weak else "global"))
    return out


def _with_size(attrs: str, size: int) -> str:
    import re
    if re.search(r"\bsize:0x[0-9A-Fa-f]+", attrs):
        return re.sub(r"\bsize:0x[0-9A-Fa-f]+", f"size:0x{size:X}", attrs, count=1)
    return attrs.replace("type:object", f"type:object size:0x{size:X}", 1)


def analyze_project(project, target: str | None, folder: Path) -> dict[str, Any]:
    from .bridge import default_target
    target = default_target(project, target)
    config = project.target(target)
    program = Program.from_project(project, target)
    folder.mkdir(parents=True, exist_ok=True)
    if "discovered" in program.cache:                  # no symbols file: start from what discovery found
        from .discover import write_symbols
        symbols = write_symbols(program.cache["discovered"], folder / "symbols.txt")
    elif config.get("symbols") and project.file(config["repository"], config["symbols"]).is_file():
        symbols = project.file(config["repository"], config["symbols"])
    elif program.platform.name == "switch":            # a module's own tables: its unwind table, stubs, symbols
        from .new import write_symbols
        symbols = write_symbols(program, folder / "symbols.txt")
    else:
        raise ValueError(f"Target {target} has no symbols file to start from (a symbols.txt)")
    return {"target": target, **write(program, analyze(program), symbols, folder)}
