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
    proposals = signatures.propose(program, signatures.donors()) if signatures.listed() else []
    placed = {p.address: p.unit for p in proposals if p.kind == "function" and p.unit}  # the donors' units
    initializers = _initializers(program)
    if initializers:                                # what an initializer array calls is named by its file alone
        program = _unnamed(program, initializers)
    current = {f.address: f.name for f in program.functions} | {o.address: o.name for o in program.objects}
    named = [p for p in proposals if p.kind != "label" and _placeholder(current.get(p.address))
             and p.address not in initializers]
    if program.platform.name != "gamecube":
        named += _slot_names(program, named)
        symbols = {p.address: (p.name, "function" if p.kind == "function" else "object", 0) for p in named}
        sizes = {p.address: p.size for p in named if p.kind == "object" and p.size}
        weak = {p.address for p in named if p.weak}
        with_data = _with_objects(program, _new_objects(program, symbols, sizes, set(current), weak))
        named_program = signatures.renamed(with_data, named)       # the names say which class owns a function
        proposal = units.propose(named_program, fixed, placed)
        own = _initializer_names(program, proposal, initializers)
        named += own
        symbols |= {p.address: (p.name, "function", 0) for p in own}
        return {"units": proposal, "classes": None, "symbols": symbols,
                "sizes": sizes, "signatures": named,     # the data named counts for the units' data
                "weak": weak, "local": {p.address for p in own}}
    proposal = units.propose(program, fixed, placed)
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


def _initializers(program: Program) -> dict[int, bool]:
    """{address: whether it tests a guard} for every function a Switch module's `.init_array` calls. clang names
    a file's own static initializer (no guard) `_GLOBAL__sub_I_<file>` and a template static member's
    (guarded) `__cxx_global_var_init.<n>`, both file-local: no other build exports either, and an initializer
    takes no arguments, so a donor's name on one (a constructor's, by its shape) is never its own."""
    if program.platform.name != "switch":
        return {}
    from .aarch64 import guarded
    out = {}
    for address in getattr(program.image, "init_array", ()):
        index = program.function_index.get(address)
        if index is not None:
            size = program.functions[index].size
            out[address] = guarded(program.platform.words(program.image, address, min(size, 64)))
    return out


def _unnamed(program: Program, addresses) -> Program:
    """The program with the functions at `addresses` back to their placeholders."""
    from dataclasses import replace
    out = Program(program.platform, program.image,
                  [replace(f, name=f"fn_{program.platform.text(f.address)[2:]}") if f.address in addresses
                   and not _placeholder(f.name) else f for f in program.functions], program.objects, program.sda)
    out.labels, out.sections = program.labels, program.sections
    return out


def _initializer_names(program: Program, proposal: dict[str, Any], initializers: dict[int, bool]) -> list:
    """Each unit's own static initializer named as clang names it: `_GLOBAL__sub_I_` and the file's name, every
    character but letters, digits, `_` and `.` made `_`. Only where the unit has exactly one."""
    from . import signatures
    found: dict[str, list[int]] = {}
    for unit in proposal["units"]:
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
    lines, seen, starts = [], set(), set()
    for line in symbols_in.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYMBOL_LINE.match(line.strip())
        if not match:
            lines.append(line)
            continue
        address = int(match["address"], 16)
        starts.add(address)
        if address in renamed and address not in seen:
            name, kind, size = renamed[address]
            seen.add(address)
            attrs = match["attrs"]
            if size:
                attrs = _with_size(attrs, size)
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
    out = Program(program.platform, program.image, program.functions, list(program.objects) + added, program.sda)
    out.labels, out.sections = program.labels, program.sections
    return out


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
