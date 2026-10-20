"""A fresh analysis of an original, written as a project configuration: a splits.txt with every
unit's code and data, a symbols.txt, and a header per recovered class, plus the evidence behind each.

Names are only what evidence proves. Functions and data other builds name (the signature cache: libraries every
game links, another build of this one) take those names where the evidence admits one, and data they name that
the symbols lack is added with the donors' size, up to the next symbol. A function a donor with units names is
evidence for the units too: it is in the unit that build put it in. A class table is `__vt__` of its class
and a CodeWarrior destructor is `__dt__<class>Fv` (destructors never declare parameters), so both are named; a
constructor or a virtual method keeps its `fn_` placeholder until its parameters are known, because a mangled
name claims a signature. Classes are recovered from CodeWarrior's tables only; a Switch module's names come from
the signatures alone.
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
    current = {f.address: f.name for f in program.functions} | {o.address: o.name for o in program.objects}
    named = [p for p in proposals if p.kind != "label" and _placeholder(current.get(p.address))]
    if program.platform.name != "gamecube":
        symbols = {p.address: (p.name, "function" if p.kind == "function" else "object", 0) for p in named}
        sizes = {p.address: p.size for p in named if p.kind == "object" and p.size}
        weak = {p.address for p in named if p.weak}
        with_data = _with_objects(program, _new_objects(program, symbols, sizes, set(current), weak))
        named_program = signatures.renamed(with_data, named)       # the names say which class owns a function
        return {"units": units.propose(named_program, fixed, placed), "classes": None, "symbols": symbols,
                "sizes": sizes, "signatures": named,     # the data named counts for the units' data
                "weak": weak}
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
    renamed, weak = result["symbols"], result.get("weak", set())
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
