"""A fresh analysis of an original, written the way decomp-toolkit's configuration is: a splits.txt with every
unit's code and data, a symbols.txt, and a header per recovered class, plus the evidence behind each.

Names are only what evidence proves. Functions and data other builds name (the signature cache: libraries every
game links, another build of this one) take those names where the evidence admits one. A class table is `__vt__`
of its class and a CodeWarrior destructor is `__dt__<class>Fv` (destructors never declare parameters), so both
are named; a constructor or a virtual method keeps its `fn_` placeholder until its parameters are known, because
a mangled name claims a signature.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import classes, cwnames, units, vtables
from .program import Program


def analyze(program: Program) -> dict[str, Any]:
    proposal = units.propose(program)
    result: dict[str, Any] = {"units": proposal, "classes": None, "symbols": {}, "signatures": []}
    if program.platform.name != "gamecube":
        return result
    from . import signatures
    current = {f.address: f.name for f in program.functions} | {o.address: o.name for o in program.objects}
    named = [p for p in (signatures.propose(program, signatures.donors()) if signatures.listed() else [])
             if p.kind != "label" and _placeholder(current.get(p.address))]
    program = signatures.renamed(program, named)
    result["signatures"] = named
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
    """splits.txt, symbols.txt (the base symbols with the evidence's names and sizes applied), include/classes/,
    and analysis.json with the evidence."""
    from .gc import SYMBOL_LINE
    folder.mkdir(parents=True, exist_ok=True)
    units.write_splits(result["units"], folder / "splits.txt")
    renamed = result["symbols"]
    lines, seen = [], set()
    for line in symbols_in.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYMBOL_LINE.match(line.strip())
        if not match:
            lines.append(line)
            continue
        address = int(match["address"], 16)
        if address in renamed and address not in seen:
            name, kind, size = renamed[address]
            seen.add(address)
            attrs = match["attrs"]
            if size:
                attrs = _with_size(attrs, size)
            lines.append(f"{name} = {match['section']}:0x{address:08X}; //{attrs}")
        else:
            lines.append(line)
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


def _with_size(attrs: str, size: int) -> str:
    import re
    if re.search(r"\bsize:0x[0-9A-Fa-f]+", attrs):
        return re.sub(r"\bsize:0x[0-9A-Fa-f]+", f"size:0x{size:X}", attrs, count=1)
    return attrs.replace("type:object", f"type:object size:0x{size:X}", 1)


def analyze_project(project, target: str | None, folder: Path) -> dict[str, Any]:
    from .bridge import default_target
    target = default_target(project, target)
    config = project.target(target)
    if not config.get("symbols"):
        raise ValueError(f"Target {target} has no symbols file to start from (a decomp-toolkit symbols.txt)")
    program = Program.from_project(project, target)
    return {"target": target, **write(program, analyze(program), project.file(config["repository"],
                                                                                config["symbols"]), folder)}
