"""Compiled objects against the original, and against themselves before a change.

Two questions every decomp asks, answered from the ELF objects the build already wrote:
- function: does the compiled function equal the original one (bytes and relocations), and where does it differ?
- identity: after a source change that must not change code (a cleanup, a rename, a header move), is every object
  identical to a saved copy, apart from the renames that change intended?
objdiff remains the authority for match percentages; these are fast exact checks with the differing lines shown.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .elf import Elf, Relocation, Section
from .project import Project

# Sections that never carry the program: compiler notes, debug info, line tables, address-significance tables.
SKIP_SECTIONS = re.compile(r"^(\.comment|\.mwcats.*|\.debug.*|\.line|\.note.*|\.llvm_addrsig|\.llvm\.call-graph-profile|"
                           r"\.ARM\.attributes|\.eh_frame|\.rela?\..*|\.symtab|\.strtab|\.shstrtab|\.group)$")


def _anonymous(name: str, bind: str) -> bool:
    """Compiler-numbered locals whose number is not stable across edits: MWCC @123, clang .L and .str.N."""
    return bind == "local" and (name.startswith("@") or name.startswith((".L", "$x", "$d", ".str", "__func__.")))


def objdiff_units(project: Project, target: str) -> dict[str, dict]:
    """{unit name: objdiff.json unit} for a target's repository."""
    config = project.target(target)
    path = project.file(config["repository"], config.get("objdiff", "objdiff.json"))
    if not path.is_file():
        raise ValueError(f"No {path.name} in {config['repository']}: build the project once (it writes objdiff's "
                         "project file)")
    data = json.loads(path.read_text(encoding="utf-8"))
    return {u["name"]: u for u in data.get("units", []) if u.get("name")}


def _symbol_name(elf: Elf, index: int) -> str:
    symbol = elf.symbols[index] if index < len(elf.symbols) else None
    if symbol is None:
        return "?"
    if symbol.kind == "section" or not symbol.name:
        return f"<{elf.sections[symbol.section].name if symbol.section < len(elf.sections) else '?'}>"
    if _anonymous(symbol.name, symbol.bind):
        where = elf.sections[symbol.section].name if 0 < symbol.section < len(elf.sections) else "?"
        return f"<{where}+0x{symbol.value:X}>"
    return symbol.name


def _relocs(elf: Elf, section: Section, start: int, end: int, rename: dict[str, str],
            width: int = 4) -> dict[int, tuple]:
    """Relocations inside [start, end), keyed by the instruction word they patch (PowerPC relocates half-words
    inside an instruction), as (types, targets, addends) tuples."""
    grouped: dict[int, list[tuple]] = {}
    for reloc in elf.relocations(section):
        if start <= reloc.offset < end:
            name = _symbol_name(elf, reloc.symbol)
            word = (reloc.offset - start) // width * width
            grouped.setdefault(word, []).append((reloc.type, rename.get(name, name), reloc.addend))
    return {word: (tuple(r[0] for r in rows), tuple(r[1] for r in rows), tuple(r[2] for r in rows))
            for word, rows in grouped.items()}


def _find(elf: Elf, name: str):
    functions = elf.functions()
    if name in functions:
        return functions[name]
    return None


def _reloc_text(reloc: tuple | None) -> str | None:
    if not reloc:
        return None
    return ", ".join(f"{name}{addend:+#x}" if addend else name for name, addend in zip(reloc[1], reloc[2]))


def function_diff(target_path: Path, base_path: Path, name: str, base_name: str | None = None,
                  rename: dict[str, str] | None = None, limit: int = 24) -> dict[str, Any]:
    """Compare one function in the original's object with the compiled one."""
    rename = rename or {}
    original, built = Elf.load(target_path), Elf.load(base_path)
    a, b = _find(original, name), _find(built, base_name or name)
    out: dict[str, Any] = {"function": name, "target": str(target_path), "base": str(base_path),
                           "machine": original.machine}
    if a is None:
        raise ValueError(f"{name} is not a function in {target_path}")
    if b is None:
        out.update(exact=False, missing=True, size=a.size,
                   message=f"the compiled object defines no function {base_name or name}; check the name/mangling "
                           f"(it defines {len(built.functions())} functions)")
        return out
    sa, sb = original.sections[a.section], built.sections[b.section]
    da = original.data(sa)[a.value:a.value + a.size]
    db = built.data(sb)[b.value:b.value + b.size]
    ra = _relocs(original, sa, a.value, a.value + a.size, {})
    rb = _relocs(built, sb, b.value, b.value + b.size, {v: k for k, v in rename.items()})
    width = 4
    rows = []
    for offset in range(0, max(len(da), len(db)), width):
        wa, wb = da[offset:offset + width], db[offset:offset + width]
        xa, xb = ra.get(offset), rb.get(offset)
        if wa != wb or (xa and xb and xa[0] != xb[0]) or bool(xa) != bool(xb):
            rows.append({"offset": offset, "original": wa.hex(), "compiled": wb.hex(),
                         "original_reloc": _reloc_text(xa), "compiled_reloc": _reloc_text(xb)})
        elif xa and xb and (xa[1] != xb[1] or xa[2] != xb[2]):
            rows.append({"offset": offset, "original": wa.hex(), "compiled": wb.hex(),
                         "original_reloc": _reloc_text(xa), "compiled_reloc": _reloc_text(xb), "reloc_only": True})
    reloc_only = rows and all(r.get("reloc_only") for r in rows)
    out.update(exact=not rows and len(da) == len(db), size=len(da), compiled_size=len(db), differences=len(rows),
               reloc_only=bool(reloc_only), rows=rows[:limit])
    if rows:
        out["first_difference"] = rows[0]["offset"]
    return out


def unit_diff(target_path: Path, base_path: Path, rename: dict[str, str] | None = None) -> dict[str, Any]:
    """Every function of a unit: exact, differing (with the count of differing words), or missing."""
    original, built = Elf.load(target_path), Elf.load(base_path)
    names = sorted(original.functions(), key=lambda n: original.functions()[n].value)
    rows = []
    for name in names:
        try:
            result = function_diff(target_path, base_path, name, rename=rename, limit=0)
        except ValueError as error:
            rows.append({"function": name, "error": str(error)})
            continue
        rows.append({"function": name, "exact": result["exact"], "size": result["size"],
                     "differences": result.get("differences"), "missing": result.get("missing", False),
                     "reloc_only": result.get("reloc_only", False)})
    extra = sorted(set(built.functions()) - set(original.functions()))
    return {"target": str(target_path), "base": str(base_path), "functions": rows,
            "exact": sum(1 for r in rows if r.get("exact")), "total": len(rows), "compiled_only": extra}


# Identity: the same compiled program before and after a change that must not change code.

def _sections(elf: Elf) -> dict[str, bytes | int]:
    out: dict[str, bytes | int] = {}
    for section in elf.sections:
        if not section.name or SKIP_SECTIONS.match(section.name) or section.type in (0, 2, 3):
            continue
        out[section.name] = section.size if section.type == 8 else elf.data(section)
    return out


def _defined(elf: Elf, rename: dict[str, str]) -> dict[str, list[tuple]]:
    out: dict[str, list[tuple]] = {}
    for symbol in elf.symbols:
        if not symbol.name or symbol.kind in ("section", "file") or _anonymous(symbol.name, symbol.bind):
            continue
        if not 0 < symbol.section < 0xFF00:
            continue  # undefined: matters only through relocations
        where = elf.sections[symbol.section].name if symbol.section < len(elf.sections) else str(symbol.section)
        out.setdefault(rename.get(symbol.name, symbol.name), []).append((where, symbol.value, symbol.size, symbol.bind))
    return out


def _all_relocs(elf: Elf, rename: dict[str, str]) -> dict[str, list[tuple]]:
    out = {}
    for section in elf.sections:
        if not section.name or SKIP_SECTIONS.match(section.name) or section.type in (0, 2, 3, 4, 9):
            continue
        rows = []
        for reloc in elf.relocations(section):
            name = _symbol_name(elf, reloc.symbol)
            rows.append((reloc.offset, reloc.type, rename.get(name, name), reloc.addend))
        if rows:
            out[section.name] = rows
    return out


def identical(before: Path, after: Path, rename: dict[str, str] | None = None) -> list[str]:
    """Differences between two objects (empty: identical code and data), with `rename` (old -> new) applied."""
    rename = rename or {}
    a, b = Elf.load(before), Elf.load(after)
    problems = []
    sa, sb = _sections(a), _sections(b)
    for name in sorted(set(sa) | set(sb)):
        if sa.get(name) != sb.get(name):
            problems.append(f"section {name} differs" if name in sa and name in sb else
                            f"section {name} only {'before' if name in sa else 'after'}")
    ya, yb = _defined(a, rename), _defined(b, {})
    for name in sorted(set(ya) | set(yb)):
        if ya.get(name) != yb.get(name):
            problems.append(f"symbol {name}: {ya.get(name)} -> {yb.get(name)}")
    ra, rb = _all_relocs(a, rename), _all_relocs(b, {})
    for name in sorted(set(ra) | set(rb)):
        if ra.get(name) != rb.get(name):
            problems.append(f"relocations of {name} differ")
    return problems


def _store(project: Project, target: str) -> Path:
    from .activity import state_dir
    return state_dir(project) / "objects" / target


def save(project: Project, target: str, label: str = "saved") -> dict[str, Any]:
    """Copy every built object of the target (objdiff base_path) aside, to compare after a change."""
    units = objdiff_units(project, target)
    repo = project.target(target)["repository"]
    root = project.root(repo)
    folder = _store(project, target) / re.sub(r"[^\w.-]", "_", label)
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    copied = missing = 0
    started = time.monotonic()
    paths = [u["base_path"] for u in units.values() if u.get("base_path")]
    for relative in paths:
        source = root / relative
        if not source.is_file():
            missing += 1
            continue
        destination = folder / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1
    meta = {"label": label, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "objects": copied,
            "missing": missing, "seconds": round(time.monotonic() - started, 1)}
    (folder / "meta.json").write_text(json.dumps(meta) + "\n", encoding="utf-8")
    return meta


def compare_saved(project: Project, target: str, label: str = "saved", rename: dict[str, str] | None = None,
                  limit: int = 40) -> dict[str, Any]:
    """Every built object against its saved copy: identical, changed (with what changed), new or gone."""
    folder = _store(project, target) / re.sub(r"[^\w.-]", "_", label)
    if not (folder / "meta.json").is_file():
        raise ValueError(f"No saved objects named {label}: `zkit objects --save` first")
    meta = json.loads((folder / "meta.json").read_text(encoding="utf-8"))
    units = objdiff_units(project, target)
    root = project.root(project.target(target)["repository"])
    changed, identical_count, new, gone, stale = [], 0, [], [], []
    saved_at = datetime.fromisoformat(meta["time"]).timestamp()
    for name, unit in sorted(units.items()):
        relative = unit.get("base_path")
        if not relative:
            continue
        current, before = root / relative, folder / relative
        if not current.is_file():
            if before.is_file():
                gone.append(relative)
            continue
        if not before.is_file():
            new.append(relative)
            continue
        if current.stat().st_mtime < saved_at - 1 and current.read_bytes() == before.read_bytes():
            stale.append(relative)  # not rebuilt since the copy: it proves nothing about the change
        problems = identical(before, current, rename)
        if problems:
            changed.append({"object": relative, "unit": name, "problems": problems[:6], "count": len(problems)})
        else:
            identical_count += 1
    return {"label": label, "saved": meta, "identical": identical_count, "changed": changed[:limit],
            "changed_count": len(changed), "new": new[:limit], "gone": gone[:limit], "not_rebuilt": len(stale),
            "ok": not changed and not gone,
            "limits": "Allocated sections, defined symbols and relocations with compiler-numbered locals compared by "
                      "place; debug and comment sections ignored. Objects not rebuilt since the copy are counted: "
                      "run the build before comparing."}


def disassembly(project: Project, target: str, path: Path, function: str, machine: str) -> list[str]:
    """The project's disassembler on one function of an object, when one is available."""
    tool = None
    if machine == "aarch64":
        tool = shutil.which("llvm-objdump")
        args = [tool, "-d", "-r", "--no-show-raw-insn", f"--disassemble-symbols={function}", str(path)] if tool else None
    else:
        from .inspect_dol import _objdump
        tool = _objdump(project)
        args = [tool, "-d", "-r", f"--disassemble={function}", "-M", "gekko", str(path)] if tool else None
    if not args:
        return []
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    lines = result.stdout.splitlines()
    start = next((i for i, l in enumerate(lines) if re.search(r"<.*>:$", l)), None)
    return [l.rstrip() for l in lines[start + 1:]] if start is not None else []
