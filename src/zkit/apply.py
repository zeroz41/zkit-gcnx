"""Names from the build back into the symbols: after a rename in the source, the compiled object carries the new
name while the target object (cut from the original with the symbols file's names) keeps the old one, and objdiff,
which pairs symbols by name, stops pairing them.

For each unit with both objects, the functions and data objects of each section are lined up by place: when both
sides hold the same number of symbols at the same offsets with the same sizes, the layouts are the same and each
target symbol's compiled counterpart is the one at its offset. A different name there is a rename, applied at the
symbol's original address (from the target's `.note.split`). Sections whose layouts differ are reported, never
guessed.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from .elf import Elf
from .project import Project


def _virtual(elf: Elf) -> list[int]:
    """Original addresses by symbol index, from objdiff's `.note.split` (empty when the object has none)."""
    note = elf.section(".note.split")
    if note is None:
        return []
    data, position = elf.data(note), 0
    while position + 12 <= len(data):
        namesz, descsz, kind = struct.unpack_from(elf.endian + "III", data, position)
        position += 12 + namesz + (-namesz % 4)
        desc = data[position:position + descsz]
        position += descsz + (-descsz % 4)
        if kind == int.from_bytes(b"VIRT", "big"):
            width = elf.bits // 8
            return [int.from_bytes(desc[i:i + width], "big" if elf.endian == ">" else "little")
                    for i in range(0, len(desc), width)]
    return []


def _placed(elf: Elf) -> dict[str, list[tuple[int, int, str, int]]]:
    """{section: [(offset, size, name, symbol index)]} of named functions and data objects."""
    out: dict[str, list] = {}
    for index, symbol in enumerate(elf.symbols):
        if symbol.kind not in ("func", "object") or not symbol.name or not 0 < symbol.section < len(elf.sections):
            continue
        if symbol.name.startswith(("@", ".L")):
            continue
        out.setdefault(elf.sections[symbol.section].name, []).append((symbol.value, symbol.size, symbol.name, index))
    return {name: sorted(rows) for name, rows in out.items()}


def unit_renames(target_path: Path, base_path: Path) -> tuple[list[dict], list[str]]:
    """Renames for one unit, and the sections whose layouts differ."""
    target, base = Elf.load(target_path), Elf.load(base_path)
    virtual = _virtual(target)
    ours, theirs = _placed(target), _placed(base)
    renames, unsure = [], []
    for section, rows in ours.items():
        other = theirs.get(section, [])
        if [(o, s) for o, s, _, _ in rows] != [(o, s) for o, s, _, _ in other]:
            if other:
                unsure.append(section)
            continue
        for (offset, size, old, index), (_, _, new, _) in zip(rows, other):
            if old != new and index < len(virtual) and virtual[index]:
                renames.append({"address": virtual[index], "old": old, "new": new, "section": section})
    return renames, unsure


def renames(project: Project, target: str) -> dict[str, Any]:
    from .objects import objdiff_units
    root = project.root(project.target(target)["repository"])
    found, unsure, units = [], [], 0
    for name, unit in sorted(objdiff_units(project, target).items()):
        target_path, base_path = unit.get("target_path"), unit.get("base_path")
        if not target_path or not base_path or not (root / target_path).is_file() or not (root / base_path).is_file():
            continue
        units += 1
        rows, sections = unit_renames(root / target_path, root / base_path)
        found += [{**row, "unit": name} for row in rows]
        unsure += [f"{name} {section}" for section in sections]
    return {"target": target, "units": units, "renames": found, "layouts_differ": unsure}


LINE = re.compile(r"^(?P<name>\S+)(?P<rest>\s*=\s*[.\w]+:0x(?P<address>[0-9A-Fa-f]+);.*)$")


def write(project: Project, target: str, rows: list[dict]) -> int:
    """Rename the symbols file's entries at the renamed addresses; returns how many lines changed."""
    config = project.target(target)
    path = project.file(config["repository"], config["symbols"])
    by_address = {row["address"]: row for row in rows}
    lines, changed = [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LINE.match(line)
        row = by_address.get(int(match["address"], 16)) if match else None
        if row is not None and match["name"] == row["old"]:
            line = row["new"] + match["rest"]
            changed += 1
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed
