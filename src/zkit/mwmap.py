"""CodeWarrior linker maps (the `.MAP` some GameCube and Wii builds ship): every object's part of every section,
and every symbol in it, with its size. Where a game has one, it is the truth about units and names.
"""

from __future__ import annotations

import re
from pathlib import Path

from .score import CODE_SECTIONS, Split

LAYOUT = re.compile(r"^(?P<section>\S+) section layout\s*$")
ENTRY = re.compile(r"^\s+(?P<offset>[0-9a-fA-F]{8}|UNUSED)\s+(?P<size>[0-9a-fA-F]{6,8})\s+(?P<address>[0-9a-fA-F]{8}|\.{8})"
                   r"(?:\s+[0-9a-fA-F]{8})?\s+(?P<align>\d+)?\s*(?P<name>\S.*?)\s*\t(?P<where>.*?)\s*$")


def unit_name(where: str) -> str:
    """`Lib.a file.cpp` -> `Lib/file.cpp`; `file.o` -> `file.cpp`-like as written."""
    parts = where.split()
    if len(parts) >= 2 and parts[0].endswith(".a"):
        return f"{parts[0][:-2]}/{' '.join(parts[1:])}"
    return " ".join(parts)


def read(path: Path) -> Split:
    split = Split()
    section = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        header = LAYOUT.match(line)
        if header:
            section = header["section"]
            continue
        if section is None or section.startswith(".debug") or section in (".line",):
            continue
        match = ENTRY.match(line)
        if not match or match["offset"] == "UNUSED" or match["address"].startswith("."):
            continue
        address, size, name = int(match["address"], 16), int(match["size"], 16), match["name"]
        unit = unit_name(match["where"])
        if name == section and match["align"] == "1":
            if size:
                split.units[unit].append((section, address, address + size))
            continue
        if section in CODE_SECTIONS:
            split.functions.setdefault(address, (size, name))
        elif size:
            split.objects.setdefault(address, (size, name, section))
    return split
