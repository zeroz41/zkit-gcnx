"""CodeWarrior linker maps (the `.MAP` some GameCube and Wii builds ship): every object's part of every section,
and every symbol in it, with its size. Where a game has one, it is the truth about units and names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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


TREE = re.compile(r"^\s*\d+\]\s+(?P<name>\S.*?)\s+\((?P<kind>\w+),(?P<scope>\w+)\)\s+found in\s+(?P<where>.*?)\s*$")


@dataclass
class Symbol:
    name: str
    address: int
    size: int
    align: int
    kind: str = ""               # func, object or notype, from the reference tree ("" when it is not there)
    scope: str = ""              # global, local or weak, likewise


@dataclass
class Piece:
    """One object's part of one section, in link order: where it starts, the bytes the linker kept (the section
    line's size counts code dead-stripping dropped, so the extent ends at the next piece or its last symbol),
    and its symbols."""
    unit: str
    section: str
    address: int
    size: int
    symbols: list[Symbol] = field(default_factory=list)


@dataclass
class Layout:
    pieces: dict[str, list[Piece]] = field(default_factory=dict)    # section -> pieces in address order

    def units(self) -> list[str]:
        """Every object in link order (the order of its first code, else of its first piece anywhere)."""
        order: dict[str, int] = {}
        for section in sorted(self.pieces, key=lambda s: (s not in CODE_SECTIONS, s)):
            for piece in self.pieces[section]:
                order.setdefault(piece.unit, len(order))
        return sorted(order, key=order.get)


def layout(path: Path) -> Layout:
    """Every section's pieces with their symbols, and each symbol's kind and scope from the reference tree (where
    it is listed: the tree shows only what the link reached from the entry point and the forced-active symbols)."""
    out = Layout()
    tree: dict[tuple[str, str], tuple[str, str]] = {}
    section = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        header = LAYOUT.match(line)
        if header:
            section = header["section"]
            continue
        if section is None:
            found = TREE.match(line)
            if found and not found["name"].startswith(">>>"):
                tree.setdefault((found["name"], unit_name(found["where"])), (found["kind"], found["scope"]))
            continue
        if section.startswith(".debug") or section == ".line":
            continue
        match = ENTRY.match(line)
        if not match or match["offset"] == "UNUSED" or match["address"].startswith(".") or "(entry of" in match["name"]:
            continue
        address, size, name = int(match["address"], 16), int(match["size"], 16), match["name"]
        unit = unit_name(match["where"])
        rows = out.pieces.setdefault(section, [])
        if name == section and match["align"] == "1":
            rows.append(Piece(unit, section, address, size))
            continue
        if not rows or rows[-1].unit != unit:
            rows.append(Piece(unit, section, address, 0))         # a piece whose section line the map leaves out
        kind, scope = tree.get((name, unit), ("", ""))
        rows[-1].symbols.append(Symbol(name, address, size, int(match["align"] or 1), kind, scope))
    for rows in out.pieces.values():
        rows.sort(key=lambda p: p.address)
        for piece, after in zip(rows, rows[1:] + [None]):
            end = piece.address + piece.size
            if after is not None and after.address >= piece.address:
                end = min(end, after.address)
            if piece.symbols:
                end = max(end, max(s.address + s.size for s in piece.symbols))
            piece.size = end - piece.address
    return out


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
