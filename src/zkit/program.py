"""The original executable as a program: its functions, data objects and the references between them.

Built from the image and a base symbol list (a decomp's symbols.txt, or the symbols a fresh analysis wrote), so
the analyses above it (units, classes, names) need no project and run the same on a new game and on a decomp in
progress. Everything here is decoded from the image; nothing is guessed from names.
"""

from __future__ import annotations

import bisect
import collections
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .platform import Platform

CODE_SECTIONS = (".init", ".text")


@dataclass(frozen=True)
class Function:
    address: int
    size: int
    name: str


@dataclass(frozen=True)
class DataObject:
    address: int
    size: int
    name: str
    section: str


class Program:
    def __init__(self, platform: Platform, image, functions: Iterable[Function], objects: Iterable[DataObject],
                 sda: dict[int, int] | None = None):
        self.platform, self.image = platform, image
        self.functions = sorted(functions, key=lambda f: f.address)
        self.objects = sorted(objects, key=lambda o: o.address)
        self.function_index = {f.address: i for i, f in enumerate(self.functions)}
        self._function_starts = [f.address for f in self.functions]
        self._object_starts = [o.address for o in self.objects]
        self.sda = sda or {}
        self._refs: dict[int, list[tuple[int, int, str]]] | None = None
        self._calls: dict[int, list[int]] | None = None
        self._pointers: list[tuple[int, int]] | None = None
        self.cache: dict = {}  # results analyses share (register flows, tables), keyed by the analysis

    @classmethod
    def from_symbols(cls, platform: Platform, image_path: Path, symbols_path: Path) -> "Program":
        """An image and a decomp-toolkit symbols.txt (functions in code sections, sized objects elsewhere)."""
        return cls._build(platform, platform.open(image_path), symbols_path)

    @classmethod
    def from_project(cls, project, target: str) -> "Program":
        """A project target's original and its symbols file."""
        from .inspect_dol import _dol
        from .platform import for_target
        config = project.target(target)
        if not config.get("symbols"):
            raise ValueError(f"Target {target} has no `symbols` file in the project")
        return cls._build(for_target(config), _dol(project, target),
                          project.file(config["repository"], config["symbols"]))

    @classmethod
    def _build(cls, platform: Platform, image, symbols_path: Path) -> "Program":
        from .gc import read_symbols
        symbols = read_symbols(symbols_path)
        functions = [Function(s.address, s.size, s.name) for s in symbols
                     if s.type == "function" and s.section in CODE_SECTIONS and s.size]
        objects = [DataObject(s.address, s.size, s.name, s.section) for s in symbols
                   if s.type == "object" and s.section not in CODE_SECTIONS]
        sda = {}
        start = next((s.address for s in symbols if s.name == "__init_registers"), None)
        if start is not None and platform.name == "gamecube":
            sda = _gamecube_sda(image, start)
        return cls(platform, image, functions, objects, sda)

    # lookups

    def object_at(self, address: int) -> DataObject | None:
        index = bisect.bisect_right(self._object_starts, address) - 1
        if index >= 0:
            found = self.objects[index]
            if found.address <= address < found.address + max(found.size, 1):
                return found
        return None

    def function_at(self, address: int) -> int | None:
        """Index of the function containing an address."""
        index = bisect.bisect_right(self._function_starts, address) - 1
        if index >= 0 and address < self.functions[index].address + self.functions[index].size:
            return index
        return None

    def read(self, address: int, size: int) -> bytes:
        return self.platform.read(self.image, address, size)

    # references, decoded once

    @property
    def refs(self) -> dict[int, list[tuple[int, int, str]]]:
        """{function index: [(pc, address, kind)]} for addresses straight-line code forms."""
        if self._refs is None:
            context = {"sda": self.sda}
            self._refs = {i: self.platform.addresses(self.image, f.address, f.size, context)
                          for i, f in enumerate(self.functions)}
        return self._refs

    @property
    def calls(self) -> dict[int, list[int]]:
        """{caller index: [callee index]} for direct calls between known functions."""
        if self._calls is None:
            self._calls = collections.defaultdict(list)
            for i, f in enumerate(self.functions):
                for _, target in self.platform.calls(self.image, f.address, f.size):
                    j = self.function_index.get(target)
                    if j is not None:
                        self._calls[i].append(j)
        return self._calls

    @property
    def pointers(self) -> list[tuple[int, int]]:
        """(holder, pointee) for pointer-sized data words that point into the image."""
        if self._pointers is None:
            self._pointers = list(self.platform.data_pointers(self.image))
        return self._pointers

    def users(self) -> dict[DataObject, set[int]]:
        """Each data object and the functions whose code forms an address inside it."""
        out: dict[DataObject, set[int]] = collections.defaultdict(set)
        for i, rows in self.refs.items():
            for _, address, _ in rows:
                found = self.object_at(address)
                if found is not None:
                    out[found].add(i)
        return out


def _gamecube_sda(image, start: int) -> dict[int, int]:
    """r2 and r13 as __init_registers sets them."""
    registers: dict[int, int] = {}
    for word in image.words(start, 0x40):
        op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 15 and ra == 0:
            registers[rd] = (imm << 16) & 0xFFFFFFFF
        elif op == 24 and rd in registers:
            registers[ra] = registers.get(rd, 0) | imm
        elif op == 14 and ra in registers:
            registers[rd] = (registers[ra] + (imm - 0x10000 if imm & 0x8000 else imm)) & 0xFFFFFFFF
        elif word == 0x4E800020:
            break
    return {r: registers[r] for r in (2, 13) if r in registers}
