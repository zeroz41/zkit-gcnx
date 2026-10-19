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
    scope: str = "global"


@dataclass(frozen=True)
class DataObject:
    address: int
    size: int
    name: str
    section: str
    scope: str = "global"
    data: str = ""  # what the bytes are when known (string, float, 4byte, ...)


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
        self.labels: list[DataObject] = []  # names at addresses with no extent (`type:label`)
        self.sections: list[tuple[str, int, int]] = []  # (name, start, end) of every named section

    def in_image(self, address: int) -> bool:
        """Inside a section of the image (loaded or zero-initialized)."""
        return self.section_of(address) is not None

    def in_code(self, address: int) -> bool:
        return any(s.kind == "text" and s.address <= address < s.address + s.size
                   for s in self.platform.sections(self.image))

    def section_of(self, address: int) -> str | None:
        """The name of the section holding an address ("text"/"data" when the symbols name none)."""
        if self.sections:
            if "section_starts" not in self.cache:
                self.cache["section_starts"] = [s[1] for s in self.sections]
            index = bisect.bisect_right(self.cache["section_starts"], address) - 1
            return self.sections[index][0] if index >= 0 and address < self.sections[index][2] else None
        return next((s.kind for s in self.platform.sections(self.image) if s.address <= address < s.address + s.size),
                    None)

    @classmethod
    def from_symbols(cls, platform: Platform, image_path: Path, symbols_path: Path) -> "Program":
        """An image and a symbols.txt (functions in code sections, sized objects elsewhere)."""
        return cls._build(platform, platform.open(image_path), symbols_path)

    @classmethod
    def from_image(cls, platform: Platform, image) -> "Program":
        """A GameCube executable alone: functions, data objects, sections and small-data bases discovered from its
        bytes (discover.py), named `fn_`/`lbl_` by address."""
        from .discover import discover
        return cls.from_found(platform, image, discover(image))

    @classmethod
    def from_found(cls, platform: Platform, image, found) -> "Program":
        functions = [Function(a, s, f"fn_{a:08X}") for a, s in found.functions.items()]
        objects = [DataObject(a, s, n, section) for a, s, section, n in found.objects]
        program = cls(platform, image, functions, objects, found.sda)
        program.labels = [DataObject(a, 0, f"lbl_{a:08X}", found.section_of(a) or "") for a in found.labels]
        program.labels += [DataObject(a, 0, f"_{n.lstrip('.')}", n) for n, a, _ in found.sections
                           if n in (".ctors", ".dtors")]   # the linker's names for where the tables begin
        program.sections = list(found.sections)
        program.cache["discovered"] = found
        return program

    @classmethod
    def from_project(cls, project, target: str) -> "Program":
        """A project target's original, its symbols file when it has one (functions and data objects), else what
        the original alone gives (a GameCube target's discovery; a Switch module's unwind table, exports, import
        stubs and the data its code and pointers refer to, `nxdata`), else the functions zkit's index knows for it
        (a report or a function list). A Switch module's own data symbols fill in when the symbols file names no
        data."""
        from .gc import Symbol, read_symbols
        from .inspect_dol import _dol
        from .platform import for_target
        config = project.target(target)
        platform, image = for_target(config), _dol(project, target)
        if config.get("symbols") and project.file(config["repository"], config["symbols"]).is_file():
            symbols = read_symbols(project.file(config["repository"], config["symbols"]))
        elif platform.name == "gamecube":
            return cls.from_image(platform, image)
        elif platform.name == "switch":    # the module's own tables, never names the index kept from a decomp
            from .nxdata import linker_tables, objects
            stubs = image.stubs()
            functions = image.functions()
            symbols = [Symbol(image.symbols.get(a) or stubs.get(a) or f"fn_{platform.text(a)[2:]}", ".text", a,
                              "function", s, "global") for a, s in functions]
            own = _module_objects(project, target)
            symbols += own + [Symbol(f"lbl_{platform.text(a)[2:]}", section, a, "object", size, "global")
                              for a, size, section in objects(image, functions, [(s.address, s.size) for s in own])]
            symbols += [Symbol(name or f"lbl_{platform.text(a)[2:]}", section, a, "object", size, "global")
                        for a, size, section, name in linker_tables(image)]
        else:
            from .index import connect, refresh
            refresh(project)
            symbols = [Symbol(n, ".text", a, "function", s, "global") for a, s, n in connect(project).execute(
                "SELECT address, size, name FROM functions WHERE target=? AND size>0", (target,)).fetchall()]
        if platform.name == "switch" and not any(s.type == "object" for s in symbols):
            symbols += _module_objects(project, target)
        return cls.from_symbol_list(platform, image, symbols)

    @classmethod
    def _build(cls, platform: Platform, image, symbols_path: Path) -> "Program":
        from .gc import read_symbols
        return cls.from_symbol_list(platform, image, read_symbols(symbols_path))

    @classmethod
    def from_symbol_list(cls, platform: Platform, image, symbols: list) -> "Program":
        """An opened image and symbols already read (`gc.Symbol` rows: a symbols.txt's, or a linker map's)."""
        functions = [Function(s.address, s.size, s.name, s.scope) for s in symbols
                     if s.type == "function" and s.section in CODE_SECTIONS and s.size]
        objects = [DataObject(s.address, s.size, s.name, s.section, s.scope, s.data) for s in symbols
                   if s.type == "object" and s.section not in CODE_SECTIONS]
        labels = [DataObject(s.address, 0, s.name, s.section, s.scope) for s in symbols
                  if s.type == "label" or (s.type == "object" and not s.size)]
        sda = {}
        start = next((s.address for s in symbols if s.name == "__init_registers"), None)
        if start is not None and platform.name == "gamecube":
            sda = _gamecube_sda(image, start)
        elif platform.name == "gamecube" and hasattr(image, "entry"):
            from .discover import small_data_bases     # no name yet: the function the entry point calls to set them
            sda = small_data_bases(image)[0]
        program = cls(platform, image, functions, objects, sda)
        program.labels = labels
        program.sections = _named_sections(platform, image, symbols)
        return program

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

    def strings(self, minimum: int = 4) -> dict[int, str]:
        """Printable NUL-terminated strings in the data sections, by address."""
        import re
        if "strings" not in self.cache:
            pattern = re.compile(rb"[\x20-\x7e]{%d,}\x00" % minimum)
            out = {}
            for section in self.platform.sections(self.image):
                if section.kind != "data":
                    continue
                try:
                    raw = self.platform.read(self.image, section.address, section.size)
                except ValueError:
                    continue
                for match in pattern.finditer(raw):
                    out[section.address + match.start()] = match.group(0)[:-1].decode("ascii")
            self.cache["strings"] = out
        return self.cache["strings"]

    def users(self) -> dict[DataObject, set[int]]:
        """Each data object and the functions whose code forms an address inside it."""
        out: dict[DataObject, set[int]] = collections.defaultdict(set)
        for i, rows in self.refs.items():
            for _, address, _ in rows:
                found = self.object_at(address)
                if found is not None:
                    out[found].add(i)
        return out


def _module_objects(project, target: str) -> list:
    """Switch: the sized data symbols the module itself carries (dynamic symbols, RTTI vtables and typeinfos), in
    the dotted sections a symbols.txt names."""
    from .bridge import _module_symbols
    from .gc import Symbol
    return [Symbol(s.name, f".{s.section}", s.address, "object", s.size, s.scope)
            for s in _module_symbols(project, target)
            if s.type != "function" and s.size and s.section in ("rodata", "data", "bss")]


def _named_sections(platform: Platform, image, symbols) -> list[tuple[str, int, int]]:
    """(name, start, end) per section: the image's sections (and a DOL's zero-initialized range) named by the
    section most of their symbols are in, split where the symbols change section (.bss/.sbss/.sbss2 share one
    zero-initialized range)."""
    ranges = [(s.address, s.address + s.size) for s in platform.sections(image)]
    bss = getattr(image, "bss", None)
    if bss and bss[1]:                                 # the zero-initialized range, minus loaded sections inside it
        cursor, end = bss[0], bss[0] + bss[1]
        for start, stop in sorted(r for r in ranges if r[1] > bss[0] and r[0] < end):
            if start > cursor:
                ranges.append((cursor, start))
            cursor = max(cursor, stop)
        if cursor < end:
            ranges.append((cursor, end))
    placed = sorted((s.address, s.section) for s in symbols if s.section)
    out = []
    for start, end in sorted(ranges):
        inside = [(a, n) for a, n in placed if start <= a < end]
        if not inside:
            continue
        runs: list[list] = []
        for address, name in inside:
            if runs and runs[-1][0] == name:
                continue
            runs.append([name, address])
        runs[0][1] = start
        for i, (name, first) in enumerate(runs):
            out.append((name, first, runs[i + 1][1] if i + 1 < len(runs) else end))
    return out


def _gamecube_sda(image, start: int) -> dict[int, int]:
    """r2 and r13 as __init_registers sets them, read up to its `blr` (some runtimes clear every register first,
    so the bases come late in the function)."""
    registers: dict[int, int] = {}
    for index in range(256):
        try:
            word = image.words(start + index * 4, 4)[0]
        except ValueError:
            break
        op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 15 and ra == 0:                       # lis
            registers[rd] = (imm << 16) & 0xFFFFFFFF
        elif op == 24 and rd in registers:             # ori (rA is the destination)
            registers[ra] = registers[rd] | imm
        elif op == 14 and ra == 0:                     # li (rA 0 means the literal 0): a constant, not a base
            registers.pop(rd, None)
        elif op == 14 and ra in registers:             # addi
            registers[rd] = (registers[ra] + (imm - 0x10000 if imm & 0x8000 else imm)) & 0xFFFFFFFF
        elif word == 0x4E800020:
            break
    return {r: registers[r] for r in (2, 13) if r in registers}
