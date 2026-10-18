"""Virtual tables recovered from the code (CodeWarrior's layout).

A CodeWarrior vtable is two header words (the RTTI pointer, zero when RTTI is off, and the offset to the complete
object, zero for a primary table) and then one function pointer per virtual slot (zero for a pure virtual). The
constructors and destructor of a class form its table's address and store it into the object, so a table is a
data address the code forms whose words have that shape and that some function stores into an object. A
class's destructor is also one of its slots. A dispatch table of handlers has the shape too but is only read
from, and has no such destructor; either fact alone keeps a table, and a name alone keeps none. `classes` reads the classes the tables prove.
"""

from __future__ import annotations

import collections
import struct
from dataclasses import dataclass, field

from .program import Program


@dataclass
class VTable:
    address: int
    offset: int                     # offset-to-top: 0 for a primary table, negative for a secondary one
    slots: list[int]                # function addresses (0 = pure virtual)
    installers: list[int] = field(default_factory=list)  # function indexes that form the table's address
    name: str | None = None         # the class name when the symbols already give one

    @property
    def size(self) -> int:
        return 8 + 4 * len(self.slots)


def find(program: Program, data_sections: tuple[str, ...] = (".data",)) -> dict[int, VTable]:
    """Every table the code forms the address of, with its exact extent."""
    starts = {f.address for f in program.functions}
    formed: dict[int, list[int]] = collections.defaultdict(list)
    for index, rows in program.refs.items():
        for _, address, kind in rows:
            if kind == "addr":
                formed[address].append(index)
    referenced = set(formed) | {pointee for _, pointee in program.pointers}
    tables: dict[int, VTable] = {}
    for address, users in sorted(formed.items()):
        found = program.object_at(address)
        section = found.section if found else _section_of(program, address)
        if section not in data_sections or address % 4:
            continue
        table = _read(program, address, starts, referenced)
        if table is not None:
            table.installers = sorted(set(users))
            tables[address] = table
    for symbol in program.objects:
        if symbol.address in tables and symbol.name.startswith("__vt__"):
            tables[symbol.address].name = _class_from_vtable(symbol.name)
    stored = _stored(program, set(tables))
    for address in [a for a in tables if a not in stored and not _destructor(program, tables[a])]:
        del tables[address]
    return tables


def _stored(program: Program, candidates: set[int]) -> set[int]:
    """Candidate tables some function stores into an object (through `this` or a fresh allocation)."""
    from . import ppcflow
    out = set()
    for flow in ppcflow.flows(program).values():
        for store in flow.stores:
            if store.value is not None and store.value.kind == ppcflow.ADDR and store.value.amount in candidates \
                    and store.width == 4 and store.base.kind in (ppcflow.THIS, ppcflow.NEW):
                out.add(store.value.amount)
    return out


def _destructor(program: Program, table: VTable) -> int | None:
    return next((program.functions[i].address for i in table.installers
                 if program.functions[i].address in table.slots), None)


def _section_of(program: Program, address: int) -> str | None:
    for section in program.platform.sections(program.image):
        if section.address <= address < section.address + section.size:
            return ".data" if section.kind == "data" else ".text"
    return None


def _read(program: Program, address: int, starts: set[int], referenced: set[int]) -> VTable | None:
    try:
        rtti, offset = struct.unpack(">Ii", program.read(address, 8))
    except ValueError:
        return None
    if rtti and (not program.platform.in_image(program.image, rtti) or _section_of(program, rtti) != ".data"):
        return None                                  # an RTTI record lives in data; a code address means a jump table
    if offset > 0 or offset < -0x10000:
        return None
    slots: list[int] = []
    cursor = address + 8
    while True:
        if slots and cursor in referenced:           # the next table or object starts here
            break
        try:
            word = struct.unpack(">I", program.read(cursor, 4))[0]
        except ValueError:
            break
        if word in starts or word == 0:
            slots.append(word)
            cursor += 4
            continue
        break
    while slots and slots[-1] == 0:                  # trailing zeros are the next object's, not pure virtuals
        slots.pop()
    if not any(slots):
        return None
    return VTable(address, offset, slots)


def _class_from_vtable(name: str) -> str:
    """`__vt__10TAdADXlogo` -> `TAdADXlogo` (CodeWarrior's length-prefixed class name)."""
    body = name[len("__vt__"):]
    digits = len(body) - len(body.lstrip("0123456789"))
    if digits and int(body[:digits]) <= len(body) - digits:
        return body[digits:digits + int(body[:digits])]
    return body
