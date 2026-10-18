"""Classes from Itanium C++ RTTI in a loaded module: names, bases and vtables with their slots.

A typeinfo object starts with a pointer into one of the `__cxxabiv1` type-info vtables (an import, so the
relocation names it), then a pointer to the mangled type name. Single-inheritance typeinfo adds its base;
multiple-inheritance typeinfo adds a base list with offsets. A vtable is an offset-to-top word, a pointer to a
typeinfo, then the virtual functions. All of it is evidence that holds without a single symbol: the class
names, the hierarchy and which function sits in which slot.
"""

from __future__ import annotations

import struct
import subprocess
from dataclasses import dataclass, field

from .nx import Module

CLASS = "_ZTVN10__cxxabiv117__class_type_infoE"
SINGLE = "_ZTVN10__cxxabiv120__si_class_type_infoE"
MULTIPLE = "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
KINDS = {CLASS: "class", SINGLE: "single", MULTIPLE: "multiple"}


@dataclass
class ClassInfo:
    typeinfo: int
    mangled: str                 # the type name as stored, e.g. N2mp6LayoutE
    kind: str                    # class, single, multiple
    bases: list[tuple[int, int]] = field(default_factory=list)   # (base typeinfo, offset flags)
    vtables: list[dict] = field(default_factory=list)            # {address, offset_to_top, slots: [function offsets]}
    name: str = ""               # demangled


def _string(module: Module, offset: int, limit: int = 512) -> str | None:
    if not 0 <= offset < len(module.image):
        return None
    end = module.image.find(b"\0", offset, offset + limit)
    if end < 0:
        return None
    try:
        return module.image[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def classes(module: Module) -> dict[int, ClassInfo]:
    """{typeinfo offset: ClassInfo} for every class typeinfo the module defines."""
    found: dict[int, ClassInfo] = {}
    for offset, name in module.imports.items():
        base_name = name.split("+", 1)[0]
        kind = KINDS.get(base_name)
        if kind is None:
            continue
        pointer = module.pointers.get(offset + 8)
        mangled = _string(module, pointer) if pointer is not None else None
        if not mangled:
            continue
        info = ClassInfo(offset, mangled, kind)
        if kind == "single":
            base = module.pointers.get(offset + 16)
            if base is not None:
                info.bases.append((base, 0))
        elif kind == "multiple":
            count = struct.unpack_from("<I", module.image, offset + 20)[0]
            for i in range(min(count, 64)):
                base = module.pointers.get(offset + 24 + i * 16)
                flags = struct.unpack_from("<q", module.image, offset + 32 + i * 16)[0]
                if base is not None:
                    info.bases.append((base, flags))
        found[offset] = info
    _vtables(module, found)
    _demangle(found)
    return found


def _vtables(module: Module, found: dict[int, ClassInfo]) -> None:
    text = next((s for s in module.segments if s.name == "text"), None)
    if text is None:
        return
    in_text = lambda value: text.offset <= value < text.offset + text.size
    pointers = module.pointers
    for slot, target in sorted(pointers.items()):
        info = found.get(target)
        if info is None:
            continue
        top = slot - 8
        if top in pointers or slot + 8 not in pointers and slot + 8 not in module.imports:
            continue  # not a vtable header (offset-to-top is a plain integer)
        offset_to_top = struct.unpack_from("<q", module.image, top)[0]
        if offset_to_top > 0 or offset_to_top < -0x100000:
            continue
        functions = []
        position = slot + 8
        while position in pointers or position in module.imports:
            value = pointers.get(position)
            if value is None:  # an import in a slot: a function from another module (pure virtual, base)
                functions.append(-1)
            elif in_text(value):
                functions.append(value)
            else:
                break
            position += 8
            if position - 8 in found or position in found:
                break
        if functions:
            info.vtables.append({"address": slot + 8, "offset_to_top": offset_to_top, "slots": functions})


def _demangle(found: dict[int, ClassInfo]) -> None:
    names = [f"_ZTS{info.mangled}" for info in found.values()]
    if not names:
        return
    from .fetch import llvm_tool
    for tool in (llvm_tool("llvm-cxxfilt") or "llvm-cxxfilt", "c++filt"):
        try:
            result = subprocess.run([tool], input="\n".join(names), capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        lines = result.stdout.splitlines()
        if len(lines) == len(names):
            for info, line in zip(found.values(), lines):
                info.name = line.removeprefix("typeinfo name for ").strip()
            return
    for info in found.values():
        info.name = info.mangled


def graph(module: Module) -> dict:
    """Classes with their bases by name and their primary vtable slots, ready for headers and naming."""
    found = classes(module)
    out = []
    for info in sorted(found.values(), key=lambda i: i.name):
        bases = [found[b].name if b in found else f"<external 0x{b:X}>" for b, _ in info.bases]
        primary = next((v for v in info.vtables if v["offset_to_top"] == 0), None)
        out.append({"name": info.name, "typeinfo": info.typeinfo, "kind": info.kind, "bases": bases,
                    "vtables": info.vtables, "slots": len(primary["slots"]) if primary else 0})
    return {"classes": out, "count": len(out),
            "with_vtable": sum(1 for c in out if c["vtables"])}
