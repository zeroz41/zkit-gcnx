"""Read the original executable directly: disassembly and typed data.

Past sessions wrote hundreds of throwaway DOL readers. These two functions
are the shared, tested replacement. They read the ORIGINAL bytes, so they
are evidence about the game, never about the current build.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from .gc import Dol
from .index import MODULE_SHIFT, address_text, connect, containing, refresh, unit_asm
from .project import Project

TYPES = {"u8": ">B", "s8": ">b", "u16": ">H", "s16": ">h", "u32": ">I", "s32": ">i",
         "f32": ">f", "f64": ">d", "ptr": ">I"}


_DOLS: dict[str, tuple[tuple[int, int], Dol]] = {}


def _dol(project: Project, target: str) -> Dol:
    """The original executable, parsed once per process (the MCP server reads it on every asm/data/lookup call)."""
    config = project.target(target)
    if not config.get("original"):
        raise ValueError(f"Target {target} has no original executable configured")
    path = project.file(config["repository"], config["original"])
    if not path.is_file():
        raise ValueError(f"Original executable is missing: {path}")
    info = path.stat()
    stamp = (info.st_mtime_ns, info.st_size)
    cached = _DOLS.get(str(path))
    if cached is None or cached[0] != stamp:
        cached = (stamp, Dol.load(path))
        _DOLS[str(path)] = cached
    return cached[1]


OBJDUMP_NAMES = ("powerpc-eabi-objdump", "powerpc-linux-gnu-objdump", "powerpc-elf-objdump")


def saved_objdump_path() -> Path:
    import os
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "gcn-zkit" / "objdump"


def _objdump(project: Project) -> str | None:
    """$ZKIT_OBJDUMP, manifest `objdump`, PATH, any repo's dtk binutils, then the path saved by setup."""
    import os
    candidates = [os.environ.get("ZKIT_OBJDUMP")]
    configured = project.config.get("objdump")
    if configured:
        repo, sep, rel = configured.partition(":")
        candidates.append(str(project.file(repo, rel)) if sep and repo in project.config["repositories"] else configured)
    candidates += [shutil.which(name) for name in OBJDUMP_NAMES]
    # decomp-toolkit projects download GNU binutils for PowerPC on their first build (dtk-template:
    # build/binutils, older layouts: build/tools/binutils); .exe on Windows.
    for repo in project.config["repositories"]:
        for folder in ("build/binutils", "build/tools/binutils"):
            candidates += [str(project.root(repo) / folder / (OBJDUMP_NAMES[0] + suffix)) for suffix in ("", ".exe")]
    saved = saved_objdump_path()
    if saved.is_file():
        candidates.append(saved.read_text(encoding="utf-8").strip())
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return candidate
    return None


def _name(db, target: str, address: int) -> str:
    row = containing(db, target, address)
    if row is None:
        return ""
    label = row["demangled"] or row["name"]
    offset = address - row["address"]
    return label + (f"+0x{offset:X}" if offset else "")


def sda_bases(project: Project, target: str, dol: Dol) -> dict[int, int]:
    """r2/r13 small-data bases, decoded from the original __init_registers.

    Manifest `sda_bases` ({"r2": "0x...", "r13": "0x..."}) overrides this."""
    configured = project.target(target).get("sda_bases")
    if configured:
        return {int(k.lstrip("r")): int(v, 16) for k, v in configured.items()}
    config = project.target(target)
    if not config.get("symbols"):
        return {}
    path = project.file(config["repository"], config["symbols"])
    if not path.is_file():
        return {}
    start = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("__init_registers "):
            start = int(re.search(r":0x([0-9A-Fa-f]+)", line)[1], 16)
            break
    if start is None:
        return {}
    regs: dict[int, int] = {}
    for word in dol.words(start, 0x40):
        op, rd, ra, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 15 and ra == 0:  # lis
            regs[rd] = (imm << 16) & 0xFFFFFFFF
        elif op == 24 and rd in regs:  # ori (rA is the destination)
            regs[ra] = regs.get(rd, 0) | imm
        elif op == 14 and ra in regs:  # addi
            regs[rd] = (regs[ra] + (imm - 0x10000 if imm & 0x8000 else imm)) & 0xFFFFFFFF
        elif word == 0x4E800020:
            break
    return {r: v for r, v in regs.items() if r in (2, 13)}


def disasm(project: Project, target: str, address: int, size: int | None = None,
           max_lines: int = 400) -> dict:
    """Original instructions. With size, start exactly at address (an interior address is honoured);
    without, the whole containing function, marking address when it is interior."""
    refresh(project, [])
    db = connect(project)
    size = None if size is None else max(4, size - size % 4)
    row = containing(db, target, address)
    start = address if size is not None or row is None else row["address"]
    size = size or (row["size"] if row else 0x40)
    truncated = size > max_lines * 4
    size = min(size, max_lines * 4)
    from .bridge import _status
    module = start >= 1 << MODULE_SHIFT
    tool = None if module else _objdump(project)
    if module or not tool:
        lines = _dtk_lines(project, target, row, start, size, address) if row else None
        if lines is not None:
            return {"target": target, "address": address_text(start), "size": size, "truncated": truncated,
                    "function": _status(row), "disassembler": "decomp-toolkit asm (relocations resolved)",
                    "text": "\n".join(lines), "source": "original bytes, as split by decomp-toolkit"}
        if module:
            raise ValueError(f"{address_text(start)} is in a REL: its disassembly comes from decomp-toolkit's asm "
                             "output, which is missing. Build the decomp once (`python configure.py && ninja`).")
    dol = _dol(project, target)
    code = dol.read(start, size)
    lines = []
    if tool:
        # delete=False: Windows cannot open a NamedTemporaryFile from a second process while it is open.
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as blob:
            blob.write(code)
        try:
            result = subprocess.run([tool, "-D", "-b", "binary", "-m", "powerpc:common", "-M", "gekko", "-EB",
                                     f"--adjust-vma=0x{start:X}", blob.name],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        finally:
            Path(blob.name).unlink(missing_ok=True)
        from .gc import track_addresses
        sda = sda_bases(project, target, dol)
        resolved_at = track_addresses(list(struct.unpack(f">{len(code) // 4}I", code[:len(code) - len(code) % 4])),
                                      start, sda)
        for line in result.stdout.splitlines():
            match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){3}[0-9a-f]{2})\s*(.*)", line)
            if not match:
                continue
            pc, text = int(match[1], 16), re.sub(r"\s+", " ", match[3].strip())
            hit = resolved_at.get(pc)
            resolved = hit[0] if hit else None
            if resolved is not None and 0x80000000 <= resolved < 0x81800000:
                label = _name(db, target, resolved) or _symbol_name(project, target, resolved)
                text += f"  ; =0x{resolved:08X}" + (f" {label}" if label else "")
                kind = hit[1] if hit[1] in ("f32", "f64") else None
                if kind:
                    try:
                        text += f" = {_value(db, target, dol, resolved, kind)}"
                    except ValueError:
                        pass
                lines.append(f"{pc:08X}  {match[2].replace(' ', '')}  {text}" + ("   <=" if pc == address != start else ""))
                continue
            target_match = re.search(r"\b(?:bl|b|b[a-z]+)\s+(?:[^,]*,)?0x([0-9a-f]+)", text)
            note = ""
            if target_match:
                destination = int(target_match[1], 16)
                label = _name(db, target, destination)
                if label and not (start <= destination < start + size and not text.startswith("bl ")):
                    note = f"  ; {label}"
            lines.append(f"{pc:08X}  {match[2].replace(' ', '')}  {text}{note}" + ("   <=" if pc == address != start else ""))
    else:
        for i, word in enumerate(struct.unpack(f">{len(code) // 4}I", code[:len(code) - len(code) % 4])):
            lines.append(f"{start + i * 4:08X}  {word:08X}")
    return {"target": target, "address": f"0x{start:08X}", "size": size, "truncated": truncated,
            "function": _status(row) if row else None,
            "disassembler": tool or "none (raw words)", "text": "\n".join(lines),
            "source": "original executable bytes"}


def _dtk_lines(project: Project, target: str, row, start: int, size: int, address: int) -> list[str] | None:
    """The function's lines from decomp-toolkit's asm output, or None when that file is missing."""
    from .gc import asm_functions, asm_objects, asm_references, directive_value
    module = row["address"] >= 1 << MODULE_SHIFT
    path = unit_asm(project, project.target(target), row["unit"], module)
    if path is None:
        return None
    body = asm_functions(path).get(row["name"])
    if not body:
        return None
    objects = None
    base = (row["address"] >> MODULE_SHIFT) << MODULE_SHIFT if module else 0
    lines = []
    for instruction in body:
        pc = base | instruction.address
        if not start <= pc < start + size:
            continue
        text = f"{instruction.mnemonic} {instruction.operands}".strip()
        _, refs = asm_references(instruction)
        for symbol, kind in refs:
            if kind in ("f32", "f64"):
                objects = asm_objects(path) if objects is None else objects
                value = directive_value(objects.get(symbol, ""), kind)
                if value is None:  # a DOL constant defined in another unit: read the original bytes
                    value = _dol_constant(project, target, symbol, kind)
                if value is not None:
                    text += f"  ; = {value}"
        where = address_text(pc) if module else f"{pc:08X}"
        lines.append(f"{where}  {instruction.word}  {text}" + ("   <=" if pc == address != start else ""))
    return lines


def _dol_constant(project: Project, target: str, symbol: str, kind: str) -> str | None:
    from .bridge import symbol_named
    found = symbol_named(project, target, symbol)
    if found is None:
        return None
    try:
        raw = _dol(project, target).read(found.address, 4 if kind == "f32" else 8)
    except ValueError:
        return None
    return repr(struct.unpack(">f" if kind == "f32" else ">d", raw)[0])


def _readable(project: Project, target: str, dol: Dol, address: int, width: int) -> None:
    """Explain why an address has no bytes in the executable (bss) instead of a bare range error."""
    section = dol.section_at(address)
    if section is not None and address + width <= section.address + section.size:
        return
    from .bridge import _symbol_lookup
    symbol = _symbol_lookup(project, target, address)
    where = f" ({symbol['name']}+0x{symbol['offset']:X}, {symbol['section']})" if symbol else ""
    bss_start, bss_size = dol.bss
    if bss_start <= address < bss_start + bss_size or (symbol and "bss" in symbol["section"]):
        raise ValueError(f"0x{address:08X}{where} is zero-initialized .bss: the executable has no bytes for it; "
                         "its runtime value comes from code. `gcn-zkit xrefs` lists who writes it.")
    raise ValueError(f"0x{address:08X}+{width}{where} is not inside one section of the executable")


def count_for_size(size: int, kind: str = "u32", fields: list[str] | None = None, stride: int | None = None) -> int:
    """Element/record count that covers `size` bytes (agents ask for bytes as often as for a count)."""
    if fields:
        layout = [f.strip() for f in fields]
        width = stride or sum(struct.calcsize(TYPES[f]) if f in TYPES else int(f[3:] or 0) for f in layout
                              if f in TYPES or re.fullmatch(r"pad\d+", f))
    else:
        width = struct.calcsize(TYPES[kind]) if kind in TYPES else 1
    return max(1, -(-size // max(width, 1)))


def read_data(project: Project, target: str, address: int, kind: str = "u32", count: int = 16,
              stride: int | None = None, fields: list[str] | None = None) -> dict:
    """Typed reads; `fields` + `stride` decode a table of records."""
    refresh(project, [])
    db = connect(project)
    dol = _dol(project, target)
    if kind not in TYPES and kind != "str":
        raise ValueError(f"Unknown type {kind!r}; use one of {', '.join(list(TYPES) + ['str'])}")
    for field in fields or []:
        if field.strip() not in TYPES and not re.fullmatch(r"pad\d+", field.strip()):
            raise ValueError(f"Unknown field {field!r}; use {', '.join(TYPES)} or padN")
    _readable(project, target, dol, address, 1)
    rows = []
    if fields:
        layout = [f.strip() for f in fields]
        width = sum(struct.calcsize(TYPES[f]) if f in TYPES else int(f.lstrip("pad")) for f in layout)
        stride = stride or width
        for index in range(min(count, 512)):
            base = address + index * stride
            values, offset = [], 0
            for field in layout:
                if field.startswith("pad"):
                    offset += int(field[3:])
                    continue
                values.append(_value(db, target, dol, base + offset, field, project))
                offset += struct.calcsize(TYPES[field])
            rows.append({"index": index, "address": f"0x{base:08X}", "values": values})
    elif kind == "str":
        # count = number of consecutive NUL-terminated strings (padding NULs between them are skipped).
        section = dol.section_at(address)
        cursor = address
        for _ in range(min(max(count, 1), 256)):
            limit = min(4096, section.address + section.size - cursor)
            if limit <= 0:
                break
            raw = dol.read(cursor, limit)
            text = raw.split(b"\0", 1)[0]
            rows.append({"address": f"0x{cursor:08X}", "values": [text.decode("shift_jis", errors="replace")]})
            cursor += len(text) + 1
            while cursor < section.address + section.size and dol.read(cursor, 1) == b"\0":
                cursor += 1
    else:
        width = struct.calcsize(TYPES[kind])
        for index in range(min(count, 1024)):
            base = address + index * (stride or width)
            rows.append({"address": f"0x{base:08X}", "values": [_value(db, target, dol, base, kind, project)]})
    owner = containing(db, target, address)
    return {"target": target, "address": f"0x{address:08X}", "kind": kind if not fields else fields,
            "rows": rows, "source": "original executable bytes",
            "inside_function": (owner["demangled"] or owner["name"]) if owner else None}


def _symbol_name(project: Project, target: str, address: int) -> str:
    from .bridge import _symbol_lookup
    symbol = _symbol_lookup(project, target, address)
    if not symbol:
        return ""
    return symbol["name"] + (f"+0x{symbol['offset']:X}" if symbol["offset"] else "")


def _value(db, target: str, dol: Dol, address: int, kind: str, project: Project | None = None):
    value = struct.unpack(TYPES[kind], dol.read(address, struct.calcsize(TYPES[kind])))[0]
    if kind == "ptr":
        label = (_name(db, target, value) or (_symbol_name(project, target, value) if project else "")) \
            if 0x80000000 <= value < 0x81800000 else ""
        return f"0x{value:08X}" + (f" ({label})" if label else "")
    if kind == "f32":
        return float(f"{value:.9g}")
    if kind == "f64":
        return value  # full precision: neighbouring magic doubles differ in the last digits
    if kind.startswith("u") and kind != "u8":
        return f"0x{value:X}" if value > 0xFFFF else value
    return value
