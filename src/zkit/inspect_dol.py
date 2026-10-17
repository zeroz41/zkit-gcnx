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

from .index import MODULE_SHIFT, address_text, connect, containing, refresh, unit_asm
from .project import Project

TYPES = {"u8": ">B", "s8": ">b", "u16": ">H", "s16": ">h", "u32": ">I", "s32": ">i",
         "u64": ">Q", "s64": ">q", "f32": ">f", "f64": ">d", "ptr": ">I"}


def _format(project: Project, target: str, kind: str) -> str:
    """struct format of a type in the target's byte order and pointer size."""
    from .platform import for_target
    platform = for_target(project.target(target))
    code = TYPES[kind][1:]
    if kind == "ptr" and platform.pointer_size == 8:
        code = "Q"
    return platform.endian + code


_DOLS: dict[str, tuple[tuple[int, int], object]] = {}


def _dol(project: Project, target: str):
    """The original executable (a DOL, or a Switch module), parsed once per process."""
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
        from .platform import for_target
        cached = (stamp, for_target(config).open(path))
        _DOLS[str(path)] = cached
    return cached[1]


OBJDUMP_NAMES = ("powerpc-eabi-objdump", "powerpc-linux-gnu-objdump", "powerpc-elf-objdump")


def saved_objdump_path() -> Path:
    import os
    from .paths import config_home
    return config_home() / "objdump"


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
    from .platform import for_target
    if for_target(project.target(target)).name == "switch":
        return _disasm_elf(project, target, address, size, max_lines)
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


_ELVES: dict[str, tuple[str, Path]] = {}


def module_elf(project: Project, target: str) -> Path:
    """The original module as an ELF with the index's function names, cached: what disassemblers and Ghidra read."""
    from .index import _meta, cache_path
    from .nx import to_elf
    from .platform import for_target
    config = project.target(target)
    platform = for_target(config)
    db = connect(project)
    original = project.file(config["repository"], config["original"])
    stamp = f"{original.stat().st_size}:{original.stat().st_mtime_ns}:{_meta(db, f'bounds:{target}')}:{platform.base}"
    path = cache_path(project).with_name(f"{cache_path(project).stem}-{target}.elf")
    if _ELVES.get(str(path), ("",))[0] == stamp and path.is_file():
        return path
    marker = path.with_suffix(".stamp")
    if not (path.is_file() and marker.is_file() and marker.read_text(encoding="utf-8") == stamp):
        rows = db.execute("SELECT address, size, name FROM functions WHERE target=? AND address<? ORDER BY address",
                          (target, 1 << MODULE_SHIFT)).fetchall()
        blob = to_elf(_dol(project, target), platform.base, [(r[0], r[1], r[2]) for r in rows])
        partial = path.with_suffix(".partial")
        partial.write_bytes(blob)
        partial.replace(path)
        marker.write_text(stamp, encoding="utf-8")
    _ELVES[str(path)] = (stamp, path)
    return path


def _disasm_elf(project: Project, target: str, address: int, size: int | None, max_lines: int) -> dict:
    """AArch64: llvm-objdump over the cached module ELF; adrp-formed addresses named and float constants read."""
    from .bridge import _status
    from .platform import for_target
    platform = for_target(project.target(target))
    db = connect(project)
    tool = shutil.which("llvm-objdump") or shutil.which("aarch64-linux-gnu-objdump")
    if tool is None:
        raise ValueError("No AArch64 disassembler: install LLVM (llvm-objdump)")
    row = containing(db, target, address)
    start = address if size is not None or row is None else row["address"]
    size = size or (row["size"] if row else 0x40)
    truncated = size > max_lines * 4
    size = min(size, max_lines * 4)
    elf = module_elf(project, target)
    result = subprocess.run([tool, "-d", f"--start-address=0x{platform.base + start:X}",
                             f"--stop-address=0x{platform.base + start + size:X}", str(elf)],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    image = _dol(project, target)
    refs: dict[int, list[tuple[int, str]]] = {}
    for pc, value, kind in platform.addresses(image, start, size, {}):
        refs.setdefault(pc, []).append((value, kind))
    lines = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){4}|[0-9a-f]{8})\s*(.*)", line)
        if not match:
            continue
        pc = int(match[1], 16) - platform.base
        word = match[2].replace(" ", "")
        text = re.sub(r"\s+", " ", match[3].strip())
        for value, kind in refs.get(pc, []):
            label = _name(db, target, value) or _symbol_name(project, target, value) or \
                (image.symbols.get(value) if hasattr(image, "symbols") else "")
            text += f"  ; ={address_text(value)}" + (f" {label}" if label else "")
            if kind in ("f32", "f64"):
                try:
                    text += f" = {_value(db, target, image, value, kind, project)}"
                except (ValueError, struct.error):
                    pass
        lines.append(f"{address_text(pc)[2:]}  {word}  {text}" + ("   <=" if pc == address != start else ""))
    return {"target": target, "address": address_text(start), "size": size, "truncated": truncated,
            "function": _status(row) if row else None, "disassembler": Path(tool).name, "text": "\n".join(lines),
            "source": "original module bytes"}


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
    return repr(struct.unpack(_format(project, target, kind), raw)[0])


def _readable(project: Project, target: str, dol, address: int, width: int) -> None:
    """Explain why an address has no bytes in the executable (bss) instead of a bare range error."""
    section = dol.section_at(address)
    if section is not None and address + width <= section.address + section.size:
        return
    from .bridge import _symbol_lookup
    symbol = _symbol_lookup(project, target, address)
    where = f" ({symbol['name']}+0x{symbol['offset']:X}, {symbol['section']})" if symbol else ""
    bss_start, bss_size = dol.bss
    if bss_start <= address < bss_start + bss_size or (symbol and "bss" in symbol["section"]):
        raise ValueError(f"{address_text(address)}{where} is zero-initialized .bss: the executable has no bytes for it; "
                         "its runtime value comes from code. `zkit xrefs` lists who writes it.")
    raise ValueError(f"{address_text(address)}+{width}{where} is not inside one section of the executable")


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
        width = sum(struct.calcsize(_format(project, target, f)) if f in TYPES else int(f.lstrip("pad")) for f in layout)
        stride = stride or width
        for index in range(min(count, 512)):
            base = address + index * stride
            values, offset = [], 0
            for field in layout:
                if field.startswith("pad"):
                    offset += int(field[3:])
                    continue
                values.append(_value(db, target, dol, base + offset, field, project))
                offset += struct.calcsize(_format(project, target, field))
            rows.append({"index": index, "address": address_text(base), "values": values})
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
            rows.append({"address": address_text(cursor), "values": [_decode_text(project, target, text)]})
            cursor += len(text) + 1
            while cursor < section.address + section.size and dol.read(cursor, 1) == b"\0":
                cursor += 1
    else:
        width = struct.calcsize(_format(project, target, kind))
        for index in range(min(count, 1024)):
            base = address + index * (stride or width)
            rows.append({"address": address_text(base), "values": [_value(db, target, dol, base, kind, project)]})
    owner = containing(db, target, address)
    return {"target": target, "address": address_text(address), "kind": kind if not fields else fields,
            "rows": rows, "source": "original executable bytes",
            "inside_function": (owner["demangled"] or owner["name"]) if owner else None}


def _decode_text(project: Project, target: str, raw: bytes) -> str:
    """Strings as the game stores them: Shift-JIS on GameCube, UTF-8 on Switch."""
    from .platform import for_target
    encoding = "utf-8" if for_target(project.target(target)).name == "switch" else "shift_jis"
    return raw.decode(encoding, errors="replace")


def _symbol_name(project: Project, target: str, address: int) -> str:
    from .bridge import _symbol_lookup
    symbol = _symbol_lookup(project, target, address)
    if not symbol:
        return ""
    return symbol["name"] + (f"+0x{symbol['offset']:X}" if symbol["offset"] else "")


def _value(db, target: str, dol, address: int, kind: str, project: Project | None = None):
    fmt = _format(project, target, kind) if project else TYPES[kind]
    value = struct.unpack(fmt, dol.read(address, struct.calcsize(fmt)))[0]
    if kind == "ptr":
        from .index import platform
        current = platform()
        key = value - current.base if current.base and value >= current.base else value
        inside = bool(value) and current.in_image(dol, key)
        label = (_name(db, target, key) or (_symbol_name(project, target, key) if project else "")) if inside else ""
        return (address_text(key) if inside else f"0x{value:X}") + (f" ({label})" if label else "")
    if kind == "f32":
        return float(f"{value:.9g}")
    if kind == "f64":
        return value  # full precision: neighbouring magic doubles differ in the last digits
    if kind.startswith("u") and kind != "u8":
        return f"0x{value:X}" if value > 0xFFFF else value
    return value
