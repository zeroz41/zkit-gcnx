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

from .index import MODULE_SHIFT, address_text, connect, containing, refresh
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
    """$ZKIT_OBJDUMP, manifest `objdump`, PATH, any repo's downloaded binutils, then the path saved by setup."""
    import os
    candidates = [os.environ.get("ZKIT_OBJDUMP")]
    configured = project.config.get("objdump")
    if configured:
        repo, sep, rel = configured.partition(":")
        candidates.append(str(project.file(repo, rel)) if sep and repo in project.config["repositories"] else configured)
    candidates += [shutil.which(name) for name in OBJDUMP_NAMES]
    # Many decomp projects download GNU binutils for PowerPC on their first build (into
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


def sda_bases(project: Project, target: str, dol) -> dict[int, int]:
    """r2/r13 small-data bases, decoded from the original __init_registers.

    Manifest `sda_bases` ({"r2": "0x...", "r13": "0x..."}) overrides this."""
    configured = project.target(target).get("sda_bases")
    if configured:
        return {int(k.lstrip("r")): int(v, 16) for k, v in configured.items()}
    config = project.target(target)
    path = project.file(config["repository"], config["symbols"]) if config.get("symbols") else None
    start = None
    for line in (path.read_text(encoding="utf-8", errors="replace").splitlines() if path and path.is_file() else []):
        if line.startswith("__init_registers "):
            start = int(re.search(r":0x([0-9A-Fa-f]+)", line)[1], 16)
            break
    if start is None:                                 # not named yet: the function the entry point calls to set them
        from .discover import small_data_bases
        return small_data_bases(dol)[0]
    from .program import _gamecube_sda
    return _gamecube_sda(dol, start)


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
    if start >= 1 << MODULE_SHIFT:
        return _disasm_module(project, target, row, start, size, address, truncated)
    tool = _objdump(project)
    dol = _dol(project, target)
    code = dol.read(start, size)
    lines = []
    if tool:
        from .gc import track_addresses
        sda = sda_bases(project, target, dol)
        resolved_at = track_addresses(list(struct.unpack(f">{len(code) // 4}I", code[:len(code) - len(code) % 4])),
                                      start, sda)
        for pc, word, text in _objdump_lines(tool, code, start):
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
                lines.append(f"{pc:08X}  {word}  {text}" + ("   <=" if pc == address != start else ""))
                continue
            target_match = re.search(r"\b(?:bl|b|b[a-z]+)\s+(?:[^,]*,)?0x([0-9a-f]+)", text)
            note = ""
            if target_match:
                destination = int(target_match[1], 16)
                label = _name(db, target, destination)
                if label and not (start <= destination < start + size and not text.startswith("bl ")):
                    note = f"  ; {label}"
            lines.append(f"{pc:08X}  {word}  {text}{note}" + ("   <=" if pc == address != start else ""))
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
    from .fetch import llvm_tool
    tool = llvm_tool("llvm-objdump") or shutil.which("aarch64-linux-gnu-objdump")
    if tool is None:
        raise ValueError("No AArch64 disassembler: `zkit build --download` fetches LLVM, or install llvm-objdump")
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


def _objdump_lines(tool: str, code: bytes, vma: int) -> list[tuple[int, str, str]]:
    """(address, word, text) per instruction of PowerPC bytes, through GNU objdump."""
    # delete=False: Windows cannot open a NamedTemporaryFile from a second process while it is open.
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as blob:
        blob.write(code)
    try:
        result = subprocess.run([tool, "-D", "-b", "binary", "-m", "powerpc:common", "-M", "gekko", "-EB",
                                 f"--adjust-vma=0x{vma:X}", blob.name],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    finally:
        Path(blob.name).unlink(missing_ok=True)
    out = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){3}[0-9a-f]{2})\s*(.*)", line)
        if match:
            out.append((int(match[1], 16), match[2].replace(" ", ""), re.sub(r"\s+", " ", match[3].strip())))
    return out


def _rel_modules(project: Project, target: str, wanted: set[int]) -> dict:
    """{module id: rel.Module} for the wanted modules' REL files: the ones the index decoded, else found as it
    finds them."""
    import json
    from . import rel
    from .index import _MODULE_NAMES, _meta
    known = [Path(p) for p in json.loads(_meta(connect(project), f"modfiles:{target}") or "[]")]
    files: dict[int, list[Path]] = {}
    for path in known:
        number = rel.cached_id(path)
        if number in wanted:
            files.setdefault(number, []).append(path)
    if not wanted <= set(files):
        files = rel.module_files(project, target)
    out = {}
    for number in wanted:
        path = rel.pick(files.get(number, []), _MODULE_NAMES.get(number))
        if path is not None:
            out[number] = rel.cached(path)
    return out


def _disasm_module(project: Project, target: str, row, start: int, size: int, address: int,
                   truncated: bool) -> dict:
    """A REL function from the module's own bytes, through the same objdump as the DOL: each relocated field named
    from the module's relocation table (DOL symbols, functions of this or another module, a section offset for
    module data, the value a float load reads) and each call makerel applied named by its target."""
    from . import rel
    from .bridge import _status
    db = connect(project)
    number = start >> MODULE_SHIFT
    found = _rel_modules(project, target, {number})
    module = found.get(number)
    if module is None or module.code is None:
        raise ValueError(f"{address_text(start)} is in a REL zkit did not find: list its file (or folder) under the "
                         "target's `modules` in the project file")
    base = module.base[module.code]
    offset = start & 0xFFFFFFFF
    code = module.read(base + offset, size)
    fields = module.relocations(base + offset, base + offset + size)
    others = _rel_modules(project, target, {r.module for _, r in fields} - {0, number})
    others[number] = module
    notes: dict[int, list[str]] = {}
    for field, reloc in fields:
        word = struct.unpack_from(">I", code, field - field % 4 - base - offset)[0]
        notes.setdefault(field - field % 4, []).append(
            _relocated(project, target, db, module, others, reloc, module.target(reloc, others), word))
    tool = _objdump(project)
    rows = _objdump_lines(tool, code, offset) if tool else [
        (offset + i * 4, f"{w:08X}", "") for i, w in enumerate(struct.unpack(f">{len(code) // 4}I", code))]
    lines = []
    for pc, word, text in rows:
        note = "".join(notes.get(base + pc, []))
        if not note:
            branch = re.search(r"\b(?:bl|b|b[a-z]+)\s+(?:[^,]*,)?0x([0-9a-f]+)", text)
            destination = (number << MODULE_SHIFT) | int(branch[1], 16) if branch else None
            if destination is not None and not (start <= destination < start + size and not text.startswith("bl ")):
                label = _name(db, target, destination)
                note = f"  ; {label}" if label else ""
        lines.append(f"{address_text((number << MODULE_SHIFT) | pc)}  {word}  {text}{note}"
                     + ("   <=" if (number << MODULE_SHIFT) | pc == address != start else ""))
    return {"target": target, "address": address_text(start), "size": size, "truncated": truncated,
            "function": _status(row) if row else None, "disassembler": tool or "none (raw words)",
            "text": "\n".join(lines), "source": "original REL bytes and relocation table"}


def _relocated(project: Project, target: str, db, module, others: dict, reloc, destination: int, word: int) -> str:
    """What one relocated field of REL code names: `; -> name` for a branch, `; =address name` for an address
    (with the value a float load reads). Module data has no address of its own: module[section]+offset."""
    from . import rel
    key = module.key(destination, others)
    owner = others.get(reloc.module) if reloc.module else None
    if key is not None:
        label = _name(db, target, key) or ("" if reloc.module else _symbol_name(project, target, key))
        where = address_text(key) if reloc.module else f"0x{key:08X}"
    else:
        label = ""
        where = f"{address_text(reloc.module << MODULE_SHIFT).split('+')[0]}[{reloc.target_section}]+0x{reloc.addend:X}"
    if reloc.kind in (rel.REL24, rel.REL14):
        return f"  ; -> {where}" + (f" {label}" if label else "")
    text = f"  ; ={where}" + (f" {label}" if label else "")
    kind = rel.access(word)
    if reloc.kind != rel.ADDR16_HA and kind in ("f32", "f64") and (owner is not None or not reloc.module):
        width = 4 if kind == "f32" else 8
        try:
            raw = owner.read(owner.base.get(reloc.target_section, 0) + reloc.addend, width) if owner else \
                _dol(project, target).read(destination, width)
            value = struct.unpack(">f" if kind == "f32" else ">d", raw)[0]
            text += f" = {float(f'{value:.9g}') if kind == 'f32' else value}"
        except (ValueError, struct.error):
            pass
    return text


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


READ_CAPS = {"rows": 1024, "records": 512, "strings": 256}


def read_data(project: Project, target: str, address: int, kind: str | None = None, count: int | None = None,
              stride: int | None = None, fields: list[str] | None = None, size: int | None = None) -> dict:
    """Typed reads; `fields` + `stride` decode a table of records. Without count (or size, in bytes), the data
    symbol at the address gives the extent, else 16 elements. Reads stop at the end of the section. Without a
    kind, words: u32, or pointer-sized where a 64-bit module relocates words of what is read."""
    refresh(project, [])
    db = connect(project)
    dol = _dol(project, target)
    if kind is not None and kind not in TYPES and kind != "str":
        raise ValueError(f"Unknown type {kind!r}; use one of {', '.join(list(TYPES) + ['str'])}")
    for field in fields or []:
        if field.strip() not in TYPES and not re.fullmatch(r"pad\d+", field.strip()):
            raise ValueError(f"Unknown field {field!r}; use {', '.join(TYPES)} or padN")
    _readable(project, target, dol, address, 1)
    from .bridge import _symbol_lookup
    symbol = _symbol_lookup(project, target, address)
    extent = size or (symbol["size"] - symbol["offset"] if symbol and symbol["size"] > symbol["offset"] else None)
    section = dol.section_at(address)
    end = min(section.address + section.size, address + size) if size else section.address + section.size
    if kind is None:
        kind = _word(project, target, dol, address, min(end, address + (extent or 16 * 8)))
    rows, notes = [], []

    def bounded(wanted: int, cap: str) -> int:
        if wanted > READ_CAPS[cap]:
            notes.append(f"first {READ_CAPS[cap]} of {wanted} {cap}; read the rest from a later address")
        return min(wanted, READ_CAPS[cap])

    if fields:
        layout = [f.strip() for f in fields]
        width = sum(struct.calcsize(_format(project, target, f)) if f in TYPES else int(f.lstrip("pad")) for f in layout)
        stride = stride or width
        wanted = count or (max(1, extent // stride) if extent else 16)
        for index in range(bounded(wanted, "records")):
            base = address + index * stride
            if base + width > end:
                notes.append(f"stopped after {index} records at the end of the section or size")
                break
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
        cursor = address
        wanted = count or (READ_CAPS["strings"] if size else 1 if extent else 16)  # with size: every string in it
        for _ in range(bounded(wanted, "strings") if count else wanted):
            limit = min(4096, end - cursor)
            if limit <= 0:
                break
            raw = dol.read(cursor, limit)
            text = raw.split(b"\0", 1)[0]
            rows.append({"address": address_text(cursor), "values": [_decode_text(project, target, text)]})
            cursor += len(text) + 1
            while cursor < end and dol.read(cursor, 1) == b"\0":
                cursor += 1
    else:
        width = struct.calcsize(_format(project, target, kind))
        step = stride or width
        wanted = count or (max(1, -(-extent // step)) if extent else 16)
        for index in range(bounded(wanted, "rows")):
            base = address + index * step
            if base + width > end:
                notes.append(f"stopped after {index} values at the end of the section or size")
                break
            rows.append({"address": address_text(base), "values": [_value(db, target, dol, base, kind, project)]})
    owner = containing(db, target, address)
    return {"target": target, "address": address_text(address), "kind": kind if not fields else fields,
            "rows": rows, "source": "original executable bytes", "notes": notes,
            "symbol": symbol["name"] + (f"+0x{symbol['offset']:X}" if symbol["offset"] else "") if symbol else None,
            "inside_function": (owner["demangled"] or owner["name"]) if owner else None}


def _word(project: Project, target: str, dol, address: int, end: int) -> str:
    """The type a read without one takes: u32, or on a 64-bit target the pointer-sized word where the module
    relocates a word of [address, end) (a vtable, a table of pointers)."""
    from .platform import for_target
    if for_target(project.target(target)).pointer_size != 8 or address % 8 or getattr(dol, "pointers", None) is None:
        return "u32"
    return "ptr" if any(a in dol.pointers or a in dol.imports for a in range(address, end, 8)) else "u32"


def _decode_text(project: Project, target: str, raw: bytes) -> str:
    """Strings as the game stores them: UTF-8 or Shift-JIS (cp932, Windows' superset of it, for the rest),
    whichever the bytes are, Shift-JIS first on GameCube; bytes that are neither are escaped."""
    from .platform import for_target
    order = ("utf-8", "shift_jis", "cp932")
    if for_target(project.target(target)).name != "switch":
        order = ("shift_jis", "cp932", "utf-8")
    for encoding in order:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            pass
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in raw.decode("latin-1"))


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
        if getattr(dol, "pointers", None) is not None:  # a module: a word is a pointer where a relocation makes it one
            if address in dol.imports:
                return f"{dol.imports[address]} (import)"
            key, inside = dol.pointers.get(address, value), address in dol.pointers
        else:
            key = value - current.base if current.base and value >= current.base else value
            inside = bool(value) and current.in_image(dol, key)
        label = (_name(db, target, key) or (_symbol_name(project, target, key) if project else "")) if inside else ""
        return (address_text(key) if inside else f"0x{value:X}") + (f" ({label})" if label else "")
    if kind == "f32":
        return float(f"{value:.9g}")
    if kind == "f64":
        return value  # full precision: neighbouring magic doubles differ in the last digits
    if kind.startswith("u") and kind != "u8":
        return f"0x{value:X}"  # one notation per column: words, flags and offsets read as hex
    return value
