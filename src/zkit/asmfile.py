"""Assembly files a decompiler reads (m2c), written from the original for GameCube functions.

Each function becomes `.fn`/`.endfn` with its instructions as GNU syntax, every reference written as the symbol the
delinker gives it: `sym@ha`/`sym@h` on the `lis`, `sym@l` on the low half, `sym@sda21(r2)` for small data, `bl sym`
for calls and `.L_<address>` labels for branches inside the function. The data the code reads follows as `.obj`
blocks (words, and `.rel` for jump-table cases) so a decompiler can print constants as values. The relocations and
names are the delinker's, so they are the ones the target objects carry.
"""

from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from pathlib import Path

from . import ppc
from .project import Project

LOW_ARITHMETIC = re.compile(r"^(addi|addic\.?|ori|la)\s+(r\d+),\s*(r\d+),\s*(-?(?:0x)?[0-9a-f]+)$")
LOAD_STORE = re.compile(r"^(\w+)\s+(\w+),\s*(-?(?:0x)?[0-9a-f]+)\((r\d+)\)$")
HIGH = re.compile(r"^(lis|addis)\s+(r\d+),\s*(?:r0,\s*)?(-?(?:0x)?[0-9a-f]+)$")
BRANCH = re.compile(r"^(b[\w+-]*)\s+(?:(cr\d+|[0-9]+),\s*)?0x([0-9a-f]+)")


def _disassemble(tool: str, code: bytes, start: int) -> dict[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as blob:
        blob.write(code)
    try:
        result = subprocess.run([tool, "-D", "-b", "binary", "-m", "powerpc:common", "-M", "gekko", "-EB",
                                 f"--adjust-vma=0x{start:X}", blob.name],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    finally:
        Path(blob.name).unlink(missing_ok=True)
    out = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} ){3}[0-9a-f]{2}\s*(.*)", line)
        if match:
            out[int(match[1], 16)] = re.sub(r"\s+", " ", match[2].strip()).replace(",", ", ").replace(",  ", ", ")
    return out


def _symbol(name: str, addend: int) -> str:
    return f"{name}+0x{addend:X}" if addend else name


def function(image, tool: str, start: int, size: int, referenced: set[int]) -> list[str]:
    """One function's lines; adds the data addresses it references to `referenced`."""
    words = list(struct.unpack(f">{size // 4}I", image.read(start, size - size % 4)))
    relocs, _ = image.code(start, size, None)
    by_site: dict[int, list[tuple[int, int]]] = {}
    for offset, kind, target, _got in relocs:
        site = offset - offset % 4
        by_site.setdefault(site, []).append((kind, target))
    text = _disassemble(tool, image.read(start, size - size % 4), start)
    end = start + 4 * len(words)
    labels = set()
    for index, word in enumerate(words):
        found = ppc.branch(word, start + index * 4)
        if found and found[0] is not None and start <= found[0] < end and found[0] != start:
            labels.add(found[0])
    entry = image.symbols.functions[start]
    scope = "local" if entry.scope == "local" else "weak" if entry.scope == "weak" else "global"
    lines = [f".fn {entry.name}, {scope}"]
    for index, word in enumerate(words):
        pc = start + index * 4
        if pc in labels:
            lines.append(f".L_{pc:08X}:")
        instruction = text.get(pc, f".4byte 0x{word:08X}")
        for kind, target in by_site.get(pc, []):
            name, addend = image.symbols.resolve(target)
            symbol = _symbol(name, addend)
            if kind in (ppc.REL24, ppc.REL14):
                instruction = re.sub(r"0x[0-9a-f]+(?: <[^>]*>)?$", symbol, instruction)
                continue
            if image.symbols.function_containing(target) is None:
                referenced.add(target)
            if kind in (ppc.ADDR16_HA, ppc.ADDR16_HI) and (m := HIGH.match(instruction)):
                instruction = f"{m[1]} {m[2]}, {symbol}@{'ha' if kind == ppc.ADDR16_HA else 'h'}"
            elif kind == ppc.ADDR16_LO and (m := LOW_ARITHMETIC.match(instruction)):
                instruction = f"{m[1]} {m[2]}, {m[3]}, {symbol}@l"
            elif kind == ppc.ADDR16_LO and (m := LOAD_STORE.match(instruction)):
                instruction = f"{m[1]} {m[2]}, {symbol}@l({m[4]})"
            elif kind == ppc.EMB_SDA21 and (m := LOAD_STORE.match(instruction)):
                instruction = f"{m[1]} {m[2]}, {symbol}@sda21({m[4]})"
            elif kind == ppc.EMB_SDA21 and (m := LOW_ARITHMETIC.match(instruction)):
                instruction = f"{m[1]} {m[2]}, {m[3]}, {symbol}@sda21"
        if (m := BRANCH.match(instruction)) and not by_site.get(pc):
            destination = int(m[3], 16)
            if destination in labels:
                instruction = re.sub(r"0x[0-9a-f]+(?: <[^>]*>)?$", f".L_{destination:08X}", instruction)
        lines.append(f"/* {pc:08X} {word:08X} */\t{instruction}")
    lines.append(f".endfn {entry.name}")
    return lines


def data(image, address: int, done: set[int]) -> list[str]:
    """The data object holding `address`, as words (`.rel` for words pointing inside a function)."""
    entry = image.symbols.containing(address)
    if entry is None or entry.address in done or not entry.size:
        return []
    done.add(entry.address)
    size = entry.size - entry.size % 4
    lines = [f".obj {entry.name}, {'local' if entry.scope == 'local' else 'global'}"]
    if (image.section_of(entry.address) or "").startswith((".bss", ".sbss")):   # zero-initialized: no bytes
        return lines + [f"\t.skip 0x{entry.size:X}", f".endobj {entry.name}"]
    raw = image.read(entry.address, entry.size)
    pointers = {slot: pointee for slot, pointee, _ in image.pointers(entry.address, entry.address + size)}
    for offset in range(0, size, 4):
        slot = entry.address + offset
        if slot in pointers:
            name, addend = image.symbols.resolve(pointers[slot])
            home = image.symbols.function_containing(pointers[slot])
            if home is not None and addend:
                lines.append(f"\t.rel {home.name}, .L_{pointers[slot]:08X}")
            else:
                lines.append(f"\t.4byte {_symbol(name, addend)}")
        else:
            lines.append(f"\t.4byte 0x{struct.unpack('>I', raw[offset:offset + 4])[0]:08X}")
    if entry.size % 4:
        lines.append("\t.byte " + ", ".join(f"0x{b:02X}" for b in raw[size:]))
    lines.append(f".endobj {entry.name}")
    return lines


def write(project: Project, target: str, addresses: list[int]) -> str:
    """An assembly file for the functions holding `addresses`, with the data they read."""
    from .delink import _image
    from .inspect_dol import _objdump
    from .platform import for_target
    if for_target(project.target(target)).name != "gamecube":
        raise ValueError("Assembly files for decompilers are written for GameCube (PowerPC) targets")
    tool = _objdump(project)
    if tool is None:
        raise ValueError("No PowerPC objdump (powerpc-eabi-objdump): install GNU binutils for powerpc-eabi or set "
                         "`objdump` in the project file")
    image = _image(project, target)
    referenced: set[int] = set()
    out = ['.include "macros.inc"', "", ".section .text"]
    seen = set()
    for address in addresses:
        entry = image.symbols.function_containing(address)
        if entry is None:
            raise ValueError(f"0x{address:08X} is in no known function")
        if entry.address in seen:
            continue
        seen.add(entry.address)
        out += [""] + function(image, tool, entry.address, entry.size, referenced)
    by_section: dict[str, list[str]] = {}
    done: set[int] = set()
    for address in sorted(referenced):
        block = data(image, address, done)
        if block:
            by_section.setdefault(image.section_of(address) or ".data", []).extend([""] + block)
    for name, lines in by_section.items():
        out += ["", f".section {name}"] + lines
    return "\n".join(out) + "\n"


def find_m2c(project: Project) -> list[str] | None:
    """How to run m2c: the project file's `m2c` (a command, a path to m2c.py, or an argv list such as a project's own
    adapter `["python", "tools/m2c_runner.py", "../m2c"]`, run from the decomp root), `m2c` on PATH, the checkout
    `zkit build --download` fetched (build/tools/m2c), or an m2c checkout beside a repository (../m2c/m2c.py)."""
    import shutil
    import sys
    configured = project.config.get("m2c")
    if isinstance(configured, list) and configured:
        return [str(part) for part in configured]
    candidates = [configured] if configured else []
    candidates.append(shutil.which("m2c"))
    candidates += [str(project.root(repo) / "build/tools/m2c/m2c.py") for repo in project.config["repositories"]]
    candidates += [str(project.root(repo).parent / "m2c" / "m2c.py") for repo in project.config["repositories"]]
    for candidate in candidates:
        if not candidate:
            continue
        if candidate.endswith(".py") and Path(candidate).is_file():
            return [sys.executable, candidate]
        if Path(candidate).is_file() or shutil.which(candidate):
            return [candidate]
    return None


FAILED = re.compile(r"Decompilation failure|M2C_ERROR|unknown instruction")


def ghidra_advice(text: str) -> str | None:
    """When Ghidra's reading is worth taking: where m2c failed or emitted goto, Ghidra's loops and branches were
    closer to the matched source (111 of 160 differing functions on a 27.5k-function decomp); elsewhere m2c's
    switch, return and call shape was, so m2c's seed stands on its own."""
    gotos = len(re.findall(r"\bgoto\b", text))
    if not text.strip() or re.search(r"Decompilation failure", text):
        return "m2c failed: take loop and branch shape from Ghidra"
    if FAILED.search(text):
        return "m2c left errors (M2C_ERROR): take loop and branch shape from Ghidra"
    if gotos:
        return f"m2c emitted {gotos} goto(s): take loop and branch shape from Ghidra"
    return None


def m2c(project: Project, target: str, addresses: list[int], language: str | None = None,
        context: Path | None = None, ghidra: bool = True) -> dict:
    """m2c's C for the functions holding `addresses`, each from an assembly file written by `write`. Where m2c
    fails or emits goto, Ghidra's reading of the same bytes follows when Ghidra is set up (`ghidra_advice`)."""
    from .delink import _image
    from .platform import for_target
    if for_target(project.target(target)).name != "gamecube":
        raise ValueError("m2c reads PowerPC (and MIPS) code, not this target's: use zkit decompile (Ghidra)")
    command = find_m2c(project)
    if command is None:
        raise ValueError("m2c not found: `zkit build --download` fetches it (or set `m2c` in the project file: a "
                         "command, a path to m2c.py, or the argv of the project's own m2c adapter; put it on PATH; or "
                         "check it out beside the decomp, ../m2c)")
    from .activity import state_dir
    folder = state_dir(project) / "m2c"
    folder.mkdir(parents=True, exist_ok=True)
    workdir = project.root(project.target(target)["repository"])
    image = _image(project, target)
    results = []
    for address in dict.fromkeys(addresses):
        entry = image.symbols.function_containing(address)
        if entry is None:
            raise ValueError(f"0x{address:08X} is in no known function")
        lang = language or ("c++" if re.search(r"__\d|__ct|__dt|^\w+__\w", entry.name) else "c")
        path = folder / f"{entry.name}.s"
        path.write_text(write(project, target, [entry.address]), encoding="utf-8")
        argv = [*command, "--target", f"ppc-mwcc-{lang}", "-f", entry.name]
        if context:
            argv += ["--context", str(context.resolve())]
        result = subprocess.run([*argv, str(path.resolve())], cwd=workdir, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=300)
        text = result.stdout if result.returncode == 0 else ""
        row = {"function": entry.name, "address": f"0x{entry.address:08X}", "language": lang, "asm": str(path),
               "text": text}
        if result.returncode:
            row["error"] = (result.stderr or result.stdout).strip()[-800:]
        advice = ghidra_advice(text)
        if advice:
            row["ghidra_advice"] = advice
        results.append(row)
    wanted = [int(r["address"], 16) for r in results if r.get("ghidra_advice")]
    if ghidra and wanted:
        from .decompile import decompile
        try:
            readings = {int(r["address"], 16): r for r in decompile(project, target, wanted)["results"]}
        except ValueError as error:  # Ghidra is optional: say how to get its reading instead
            readings = {}
            for r in results:
                if r.get("ghidra_advice"):
                    r["ghidra_error"] = str(error)
        for r in results:
            reading = readings.get(int(r["address"], 16))
            if reading and reading.get("text"):
                r["ghidra"] = reading["text"]
    return {"command": command, "results": results}
