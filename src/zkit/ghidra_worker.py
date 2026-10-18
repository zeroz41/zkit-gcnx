"""Ghidra decompiler worker. Runs in its own process (`python -m zkit.ghidra_worker REQUEST.json`), never in
the MCP server: the JVM costs ~3 s to start and ~1 GB to hold.

The DOL is mapped here from its header; no Ghidra loader runs, because the GameCube Loader's DOL importer opens
Swing dialogs, and the JVM is forced headless so nothing can open a window. Functions are created at the given
boundaries under address names (fn_XXXXXXXX) and data is left undefined, so the output depends only on the
original bytes and the boundaries: the caller substitutes current names when it reads the cache. No auto-analysis:
on a real project it cost ~10x the decompile time and changed no recovered control flow.
"""

from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LANGUAGE = "PowerPC:BE:32:Gekko_Broadway"
SWITCH_LANGUAGE = "AARCH64:LE:64:v8A"


def main(request_path: str) -> int:
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    out = Path(request["output"])
    started = time.monotonic()

    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=Path(request["install_dir"]))
    launcher.add_vmargs("-Djava.awt.headless=true", f"-Xmx{request.get('heap', '2048m')}")
    launcher.start()

    from java.io import ByteArrayInputStream
    from java.lang import Object
    from java.math import BigInteger
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.program.database import ProgramDB
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.lang import CompilerSpecID, LanguageID
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import TaskMonitor

    from .gc import Dol

    switch = request.get("platform") == "switch"
    base = int(request.get("base") or 0)
    wanted = SWITCH_LANGUAGE if switch else LANGUAGE
    try:
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(wanted))
    except Exception:
        out.write_text(json.dumps({"error": f"Ghidra has no {wanted} language" + (
            "" if switch else ": install the GameCube Loader extension (see `zkit doctor`)")}) + "\n", encoding="utf-8")
        return 2
    program = ProgramDB("original", language, language.getCompilerSpecByID(CompilerSpecID("default")), Object())
    address = program.getAddressFactory().getDefaultAddressSpace().getAddress
    transaction = program.startTransaction("map")
    memory = program.getMemory()
    if switch:
        from .nx import load
        module = load(Path(request["dol"]))
        for segment in module.segments:
            if segment.name == "bss":
                memory.createUninitializedBlock("bss", address(base + segment.offset), segment.size, False).setWrite(True)
                continue
            blob = bytes(module.image[segment.offset:segment.offset + segment.size])
            block = memory.createInitializedBlock(segment.name, address(base + segment.offset),
                                                  ByteArrayInputStream(blob), len(blob), TaskMonitor.DUMMY, False)
            block.setRead(True)
            block.setWrite(segment.name == "data")
            block.setExecute(segment.kind == "code")
    else:
        dol = Dol.load(Path(request["dol"]))
        for section in dol.sections:
            blob = dol.raw[section.offset:section.offset + section.size]
            block = memory.createInitializedBlock(f"{section.kind}{section.index}", address(section.address),
                                                  ByteArrayInputStream(blob), len(blob), TaskMonitor.DUMMY, False)
            block.setRead(True)
            block.setWrite(section.kind == "data")
            block.setExecute(section.kind == "text")
        low, high = dol.bss[0], dol.bss[0] + dol.bss[1]
        cursor = low  # .bss as the symbols see it also spans .sdata/.sbss: map only the gaps no section covers
        for start, end in sorted((s.address, s.address + s.size) for s in dol.sections if s.kind == "data") + [(high, high)]:
            if start > cursor and cursor < high:
                memory.createUninitializedBlock(f"bss_{cursor:X}", address(cursor), min(start, high) - cursor,
                                                False).setWrite(True)
            cursor = max(cursor, end)
    width = 10 if switch else 8
    functions = program.getFunctionManager()
    for start, size in request["functions"]:
        at = base + start
        try:
            functions.createFunction(f"fn_{at:0{width}X}", address(at), AddressSet(address(at),
                                     address(at + max(size, 4) - 1)), SourceType.IMPORTED)
        except Exception:
            pass  # overlapping or out-of-image boundary: that function reports "no function"
    context = program.getProgramContext()
    # GameCube: GQR0 is zero (__OSPSInit) and MWCC's own paired-single code uses it; without this every
    # psq_l/psq_st decompiles into dequantization branches. r2/r13 are the small-data bases.
    values = [] if switch else [(f"r{reg}", value) for reg, value in request["sda"].items()] + [("GQR0", 0)]
    for name, value in values:
        register = program.getRegister(name)
        if register is None:
            continue
        for block in memory.getBlocks():
            if block.isExecute():
                context.setValue(register, block.getStart(), block.getEnd(), BigInteger.valueOf(value))
    program.endTransaction(transaction, True)
    setup = time.monotonic() - started

    import threading
    local = threading.local()

    def decompile(start: int) -> dict:
        interface = getattr(local, "interface", None)
        if interface is None:
            interface = DecompInterface()
            options = DecompileOptions()
            options.grabFromProgram(program)
            interface.setOptions(options)
            interface.toggleSyntaxTree(False)
            interface.openProgram(program)
            local.interface = interface
        function = functions.getFunctionAt(address(base + start))
        if function is None:
            return {"address": start, "error": "no function at this boundary"}
        result = interface.decompileFunction(function, request.get("timeout", 60), TaskMonitor.DUMMY)
        if not result.decompileCompleted():
            return {"address": start, "error": str(result.getErrorMessage()).strip() or "decompiler failed"}
        return {"address": start, "text": str(result.getDecompiledFunction().getC()).strip()}

    begun = time.monotonic()
    with ThreadPoolExecutor(max(1, request.get("threads", 8))) as pool, out.open("w", encoding="utf-8") as stream:
        for row in pool.map(decompile, request["addresses"]):
            stream.write(json.dumps(row) + "\n")
        stream.write(json.dumps({"timing": {"setup": round(setup, 2), "decompile": round(time.monotonic() - begun, 2),
                                            "count": len(request["addresses"])}}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
