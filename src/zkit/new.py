"""`zkit new`: a decomp repository from the original alone, with nothing set up by hand.

From a GameCube disc image (or a bare DOL) or a Switch module (NSO, or an ELF of one): the original is copied
into `orig/<id>/` (a disc is extracted, its Yaz0 files and RARC archives unpacked), never committed; the
project file is written and registered; then zkit finds the functions, proposes the units with their data, writes
`config/<id>/symbols.txt` and `splits.txt`, a header per recovered class, and every unit's target object with
objdiff's project file. What is left is the decomp itself.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import archive, onboard
from .disc import Disc
from .gc import GC_DISC_MAGIC

GITIGNORE = """# The original game and everything derived from it stay local
orig/
build/
*.iso
*.gcm
*.nsp
*.xci
*.nca
*.keys
"""


def kind_of(source: Path) -> str:
    """'disc', 'dol', 'nso' or 'elf', from the file's own header."""
    with source.open("rb") as stream:
        head = stream.read(0x100)
    if len(head) >= 0x20 and int.from_bytes(head[0x1C:0x20], "big") == GC_DISC_MAGIC:
        return "disc"
    if head[:4] == b"NSO0":
        return "nso"
    if head[:4] == b"\x7fELF":
        return "elf"
    if len(head) == 0x100 and all(0x80000000 <= int.from_bytes(head[0x48 + 4 * i:0x4C + 4 * i], "big") < 0x81800000
                                  or not int.from_bytes(head[0x90 + 4 * i:0x94 + 4 * i], "big") for i in range(18)):
        return "dol"
    raise ValueError(f"{source} is not a GameCube disc, a DOL, an NSO or an ELF")


def _extract(source: Path, kind: str, orig: Path) -> tuple[str, dict[str, Any]]:
    """Copy or extract the original under orig/; returns (original path relative to the repo, facts)."""
    if kind == "disc":
        disc = Disc(source)
        facts = disc.extract(orig)
        unpacked = 0
        for path in sorted(orig.glob("files/**/*")):
            if not path.is_file():
                continue
            head = path.open("rb").read(4)
            if head == b"Yaz0" and path.suffix.lower() == ".rel":
                path.write_bytes(archive.yaz0(path.read_bytes()))
                unpacked += 1
            elif path.suffix.lower() == ".arc" and head in (b"Yaz0", b"RARC"):
                unpacked += len(archive.unpack(path, path.with_suffix("")))
        facts["unpacked"] = unpacked
        return "sys/main.dol", facts
    name = "sys/main.dol" if kind == "dol" else source.name
    (orig / name).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, orig / name)
    return name, {"files": 1}


def _game_id(source: Path, kind: str, given: str | None) -> str:
    if given:
        return given
    if kind == "disc":
        return Disc(source).game_id
    return re.sub(r"[^A-Za-z0-9_]+", "_", source.stem).strip("_") or "main"


def new(source: Path, folder: Path, game_id: str | None = None, name: str | None = None) -> dict[str, Any]:
    source, folder = source.resolve(), folder.resolve()
    kind = kind_of(source)
    game = _game_id(source, kind, game_id)
    if (folder / "config" / game).exists():
        raise ValueError(f"{folder} already has config/{game}: this command starts a new project")
    folder.mkdir(parents=True, exist_ok=True)
    if not (folder / ".git").exists():
        subprocess.run(["git", "init", "-q", str(folder)], check=True)
    gitignore = folder / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(GITIGNORE, encoding="utf-8")
    original, facts = _extract(source, kind, folder / "orig" / game)
    platform = "switch" if kind in ("nso", "elf") else "gamecube"
    config = f"config/{game}"
    target: dict[str, Any] = {"repository": "decomp", "platform": platform, "module": "main",
                              "original": f"orig/{game}/{original}", "symbols": f"{config}/symbols.txt",
                              "splits": f"{config}/splits.txt", "objdiff": "objdiff.json",
                              "report": f"build/{game}/report.json"}
    identity = onboard._git_identity(folder)
    manifest = {"schema_version": 1, "id": name or onboard._slug(f"{folder.name}-{game}"), "generated_by": "zkit new",
                "repositories": {"decomp": {
                    "root": str(folder), "role": "decomp", "index_paths": ["README.md", "docs", "include", "src"],
                    "finish": ["zkit progress --since session --check", "zkit hygiene"], "rules": [],
                    "quality": {"gate": "error"}, "hygiene": {"identity": identity}}},
                "targets": {game.lower(): target}}
    path = onboard.projects_dir() / f"{manifest['id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"manifest": str(path), "folder": str(folder), "kind": kind, "game": game, "extracted": facts,
            **populate(path, game.lower())}


def populate(manifest: Path, target: str) -> dict[str, Any]:
    """Functions, symbols, units, class headers and target objects for a project's target."""
    from . import analyze, delink, units
    from .program import Program
    from .project import Project
    project = Project.load(manifest)
    config = project.target(target)
    root = project.root(config["repository"])
    program = Program.from_project(project, target)
    symbols = root / config["symbols"]
    write_symbols(program, symbols)
    proposal = units.propose(program)
    units.write_splits(proposal, root / config["splits"])
    out: dict[str, Any] = {"functions": len(program.functions), "data_objects": len(program.objects),
                           "units": proposal["counts"]["units"]}
    if program.platform.name == "gamecube":
        written = analyze.write(program, analyze.analyze(program), symbols, root / "build" / target / "analysis")
        out["class_headers"] = written["class_headers"]
    result = delink.delink(project, target, root / config["splits"], root / "build" / target / "obj",
                           objdiff=root / config.get("objdiff", "objdiff.json"),
                           compiled=root / "build" / target / "src")
    out["objects"] = len(result["units"])
    out["unassigned_references"] = result["unassigned"]
    return out


def write_symbols(program, path: Path) -> Path:
    """A symbols.txt of what the program knows: functions with sizes, data objects, section by section."""
    lines = []
    for function in program.functions:
        section = program.section_of(function.address) or "text"
        section = section if section.startswith(".") else f".{section}"
        lines.append(f"{function.name} = {section}:0x{function.address:08X}; // type:function "
                     f"size:0x{function.size:X} scope:{function.scope}")
    for item in program.objects:
        lines.append(f"{item.name} = {item.section}:0x{item.address:08X}; // type:object size:0x{item.size:X} "
                     f"scope:{item.scope}" + (f" data:{item.data}" if item.data else ""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
