"""`zkit new`: a decomp repository from the original alone, with nothing set up by hand.

From a GameCube disc image (or a bare DOL) or a Switch module (NSO, or an ELF of one): the original is copied
into `orig/<id>/` (a disc is extracted, its Yaz0 files and RARC archives unpacked), never committed; the
project file is written with the original's SHA-1 and the platform's build settings, and registered; then zkit
finds the functions, proposes the units with their data, writes `config/<id>/symbols.txt` and `splits.txt`, a
header per recovered class, every unit's target object and the build files (`zkit build`), a README and zkit's
git hooks. What is left is the decomp itself.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import archive, build, onboard
from .disc import Disc
from .gc import GC_DISC_MAGIC

GITIGNORE = """# The original game and everything derived from it stay local
orig/
build/
objdiff.json
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
    (folder / "src").mkdir(exist_ok=True)  # where the decomp goes; the build watches it
    gitignore = folder / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(GITIGNORE, encoding="utf-8")
    original, facts = _extract(source, kind, folder / "orig" / game)
    platform = "switch" if kind in ("nso", "elf") else "gamecube"
    config = f"config/{game}"
    executable = folder / "orig" / game / original
    target: dict[str, Any] = {"repository": "decomp", "platform": platform, "module": "main",
                              "original": f"orig/{game}/{original}",
                              "sha1": hashlib.sha1(executable.read_bytes()).hexdigest(),
                              "symbols": f"{config}/symbols.txt", "splits": f"{config}/splits.txt",
                              "objdiff": "objdiff.json", "report": f"build/{game}/report.json",
                              "build": json.loads(json.dumps(build.DEFAULTS[platform]))}
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
    out = {"manifest": str(path), "folder": str(folder), "kind": kind, "game": game, "extracted": facts,
           **populate(path, game.lower())}
    readme = folder / "README.md"
    if not readme.exists():
        readme.write_text(README[platform].format(game=game, original=target["original"], config=config,
                                                  report=target["report"], name=source.name), encoding="utf-8")
        out["readme"] = str(readme)
    from .install import install
    from .project import Project
    out["hooks"] = install(Project.load(path), "git-hook", folder)
    return out


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
    paths = build.layout(target, config)
    if program.platform.name == "gamecube":
        written = analyze.write(program, analyze.analyze(program), symbols, root / paths.dir / "analysis")
        out["class_headers"] = written["class_headers"]
    # Written after the splits and symbols, so the build's delink step starts out current.
    result = delink.delink(project, target, root / config["splits"], root / paths.obj)
    out["objects"] = len(result["units"])
    out["unassigned_references"] = result["unassigned"]
    configured = build.configure(project, config["repository"], target)
    out["build"] = {"ninja": configured["ninja"], "notes": configured["targets"][target]["notes"]}
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


_WORK = """
## Work

- `{config}/splits.txt` lists the units (each one source file of the original) and their address ranges;
  `{config}/symbols.txt` names the functions and data.
- To decompile unit `a/b.cpp`, write `src/a/b.cpp`. `zkit build` compiles it and the report shows how much of it
  matches; `zkit try <function> <file>` compiles a candidate with the unit's own command without touching `src/`.
- `zkit progress` sums the report, `zkit unit <unit>` shows a unit, `zkit doctor` checks the setup. objdiff opens
  `objdiff.json` (written by the build) to diff a unit function by function.
- `orig/` and `build/` stay out of git: never commit the original or anything built from it.
"""
README = {
    "gamecube": """# {game}

A matching decompilation of the GameCube game {game}, started from `{name}` with `zkit new`. The original
executable is `{original}` (not in git; the project file pins its SHA-1).

## Build

    zkit build

writes every unit's target object (cut from the original), compiles every unit that has a source in `src/` with
CodeWarrior, writes `{report}` (with objdiff-cli) and relinks the executable to check it against the original
(when this zkit has `zkit link`). It needs ninja; `zkit build --download` fetches the rest into `build/` (the
CodeWarrior compilers, wibo, objdiff-cli, binutils, m2c and decomp-permuter), each checked against its pinned hash.
The compiler version and flags are the `build` settings of the project file (`zkit projects` shows where it is):
set them to what the game was built with, per unit where they differ.
""" + _WORK,
    "switch": """# {game}

A matching decompilation of the Switch module {game}, started from `{name}` with `zkit new`. The original module
is `{original}` (not in git; the project file pins its SHA-1).

## Build

    zkit build

writes every unit's target object (cut from the original), compiles every unit that has a source in `src/` with
clang and writes `{report}` (with objdiff-cli). It needs ninja; `zkit build --download` fetches objdiff-cli and
LLVM's disassembler and demangler into `build/`, each checked against its pinned hash. The clang to use and its
flags are the `build` settings of the project file (`zkit projects` shows where it is): set them to the toolchain
the game was built with, per unit where they differ, and pin its archive in `build.compiler_download` so
`zkit build --download` fetches it too.
""" + _WORK,
}
