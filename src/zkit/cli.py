from __future__ import annotations

import argparse
import json
import os
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

from . import render

from .paths import config_home

CONFIG = config_home() / "project"
NO_PROJECT = ("No zkit project for this folder. Run `zkit init <path to your decomp repo>` once, "
              "then run commands inside that repo (or pass --project).")


def default_manifest() -> Path | None:
    if CONFIG.is_file():
        path = Path(CONFIG.read_text(encoding="utf-8").strip())
        return path if path.is_file() else None
    return None


def find_manifest(explicit: Path | None, strict: bool = False) -> Path | None:
    """--project, $ZKIT_PROJECT, zkit.project.json above cwd, a registered project containing cwd, then the
    default project (`zkit use`), then the only registered project. strict: only a project that contains
    cwd (or an explicit one); None when there is none."""
    from .onboard import project_for, registered
    if explicit:
        return explicit
    if os.environ.get("ZKIT_PROJECT"):
        return Path(os.environ["ZKIT_PROJECT"])
    cwd = Path.cwd()
    for directory in [cwd, *cwd.parents]:
        candidate = directory / "zkit.project.json"
        if candidate.is_file():
            return candidate
    known = registered()
    default = default_manifest()
    found = project_for(cwd, known + ([default] if default and default not in known else []))
    if found or strict:
        return found
    if default:
        return default
    if len(known) == 1:
        return known[0]
    raise ValueError(NO_PROJECT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zkit", description="Cross-repo evidence for decomp + native-port work")
    from . import __version__
    parser.add_argument("--version", action="version", version=f"zkit {__version__}")
    parser.add_argument("--project", type=Path, help="Project file (default: the project whose repo you are in)")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    parser.add_argument("--target", help="Target name when the manifest has several")
    sub = parser.add_subparsers(dest="command", required=True)
    # --json is also accepted after the subcommand (SUPPRESS keeps the top-level value when absent).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Machine-readable output")
    add = lambda name, **kw: sub.add_parser(name, parents=[common], **kw)

    c = add("init", help="Set up a decomp repository (writes and registers its project file, builds the index)")
    c.add_argument("decomp", type=Path, nargs="?", default=Path("."), help="decomp repo folder (default: here)")
    c.add_argument("--version", help="game version folder under config/ (default: the repo's default)")
    c.add_argument("--native", type=Path, help="optional native port / reimplementation repo to join")
    c.add_argument("--name", help="project id (default: <folder>-<version>)")
    c.add_argument("--dry-run", action="store_true", help="print the project file without writing it")
    c = add("new", help="Start a decomp from the original alone: a GameCube disc image or DOL, or a Switch NSO/ELF "
                        "(extracts it locally, registers the project, finds functions and units, writes symbols, "
                        "splits, class headers and every unit's target object)")
    c.add_argument("source", type=Path, help="disc image (.iso/.gcm), DOL, NSO or ELF")
    c.add_argument("folder", type=Path, help="the new repository folder")
    c.add_argument("--id", help="game id (default: the disc's, or the file name)")
    c.add_argument("--name", help="project id (default: <folder>-<id>)")
    add("projects", help="List registered projects and which one this folder uses")
    c = add("use", help="Register a hand-written manifest and make it the default project")
    c.add_argument("manifest", type=Path)
    c = add("setup", help="Full install: init (or a project file), index, and connect Claude Code and/or Codex")
    c.add_argument("decomp", type=Path, nargs="?", default=Path("."),
                   help="decomp repo folder (default: here), or your own project .json file")
    c.add_argument("--version", help="game version folder under config/")
    c.add_argument("--native", type=Path, help="optional native port repo to join")
    c.add_argument("--name", help="project id")
    c.add_argument("--no-agents", action="store_true", help="only set up the decomp; don't touch Claude/Codex")
    c.add_argument("--refresh-agents", action="store_true", help="refresh installed agent plugins as well")
    c.add_argument("--plugin-source", help="plugin marketplace checkout or repository (default: upstream)")
    c.add_argument("--dry-run", action="store_true", help="show what would change without changing it")
    c = add("brief", help="Start-of-session packet: rules, activity, handoffs, next action, port demand")
    c.add_argument("repo", nargs="?")
    c.add_argument("--full", action="store_true", help="show full packets for all repositories")
    c = add("lookup", help="Everything about original functions: status, TU, callers, callees, slots, cites")
    c.add_argument("query", nargs="+", help="address(es), mangled or demangled name, or Class::method fragment")
    c.add_argument("--body", action="store_true", help="include the decomp source of the definition")
    c = add("names", help="Live names, one line each: by address/symbol, --regex, --unit or --range")
    c.add_argument("query", nargs="*")
    c.add_argument("--regex")
    c.add_argument("--unit")
    c.add_argument("--range", help="START-END addresses, e.g. 8013D000-8013F000")
    c.add_argument("--provisional", action="store_true", help="only provisional names")
    c.add_argument("--signatures", action="store_true", help="names the signature cache proves for this target "
                                                             "(new ones, and ones that differ from the current)")
    c.add_argument("--below", type=float, metavar="PERCENT", help="only functions matched below this %% (100 = not exact)")
    c.add_argument("--sort", choices=["address", "match", "size"], default="address",
                   help="match: closest near-misses first; size: largest first")
    c.add_argument("--limit", type=int, default=200)
    c = add("xrefs", help="Code that reads/writes/takes the address of a global or table, and pointers to it")
    c.add_argument("query", nargs="+", help="address(es) or symbol name(s)")
    c.add_argument("--size", type=lambda v: int(v, 0))
    c = add("unit", help="A split unit: section ranges, functions, data, cross-unit references, neighbours; "
                         "--blocked: every exact unit that is not linked, with what references cross its boundary")
    c.add_argument("query", nargs="*", help="unit path from splits.txt, an address, or a function in it")
    c.add_argument("--blocked", action="store_true")
    c.add_argument("--gaps", action="store_true", help="per-section split coverage and every unclaimed range")
    c.add_argument("--section", help="with --gaps: only this section, e.g. .sdata2")
    c.add_argument("--limit", type=int, default=40)
    c = add("classes", help="Classes recovered from the original's code (tables, constructors, destructors, bases) "
                            "against the current names: mislabelled tables, unnamed classes, misfiled and role-named "
                            "functions, one name per virtual slot")
    c.add_argument("--class", dest="cls", help="only this class")
    c.add_argument("--limit", type=int, default=60)
    c.add_argument("--headers", type=Path, metavar="DIR", help="write one header per recovered class into DIR")
    c.add_argument("--types-include", default="types.h", help="with --headers: the header defining u8..f64")
    c.add_argument("--prove", action="store_true", help="compile the recovered declarations with the project's "
                                                        "compiler and compare tables, pointer offsets and sizes")
    c = add("renamed", help="Decomp symbols renamed since a git revision (old -> new)")
    c.add_argument("since")
    c = add("port-plan", help="Original call tree joined with native coverage: reuse / port / decompile-first")
    c.add_argument("query", nargs="+")
    c.add_argument("--depth", type=int, default=2)
    c = add("demand", help="Decomp functions the port cites that are unmatched or provisionally named")
    c.add_argument("--limit", type=int, default=40)
    c.add_argument("--offset", type=int, default=0)
    c.add_argument("--match-only", action="store_true", help="Only rows that still need a byte match")
    c.add_argument("--need", choices=["match", "name", "link"], help="Only rows needing this")
    c.add_argument("--format", choices=["text", "addrs"], default="text", help="addrs: one address per line")
    c = add("asm", help="Disassemble original bytes with symbol/SDA/lis resolution")
    c.add_argument("query", nargs="+")
    c.add_argument("--size", type=lambda v: int(v, 0))
    c.add_argument("--lines", type=int, default=400, help="at most this many instructions per function")
    c.add_argument("--words", action="store_true", help="also print each instruction's word")
    c = add("decompile", help="Ghidra C for original functions, a second reading next to m2c (cached)")
    c.add_argument("query", nargs="*", help="address(es) or name(s)")
    c.add_argument("--all", action="store_true", help="fill the cache for every DOL function (~40 s for 27k)")
    c.add_argument("--threads", type=int)
    c = add("data", help="Typed reads of original data (f32, u32, ptr, str, tables) by address or symbol")
    c.add_argument("address", nargs="+", help="address(es) or symbol name(s) (lbl_*, jumptable_*, __vt__*)")
    c.add_argument("--type", help="u8 s8 u16 s16 u32 s32 u64 s64 f32 f64 ptr str (also string, hex, bytes, float, "
                                  "double, int, pointer); default u32, ptr where a 64-bit module relocates the words")
    c.add_argument("--count", type=int, help="elements, records or strings (default: the symbol's extent, else 16)")
    c.add_argument("--size", type=lambda v: int(v, 0), help="bytes to cover instead of --count")
    c.add_argument("--fields", help="Record layout, e.g. u32,f32,ptr,pad4")
    c.add_argument("--stride", type=lambda v: int(v, 0))
    c = add("compiled", help="A function (or a whole unit) compiled vs the original object: identical, or the "
                             "differing words with both disassemblies")
    c.add_argument("query", help="address, name, or a unit name from objdiff.json")
    c.add_argument("--limit", type=int, default=24)
    c = add("try", help="Compile a candidate (outside the tree) with its unit's exact command and compare the "
                        "function with the original; records the attempt (cap 4 per address)")
    c.add_argument("query", help="the function's address or name")
    c.add_argument("candidate", type=Path, help="source file: the function and the includes it needs, or a unit copy")
    c.add_argument("--force", action="store_true", help="past the attempt cap (say why in your notes)")
    c.add_argument("--keep", type=Path, help="also copy the compiled object here")
    c.add_argument("--unit", action="store_true", help="the candidate is the whole unit (query: the unit or an "
                   "address in it): every function compared and, on Switch, the object linked into the original; "
                   "lists what became identical or was lost against the tree's build; records no attempts")
    c.add_argument("--include", type=Path, action="append", default=[], metavar="DIR",
                   help="header copies searched before the tree's (repeatable); DIR mirrors the include paths, "
                        "e.g. DIR/classes/x.h stands in for include/classes/x.h")
    c = add("probe", help="Compile any file with a unit's exact command and print the code it makes (+offset, "
                          "relocations folded in): compiler experiments without hand-copied flags; compares nothing, "
                          "records no attempts")
    c.add_argument("query", help="the unit whose command compiles it: its name, or an address in it")
    c.add_argument("source", type=Path, help="the file to compile")
    c.add_argument("names", nargs="*", help="functions to show (a name or part of one); default all")
    c.add_argument("--include", type=Path, action="append", default=[], metavar="DIR",
                   help="header copies searched before the tree's (repeatable)")
    c = add("sweep", help="Near-misses (Switch and GameCube): rewrite one function's source site by site (operand order, compound "
                          "assignment, ++ form, if/else, counter type, loop direction, statement order), compile "
                          "each with its unit's command and climb to the closest; writes the best text, records "
                          "no attempts")
    c.add_argument("query", help="the function's address or name")
    c.add_argument("candidate", type=Path, help="source file holding the function (a unit copy or a try file)")
    c.add_argument("--out", type=Path, help="where to write the best text (default build/sweep/<address>.cpp)")
    c.add_argument("--jobs", type=int, help="compiles at once (default: half the CPUs)")
    c.add_argument("--rounds", type=int, default=12, help="most rewrites taken one after another")
    c.add_argument("--seconds", type=float, default=600.0)
    c = add("objects", help="Prove a change kept the code: --save copies every built object, --compare (after the "
                            "build) checks each against its copy modulo intended renames")
    c.add_argument("--save", action="store_true")
    c.add_argument("--compare", action="store_true")
    c.add_argument("--label", default="saved")
    c.add_argument("--rename", action="append", default=[], metavar="OLD=NEW", help="an intended symbol rename")
    c.add_argument("--rename-json", type=Path, help="a JSON {old: new} map of intended renames")
    c = add("score", help="Score a split (splits.txt + symbols.txt folder) against a reference: another split, or "
                          "a CodeWarrior linker map; an objdiff report marks the reference's proven units")
    c.add_argument("proposal", type=Path, help="folder with splits.txt and symbols.txt")
    c.add_argument("reference", type=Path, help="reference folder, or a .MAP linker map")
    c.add_argument("--report", type=Path, help="objdiff report.json of the reference (its complete units are proven)")
    c.add_argument("--module", help="with --report: only this module's units")
    c = add("rel", help="REL modules: `info FILE` (header, sections, relocations per module), or `make PLF... --dol "
                        "ELF --out DIR` (each partially linked module as a REL, as makerel does)")
    c.add_argument("action", choices=("info", "make"))
    c.add_argument("files", type=Path, nargs="+", help="info: the REL; make: the modules' partially linked ELFs")
    c.add_argument("--dol", type=Path, help="make: the linked DOL's ELF the modules call into")
    c.add_argument("--out", type=Path, help="make: folder for the RELs")
    c.add_argument("--like", type=Path, action="append", default=[],
                   help="make: original RELs (files or folders) whose header facts and module ids to keep")
    c.add_argument("--rel-version", type=int, default=3, help="make: REL version without --like (default 3)")
    c = add("analyze", help="A fresh analysis of the original into a folder: splits.txt (units with their data), "
                            "symbols.txt (recovered tables and destructors named), a header per class, analysis.json")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--types-include", default="types.h")
    c = add("discover", help="Functions, sections, small-data bases and data objects found in the original alone "
                             "(no symbols file needed), written as a symbols.txt")
    c.add_argument("--out", type=Path, required=True, help="the symbols.txt to write")
    c = add("signatures", help="Names from other builds: build a donor's function signatures into zkit's cache "
                               "(an original named by its symbols.txt or a CodeWarrior .MAP, compiled objects or "
                               "libraries, or this project), list or remove them, or match this target against them")
    c.add_argument("action", choices=["build", "list", "remove", "match"])
    c.add_argument("name", nargs="?", help="the donor (build, remove)")
    c.add_argument("--image", type=Path, help="build: an original executable (.dol or disc image, "
                                              "or a Switch NSO or ELF)")
    c.add_argument("--symbols", type=Path, help="build: its symbols.txt")
    c.add_argument("--splits", type=Path, help="build: its splits.txt (places file-local names, and "
                                               "gives `zkit analyze` its units)")
    c.add_argument("--map", type=Path, help="build: its CodeWarrior linker map instead of a symbols.txt")
    c.add_argument("--objects", type=Path, action="append", default=[], help="build: objects, libraries or "
                                                                              "folders of them (repeatable)")
    c.add_argument("--complete", action="store_true", help="build from this project: only the compiled objects "
                                                           "of the units its report marks complete")
    c.add_argument("--donor", action="append", default=[], help="match: only this donor (repeatable)")
    c.add_argument("--all", action="store_true", help="match: also list names the target already has")
    c.add_argument("--seeded", action="store_true", help="match: start from the target's own names (a decomp's "
                   "matched names name what they call, read and hold) and list the names evidence contradicts")
    c.add_argument("--limit", type=int, default=60)
    c = add("units", help="Translation units from evidence in the original (source paths its code cites, literal "
                          "copies, data one run of code uses, classes): a fresh proposal, or --check the current splits")
    c.add_argument("--check", action="store_true", help="folds, splits and data claims for the existing splits.txt")
    c.add_argument("--splits", type=Path, help="write the fresh proposal as a splits.txt")
    c.add_argument("--map", type=Path, nargs="?", const=Path(), metavar="FILE",
                   help="take units, names and sizes from a CodeWarrior linker map of another build of the same "
                        "code wherever it lines up (no FILE: the maps that came with the original's disc)")
    c.add_argument("--write", action="store_true", help="with --map: rewrite the target's splits.txt and symbols.txt")
    c.add_argument("--limit", type=int, default=30)
    c = add("delink", help="Split the original into one relocatable object per unit of a splits.txt (GameCube and "
                           "Switch): the target objects objdiff compares the compiled ones with")
    c.add_argument("--splits", type=Path, help="default: the target's splits file")
    c.add_argument("--unit", action="append", default=[], help="only this unit (repeatable)")
    c.add_argument("--out", type=Path, required=True, help="folder for the objects (unit a/b.cpp: OUT/a/b.o)")
    c.add_argument("--objdiff", type=Path, help="also write objdiff's project file here")
    c.add_argument("--compiled", type=Path, help="where the build writes each unit's object (for --objdiff)")
    c = add("apply", help="Names from the build back into the symbols file: compiled symbols whose name differs from "
                          "the target object's at the same place (renames made in the source)")
    c.add_argument("--write", action="store_true", help="rewrite the symbols file (default: list the renames)")
    c.add_argument("--limit", type=int, default=40)
    c = add("link", help="Link the original back together from delinked and compiled objects and check it against "
                         "the original: with the project's CodeWarrior linker (GameCube DOL), or by placing every "
                         "compiled section where the original holds it (Switch NSO, segment hashes); the units it "
                         "proves are marked linked in the report")
    c.add_argument("--out", type=Path, required=True, help="folder for the objects, script, ELF and DOL, or the NSO")
    c.add_argument("--compiled", choices=("none", "units", "functions"), default="functions",
                   help="none: every unit delinked; units: compiled objects of complete units; functions (default): "
                        "also every exact function of the other units")
    c.add_argument("--splits", type=Path, help="default: the target's splits file")
    c.add_argument("--build", type=Path, help="the build.ninja holding the link command (default: the repository's)")
    c.add_argument("--no-mark", action="store_true", help="Switch: leave the report as objdiff wrote it")
    c = add("asmfile", help="An assembly file of original functions for a decompiler (m2c): references as symbols, "
                            "labels, and the data they read (GameCube)")
    c.add_argument("addresses", nargs="+", help="addresses or names of functions")
    c.add_argument("--out", type=Path, help="write here instead of printing")
    c = add("m2c", help="m2c's C for original functions: the seed to match from (GameCube). Where m2c fails or "
                        "emits goto, Ghidra's reading of the same bytes follows when Ghidra is set up")
    c.add_argument("addresses", nargs="+", help="addresses or names of functions")
    c.add_argument("--language", choices=("c", "c++"), help="default: c++ for a mangled name, else c")
    c.add_argument("--context", type=Path, help="C context file with the types and declarations m2c should use")
    c.add_argument("--no-ghidra", action="store_true", help="m2c only, never Ghidra's reading")
    c = add("permute", help="Set up a decomp-permuter scratch for a near-miss whose gap is register allocation or "
                            "scheduling: the unit's exact compile command, its target object, the function's "
                            "disassembly for scoring (GameCube)")
    c.add_argument("query", help="the function's address or name")
    c.add_argument("--seed", type=Path, help="the best candidate so far (default: the unit's source)")
    c.add_argument("--out", type=Path, help="scratch folder (default: build/permuter/<function> in the decomp)")
    c.add_argument("--run", action="store_true", help="run the permuter (stops at the first zero score) and verify "
                                                      "every zero-score output against the target object")
    c.add_argument("--time", type=int, default=180, help="seconds the permuter may run with --run (default 180)")
    c.add_argument("--jobs", "-j", type=int, help="permuter processes with --run (default: min(16, CPUs-2))")
    c = add("configure", help="Write build/build.ninja, objdiff.json and build/compile_commands.json from the project "
                              "file's build settings (zkit build runs it)")
    c.add_argument("--download", action="store_true", help="fetch what is missing: the CodeWarrior bundle and the "
                                                           "pinned tools (wibo, objdiff-cli, binutils, m2c, "
                                                           "decomp-permuter; Switch: LLVM, the project's clang), "
                                                           "each checked against its SHA-256 or commit")
    c = add("build", help="Build the project: target objects from the original, every unit with a source in src/, "
                          "the objdiff report, and the relinked executable checked against the original (GameCube: "
                          "the DOL's SHA-1; Switch: the NSO's segment SHA-256s, marking the units it proves linked)")
    c.add_argument("targets", nargs="*", help="ninja targets (default: everything; also objects, compile, report, "
                                              "link, or one object)")
    c.add_argument("-j", "--jobs", type=int)
    c.add_argument("-k", "--keep-going", type=int, metavar="N", help="keep going until N jobs fail (0: never stop)")
    c.add_argument("--download", action="store_true", help="fetch what is missing: the CodeWarrior bundle and the "
                                                           "pinned tools (wibo, objdiff-cli, binutils, m2c, "
                                                           "decomp-permuter; Switch: LLVM, the project's clang), "
                                                           "each checked against its SHA-256 or commit")
    c = add("refs", help="Where a function or global is defined, declared and used in the source (any spelling)")
    c.add_argument("query", nargs="+")
    c.add_argument("--repo")
    c.add_argument("--limit", type=int, default=60)
    c = add("search", help="Ranked full-text search over every configured repo")
    c.add_argument("words", nargs="+")
    c.add_argument("--repo")
    c.add_argument("--path", help="Substring filter on the file path")
    c.add_argument("--limit", type=int, default=12)
    c = add("read", help="Read repo:path[:line] (centred on line when given)")
    c.add_argument("reference")
    c.add_argument("--start", type=int, default=1)
    c.add_argument("--lines", type=int, default=120)
    c.add_argument("--end", type=int, help="last line to show (inclusive), instead of --lines")
    c = add("check", help="Lint the working-tree diff against the repo's contract rules")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*")
    c.add_argument("--base", default="HEAD")
    c.add_argument("--staged", action="store_true", help="judge the staged change (index content), as a pre-commit hook")
    c = add("impact", help="Native: consumers of changed files and the exact tests to run")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*")
    c.add_argument("--base", default="HEAD")
    c.add_argument("--budget", type=float, metavar="SECONDS",
                   help="keep all direct tests; add near tests cheapest first within this recorded time; list the rest")
    c = add("architecture", help="Check project-defined include boundaries (native-port architecture)")
    c.add_argument("repo")
    c.add_argument("paths", nargs="*")
    c.add_argument("--base", default="HEAD")
    c.add_argument("--all", action="store_true", dest="all_files", help="scan all configured architecture roots")
    c = add("coverage", help="Compare declared inventories across import/integration stages")
    c.add_argument("repo")
    c.add_argument("name", help="project-owned coverage inventory name")
    c = add("stale", help="Native: built programs older than a source or header compiled into them (rebuild first)")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*", metavar="program",
                   help="program names (default: the manifest's tests.apps, else every linked one)")
    c = add("test-plan", help="Exact CTest names, fixture costs and optional consolidated parallel prebuilds")
    c.add_argument("repo")
    c.add_argument("names", nargs="+")
    c.add_argument("--jobs", type=int, default=2, help="parallel jobs for suggested prebuilds (nothing is executed)")
    c = add("grounding", aliases=["suspects"],
            help="Native: how much cited original behavior is a ready reference in the decomp, and the units most "
                 "likely to behave slightly off, with the next action")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*", help="folders/files (default: code_paths)")
    c.add_argument("--limit", type=int, default=25)
    c = add("tiers", help="Native: which fidelity tier (exact/equivalent/liberty/infrastructure) each path is in")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*")
    c = add("consts", help="Native: float literals vs the constants the cited originals load")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*")
    c = add("drift", help="Decomp changes under cited functions since the accepted baseline (what to re-verify)")
    c.add_argument("repo", nargs="?", help=argparse.SUPPRESS)  # agents write `drift native`; drift spans every repo
    c.add_argument("--accept", action="store_true", help="accept the current state as the new baseline")
    c.add_argument("--since", type=Path, help="compare with an old decomp report.json instead of the baseline")
    c = add("reuse", help="Duplicate helpers and central per-variant dispatch sites")
    c.add_argument("repo", nargs="?")
    c.add_argument("--variants", help="Manifest variant group, e.g. enemy-families")
    c.add_argument("--terms", help="Comma-separated sibling names")
    c.add_argument("--min-files", type=int, default=3)
    c = add("activity", help="Other sessions, builds, locks, dirty files, worktrees, handoffs")
    c.add_argument("repo", nargs="?", help=argparse.SUPPRESS)  # `activity decomp`: activity always covers every repo
    c = add("wait", help="Block until no build runs and no build lock is held in a checkout (instead of pgrep/sleep)")
    c.add_argument("repo", nargs="?", help="repo or worktree path (default: the checkout you are in)")
    c.add_argument("--timeout", type=float, default=600, help="seconds before giving up (exit 1)")
    c.add_argument("--settle", type=float, default=3, help="seconds that must stay quiet (bridges chained commands)")
    c = add("handoff", help="Leave a note for the next session (repo state captured automatically); without text, "
                            "print the latest notes in full")
    c.add_argument("repo")
    c.add_argument("text", nargs="*")
    c.add_argument("--list", type=int, default=1, metavar="N", help="without text: how many notes to print")
    c = add("lessons", help="Curated gotchas/rules; give one or more ids to print them")
    c.add_argument("id", nargs="*")
    c.add_argument("--role")
    c = add("gate", help="Canonical finish gate and where repo copies disagree")
    c.add_argument("repo", nargs="?")
    c = add("progress", help="objdiff progress (code/data matched and linked, functions, categories, modules); "
                             "--since compares with a saved baseline by original address")
    c.add_argument("--since", nargs="?", const="latest",
                   help="baseline to compare with: latest (default), session, a saved name or label, or a report file")
    c.add_argument("--save", action="store_true", help="save the current report as a baseline")
    c.add_argument("--list", action="store_true", help="list saved baselines")
    c.add_argument("--check", action="store_true", help="with --since: exit 1 on any lost match, link or data")
    c = add("report", help="Write a browsable offline HTML page from the objdiff reports (the build writes it too), "
                           "and with --readme the progress table in the README")
    c.add_argument("--out", type=Path, help="folder for index.html (default: build/progress in the repository)")
    c.add_argument("--title", help="page title (default: the project's title or id)")
    c.add_argument("--targets", nargs="*", help="targets to include (default: every target with a report)")
    c.add_argument("--readme", nargs="?", type=Path, const=Path("README.md"),
                   help="also rewrite the progress table between <!-- progress --> and <!-- /progress --> in this "
                        "file (default: the repository's README.md)")
    c = add("quality", help="Decompiler debt left in the source (hand-mangled names, raw offsets, fake vtables, "
                            "temporaries, placeholder names), at the working tree or a revision")
    c.add_argument("repo", nargs="?")
    c.add_argument("paths", nargs="*")
    c.add_argument("--at", help="measure this git revision instead of the working tree")
    c.add_argument("--since", help="compare this git revision with the working tree (or with --at)")
    c.add_argument("--files", type=int, default=15, help="how many of the worst files to list")
    c = add("hygiene", help="What must not be committed or left behind: AI-only docs, session logs, unused scripts, "
                            "original files, commit message/identity rules, stray branches and worktrees")
    c.add_argument("repo", nargs="?")
    c.add_argument("--since", help="judge the commits in SINCE..HEAD (default: the last --limit commits)")
    c.add_argument("--limit", type=int, default=30)
    c.add_argument("--only", choices=["commits", "files", "tree"], action="append", help="run only these parts")
    c = add("contract", help="Print the toolkit's rules for a decomp or a port (no project needed)")
    c.add_argument("kind", choices=["decomp", "port"])
    c = add("commit-msg", help="Check a commit message file against the repo's commit rules (the commit-msg hook)")
    c.add_argument("file", type=Path)
    c = add("cites", help="Native citations that resolve to nothing in the target")
    c.add_argument("--limit", type=int, default=50)
    c.add_argument("--unresolved", action="store_true", help=argparse.SUPPRESS)  # what cites always lists
    add("index", help="Refresh the cross-repo index and print its stats")
    c = add("cache", help="The toolkit's cache files and their size; --prune deletes those no project uses")
    c.add_argument("--prune", action="store_true")
    c.add_argument("--dry-run", action="store_true")
    add("doctor", help="Self-check of the whole setup, with the exact fix for each problem")
    c = add("recipes", help="List fidelity recipes")
    c.add_argument("repository", nargs="?")
    c.add_argument("--query", default="")
    c.add_argument("--limit", type=int, default=20)
    c = add("check-recipe", aliases=["recipe-preflight"], help="Preflight one fidelity recipe (does not run it)")
    c.add_argument("reference")
    c.add_argument("--catalog")
    c = add("plan", help="Show a configured command's argv/cwd without running it")
    c.add_argument("name")
    c = add("snapshot")
    c.add_argument("--reference", action="append", default=[])
    c = add("check-snapshot")
    c.add_argument("path", type=Path)
    add("serve", help="Run the MCP server on stdio")
    c = add("hook", help="Client hook entry points")
    c.add_argument("event", choices=["session-start", "subagent-start"])
    c = add("install", help="Print (or write) client configuration for this project")
    c.add_argument("client", choices=["claude", "codex", "skills", "git-hook"])
    c.add_argument("--write", type=Path, metavar="REPO", help="Write into this repository instead of printing")
    return parser


def _ready(project, notes: list[str], said: str, plugins_next: bool = True) -> str:
    """Build the index once and say what works."""
    from .index import refresh
    from .inspect_dol import _objdump
    stats = refresh(project)
    lines = [said, *(f"note: {n}" for n in notes)]
    tool = _objdump(project)
    lines.append(f"disassembler: {tool}" if tool else
                 "disassembler: none (no PowerPC objdump found: asm shows raw words)")
    from .index import connect
    db = connect(project)
    counts = {t: db.execute("SELECT count(*), sum(address >= 4294967296) FROM functions WHERE target=?", (t,)).fetchone()
              for t in project.config.get("targets", {})}
    for target, (total, rel) in counts.items():
        lines.append(f"{target}: {total or 0} functions indexed" + (f" ({rel} in REL modules)" if rel else ""))
    lines.append(f"index: {stats['files_reindexed']} files in {stats['seconds']} s")
    lines.append("next: `zkit setup` connects Claude Code / Codex (or see the README)" if plugins_next else
                 "next: start your agent in this folder; `zkit doctor` checks everything")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> tuple[object, str]:
    from .project import Project

    made = None
    if args.command == "setup" and not args.native:   # a project `zkit new` made: init cannot read it back
        from .onboard import project_for, registered
        found = project_for(args.decomp, registered()) if args.decomp.is_dir() else None
        made = found if found and Project.load(found).config.get("generated_by") == "zkit new" else None
    if args.command == "setup" and args.decomp.suffix == ".json" and args.decomp.is_file():
        args = argparse.Namespace(**{**vars(args), "manifest": args.decomp})  # 0.3: `setup <manifest>`
    elif made is not None:
        args = argparse.Namespace(**{**vars(args), "manifest": made})
    elif args.command == "setup":
        from .onboard import compact_sessions, connect_agents
        made_init, said = run(argparse.Namespace(**{**vars(args), "command": "init", "from_setup": True}))
        steps = []
        if not args.no_agents:
            steps = connect_agents(args.dry_run, args.refresh_agents, args.plugin_source)
            if not args.dry_run and made_init.get("manifest"):
                steps += compact_sessions(Project.load(made_init["manifest"]))
            said += "\n" + "\n".join(steps)
        return {"ok": not any(s.startswith("FAILED:") for s in steps)}, said
    if args.command == "new":
        from .new import new
        result = new(args.source, args.folder, args.id, args.name)
        if not default_manifest():
            CONFIG.parent.mkdir(parents=True, exist_ok=True)
            CONFIG.write_text(result["manifest"] + "\n", encoding="utf-8")
        return result, (f"new {result['kind']} project {result['game']} in {result['folder']}: "
                        f"{result['functions']:,} functions, {result['units']:,} units, {result['objects']:,} target "
                        f"objects" + (f", {result['class_headers']:,} class headers" if "class_headers" in result else "")
                        + (f"; from {result['map']['path']}: {result['map']['units_lined_up']:,} objects line up, "
                           f"{result['map']['units_bounded']:,} more bounded, {result['map']['functions_named']:,} "
                           f"functions named" if "map" in result else "")
                        + (f"; {result['unassigned_references']:,} referenced addresses are in no unit yet"
                           if result["unassigned_references"] else "") + f"\nproject file: {result['manifest']}"
                        + "".join(f"\nnote: {note}" for note in result["build"]["notes"])
                        + f"\nnext: cd {result['folder']} && zkit build --download")
    if args.command == "init":
        from .onboard import init
        result = init(args.decomp, args.version, args.native, args.name, write=not args.dry_run)
        if args.dry_run:
            return result, json.dumps(result["project"], indent=2) + "\n" + "\n".join(f"note: {n}" for n in result["notes"])
        if not default_manifest():
            CONFIG.parent.mkdir(parents=True, exist_ok=True)
            CONFIG.write_text(result["manifest"] + "\n", encoding="utf-8")
        return result, _ready(Project.load(result["manifest"]), result["notes"], "wrote " + result["manifest"],
                              plugins_next=not getattr(args, "from_setup", False))
    if args.command in ("use", "setup"):
        from .onboard import register
        path = Path(args.manifest).resolve(strict=True)
        Project.load(path)
        if args.command == "setup" and args.dry_run:
            from .onboard import connect_agents
            steps = [] if args.no_agents else connect_agents(True, args.refresh_agents, args.plugin_source)
            return {"manifest": str(path), "dry_run": True}, f"would register and index: {path}\n" + "\n".join(steps)
        register(path)
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(str(path) + "\n", encoding="utf-8")
        said = f"default project: {path}"
        steps = []
        if args.command == "setup":  # `setup my.project.json`: a hand-made project file, same full install
            from .onboard import connect_agents
            said = _ready(Project.load(path), [], said, plugins_next=False)
            if not getattr(args, "no_agents", False):
                from .onboard import compact_sessions
                steps = connect_agents(args.dry_run, args.refresh_agents, args.plugin_source)
                steps += compact_sessions(Project.load(path), args.dry_run)
                said += "\n" + "\n".join(steps)
        return {"default_project": str(path), "ok": not any(s.startswith("FAILED:") for s in steps)}, said
    if args.command == "projects":
        from .onboard import registered
        here = find_manifest(None, strict=True)
        rows = []
        for path in registered():
            try:
                config = Project.load(path).config
            except (OSError, ValueError) as error:
                rows.append({"manifest": str(path), "error": str(error)})
                continue
            rows.append({"id": config["id"], "manifest": str(path), "here": here == path, "default": default_manifest() == path,
                         "repositories": {n: r["root"] for n, r in config["repositories"].items()}})
        text = "\n".join(f"{'*' if r.get('here') else ' '} {r.get('id', '?'):<32} {r['manifest']}"
                         + (" (default)" if r.get("default") else "") for r in rows) or "no projects yet: zkit init <decomp repo>"
        return rows, text + ("\n* = the project for this folder" if any(r.get("here") for r in rows) else "")
    if args.command == "rel":
        from . import rel
        if args.action == "info":
            data = rel.info(rel.load(args.files[0]))
            return data, render.rel_info(data)
        if args.dol is None or args.out is None:
            raise ValueError("rel make needs --dol (the DOL's linked ELF) and --out (a folder)")
        rows = rel.make_all(args.dol, args.files, args.out.expanduser().resolve(), args.like, args.rel_version)
        return rows, "\n".join(f"{r['rel']}: module {r['id']}, {r['bytes']:,} bytes"
                                + (f", {'identical to' if r['identical'] else 'differs from'} {r['like']}"
                                   if "like" in r else "") for r in rows)
    if args.command == "score":
        from . import mwmap, score
        reference = mwmap.read(args.reference) if args.reference.is_file() else score.load(args.reference)
        proven = score.complete_units(args.report, args.module) if args.report else set()
        data = score.score(reference, score.load(args.proposal), proven)
        return data, render.score(data)
    if args.command == "signatures" and (args.action in ("list", "remove") or args.image or args.objects):
        from . import signatures
        return signatures.command(args)
    if args.command == "contract":
        from importlib import resources
        text = resources.files("zkit").joinpath(f"contracts/{args.kind}.md").read_text(encoding="utf-8")
        return {"kind": args.kind, "text": text}, text
    if args.command == "cache":
        from .index import cache_inventory, prune_cache
        if args.prune:
            data = prune_cache(args.dry_run)
            return data, (f"{'would remove' if args.dry_run else 'removed'} {len(data['removed'])} file(s), "
                          f"{data['bytes'] / 1e6:.0f} MB")
        data = cache_inventory()
        lines = [f"{data['cache']}: {data['bytes'] / 1e6:.0f} MB, {data['stale_bytes'] / 1e6:.0f} MB unused"]
        lines += [f"  {'in use' if e['live'] else 'unused'}  {e['bytes'] / 1e6:8.1f} MB  {e['age_days']:5.1f} d  {e['name']}"
                  for e in data["entries"]]
        return data, "\n".join(lines) + ("\n`zkit cache --prune` deletes the unused ones" if data["stale_bytes"] else "")
    if args.command == "hook":
        manifest = find_manifest(args.project, strict=True)
        if manifest is None:
            return None, ""  # not inside a configured repo: no brief, no noise
        project = Project.load(manifest)
    elif args.command == "serve":
        try:
            manifest = find_manifest(args.project)
        except ValueError:
            from .server import serve_unconfigured
            serve_unconfigured()
            return None, ""
        project = Project.load(manifest)
    else:
        project = Project.load(find_manifest(args.project))
    from . import bridge, inspect_dol, session
    from .activity import activity, write_handoff
    from .index import refresh, use_platform
    use_platform(project)

    target = bridge.default_target(project, args.target) if project.config.get("targets") else None
    command = "check-recipe" if args.command == "recipe-preflight" else args.command
    native_only = ("impact", "grounding", "suspects", "consts", "tiers", "stale")
    path_commands = ("check", "quality") + native_only
    here, worktree = project.locate(Path.cwd())
    if getattr(args, "repo", None):
        try:
            scoped, key = project.scope(args.repo)
            if key is not None:
                project, args.repo = scoped, key
        except ValueError:
            if command not in path_commands:
                raise
            args.paths, args.repo = [args.repo, *args.paths], None
    if getattr(args, "repo", "unset") is None and command in path_commands + ("reuse", "gate", "brief", "recipes", "wait", "hygiene"):
        if here is not None:
            args.repo = here
            project = project.with_overlay(here, worktree)  # a git worktree reads its own files
        elif command in native_only and len(bridge.role_repos(project, "native")) == 1:
            args.repo = bridge.role_repos(project, "native")[0]
        elif command not in ("brief",):
            raise ValueError(f"Run inside a configured repo (or a git worktree of one) or name one: "
                             f"{', '.join(project.config['repositories'])}")
    if command == "brief":
        data = session.brief(project, args.repo)
        return data, render.brief(data, compact=args.repo is None and not args.full)
    if command == "lookup":
        data = bridge.lookup(project, " ".join(args.query), target, body=args.body)
        return data, render.lookup(data)
    if command == "signatures" or command == "names" and args.signatures:
        from . import signatures
        if command == "names":
            args = argparse.Namespace(**{**vars(args), "action": "match", "donor": [], "all": False})
        return signatures.command(args, project, target)
    if command == "names":
        start = end = None
        if args.range:
            lo, _, hi = args.range.partition("-")
            start, end = int(lo, 16), int(hi or lo, 16) + (0 if hi else 1)
        data = bridge.names(project, args.query or None, target, args.regex, args.unit, start, end, args.limit,
                            True if args.provisional else None, args.below, args.sort)
        return data, render.names(data)
    if command == "xrefs":
        data = bridge.batch(bridge.query_list(" ".join(args.query)),
                            lambda q: bridge.xrefs(project, q, target, size=args.size))
        return data, render.xrefs(data)
    if command == "unit":
        from . import structure
        if args.gaps:
            data = structure.gaps(project, target, args.section, args.limit)
            return data, render.split_gaps(data)
        if args.blocked or not args.query:
            data = structure.blocked(project, target, args.limit)
            return data, render.blocked_units(data)
        data = bridge.batch(bridge.query_list(" ".join(args.query)),
                            lambda q: structure.unit(project, q, target, args.limit))
        return data, render.unit(data)
    if command == "classes":
        from . import classes
        if args.headers:
            data = classes.write_headers(project, target, args.headers.expanduser().resolve(), args.types_include)
            proof = data.get("proof")
            return data, f"wrote {data['headers']} headers to {data['folder']}" + (
                "; proof: " + ", ".join(f"{v:,} {k}" for k, v in sorted(proof.items(), key=lambda kv: -kv[1]))
                if proof else "")
        if args.prove:
            data = classes.prove(project, target, args.cls, args.limit)
            return data, render.classes_proof(data)
        data = classes.audit_project(project, target, args.cls, args.limit)
        return data, render.classes(data)
    if command == "renamed":
        data = bridge.renamed(project, args.since, target)
        return data, render.renamed(data)
    if command == "port-plan":
        data = bridge.port_plan(project, " ".join(args.query), args.depth, target)
        return data, render.port_plan(data)
    if command == "demand":
        data = bridge.demand(project, target, args.limit, not args.match_only, args.need, args.offset)
        if args.format == "addrs":
            return data, "\n".join(r["address"] for r in data["rows"])
        return data, render.demand(data)
    if command == "asm":
        results = []
        for query in bridge.split_queries(" ".join(args.query)):
            start = bridge.resolve_address(project, query, target) if args.size else None
            found = [start] if start is not None else bridge.resolve(project, query, target)
            if not found:
                raise ValueError(f"No function matches {query}")
            exact = bridge.HEX.match(query.strip())
            results.append(inspect_dol.disasm(project, target, int(exact[1], 16) if exact else found[0], args.size,
                                              max_lines=max(1, args.lines), words=args.words))
        data = results[0] if len(results) == 1 else {"batch": results}
        return data, render.disasm(data)
    if command == "decompile":
        from .decompile import decompile
        if args.all:
            data = decompile(project, target, None, args.threads)
        else:
            queries = bridge.split_queries(" ".join(args.query))
            if not queries:
                raise ValueError("Pass address(es) or name(s), or --all")
            found = []
            for query in queries:
                hits = bridge.resolve(project, query, target)
                if not hits:
                    raise ValueError(f"No function matches {query}")
                found.append(hits[0])
            data = decompile(project, target, found, args.threads)
        return data, render.decompiled(data)
    if command == "data":
        fields = args.fields.split(",") if args.fields else None
        refresh(project, [])
        def one(query: str) -> dict:
            query, kind, n = bridge.typed_query(query, bridge.data_type(args.type), args.count)  # `ADDR:ptr:12`
            address = bridge.resolve_address(project, query, target)
            if address is None:
                raise ValueError(f"No address or symbol matches {query}")
            return inspect_dol.read_data(project, target, address, kind, n, args.stride, fields, args.size)
        data = bridge.batch(bridge.query_list(" ".join(args.address)), one)
        return data, render.data_rows(data)
    if command == "compiled":
        data = bridge.compiled(project, args.query, target, args.limit)
        return data, render.compiled(data)
    if command == "try":
        if args.unit:
            from .candidate import check_unit
            data = check_unit(project, target, args.query, args.candidate, _folders(args.include))
            return data, render.candidate_unit(data)
        from .candidate import check
        data = check(project, target, args.query, args.candidate, args.force, args.keep, _folders(args.include))
        return data, render.candidate(data)
    if command == "probe":
        from .candidate import probe
        data = probe(project, target, args.query, args.source, args.names, _folders(args.include))
        return data, render.probe(data)
    if command == "sweep":
        from .sweep import sweep
        data = sweep(project, target, args.query, args.candidate, args.out, args.jobs, args.rounds, args.seconds)
        lines = [f"{data['address']} {data['function']}: {data['score']} after {len(data['history']) - 1} "
                 f"rewrite(s); {data['variants_compiled']} variants compiled in {data['seconds']} s"]
        lines += [f"  {step['score']:<36} {step['step']}" for step in data["history"]]
        lines.append(f"wrote {data['written']}" + ("  (identical: check it with `zkit try`)" if data["exact"]
                                                     else ""))
        return data, "\n".join(lines)
    if command == "objects":
        from . import objects
        if args.save:
            meta = objects.save(project, target, args.label)
            return meta, f"saved {meta['objects']} objects as {meta['label']} in {meta['seconds']} s" + (
                f" ({meta['missing']} not built yet)" if meta["missing"] else "")
        rename = json.loads(args.rename_json.read_text(encoding="utf-8")) if args.rename_json else {}
        rename.update(dict(item.split("=", 1) for item in args.rename))
        data = objects.compare_saved(project, target, args.label, rename)
        return data, render.objects_compare(data)
    if command == "analyze":
        from . import analyze
        data = analyze.analyze_project(project, target, args.out.expanduser().resolve())
        u = data["units"]
        return data, (f"wrote {data['folder']}: {u['units']:,} units, {data['named_symbols']:,} named symbols, "
                      f"{data['class_headers']:,} class headers")
    if command == "discover":
        from .discover import discover_project
        data = discover_project(project, target, args.out.expanduser().resolve())
        return data, render.discovered(data)
    if command == "units":
        from . import units
        if args.map is not None:
            from . import mapalign
            data = mapalign.adopt_project(project, target, args.map.expanduser().resolve() if str(args.map) != "."
                                          else None, args.write)
            return data, render.map_adoption(data)
        if args.check:
            data = units.check_project(project, target, args.limit)
            return data, render.units_check(data)
        data = units.propose_project(project, target)
        if args.splits:
            units.write_splits(data, args.splits.expanduser().resolve())
            data["written"] = str(args.splits)
        return data, render.units_proposal(data, args.limit) + (f"\nwrote {args.splits}" if args.splits else "")
    if command == "apply":
        from . import apply
        data = apply.renames(project, target)
        lines = [f"{len(data['renames'])} renames in {data['units']} units"
                 + (f"; {len(data['layouts_differ'])} sections whose layouts differ were left alone"
                    if data["layouts_differ"] else "")]
        lines += [f"  0x{r['address']:08X} {r['old']} -> {r['new']} ({r['unit']})" for r in data["renames"][:args.limit]]
        if args.write and data["renames"]:
            data["written"] = apply.write(project, target, data["renames"])
            lines.append(f"rewrote {data['written']} symbols; rebuild so the target objects carry the new names")
        return data, "\n".join(lines)
    if command == "link":
        from . import link
        from .platform import for_target
        if for_target(project.target(target)).name == "switch":
            from . import nxlink
            data = nxlink.link(project, target, args.out.expanduser().resolve(), args.compiled,
                               args.splits.expanduser().resolve() if args.splits else None, not args.no_mark)
            return data, render.nxlink(data)
        data = link.link(project, target, args.out.expanduser().resolve(), args.compiled,
                         args.splits.expanduser().resolve() if args.splits else None,
                         args.build.expanduser().resolve() if args.build else None)
        return data, render.link(data)
    if command in ("asmfile", "m2c"):
        from . import asmfile
        def resolve(query: str) -> int:
            exact = bridge.HEX.match(query.strip())
            found = [int(exact[1], 16)] if exact else bridge.resolve(project, query, target)
            if not found:
                raise ValueError(f"No function matches {query}")
            return found[0]
        if command == "asmfile":
            text = asmfile.write(project, target, [resolve(a) for a in args.addresses])
            if args.out:
                args.out.write_text(text, encoding="utf-8")
                return {"written": str(args.out)}, f"wrote {args.out}"
            return {"text": text}, text.rstrip()
        data = asmfile.m2c(project, target, [resolve(a) for a in args.addresses], args.language,
                           args.context.expanduser() if args.context else None, not args.no_ghidra)
        return data, render.m2c(data)
    if command == "permute":
        from . import permute
        data = permute.scratch(project, target, args.query, args.seed.expanduser() if args.seed else None,
                               args.out.expanduser() if args.out else None)
        if args.run:
            data = permute.run(project, target, data, args.jobs, args.time)
        return data, render.permute(data)
    if command == "delink":
        from . import delink
        project = project.with_overlay(here, worktree) if here else project   # a worktree splits by its own symbols
        config = project.target(target)
        if args.splits:
            splits = args.splits.expanduser().resolve()
        elif config.get("splits"):
            splits = project.file(config["repository"], config["splits"])
        else:
            raise ValueError("Pass --splits FILE: the target has no `splits` file in the project")
        data = delink.delink(project, target, splits, args.out.expanduser().resolve(),
                             args.objdiff.expanduser().resolve() if args.objdiff else None,
                             args.compiled.expanduser().resolve() if args.compiled else None,
                             set(args.unit) or None)
        lines = [f"wrote {len(data['units'])} objects to {data['out']}"]
        inside = [(u["unit"], a) for u in data["units"] for a in u.get("pointers_inside_functions", [])]
        if inside:
            lines.append(f"{len(inside)} data words point into the middle of a function (a start the symbols lack, "
                         "or a wrong boundary): " + ", ".join(f"{a} in {u}" for u, a in inside[:6]))
        if data["unassigned"]:
            lines.append(f"{data['unassigned']} referenced addresses are in no unit's ranges (extend the splits): "
                         + ", ".join(data.get("unassigned_examples", [])[:8]))
        if args.objdiff:
            lines.append(f"wrote {args.objdiff}")
        return data, "\n".join(lines)
    if command in ("configure", "build"):
        from . import build
        project = project.with_overlay(here, worktree) if here else project
        if command == "configure":
            fetched = build.ensure_downloads(project, build.build_targets(project, here, args.target)) \
                if args.download else []
            data = {**build.configure(project, here, args.target), "downloaded": fetched}
        else:
            data = build.build(project, here, args.target, args.targets, args.jobs, args.keep_going, args.download,
                               quiet=args.json)
        return data, build.render(data)
    if command == "refs":
        data = bridge.refs(project, " ".join(args.query), target, project.repo_key(args.repo) if args.repo else None,
                           args.limit)
        return data, render.refs(data)
    if command == "search":
        data = bridge.search(project, " ".join(args.words), args.repo, args.path, args.limit)
        return data, render.search(data)
    if command == "read":
        lines = max(1, args.end - args.start + 1) if args.end else args.lines
        data = bridge.read(project, args.reference, args.start, lines)
        return data, data["text"]
    if command == "check":
        data = bridge.check(project, args.repo, args.base, args.paths or None, target, args.staged)
        return data, render.check(data)
    if command == "impact":
        from .native import impact
        data = impact(project, args.repo, args.paths or None, args.base, target, args.budget)
        return data, render.impact(data)
    if command == "architecture":
        from .architecture import audit
        data = audit(project, args.repo, args.paths, args.base, args.all_files)
        return data, render.architecture(data)
    if command == "coverage":
        from .coverage import audit
        data = audit(project, args.repo, args.name)
        return data, render.coverage(data)
    if command == "stale":
        from .native import stale
        data = stale(project, args.repo, args.paths or None)
        return data, render.stale(data)
    if command == "test-plan":
        from .native import test_plan
        data = test_plan(project, args.repo, args.names, args.jobs)
        return data, render.test_plan(data)
    if command in ("grounding", "suspects"):
        from .fidelity import grounding
        data = grounding(project, args.repo, args.paths or None, target, args.limit)
        return data, render.grounding(data)
    if command == "tiers":
        from .tiers import summary
        data = summary(project, args.repo, args.paths or None)
        return data, render.tiers(data)
    if command == "consts":
        from .fidelity import constant_audit
        data = constant_audit(project, args.repo, args.paths or None, target)
        return data, render.consts(data)
    if command == "drift":
        from .fidelity import drift
        data = drift(project, target, args.accept, args.since.resolve() if args.since else None)
        return data, render.drift(data)
    if command == "reuse":
        data = bridge.reuse(project, args.repo, bridge.variant_terms(project, args.variants, args.terms), args.min_files)
        return data, render.reuse(data)
    if command == "activity":
        data = activity(project)
        return data, render.activity(data)
    if command == "wait":
        from .activity import wait_idle
        overlay = dict(project.overlays).get(args.repo)
        data = wait_idle(project, args.repo, overlay, args.timeout, args.settle)
        return data, render.wait(data)
    if command == "handoff":
        if not args.text:
            from .activity import handoffs
            rows = handoffs(project, args.repo, limit=max(1, args.list))
            return rows, "\n\n".join(f"{r['time']} {r['author']} @ {r.get('head')}\n{r['text']}" for r in rows) \
                or f"no handoff notes for {args.repo}"
        data = write_handoff(project, args.repo, " ".join(args.text))
        return data, (f"handoff saved for {args.repo} at {data['time']} ({data['head']})"
                      + (f"; replaced this session's note from {data['replaced']}" if data.get("replaced") else ""))
    if command == "lessons":
        rows = session.lessons(project, args.role)
        if args.id:
            wanted = [i.strip().strip(".,;:()`'\"\\") for i in args.id]  # ids pasted from prose
            found = [r for w in wanted for r in rows if r["id"] == w]
            missing = [w for w in wanted if not any(r["id"] == w for r in rows)]
            if not found:
                raise ValueError(f"No lesson {', '.join(missing)}")
            text = "\n\n".join(f"# {r['title']}\n\n{r['body']}" for r in found)
            return (found[0] if len(found) == 1 else found), text + (f"\n\n(no lesson {', '.join(missing)})" if missing else "")
        return rows, "\n".join(f"{r['id']:<28} [{r['applies']}/{r['kind']}] {r['title']}" for r in rows)
    if command == "gate":
        data = session.gate(project, args.repo)
        return data, render.gate(data)
    if command == "progress":
        from . import progress
        if target is None:
            raise ValueError("The project has no targets with an objdiff report")
        if args.list:
            rows = progress.baselines(project, target)
            return rows, "\n".join(f"{r['name']}  {r.get('label', '')}  report {r.get('report_time', '')}" for r in rows) \
                or "no saved baselines"
        if args.save:
            meta = progress.save_baseline(project, target, "manual", only_if_changed=False)
            if meta is None:
                raise ValueError("No complete report to save")
            return meta, f"saved baseline {meta['name']} ({meta['label']})"
        if args.since:
            data = progress.since(project, target, None if args.since == "latest" else args.since)
            if not args.check:
                data["regression_free"] = data.pop("ok")
            return data, render.delta(data)
        data = progress.progress(project, target)
        return data, render.progress(data)
    if command == "report":
        from . import progress
        targets = args.targets or [t for t, c in project.config.get("targets", {}).items() if c.get("report")]
        if not targets:
            raise ValueError("The project has no targets with an objdiff report")
        root = project.root(project.target(targets[0])["repository"])
        out = args.out.expanduser().resolve() if args.out else root / "build" / "progress"
        index = progress.write_page(project, targets, out, args.title)
        result, said = {"index": str(index)}, f"wrote {index}"
        if args.readme is not None:
            readme = args.readme.expanduser()
            readme = readme if readme.is_absolute() else root / readme
            result["readme"] = {"path": str(readme), "changed": progress.write_readme(project, targets, readme)}
            said += f"\n{'updated' if result['readme']['changed'] else 'unchanged'}: progress table in {readme}"
        return result, said
    if command == "quality":
        from . import quality
        repo = args.repo or (bridge.role_repos(project, "decomp") or [None])[0]
        if repo is None:
            raise ValueError("Name the repository to measure")
        if args.since:
            data = quality.compare(project, repo, args.since, args.at, args.paths or None)
            return data, render.quality_compare(data)
        data = quality.audit(project, repo, args.paths or None, args.at, args.files)
        return data, render.quality(data)
    if command == "hygiene":
        from . import hygiene
        repo = args.repo or (bridge.role_repos(project, "decomp") or list(project.config["repositories"]))[0]
        revisions = f"{args.since}..HEAD" if args.since else None
        data = hygiene.audit(project, repo, revisions, args.limit, tuple(args.only or ("commits", "files", "tree")))
        return data, render.hygiene(data)
    if command == "commit-msg":
        from .hygiene import message
        repo = here or (bridge.role_repos(project, "decomp") or list(project.config["repositories"]))[0]
        data = message(project, repo, args.file.read_text(encoding="utf-8", errors="replace"))
        return data, "" if data["ok"] else ("commit message refused:\n  " + "\n  ".join(data["problems"]) +
                                             "\n(one short line in plain words; `git commit --no-verify` skips this once)")
    if command == "cites":
        refresh(project)
        data = bridge.unresolved_cites(project, target, args.limit)
        return data, "\n".join(f"{r['address']} {r['repo']}:{r['path']}:{r['line']}  {r['text'][:100]}" for r in data) \
            or "every native citation resolves to a function or symbol"
    if command == "index":
        data = refresh(project)
        return data, render.generic(data)
    if command == "doctor":
        from .health import doctor, render as render_doctor
        data = doctor(project)
        return data, render_doctor(data)
    if command == "recipes":
        from .workflows import recipe_inventory
        repository = project.repo_key(args.repository) if args.repository else getattr(args, "repo", None)
        if repository is None:
            repository = (bridge.role_repos(project, "native") or [None])[0]
        data = recipe_inventory(project, repository, args.query, args.limit)
        return data, render.generic(data)
    if command == "check-recipe":
        from .recipes import check_recipe
        data = check_recipe(project, args.reference, args.catalog)
        return data, render.generic(data)
    if command == "plan":
        from .workflows import command_plan
        data = command_plan(project, args.name)
        return data, data["shell_display"]
    if command == "snapshot":
        from .project import snapshot
        data = snapshot(project, args.reference)
        return data, render.generic(data)
    if command == "check-snapshot":
        from .project import check_snapshot
        data = check_snapshot(project, json.loads(args.path.read_text(encoding="utf-8")))
        return data, render.generic(data)
    if command == "serve":
        from .server import serve
        serve(project)
        return None, ""
    if command == "hook" and args.event == "subagent-start":
        payload = {"hookSpecificOutput": {"hookEventName": "SubagentStart",
                                          "additionalContext": session.subagent_context(project, _hook_agent())}}
        return payload, json.dumps(payload)
    if command == "hook":
        repo, worktree = project.locate(Path.cwd())
        try:
            session.record_start(project)  # what this session starts from, for its finish gate
        except Exception:  # noqa: BLE001 - never block a session start
            pass
        try:
            text = render.brief(session.brief(project.with_overlay(repo, worktree) if repo else project, repo),
                                compact=True)
        except Exception as error:  # noqa: BLE001 - the session must still start, and say why the brief is missing
            text = f"# zkit brief unavailable: {type(error).__name__}: {error}\nRun `zkit doctor`."
        payload = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}}
        return payload, json.dumps(payload)
    if command == "install":
        from .install import install
        text = install(project, args.client, args.write)
        return {"text": text}, text
    raise ValueError(f"Unhandled command {command}")


def _hook_agent() -> str:
    """The agent type in a hook's input (JSON on stdin), or "" when there is none."""
    import select
    try:
        if sys.stdin is None or sys.stdin.isatty() or not select.select([sys.stdin], [], [], 2)[0]:
            return ""
        return str(json.loads(sys.stdin.read() or "{}").get("agent_type") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def _folders(paths: list[Path]) -> list[Path]:
    folders = [p.expanduser().resolve() for p in paths]
    for folder in folders:
        if not folder.is_dir():
            raise ValueError(f"--include {folder}: no such folder")
    return folders


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to a legacy code page
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        data, text = run(args)
    except Exception as error:  # noqa: BLE001
        if args.command == "hook":
            return 0  # a hook must never block or break the session start
        if not isinstance(error, (OSError, ValueError, KeyError, sqlite3.Error, struct.error, subprocess.SubprocessError)):
            raise
        print(json.dumps({"error": str(error)}) if args.json else f"error: {error}", file=sys.stderr)
        return 2
    if data is None:
        if text:
            print(text)
        return 0
    if args.command == "hook":
        print(text)
        return 0
    print(json.dumps(data, indent=1, ensure_ascii=False, default=str) if args.json else text)
    if isinstance(data, dict):
        if data.get("ok") is False or data.get("current") is False or data.get("ready_for_review") is False:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
