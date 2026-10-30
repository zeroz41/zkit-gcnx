"""Check a candidate outside the tree: compile it with its unit's exact build command and compare the function
with the original, the same way for every project (a ninja or a compile_commands.json build).

A candidate is a source file (the function with the includes it needs, or a whole copy of the unit) that is never
written into the tree. Attempts are recorded per address; the fifth attempt on the same address is refused, the
stop rule that kept matching sessions from grinding one function for hours.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .platform import platform_name
from .project import Project

ATTEMPT_CAP = 4
_PLACEHOLDER_ADDRESS = re.compile(r"_([0-9A-Fa-f]{6,16})$")
DEP_FLAGS = {"-MMD", "-MD", "-MP", "-M", "-MM"}
DEP_ARGS = {"-MF", "-MT", "-MQ"}


def compile_command(project: Project, target: str, unit: dict) -> tuple[list[str], Path, str]:
    """(argv, working directory, source as written in argv) that builds a unit's object."""
    repo = project.target(target)["repository"]
    root = project.root(repo)
    source = (unit.get("metadata") or {}).get("source_path")
    base = unit.get("base_path")
    if not source or not base:
        planned = _planned_command(project, target, unit)
        if planned is None:
            raise ValueError(f"Unit {unit.get('name')} has no source file yet")
        return planned
    # The build's own rule first: a compile_commands.json beside a ninja build is often an editor database
    # (clangd) whose compiler is not the one that builds the objects.
    if (root / "build.ninja").is_file():
        result = subprocess.run(["ninja", "-C", str(root), "-t", "commands", "-s", base], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=60)
        line = result.stdout.strip().splitlines()[-1] if result.returncode == 0 and result.stdout.strip() else ""
        if line:
            return shlex.split(line.split(" && ")[0]), root, source
    database = next((p for p in (root / "compile_commands.json", root / "build" / "compile_commands.json")
                     if p.is_file()), None)
    if database is not None:
        for entry in json.loads(database.read_text(encoding="utf-8")):
            path = Path(entry["directory"]) / entry["file"]
            if path.resolve() == (root / source).resolve():
                argv = entry.get("arguments") or shlex.split(entry["command"])
                return list(argv), Path(entry["directory"]), entry["file"]
    raise ValueError(f"No build command for {base}: neither build.ninja nor compile_commands.json names it")


def _planned_source(project: Project, target: str, unit: dict) -> str | None:
    """The source a unit with no file yet will have in a zkit build (`src/<unit>` as its splits.txt names it)."""
    from . import build
    config = project.target(target)
    if build.settings(config) is None or not config.get("splits"):
        return None
    splits = project.file(config["repository"], config["splits"])
    name = next((u for u in build.unit_names(splits) if build.stem(u) == unit.get("name")), None)
    return f"src/{name}" if name else None


def _planned_command(project: Project, target: str, unit: dict) -> tuple[list[str], Path, str] | None:
    """A unit with no source file yet: the command a zkit build will compile it with once it has one."""
    from . import build
    source = _planned_source(project, target, unit)
    if source is None:
        return None
    config = project.target(target)
    root = project.root(config["repository"])
    name = source[len("src/"):]
    step = build._compile(root, build.unit_settings(build.settings(config), name), name,
                          build.layout(target, config), {}, [])
    return step["argv"], root, source


def _rel(path: Path, base: Path) -> str:
    """Paths under the working directory are passed relative (Windows compilers run through wibo/Wine need it)."""
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def _rooted(argv: list[str], workdir: Path, source: Path) -> tuple[int, int] | None:
    """A command compiling from another folder (clang's `-working-directory`, the build's `source_root`): the
    indices of that folder and of the source as it names it, which reads as the original's path."""
    if "-working-directory" not in argv[:-1]:
        return None
    folder_index = argv.index("-working-directory") + 1
    folder = workdir / argv[folder_index]
    for index, arg in enumerate(argv):
        if index != folder_index and not arg.startswith("-") and (folder / arg).resolve() == source.resolve():
            return folder_index, index
    return None


def plain_command(argv: list[str], workdir: Path, source_arg: str) -> list[str]:
    """A rooted command (`_rooted`) as an ordinary one, for a compile whose `__FILE__` does not matter: from the
    working directory, the source as src/ names it."""
    rooted = _rooted(argv, workdir, workdir / source_arg)
    if rooted is None:
        return argv
    folder, source = rooted
    return [source_arg if i == source else a for i, a in enumerate(argv) if i not in (folder - 1, folder)]


def _restage(argv: list[str], source_arg: str, staged: Path, out_dir: Path, source_dir: Path,
             workdir: Path, rooted: tuple[int, int] | None = None,
             includes: list[Path] | None = None) -> tuple[list[str], Path]:
    """The unit's command, compiling `staged` into `out_dir` with `includes` (header copies that stand in for the
    tree's) and then the unit's own folder searched first. A rooted command (`_rooted`) compiles from `out_dir`
    instead, where `staged` has the source's path, so the candidate's `__FILE__` is the unit's; its other paths are
    absolute."""
    mwcc = any("mwcc" in Path(a).name.lower() for a in argv[:3])
    out: list[str] = []
    skip = False
    replaced = False
    expected = out_dir / (staged.stem + ".o")
    place = (lambda path: str(path.resolve())) if rooted else (lambda path: _rel(path, workdir))
    for index, arg in enumerate(argv):
        if skip:
            skip = False
            continue
        if arg in DEP_FLAGS:
            continue
        if arg in DEP_ARGS:
            skip = True
            continue
        if rooted and index == rooted[0]:
            out.append(str(out_dir.resolve()))
            continue
        if rooted and index == rooted[1]:
            out.append(arg)
            replaced = True
            continue
        if arg == "-o" and index + 1 < len(argv):
            out += ["-o", place(out_dir if mwcc else expected)]
            skip = True
            continue
        if arg.startswith("-o") and len(arg) > 2 and not mwcc:
            out.append(f"-o{place(expected)}")
            continue
        if not rooted and (arg == source_arg or Path(arg).as_posix() == Path(source_arg).as_posix()):
            out.append(_rel(staged, workdir))
            replaced = True
            continue
        out.append(arg)
    if not replaced:
        raise ValueError("Could not find the unit's source in its compile command")
    # Header copies, then the unit's folder, so its quoted includes resolve as they do in the tree.
    search = []
    for folder in [place(path) for path in includes or []] + [place(source_dir)]:
        search += ["-i", folder] if mwcc else [f"-I{folder}"]
    first_flag = next((i for i, a in enumerate(out) if a.startswith("-")), len(out))
    return out[:first_flag] + search + out[first_flag:], expected


def _compile(project: Project, target: str, unit: dict, text: str, work: Path,
             includes: list[Path] | None = None) -> tuple[Path | None, str, str]:
    """Compile `text` in `work` with the unit's exact command, `includes` searched before the tree's headers:
    (the object or None, the command, its messages)."""
    argv, workdir, source_arg = compile_command(project, target, unit)
    root = project.root(project.target(target)["repository"])
    source_path = root / ((unit.get("metadata") or {}).get("source_path") or _planned_source(project, target, unit))
    rooted = _rooted(argv, workdir, source_path)
    # same basename: static initializer names embed it; a rooted command's whole path: `__FILE__` is it
    staged = work / argv[rooted[1]] if rooted else work / source_path.name
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text(text, encoding="utf-8")
    command, expected = _restage(argv, source_arg, staged, work, source_path.parent, workdir, rooted, includes)
    cwd = workdir
    if rooted:   # from the folder itself: clang's -working-directory would make `__FILE__` absolute
        at = command.index("-working-directory")
        cwd = Path(command[at + 1])
        command = command[:at] + command[at + 2:]
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=300)
    built = expected if expected.is_file() else next(iter(work.glob("*.o")), None)
    message = (result.stdout + result.stderr).strip()
    if result.returncode != 0 or built is None:
        if result.returncode in (-31, 159) or "Bad system call" in message:
            message = ("the compiler was killed by the sandbox (SIGSYS): rerun this command with permission to "
                       "run the compiler outside the sandbox\n" + message[-800:])
        return None, shlex.join(command), message
    return built, shlex.join(command), message


def _scratch(project: Project, target: str) -> Path | None:
    workdir = project.root(project.target(target)["repository"]) / "build"  # ignored by the project
    return workdir if workdir.is_dir() else None


def compare(project: Project, target: str, unit: dict, name: str, text: str, keep: Path | None = None,
            includes: list[Path] | None = None) -> dict:
    """Compile `text` outside the tree with the unit's exact command and compare function `name` with the unit's
    target object: {command, compiled, errors} or {command, compiled, exact, differences, reloc_only, rows...}."""
    from . import objects
    root = project.root(project.target(target)["repository"])
    with tempfile.TemporaryDirectory(prefix="zkit-try-", dir=_scratch(project, target)) as work:
        built, command, message = _compile(project, target, unit, text, Path(work), includes)
        out: dict[str, Any] = {"command": command}
        if built is None:
            out.update(compiled=False, errors=message[-3000:])
            return out
        diff = objects.function_diff(root / unit["target_path"], built, name,
                                     labels=objects.label_reader(project, target))
        out.update(compiled=True, **{k: v for k, v in diff.items() if k not in ("target", "base")})
        if keep:
            keep.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(built, keep)
    return out


def symbol_placeholders(db, target: str, debt: list[dict]) -> tuple[list[dict], list[str]]:
    """(debt left, placeholders the symbols carry). An address-named function whose function at that address the
    symbols name with that very placeholder (plainly, inside an Itanium name or before a CodeWarrior suffix) is
    the callee's naming debt, kept until evidence names it: a candidate can only spell what the symbols say.
    `zkit quality` still counts it across the tree; a placeholder the symbols do not carry stays the candidate's."""
    from .index import function_at, parse_address
    kept, carried = [], set()
    for item in debt:
        token = item.get("text", "")
        match = _PLACEHOLDER_ADDRESS.search(token) if item.get("key") == "function_placeholder" else None
        address = parse_address("0x" + match.group(1)) if match else None  # the index's key (Switch: module offset)
        row = function_at(db, target, address) if address is not None else None
        name = row["name"] if row is not None and row["address"] == address else ""
        if name and (name == token or f"{len(token)}{token}" in name or name.startswith(token + "__")):
            carried.add(token)
        else:
            kept.append(item)
    return kept, sorted(carried)


def _state(row: dict) -> str:
    if row.get("missing"):
        return "missing"
    if row.get("exact"):
        return "identical"
    return "relocations only" if row.get("reloc_only") else f"{row.get('differences')} word(s)"


def check_unit(project: Project, target: str, query: str, candidate: Path,
               includes: list[Path] | None = None) -> dict[str, Any]:
    """A whole unit's candidate, outside the tree: compiled with the unit's command, every function of the unit
    compared with the original's, and (Switch) the object linked into the original, which proves the unit's data,
    strings and tables too. Each function's state is set beside its state in the tree's last build of the unit, so
    what the candidate gained and lost is listed. Records no attempts: it judges a unit, not one function's try."""
    from . import objects, quality
    from .elf import Elf
    from .index import connect
    from .nxlink import structor_partner
    unit = _unit_for(project, target, query)
    root = project.root(project.target(target)["repository"])
    text = candidate.read_text(encoding="utf-8", errors="replace")
    out: dict[str, Any] = {"unit": unit["name"], "candidate": str(candidate)}
    labels = objects.label_reader(project, target)
    with tempfile.TemporaryDirectory(prefix="zkit-try-unit-", dir=_scratch(project, target)) as work:
        built, command, message = _compile(project, target, unit, text, Path(work), includes)
        out["command"] = command
        if built is None:
            out.update(compiled=False, errors=message[-3000:])
            return out
        out["compiled"] = True
        original = Elf.load(root / unit["target_path"])
        names = {s.name for s in Elf.load(built).symbols if s.kind == "func"}
        rows = []
        for symbol in sorted((s for s in original.symbols if s.kind == "func" and s.size), key=lambda s: s.value):
            base = symbol.name if symbol.name in names else structor_partner(symbol.name)
            if base not in names:
                rows.append({"function": symbol.name, "exact": False, "missing": True})
                continue
            diff = objects.function_diff(root / unit["target_path"], built, symbol.name, base_name=base,
                                         labels=labels)
            rows.append({"function": symbol.name, "exact": bool(diff.get("exact")),
                         "differences": diff.get("differences"), "reloc_only": diff.get("reloc_only")})
        out["functions"] = rows
        out["exact"] = sum(r["exact"] for r in rows)
        debt = quality.findings(text, quality.patterns(project, project.target(target)["repository"]))
        debt, out["placeholders"] = symbol_placeholders(connect(project), target, debt)
        out["debt"] = sorted({item["label"] for item in debt})
        if platform_name(project.target(target)) == "switch":
            from .delink import read_units
            from .nxlink import link_unit
            config = project.target(target)
            splits = project.file(config["repository"], config["splits"])
            name = next((u.name for u in read_units(splits) if u.name.rsplit(".", 1)[0] == unit["name"]), None)
            out["link"] = link_unit(project, target, name, built) if name else {"linked": False,
                                                                                  "problems": ["no split unit"]}
        if out.get("link", {}).get("linked"):      # the link placed every byte where the original has it: a
            for row in rows:                         # difference in relocation names only reaches the same thing
                if not row["exact"] and row.get("reloc_only"):
                    row["exact"] = row["proven_by_link"] = True
            out["exact"] = sum(r["exact"] for r in rows)
        out["done"] = out["exact"] == len(rows) and not out["debt"] and out.get("link", {}).get("linked", True)
    out["tree"] = _tree_delta(root, unit, rows, labels)
    return out


def _tree_delta(root: Path, unit: dict, rows: list[dict], labels) -> dict[str, Any] | None:
    """The candidate's functions against the tree's last build of the unit (its objdiff base object): which became
    identical and which no longer are. None when the tree has not built the unit."""
    from . import objects
    from .elf import Elf
    from .nxlink import structor_partner
    base = root / unit["base_path"] if unit.get("base_path") else None
    if base is None or not base.is_file():
        return None
    names = {s.name for s in Elf.load(base).symbols if s.kind == "func"}
    gained, lost = [], []
    for row in rows:
        name = row["function"]
        partner = name if name in names else structor_partner(name)
        if partner in names:
            diff = objects.function_diff(root / unit["target_path"], base, name, base_name=partner, labels=labels)
            before = {"exact": bool(diff.get("exact")), "differences": diff.get("differences"),
                      "reloc_only": diff.get("reloc_only")}
        else:
            before = {"exact": False, "missing": True}
        now = row["exact"] and not row.get("proven_by_link")  # the link proves the tree's build nothing
        if now and not before["exact"]:
            gained.append({"function": name, "tree": _state(before)})
        elif before["exact"] and not now:
            lost.append({"function": name, "now": _state({**row, "exact": now})})
    return {"base": str(base), "built": datetime.fromtimestamp(base.stat().st_mtime, timezone.utc)
            .isoformat(timespec="seconds"), "gained": gained, "lost": lost}


def _ledger(project: Project) -> Path:
    from .activity import state_dir
    return state_dir(project) / "attempts.jsonl"


def attempts(project: Project, address: str) -> list[dict]:
    path = _ledger(project)
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("address") == address:
            rows.append(row)
    return rows


def _fingerprint(text: str, includes: list[Path] | None) -> str:
    """The attempt's identity: the candidate and every header copy it is compiled against."""
    digest = hashlib.sha256(text.encode())
    for folder in includes or []:
        for path in sorted(p for p in folder.rglob("*") if p.is_file()):
            digest.update(path.relative_to(folder).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()[:16]


def check(project: Project, target: str, query: str, candidate: Path, force: bool = False,
          keep: Path | None = None, includes: list[Path] | None = None) -> dict[str, Any]:
    """Compile a candidate for one original function and compare it with the original object."""
    from . import bridge, objects, quality
    from .activity import agent_identity
    from .index import address_text, connect, containing, refresh
    refresh(project)
    db = connect(project)
    found = bridge.resolve(project, query, target, limit=2)
    if len(found) != 1:
        raise ValueError(f"{query} names {'no' if not found else 'more than one'} function; use its address")
    row = containing(db, target, found[0])
    if row is None:
        raise ValueError(f"{query} is not inside a known function")
    address = address_text(row["address"])
    text = candidate.read_text(encoding="utf-8", errors="replace")
    fingerprint = _fingerprint(text, includes)
    history = [r for r in attempts(project, address) if r.get("compiled", True)]
    tried = {r["fingerprint"] for r in history}
    if len(tried) >= ATTEMPT_CAP and fingerprint not in tried and not force:
        best = max((r.get("differences") is not None and -r["differences"] or -10**9 for r in history), default=None)
        raise ValueError(f"{address} already has {len(tried)} attempts (cap {ATTEMPT_CAP}); stop and record the "
                         "blocker, or hand it to the permuter/variant sweep if the gap is register allocation. "
                         f"Best so far: {-best if best is not None and best > -10**9 else '?'} differing words. "
                         "--force overrides with a reason.")
    units = objects.objdiff_units(project, target)
    unit = units.get(row["unit"] or "")
    if unit is None:
        raise ValueError(f"{address} belongs to no objdiff unit ({row['unit']})")
    out: dict[str, Any] = {"address": address, "function": row["name"], "unit": row["unit"],
                           "candidate": str(candidate), "attempt": len(tried | {fingerprint}),
                           "attempts_so_far": len(tried), "cap": ATTEMPT_CAP}
    out.update(compare(project, target, unit, row["name"], text, keep, includes))
    exact, differences = out.get("exact", False), out.get("differences")
    repo = project.target(target)["repository"]
    catalog = quality.patterns(project, repo)
    lines = text.splitlines()
    span = bridge.find_definition(lines, bridge.definition_names(row["name"], row["demangled"]),
                                  params=bridge.parameter_count(row["demangled"]))
    body = "\n".join(lines[span[0]:span[1] + 1]) if span else text
    out["judged"] = "the function's definition" if span else "the whole candidate (definition not found)"
    debt, out["placeholders"] = symbol_placeholders(db, target, quality.findings(body, catalog))
    if debt:
        labels: dict[str, int] = {}
        for item in debt:
            labels[item["label"]] = labels.get(item["label"], 0) + 1
        out["debt"] = [f"{label} x{n}" for label, n in sorted(labels.items(), key=lambda kv: -kv[1])]
        out["bankable"] = False
        out["bank_note"] = ("matches bytes but still reads as decompiler output: type it against the class header "
                            "(members, fields, real names) before it goes into the tree") if exact else None
    else:
        out["bankable"] = bool(exact)
    with _ledger(project).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"address": address, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 "agent": agent_identity(), "fingerprint": fingerprint, "exact": exact,
                                 "differences": differences, "compiled": bool(out.get("compiled")),
                                 "forced": bool(force and len(tried) >= ATTEMPT_CAP)})
                     + "\n")
    return out


def _unit_for(project: Project, target: str, query: str) -> dict:
    """The objdiff unit a query names: the unit's name, or an address or function inside it."""
    from . import bridge, objects
    from .index import connect, containing, refresh
    units = objects.objdiff_units(project, target)
    unit = units.get(query) or units.get(query.rsplit(".", 1)[0])
    if unit is None:
        refresh(project)
        found = bridge.resolve(project, query, target, limit=2)
        row = containing(connect(project), target, found[0]) if len(found) == 1 else None
        unit = units.get(row["unit"]) if row is not None and row["unit"] else None
    if unit is None:
        raise ValueError(f"{query} names no objdiff unit (give the unit's name or an address in it)")
    return unit


_RELOC_LINE = re.compile(r"^\s*[0-9a-f]+:\s+(R_[A-Z0-9_]+)\s+(\S+)")
_INSN_LINE = re.compile(r"^\s*([0-9a-f]+):\s+(?:(?:[0-9a-f]{2} ){3}[0-9a-f]{2}\s+|[0-9a-f]{8}\s+)?(.*)$")


def compact_disassembly(lines: list[str], name: str = "", start: int = 0) -> list[str]:
    """objdump lines as `+offset  instruction` (from `start`, the function's place in its section): a branch inside
    the function as `+0x..`, an operand a relocation fills as the relocation's target, any other relocation noted
    after the instruction."""
    here = re.compile(r"(?:0x)?[0-9a-f]+ <" + re.escape(name) + r"(?:\+(0x[0-9a-f]+))?>") if name else None
    rows: list[list] = []   # [offset, text, [relocation targets]]
    for line in lines:
        reloc = _RELOC_LINE.match(line)
        if reloc and rows:
            rows[-1][2].append(reloc.group(2))
            continue
        insn = _INSN_LINE.match(line)
        if insn and insn.group(2).strip():
            rows.append([int(insn.group(1), 16) - start, re.sub(r"\s+", " ", insn.group(2).strip()), []])
    out = []
    for offset, text, targets in rows:
        m = here.search(text) if targets and here is not None else None
        if m and int(m.group(1) or "0", 16) in (0, offset):   # an unrelocated operand: the function or itself
            text = text[:m.start()] + targets.pop(0) + text[m.end():]
        if here is not None:
            text = here.sub(lambda m: "+" + (m.group(1) or "0x0"), text)
        out.append(f"+{offset:x}  {text}" + (f"  ; {', '.join(targets)}" if targets else ""))
    return out


def probe(project: Project, target: str, query: str, source: Path, names: list[str] | None = None,
          includes: list[Path] | None = None) -> dict[str, Any]:
    """Compile any file with a unit's exact command and read back the code it makes: compiler experiments
    (variants of one construct side by side) without hand-copied flags. Compares nothing with the original and
    records no attempts. `names`: functions to show (exact or a substring of the name); default every function."""
    from . import objects
    from .elf import Elf
    unit = _unit_for(project, target, query)
    text = source.read_text(encoding="utf-8", errors="replace")
    out: dict[str, Any] = {"unit": unit["name"], "source": str(source)}
    with tempfile.TemporaryDirectory(prefix="zkit-probe-", dir=_scratch(project, target)) as work:
        built, command, message = _compile(project, target, unit, text, Path(work), includes)
        out["command"] = command
        if built is None:
            out.update(compiled=False, errors=message[-3000:])
            return out
        elf = Elf.load(built)
        functions = sorted(elf.functions().values(), key=lambda s: (s.section, s.value))
        if names:
            functions = [f for f in functions if any(n == f.name or n in f.name for n in names)]
        out.update(compiled=True, warnings=message[-1500:] if message else "", functions=[
            {"function": f.name, "size": f.size,
             "asm": compact_disassembly(objects.disassembly(project, target, built, f.name, elf.machine), f.name, f.value)}
            for f in functions])
    return out
