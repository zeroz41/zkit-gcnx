"""Build a project: compile every unit that has a source, write the original's target objects, pair them for
objdiff, report, link and check the result against the original's pinned SHA-1. One ninja file does it,
generated from the project file: the role a hand-written configure.py and build.ninja play elsewhere.

The settings are the target's `build` object (docs/project-file.md): the compiler and its flags, include folders,
where the compilers live and what runs them, and per-unit overrides. A unit `a/b.cpp` of the splits is compiled
from `src/a/b.cpp` when that file exists, into `<dir>/src/a/b.o`; its target object is `<dir>/obj/a/b.o`. The ninja
file is `build/build.ninja` (build/ is never committed) with objdiff's project file and a compile_commands.json
(the exact command of every compiled unit, which `zkit try` reuses).

GameCube compilers are CodeWarrior's, one folder per version (`GC/2.6/mwcceppc.exe`), run through wibo (or wine)
outside Windows; they are never fetched unless the owner asks (`--download`), and then only the standard GameCube/Wii
compiler bundle, checked against its SHA-256, with the pinned tools a target lacks (fetch.py: wibo, objdiff-cli,
binutils, m2c, decomp-permuter). Switch units are compiled with the configured clang.
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .project import Project

NINJA = "build/build.ninja"
# The standard GameCube/Wii compiler bundle (tag 20251118), and
# the SHA-256 measured on it: CodeWarrior for GameCube 1.0-3.0a5.2 and Wii.
COMPILERS_URL = "https://files.decomp.dev/compilers_20251118.zip"
COMPILERS_SHA256 = "69b0d4980a2eccea4ae6e70b486714b5190cb6c75e3bc7b8fb5878a8854d0d1c"

DEFAULTS: dict[str, dict[str, Any]] = {
    "gamecube": {
        "compilers": "build/compilers", "compiler": "GC/1.3.2", "wrapper": "wibo",
        "cflags": ["-nodefaults", "-proc gekko", "-align powerpc", "-enum int", "-fp hardware", "-Cpp_exceptions off",
                   "-RTTI off", "-O4,p", "-inline auto", "-str reuse", "-maxerrors 1", "-nosyspath",
                   "-fp_contract on", "-multibyte"],
        "includes": ["include", "src"],
        "ldflags": ["-fp hardware", "-nodefaults"]},
    "switch": {
        "compiler": "clang++",
        "cflags": ["--target=aarch64-none-elf", "-march=armv8-a+crc+crypto", "-mtune=cortex-a57", "-fPIC", "-O3",
                   "-fno-exceptions", "-fno-rtti", "-fno-asynchronous-unwind-tables", "-std=gnu++17"],
        "includes": ["include", "src"]},
}
UNIT_KEYS = {"compiler", "cflags", "extra_cflags", "includes", "compiler_version"}


def words(value: str | list[str] | None) -> list[str]:
    """Flags as argv words: a string, or a list whose items may hold several words ("-proc gekko")."""
    if not value:
        return []
    return [word for item in ([value] if isinstance(value, str) else value) for word in shlex.split(item)]


def settings(target: dict[str, Any]) -> dict[str, Any] | None:
    """The target's build settings over its platform's defaults, or None when it has no `build` object."""
    own = target.get("build")
    if own is None:
        return None
    if not isinstance(own, dict):
        raise ValueError("A target's `build` must be an object")
    platform = (target.get("platform") or "gamecube").lower()
    platform = "switch" if platform in ("switch", "nx") else "gamecube"
    for pattern, override in own.get("units", {}).items():
        unknown = set(override) - UNIT_KEYS
        if unknown:
            raise ValueError(f"build.units[{pattern!r}]: unknown setting {', '.join(sorted(unknown))} "
                             f"(per unit: {', '.join(sorted(UNIT_KEYS))})")
    return {"platform": platform, **DEFAULTS[platform], **own}


def unit_settings(config: dict[str, Any], unit: str) -> dict[str, Any]:
    """The settings one unit compiles with: every `units` pattern matching its path applies in order, later ones
    winning; `extra_cflags` adds to the flags instead of replacing them."""
    out = {key: value for key, value in config.items() if key != "units"}
    out["extra_cflags"] = words(config.get("extra_cflags"))
    for pattern, override in config.get("units", {}).items():
        if fnmatch.fnmatchcase(unit, pattern):
            out.update({key: value for key, value in override.items() if key != "extra_cflags"})
            out["extra_cflags"] = out["extra_cflags"] + words(override.get("extra_cflags"))
    return out


@dataclass(frozen=True)
class Layout:
    """Where a target's build writes, relative to its repository."""
    dir: str

    @property
    def obj(self) -> str:
        return f"{self.dir}/obj"

    @property
    def src(self) -> str:
        return f"{self.dir}/src"

    @property
    def report(self) -> str:
        return f"{self.dir}/report.json"

    @property
    def link(self) -> str:
        return f"{self.dir}/link"


def layout(name: str, target: dict[str, Any]) -> Layout:
    """build.dir, else the report's folder (build/<ID>/report.json), else build/<target>."""
    own = (target.get("build") or {}).get("dir")
    if own:
        return Layout(own.rstrip("/"))
    if target.get("report"):
        return Layout(Path(target["report"]).parent.as_posix())
    return Layout(f"build/{name}")


def unit_names(splits: Path) -> list[str]:
    """Units of a splits.txt in file order (those with at least one range)."""
    from .gc import read_splits
    return list(dict.fromkeys(unit for unit, *_ in read_splits(splits)))


def stem(unit: str) -> str:
    return unit.rsplit(".", 1)[0]


# Tools

def _tool(root: Path, value: str | None) -> Path | None:
    """A tool given as a path (repository-relative or absolute, `~` allowed) or a name on PATH."""
    if not value:
        return None
    path = Path(value).expanduser()
    path = path if path.is_absolute() else root / path
    if path.is_file():
        return path
    found = shutil.which(value) if os.sep not in value and "/" not in value else None
    return Path(found) if found else None


def compilers_folder(root: Path, config: dict[str, Any]) -> Path:
    path = Path(config.get("compilers") or "build/compilers").expanduser()
    return path if path.is_absolute() else root / path


def compiler(root: Path, config: dict[str, Any]) -> tuple[Path | None, str]:
    """(executable or None, what was looked for) of a unit's compiler: GameCube, the CodeWarrior version folder
    under `compilers`; Switch, the clang path or name."""
    if config["platform"] == "gamecube":
        path = compilers_folder(root, config) / config["compiler"] / "mwcceppc.exe"
        return (path if path.is_file() else None), str(path)
    return _tool(root, config["compiler"]), config["compiler"]


def linker(root: Path, config: dict[str, Any]) -> Path | None:
    """GameCube: mwldeppc.exe of `linker` (default: the target's compiler version)."""
    path = compilers_folder(root, config) / (config.get("linker") or config["compiler"]) / "mwldeppc.exe"
    return path if path.is_file() else None


def wrapper(root: Path, config: dict[str, Any]) -> tuple[Path | None, bool]:
    """(program that runs Windows compilers here, whether one is needed): none on Windows, else `wrapper`."""
    if os.name == "nt" or config["platform"] != "gamecube":
        return None, False
    if config.get("wrapper") not in (None, "wibo"):
        return _tool(root, config["wrapper"]), True
    from .fetch import managed
    return managed(root, "wibo") or _tool(root, "wibo"), True


def objdiff_cli(root: Path, config: dict[str, Any]) -> Path | None:
    """`objdiff_cli` when set, else build/tools/objdiff-cli in the repository, else objdiff-cli on PATH."""
    if config.get("objdiff_cli"):
        return _tool(root, config["objdiff_cli"])
    from .fetch import managed
    return managed(root, "objdiff-cli") or _tool(root, "objdiff-cli")


def has_link() -> bool:
    """This zkit has `zkit link` (the GameCube relinker)."""
    return importlib.util.find_spec("zkit.link") is not None


def clang_version(path: Path) -> str:
    result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=60)
    return (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr) else ""


# Ninja text

def _command(argv: list[str]) -> str:
    """argv as ninja hands it to the system: sh on POSIX, CreateProcess on Windows; `$` escaped for ninja."""
    text = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    return text.replace("$", "$$").replace("\n", " ")


def _path(text: str) -> str:
    return re.sub(r"([$ :])", r"$\1", text)


def _paths(items: list[str]) -> str:
    return " $\n    ".join(_path(item) for item in items)


class Ninja:
    def __init__(self):
        self.lines: list[str] = []

    def comment(self, text: str) -> None:
        self.lines += [f"# {line}" for line in text.splitlines()]

    def variable(self, name: str, value: str, indent: bool = False) -> None:
        self.lines.append(f"{'  ' if indent else ''}{name} = {value}")

    def rule(self, name: str, command: str, **extra: str) -> None:
        self.lines.append(f"rule {name}")
        self.variable("command", command, True)
        for key, value in extra.items():
            self.variable(key, value, True)
        self.lines.append("")

    def build(self, outputs: list[str], rule: str, inputs: list[str] = (), implicit: list[str] = (),
              order: list[str] = (), implicit_outputs: list[str] = (), variables: dict[str, str] | None = None) -> None:
        line = f"build {_paths(list(outputs))}"
        if implicit_outputs:
            line += f" | {_paths(list(implicit_outputs))}"
        line += f": {rule}"
        if inputs:
            line += f" {_paths(list(inputs))}"
        if implicit:
            line += f" | {_paths(list(implicit))}"
        if order:
            line += f" || {_paths(list(order))}"
        self.lines.append(line)
        for key, value in (variables or {}).items():
            self.variable(key, value, True)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _relative(path: Path, root: Path) -> str:
    """Repository-relative (posix) when inside it, else absolute: compilers run through wibo get short paths."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _zkit_stamp() -> str:
    """zkit's version and a hash of its code: what the objects it cuts depend on besides the project's files."""
    import hashlib
    from . import __version__
    digest = hashlib.sha1()
    for path in sorted(Path(__file__).parent.glob("*.py")):
        digest.update(path.read_bytes())
    return f"{__version__} {digest.hexdigest()}\n"


def _write(path: Path, text: str) -> bool:
    """Write when the content differs (so ninja sees no change otherwise); True when written."""
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


# Configure

def build_targets(project: Project, repository: str | None = None, only: str | None = None) -> list[str]:
    """Targets with `build` settings (in `repository` when given); `only` must be one of them."""
    names = [name for name, target in project.config.get("targets", {}).items()
             if target.get("build") is not None and (repository is None or target["repository"] == repository)]
    if only is not None:
        if only not in names:
            raise ValueError(f"Target {only} has no `build` settings in {project.path}: add a \"build\" object "
                             "(docs/project-file.md)")
        return [only]
    if not names:
        raise ValueError(f"No target in {project.path} has `build` settings (projects made by `zkit new` have them; "
                         "a project with its own configure.py builds with that)")
    return names


def zkit_command(project: Project) -> list[str]:
    """How the ninja file calls this same zkit (its Python, so a development checkout builds with itself)."""
    return [sys.executable, "-m", "zkit.cli", "--project", str(project.path)]


def configure(project: Project, repository: str | None = None, only: str | None = None,
              zkit: list[str] | None = None) -> dict[str, Any]:
    """Write build/build.ninja, objdiff's project file and build/compile_commands.json for the targets with
    `build` settings; report what each target builds and what it lacks."""
    names = build_targets(project, repository, only)
    repositories = {project.target(name)["repository"] for name in names}
    if len(repositories) > 1:
        raise ValueError("Targets in several repositories: build one at a time (run inside its repository)")
    repository = repositories.pop()
    root = project.root(repository)
    zkit = zkit or zkit_command(project)
    python = [sys.executable, "-m", "zkit.build"]
    ninja = Ninja()
    ninja.comment(f"Generated by `zkit configure` from {project.path}; `zkit build` rewrites it. Never edit or "
                  "commit it.")
    ninja.variable("ninja_required_version", "1.10")
    ninja.variable("builddir", "build")  # ninja's own log and lock, out of the repository's top folder
    ninja.lines.append("")
    ninja.rule("configure", _command(zkit) + " configure", generator="1", description="CONFIGURE $out")
    ninja.rule("sha1", _command(python) + " sha1 $in $sha1 $out", description="SHA-1 $in")
    # generator: rerun only when the splits, symbols, original or zkit change, never for a changed command line
    ninja.rule("delink", _command(zkit) + " --target $target delink --splits $splits --out $outdir",
               generator="1", description="DELINK $target")
    ninja.rule("mwcc", "$cc $cflags -MMD -c $in -o $basedir" + (
        f" && {_command(python)} depfile $basefile.d $out" if os.name != "nt" else ""),
        depfile="$basefile.d", deps="gcc", description="MWCC $out")
    ninja.rule("clang", "$cc $cflags -MMD -MF $out.d -c $in -o $out", depfile="$out.d", deps="gcc",
               description="CC $out")
    ninja.rule("report", "$objdiff report generate -p $project $args -o $out", description="REPORT $out")
    inputs = [str(project.path)]
    stamp = "build/zkit.stamp"                       # the target objects are cut again when zkit itself changes
    _write(root / stamp, _zkit_stamp())
    groups: dict[str, list[str]] = {"objects": [], "compile": [], "report": [], "link": []}
    defaults: list[str] = []
    commands, summary, objdiff_files = [], {}, {}
    for name in names:
        target = project.target(name)
        config = settings(target)
        paths = layout(name, target)
        notes: list[str] = []
        if not target.get("splits"):
            raise ValueError(f"Target {name} has no `splits` file: the units come from it")
        splits = project.file(repository, target["splits"])
        original = project.file(repository, target["original"]) if target.get("original") else None
        if original is None or not original.is_file():
            raise ValueError(f"Target {name}: the original {target.get('original')} is missing")
        units = unit_names(splits)
        inputs.append(_relative(splits, root))
        objects = [f"{paths.obj}/{stem(u)}.o" for u in units]
        checked: list[str] = []
        if target.get("sha1"):
            checked = [f"{paths.dir}/original.sha1"]
            ninja.build(checked, "sha1", [_relative(original, root)], variables={"sha1": target["sha1"]})
        else:
            notes.append("no `sha1` pinned for the original: the build cannot tell a wrong revision")
        if objects:
            symbols = [_relative(project.file(repository, target["symbols"]), root)] if target.get("symbols") else []
            ninja.build(objects[:1], "delink", [_relative(splits, root), _relative(original, root), *symbols, stamp],
                        order=checked, implicit_outputs=objects[1:],
                        variables={"target": name, "splits": _command([_relative(splits, root)]),
                                   "outdir": _command([paths.obj])})
        ninja.lines.append("")
        compiled, sources, found = [], set(), {}
        for unit in units:
            if not (root / "src" / unit).is_file():
                continue
            step = _compile(root, unit_settings(config, unit), unit, paths, found, notes)
            commands.append({"directory": str(root), "file": f"src/{unit}", "arguments": step["argv"],
                             "output": step["out"]})
            if config["platform"] == "gamecube":
                basedir = Path(step["out"]).parent.as_posix()
                variables = {"basedir": _command([basedir]), "basefile": _command([f"{basedir}/{Path(unit).stem}"])}
            else:
                variables = {}
            ninja.build([step["out"]], step["rule"], [f"src/{unit}"], implicit=step["implicit"],
                        variables={"cc": _command(step["cc"]), "cflags": _command(step["flags"]), **variables})
            compiled.append(step["out"])
            sources.add(unit)
        objdiff = project.file(repository, target.get("objdiff", "objdiff.json"))
        if objdiff in objdiff_files.values():
            raise ValueError(f"Targets {name} and {next(n for n, p in objdiff_files.items() if p == objdiff)} share "
                             f"{objdiff.name}: give each target its own `objdiff` file")
        objdiff_files[name] = objdiff
        wrote = _write(objdiff, write_objdiff(objdiff, root, units, sources, paths,
                                              target.get("module") or name))
        report, tool = None, objdiff_cli(root, config)
        if tool and objdiff.name == "objdiff.json":
            report = paths.report
            ninja.build([report], "report", implicit=[_relative(objdiff, root), *objects, *compiled,
                                                      _relative(tool, root)], variables={
                "objdiff": _command([_relative(tool, root)]), "project": _command([_relative(objdiff.parent, root)]),
                "args": _command(words(config.get("report_args")))})
        elif tool:
            notes.append(f"no report: objdiff-cli reads a file named objdiff.json, not {objdiff.name}")
        else:
            notes.append("no report: objdiff-cli not found (`zkit build --download` fetches it; or set "
                         "build.objdiff_cli, or put it on PATH)")
        linked = _link(ninja, project, name, target, config, root, paths, [*objects, *compiled, *filter(None, [report])],
                       notes, zkit)
        ninja.lines.append("")
        groups["objects"] += objects
        groups["compile"] += compiled
        groups["report"] += [report] if report else []
        groups["link"] += linked[:1]
        defaults += linked[-1:] or ([report] if report else ["objects", "compile"])
        summary[name] = {"units": len(units), "compiled": len(compiled), "objects": len(objects), "dir": paths.dir,
                         "report": report, "link": bool(linked), "objdiff": str(objdiff), "objdiff_written": wrote,
                         "notes": notes}
    # A source added or removed changes its folder's time: ninja then reconfigures before building.
    sources = root / "src"
    folders = [_relative(p, root) for p in [sources, *sorted(p for p in sources.rglob("*") if p.is_dir())]] \
        if sources.is_dir() else []
    ninja.build([NINJA], "configure", implicit=sorted(set(inputs)) + folders)
    for folder in folders:  # a folder that disappears makes the file stale instead of breaking ninja
        ninja.build([folder], "phony")
    ninja.lines.append("")
    for group, items in groups.items():
        ninja.build([group], "phony", items)
    defaults = list(dict.fromkeys(defaults))
    ninja.lines.append("default " + " ".join(_path(item) for item in defaults))
    path = root / NINJA
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ninja.text(), encoding="utf-8")  # always: its time stamp says it is current
    _write(root / "build" / "compile_commands.json", json.dumps(commands, indent=1) + "\n")
    return {"ninja": str(path), "root": str(root), "repository": repository, "targets": summary,
            "default": defaults}


def _compile(root: Path, config: dict[str, Any], unit: str, paths: Layout, found: dict[str, Path | None],
             notes: list[str]) -> dict[str, Any]:
    """One unit's compile step: its rule, the compiler words and flags, the whole argv (compile_commands.json),
    its object and the tool files ninja depends on."""
    out, source = f"{paths.src}/{stem(unit)}.o", f"src/{unit}"
    if config["compiler"] not in found:
        exe, wanted = compiler(root, config)
        if exe is None:
            notes.append(f"compiler not found: {wanted}" + (" (`zkit build --download` fetches the CodeWarrior "
                                                            "bundle)" if config["platform"] == "gamecube" else
                                                            " (set build.compiler, or pin its archive in "
                                                            "build.compiler_download for `zkit build --download`)"))
        elif config["platform"] == "switch" and config.get("compiler_version") and \
                config["compiler_version"] not in clang_version(exe):
            raise ValueError(f"{exe} is not {config['compiler_version']!r}: it says {clang_version(exe)!r}")
        found[config["compiler"]] = exe
    exe = found[config["compiler"]]
    includes = words(config.get("includes"))
    if config["platform"] == "gamecube":
        run, needed = wrapper(root, config)
        if needed and run is None and "wrapper" not in found:
            found["wrapper"] = None
            notes.append(f"{config.get('wrapper') or 'wibo'} not found: it runs the Windows compilers here "
                         "(`zkit build --download` fetches wibo; or set build.wrapper)")
        cc = [_relative(run, root)] if run else [config.get("wrapper") or "wibo"] if needed else []
        cc.append(_relative(exe, root) if exe else str(compiler(root, config)[1]))
        flags = words(config["cflags"]) + [w for folder in includes for w in ("-i", folder)] + config["extra_cflags"]
        argv = [*cc, *flags, "-c", source, "-o", Path(out).parent.as_posix()]
        return {"rule": "mwcc", "cc": cc, "flags": flags, "argv": argv, "out": out,
                "implicit": [_relative(p, root) for p in (run, exe) if p]}
    cc = [str(exe) if exe else config["compiler"]]
    flags = words(config["cflags"]) + [f"-I{folder}" for folder in includes] + config["extra_cflags"]
    return {"rule": "clang", "cc": cc, "flags": flags, "argv": [*cc, *flags, "-c", source, "-o", out], "out": out,
            "implicit": [_relative(exe, root)] if exe else []}


def write_objdiff(path: Path, root: Path, units: list[str], compiled: set[str], paths: Layout,
                  module: str = "main") -> str:
    """objdiff's project file: each unit's target object, and its compiled one when it has a source (objdiff
    refuses a base object that does not exist), and the module it links into, so a unit that moves to another
    folder keeps its functions' place in the report. Paths are relative to the file's folder; objdiff rebuilds a
    compiled object with `ninja -f build/build.ninja <object>`."""
    folder = path.parent
    relative = lambda p: os.path.relpath(root / p, folder).replace(os.sep, "/")
    rows = []
    for unit in units:
        row: dict[str, Any] = {"name": stem(unit), "target_path": relative(f"{paths.obj}/{stem(unit)}.o")}
        if unit in compiled:
            row["base_path"] = relative(f"{paths.src}/{stem(unit)}.o")
        row["metadata"] = {"source_path": f"src/{unit}", "module_name": module}
        rows.append(row)
    return json.dumps({"min_version": "2.0.0", "custom_make": "ninja",
                       "custom_args": ["-f", os.path.relpath(root / NINJA, folder).replace(os.sep, "/")],
                       "build_target": False, "build_base": True,
                       "watch_patterns": ["*.c", "*.cp", "*.cpp", "*.h", "*.hpp", "*.inc"], "units": rows},
                      indent=1) + "\n"


def _link(ninja: Ninja, project: Project, name: str, target: dict[str, Any], config: dict[str, Any], root: Path,
          paths: Layout, inputs: list[str], notes: list[str], zkit: list[str]) -> list[str]:
    """The GameCube link and its check: `zkit link` relinks the executable from delinked and compiled objects
    with the project's mwld, then the DOL's SHA-1 is compared with the pinned one. [DOL, check stamp], or []."""
    if config["platform"] != "gamecube":
        return []
    if not has_link():
        notes.append("no link: this zkit has no `zkit link` yet")
        return []
    mwld = linker(root, config)
    run, needed = wrapper(root, config)
    if mwld is None or (needed and run is None):
        notes.append("no link: " + ("mwldeppc.exe not found under " + str(compilers_folder(root, config) / (
            config.get("linker") or config["compiler"])) if mwld is None else "no wrapper to run mwld"))
        return []
    module = target.get("module") or name
    # zkit link reads the linker from this edge (rule `link`, output <module>.elf); ninja never runs it.
    head = [_relative(run, root)] if run else []
    ninja.rule("link", _command([*head, _relative(mwld, root)]) + " $ldflags -o $out @$out.rsp",
               rspfile="$out.rsp", rspfile_content="$in_newline", description="LINK $out")
    ninja.build([f"{paths.link}/{module}.elf"], "link", variables={"ldflags": _command(words(config.get("ldflags")))})
    ninja.rule("zkit_link", _command(zkit) + f" --target $target link --out $outdir --build {_command([NINJA])}",
               description="ZKIT LINK $target")
    dol = f"{paths.link}/{module}.dol"
    splits = _relative(project.file(target["repository"], target["splits"]), root)
    ninja.build([dol], "zkit_link", implicit=[splits, *inputs], variables={"target": name,
                                                                          "outdir": _command([paths.link])})
    if not target.get("sha1"):
        return [dol]
    ninja.build([f"{paths.dir}/ok"], "sha1", [dol], variables={"sha1": target["sha1"]})
    return [dol, f"{paths.dir}/ok"]


# Running it

def download_compilers(folder: Path, url: str = COMPILERS_URL, sha256: str = COMPILERS_SHA256) -> dict[str, Any]:
    """Fetch the compiler bundle, refuse it unless its SHA-256 is the pinned one, and unpack it into folder."""
    from .fetch import download, unzip
    folder.mkdir(parents=True, exist_ok=True)
    temporary = download(url, sha256, folder.parent)
    try:
        count = unzip(temporary, folder, url)
    finally:
        temporary.unlink(missing_ok=True)
    return {"url": url, "sha256": sha256, "folder": str(folder), "files": count}


def ensure_compilers(project: Project, names: list[str]) -> list[dict[str, Any]]:
    """--download: fetch the bundle into each GameCube target's compilers folder that lacks its compiler."""
    fetched, done = [], set()
    for name in names:
        target = project.target(name)
        config = settings(target)
        root = project.root(target["repository"])
        folder = compilers_folder(root, config)
        wanted = [config["compiler"], config.get("linker") or config["compiler"],
                  *(o["compiler"] for o in config.get("units", {}).values() if "compiler" in o)]
        if config["platform"] != "gamecube" or folder in done or all(
                (folder / version / "mwcceppc.exe").is_file() for version in wanted):
            continue
        fetched.append(download_compilers(folder))
        done.add(folder)
    return fetched


def ensure_downloads(project: Project, names: list[str]) -> list[dict[str, Any]]:
    """--download: the compiler bundle where a compiler is missing, then every pinned tool a target lacks."""
    from .fetch import ensure
    return ensure_compilers(project, names) + ensure(project, names)


def run_ninja(root: Path, targets: list[str], jobs: int | None = None, keep_going: int | None = None,
              quiet: bool = False) -> int:
    """ninja -f build/build.ninja from the repository root (output to the terminal, or stderr when quiet)."""
    ninja = shutil.which("ninja")
    if ninja is None:
        raise ValueError("ninja is not installed (https://ninja-build.org; most package managers have it)")
    argv = [ninja, "-f", NINJA, *(["-j", str(jobs)] if jobs else []), *(["-k", str(keep_going)]
                                                                        if keep_going is not None else []), *targets]
    return subprocess.run(argv, cwd=root, stdout=sys.stderr if quiet else None, check=False).returncode


def build(project: Project, repository: str | None = None, only: str | None = None, targets: list[str] = (),
          jobs: int | None = None, keep_going: int | None = None, download: bool = False,
          quiet: bool = False) -> dict[str, Any]:
    """Configure, then run ninja; what was built and where each target's report and link stand."""
    names = build_targets(project, repository, only)
    fetched = ensure_downloads(project, names) if download else []
    configured = configure(project, repository, only)
    code = run_ninja(Path(configured["root"]), list(targets), jobs, keep_going, quiet)
    root = Path(configured["root"])
    for name, row in configured["targets"].items():
        report = root / row["report"] if row["report"] else None
        if report and report.is_file():
            data = json.loads(report.read_text(encoding="utf-8"))
            measures = data.get("measures", {})
            row["progress"] = {key: measures.get(key) for key in (
                "matched_code_percent", "matched_data_percent", "matched_functions", "total_functions",
                "complete_units", "total_units")}
        stamp = root / row["dir"] / "ok"
        row["identical"] = stamp.is_file() if row["link"] else None
    return {**configured, "ok": code == 0, "ninja_exit": code, "downloaded": fetched}


def render(data: dict[str, Any]) -> str:
    lines = [f"downloaded {d['files']} files from {d['url']} into {d['folder']}" for d in data.get("downloaded", [])]
    lines.append(f"wrote {data['ninja']} (default: {' '.join(data['default'])})")
    for name, row in data["targets"].items():
        lines.append(f"{name}: {row['units']:,} units, {row['objects']:,} target objects, {row['compiled']:,} "
                     f"compiled from src/; report: {row['report'] or 'none'}; link: {'yes' if row['link'] else 'no'}")
        lines += [f"  note: {note}" for note in row["notes"]]
        progress = row.get("progress")
        if progress:
            lines.append(f"  matched: code {progress['matched_code_percent'] or 0:.2f}%, data "
                         f"{progress['matched_data_percent'] or 0:.2f}%, functions {progress['matched_functions'] or 0}"
                         f" of {progress['total_functions'] or 0}")
        if row.get("identical") is not None:
            lines.append("  relinked executable: " + ("identical to the original (SHA-1 checked)" if row["identical"]
                                                      else "not checked identical (see the link step above)"))
    if "ninja_exit" in data:
        lines.append("build: ok" if data["ok"] else f"build failed (ninja exit {data['ninja_exit']})")
    return "\n".join(lines)


def health(project: Project, name: str) -> list[tuple[str, str, str, str]]:
    """(status, check, detail, fix) rows `zkit doctor` shows for a target with build settings."""
    target = project.target(name)
    config = settings(target)
    if config is None:
        return []
    root = project.root(target["repository"])
    rows = [("ok" if shutil.which("ninja") else "fail", f"{name}: ninja", shutil.which("ninja") or "not found",
             "install ninja (https://ninja-build.org)")]
    found, wanted = compiler(root, config)
    rows.append(("ok" if found else "warn", f"{name}: compiler", str(found or f"{wanted} missing"),
                 "zkit build --download" if config["platform"] == "gamecube" or config.get("compiler_download")
                 else "set build.compiler (and build.compiler_download to have `zkit build --download` fetch it)"))
    run, needed = wrapper(root, config)
    if needed:
        rows.append(("ok" if run else "warn", f"{name}: wrapper", str(run or f"{config.get('wrapper')} not found"),
                     "zkit build --download   # fetches wibo; or set build.wrapper"))
    tool = objdiff_cli(root, config)
    rows.append(("ok" if tool else "warn", f"{name}: objdiff-cli", str(tool or "not found: no report"),
                 "zkit build --download   # fetches objdiff-cli; or put it on PATH"))
    if config["platform"] == "gamecube":
        from .asmfile import find_m2c
        from .permute import find_permuter
        m2c, permuter = find_m2c(project), find_permuter(project)
        rows.append(("ok" if m2c else "warn", f"{name}: m2c", " ".join(m2c) if m2c else "not found: no seeds",
                     "zkit build --download   # fetches m2c"))
        rows.append(("ok" if permuter else "warn", f"{name}: decomp-permuter", str(permuter or "not found"),
                     "zkit build --download   # fetches decomp-permuter"))
    return rows


# Steps the ninja file runs (python -m zkit.build ...)

def fix_depfile(path: Path, output: str) -> None:
    """Rewrite a dependency file CodeWarrior wrote under wibo or wine (`Z:\\home\\...` with backslashes) into
    POSIX paths, naming the object ninja expects."""
    text = path.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
    deps = []
    for word in text.partition(": ")[2].split():
        word = word.replace("\\", "/")
        deps.append(word[2:] if re.match(r"^[zZ]:/", word) else word)  # wibo and wine map / to Z:
    path.write_text(f"{output}: " + " \\\n  ".join(deps) + "\n", encoding="utf-8")


def check_sha1(path: Path, expected: str, stamp: Path) -> int:
    actual = hashlib.sha1(path.read_bytes()).hexdigest()
    if actual != expected.lower():
        print(f"{path}: SHA-1 {actual}, expected {expected.lower()}", file=sys.stderr)
        stamp.unlink(missing_ok=True)
        return 1
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(actual + "\n", encoding="utf-8")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "depfile":
        fix_depfile(Path(argv[1]), argv[2])
        return 0
    if len(argv) == 4 and argv[0] == "sha1":
        return check_sha1(Path(argv[1]), argv[2], Path(argv[3]))
    print("usage: python -m zkit.build depfile FILE OBJECT | sha1 FILE EXPECTED STAMP", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
