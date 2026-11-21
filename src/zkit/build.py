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
PAGE = "build/progress/index.html"   # `zkit report`'s page of every report
TREEMAP = "build/progress/treemap.html"   # and its treemap, beside it
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
    # The console's facts only: its CPU, position-independent modules, and unwind information for every function
    # (the prologue's CFI fixes where the frame pointer is set up, so code is only reproduced with unwind tables
    # on). A game's own choices (optimization level, exceptions, RTTI, language standard) are its project's.
    "switch": {
        "compiler": "clang++",
        "cflags": ["--target=aarch64-none-elf", "-march=armv8-a+crc+crypto", "-mtune=cortex-a57", "-fPIC",
                   "-fasynchronous-unwind-tables"],
        "includes": ["include", "src"]},
}
# What `zkit new` writes for a game's own choices, to confirm or change with its first matched functions: a release
# build, without exceptions or RTTI.
STARTING_CFLAGS = {"gamecube": [], "switch": ["-O3", "-fno-exceptions", "-fno-rtti", "-std=gnu++17"]}
IMPORTS = "imports.txt"   # beside the target objects of a `relax` target: the module's imported names, one a line
UNIT_KEYS = {"compiler", "cflags", "extra_cflags", "includes", "compiler_version", "source_root", "clang_plugins",
             "clang_patches", "header_patches", "compiler_download", "optimizer", "optimizer_version",
             "optimizer_patches"}
PLUGINS = Path(__file__).parent / "clang_plugins"   # zkit's clang pass plugins (build.clang_plugins)
PATCHES = Path(__file__).parent / "clang_patches"   # zkit's byte patches to official clang releases (build.clang_patches)
HEADER_PATCHES = Path(__file__).parent / "header_patches"   # zkit's edits to official library headers (build.header_patches)


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
    from .platform import platform_name
    platform = platform_name(target)
    for pattern, override in own.get("units", {}).items():
        unknown = set(override) - UNIT_KEYS
        if unknown:
            raise ValueError(f"build.units[{pattern!r}]: unknown setting {', '.join(sorted(unknown))} "
                             f"(per unit: {', '.join(sorted(UNIT_KEYS))})")
    if "trap" in own:
        trap_word(own["trap"], platform)
    return {"platform": platform, **DEFAULTS[platform], **own}


def trap_word(value: Any, platform: str = "switch") -> int:
    """`build.trap` as the instruction word it names: a hex string of 32 bits, on a Switch target."""
    if platform != "switch":
        raise ValueError("build.trap: only a Switch target's compiles write clang's trap (`brk #1`) to rewrite")
    try:
        word = int(value, 16) if isinstance(value, str) else -1
    except ValueError:
        word = -1
    if not 0 <= word <= 0xFFFFFFFF:
        raise ValueError(f"build.trap must be an instruction word in hex, such as \"0x00008002\": got {value!r}")
    return word


def apply_trap(path: Path, value: str) -> int:
    """Write the object's traps as the original's compiler does (`build.trap`, `elf.with_trap`); how many."""
    from .elf import with_trap
    raw = path.read_bytes()
    out, changed = with_trap(raw, trap_word(value))
    if changed:
        path.write_bytes(out)
    return changed


DEP_FLAGS = {"-MMD", "-MD", "-MP", "-M", "-MM"}   # a compile's dependency file: the words that ask for one
DEP_ARGS = {"-MF", "-MT", "-MQ"}                 # and those followed by a value


def stages(command: list[str], backend: list[str]) -> tuple[list[list[str]], Path]:
    """build.optimizer: a Switch compile `command` (the optimizer's own: COMPILER FLAGS... -c SOURCE -o OBJECT) as
    the two compiles it stands for, and the bitcode between them (OBJECT with the suffix `.bc`). The optimizer
    compiles the source with every flag to optimized bitcode; the `backend` compiler makes the object from it with
    the same flags and its own passes off (`-disable-llvm-passes`), so its code generation alone stands where a
    compiler built from one release's optimizer and another's code generator ran. The dependency file is the
    optimizer's, naming the object as its target, as ninja reads it."""
    try:
        at = len(command) - 1 - command[::-1].index("-o")
        source_at = len(command) - 1 - command[::-1].index("-c") + 1
        obj, source = command[at + 1], command[source_at]
    except (ValueError, IndexError):
        raise ValueError(f"build.optimizer: no `-c SOURCE -o OBJECT` in {shlex.join(command)}") from None
    bitcode = Path(obj).with_suffix(".bc")
    first = [*command[:at + 1], bitcode.as_posix(), *command[at + 2:], "-emit-llvm"]
    if any(word in DEP_FLAGS for word in command) and "-MT" not in command and "-MQ" not in command:
        first += ["-MT", obj]
    flags, skip = [], False
    for index, word in enumerate(command[1:], 1):
        if skip:
            skip = False
        elif word in DEP_ARGS or index in (at, source_at - 1):
            skip = True
        elif word not in DEP_FLAGS and index != source_at:
            flags.append(word)
    second = [*backend, *flags, "-Xclang", "-disable-llvm-passes", "-Wno-unused-command-line-argument",
              "-c", "-x", "ir", bitcode.as_posix(), "-o", obj]
    return [first, second], bitcode


def run_compile(command: list[str], backend: list[str] | None = None, trap: str | None = None,
                **options: Any) -> subprocess.CompletedProcess:
    """Run a unit's compile `command` as the build does: with build.optimizer, as its `stages` through `backend`
    (the bitcode removed after), then the object's traps written (`apply_trap`, build.trap). `options` go to
    subprocess.run; captured output joins both stages'."""
    runs, bitcode = stages(command, backend) if backend else ([command], None)
    outputs: list[str] = []
    done = None
    for run in runs:
        done = subprocess.run(run, **options)
        outputs += [done.stdout or "", done.stderr or ""] if options.get("capture_output") else []
        if done.returncode:
            break
    if bitcode is not None:
        workdir = Path(options.get("cwd") or ".")
        (workdir / bitcode).unlink(missing_ok=True)
    if done.returncode == 0 and trap:
        obj = command[len(command) - 1 - command[::-1].index("-o") + 1]
        apply_trap(Path(options.get("cwd") or ".") / obj, trap)
    if outputs:
        done = subprocess.CompletedProcess(done.args, done.returncode, outputs[0][:0].join(outputs), outputs[0][:0])
    return done


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

    @property
    def view(self) -> str:
        return f"{self.dir}/view"


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
    """A tool given as a path (repository-relative or absolute, `~` allowed; on Windows `.exe` may be left off, so
    one project file names it on every system) or a name on PATH."""
    if not value:
        return None
    path = Path(value).expanduser()
    path = path if path.is_absolute() else root / path
    for candidate in (path, path.with_name(path.name + ".exe")) if sys.platform == "win32" and not path.suffix \
            else (path,):
        if candidate.is_file():
            return candidate
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


def plugin_source(name: str) -> Path:
    """build.clang_plugins: the source of zkit's clang plugin `name` (clang_plugins/<name>.cpp, `-` read as `_`)."""
    source = PLUGINS / f"{name.replace('-', '_')}.cpp"
    if not source.is_file():
        known = sorted(path.stem.replace("_", "-") for path in PLUGINS.glob("*.cpp"))
        raise ValueError(f"build.clang_plugins: no plugin {name!r} (zkit has: {', '.join(known)})")
    return source


def plugin_patches(name: str) -> list[dict[str, Any]]:
    """build.clang_plugins: plugin `name`'s rule as byte patches to official clang binaries that can load no plugin
    (clang_plugins/<name>.patches.json): each names the SHA-256 of the binary it fits, its edits (file offset, old
    and new bytes) and the SHA-256 of the result."""
    table = plugin_source(name).with_suffix(".patches.json")
    return json.loads(table.read_text(encoding="utf-8"))["patches"] if table.is_file() else []


def clang_patches(name: str) -> list[dict[str, Any]]:
    """build.clang_patches: zkit's rule `name` (clang_patches/<name>.json, `-` read as `_`), a change to a part of
    clang no plugin reaches, such as one code generation pass, as byte patches to official clang binaries, in
    `plugin_patches`' form."""
    table = PATCHES / f"{name.replace('-', '_')}.json"
    if not table.is_file():
        known = sorted(path.stem.replace("_", "-") for path in PATCHES.glob("*.json"))
        raise ValueError(f"build.clang_patches: no rule {name!r} (zkit has: {', '.join(known) or 'none'})")
    return json.loads(table.read_text(encoding="utf-8"))["patches"]


def header_patches(name: str) -> dict[str, Any]:
    """build.header_patches: zkit's rule `name` (header_patches/<name>.json, `-` read as `_`), a change to one header
    of an official library release that the original's toolchain shipped written otherwise: the header's path as
    the compiler finds it (`file`, such as `vector`) and text edits to exactly the releases' copies (`patches`,
    each picked by the copy's SHA-256: `edits` of `old` text, found once, to `new`, and the result's SHA-256)."""
    table = HEADER_PATCHES / f"{name.replace('-', '_')}.json"
    if not table.is_file():
        known = sorted(path.stem.replace("_", "-") for path in HEADER_PATCHES.glob("*.json"))
        raise ValueError(f"build.header_patches: no rule {name!r} (zkit has: {', '.join(known) or 'none'})")
    return json.loads(table.read_text(encoding="utf-8"))


def patched_headers(root: Path, includes: list[str], rules: list[str]) -> tuple[Path | None, list[str]]:
    """(folder, notes) for build.header_patches: each rule's header, found in the target's `includes` as the
    compiler would (the first folder that has it), with zkit's edits for exactly that copy (its SHA-256 picks the
    patch, each edit's text must be there once, and the result must have the patch's SHA-256), written under
    build/tools/header-patches/<rules>. The folder is searched before the includes, so the compiler reads the
    edited copy and every other header as before; a header that continues the search (`#include_next`) cannot be
    one. Rules on one header apply in turn. A header zkit has no patch for, or none found, keeps the release's
    copy and gets a note; None when no header was edited. The copies are written again when they differ."""
    texts: dict[str, tuple[Path, str]] = {}
    notes: list[str] = []
    for name in rules:
        rule = header_patches(name)
        relative = rule["file"]
        if relative not in texts:
            found = next((root / folder / relative for folder in includes if (root / folder / relative).is_file()),
                         None)
            if found is None:
                notes.append(f"build.header_patches: {name}'s header {relative} is in none of the includes "
                             f"({', '.join(includes)}): units build without it")
                continue
            texts[relative] = (found, found.read_bytes().decode("utf-8"))
        source, text = texts[relative]
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        patch = next((patch for patch in rule["patches"] if patch["sha256"] == digest), None)
        if patch is None:
            notes.append(f"zkit has no patch for {_relative(source, root)} (SHA-256 {digest}) for "
                         f"build.header_patches ({name}): units build with the release's header and may not match")
            continue
        for edit in patch["edits"]:
            if text.count(edit["old"]) != 1:
                raise ValueError(f"build.header_patches: {name}'s edit {edit['old']!r} is not in "
                                 f"{_relative(source, root)} exactly once")
            text = text.replace(edit["old"], edit["new"])
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != patch["patched_sha256"]:
            raise ValueError(f"build.header_patches: {name}'s patch for {_relative(source, root)} gave SHA-256 "
                             f"{digest}, not {patch['patched_sha256']}")
        if "#include_next" in text:
            raise ValueError(f"build.header_patches: {relative} continues the include search (#include_next), so "
                             "an edited copy searched first cannot stand in for it")
        texts[relative] = (source, text)
    edited = {relative: text for relative, (source, text) in texts.items()
              if text != source.read_bytes().decode("utf-8")}
    if not edited:
        return None, notes
    folder = root / "build" / "tools" / "header-patches" / "+".join(name.replace("-", "_") for name in rules)
    for relative, text in edited.items():
        out = folder / relative
        if out.is_file() and out.read_bytes() == text.encode("utf-8"):
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        partial = out.with_name(out.name + ".partial")
        partial.write_bytes(text.encode("utf-8"))
        partial.replace(out)
    return folder, notes


def patched_clang(clang: Path, names: list[str], rules: list[str] = (),
                  setting: str = "build.clang_patches") -> Path | None:
    """A copy of the official `clang` with byte patches applied in turn: first each of the plugins `names` as its
    rule (build.clang_plugins where clang can load no plugin, a Windows clang.exe), then each of zkit's `rules`
    (build.clang_patches, or the `setting` that names them, such as build.optimizer_patches, on every system). Each
    takes zkit's patch for exactly the binary it has then (its SHA-256
    picks the patch, each edit's old bytes are checked, and the result must have the patch's SHA-256); None when
    zkit has no patch for it. The copy lies beside `clang`, so it finds the same resource folder, named
    `<name>-<plugins and rules>` (clang's driver reads its mode from its name without the last `-` part, so a
    clang++ copy is still clang++); it is made once and made again when its bytes are not the expected ones."""
    for name in names:
        plugin_source(name)
    tables = [("build.clang_plugins", name, plugin_patches(name)) for name in names] + \
             [(setting, name, clang_patches(name)) for name in rules]
    patched = bytearray(clang.read_bytes())
    digest = hashlib.sha256(patched).hexdigest()
    for setting, name, patches in tables:
        patch = next((patch for patch in patches if patch["sha256"] == digest), None)
        if patch is None:
            return None
        for edit in patch["edits"]:
            offset, old, new = int(edit["offset"], 16), bytes.fromhex(edit["old"]), bytes.fromhex(edit["new"])
            if len(new) != len(old) or patched[offset:offset + len(old)] != old:
                raise ValueError(f"{setting}: {name}'s patch for {clang} does not fit it at {edit['offset']}")
            patched[offset:offset + len(new)] = new
        digest = hashlib.sha256(patched).hexdigest()
        if digest != patch["patched_sha256"]:
            raise ValueError(f"{setting}: {name}'s patch for {clang} gave SHA-256 {digest}, not "
                             f"{patch['patched_sha256']}")
    tag = "+".join(name.replace("-", "_") for _, name, _ in tables)
    out = clang.with_name(f"{clang.stem}-{tag}{clang.suffix}")
    if out.is_file() and hashlib.sha256(out.read_bytes()).hexdigest() == digest:
        return out
    partial = out.with_name(out.name + ".partial")
    partial.write_bytes(patched)
    shutil.copymode(clang, partial)
    partial.replace(out)
    return out


def clang_plugin(root: Path, clang: Path, name: str) -> Path:
    """build.clang_plugins: zkit's clang plugin `name` (clang_plugins/<name>.cpp) as a shared object built with the
    host C++ compiler ($CXX, else c++) against this clang's own LLVM headers (`<clang>/../../include`, as its
    release archive has them), once per source and LLVM version, into build/tools/clang-plugins. On macOS its LLVM
    symbols are left for clang itself to provide when it loads the plugin (Linux allows that by default), and it is
    built for clang's own architecture (an x86-64 clang, run by Rosetta 2 on an Arm Mac, loads only an x86-64 one)."""
    source = plugin_source(name)
    include = clang.parent.parent / "include"
    version = include / "llvm" / "Config" / "llvm-config.h"
    if not version.is_file():
        raise ValueError(f"build.clang_plugins: {include} has no LLVM headers (a plugin is built against the "
                         "clang's own release archive)")
    digest = hashlib.sha256(source.read_bytes() + version.read_bytes()).hexdigest()[:12]
    out = root / "build" / "tools" / "clang-plugins" / f"{source.stem}-{digest}.so"
    if out.is_file():
        return out
    cxx = os.environ.get("CXX") or shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if not cxx:
        raise ValueError("build.clang_plugins: no host C++ compiler to build the plugin with (set CXX)")
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_suffix(".partial")
    darwin = ["-undefined", "dynamic_lookup", *(["-arch", arch] if (arch := macho_arch(clang)) else [])] \
        if sys.platform == "darwin" else []
    run = subprocess.run([*shlex.split(cxx), "-shared", "-fPIC", "-O2", "-std=c++11", "-fno-rtti", "-w", *darwin,
                          f"-I{include}", "-D__STDC_CONSTANT_MACROS", "-D__STDC_LIMIT_MACROS", str(source),
                          "-o", str(partial)], capture_output=True, text=True)
    if run.returncode != 0:
        partial.unlink(missing_ok=True)
        raise ValueError(f"build.clang_plugins: building {name} failed:\n{run.stderr[-2000:]}")
    partial.replace(out)
    return out


# A thin 64-bit Mach-O executable: its magic, then its CPU type.
MACHO_ARCHES = {0x01000007: "x86_64", 0x0100000C: "arm64"}


def macho_arch(path: Path) -> str | None:
    """The architecture of a thin 64-bit Mach-O executable, or None (another format, or a universal binary)."""
    try:
        with open(path, "rb") as stream:
            head = stream.read(8)
    except OSError:
        return None
    if len(head) < 8 or head[:4] != b"\xcf\xfa\xed\xfe":
        return None
    return MACHO_ARCHES.get(int.from_bytes(head[4:8], "little"))


def ninja_command() -> str:
    """How objdiff runs ninja: by name, unless the ninja found is the one installed with zkit's own Python (in its
    virtual environment), which objdiff, started on its own, would not find on PATH."""
    found = shutil.which("ninja")
    scripts = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")
    if found and sys.prefix != sys.base_prefix and Path(found).resolve().parent == scripts.resolve():
        return str(Path(found).resolve())
    return "ninja"


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
        self.rules: dict[str, tuple] = {}

    def comment(self, text: str) -> None:
        self.lines += [f"# {line}" for line in text.splitlines()]

    def variable(self, name: str, value: str, indent: bool = False) -> None:
        self.lines.append(f"{'  ' if indent else ''}{name} = {value}")

    def rule(self, name: str, command: str, **extra: str) -> None:
        """A rule, written once: a target's rule that another target already wrote (each Switch target's link) is
        the same rule; one by the same name that differs is an error, as ninja would make it."""
        if name in self.rules:
            if self.rules[name] != (command, extra):
                raise ValueError(f"ninja rule {name} defined twice, differently")
            return
        self.rules[name] = (command, extra)
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
    # `trap`: the compile, then its object's traps written as the original's compiler writes them (`apply_trap`)
    ninja.rule("clang_trap", _command(python) + " trap $trap $out $cc $cflags -MMD -MF $out.d -c $in -o $out",
               depfile="$out.d", deps="gcc", description="CC $out")
    # build.optimizer: the optimizer's compile as its two `stages` through $backend, then any trap ($trap, or -)
    ninja.rule("clang_stages", _command(python) + " stages $trap $backend $cc $cflags -MMD -MF $out.d -c $in -o $out",
               depfile="$out.d", deps="gcc", description="CC $out")
    # `source_root`: each unit's copy that names it as the original's build did (`stage`); one step writes every
    # copy whose source changed, restat: an unchanged copy keeps its time, so only a changed unit recompiles
    ninja.rule("rooted", _command(python) + " rooted $in", restat="1", description="ROOTED $in")
    ninja.rule("report", "$objdiff report generate -p $project $args -o $out", description="REPORT $out")
    # restat: a view whose bytes did not change keeps its time, so the report reruns only for a changed one
    ninja.rule("views", _command(python) + " views $list $folders", rspfile="$list", rspfile_content="$in_newline",
               restat="1", description="VIEWS $list")
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
        if original is not None and not original.is_file() and config["platform"] == "switch":
            notes.append(_provide_original(root, name, target, original))
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
            # a target whose linker relaxed address pairs: the delink also lists the module's imports (`views`)
            imports = [f"{paths.obj}/{IMPORTS}"] if config.get("relax") else []
            ninja.build(objects[:1], "delink", [_relative(splits, root), _relative(original, root), *symbols, stamp],
                        order=checked, implicit_outputs=objects[1:] + imports,
                        variables={"target": name, "splits": _command([_relative(splits, root)]),
                                   "outdir": _command([paths.obj])})
        ninja.lines.append("")
        compiled, sources, found, staged = [], set(), {}, []
        for unit in units:
            if not (root / "src" / unit).is_file():
                continue
            step = _compile(root, unit_settings(config, unit), unit, paths, found, notes)
            commands.append({"directory": str(root), "file": f"src/{unit}", "arguments": step["argv"],
                             "output": step["out"]})
            variables = {}
            if config["platform"] == "gamecube":
                basedir = Path(step["out"]).parent.as_posix()
                variables = {"basedir": _command([basedir]), "basefile": _command([f"{basedir}/{Path(unit).stem}"])}
            if step.get("stage"):
                staged.append(step["stage"])
            ninja.build([step["out"]], step["rule"], [step["stage"]["copy"] if step.get("stage") else f"src/{unit}"],
                        implicit=step["implicit"],
                        variables={"cc": _command(step["cc"]), "cflags": _command(step["flags"]),
                                   **step.get("variables", {}), **variables})
            compiled.append(step["out"])
            sources.add(unit)
        if staged:
            manifest = f"{paths.dir}/rooted.json"
            _write(root / manifest, json.dumps(staged, indent=1) + "\n")
            ninja.build([row["copy"] for row in staged], "rooted", [manifest],
                        implicit=[row["source"] for row in staged])
        objdiff = project.file(repository, target.get("objdiff", "objdiff.json"))
        if objdiff in objdiff_files.values():
            raise ValueError(f"Targets {name} and {next(n for n, p in objdiff_files.items() if p == objdiff)} share "
                             f"{objdiff.name}: give each target its own `objdiff` file")
        objdiff_files[name] = objdiff
        wrote = _write(objdiff, write_objdiff(objdiff, root, units, sources, paths,
                                              target.get("module") or name, target.get("categories")))
        uncategorized = [u for u in units if target.get("categories") and not categories_of(u, target["categories"])]
        if uncategorized:
            notes.append(f"{len(uncategorized)} units in no category (first: {uncategorized[0]})")
        report, tool = None, objdiff_cli(root, config)
        if tool and objdiff.name == "objdiff.json":
            report, measured, compared = paths.report, objdiff, compiled
            if config["platform"] == "switch" and compiled:
                # The report compares each compiled object as the link keeps it (`views`): objdiff's project file
                # for it beside the views, objdiff.json itself left on the compiled objects for every other reader.
                measured = root / paths.view / "objdiff.json"
                compared = _views(ninja, paths, sorted(sources), bool(config.get("relax")))
                _write(measured, write_objdiff(measured, root, units, sources, paths, target.get("module") or name,
                                               target.get("categories"), base=paths.view))
            ninja.build([report], "report", implicit=[_relative(measured, root), *objects, *compared,
                                                      _relative(tool, root)], variables={
                "objdiff": _command([_relative(tool, root)]), "project": _command([_relative(measured.parent, root)]),
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
    if groups["report"]:  # the browsable page of every report, current after each build (and link: it marks)
        reported = [name for name in names if summary[name]["report"]]
        ninja.rule("page", _command(zkit) + " report --out build/progress --targets " + _command(reported),
                   description="PAGE $out")
        ninja.build([PAGE, TREEMAP], "page", implicit=groups["report"] + groups["link"])
        groups["progress"] = [PAGE]
        defaults.append(PAGE)
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


def _package_folders(root: Path, target: dict[str, Any], original: Path) -> tuple[list[Path], bool]:
    """(folders, whether their subfolders count) where a Switch target's packages go: its `packages` folder(s) in
    the repository and their subfolders, or else the original's folder and each one above it."""
    from . import nxpackage
    named = target.get("packages")
    if named:
        return [root / folder for folder in ([named] if isinstance(named, str) else named)], True
    return nxpackage.near(root, original), False


def _provide_original(root: Path, name: str, target: dict[str, Any], original: Path) -> str:
    """A Switch original that is missing comes out of the game's packages (.nsp/.xci/.nup) where its target keeps them
    (`_package_folders`), decrypted with prod.keys there or in the user's usual places (`nxpackage`)."""
    from . import nxpackage
    folders, recursive = _package_folders(root, target, original)
    try:
        done = nxpackage.provide(original, target.get("sha1"), folders, recursive=recursive)
    except nxpackage.NotFound as error:
        where = _relative(folders[0] if recursive or len(folders) == 1 else folders[-2], root)
        why = "" if isinstance(error, nxpackage.NoPackages) and "compressed" not in str(error) else f" ({error})"
        raise ValueError(f"Target {name}: the original {target['original']} is missing: put the game's packages "
                         f"(.nsp or .xci: the game and its update, and prod.keys; or a .nup) in {where}/, or run `zkit extract "
                         f"<folder>`{why}") from None
    return f"extracted {target['original']} from {Path(done['package']).name}"


def extract(project: Project, repository: str | None = None, only: str | None = None,
            sources: list[Path] = (), keys: Path | None = None) -> dict[str, Any]:
    """`zkit extract`: each Switch target's missing original out of the game's packages among `sources` (files, or
    folders and their subfolders; default: where `zkit build` looks for them, `_package_folders`)."""
    from . import nxpackage
    from .platform import platform_name
    targets = project.config.get("targets", {})
    if only is not None and only not in targets:
        raise ValueError(f"Unknown target: {only}")
    rows = {}
    for name, target in targets.items():
        if only not in (None, name) or (repository and target["repository"] != repository) or \
                platform_name(target) != "switch" or not target.get("original"):
            continue
        original = project.file(target["repository"], target["original"])
        if original.is_file():
            rows[name] = {"original": target["original"], "present": True}
            continue
        folders, recursive = (list(sources), True) if sources else \
            _package_folders(project.root(target["repository"]), target, original)
        try:
            done = nxpackage.provide(original, target.get("sha1"), folders, [keys] if keys else None,
                                     recursive=recursive)
            rows[name] = {"original": target["original"], **done}
        except nxpackage.NotFound as error:
            rows[name] = {"original": target["original"], "error": str(error)}
    if not rows:
        raise ValueError(f"No Switch target with an `original` in {project.path}")
    return {"targets": rows, "ok": not any("error" in row for row in rows.values())}


def render_extract(data: dict[str, Any]) -> str:
    lines = []
    for name, row in data["targets"].items():
        if row.get("present"):
            lines.append(f"{name}: {row['original']} is already there")
        elif "error" in row:
            lines.append(f"{name}: {row['original']} not extracted: {row['error']}")
        else:
            lines.append(f"{name}: wrote {row['original']} ({row['size']:,} bytes, SHA-1 {row['sha1']}) from "
                         f"{Path(row['package']).name}")
    return "\n".join(lines)


def _pending_archives(root: Path, config: dict[str, Any]) -> list[tuple[dict[str, Any], Path]]:
    from .fetch import pending_archives
    return pending_archives(root, config)


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
        elif config["platform"] == "switch" and (pending := _pending_archives(root, config)):
            raise ValueError(f"build.compiler_download: {pending[0][0]['url']} is not unpacked into {pending[0][1]} "
                             "(`zkit build --download` fetches it)")
        elif config["platform"] == "switch" and config.get("compiler_version"):
            accepted = [config["compiler_version"]] if isinstance(config["compiler_version"], str) \
                else config["compiler_version"]
            says = clang_version(exe)
            if not any(version in says for version in accepted):
                raise ValueError(f"{exe} is not {' or '.join(map(repr, accepted))}: it says {says!r}")
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
    if config.get("optimizer") and config.get("clang_plugins"):
        # a plugin's passes would run in the compiler, whose passes build.optimizer turns off
        raise ValueError(f"{unit}: build.optimizer and build.clang_plugins together: the plugin's passes would run "
                         "in the compiler, which only generates code from the optimizer's bitcode")
    cc = [str(exe) if exe else config["compiler"]]
    implicit = [_relative(exe, root)] if exe else []
    wanted = words(config.get("clang_plugins")) if exe else []
    rules = words(config.get("clang_patches")) if exe else []
    if rules or (wanted and sys.platform == "win32"):
        # A Windows clang.exe exports none of LLVM's symbols, so it can load no plugin: there the plugins' rules
        # are zkit's byte patches, as zkit's clang_patches rules are on every system. Compile with a copy of clang
        # that has them, or, for a clang zkit has no patch for, without them (said once).
        patched = wanted if sys.platform == "win32" else []
        key = f"patched_clang {exe} {' '.join(patched)} / {' '.join(rules)}"
        if key not in found:
            found[key] = patched_clang(exe, patched, rules)
            if found[key] is None:
                digest = hashlib.sha256(exe.read_bytes()).hexdigest()
                if patched:
                    notes.append(f"clang on Windows cannot load plugins, and zkit has no patch for this {exe.name} "
                                 f"(SHA-256 {digest}): units built with build.clang_plugins ({', '.join(patched)}) "
                                 "may not match here (build on Linux or in WSL to match them)")
                if rules:
                    notes.append(f"zkit has no patch for this {exe.name} (SHA-256 {digest}) for build.clang_patches "
                                 f"({', '.join(rules)}): units built with them compile with the official binary and "
                                 "may not match here")
        if found[key] is not None:
            cc, implicit = [str(found[key])], [_relative(found[key], root)]
        if sys.platform == "win32":
            wanted = []
    plugins = [clang_plugin(root, exe, name) for name in wanted]
    implicit += [_relative(path, root) for path in plugins]
    config = {**config, "extra_cflags": config["extra_cflags"] + [word for path in plugins for word in
                                                                  ("-Xclang", "-load", "-Xclang", path.as_posix())]}
    headers = words(config.get("header_patches"))
    if headers:
        key = f"patched_headers {' '.join(includes)} / {' '.join(headers)}"
        if key not in found:
            found[key], said = patched_headers(root, includes, headers)
            notes.extend(said)
        if found[key] is not None:
            includes = [_relative(found[key], root), *includes]
    named = original_name(config, unit)
    # `source_root`: ninja compiles a copy that names the source as the original's build did (`stage`), with the
    # source's own folder searched first for quoted includes, as the source's would be. argv (compile_commands.json,
    # editors, `zkit try`) compiles the source itself: the same object but for `__FILE__`.
    quoted = ["-iquote", Path(source).parent.as_posix()] if named else []
    flags = words(config["cflags"]) + quoted + [f"-I{folder}" for folder in includes] + config["extra_cflags"]
    step = {"rule": "clang", "cc": cc, "flags": flags, "argv": [*cc, *flags, "-c", source, "-o", out], "out": out,
            "implicit": implicit}
    if config.get("optimizer"):
        # build.optimizer: the optimizer compiles the source to optimized bitcode and the compiler (with its
        # clang_patches) makes the object from it (`stages`). argv (compile_commands.json, editors, `zkit try`)
        # is the optimizer's own command, the source's front end; `backend` the compiler's words.
        exe = _optimizer(root, config, found, notes)
        front = [str(exe) if exe else config["optimizer"]]
        step.update(rule="clang_stages", cc=front, argv=[*front, *flags, "-c", source, "-o", out], backend=cc,
                    implicit=implicit + ([_relative(exe, root)] if exe else []),
                    variables={"backend": _command(cc), "trap": _command([config.get("trap") or "-"])})
    elif config.get("trap"):   # argv (compile_commands.json, editors) stays the compiler's own command
        step.update(rule="clang_trap", variables={"trap": _command([config["trap"]])})
    if named:
        step["stage"] = {"source": source, "named": named, "copy": f"{paths.dir}/rooted/{unit}"}
    return step


def _optimizer(root: Path, config: dict[str, Any], found: dict[str, Path | None], notes: list[str]) -> Path | None:
    """build.optimizer: the optimizer's executable (None when not found, said once), checked once against
    build.optimizer_version as the compiler is against build.compiler_version. build.optimizer_patches names zkit's
    clang_patches rules for a part of the optimizer (such as one optimization pass) the original's differed in: the
    executable is then a patched copy beside the official one, as for the compiler's build.clang_patches, or the
    official one for a binary zkit has no patch for (said once)."""
    rules = words(config.get("optimizer_patches"))
    key = f"optimizer {config['optimizer']} / {' '.join(rules)}"
    if key not in found:
        exe = _tool(root, config["optimizer"])
        if exe is None:
            notes.append(f"optimizer not found: {config['optimizer']} (set build.optimizer, or pin its archive in "
                         "build.compiler_download for `zkit build --download`)")
        elif config.get("optimizer_version"):
            accepted = [config["optimizer_version"]] if isinstance(config["optimizer_version"], str) \
                else config["optimizer_version"]
            says = clang_version(exe)
            if not any(version in says for version in accepted):
                raise ValueError(f"{exe} is not {' or '.join(map(repr, accepted))}: it says {says!r}")
        if exe is not None and rules:
            patched = patched_clang(exe, [], rules, "build.optimizer_patches")
            if patched is None:
                digest = hashlib.sha256(exe.read_bytes()).hexdigest()
                notes.append(f"zkit has no patch for this {exe.name} (SHA-256 {digest}) for build.optimizer_patches "
                             f"({', '.join(rules)}): units built with them optimize with the official binary and may "
                             "not match here")
            exe = patched or exe
        found[key] = exe
    return found[key]


def original_name(config: dict[str, Any], unit: str) -> str | None:
    """The unit's path as the original's build named it, which its `__FILE__` strings cite: `<source_root>/<unit>`
    (e.g. `D:/Studio/Game/prog/game/Player.cpp`); None without `source_root`."""
    original = (config.get("source_root") or "").strip("/")
    return f"{original}/{unit}" if original else None


def stage(source: bytes, named: str) -> bytes:
    """The source as a file named `named`: a `#line` directive first (after any byte-order mark), so `__FILE__`
    and `__LINE__` read as in the original's build, from any folder, on any system."""
    mark = b"\xef\xbb\xbf" if source.startswith(b"\xef\xbb\xbf") else b""
    quoted = named.replace("\\", "\\\\").replace('"', '\\"')
    return mark + f'#line 1 "{quoted}"\n'.encode() + source[len(mark):]


def write_staged(rows: list[dict[str, str]]) -> int:
    """Write each row's `stage` copy whose bytes differ; the number written."""
    written = 0
    for row in rows:
        data = stage(Path(row["source"]).read_bytes(), row["named"])
        copy = Path(row["copy"])
        if copy.is_file() and copy.read_bytes() == data:
            continue
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(data)
        written += 1
    return written


def categories_of(unit: str, categories: list[dict[str, Any]]) -> list[str]:
    """The ids of the target's progress categories a unit (its path under `src/`) is in: each category whose
    `paths` globs match it (`*` crosses folders; a pattern ending in `/` takes the folder's whole tree)."""
    return [c["id"] for c in categories
            if any(fnmatch.fnmatchcase(unit, p + "*" if p.endswith("/") else p) for p in c.get("paths", []))]


def _views(ninja: Ninja, paths: Layout, units: list[str], relax: bool = False) -> list[str]:
    """One edge writes each compiled unit's view (`write_views`) from its compiled and target objects (and, for a
    target whose linker relaxed address pairs, the module's imports the delink lists)."""
    views = [f"{paths.view}/{stem(u)}.o" for u in units]
    imports = [f"{paths.obj}/{IMPORTS}"] if relax else []
    ninja.build(views, "views", [f"{paths.src}/{stem(u)}.o" for u in units],
                implicit=[f"{paths.obj}/{stem(u)}.o" for u in units] + imports, variables={
                    "list": _command([f"{paths.view}.rsp"]),
                    "folders": _command([paths.src, paths.obj, paths.view, *imports])})
    return views


def write_views(rows: list[tuple[Path, Path, Path]], imports: set[str] | None = None) -> int:
    """Each compiled object as the link keeps it, for the report: COMDAT groups of data whose signature its unit's
    target object does not define are the copy another unit owns (`elf.without_foreign_data`), so a weak inline
    static or template vtable that the link deduplicates is not scored as this unit's data. objdiff has no switch
    for it: it combines a unit's .bss.* / .data.* sections and pairs data by name, else by each symbol's offset
    and size, so an extra copy shifts or outnumbers the unit's own. With `imports` (a target whose linker relaxed
    address pairs, `relax`: the module's imported names), each GOT load the linker turned into `adrp` + `add` is
    written so (`elf.with_got_loads_relaxed`). Writes a view only when its bytes change; returns how many it
    wrote."""
    from .elf import Elf, with_got_loads_relaxed, without_foreign_data
    written = 0
    for target, compiled, view in rows:
        raw = compiled.read_bytes()
        if target.is_file():
            elf = Elf.load(target)
            owned = {s.name for s in elf.symbols if 0 < s.section < 0xFF00 and s.kind not in ("section", "file")}
            raw = without_foreign_data(raw, owned)[0]
        if imports is not None:
            raw = with_got_loads_relaxed(raw, imports)[0]
        if view.is_file() and view.read_bytes() == raw:
            continue
        view.parent.mkdir(parents=True, exist_ok=True)
        view.write_bytes(raw)
        written += 1
    return written


def write_objdiff(path: Path, root: Path, units: list[str], compiled: set[str], paths: Layout,
                  module: str = "main", categories: list[dict[str, Any]] | None = None,
                  base: str | None = None) -> str:
    """objdiff's project file: each unit's target object, and its compiled one when it has a source (objdiff
    refuses a base object that does not exist), and the module it links into, so a unit that moves to another
    folder keeps its functions' place in the report. Paths are relative to the file's folder; objdiff rebuilds a
    compiled object with `ninja -f build/build.ninja <object>`. `categories` (the target's: `{id, name, paths}`)
    become objdiff's progress categories, each unit in those its path matches. `base`: the folder of the compiled
    objects (the build's src/ folder, else the views the report compares)."""
    folder = path.parent
    relative = lambda p: os.path.relpath(root / p, folder).replace(os.sep, "/")
    rows = []
    for unit in units:
        row: dict[str, Any] = {"name": stem(unit), "target_path": relative(f"{paths.obj}/{stem(unit)}.o")}
        if unit in compiled:
            row["base_path"] = relative(f"{base or paths.src}/{stem(unit)}.o")
        row["metadata"] = {"source_path": f"src/{unit}", "module_name": module}
        if categories:
            row["metadata"]["progress_categories"] = categories_of(unit, categories)
        rows.append(row)
    config: dict[str, Any] = {"min_version": "2.0.0", "custom_make": ninja_command(),
                              "custom_args": ["-f", os.path.relpath(root / NINJA, folder).replace(os.sep, "/")],
                              "build_target": False, "build_base": True,
                              "watch_patterns": ["*.c", "*.cp", "*.cpp", "*.h", "*.hpp", "*.inc"]}
    if categories:
        config["progress_categories"] = [{"id": c["id"], "name": c.get("name") or c["id"]} for c in categories]
    return json.dumps({**config, "units": rows}, indent=1) + "\n"


def _link(ninja: Ninja, project: Project, name: str, target: dict[str, Any], config: dict[str, Any], root: Path,
          paths: Layout, inputs: list[str], notes: list[str], zkit: list[str]) -> list[str]:
    """The link and its check. GameCube: `zkit link` relinks the executable from delinked and compiled objects
    with the project's mwld, then the DOL's SHA-1 is compared with the pinned one ([DOL, check stamp]). Switch:
    `zkit link` places the compiled objects into the original module, proves it identical (segment SHA-256s) and
    marks the units it proves linked in the report ([NSO, its link.json]). [] when there is nothing to link."""
    if config["platform"] == "switch":
        if not paths.report or not any(i == paths.report for i in inputs):
            notes.append("no link: it reads the report, and there is none")
            return []
        module = target.get("module") or name
        ninja.rule("zkit_nxlink", _command(zkit) + " --target $target link --out $outdir",
                   description="ZKIT LINK $target")
        nso, record = f"{paths.link}/{module}.nso", f"{paths.link}/link.json"
        splits = _relative(project.file(target["repository"], target["splits"]), root)
        ninja.build([nso], "zkit_nxlink", implicit=[splits, *inputs], implicit_outputs=[record],
                    variables={"target": name, "outdir": _command([paths.link])})
        return [nso]
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


def ensure_downloads(project: Project, names: list[str], analysis: bool = True) -> list[dict[str, Any]]:
    """--download: the compiler bundle where a compiler is missing, then every pinned tool a target lacks (only
    those building needs without `analysis`: --download-build-tools)."""
    from .fetch import ensure
    return ensure_compilers(project, names) + ensure(project, names, analysis)


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
          quiet: bool = False, analysis: bool = True) -> dict[str, Any]:
    """Configure, then run ninja; what was built and where each target's report and link stand."""
    names = build_targets(project, repository, only)
    fetched = ensure_downloads(project, names, analysis) if download else []
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
        stamp, record = root / row["dir"] / "ok", root / row["dir"] / "link" / "link.json"
        row["identical"] = stamp.is_file() if row["link"] else None
        if row["link"] and record.is_file():   # Switch: the link's own record
            linked = json.loads(record.read_text(encoding="utf-8"))
            row["identical"] = linked.get("identical")
            row["linked_units"] = len(linked.get("linked_units", []))
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
        if row.get("identical") is not None and "linked_units" in row:
            lines.append("  rebuilt module: " + ("identical to the original (segment SHA-256s checked)"
                                                 if row["identical"] else "NOT identical (see the link step above)")
                         + f"; {row['linked_units']} units linked from source")
        elif row.get("identical") is not None:
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
    record = root / layout(name, target).dir / "link" / "link.json"
    if config["platform"] == "switch" and record.is_file():   # the last build's link
        linked = json.loads(record.read_text(encoding="utf-8"))
        rows.append(("ok" if linked.get("identical") else "fail", f"{name}: rebuilt module",
                     ("identical to the original" if linked.get("identical") else "NOT identical to the original")
                     + f"; {len(linked.get('linked_units', []))} units linked from source",
                     "zkit link --out build/<dir>/link   # says where it differs"))
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
    if len(argv) in (5, 6) and argv[0] == "views":   # LIST: the compiled objects under SRC, one per line;
        src, obj, view = (Path(a) for a in argv[2:5])    # IMPORTS: the module's imported names (`relax`)
        compiled = [Path(line) for line in Path(argv[1]).read_text(encoding="utf-8").splitlines() if line.strip()]
        imports = set(Path(argv[5]).read_text(encoding="utf-8").split()) if len(argv) == 6 else None
        write_views([(obj / c.relative_to(src), c, view / c.relative_to(src)) for c in compiled], imports)
        return 0
    if len(argv) > 3 and argv[0] == "trap":   # WORD OBJECT COMMAND...: compile, then `apply_trap`
        done = subprocess.run(argv[3:])
        if done.returncode == 0:
            apply_trap(Path(argv[2]), argv[1])
        return done.returncode
    if len(argv) > 3 and argv[0] == "stages":   # TRAP BACKEND COMMAND...: build.optimizer's `run_compile`
        return run_compile(argv[3:], [argv[2]], None if argv[1] == "-" else argv[1]).returncode
    if len(argv) == 2 and argv[0] == "rooted":  # MANIFEST: configure's list of `stage` copies
        write_staged(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
        return 0
    print("usage: python -m zkit.build depfile FILE OBJECT | sha1 FILE EXPECTED STAMP | "
          "views LIST SRC OBJ VIEW [IMPORTS] | rooted MANIFEST | trap WORD OBJECT COMMAND... | "
          "stages TRAP BACKEND COMMAND...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
