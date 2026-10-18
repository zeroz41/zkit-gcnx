"""The external tools zkit runs, fetched on request into a repository's build/ folder (never committed).

`zkit build --download` (and `zkit configure --download`) fetches each tool a target needs that is found nowhere
else. Every target: objdiff-cli (the report). GameCube: wibo (runs the Windows CodeWarrior compilers on Linux and
macOS), GNU binutils for powerpc-eabi (disassembly), m2c (the seed to match from) and decomp-permuter
(register-allocation near-misses). Switch: LLVM's llvm-objdump and llvm-cxxfilt (disassembly and demangling), and
the matching clang when the project pins its archive (`build.compiler_download`: the exact toolchain a game was
built with is the project's evidence, so zkit never picks one). A tool set in the project file, or already on PATH,
is used as it is and never fetched.

Every download is pinned: a release asset is refused unless its SHA-256 is the one recorded here (the digest GitHub
publishes for the asset) or in the project file, and a source checkout is refused unless git resolves it to the
pinned commit. `build/tools/versions.json` records what was fetched, so a newer zkit that pins a newer version
fetches it again.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

TOOLS_DIR = "build/tools"
BINUTILS_DIR = "build/binutils"
LLVM_DIR = "build/llvm"
VERSIONS = f"{TOOLS_DIR}/versions.json"


@dataclass(frozen=True)
class Tool:
    """One pinned tool. kind 'file' (a single executable), 'archive' (a zip or tarball unpacked into `folder`,
    only the `members` it lists when it lists some) or 'git' (a source checkout at `version`, a commit). `assets`
    maps a host (`host()`) to (asset name, SHA-256)."""
    name: str
    kind: str
    version: str
    source: str  # release download base (file, zip) or git repository URL
    assets: dict[str, tuple[str, str]] = field(default_factory=dict)
    marker: str = ""  # git, archive: the file a usable copy has
    folder: str = ""  # archive: where it is unpacked
    members: tuple[str, ...] = ()  # archive: glob patterns of the files to keep (top folder stripped)

    def destination(self, root: Path) -> Path:
        if self.kind == "archive":
            return root / self.folder
        suffix = ".exe" if self.kind == "file" and os.name == "nt" else ""
        return root / TOOLS_DIR / (self.name + suffix)


TOOLS: dict[str, Tool] = {tool.name: tool for tool in (
    Tool("wibo", "file", "1.2.0", "https://github.com/decompals/wibo/releases/download/1.2.0", {
        "linux-x86_64": ("wibo-x86_64", "13f86a2d618f0dbe67179d349625345eabf9b46450295cb4c904e49f6aff85af"),
        "linux-i686": ("wibo-i686", "2575d3b0a2f408b2c2b0850db56f1af5d005a138394a6774eba77b6708ecc304"),
        "macos-arm64": ("wibo-macos", "2b3000ef6a7a490c24ccd71967735ae0005e218922e51806cca1b8d77fd3cf7c"),
        "macos-x86_64": ("wibo-macos", "2b3000ef6a7a490c24ccd71967735ae0005e218922e51806cca1b8d77fd3cf7c")}),
    Tool("objdiff-cli", "file", "v3.8.2", "https://github.com/encounter/objdiff/releases/download/v3.8.2", {
        "linux-x86_64": ("objdiff-cli-linux-x86_64",
                         "e5445089a6f707e30cb5e02992451b604619cedfd2660ee2373a86bfefd9e718"),
        "linux-i686": ("objdiff-cli-linux-i686", "95430defe6e4a8b12553d823f88b34fa451e504cfb1a2f25d28ace0d464aeabc"),
        "linux-aarch64": ("objdiff-cli-linux-aarch64",
                          "087516e73e1b3223b39974f00bc2810fea5c3dc2c93a8e1f06442ec68acaacb4"),
        "macos-arm64": ("objdiff-cli-macos-arm64", "767c67e13b7b5e6ca545e7d2235e47c7bceac07d47a52776f74a52914cb4085a"),
        "macos-x86_64": ("objdiff-cli-macos-x86_64",
                         "2cfe0f46fc84cef7d96813f100a0f01fbf99ac7e423b7fda1d314aada4d5ff72"),
        "windows-x86_64": ("objdiff-cli-windows-x86_64.exe",
                           "36d229ac6ce74a26b47f42cf86ea8e808d8cd834a54aa62d7ed3f47b765d971b"),
        "windows-arm64": ("objdiff-cli-windows-arm64.exe",
                          "c4fed8851366859e69499bfd1fed7f026169602833d3032708329809f307f7d0")}),
    Tool("binutils", "archive", "2.42-2", "https://github.com/encounter/gc-wii-binutils/releases/download/2.42-2", {
        "linux-x86_64": ("linux-x86_64.zip", "64e4bf7aee5c06075d8fa818ebd2a0a3a72e0eeef3896bdec2f198b0e950fe63"),
        "linux-i686": ("linux-i686.zip", "4a7f728db87e71917326e6a416298a506b3360837b3fd6ed6223393bb2557207"),
        "linux-aarch64": ("linux-aarch64.zip", "41e70c39adf0dc588d5909691f9b9f1c0372002be485191eda581bf498866723"),
        "macos-arm64": ("macos-universal.zip", "c40bad23fd7d9eb22d4533875922fc19785ed067978b605804e345bc6e62449d"),
        "macos-x86_64": ("macos-universal.zip", "c40bad23fd7d9eb22d4533875922fc19785ed067978b605804e345bc6e62449d"),
        "windows-x86_64": ("windows-x86_64.zip",
                           "bd95bd57607efb45c437e97b77ec199073e242869027eb72196b0720611bb1c1")},
         folder=BINUTILS_DIR),
    # The full LLVM release (1.5-2 GB to download); only the tools zkit runs and the libraries they load are kept.
    Tool("llvm", "archive", "23.1.3", "https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3", {
        "linux-x86_64": ("LLVM-23.1.3-Linux-X64.tar.xz",
                         "ca9fe385a5d9e2d88132dc0e23a00e9f87f38fa75f67207b5e457d208e71d013"),
        "linux-aarch64": ("LLVM-23.1.3-Linux-ARM64.tar.xz",
                          "56d005e339c979a696ed6c244e6472e16f3b1371e48987a07e6145bda7ee0d03"),
        "macos-arm64": ("LLVM-23.1.3-macOS-ARM64.tar.xz",
                        "3dcfd88aec10be204a24037bcb0dc0ad777882e9dbe8ac60e2639060d8a794b1"),
        "windows-x86_64": ("clang+llvm-23.1.3-x86_64-pc-windows-msvc.tar.xz",
                           "9ee6a2192fbb30c776415af529927f76ca6b5d1d55699bb1315f9878e610b5b8"),
        "windows-arm64": ("clang+llvm-23.1.3-aarch64-pc-windows-msvc.tar.xz",
                          "4a42903db59f990a10c245eb32999f1e3247c37ba66de87f8f8dc2338ed9a79b")},
         folder=LLVM_DIR, marker="bin/llvm-objdump",
         members=("bin/llvm-objdump*", "bin/llvm-cxxfilt*", "lib/libLLVM*", "lib/*/libLLVM*", "bin/*.dll")),
    Tool("m2c", "git", "708d2d2cb2698f091a92492b328f73b24209f72d", "https://github.com/matt-kempster/m2c.git",
         marker="m2c.py"),
    Tool("decomp-permuter", "git", "8556c81d80d1c1af98a858c8f4dc951357f29139",
         "https://github.com/simonlindholm/decomp-permuter.git", marker="permuter.py"),
)}


def host() -> str:
    """This machine as the release assets name it: linux-x86_64, macos-arm64, windows-x86_64, ..."""
    system = {"linux": "linux", "darwin": "macos", "win32": "windows"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "x64": "x86_64", "i386": "i686", "i586": "i686", "x86": "i686",
               "arm64": "arm64" if system != "linux" else "aarch64", "aarch64": "aarch64" if system == "linux"
               else "arm64"}.get(machine, machine)
    return f"{system}-{machine}"


def managed(root: Path, name: str) -> Path | None:
    """The executable (file), folder (zip) or checkout (git) of a tool fetched into root, if it is there."""
    tool = TOOLS[name]
    path = tool.destination(root)
    if tool.kind == "file":
        return path if path.is_file() else None
    if tool.marker:
        marker = path / tool.marker
        return path if marker.is_file() or marker.with_suffix(".exe").is_file() else None
    return path if path.is_dir() and any(path.iterdir()) else None


def _versions(root: Path) -> dict[str, str]:
    try:
        return json.loads((root / VERSIONS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def current(root: Path, name: str) -> bool:
    """The tool is fetched into root at the version this zkit pins."""
    return managed(root, name) is not None and _versions(root).get(name) == TOOLS[name].version


def download(url: str, sha256: str, directory: Path) -> Path:
    """Fetch url into a temporary file in directory; refuse it (and remove it) unless its SHA-256 is sha256."""
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with tempfile.NamedTemporaryFile(dir=directory, suffix=".part", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "zkit"})
            with urllib.request.urlopen(request, timeout=120) as response:
                for block in iter(lambda: response.read(1 << 20), b""):
                    digest.update(block)
                    stream.write(block)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    if digest.hexdigest() != sha256:
        temporary.unlink(missing_ok=True)
        raise ValueError(f"{url} has SHA-256 {digest.hexdigest()}, not {sha256}: refusing it")
    return temporary


def unpack(archive_path: Path, folder: Path, source: str, members: tuple[str, ...] = (), strip: int = 0) -> int:
    """Unpack a zip or tarball into folder (never outside it), every file executable; the number of files. `strip`
    drops that many leading folders from each path (tar's --strip-components); with `members`, only the files
    matching those globs (after stripping) are kept. A tarball is read once, in order (an xz stream)."""
    folder.mkdir(parents=True, exist_ok=True)
    count = 0
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                destination = _destination(folder, member.filename, strip, members, source)
                if destination is None or member.is_dir():
                    continue
                with archive.open(member) as stream, destination.open("wb") as out:
                    shutil.copyfileobj(stream, out, 1 << 20)
                destination.chmod(0o755)
                count += 1
        return count
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            destination = _destination(folder, member.name, strip, members, source)
            if destination is None or not (member.isfile() or member.issym()):
                continue
            if member.issym():
                if not (destination.parent / member.linkname).resolve().is_relative_to(folder.resolve()):
                    raise ValueError(f"{source}: {member.name} links outside {folder}")
                destination.unlink(missing_ok=True)
                destination.symlink_to(member.linkname)
            else:
                with archive.extractfile(member) as stream, destination.open("wb") as out:
                    shutil.copyfileobj(stream, out, 1 << 20)
                destination.chmod(0o755)
            count += 1
    return count


def _destination(folder: Path, name: str, strip: int, members: tuple[str, ...], source: str) -> Path | None:
    """Where an archive member goes (its parent folder made), or None when it is stripped away or not kept."""
    parts = [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")][strip:]
    if not parts or (members and not any(fnmatchcase("/".join(parts), pattern) for pattern in members)):
        return None
    destination = folder.joinpath(*parts)
    if not destination.resolve().is_relative_to(folder.resolve()):
        raise ValueError(f"{source}: {name} would land outside {folder}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def unzip(archive_path: Path, folder: Path, source: str) -> int:
    """A zip unpacked as it is (the compiler bundle's layout)."""
    return unpack(archive_path, folder, source)


def _checkout(tool: Tool, destination: Path) -> int:
    """A shallow checkout of the pinned commit, refused unless git resolves it to that commit."""
    git = shutil.which("git")
    if git is None:
        raise ValueError(f"{tool.name}: git is not installed (https://git-scm.com)")
    destination.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=destination.parent, prefix=f".{tool.name}-"))
    try:
        for argv in (["init", "-q"], ["fetch", "-q", "--depth", "1", tool.source, tool.version],
                     ["-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"]):
            result = subprocess.run([git, "-C", str(work), *argv], capture_output=True, text=True, timeout=600)
            if result.returncode:
                raise ValueError(f"{tool.name}: git {' '.join(argv[:2])} failed: {result.stderr.strip()}")
        head = subprocess.run([git, "-C", str(work), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
        if head != tool.version or not (work / tool.marker).is_file():
            raise ValueError(f"{tool.source} gave {head}, not {tool.version}: refusing it")
        if destination.exists():
            shutil.rmtree(destination)
        work.rename(destination)
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
    return sum(1 for path in destination.rglob("*") if path.is_file() and ".git" not in path.parts)


def _record(root: Path, name: str, version: str) -> None:
    versions = {**_versions(root), name: version}
    (root / VERSIONS).parent.mkdir(parents=True, exist_ok=True)
    (root / VERSIONS).write_text(json.dumps(versions, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def fetch(root: Path, name: str, place: str | None = None) -> dict[str, Any]:
    """Fetch one pinned tool into root's build folder (replacing an older fetched version)."""
    tool = TOOLS[name]
    destination = tool.destination(root)
    if tool.kind == "git":
        files, url = _checkout(tool, destination), f"{tool.source}@{tool.version[:12]}"
    else:
        place = place or host()
        if place not in tool.assets:
            raise ValueError(f"{tool.name} {tool.version} has no build for {place}: install it yourself (on PATH, "
                             "or set it in the project file)")
        asset, sha256 = tool.assets[place]
        url = f"{tool.source}/{asset}"
        temporary = download(url, sha256, destination.parent)
        try:
            if tool.kind == "file":
                temporary.chmod(0o755)
                temporary.replace(destination)
                files = 1
            else:
                if destination.exists():
                    shutil.rmtree(destination)
                files = unpack(temporary, destination, url, tool.members, strip=1 if tool.members else 0)
        finally:
            temporary.unlink(missing_ok=True)
        if tool.marker and managed(root, name) is None:
            raise ValueError(f"{url} unpacked without {tool.marker}")
    _record(root, name, tool.version)
    if name == "llvm":
        saved_llvm_path().parent.mkdir(parents=True, exist_ok=True)
        saved_llvm_path().write_text(str(destination / "bin") + "\n", encoding="utf-8")
    return {"tool": name, "version": tool.version, "url": url, "folder": str(destination), "files": files}


def saved_llvm_path() -> Path:
    """Where the bin folder of the last LLVM fetched is recorded, for tools that run without a project."""
    from .paths import config_home
    return config_home() / "llvm"


def llvm_tool(name: str) -> str | None:
    """An LLVM tool (llvm-objdump, llvm-cxxfilt): on PATH, else in the LLVM `--download` fetched."""
    found = shutil.which(name)
    if found:
        return found
    try:
        folder = Path(saved_llvm_path().read_text(encoding="utf-8").strip())
    except OSError:
        return None
    for candidate in (folder / name, folder / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return None


def compiler_archive(root: Path, config: dict[str, Any]) -> dict[str, Any] | None:
    """`build.compiler_download` ({url, sha256, folder?, strip?}): the project's own pinned compiler archive, fetched
    into `folder` (default build/compilers/<archive name>) when the configured compiler is missing."""
    spec = config.get("compiler_download")
    if not spec:
        return None
    if not isinstance(spec, dict) or not spec.get("url") or not spec.get("sha256"):
        raise ValueError("build.compiler_download needs `url` and `sha256` (and optionally `folder`, `strip`)")
    from .build import compiler
    if compiler(root, config)[0] is not None:
        return None
    url = spec["url"]
    stem = url.rstrip("/").rsplit("/", 1)[-1]
    for suffix in (".tar.xz", ".tar.gz", ".tar.bz2", ".tgz", ".zip"):
        stem = stem.removesuffix(suffix)
    folder = Path(spec.get("folder") or f"build/compilers/{stem}").expanduser()
    folder = folder if folder.is_absolute() else root / folder
    temporary = download(url, spec["sha256"].lower().removeprefix("sha256:"), folder.parent)
    try:
        files = unpack(temporary, folder, url, strip=int(spec.get("strip", 1)))
    finally:
        temporary.unlink(missing_ok=True)
    if compiler(root, config)[0] is None:
        raise ValueError(f"{url} unpacked into {folder}, but the configured compiler {config['compiler']} is still "
                         "not there: point build.compiler at it")
    return {"tool": "compiler", "url": url, "folder": str(folder), "files": files}


def needed(project, name: str) -> list[str]:
    """The tools a target needs that are found nowhere else (or were fetched at an older version)."""
    from . import build
    from .platform import for_target
    target = project.target(name)
    config = build.settings(target)
    root = project.root(target["repository"])
    found: dict[str, Any] = {}
    if config is not None and not config.get("objdiff_cli"):
        found["objdiff-cli"] = build.objdiff_cli(root, config)
    if for_target(target).name == "switch":
        mine = managed(root, "llvm")
        for program in ("llvm-objdump", "llvm-cxxfilt"):
            path = shutil.which(program) or (str(mine / "bin" / program) if mine else None)
            found.setdefault("llvm", path if path and Path(path).exists() else None)
    else:
        from .asmfile import find_m2c
        from .inspect_dol import _objdump
        from .permute import find_permuter
        if config is not None and os.name != "nt" and config.get("wrapper") in (None, "wibo"):
            found["wibo"] = build.wrapper(root, config)[0]
        found["binutils"] = _objdump(project)
        found["m2c"] = find_m2c(project)
        found["decomp-permuter"] = find_permuter(project)
    wanted = []
    for tool, path in found.items():
        mine = managed(root, tool)
        if path is None or (mine is not None and not current(root, tool) and _same(path, mine)):
            wanted.append(tool)
    return wanted


def _same(found: Any, mine: Path) -> bool:
    """The located tool is the fetched copy (m2c is located as an argv, binutils as the objdump inside)."""
    text = found[-1] if isinstance(found, list) else str(found)
    try:
        return Path(text).resolve().is_relative_to(mine.resolve())
    except OSError:
        return False


def ensure(project, names: list[str]) -> list[dict[str, Any]]:
    """--download: each target's own pinned compiler archive when its compiler is missing, then every missing tool,
    once per repository."""
    from .build import settings
    fetched, done = [], set()
    for name in names:
        target = project.target(name)
        root = project.root(target["repository"])
        config = settings(target)
        if config is not None and config["platform"] == "switch":
            result = compiler_archive(root, config)
            fetched += [result] if result else []
        for tool in needed(project, name):
            if (root, tool) in done:
                continue
            fetched.append(fetch(root, tool))
            done.add((root, tool))
    return fetched
