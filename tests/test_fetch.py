import support  # noqa: F401  (isolates config, cache and state)
import dataclasses
import hashlib
import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from zkit import fetch

GIT = shutil.which("git")


def _tarball(path: Path, files: dict[str, bytes]) -> str:
    with tarfile.open(path, "w:xz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class UnpackTests(unittest.TestCase):
    def test_tarball_strips_its_top_folder_and_keeps_only_the_listed_members(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _tarball(root / "llvm.tar.xz", {"LLVM-1/bin/llvm-objdump": b"od", "LLVM-1/bin/clang": b"cc",
                                            "LLVM-1/lib/libLLVM.so.1": b"so", "LLVM-1/include/x.h": b"h"})
            count = fetch.unpack(root / "llvm.tar.xz", root / "out", "llvm", ("bin/llvm-objdump*", "lib/libLLVM*"),
                                 strip=1)
            self.assertEqual(count, 2)
            self.assertEqual(sorted(str(p.relative_to(root / "out")) for p in (root / "out").rglob("*")
                                    if p.is_file()), ["bin/llvm-objdump", "lib/libLLVM.so.1"])

    def test_archives_never_write_outside_their_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _tarball(root / "bad.tar.xz", {"../escape": b"x"})
            with self.assertRaisesRegex(ValueError, "outside"):
                fetch.unpack(root / "bad.tar.xz", root / "out", "bad")
            with zipfile.ZipFile(root / "bad.zip", "w") as archive:
                archive.writestr("../escape", b"x")
            with self.assertRaisesRegex(ValueError, "outside"):
                fetch.unpack(root / "bad.zip", root / "out", "bad")
            self.assertFalse((root / "escape").exists())


class FetchTests(unittest.TestCase):
    def test_a_release_asset_is_refused_unless_its_hash_is_pinned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dist").mkdir()
            (root / "dist/objdiff-cli-test").write_bytes(b"ELF")
            good = hashlib.sha256(b"ELF").hexdigest()
            tool = dataclasses.replace(fetch.TOOLS["objdiff-cli"], source=(root / "dist").as_uri(), version="v0",
                                       assets={"test": ("objdiff-cli-test", "0" * 64)})
            with mock.patch.dict(fetch.TOOLS, {"objdiff-cli": tool}):
                with self.assertRaisesRegex(ValueError, "refusing"):
                    fetch.fetch(root / "repo", "objdiff-cli", "test")
                self.assertIsNone(fetch.managed(root / "repo", "objdiff-cli"))
                self.assertEqual(list((root / "repo/build/tools").iterdir()), [])
                tool = dataclasses.replace(tool, assets={"test": ("objdiff-cli-test", good)})
                fetch.TOOLS["objdiff-cli"] = tool
                result = fetch.fetch(root / "repo", "objdiff-cli", "test")
                self.assertEqual(result["files"], 1)
                self.assertTrue(fetch.current(root / "repo", "objdiff-cli"))
                fetch.TOOLS["objdiff-cli"] = dataclasses.replace(tool, version="v1")
                self.assertFalse(fetch.current(root / "repo", "objdiff-cli"))  # a newer pin fetches again

    def test_a_host_without_a_build_is_told_to_install_the_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "no build for plan9-mips"):
                fetch.fetch(Path(temp), "wibo", "plan9-mips")

    def test_llvm_keeps_only_its_tools_and_is_found_without_a_project(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dist").mkdir()
            sha = _tarball(root / "dist/llvm.tar.xz", {"LLVM-9/bin/llvm-objdump": b"od", "LLVM-9/bin/llvm-cxxfilt":
                                                       b"filt", "LLVM-9/bin/clang": b"cc"})
            tool = dataclasses.replace(fetch.TOOLS["llvm"], source=(root / "dist").as_uri(),
                                       assets={"test": ("llvm.tar.xz", sha)})
            with mock.patch.dict(fetch.TOOLS, {"llvm": tool}), mock.patch("shutil.which", return_value=None):
                fetch.fetch(root / "repo", "llvm", "test")
                self.assertEqual(fetch.llvm_tool("llvm-cxxfilt"), str(root / "repo/build/llvm/bin/llvm-cxxfilt"))
                self.assertFalse((root / "repo/build/llvm/bin/clang").exists())

    @unittest.skipUnless(GIT, "git")
    def test_a_checkout_is_refused_unless_it_is_the_pinned_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "m2c-src"
            source.mkdir()
            (source / "m2c.py").write_text("print('m2c')\n")
            for argv in (["init", "-q"], ["add", "m2c.py"],
                         ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "m2c"]):
                subprocess.run([GIT, "-C", str(source), *argv], check=True)
            head = subprocess.run([GIT, "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  check=True).stdout.strip()
            tool = dataclasses.replace(fetch.TOOLS["m2c"], source=str(source), version=head)
            with mock.patch.dict(fetch.TOOLS, {"m2c": tool}):
                fetch.fetch(root / "repo", "m2c")
                self.assertTrue((root / "repo/build/tools/m2c/m2c.py").is_file())
                self.assertTrue(fetch.current(root / "repo", "m2c"))
                fetch.TOOLS["m2c"] = dataclasses.replace(tool, version="1" * 40)
                with self.assertRaises(ValueError):
                    fetch.fetch(root / "repo", "m2c")
                self.assertTrue((root / "repo/build/tools/m2c/m2c.py").is_file())  # the old checkout stays

    def test_a_projects_own_compiler_archive_is_fetched_where_its_compiler_points(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sha = _tarball(root / "clang-4.0.1.tar.xz", {"clang+llvm-4.0.1/bin/clang++": b"cc"})
            config = {"platform": "switch", "compiler": "build/compilers/clang-4.0.1/bin/clang++",
                      "compiler_download": {"url": (root / "clang-4.0.1.tar.xz").as_uri(), "sha256": "0" * 64}}
            with self.assertRaisesRegex(ValueError, "refusing"):
                fetch.compiler_archive(root / "repo", config)
            config["compiler_download"]["sha256"] = sha
            result = fetch.compiler_archive(root / "repo", config)
            self.assertEqual(result["files"], 1)
            self.assertTrue((root / "repo/build/compilers/clang-4.0.1/bin/clang++").is_file())
            self.assertIsNone(fetch.compiler_archive(root / "repo", config))  # present: nothing to fetch


class _Project:
    """Just enough of a project for `needed`: one decomp repository and one target."""
    def __init__(self, root: Path, platform: str):
        self.config = {"repositories": {"decomp": {"root": str(root)}}}
        self._target = {"repository": "decomp", "platform": platform, "build": {}}
        self._root = root

    def target(self, name):
        return self._target

    def root(self, repo):
        return self._root


class NeededTests(unittest.TestCase):
    def test_each_platform_asks_only_for_its_own_tools(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch("shutil.which", return_value=None), \
                mock.patch.dict("os.environ", {"PERMUTER_DIR": "", "ZKIT_OBJDUMP": ""}):
            gamecube = fetch.needed(_Project(Path(temp), "gamecube"), "t")
            switch = fetch.needed(_Project(Path(temp), "switch"), "t")
        self.assertNotIn("llvm", gamecube)  # a GameCube project never downloads LLVM
        self.assertEqual(set(gamecube) - {"wibo"}, {"objdiff-cli", "binutils", "m2c", "decomp-permuter"})
        self.assertEqual(switch, ["objdiff-cli", "llvm"])


class HostTests(unittest.TestCase):
    def test_hosts_are_named_as_the_release_assets_name_them(self):
        for system, machine, expected in (("linux", "x86_64", "linux-x86_64"), ("linux", "aarch64", "linux-aarch64"),
                                          ("darwin", "arm64", "macos-arm64"), ("win32", "AMD64", "windows-x86_64")):
            with mock.patch("sys.platform", system), mock.patch("platform.machine", return_value=machine):
                self.assertEqual(fetch.host(), expected)


if __name__ == "__main__":
    unittest.main()
