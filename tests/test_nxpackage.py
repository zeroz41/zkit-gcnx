import support  # noqa: F401  (isolates config, cache and state)
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from zkit import build, nxpackage
from zkit.project import Project

KEYS = {"header_key": bytes(range(32)), "titlekek_00": b"\x11" * 16, "titlekek_02": b"\x12" * 16,
        "key_area_key_application_00": b"\x21" * 16, "key_area_key_application_02": b"\x22" * 16}
# What a newer console would also have: packages are made with these, the user's prod.keys holds only KEYS.
NEWER = {**KEYS, "titlekek_04": b"\x14" * 16, "key_area_key_application_04": b"\x24" * 16}


def _encrypt(key: bytes, mode, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), mode).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def keys_file(path: Path, keys: dict[str, bytes] = KEYS) -> Path:
    path.write_text("".join(f"{name} = {value.hex()}\n" for name, value in keys.items()))
    return path


def container(files: list[tuple[str, bytes]], magic: bytes = b"PFS0") -> bytes:
    """A PFS0 or HFS0 of the files, in order."""
    names = b"".join(name.encode() + b"\0" for name, _ in files)
    names += bytes(-len(names) % 0x20)
    entries, data, at = b"", b"", 0
    for name, body in files:
        name_at = names.index(name.encode() + b"\0")
        entries += struct.pack("<QQI", len(data), len(body), name_at) + bytes(4 if magic == b"PFS0" else 0x2C)
        data += body
    return magic + struct.pack("<II", len(files), len(names)) + bytes(4) + entries + names + data


def nca(content_type: int, sections: list[tuple[list[tuple[str, bytes]], bool]], key: bytes, generation: int = 0,
        rights_id: bytes = bytes(16), version: bytes = b"NCA3", key_area_key: bytes | None = None,
        header_key: bytes = KEYS["header_key"]) -> bytes:
    """An NCA with a PartitionFS section per (files, encrypted), each the files' PFS0 0x200 bytes in (after where
    the SHA-256 table would be); `key` encrypts the sections, and the key area holds it when there is no rights ID."""
    header = bytearray(0xC00)
    header[0x200:0x204] = version
    header[0x205] = content_type
    header[0x206], header[0x220] = min(generation, 2), generation
    header[0x230:0x240] = rights_id
    if not any(rights_id):
        header[0x300:0x340] = _encrypt(key_area_key, modes.ECB(), b"\xaa" * 0x20 + key + b"\xbb" * 0x10)
    body, start = b"", 0xC00
    for index, (files, encrypted) in enumerate(sections):
        pfs = container(files)
        plain = bytes(0x200) + pfs
        plain += bytes(-len(plain) % 0x200)
        fs = bytearray(0x200)
        fs[0:2] = struct.pack("<H", 2)
        fs[2], fs[3], fs[4] = nxpackage.PARTITION_FS, nxpackage.SHA256_BLOCKS, 3 if encrypted else 1
        fs[0x40:0x50] = struct.pack("<QQ", 0x200, len(pfs))
        fs[0x140:0x148] = bytes([index + 1, 0, 0, 0, 7, 0, 0, 0])
        header[0x400 + 0x200 * index:0x600 + 0x200 * index] = fs
        struct.pack_into("<II", header, 0x240 + 0x10 * index, start // 0x200, (start + len(plain)) // 0x200)
        if encrypted:
            counter = bytes(fs[0x140:0x148][::-1]) + (start >> 4).to_bytes(8, "big")
            plain = _encrypt(key, modes.CTR(counter), plain)
        body += plain
        start += len(plain)
    sectors = [bytes(header[at:at + 0x200]) for at in range(0, 0xC00, 0x200)]
    tweaks = range(6) if version == b"NCA3" else (0, 1, 0, 0, 0, 0)
    encrypted_header = b"".join(_encrypt(header_key, modes.XTS(t.to_bytes(16, "big")), s) for t, s in zip(tweaks, sectors))
    return encrypted_header + body


def ticket(rights_id: bytes, title_key: bytes, titlekek: bytes, personalized: bool = False) -> bytes:
    body = bytearray(0x180)
    body[0x40:0x50] = _encrypt(titlekek, modes.ECB(), title_key)
    body[0x141] = 1 if personalized else 0
    body[0x160:0x170] = rights_id
    return struct.pack("<I", 0x10004) + bytes(0x100 + 0x3C) + bytes(body)


def exefs(main: bytes) -> list[tuple[str, bytes]]:
    return [("main", main), ("main.npdm", b"META" + bytes(60)), ("rtld", b"rtld" * 50)]


def nsp(path: Path, main: bytes, generation: int = 0, version: bytes = b"NCA3", personalized: bool = False) -> None:
    """A downloaded title: a program NCA with a rights ID (its ExeFS, and a plain logo section), its ticket, and a
    meta NCA whose key is in its key area."""
    rights_id, title_key = os.urandom(16), os.urandom(16)
    revision = generation - 1 if generation else 0
    program = nca(0, [(exefs(main), True), ([("NintendoLogo.png", b"PNG")], False)], title_key, generation,
                  rights_id, version)
    meta = nca(1, [([("Application.cnmt", b"cnmt")], True)], os.urandom(16), generation,
               key_area_key=NEWER[f"key_area_key_application_{revision:02x}"])
    tik = ticket(rights_id, title_key, NEWER[f"titlekek_{revision:02x}"], personalized)
    path.write_bytes(container([("a" * 32 + ".nca", program), ("b" * 32 + ".cnmt.nca", meta),
                                (rights_id.hex() + ".tik", tik)]))


def xci(path: Path, main: bytes) -> None:
    """A cartridge image: no tickets (key areas), the game in `secure`, a firmware NCA nothing can read in
    `update`."""
    program = nca(0, [(exefs(main), True)], os.urandom(16), 3, key_area_key=KEYS["key_area_key_application_02"])
    secure = container([("c" * 32 + ".nca", program)], b"HFS0")
    update = container([("d" * 32 + ".nca", os.urandom(0xC00))], b"HFS0")
    root = container([("update", update), ("secure", secure)], b"HFS0")
    head = bytearray(0x200)
    head[0x100:0x104] = b"HEAD"
    head[0x130:0x140] = struct.pack("<QQ", 0x200, 0x200)
    path.write_bytes(bytes(head) + root)


def _zstd(data: bytes) -> bytes:
    try:
        from compression import zstd
        return zstd.compress(data)
    except ImportError:
        import zstandard
        return zstandard.ZstdCompressor().compress(data)


def nup(path: Path, titles: list[tuple[int, list[tuple[str, bytes]]]]) -> None:
    """A NUP of titles, each (ID, [(path under its root, bytes)]): every second file zstd-compressed."""
    names = bytearray()
    directories = [{"name": "", "children": []} for _ in titles]  # the roots first, in title order
    files, blobs = [], []

    def named(text: str) -> tuple[int, int]:
        names.extend(text.encode())
        return len(names) - len(text.encode()), len(text.encode())

    for root, (_, tree) in enumerate(titles):
        for where, body in tree:
            parent = root
            for part in where.split("/")[:-1]:
                below = [c for kind, c in directories[parent]["children"] if kind == "d"
                         and directories[c]["name"] == part]
                if not below:
                    directories.append({"name": part, "children": []})
                    directories[parent]["children"].append(("d", len(directories) - 1))
                    below = [len(directories) - 1]
                parent = below[0]
            compressed = len(files) % 2
            blobs.append(_zstd(body) if compressed else body)
            files.append((where.split("/")[-1], body, compressed))
            directories[parent]["children"].append(("f", len(files) - 1))
    children = []
    directory_records = b""
    for directory in directories:
        directory_records += struct.pack("<6I", *named(directory["name"]), len(children), len(directory["children"]),
                                         0, 0)
        children += [c if kind == "d" else len(directories) + c for kind, c in directory["children"]]
    file_names = [named(name) for name, _, _ in files]
    head = 0x80
    size = 0x30 + 0x40 * len(titles) + len(directory_records) + 0x50 * len(files) + 4 * len(children) + len(names)
    offsets = [head + size + sum(map(len, blobs[:index])) for index in range(len(blobs))]
    file_records = b"".join(struct.pack("<IIQQQ", *file_names[i], len(body), offsets[i], len(blobs[i])) +
                            hashlib.sha256(body).digest() + struct.pack("<I", compressed) + bytes(12)
                            for i, (_, body, compressed) in enumerate(files))
    body = b"".join(struct.pack("<Q", title) + bytes(0x38) for title, _ in titles) + directory_records + \
        file_records + struct.pack(f"<{len(children)}I", *children)
    table = b"TOC\x01" + struct.pack("<I4Q", len(titles), len(directories), len(files), 0x30 + len(body), len(names)) + \
        bytes(8) + body + names
    assert len(table) == size
    header = b"NUP\x01" + bytes(4) + struct.pack("<QQ", head, size) + hashlib.sha256(table).digest()
    path.write_bytes(header + bytes(head - len(header)) + table + b"".join(blobs))


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


class PackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.keys = [keys_file(self.root / "prod.keys")]

    def test_the_file_with_the_pinned_sha1_comes_out_of_the_package_holding_it(self):
        base, update = b"\x7fNSO base" * 999, b"\x7fNSO update" * 1234
        nsp(self.root / "game.nsp", base)
        nsp(self.root / "game update.nsp", update, generation=3, version=b"NCA2")
        found = nxpackage.scan(self.root / "game update.nsp", nxpackage.Keys(self.keys))
        self.assertEqual([(f.section, f.name) for f in found],
                         [(0, "main"), (0, "main.npdm"), (0, "rtld"), (1, "NintendoLogo.png")])
        for wanted in (update, base):
            out = self.root / "orig" / sha1(wanted) / "main"
            done = nxpackage.provide(out, sha1(wanted), [self.root], self.keys)
            self.assertEqual(out.read_bytes(), wanted)
            self.assertEqual(Path(done["package"]).name, "game update.nsp" if wanted == update else "game.nsp")
            self.assertFalse(out.with_name("main.partial").exists())
        # Without a SHA-1 a name must be the only one of its kind.
        with self.assertRaisesRegex(nxpackage.NotFound, "2 files named main.*pin the target's `sha1`"):
            nxpackage.provide(self.root / "x/main", None, [self.root], self.keys)
        with self.assertRaisesRegex(nxpackage.NotFound, "no package holds a file with SHA-1 0{40}"):
            nxpackage.provide(self.root / "x/main", "0" * 40, [self.root], self.keys)

    def test_a_cartridge_image_reads_its_key_areas_and_skips_the_firmware(self):
        main = b"\x7fNSO cart" * 777
        xci(self.root / "game.xci", main)
        nxpackage.provide(self.root / "out/main", None, [self.root / "game.xci"], self.keys)
        self.assertEqual((self.root / "out/main").read_bytes(), main)

    def test_what_cannot_be_read_says_why(self):
        nsp(self.root / "mine.nsp", b"main", personalized=True)
        with self.assertRaisesRegex(nxpackage.NotFound, "mine.nsp.*personalized"):
            nxpackage.provide(self.root / "out/main", None, [self.root], self.keys)
        (self.root / "mine.nsp").unlink()
        nsp(self.root / "new.nsp", b"main", generation=5)
        with self.assertRaisesRegex(nxpackage.NotFound, "no titlekek_04 in .*prod.keys"):
            nxpackage.provide(self.root / "out/main", None, [self.root], self.keys)
        other = keys_file(self.root / "other.keys", {**KEYS, "header_key": bytes(range(1, 33))})
        with self.assertRaisesRegex(nxpackage.NotFound, "does not decrypt to an NCA .*header_key"):
            nxpackage.provide(self.root / "out/main", None, [self.root], [other])
        (self.root / "new.nsp").unlink()
        (self.root / "packed.nsz").write_bytes(b"")
        with self.assertRaisesRegex(nxpackage.NoPackages, "packed.nsz: compressed"):
            nxpackage.provide(self.root / "out/main", None, [self.root], self.keys)
        nsp(self.root / "game.nsp", b"main")
        with self.assertRaisesRegex(nxpackage.NotFound, "no prod.keys found"):
            nxpackage.provide(self.root / "out/main", None, [self.root], [])

    def test_a_nup_gives_its_titles_exefs_files_without_keys(self):
        main, other = b"\x7fNSO new" * 4321, b"\x7fNSO dlc" * 99
        nup(self.root / "game.nup", [(0x0100000000001000, [("exefs/main.npdm", b"META" + bytes(60)),
                                                           ("exefs/main", main), ("romfs/data/a.bin", b"a" * 50)]),
                                     (0x0100000000001001, [("romfs/b.bin", b"b"), ("exefs/main", other)])])
        found = nxpackage.scan(self.root / "game.nup", nxpackage.Keys([]))
        self.assertEqual([(f.nca, f.name, f.sha1) for f in found],
                         [("0100000000001000", "main.npdm", sha1(b"META" + bytes(60))),
                          ("0100000000001000", "main", sha1(main)), ("0100000000001001", "main", sha1(other))])
        for wanted in (main, other):
            out = self.root / "orig" / sha1(wanted) / "main"
            nxpackage.provide(out, sha1(wanted), [self.root], [])
            self.assertEqual(out.read_bytes(), wanted)
        # A file whose bytes differ from its SHA-256 is never written.
        data = bytearray((self.root / "game.nup").read_bytes())
        data[data.index(b"META") + 1] ^= 1  # main.npdm, stored as is
        (self.root / "bad.nup").write_bytes(bytes(data))
        with self.assertRaisesRegex(ValueError, "does not match its SHA-256"):
            nxpackage.scan(self.root / "bad.nup", nxpackage.Keys([]))
        data = bytearray((self.root / "game.nup").read_bytes())
        data[0x90] ^= 1  # in the table of contents
        (self.root / "bad.nup").write_bytes(bytes(data))
        with self.assertRaisesRegex(ValueError, "bad.nup is not a NUP .*table of contents"):
            nxpackage.scan(self.root / "bad.nup", nxpackage.Keys([]))

    def test_keys_are_looked_for_by_the_packages_then_in_the_usual_places(self):
        home = self.root / "home"
        switch, emulator = home / ".switch", home / ".config/Ryujinx/system"
        for folder in (switch, emulator):
            folder.mkdir(parents=True)
        emulator = keys_file(emulator / "prod.keys")
        keys_file(switch / "prod.keys", {"header_key": b"\x01" * 32})
        environment = {name: value for name, value in os.environ.items()
                       if name not in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "APPDATA")}
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(Path, "home", return_value=home):
            self.assertEqual(nxpackage.key_files([self.root]), [self.root / "prod.keys", switch / "prod.keys", emulator])
            # The first file naming a key gives it.
            self.assertEqual(nxpackage.Keys(nxpackage.key_files([])).need("header_key"), b"\x01" * 32)

    def test_packages_go_in_the_originals_folder_or_one_above_it(self):
        self.assertEqual(nxpackage.near(self.root, self.root / "orig/v1/main"),
                         [self.root / "orig/v1", self.root / "orig", self.root])
        self.assertEqual(nxpackage.near(self.root, Path("/elsewhere/main")), [Path("/elsewhere")])


class ProjectTests(unittest.TestCase):
    """`zkit build` (configure) extracts a missing Switch original by itself; `zkit extract` takes other folders."""

    def project(self, root: Path) -> Project:
        (root / "config").mkdir()
        (root / "config/splits.txt").write_text("")
        main = b"\x7fNSO update" * 99
        config = {"schema_version": 1, "id": "t", "repositories": {"decomp": {"root": ".", "role": "decomp"}},
                  "targets": {"v1": {"repository": "decomp", "platform": "switch", "module": "main",
                                     "original": "orig/v1/main",
                                     "sha1": sha1(main), "splits": "config/splits.txt",
                                     "build": {"compiler": "clang++"}}}}
        (root / "t.project.json").write_text(json.dumps(config))
        self.main = main
        return Project.load(root / "t.project.json")

    def test_configure_extracts_the_original_from_the_packages_beside_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = self.project(root)
            with self.assertRaisesRegex(ValueError, r"orig/v1/main is missing: put the game's packages .* in orig/, "
                                                    r"or run `zkit extract <folder>`$"):
                build.configure(project, None, None, zkit=["zkit"])
            (root / "orig").mkdir()
            nsp(root / "orig/update.nsp", self.main, generation=3)
            keys_file(root / "orig/prod.keys")
            data = build.configure(project, None, None, zkit=["zkit"])
            self.assertEqual((root / "orig/v1/main").read_bytes(), self.main)
            self.assertIn("extracted orig/v1/main from update.nsp", data["targets"]["v1"]["notes"])

    def test_a_target_names_the_folder_its_packages_go_in(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = self.project(root)
            project.config["targets"]["v1"]["packages"] = "roms"
            with self.assertRaisesRegex(ValueError, r"put the game's packages .* in roms/, or run"):
                build.configure(project, None, None, zkit=["zkit"])
            nsp(root / "update.nsp", self.main, generation=3)  # outside roms/: not looked at
            keys_file(root / "prod.keys")
            with self.assertRaisesRegex(ValueError, r" in roms/, or run"):
                build.configure(project, None, None, zkit=["zkit"])
            (root / "roms/updates").mkdir(parents=True)
            nsp(root / "roms/updates/update.nsp", self.main, generation=3)
            keys_file(root / "roms/prod.keys")
            data = build.configure(project, None, None, zkit=["zkit"])
            self.assertEqual((root / "orig/v1/main").read_bytes(), self.main)
            self.assertIn("extracted orig/v1/main from update.nsp", data["targets"]["v1"]["notes"])
            (root / "orig/v1/main").unlink()
            self.assertTrue(build.extract(project)["ok"])
            self.assertEqual((root / "orig/v1/main").read_bytes(), self.main)

    def test_extract_reads_the_given_folders_and_their_subfolders(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = self.project(root)
            (root / "dumps/updates").mkdir(parents=True)
            nsp(root / "dumps/updates/update.nsp", self.main, generation=3)
            keys = keys_file(root / "keys.txt")
            data = build.extract(project, None, None, [root / "dumps"], keys)
            self.assertTrue(data["ok"])
            self.assertEqual((root / "orig/v1/main").read_bytes(), self.main)
            self.assertIn("wrote orig/v1/main", build.render_extract(data))
            self.assertEqual(build.extract(project, None, None, [root / "dumps"], keys)["targets"]["v1"],
                             {"original": "orig/v1/main", "present": True})
            (root / "orig/v1/main").unlink()
            data = build.extract(project, None, None, [root / "nowhere"], keys)
            self.assertFalse(data["ok"])
            self.assertIn("no .nsp, .xci or .nup", build.render_extract(data))


if __name__ == "__main__":
    unittest.main()
