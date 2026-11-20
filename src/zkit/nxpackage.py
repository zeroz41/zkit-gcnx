"""Switch game packages (.nsp, .xci, .nup): the files in their program NCAs' partitions (the ExeFS: main, rtld, sdk,
...), decrypted with the user's prod.keys (a .nup needs none), and written where a target's `original` says when their
SHA-1 matches. Only the headers and those partitions are read, so a multi-gigabyte package costs a few megabytes.

Formats, as switchbrew documents them:
- NSP: a PFS0 ("PFS0", file count, string table size; 0x18-byte entries: data offset, size, name offset) holding
  NCAs and, for content with a rights ID, its ticket (<rights ID>.tik).
- XCI: a cartridge image: "HEAD" at 0x100, the root HFS0 (a PFS0 with 0x40-byte entries) at the offset at 0x130,
  whose partitions (normal, secure, ...) are HFS0s of NCAs; "update" holds system firmware and is skipped.
- NCA: a 0xC00-byte header in AES-128-XTS with header_key and a big-endian sector tweak (NCA3: sectors 0-5 in order;
  NCA2: the four section headers each as sector 0). The content type at 0x205 (0: program), the key generation the
  larger of 0x206 and 0x220, the key-area key at 0x207, the rights ID at 0x230, the sections' (start, end) in
  0x200-byte blocks at 0x240, the encrypted key area at 0x300, the section headers at 0x400. A section header gives
  its type at 0x2 (1: PartitionFS), hash type at 0x3 (2: SHA-256 blocks, then the PFS0's offset at 0x40), encryption
  at 0x4 (1: none, 3: AES-CTR) and the counter's upper half at 0x140 (reversed); the counter's lower half is the
  absolute NCA offset / 16, big-endian.
- Keys: content with a rights ID uses its ticket's title key (a common ticket: the first 16 bytes of the title key
  block, AES-ECB with titlekek_<rev>); content without one uses key 2 of the key area (AES-ECB with
  key_area_key_<application|ocean|system>_<rev>). <rev> is the key generation less one (0 for 0 and 1).
- NUP: titles already decrypted, as a file tree (no NCAs, no keys). "NUP\x01" at 0; at 0x8 and 0x10 the table of
  contents' offset and size, at 0x18 its SHA-256. The table: "TOC\x01", the title count (u32), then the directory
  count, file count, string table offset (from the table) and size (u64s); from 0x30 a 0x40-byte record per title
  (its ID first, u64); then 0x18-byte directory records (name offset and length in the string table, first child,
  child count: u32s); then 0x50-byte file records (name offset and length: u32s; size, data offset, stored size:
  u64s; at 0x20 the SHA-256 of its bytes; at 0x40 a u32, 1: stored as one zstd frame, 0: stored as is); then the
  children, u32s: a directory's index, or the directory count plus a file's. The first directories are the
  titles' roots, in title order, holding exefs/ (the ExeFS, as files) and romfs/.
"""

from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

PACKAGE_SUFFIXES = (".nsp", ".xci", ".nup")
COMPRESSED_SUFFIXES = (".nsz", ".xcz")
KEY_FILE = "prod.keys"
CHUNK = 4 << 20
NUP, NUP_TOC = b"NUP\x01", b"TOC\x01"
PROGRAM, PARTITION_FS, SHA256_BLOCKS = 0, 1, 2
NO_ENCRYPTION, AES_CTR = 1, 3
KEY_AREA_KEYS = ("application", "ocean", "system")
# Ticket signature type -> (signature size, padding).
SIGNATURES = {0x10000: (0x200, 0x3C), 0x10001: (0x100, 0x3C), 0x10002: (0x3C, 0x40), 0x10003: (0x200, 0x3C),
              0x10004: (0x100, 0x3C), 0x10005: (0x3C, 0x40), 0x10006: (0x14, 0x28)}
# Where emulators and the usual tools keep prod.keys, under each per-user folder.
KEY_FOLDERS = ("Ryujinx/system", "yuzu/keys", "suyu/keys", "sudachi/keys", "citron/keys", "eden/keys")

Read = Callable[[int, int], bytes]


class NotFound(ValueError):
    """No package (or no file in one) gives what was asked for."""


class NoPackages(NotFound):
    """No package at all where they were looked for."""


def _cipher(key: bytes, mode):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    except ImportError as error:  # a dependency of zkit; missing only from an install made without them
        raise ValueError("reading Switch packages needs the `cryptography` package (pip install cryptography)") \
            from error
    return Cipher(algorithms.AES(key), mode).decryptor()


def _modes():
    from cryptography.hazmat.primitives.ciphers import modes
    return modes


def _ecb(key: bytes, data: bytes) -> bytes:
    decryptor = _cipher(key, _modes().ECB())
    return decryptor.update(data) + decryptor.finalize()


def _xts_sector(key: bytes, data: bytes, sector: int) -> bytes:
    decryptor = _cipher(key, _modes().XTS(sector.to_bytes(16, "big")))
    return decryptor.update(data) + decryptor.finalize()


def _ctr(key: bytes, upper: bytes, offset: int, data: bytes) -> bytes:
    """`data` from 16-aligned NCA offset `offset`."""
    decryptor = _cipher(key, _modes().CTR(upper + (offset >> 4).to_bytes(8, "big")))
    return decryptor.update(data) + decryptor.finalize()


# Keys.

class Keys:
    """prod.keys files (`name = hex` lines), the first file naming a key giving it."""

    def __init__(self, paths: list[Path]):
        self.paths, self.values = paths, {}
        for path in paths:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                name, equals, value = line.partition("=")
                try:
                    if equals:
                        self.values.setdefault(name.strip().lower(), bytes.fromhex(value.strip()))
                except ValueError:
                    continue

    def need(self, name: str) -> bytes:
        if name not in self.values:
            read = ", ".join(str(path) for path in self.paths)
            raise ValueError(f"no {name} in {read} (keys dumped from a console on newer firmware have it)")
        return self.values[name]


def key_files(folders: list[Path]) -> list[Path]:
    """prod.keys in the given folders, then ~/.switch and the emulators' folders (per-user data and config)."""
    home = Path.home()
    bases = [Path(os.environ[name]) for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "APPDATA") if os.environ.get(name)]
    bases += [home / ".config", home / ".local/share", home / "Library/Application Support"]
    places = [*folders, home / ".switch", *(base / folder for base in dict.fromkeys(bases) for folder in KEY_FOLDERS)]
    return [place / KEY_FILE for place in dict.fromkeys(places) if (place / KEY_FILE).is_file()]


# Containers.

@dataclass(frozen=True)
class Entry:
    name: str
    offset: int  # where its bytes start, as `read` addresses them
    size: int


def partition(read: Read, at: int) -> list[Entry]:
    """The files of the PFS0 or HFS0 at `at`."""
    head = read(at, 0x10)
    if head[:4] not in (b"PFS0", b"HFS0"):
        raise ValueError(f"no PFS0 or HFS0 at {at:#x}")
    count, table = struct.unpack_from("<II", head, 4)
    size = 0x18 if head[:4] == b"PFS0" else 0x40
    if count > 0x10000 or table > 1 << 24:
        raise ValueError(f"a partition at {at:#x} lists {count} files: not one")
    entries = read(at + 0x10, count * size + table)
    names, data = entries[count * size:], at + 0x10 + count * size + table
    out = []
    for index in range(count):
        offset, length, name_at = struct.unpack_from("<QQI", entries, index * size)
        out.append(Entry(names[name_at:].split(b"\0", 1)[0].decode("utf-8", "replace"), data + offset, length))
    return out


def _file_reader(file) -> Read:
    def read(at: int, size: int) -> bytes:
        file.seek(at)
        return file.read(size)
    return read


def contents(read: Read) -> list[Entry]:
    """Every file of an NSP, or of an XCI's partitions but its firmware update."""
    if read(0x100, 4) == b"HEAD":
        root = struct.unpack("<Q", read(0x130, 8))[0]
        return [entry for part in partition(read, root) if part.name != "update" for entry in partition(read, part.offset)]
    return partition(read, 0)


def _ticket(data: bytes) -> tuple[bytes, bytes | None]:
    """(rights ID, encrypted title key, or None for a personalized ticket)."""
    kind = struct.unpack_from("<I", data)[0]
    if kind not in SIGNATURES:
        raise ValueError(f"a ticket with an unknown signature type {kind:#x}")
    signature, padding = SIGNATURES[kind]
    body = data[4 + signature + padding:]
    return bytes(body[0x160:0x170]), (bytes(body[0x40:0x50]) if body[0x141] == 0 else None)


class Nca:
    """An NCA's decrypted header: what it holds and the key its sections use."""

    def __init__(self, read: Read, entry: Entry, keys: Keys, tickets: dict[bytes, bytes | None]):
        self.read, self.entry, self.keys, self.tickets = read, entry, keys, tickets
        raw = read(entry.offset, 0xC00)
        if len(raw) < 0xC00:
            raise ValueError(f"{entry.name}: shorter than an NCA header")
        header_key = keys.need("header_key")
        head = b"".join(_xts_sector(header_key, raw[at:at + 0x200], at // 0x200) for at in (0, 0x200))
        if head[0x200:0x204] == b"NCA3":
            sections = b"".join(_xts_sector(header_key, raw[at:at + 0x200], at // 0x200)
                                for at in range(0x400, 0xC00, 0x200))
        elif head[0x200:0x204] == b"NCA2":
            sections = b"".join(_xts_sector(header_key, raw[at:at + 0x200], 0) for at in range(0x400, 0xC00, 0x200))
        else:
            raise ValueError(f"{entry.name}: its header does not decrypt to an NCA (is header_key right?)")
        self.head, self.section_headers = head, sections
        self.content_type = head[0x205]
        generation = max(head[0x206], head[0x220])
        self.revision = generation - 1 if generation else 0
        self.rights_id = bytes(head[0x230:0x240])
        self._key: bytes | None = None

    def key(self) -> bytes:
        if self._key is None:
            if any(self.rights_id):
                if self.rights_id not in self.tickets:
                    raise ValueError(f"{self.entry.name}: no ticket for its rights ID {self.rights_id.hex()}")
                title_key = self.tickets[self.rights_id]
                if title_key is None:
                    raise ValueError(f"{self.entry.name}: its ticket is personalized (tied to the console it came "
                                     "from); dump the package again without console-specific data")
                self._key = _ecb(self.keys.need(f"titlekek_{self.revision:02x}"), title_key)
            else:
                index = self.head[0x207]
                if index >= len(KEY_AREA_KEYS):
                    raise ValueError(f"{self.entry.name}: unknown key-area key {index}")
                area = _ecb(self.keys.need(f"key_area_key_{KEY_AREA_KEYS[index]}_{self.revision:02x}"),
                            self.head[0x300:0x340])
                self._key = area[0x20:0x30]
        return self._key

    def partitions(self) -> Iterator[tuple[int, Read, list[Entry]]]:
        """(section, a reader of its decrypted bytes, its files) for each PartitionFS section."""
        for index in range(4):
            start, end = struct.unpack_from("<II", self.head, 0x240 + 0x10 * index)
            header = self.section_headers[0x200 * index:0x200 * (index + 1)]
            if end <= start or header[2] != PARTITION_FS or header[3] != SHA256_BLOCKS or \
                    header[4] not in (NO_ENCRYPTION, AES_CTR):
                continue
            read = self._section(start * 0x200, end * 0x200, header)
            try:
                files = partition(read, struct.unpack_from("<Q", header, 0x40)[0])
            except ValueError as error:
                raise ValueError(f"{self.entry.name}: section {index} holds no partition ({error}; wrong key?)") \
                    from None
            yield index, read, files

    def _section(self, begin: int, end: int, header: bytes) -> Read:
        key = self.key() if header[4] == AES_CTR else None
        upper = bytes(header[0x140:0x148][::-1])

        def read(at: int, size: int) -> bytes:
            size = max(0, min(size, end - begin - at))
            offset = begin + at
            lead = offset & 0xF if key else 0
            data = self.read(self.entry.offset + offset - lead, lead + size)
            return _ctr(key, upper, offset - lead, data)[lead:] if key else data
        return read


# NUP.

@dataclass(frozen=True)
class NupFile:
    title: str  # the title's ID, 16 hex digits
    name: str
    size: int
    offset: int
    stored: int  # its size in the package
    sha256: bytes
    compressed: bool


def nup_exefs(read: Read) -> list[NupFile]:
    """The ExeFS files of each title of a NUP, its table of contents checked against the header's SHA-256."""
    head = read(0, 0x38)
    if head[:4] != NUP:
        raise ValueError("no NUP header")
    at, size = struct.unpack_from("<QQ", head, 8)
    if size > 1 << 30:
        raise ValueError(f"its table of contents is {size:,} bytes: not one")
    table = read(at, size)
    if len(table) != size or hashlib.sha256(table).digest() != head[0x18:0x38] or table[:4] != NUP_TOC:
        raise ValueError("its table of contents does not match its SHA-256")
    titles, directories, files, names_at, names_size = struct.unpack_from("<I4Q", table, 4)
    directories_at = 0x30 + 0x40 * titles
    files_at = directories_at + 0x18 * directories
    children_at = files_at + 0x50 * files
    if children_at > names_at or names_at + names_size > size or titles > directories:
        raise ValueError("its table of contents does not add up")

    def named(record: int) -> str:
        name_at, length = struct.unpack_from("<II", table, record)
        return table[names_at + name_at:names_at + name_at + length].decode("utf-8", "replace")

    def children(directory: int) -> list[int]:
        first, count = struct.unpack_from("<II", table, directories_at + 0x18 * directory + 8)
        return list(struct.unpack_from(f"<{count}I", table, children_at + 4 * first))

    out = []
    for title in range(titles):
        title_id = f"{struct.unpack_from('<Q', table, 0x30 + 0x40 * title)[0]:016x}"
        for exefs in (c for c in children(title) if c < directories and named(directories_at + 0x18 * c) == "exefs"):
            for child in children(exefs):
                if child < directories:
                    continue
                record = files_at + 0x50 * (child - directories)
                size_, offset, stored = struct.unpack_from("<QQQ", table, record + 8)
                out.append(NupFile(title_id, named(record), size_, offset, stored, table[record + 0x20:record + 0x40],
                                   struct.unpack_from("<I", table, record + 0x40)[0] == 1))
    return out


def _zstd():
    """A zstd decompressor taking one frame in pieces: the standard library's (3.14) or the zstandard package's."""
    try:
        from compression import zstd
        return zstd.ZstdDecompressor()
    except ImportError:
        pass
    try:
        import zstandard
    except ImportError as error:  # a dependency of zkit before 3.14; missing only from an install made without them
        raise ValueError("reading .nup packages needs the `zstandard` package (pip install zstandard)") from error
    return zstandard.ZstdDecompressor().decompressobj()


def _nup_chunks(read: Read, item: NupFile) -> Iterator[bytes]:
    """`item`'s bytes, checked against its size and SHA-256 at the end."""
    decompressor, digest, total = _zstd() if item.compressed else None, hashlib.sha256(), 0
    for at in range(0, item.stored, CHUNK):
        data = read(item.offset + at, min(CHUNK, item.stored - at))
        if decompressor:
            data = decompressor.decompress(data)
        digest.update(data)
        total += len(data)
        yield data
    if total != item.size or digest.digest() != item.sha256:
        raise ValueError(f"{item.name} of title {item.title} does not match its SHA-256")


# Finding and writing files.

@dataclass(frozen=True)
class Found:
    package: Path
    nca: str  # the NCA, or a NUP's title ID
    section: int
    name: str
    size: int
    sha1: str


def packages(sources: list[Path], recursive: bool = False) -> tuple[list[Path], list[Path]]:
    """(packages, compressed packages this reader skips) among the given files and folders."""
    found: list[Path] = []
    for source in sources:
        if source.is_file():
            found.append(source)
        elif source.is_dir():
            found += sorted(path for path in (source.rglob("*") if recursive else source.iterdir()) if path.is_file())
    usable = [p for p in dict.fromkeys(found) if p.suffix.lower() in PACKAGE_SUFFIXES]
    return usable, [p for p in dict.fromkeys(found) if p.suffix.lower() in COMPRESSED_SUFFIXES]


Chunks = Callable[[], Iterator[bytes]]


def _is_nup(package: Path) -> bool:
    with package.open("rb") as file:
        return file.read(4) == NUP


def _program_files(package: Path, keys: Keys, file) -> Iterator[tuple[str, int, str, int, Chunks]]:
    """(NCA or title, section, name, size, its bytes in chunks) of each file of the package's ExeFS (and logo)."""
    read = _file_reader(file)
    if read(0, 4) == NUP:
        try:
            files = nup_exefs(read)
        except ValueError as error:
            raise ValueError(f"{package.name} is not a NUP ({error})") from None
        for item in files:
            yield item.title, 0, item.name, item.size, lambda item=item: _nup_chunks(read, item)
        return
    if not keys.paths:
        raise ValueError(f"no {KEY_FILE} found: put it next to the packages, or in ~/.switch")
    try:
        entries = contents(read)
    except ValueError as error:
        raise ValueError(f"{package.name} is not an NSP, XCI or NUP ({error})") from None
    if any(entry.name.lower().endswith(".ncz") for entry in entries):
        raise ValueError(f"{package.name} holds compressed NCAs (.ncz): decompress it first")
    tickets = dict(_ticket(read(e.offset, e.size)) for e in entries if e.name.lower().endswith(".tik"))
    for entry in entries:
        if not entry.name.lower().endswith(".nca"):
            continue
        nca = Nca(read, entry, keys, tickets)
        if nca.content_type != PROGRAM:
            continue
        for section, section_read, files in nca.partitions():
            for item in files:
                yield nca.entry.name, section, item.name, item.size, \
                    lambda section_read=section_read, item=item: _chunks(section_read, item)


def _chunks(read: Read, entry: Entry) -> Iterator[bytes]:
    for at in range(0, entry.size, CHUNK):
        yield read(entry.offset + at, min(CHUNK, entry.size - at))


def scan(package: Path, keys: Keys) -> list[Found]:
    """Every file in the package's program NCAs' partitions, with its SHA-1."""
    out = []
    with package.open("rb") as file:
        for container, section, name, size, chunks in _program_files(package, keys, file):
            digest = hashlib.sha1()
            for chunk in chunks():
                digest.update(chunk)
            out.append(Found(package, container, section, name, size, digest.hexdigest()))
    return out


def write(found: Found, keys: Keys, destination: Path) -> None:
    """Write `found` to `destination` (through a temporary file, checked against its SHA-1)."""
    with found.package.open("rb") as file:
        for container, section, name, _, chunks in _program_files(found.package, keys, file):
            if (container, section, name) != (found.nca, found.section, found.name):
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            partial = destination.with_name(destination.name + ".partial")
            digest = hashlib.sha1()
            try:
                with partial.open("wb") as out:
                    for chunk in chunks():
                        digest.update(chunk)
                        out.write(chunk)
            except BaseException:
                partial.unlink(missing_ok=True)
                raise
            if digest.hexdigest() != found.sha1:
                partial.unlink()
                raise ValueError(f"{found.package.name}: {found.name} read differently twice")
            partial.replace(destination)
            return
    raise ValueError(f"{found.package.name} no longer holds {found.name}")


def near(root: Path, original: Path) -> list[Path]:
    """The folders a target's packages go in: the original's folder and each folder above it in the repository."""
    folders, folder = [], original.parent
    while True:
        folders.append(folder)
        if folder == root or root not in folder.parents:
            return folders
        folder = folder.parent


def provide(destination: Path, sha1: str | None, sources: list[Path], key_paths: list[Path] | None = None,
            recursive: bool = False) -> dict:
    """Write the file of the packages among `sources` whose SHA-1 is `sha1` (or, without one, the only file named as
    `destination` is) to `destination`. Raises NotFound when none gives it."""
    found, compressed = packages(sources, recursive)
    folders = list(dict.fromkeys([path.parent for path in found] + [s for s in sources if s.is_dir()]))
    skipped = f" ({', '.join(p.name for p in compressed)}: compressed, decompress them first)" if compressed else ""
    if not found:
        raise NoPackages("no .nsp, .xci or .nup in " + ", ".join(str(s) for s in sources) + skipped)
    keys = Keys(key_paths if key_paths is not None else key_files(folders))
    if not keys.paths and not any(_is_nup(package) for package in found):
        raise NotFound(f"no {KEY_FILE} found: put it next to the packages, or in ~/.switch")
    matches, problems = [], []
    for package in found:
        try:
            files = scan(package, keys)
        except (ValueError, OSError) as error:
            problems.append(f"{package.name}: {error}" if package.name not in str(error) else str(error))
            continue
        for item in files:
            if (item.sha1 == sha1.lower()) if sha1 else (item.name == destination.name):
                matches.append(item)
        if sha1 and matches:
            break
    if len(matches) > 1:
        raise NotFound(f"{len(matches)} files named {destination.name} (" + ", ".join(m.package.name for m in matches)
                       + "): pin the target's `sha1` to choose")
    if not matches:
        what = f"a file with SHA-1 {sha1}" if sha1 else f"a file named {destination.name}"
        raise NotFound(f"no package holds {what} (read {len(found) - len(problems)} of {len(found)})"
                       + "".join(f"; {problem}" for problem in problems) + skipped)
    write(matches[0], keys, destination)
    item = matches[0]
    return {"written": str(destination), "package": str(item.package), "nca": item.nca, "file": item.name,
            "size": item.size, "sha1": item.sha1, "keys": [str(path) for path in keys.paths]}
