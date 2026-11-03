"""Twins: functions the tree has not matched whose machine code has the shape of one it has.

Another instantiation of a written template, a copy-pasted method, the same inline helper over another type: the
code differs in offsets, constants and call targets, not in its instructions. The matched function's source is then
a ready template for the unmatched one.

A function's shape is its instruction words with every immediate cleared (`signatures.skeleton`: offsets,
constants, shifts) and every branch, call and address target cleared (they differ wherever the code was linked).
Registers stay: a different allocation is different code. Two functions are exact twins when their shapes are
equal; near twins when the ratio of the longest common runs of their shapes (`difflib.SequenceMatcher`) reaches
`SIMILAR` and their lengths differ by less than `LENGTHS` allows. Near candidates come from a MinHash of each
shape's `GRAM`-word runs (one permutation, `BINS` bins, banded `ROWS` at a time); only the candidates sharing the
most bands are compared word by word.

Each twin says how many of the target's words differ from it: masked (in shape) and raw (any bit). A family is a
group of unmatched functions of one shape: write one and the rest follow.

Shapes and sketches are kept in zkit's cache, one file per project target, keyed by the original's SHA-1 and the
function boundaries; the match state is read fresh from the index each time.
"""

from __future__ import annotations

import collections
import difflib
import hashlib
import marshal
import struct
import sys
from pathlib import Path
from typing import Any, Iterable

from .signatures import skeleton

VERSION = 3
MINIMUM_WORDS = 16       # a shorter function's shape proves nothing: setters and thin wrappers repeat everywhere
SIMILAR = 0.85           # the default similarity a near twin needs
LENGTHS = (0.7, 1.4)     # a twin's length over the target's
GRAM = 5                 # words per run the sketch hashes
BINS = 48                # sketch values (one-permutation MinHash bins)
ROWS = 2                 # values per band: two shapes are compared when they share a band
VERIFIED = 24            # candidates compared word by word per target, most shared bands first
SHOWN = 3                # twins listed per asked-for address
MASK64 = (1 << 64) - 1
# AArch64 instructions that hold a pc-relative target: (mask, value) of the class, then the bits kept
AARCH64_TARGETS = ((0x7C000000, 0x14000000, 0xFC000000),    # b, bl
                   (0xFF000010, 0x54000000, 0xFF00001F),    # b.cond
                   (0x7E000000, 0x34000000, 0xFF00001F),    # cbz, cbnz
                   (0x7E000000, 0x36000000, 0xFFF8001F),    # tbz, tbnz (the bit tested stays)
                   (0x1F000000, 0x10000000, 0x9F00001F),    # adr, adrp
                   (0x3B000000, 0x18000000, 0xFF00001F))    # load literal


def masked(word: int, switch: bool) -> int:
    """An instruction without its immediate and without the target of a branch, call or address it forms."""
    if switch:
        for mask, value, kept in AARCH64_TARGETS:
            if word & mask == value:
                return word & kept
    elif word >> 26 == 18:                                     # b, bl (bc targets stay inside the function)
        return word & 0xFC000003
    return skeleton(word, switch)


def form(word: int, switch: bool) -> int:
    """A masked instruction without its registers, for similarity: one allocation's choice is another's."""
    if switch:
        kept = ~0x3FF                                                        # Rd/Rt, Rn
        if word & 0x0E000000 == 0x0A000000 or word & 0x0A000000 == 0x08000000 or word & 0x0E000000 == 0x0E000000:
            kept &= ~0x1F0000                                                # Rm, Rs (registers, loads, SIMD)
        if word & 0x1F000000 in (0x1B000000, 0x1F000000) or word & 0x3A000000 == 0x28000000:
            kept &= ~0x7C00                                                  # Ra, Rt2
        return word & kept
    return word if word >> 26 in (16, 18) else word & ~0x03FFF800           # rD/rS, rA, rB


def shape(words: Iterable[int], switch: bool, memo: dict[int, int] | None = None) -> tuple[int, ...]:
    memo = {} if memo is None else memo
    out = []
    for word in words:
        value = memo.get(word)
        if value is None:
            value = memo[word] = masked(word, switch)
        out.append(value)
    return tuple(out)


def sketch(words: tuple[int, ...]) -> tuple[int, ...]:
    """One-permutation MinHash of the shape's runs of `GRAM` words; an empty bin takes the next filled one's value,
    moved by the distance, so short shapes compare too."""
    bins: list[int | None] = [None] * BINS
    for i in range(max(1, len(words) - GRAM + 1)):
        h = hash(words[i:i + GRAM]) & MASK64
        b, v = h % BINS, h // BINS & 0xFFFFFFFF
        if bins[b] is None or v < bins[b]:
            bins[b] = v
    filled = [i for i, v in enumerate(bins) if v is not None]
    if not filled:
        return (0,) * BINS
    out = []
    for i, v in enumerate(bins):
        if v is None:
            step = next((d for d in range(1, BINS) if bins[(i + d) % BINS] is not None))
            v = (bins[(i + step) % BINS] + step * 0x9E3779B1) & 0xFFFFFFFF
        out.append(v)
    return tuple(out)


def bands(signature: tuple[int, ...]) -> list[int]:
    return [hash((b, signature[b * ROWS:(b + 1) * ROWS])) for b in range(BINS // ROWS)]


def differences(target: tuple[int, ...], twin: tuple[int, ...], target_raw: list[int],
                twin_raw: list[int]) -> tuple[int, int]:
    """(masked, raw): how many of the target's words its twin's do not give, in shape and in any bit, along the
    alignment of their shapes."""
    if len(target) == len(twin) and target == twin:
        return 0, sum(a != b for a, b in zip(target_raw, twin_raw))
    matcher = difflib.SequenceMatcher(None, twin, target, autojunk=False)
    shape_diff = raw_diff = 0
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            raw_diff += sum(twin_raw[i1 + k] != target_raw[j1 + k] for k in range(i2 - i1))
        else:
            shape_diff += j2 - j1
    return shape_diff, shape_diff + raw_diff


class Index:
    """The matched functions: exact by shape, near by form (sketch bands, then word by word)."""

    def __init__(self, shapes: dict[int, tuple[int, ...]], forms: dict[int, tuple[int, ...]],
                 sketches: dict[int, tuple[int, ...]], matched: Iterable[int]):
        self.exact: dict[tuple[int, ...], list[int]] = collections.defaultdict(list)
        self.groups: dict[tuple[int, ...], list[int]] = collections.defaultdict(list)
        for address in sorted(matched):
            if address in shapes:
                self.exact[shapes[address]].append(address)
                self.groups[forms[address]].append(address)
        self.unique = list(self.groups)
        self.buckets: dict[int, list[int]] = collections.defaultdict(list)
        for i, words in enumerate(self.unique):
            if len(words) >= GRAM:
                for key in bands(sketches.get(self.groups[words][0]) or sketch(words)):
                    self.buckets[key].append(i)

    def near(self, words: tuple[int, ...], outline: tuple[int, ...], signature: tuple[int, ...] | None,
             minimum: float, count: int = 1) -> list[tuple[float, list[int]]]:
        """The `count` closest matched groups at or above `minimum` (similarity, members): the functions of the
        same shape first, then by the similarity of their forms."""
        found: list[tuple[float, list[int]]] = []
        if words in self.exact:
            found.append((1.0, self.exact[words]))
            if count == 1:
                return found
        taken = set(found[0][1]) if found else set()
        if len(outline) < GRAM:
            return found
        hits: collections.Counter = collections.Counter()
        for key in bands(signature or sketch(outline)):
            hits.update(self.buckets.get(key, ()))
        low, high = LENGTHS
        ranked = [i for i, _ in sorted(hits.items(), key=lambda kv: -kv[1])
                  if low < len(self.unique[i]) / len(outline) < high]
        matcher = difflib.SequenceMatcher(None, autojunk=False)
        matcher.set_seq2(outline)
        near: list[tuple[float, list[int]]] = []
        wanted = count - len(found)
        for i in ranked[:VERIFIED]:
            members = [a for a in self.groups[self.unique[i]] if a not in taken]
            if not members:
                continue
            matcher.set_seq1(self.unique[i])
            floor = max(minimum, near[-1][0] if len(near) >= wanted else 0.0)
            if matcher.real_quick_ratio() < floor or matcher.quick_ratio() < floor:
                continue
            ratio = matcher.ratio()
            if ratio >= floor:
                near.append((ratio, members))
                near.sort(key=lambda f: -f[0])
                del near[wanted:]
        return found + near


def _function_rows(project, target: str) -> list[dict]:
    from .index import MODULE_SHIFT, connect, refresh
    refresh(project)
    rows = connect(project).execute(
        "SELECT address, size, name, demangled, match, unit, source FROM functions WHERE target = ? "
        "ORDER BY address", (target,)).fetchall()
    return [dict(r) for r in rows if r["address"] < 1 << MODULE_SHIFT and r["size"] and r["size"] % 4 == 0]


def _cache_file(project, target: str) -> Path:
    import re
    from .index import cache_path
    path, safe = cache_path(project), re.sub(r"[^\w.]", "_", target)
    return path.with_name(f"twins-{safe}-{path.stem.rsplit('-', 1)[-1]}.marshal")


def _forms(shapes: dict[int, tuple[int, ...]], switch: bool) -> dict[int, tuple[int, ...]]:
    memo: dict[int, int] = {}
    out = {}
    for address, words in shapes.items():
        found = []
        for word in words:
            value = memo.get(word)
            if value is None:
                value = memo[word] = form(word, switch)
            found.append(value)
        out[address] = tuple(found)
    return out


def _shapes(project, target: str, rows: list[dict]) -> tuple[dict, dict, dict, Any, Any]:
    """{address: shape}, {address: form}, {address: sketch of the form}, the platform and the opened original
    (shapes and sketches cached per original and function boundaries)."""
    from .inspect_dol import _dol
    from .platform import for_target
    from .signatures import identity
    platform, image = for_target(project.target(target)), _dol(project, target)
    switch = platform.name == "switch"
    bounds = hashlib.sha1(struct.pack(f"<{2 * len(rows)}Q", *(v for r in rows for v in (r["address"], r["size"]))))
    key = f"{VERSION}:{sys.version_info[:2]}:{identity(image)}:{bounds.hexdigest()}"
    store = _cache_file(project, target)
    try:
        saved, addresses, packed, signatures = marshal.loads(store.read_bytes())
        if saved == key:
            shapes = {a: struct.unpack(f"<{len(p) // 4}I", p) for a, p in zip(addresses, packed)}
            return shapes, _forms(shapes, switch), {a: struct.unpack(f"<{BINS}I", p) for a, p in zip(addresses, signatures)}, platform, image
    except (OSError, ValueError, EOFError, TypeError):
        pass
    memo: dict[int, int] = {}
    shapes = {}
    for row in rows:
        try:
            words = platform.words(image, row["address"], row["size"])
        except ValueError:
            continue
        if words:
            shapes[row["address"]] = shape(words, switch, memo)
    forms = _forms(shapes, switch)
    sketches = {a: sketch(words) for a, words in forms.items()}
    addresses = list(shapes)
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        partial = store.with_suffix(".partial")
        partial.write_bytes(marshal.dumps((key, addresses,
                                           [struct.pack(f"<{len(shapes[a])}I", *shapes[a]) for a in addresses],
                                           [struct.pack(f"<{BINS}I", *sketches[a]) for a in addresses])))
        partial.replace(store)
    except OSError:
        pass
    return shapes, forms, sketches, platform, image


def _unit(project, target: str, rows: list[dict], query: str) -> str:
    """The unit a query names: its name, or an address or function inside it."""
    if any(r["unit"] == query for r in rows):
        return query
    from . import bridge
    from .index import connect, containing
    found = bridge.resolve(project, query, target, limit=2)
    row = containing(connect(project), target, found[0]) if len(found) == 1 else None
    if row is None or not row["unit"]:
        raise ValueError(f"{query} names no unit (give the unit's name or an address in it)")
    return row["unit"]


def _exact(row: dict) -> bool:
    return row["match"] is not None and row["match"] >= 100


def _describe(row: dict) -> dict:
    from .index import address_text
    return {"address": address_text(row["address"]), "size": row["size"],
            "name": row["demangled"] or row["name"], "unit": row["unit"]}


def find(project, target: str, queries: list[str] | None = None, unit: str | None = None,
         minimum: float = SIMILAR, limit: int = 40) -> dict[str, Any]:
    """Every unmatched function (or the asked-for ones, or a unit's) with its most similar matched twin."""
    import time
    started = time.time()
    rows = _function_rows(project, target)
    by_address = {r["address"]: r for r in rows}
    shapes, forms, sketches, platform, image = _shapes(project, target, rows)
    index = Index(shapes, forms, sketches, (r["address"] for r in rows if _exact(r)))
    count = 1
    if queries:
        from . import bridge
        wanted = []
        for query in queries:
            found = bridge.resolve(project, query, target, limit=2)
            if len(found) != 1 or found[0] not in by_address:
                raise ValueError(f"{query} names {'no' if not found else 'more than one'} function; use its address")
            wanted.append(by_address[found[0]])
        count = SHOWN
    else:
        chosen = _unit(project, target, rows, unit) if unit else None
        wanted = [r for r in rows if not _exact(r) and len(shapes.get(r["address"], ())) >= MINIMUM_WORDS
                  and (chosen is None or r["unit"] == chosen)]
    raw: dict[int, list[int]] = {}

    def words_of(address: int) -> list[int]:
        if address not in raw:
            raw[address] = platform.words(image, address, by_address[address]["size"])
        return raw[address]

    entries, seen = [], {}
    for row in wanted:
        words = shapes.get(row["address"])
        if words is None:
            continue
        if words not in seen:
            seen[words] = index.near(words, forms[row["address"]], sketches.get(row["address"]), minimum, count)
        twins = []
        for ratio, members in seen[words]:
            best = None
            for member in members[:8]:
                if member == row["address"]:
                    continue
                masked_diff, raw_diff = differences(words, shapes[member], words_of(row["address"]),
                                                    words_of(member))
                if best is None or raw_diff < best[1]:
                    best = (member, raw_diff, masked_diff)
            if best is None:
                continue
            twin = by_address[best[0]]
            twins.append(dict(_describe(twin), source=twin["source"], similarity=round(ratio, 3),
                              differ_masked=best[2], differ_raw=best[1]))
        if twins:
            entries.append(dict(_describe(row), match=row["match"], words=len(words),
                                **({"twins": twins} if queries else {"twin": twins[0]})))
    if not queries:
        entries.sort(key=lambda e: (-e["size"], e["address"]))
    return {"target": target, "minimum": minimum, "functions": len(entries),
            "bytes": sum(e["size"] for e in entries), "searched": len(wanted),
            "seconds": round(time.time() - started, 1), "entries": entries[:limit] if limit else entries}


def families(project, target: str, unit: str | None = None, limit: int = 40) -> dict[str, Any]:
    """Groups of unmatched functions with one shape (two or more), most bytes beyond the first member first, each
    with a matched function of that shape when there is one."""
    rows = _function_rows(project, target)
    shapes = _shapes(project, target, rows)[0]
    groups: dict[tuple[int, ...], list[dict]] = collections.defaultdict(list)
    matched: dict[tuple[int, ...], dict] = {}
    for row in rows:
        words = shapes.get(row["address"])
        if words is None or len(words) < MINIMUM_WORDS:
            continue
        if _exact(row):
            matched.setdefault(words, row)
        else:
            groups[words].append(row)
    chosen = _unit(project, target, rows, unit) if unit else None
    found = [(words, members) for words, members in groups.items() if len(members) >= 2
             and (chosen is None or any(m["unit"] == chosen for m in members))]
    found.sort(key=lambda f: (-sum(m["size"] for m in f[1][1:]), f[1][0]["address"]))
    out = []
    for number, (words, members) in enumerate(found):
        twin = matched.get(words)
        out.append({"family": number, "members": [_describe(m) for m in members], "words": len(words),
                    "beyond_first": sum(m["size"] for m in members[1:]),
                    "twin": dict(_describe(twin), source=twin["source"]) if twin else None})
    return {"target": target, "families": len(out), "functions": sum(len(f["members"]) for f in out),
            "beyond_first": sum(f["beyond_first"] for f in out), "entries": out[:limit] if limit else out}


def text(data: dict) -> str:
    """`zkit twins`: one line per target and its twin (or its twins, for asked-for addresses)."""
    lines = [f"{data['functions']} of {data['searched']} function(s) searched ({data['bytes']:,} bytes) have a "
             f"matched twin at similarity >= {data['minimum']} ({data['seconds']}s)"]
    for e in data["entries"]:
        lines.append(f"  {e['address']} {e['size']:>6} {e['name']} [{e['unit'] or '?'}] {e['match'] or 0:.1f}%")
        for t in e.get("twins") or [e["twin"]]:
            lines.append(f"      {t['similarity']:.3f} {t['address']} {t['name']} [{t['source'] or t['unit'] or '?'}]"
                         f" differs in {t['differ_masked']} masked / {t['differ_raw']} raw of {e['words']} words")
    if data["functions"] > len(data["entries"]):
        lines.append(f"  ... {data['functions'] - len(data['entries'])} more (--limit 0 lists all)")
    return "\n".join(lines)


def families_text(data: dict) -> str:
    lines = [f"{data['families']} famil{'y' if data['families'] == 1 else 'ies'} of unmatched functions with one "
             f"shape: {data['functions']} functions, {data['beyond_first']:,} bytes beyond each family's first"]
    for f in data["entries"]:
        twin = f["twin"]
        lines.append(f"  family {f['family']}: {len(f['members'])} x {f['words']} words"
                     + (f", matched twin {twin['address']} {twin['name']} [{twin['source'] or twin['unit']}]"
                        if twin else ""))
        lines += [f"    {m['address']} {m['size']:>6} [{m['unit'] or '?'}] {m['name']}" for m in f["members"]]
    if data["families"] > len(data["entries"]):
        lines.append(f"  ... {data['families'] - len(data['entries'])} more (--limit 0 lists all)")
    return "\n".join(lines)
