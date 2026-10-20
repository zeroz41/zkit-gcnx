"""Source quality of a decomp: how much of the matching source still reads as decompiler output.

A byte match proves the code compiles to the original; it says nothing about whether the source is the program's
own C/C++. These counts measure what is left to clean (hand-mangled names, raw offsets, fake vtables, decompiler
temporaries, placeholder names), at the working tree or at any git revision, so a cleanup is measured on the tree
instead of trusted from a tool's own summary line. The same patterns judge added lines in `check` and a function's
body in port readiness.
"""

from __future__ import annotations

import bisect
import collections
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .project import Project

SOURCE_SUFFIXES = {".c", ".cc", ".cp", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}


@dataclass(frozen=True)
class Pattern:
    key: str
    label: str
    regex: re.Pattern
    group: str      # what kind of debt: linkage, layout, types, names, vtables, decompiler, asm
    blocks_port: bool = True  # inside a function body, the function is not yet a readable behavior reference
    sources_only: bool = False  # counted in .c/.cpp files only (headers may legitimately contain it)


def _p(key: str, label: str, regex: str, group: str, blocks_port: bool = True, flags: int = 0,
       sources_only: bool = False) -> Pattern:
    return Pattern(key, label, re.compile(regex, flags), group, blocks_port, sources_only)


_EXTERN_PATTERN = r'\bextern\s+"C"'

# Defaults cover CodeWarrior (GameCube/Wii) and Clang/GCC (Itanium ABI) decomps and both m2c and Ghidra output.
# A project adds or replaces patterns in its manifest (`quality.patterns`: key -> {label, regex, group}).
DEFAULT_PATTERNS: tuple[Pattern, ...] = (
    # a C module's header declares its functions in a guarded extern "C" block (the contract's rule 6), and a
    # definition gives what its file owns the original's C name; a source file's declaration of what another file
    # defines, or a C name on a C++ function, is the debt (`extern_c_debt`)
    _p("extern_c", 'extern "C" declarations of what another file defines', _EXTERN_PATTERN, "linkage",
       blocks_port=False, sources_only=True),
    # A hand-mangled spelling names its callee in full: spelling debt that does not hide what the code does.
    _p("mangled_member", "hand-mangled member names (CodeWarrior)",
       r"\b[A-Za-z_]\w*?__\d+[A-Za-z_]\w*?F\w*\b", "linkage", blocks_port=False),
    _p("mangled_free", "hand-mangled free functions (CodeWarrior name__F...)", r"\b[A-Za-z_]\w*?__F[A-Za-z]\w*\b",
       "linkage", blocks_port=False),
    _p("mangled_itanium", "hand-mangled names (Itanium _Z...)", r"\b_Z(?:N|L|T[VIS])?\d*[A-Za-z_]\w*\b", "linkage",
       blocks_port=False),
    _p("raw_offset", "raw pointer + offset accesses",
       r"\(\s*\(?\s*(?:const\s+)?(?:u8|s8|char|unsigned\s+char|signed\s+char|uint8_t|int8_t|byte|undefined1?)"
       r"\s*\*\s*\)\s*\(?\s*[\w.\->]+\s*\)?\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)", "layout"),
    _p("offset_member", "offset-named members (m_30c, unk_308, field_96, ->f30, getField1c)",
       r"\b(?:m_|unk_?|field_?)(?:0x)?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{2,4}\b|(?:->|\.)\s*f(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{2,4}\b"
       r"|\b[a-z]\w*Field_?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{1,4}\b", "layout"),
    _p("punned_deref", "type-punned or cast-pointer derefs (*(f32 *)&x, *(s32 *)(p + 0x18))",
       r"\*\s*\(\s*(?:(?:const|volatile)\s+)*[A-Za-z_][\w:]*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*(?:const\s*)?\)\s*"
       r"(?:&|\(\s*[^()]*?\+\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\))", "layout"),
    _p("fp_cast", "calls through function-pointer casts ((void (*)(T *))p)",
       r"\(\s*[A-Za-z_][\w:\s\*&<>,]*\(\s*\*+\s*\)\s*\([^()]*\)\s*\)\s*[\w(*&]", "types"),
    _p("decomp_temp", "m2c temporaries (temp_r3, var_f31)", r"\b(?:temp|var)_[rfa]\d+(?:_\d+)?\b", "decompiler"),
    _p("stack_local", "stack-slot locals (sp8, sp1C)", r"\bsp[0-9A-F]{1,3}\b", "decompiler"),
    _p("arg_name", "argN parameters (arg0, farg1)", r"\bf?arg\d+\b", "decompiler"),
    _p("ghidra_temp", "Ghidra temporaries (iVar1, puVar2, param_1, local_10)",
       r"\b(?:[a-z]{1,3}Var\d+|param_\d+|local_[0-9a-fA-F]+|in_[a-z]+\d*|unaff_\w+|extraout_\w+|auStack_\w+)\b",
       "decompiler"),
    _p("ghidra_type", "Ghidra placeholder types (undefined4, code *)", r"\bundefined[1248]?\b", "types"),
    _p("m2c_macro", "m2c helper macros (M2C_FIELD, M2C_ERROR)", r"\bM2C_\w+", "decompiler"),
    _p("data_label", "address-named data (lbl_8045A010, DAT_, Class__data_)",
       r"\b(?:lbl|DAT|PTR|dat)_[0-9A-Fa-f]{6,16}\b|\b\w+__data_[0-9A-Fa-f]{6,16}\b", "names"),
    _p("function_placeholder", "address-named functions (fn_, FUN_, sub_, Class__sub_)",
       r"\b(?:fn|FUN|func|sub)_[0-9A-Fa-f]{6,16}\b|\b\w+__sub_[0-9A-Fa-f]{6,16}\b", "names"),
    _p("address_in_name", "names built around an address (call_36A90_with_1)",
       r"\b(?!(?:lbl|fn|sub|func|dat|ptr|jumptable|switch|temp|var|arg|sp|text|data|bss|rodata)_[0-9A-F])"
       r"[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*_(?=[0-9A-F]*\d)[0-9A-F]{5,8}_[A-Za-z0-9]\w*\b", "names"),
    _p("address_type", "address-named types (Obj_800EB910 *, TUnk_804806E8::, VObj_18_...)",
       r"\b(?:struct|class|union)\s+[A-Za-z]\w*?_[0-9A-Fa-f]{8}\w*"
       r"|\b(?!(?:lbl|fn|FUN|func|sub|DAT|PTR|dat|jumptable|switch)_)[A-Za-z]\w*?_[0-9A-Fa-f]{8}\w*(?=\s*(?:[*&]|::|<))",
       "types"),
    _p("vtable_symbol", "vtable symbols spelled in source (__vt__, _ZTV)", r"\b__vt__\d+\w+|\b_ZTV\w+|\b\w+__vtable\b",
       "vtables"),
    _p("hand_vtable", "hand-written function tables standing in for vtables",
       r"\bvoid\s*\*\s*(?:const\s+)?\w*(?:vt|vtable|vtbl)\w*\s*\[\s*\d*\s*\]\s*=", "vtables", flags=re.I),
    _p("filler_virtual", "filler virtuals (VA, CAT(f, __LINE__), reserved_N, slotNN)",
       r"CAT\s*\(\s*\w+\s*,\s*__LINE__\s*\)|\bvirtual\s+\w[\w\s\*&]*\b(?:reserved|virtual|slot|dummy|pad)_?\d+\s*\(",
       "vtables"),
    _p("slot_name", "vtable-slot names (vfunc_67, Class__vt82)", r"\bvfunc_?\d+(?!\d)|\b[A-Za-z_]\w*?__vt\d+(?!\d)",
       "vtables"),
    _p("local_virtual", "virtual declarations in source files (TU-local stand-in classes)",
       r"(?m)^\s*virtual\b[^;{]*[;{]", "vtables", sources_only=True),
    _p("retype_macro", "#define re-typings of globals or functions",
       r"#\s*define\s+(\w+)\s+\(\s*\*\s*\([^)]*\*\s*\)\s*&\s*\1\s*\)|#\s*define\s+(\w+)\s+\(\s*\([^)]*\(\s*\*\s*\)\s*\([^)]*\)\s*\)\s*\2\s*\)",
       "types"),
    _p("inline_asm", "assembly in source (asm blocks, __asm__)",
       r"\basm\s*\{|\b__asm__\b|\basm\s+[\w\s\*&:~<>,]+?\w+\s*\([^;]*\)\s*\{", "asm"),
)
SUMMARY_GROUPS = ("linkage", "layout", "types", "names", "vtables", "decompiler", "asm")


def patterns(project: Project | None = None, repo: str | None = None) -> list[Pattern]:
    """The default catalog, adjusted by the repository's manifest `quality` block."""
    config = (project.config["repositories"][repo].get("quality", {}) if project and repo else {})
    out = {p.key: p for p in DEFAULT_PATTERNS if p.key not in set(config.get("disable", []))}
    for key, spec in (config.get("patterns") or {}).items():
        out[key] = _p(key, spec.get("label", key), spec["regex"], spec.get("group", "custom"),
                      spec.get("blocks_port", True))
    return list(out.values())


def _strip_comments(text: str) -> str:
    """Drop comments and string literals so documentation of a pattern is not counted as the pattern."""
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"', lambda m: "" if m[0][0] == "/" else '""', text, flags=re.S)


_EXTERN_C = re.compile(_EXTERN_PATTERN + r"\s*")
_ATTRIBUTE = re.compile(r"\b(?:__declspec|__attribute__|alignas)\s*\(")
_NOT_DECLARED = re.compile(r"\s*(?:typedef|using|template|static_assert|namespace|extern\s*$)\b|"
                           r"\s*(?:struct|class|union|enum)\s+\w+\s*$")
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_C_KEYWORDS = {"const", "volatile", "static", "extern", "inline", "unsigned", "signed", "struct", "class", "union",
               "enum", "register", "restrict", "__restrict"}


def _top_level(text: str, char: str) -> list[int]:
    """Offsets of `char` outside parentheses, brackets and braces (an '=' never as part of '==', '<=', ...)."""
    out, depth = [], 0
    for index, c in enumerate(text):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= depth > 0
        elif c == char and depth == 0 and not (char == "=" and (text[index + 1:index + 2] == "="
                                                                or text[index - 1:index] in ("=", "!", "<", ">"))):
            out.append(index)
    return out


def _declared(declarator: str) -> tuple[str, bool] | None:
    """(name, is a function) of one declarator: `void *f(int)`, `int (*fp)(void)`, `const char s[4]`."""
    pointer = re.match(r"[^(]*\(\s*[*&]+\s*(?:const\s+)?([A-Za-z_]\w*)\s*\)", declarator)
    if pointer:
        return pointer[1], False
    opens = [i for i in range(len(declarator)) if declarator[i] == "(" and not _top_level(declarator[:i], "(")]
    if opens:
        name = re.search(r"([A-Za-z_]\w*)\s*$", declarator[:opens[0]])
        return (name[1], True) if name and name[1] not in _C_KEYWORDS else None
    names = [n for n in _IDENTIFIER.findall(re.sub(r"\[[^\]]*\]", " ", declarator)) if n not in _C_KEYWORDS]
    return (names[-1], False) if len(names) > 1 else None


def _drop_attributes(head: str) -> str:
    """head with each `__declspec(...)`, `__attribute__((...))` and `alignas(...)` blanked (same length)."""
    for attribute in list(_ATTRIBUTE.finditer(head)):
        depth, index = 0, attribute.end() - 1
        while index < len(head):
            depth += head[index] == "("
            depth -= head[index] == ")"
            if depth == 0:
                break
            index += 1
        head = head[:attribute.start()] + " " * (index + 1 - attribute.start()) + head[index + 1:]
    return head


def _items(code: str, start: int, stop: int, single: bool) -> list[tuple[int, int, bool]]:
    """(start, end, has a body) of each declaration from `start`: one, or every one inside a block."""
    from .cxx import _matching
    out, begin, index, depth = [], start, start, 0
    while index < stop:
        c = code[index]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= depth > 0
        elif c == "{" and depth == 0:
            close = _matching(code, index)
            head = code[begin:index]
            if _top_level(head, "=") or "(" not in head:   # an initializer, or a class or enum body
                index = close + 1
                continue
            out.append((begin, close + 1, True))
            begin = index = close + 1
            if single:
                break
            continue
        elif c == ";" and depth == 0:
            out.append((begin, index, False))
            begin = index + 1
            if single:
                break
        index += 1
    return out


def extern_c_debt(text: str) -> list[tuple[int, str]]:
    """(1-based line, name) of each `extern "C"` in a source file that is linkage debt: a declaration of a name the
    file does not define (a call-site prototype; it belongs in the owner's header), or a C name on a C++ function
    (a hand-mangled spelling). A definition under `extern "C"` (a body, an initializer, an object inside an
    `extern "C" { }` block) gives what this file owns its C name, and a forward declaration of one is fine."""
    from . import cxx
    code = cxx.blank(text)
    starts = [0] + [m.end() for m in re.finditer(r"\n", code)]
    line = lambda offset: bisect.bisect_right(starts, offset)
    mangled = [p.regex for p in DEFAULT_PATTERNS if p.key.startswith("mangled_")]
    defined, declared, debt = set(), [], []
    for match in _EXTERN_C.finditer(text):
        if code[match.start():match.start() + 6] != "extern":   # in a comment or a string
            continue
        at = match.end()
        block = code[at:at + 1] == "{"
        stop = cxx._matching(code, at) if block else len(code)
        for begin, end, body in _items(code, at + 1 if block else at, stop, single=not block):
            head = _drop_attributes(code[begin:end].split("{", 1)[0] if body else code[begin:end])
            if not head.strip() or _NOT_DECLARED.match(head):
                continue
            initialized = bool(_top_level(head, "="))
            extern = bool(re.match(r"\s*extern\b", head))
            for piece in (head.split("=", 1)[0],) if initialized else \
                    [head[a:b] for a, b in zip([0, *(i + 1 for i in _top_level(head, ","))],
                                               [*_top_level(head, ","), len(head)])]:
                found = _declared(piece)
                if found is None:
                    continue
                name, function = found
                where = line(begin + len(head) - len(head.lstrip()))
                if any(r.fullmatch(name) for r in mangled):
                    debt.append((where, name))
                elif body or initialized or (block and not extern and not function):
                    defined.add(name)
                else:
                    declared.append((where, name))
    if declared:   # what else the file defines: function bodies, and objects initialized outside a body
        inside = set()
        for definition in cxx.definitions(text):
            defined.add(definition.name.split("::")[-1])
            inside.update(range(definition.open + 1, definition.end))
        for found in re.finditer(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\]\s*)*=(?!=)", code):
            if line(found.start()) - 1 not in inside:
                defined.add(found[1])
        debt += [(where, name) for where, name in declared if name not in defined]
    return sorted(debt)


def count(text: str, catalog: Iterable[Pattern], header: bool = False) -> collections.Counter:
    code = _strip_comments(text)
    found = collections.Counter()
    for pattern in catalog:
        if header and pattern.sources_only:
            continue
        if pattern.key == "extern_c" and pattern.regex.pattern == _EXTERN_PATTERN:
            found[pattern.key] += len(extern_c_debt(text))
            continue
        found[pattern.key] += sum(1 for _ in pattern.regex.finditer(code))
    return found


def _paths(project: Project, repo: str, paths: list[str] | None) -> tuple[list[str], list[re.Pattern]]:
    config = project.config["repositories"][repo]
    quality = config.get("quality", {})
    roots = paths or quality.get("paths") or [p for p in ("src", "include") if (project.root(repo) / p).exists()]
    exclude = [re.compile(x) for x in quality.get("exclude", [])]
    return roots, exclude


def _keep(rel: str, exclude: list[re.Pattern]) -> bool:
    return Path(rel).suffix.lower() in SOURCE_SUFFIXES and not any(x.search(rel) for x in exclude)


def _tree_files(root: Path, roots: list[str], exclude: list[re.Pattern]) -> Iterable[tuple[str, str]]:
    for base in roots:
        top = root / base
        candidates = [top] if top.is_file() else sorted(top.rglob("*")) if top.is_dir() else []
        for path in candidates:
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if _keep(rel, exclude):
                yield rel, path.read_text(encoding="utf-8", errors="replace")


def _revision_files(root: Path, revision: str, roots: list[str], exclude: list[re.Pattern]) -> Iterable[tuple[str, str]]:
    """Every source blob at a revision, read with one `git cat-file --batch` (no checkout)."""
    listing = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "-z", revision, "--", *roots],
                             capture_output=True, check=False)
    if listing.returncode:
        raise ValueError(f"Cannot list {revision}: {listing.stderr.decode(errors='replace').strip()}")
    blobs = []
    for entry in listing.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _, name = entry.partition(b"\t")
        parts = meta.split()
        rel = name.decode("utf-8", errors="surrogateescape")
        if len(parts) == 3 and parts[1] == b"blob" and _keep(rel, exclude):
            blobs.append((rel, parts[2]))
    if not blobs:
        return
    process = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE)
    assert process.stdin and process.stdout
    import threading
    feeder = threading.Thread(target=lambda: (process.stdin.write(b"".join(o + b"\n" for _, o in blobs)),
                                              process.stdin.close()), daemon=True)
    feeder.start()
    for rel, _ in blobs:
        header = process.stdout.readline().split()
        size = int(header[2])
        data = process.stdout.read(size)
        process.stdout.read(1)
        yield rel, data.decode("utf-8", errors="replace")
    feeder.join()
    process.stdout.close()
    process.wait()


def audit(project: Project, repo: str, paths: list[str] | None = None, revision: str | None = None,
          top: int = 15) -> dict[str, Any]:
    """Counts per pattern for the working tree (or a revision), and the files holding the most debt."""
    catalog = patterns(project, repo)
    roots, exclude = _paths(project, repo, paths)
    root = project.root(repo)
    files = _revision_files(root, revision, roots, exclude) if revision else _tree_files(root, roots, exclude)
    totals: collections.Counter = collections.Counter()
    per_file: dict[str, collections.Counter] = {}
    scanned = 0
    for rel, text in files:
        scanned += 1
        found = +count(text, catalog, header=Path(rel).suffix.lower() in HEADER_SUFFIXES)   # zero counts dropped
        if found:
            totals.update(found)
            per_file[rel] = found
    groups = collections.Counter()
    for pattern in catalog:
        groups[pattern.group] += totals[pattern.key]
    worst = sorted(per_file.items(), key=lambda item: -sum(item[1].values()))[:top]
    return {"repo": repo, "revision": revision or "working tree", "paths": roots, "files": scanned,
            "files_with_debt": len(per_file),
            "counts": [{"key": p.key, "label": p.label, "group": p.group, "count": totals[p.key]} for p in catalog],
            "groups": dict(groups), "total": sum(totals.values()),
            "worst_files": [{"path": rel, "total": sum(c.values()), "top": c.most_common(3)} for rel, c in worst]}


def compare(project: Project, repo: str, before: str, after: str | None = None,
            paths: list[str] | None = None) -> dict[str, Any]:
    """Debt at `before` (a revision) and `after` (a revision, or the working tree), pattern by pattern."""
    first = audit(project, repo, paths, before, top=0)
    last = audit(project, repo, paths, after, top=0)
    rows = []
    for a, b in zip(first["counts"], last["counts"]):
        rows.append({**b, "before": a["count"], "after": b["count"], "delta": b["count"] - a["count"]})
    return {"repo": repo, "before": before, "after": after or "working tree", "rows": rows,
            "total": {"before": first["total"], "after": last["total"], "delta": last["total"] - first["total"]},
            "worse": [r for r in rows if r["delta"] > 0]}


def findings(text: str, catalog: Iterable[Pattern], header: bool = False, skip: Iterable[str] = ()) -> list[dict]:
    """Every match in a piece of source (one line or a function body), for check and port readiness; `blocks`
    says whether it hides what the code does (spelling debt such as a hand-mangled call does not). In a header,
    what is debt only in a source file (a class declared with virtuals) is none. `skip` names patterns the caller
    judges itself (check reads `extern "C"` against the whole file)."""
    code = _strip_comments(text)
    out = []
    for pattern in catalog:
        if (header and pattern.sources_only) or pattern.key in skip:
            continue
        if pattern.key == "extern_c" and pattern.regex.pattern == _EXTERN_PATTERN:
            out += [{"key": pattern.key, "label": pattern.label, "text": f'extern "C" {name}', "group": pattern.group,
                     "blocks": pattern.blocks_port} for _, name in extern_c_debt(text)]
            continue
        for match in pattern.regex.finditer(code):
            out.append({"key": pattern.key, "label": pattern.label, "text": match.group(0)[:80],
                        "group": pattern.group, "blocks": pattern.blocks_port})
    return out


def body(lines: list[str], start: int) -> tuple[int, int] | None:
    """(first, last) 0-based line indexes of the brace-delimited body that opens at or after `start`."""
    depth, opened = 0, False
    for index in range(start, min(len(lines), start + 4000)):
        code = _strip_comments(lines[index])
        for char in code:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
                if opened and depth == 0:
                    return start, index
        if not opened and index > start + 12:
            return None
    return None
