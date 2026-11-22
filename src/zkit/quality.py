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
_NEVER = r"(?!)"   # judged by a parser (PARSED) or over the whole tree (TREE_CHECKS), not by a pattern
# Placeholder offsets in names; real words spelled in hex digits are names, not offsets.
_HEX_OFFSET = (r"(?:0x)?(?!(?i:add|bad|bed|cab|dab|dad|ebb|fab|fad|fed|fee|ace|bee|cafe|face|fade|dead|deaf|beef|"
               r"babe|bead|cede|dace|abbe)\b)[0-9A-Fa-f]{1,4}\b")
_BYTE_TYPE = r"(?:u8|s8|char|unsigned\s+char|signed\s+char|uint8_t|int8_t|byte|undefined1?)"
_BYTE_CAST = r"\(\s*(?:const\s+)?" + _BYTE_TYPE + r"\s*\*\s*\)\s*(?:\(\s*[\w.\->]+\s*\)|[\w.\->]+)\s*"
_PLUS_OFFSET = r"\+\s*(?:0x[0-9A-Fa-f]+|\d+)\b(?!\s*[\[(])"

# Defaults cover CodeWarrior (GameCube/Wii) and Clang/GCC (Itanium ABI) decomps and both m2c and Ghidra output.
# A project adds or replaces patterns in its manifest (`quality.patterns`: key -> {label, regex, group}).
DEFAULT_PATTERNS: tuple[Pattern, ...] = (
    # a C module's header declares its functions in a guarded extern "C" block (the contract's rule 6), and a
    # definition gives what its file owns the original's C name; a source file's declaration of what another file
    # defines, or a C name on a C++ function, is the debt (`extern_c_debt`)
    _p("extern_c", 'extern "C" declarations of what another file defines', _EXTERN_PATTERN, "linkage",
       blocks_port=False, sources_only=True),
    # a prototype or `extern` at file scope of a source file for what another file defines: it belongs in that
    # file's header (`local_decl_debt`)
    _p("local_decl", "prototypes and externs in source files (void heap_free(void *);)", _NEVER, "linkage",
       blocks_port=False, sources_only=True),
    # A hand-mangled spelling names its callee in full: spelling debt that does not hide what the code does.
    _p("mangled_member", "hand-mangled member names (CodeWarrior)",
       r"\b[A-Za-z_]\w*?__\d+[A-Za-z_]\w*?F\w*\b", "linkage", blocks_port=False),
    _p("mangled_free", "hand-mangled free functions (CodeWarrior name__F...)", r"\b[A-Za-z_]\w*?__F[A-Za-z]\w*\b",
       "linkage", blocks_port=False),
    _p("mangled_itanium", "hand-mangled names (Itanium _Z...)", r"\b_Z(?:N|L|T[VIS])?\d*[A-Za-z_]\w*\b", "linkage",
       blocks_port=False),
    # A member spelled as a C name (`TClass__method`): it is not the member's mangled symbol either, so the name must
    # change again once the function or object becomes a real member. Mangled, address and slot spellings are
    # counted by their own patterns.
    _p("flat_name", "flat C spellings of members (TClass__method, TClass__instance)",
       r"\b(?![A-Za-z0-9_]*__(?:\d|F[A-Za-z]|(?:sub|data)_[0-9A-Fa-f]{6}|vt\d))"
       r"(?=[A-Z](?:[A-Z0-9]|_(?!_))*(?:[a-z]|\d__))[A-Z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*__[a-z_][A-Za-z0-9_]*\b", "linkage", blocks_port=False),
    _p("raw_offset", "raw pointer + offset accesses ((u8 *)p + 0x30)",
       r"\(\s*" + _BYTE_CAST + r"\)\s*" + _PLUS_OFFSET + "|" + _BYTE_CAST + _PLUS_OFFSET, "layout"),
    _p("offset_cast", "casts of a pointer plus an offset ((Vec *)(p + 0x178))",
       r"(?<!\*)(?<!\*\s)\(\s*(?:const\s+)?[A-Za-z_]\w*\s*\*+\s*\)\s*\(\s*[\w.\->]+\s*\+\s*0x[0-9A-Fa-f]+\s*\)",
       "layout"),
    _p("punned_deref", "type-punned or cast-pointer derefs (*(f32 *)&x, *(s32 *)(p + 0x18))",
       r"\*\s*\(\s*(?:(?:const|volatile)\s+)*[A-Za-z_][\w:]*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*(?:const\s*)?\)\s*"
       r"(?:&|\(\s*[^()]*?\+\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\))", "layout"),
    _p("offset_member", "offset-named members (unk_30, m_c, field_96, set_field_378, ->f30)",
       r"\b(?:m_|unk_?|unknown_?|field_?|mbr_)" + _HEX_OFFSET +
       r"|\b[A-Za-z]\w*?_(?:field|unk|unknown)_?" + _HEX_OFFSET +
       r"|(?:->|\.)\s*f(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{2,4}\b|\b[a-z]\w*Field_?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{1,4}\b",
       "layout"),
    _p("fp_cast", "calls through function-pointer casts ((void (*)(T *))p)",
       r"\(\s*[A-Za-z_][\w:\s\*&<>,]*\(\s*\*+\s*\)\s*\([^()]*\)\s*\)\s*[\w(*&]", "types"),
    # counted on the text with its string literals kept (`string_casts`)
    _p("string_cast", "string literals cast to integers ((saddr)\"file.gvm\")",
       r"\(\s*(?:[su]addr|u32|s32|int|long|unsigned(?:\s+(?:int|long))?|u?intptr_t)\s*\)\s*\"", "types"),
    _p("ghidra_type", "Ghidra placeholder types (undefined4, code *)", r"\bundefined[1248]?\b", "types"),
    _p("address_type", "address-named types (Obj_800EB910 *, TUnk_804806E8::, VObj_18_...)",
       r"\b(?:struct|class|union)\s+[A-Za-z]\w*?_[0-9A-Fa-f]{8}\w*"
       r"|\b(?!(?:lbl|fn|FUN|func|sub|DAT|PTR|dat|jumptable|switch)_)[A-Za-z]\w*?_[0-9A-Fa-f]{8}\w*(?=\s*(?:[*&]|::|<))",
       "types"),
    _p("retype_macro", "#define re-typings of globals or functions",
       r"#\s*define\s+(\w+)\s+\(\s*\*\s*\([^)]*\*\s*\)\s*&\s*\1\s*\)|#\s*define\s+(\w+)\s+\(\s*\([^)]*\(\s*\*\s*\)\s*\([^)]*\)\s*\)\s*\2\s*\)",
       "types"),
    _p("decomp_temp", "m2c temporaries (temp_r3, var_f31)", r"\b(?:temp|var)_[rfa]\d+(?:_\d+)?\b", "decompiler"),
    _p("stack_local", "stack-slot locals (sp8, sp1C)", r"\bsp[0-9A-F]{1,3}\b", "decompiler"),
    _p("arg_name", "argN parameters (arg0, farg1)", r"\bf?arg\d+\b", "decompiler"),
    _p("ghidra_temp", "Ghidra temporaries (iVar1, puVar2, param_1, local_10)",
       r"\b(?:[a-z]{1,3}Var\d+|param_\d+|local_[0-9a-fA-F]+|unaff_\w+|extraout_\w+|auStack_\w+|"
       r"in_(?:[a-z]{1,4}\d+|lr|ctr|xer|fpscr|fpcr|sp|pc|nzcv|tpidr\w*|stack_[0-9a-fA-F]+|[A-Z]\w*))\b",
       "decompiler"),
    _p("m2c_macro", "m2c helper macros (M2C_FIELD, M2C_ERROR)", r"\bM2C_\w+", "decompiler"),
    # an address of the executable's image in a comment (`address_comments`): where code came from belongs in
    # history, what it is belongs in its name
    _p("address_comment", "comments naming an address of the image (// moved from 0x8043E828)", _NEVER,
       "decompiler", blocks_port=False),
    _p("data_label", "address-named data (lbl_8045A010, DAT_, Class__data_)",
       r"\b(?:lbl|DAT|PTR|dat)_[0-9A-Fa-f]{6,16}\b|\b\w+__data_[0-9A-Fa-f]{6,16}\b", "names"),
    _p("function_placeholder", "address-named functions (fn_, FUN_, sub_, Class__sub_)",
       r"\b(?:fn|FUN|func|sub)_[0-9A-Fa-f]{6,16}\b|\b\w+__sub_[0-9A-Fa-f]{6,16}\b", "names"),
    _p("address_in_name", "names built around an address (call_36A90_with_1)",
       r"\b(?!(?:lbl|fn|sub|func|dat|ptr|jumptable|switch|temp|var|arg|sp|text|data|bss|rodata)_[0-9A-F])"
       r"[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*_(?=[0-9A-F]*\d)[0-9A-F]{5,8}_[A-Za-z0-9]\w*\b", "names"),
    _p("vtable_symbol", "vtable symbols spelled in source (__vt__, _ZTV)", r"\b__vt__\d+\w+|\b_ZTV\w+|\b\w+__vtable\b",
       "vtables"),
    _p("hand_vtable", "hand-written function tables standing in for vtables",
       r"\bvoid\s*\*\s*(?:const\s+)?\w*(?:vt|vtable|vtbl)\w*\s*\[\s*\d*\s*\]\s*=", "vtables", flags=re.I),
    _p("filler_virtual", "filler virtuals (VA, CAT(f, __LINE__), reserved_N, slotNN)",
       r"CAT\s*\(\s*\w+\s*,\s*__LINE__\s*\)|\bvirtual\s+\w[\w\s\*&]*\b(?:reserved|virtual|slot|dummy|pad)_?\d+\s*\(",
       "vtables"),
    _p("slot_name", "vtable-slot names (vfunc_67, vf12, Class__vt82)", r"\bvfunc_?\d+(?!\d)|\bvf\d+\b|\b[A-Za-z_]\w*?__vt\d+(?!\d)",
       "vtables"),
    _p("local_virtual", "virtual declarations in source files (TU-local stand-in classes)",
       r"(?m)^\s*virtual\b[^;{]*[;{]", "vtables", sources_only=True),
    # where units and classes live: a unit named after an address is a fragment not yet in its real unit, a class
    # declared in a C++ source file is a stand-in or a layout kept out of its header, and a class with a body in
    # more than one file is a copy (`address_unit`, `local_classes`, `duplicates`)
    _p("address_unit", "units named after an address (TEnemy_80123456.cpp)", _NEVER, "placement",
       blocks_port=False, sources_only=True),
    _p("local_class", "classes declared in C++ source files instead of a header", _NEVER, "placement",
       blocks_port=False, sources_only=True),
    _p("duplicate_class", "classes declared in more than one file", _NEVER, "placement", blocks_port=False),
    _p("inline_asm", "assembly in source (asm blocks, __asm__)",
       r"\basm\s*\{|\b__asm__\b|\basm\s+[\w\s\*&:~<>,]+?\w+\s*\([^;]*\)\s*\{", "asm"),
)
SUMMARY_GROUPS = ("linkage", "layout", "types", "names", "vtables", "decompiler", "placement", "asm")
_DEFAULTS = {p.key: p for p in DEFAULT_PATTERNS}
_STRING_CAST = re.compile(_DEFAULTS["string_cast"].regex.pattern + r'(?:\\.|[^"\\\n])*"')   # with the literal
CPP_SUFFIXES = {".cc", ".cp", ".cpp", ".cxx"}


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


def blank_comments(text: str) -> str:
    """`text` with comments and string literals dropped as `_strip_comments` drops them, but every line kept in
    place, so a line read on its own inside a block comment is not taken for code."""
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"',
                  lambda m: "\n" * m[0].count("\n") if m[0][0] == "/" else '""', text, flags=re.S)


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


_PUNCTUATION = re.compile(r"[()\[\]{;]")


def _items(code: str, start: int, stop: int, single: bool) -> list[tuple[int, int, bool]]:
    """(start, end, has a body) of each declaration from `start`: one, or every one inside a block."""
    from .cxx import _matching
    out, begin, index, depth = [], start, start, 0
    while index < stop:
        found = _PUNCTUATION.search(code, index, stop)
        if found is None:
            break
        index, c = found.start(), found[0]
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


def _line_index(code: str):
    """The 1-based line of an offset in `code`."""
    starts = [0] + [m.end() for m in re.finditer(r"\n", code)]
    return lambda offset: bisect.bisect_right(starts, offset)


class _Source:
    """One file's text, and what the parsers read from it (blanked text, function definitions, class bodies, line
    numbers), each computed once and only when a check needs it."""

    def __init__(self, text: str):
        self.text = text
        self._code = self._defs = self._bodies = self._line = None

    @property
    def code(self) -> str:
        if self._code is None:
            from .cxx import blank
            self._code = blank(self.text)
        return self._code

    @property
    def defs(self) -> list:
        if self._defs is None:
            from .cxx import definitions
            self._defs = definitions(self.text, self.code)
        return self._defs

    @property
    def bodies(self) -> list[tuple[int, str, str]]:
        if self._bodies is None:
            self._bodies = class_bodies(self.code) if _HAS_CLASS.search(self.text) else []
        return self._bodies

    def line(self, offset: int) -> int:
        if self._line is None:
            self._line = _line_index(self.code)
        return self._line(offset)


def extern_c_debt(text: str, source: _Source | None = None) -> list[tuple[int, str]]:
    """(1-based line, name) of each `extern "C"` in a source file that is linkage debt: a declaration of a name the
    file does not define (a call-site prototype; it belongs in the owner's header), or a C name on a C++ function
    (a hand-mangled spelling). A definition under `extern "C"` (a body, an initializer, an object inside an
    `extern "C" { }` block) gives what this file owns its C name, and a forward declaration of one is fine."""
    from .cxx import _matching
    if "extern" not in text:
        return []
    source = source or _Source(text)
    code = source.code
    mangled = [p.regex for p in DEFAULT_PATTERNS if p.key.startswith("mangled_")]
    defined, declared, debt = set(), [], []
    for match in _EXTERN_C.finditer(text):
        if code[match.start():match.start() + 6] != "extern":   # in a comment or a string
            continue
        at = match.end()
        block = code[at:at + 1] == "{"
        stop = _matching(code, at) if block else len(code)
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
                where = source.line(begin + len(head) - len(head.lstrip()))
                if any(r.fullmatch(name) for r in mangled):
                    debt.append((where, name))
                elif body or initialized or (block and not extern and not function):
                    defined.add(name)
                else:
                    declared.append((where, name))
    if declared:   # what else the file defines: function bodies, and objects initialized outside a body
        spans = []   # bodies by offset, not by line: `void f() { g = 1; }` on one line still holds `g = 1`
        for definition in source.defs:
            defined.add(definition.name.split("::")[-1])
            spans.append(definition.span)
        spans.sort()
        opens = [a for a, _ in spans]
        for found in re.finditer(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\]\s*)*=(?!=)", code):
            index = bisect.bisect_left(opens, found.start()) - 1
            if index < 0 or not found.start() < spans[index][1]:
                defined.add(found[1])
        debt += [(where, name) for where, name in declared if name not in defined]
    return sorted(debt)


_MACRO_NAME = re.compile(r"[A-Z][A-Z0-9_]*")   # MACRO(...) at file scope is an invocation, not a prototype


def _file_scope(text: str, code: str, start: int, stop: int, under_c: bool,
                out: list[tuple[int, int, bool, bool]]) -> None:
    """(begin, end, has a body, under extern "C") of each declaration and definition at file scope, inside
    namespaces and extern "C" blocks too. A class body or an initializer stays part of its declaration."""
    from .cxx import _matching
    begin = index = start
    depth = 0
    while index < stop:
        found = _PUNCTUATION.search(code, index, stop)
        if found is None:
            break
        at, c = found.start(), found[0]
        index = at + 1
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= depth > 0
        elif depth:
            continue
        elif c == ";":
            out.append((begin, at, False, under_c))
            begin = index
        else:
            close = _matching(code, at)
            head = code[begin:at]
            lead = begin + len(head) - len(head.lstrip())
            if re.fullmatch(r"\s*extern\s*", head):   # extern "C" { (its string blanked)
                _file_scope(text, code, at + 1, close, under_c or bool(_EXTERN_C.match(text, lead)), out)
                begin = index = close + 1
            elif re.fullmatch(r"\s*(?:inline\s+)?namespace\b[\w\s:]*", head):
                _file_scope(text, code, at + 1, close, under_c, out)
                begin = index = close + 1
            elif _top_level(head, "=") or "(" not in head:
                index = close + 1
            else:
                out.append((begin, close + 1, True, under_c))
                begin = index = close + 1


def _unbraced(head: str) -> str:
    """head with every {...} (a class body, an initializer) replaced by spaces."""
    out, depth = [], 0
    for c in head:
        depth += c == "{"
        out.append(" " if depth else c)
        depth -= c == "}" and depth > 0
    return "".join(out)


def local_decl_debt(text: str, source: _Source | None = None) -> list[tuple[int, str]]:
    """(1-based line, declaration) of each prototype or `extern` at file scope of a source file, outside
    `extern "C"` (extern_c judges those), that names nothing the file defines: it belongs in the header of the
    file that defines it, which this file should include."""
    from .cxx import _NOT_A_NAME
    source = source or _Source(text)
    code = source.code
    items: list[tuple[int, int, bool, bool]] = []
    _file_scope(text, code, 0, len(code), False, items)
    declared = []
    defined = set()
    for begin, end, body, under_c in items:
        if body:
            continue
        head = _unbraced(_drop_attributes(code[begin:end]))
        lead = begin + len(head) - len(head.lstrip())
        if not head.strip() or _NOT_DECLARED.match(head):
            continue
        single_c = bool(_EXTERN_C.match(text, lead))
        extern = bool(re.match(r"\s*extern\b", head))
        internal = bool(re.match(r"\s*(?:static|inline)\b", head))
        commas = _top_level(head, ",")
        for a, b in zip([0, *(i + 1 for i in commas)], [*commas, len(head)]):
            piece = head[a:b]
            initialized = _top_level(piece, "=")
            found = _declared(piece[:initialized[0]] if initialized else piece)
            if found is None or found[0] in _NOT_A_NAME or _MACRO_NAME.fullmatch(found[0]):
                continue
            name, function = found
            if initialized or not (function or extern):
                defined.add(name)
            elif not (under_c or single_c or (function and internal)):
                declared.append((lead, name, " ".join(head.split())[:80]))
    if not declared:
        return []
    defined |= {d.name.split("::")[-1] for d in source.defs}
    return [(source.line(lead), found) for lead, name, found in declared if name not in defined]


_LITERAL_OR_COMMENT = re.compile(r'R"(?P<d>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=d)"|"(?:\\.|[^"\\\n])*"|'
                                 r"'(?:\\.|[^'\\\n])*'|//[^\n]*|/\*.*?\*/", re.S)
_ADDRESS = re.compile(r"\b(?:0[xX])?(8[0-3][0-9A-Fa-f]{6})\b")
_UNIT_ADDRESS = re.compile(r"_(8[0-3][0-9A-Fa-f]{6})")


def address_comments(text: str, image: tuple[int, int] | None) -> list[tuple[int, str]]:
    """(1-based line, comment) of each comment that names an address in the executable's image (`image_range`).
    Other 0x8xxxxxxx values (masks, OS globals, heap addresses) are not code or data addresses."""
    if not image:
        return []
    out, line = [], None
    for match in _LITERAL_OR_COMMENT.finditer(text):
        if match[0][0] != "/":
            continue
        address = next((a for a in _ADDRESS.finditer(match[0]) if image[0] <= int(a[1], 16) < image[1]), None)
        if address:
            line = line or _line_index(text)
            out.append((line(match.start() + address.start()), " ".join(match[0].split())[:80]))
    return out


def string_casts(text: str) -> list[tuple[int, str]]:
    """(1-based line, cast with its literal) of each string literal cast to an integer type. Read on the text with
    comments and the insides of literals blanked (offsets kept), so `"(u32)"` inside a string is no cast."""
    if '"' not in text:
        return []
    kept = _LITERAL_OR_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0][0] == "/" else
                                   m[0][0] + re.sub(r"[^\n]", " ", m[0][1:-1]) + m[0][-1], text)
    found = list(_DEFAULTS["string_cast"].regex.finditer(kept))
    if not found:
        return []
    line = _line_index(kept)
    return [(line(m.start()), " ".join((_STRING_CAST.match(text, m.start()) or m)[0].split())[:80]) for m in found]


def address_unit(rel: str, image: tuple[int, int] | None) -> list[tuple[int, str]]:
    """A source file named after an address of the image: a fragment that is not in its real unit yet."""
    path = Path(rel)
    if image and any(image[0] <= int(m[1], 16) < image[1] for m in _UNIT_ADDRESS.finditer(path.stem)):
        return [(1, path.name)]
    return []


_CLASS_BODY = re.compile(r"\b(typedef\s+)?(class|struct|union)\b\s*(?:([A-Za-z_]\w*)\s*)?(?:final\s*)?"
                         r"(?::(?!:)\s*[^{};]*)?\{")
_HAS_CLASS = re.compile(r"\b(?:class|struct|union)\b")


def class_bodies(code: str) -> list[tuple[int, str, str]]:
    """(offset, keyword, name) of each class body in blanked source not nested in another one, named by its tag
    or, for an anonymous one, by its typedef. Anonymous bodies without a typedef (one variable's type) are left
    out."""
    from .cxx import _matching
    out, outer_end = [], -1
    for match in _CLASS_BODY.finditer(code):
        brace = match.end() - 1
        if brace < outer_end or code[max(0, match.start() - 12):match.start()].rstrip().endswith("enum"):
            continue
        outer_end = _matching(code, brace)
        name = match[3]
        if not name and match[1]:
            typedef = re.match(r"\s*([A-Za-z_]\w*)\s*[;,\[]", code[outer_end + 1:outer_end + 200])
            name = typedef and typedef[1]
        if name:
            out.append((match.start(), match[2], name))
    return out


def local_classes(rel: str, source: _Source) -> list[tuple[int, str]]:
    """(line, class) of each class a C++ source file declares instead of a header. C files are left out: C code
    keeps a struct only one file uses in that file."""
    if Path(rel).suffix.lower() not in CPP_SUFFIXES:
        return []
    return [(source.line(offset), f"{keyword} {name}") for offset, keyword, name in source.bodies]


def duplicates(bodies: dict[str, dict[str, int]]) -> dict[str, list[tuple[int, str]]]:
    """Classes with a body in more than one file (`bodies`: path -> class -> line): every copy after the first, by
    the file holding it, a header's copy counting as the first. A name declared only in .c files is left out, since
    separate C files may each keep their own struct."""
    homes = collections.defaultdict(list)
    for rel, names in bodies.items():
        for name, line in names.items():
            homes[name].append((rel, line))
    out = collections.defaultdict(list)
    for name, places in homes.items():
        if len(places) < 2 or all(Path(rel).suffix.lower() == ".c" for rel, _ in places):
            continue
        places.sort(key=lambda place: (Path(place[0]).suffix.lower() not in HEADER_SUFFIXES, place[0]))
        for rel, line in places[1:]:
            out[rel].append((line, name))
    return dict(out)


# Checks a parser judges, with what it needs: "file" a whole file and its path, "image" the image's address range.
# Each takes (path or None, text, source, image) and gives [(1-based line, text of the finding)].
PARSED = {
    "extern_c": ((), lambda rel, text, source, image: [(n, f'extern "C" {name}')
                                                         for n, name in extern_c_debt(text, source)]),
    "local_decl": ((), lambda rel, text, source, image: local_decl_debt(text, source)),
    "string_cast": ((), lambda rel, text, source, image: string_casts(text)),
    "address_comment": (("image",), lambda rel, text, source, image: address_comments(text, image)),
    "address_unit": (("file", "image"), lambda rel, text, source, image: address_unit(rel, image)),
    "local_class": (("file",), lambda rel, text, source, image: local_classes(rel, source)),
}
TREE_CHECKS = {"duplicate_class"}   # judged over every file at once (`duplicates`)


def _parsed(pattern: Pattern) -> bool:
    """The pattern is judged by its parser (a manifest that replaces its regex judges it by the regex)."""
    return pattern.key in PARSED and pattern.regex.pattern == _DEFAULTS[pattern.key].regex.pattern


def parsed_findings(text: str, catalog: Iterable[Pattern], rel: str | None = None, header: bool = False,
                    image: tuple[int, int] | None = None, source: _Source | None = None) -> list[tuple[int, str, str]]:
    """(1-based line, key, text) of the parser-judged checks in a whole file. Those that need the file's path or the
    image's range are skipped without them."""
    if rel is not None:
        header = Path(rel).suffix.lower() in HEADER_SUFFIXES
    source = source or _Source(text)
    out = []
    for pattern in catalog:
        if (header and pattern.sources_only) or not _parsed(pattern):
            continue
        needs, judge = PARSED[pattern.key]
        if ("file" in needs and rel is None) or ("image" in needs and not image):
            continue
        out += [(line, pattern.key, found) for line, found in judge(rel, text, source, image)]
    return out


def count(text: str, catalog: Iterable[Pattern], header: bool = False, rel: str | None = None,
          image: tuple[int, int] | None = None, source: _Source | None = None) -> collections.Counter:
    """Debt per pattern in a file (`rel` its path, which also says whether it is a header) or a piece of one."""
    catalog = list(catalog)
    if rel is not None:
        header = Path(rel).suffix.lower() in HEADER_SUFFIXES
    code = _strip_comments(text)
    found = collections.Counter()
    for pattern in catalog:
        if (header and pattern.sources_only) or _parsed(pattern) or pattern.key in TREE_CHECKS:
            continue
        found[pattern.key] += sum(1 for _ in pattern.regex.finditer(code))
    found.update(key for _, key, _ in parsed_findings(text, catalog, rel, header, image, source))
    return found


def image_range(project: Project | None, repo: str | None) -> tuple[int, int] | None:
    """The executable's address range (its first section to the end of .bss), which address comments and units
    named after an address are read against: the manifest's `quality.image` ([start, end]), else the original DOL of
    a target built from the repository. None (no such checks) when neither is known."""
    if not project or not repo:
        return None
    config = project.config["repositories"][repo].get("quality", {})
    if config.get("image"):
        start, end = (int(v, 0) if isinstance(v, str) else int(v) for v in config["image"][:2])
        return start, end
    from .inspect_dol import _dol
    for name, target in project.config.get("targets", {}).items():
        if target.get("repository") != repo:
            continue
        try:
            image = _dol(project, name)
        except (ValueError, OSError):
            continue
        if not hasattr(image, "bss") or not image.sections:   # a GameCube/Wii DOL
            continue
        start = min(s.address for s in image.sections)
        end = max([s.address + s.size for s in image.sections] + [image.bss[0] + image.bss[1]])
        return start, end
    return None


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
    image = image_range(project, repo)
    tree = {p.key for p in catalog if p.key in TREE_CHECKS and p.regex.pattern == _NEVER}
    totals: collections.Counter = collections.Counter()
    per_file: dict[str, collections.Counter] = {}
    bodies: dict[str, dict[str, int]] = {}
    scanned = 0
    for rel, text in files:
        scanned += 1
        source = _Source(text)
        found = +count(text, catalog, rel=rel, image=image, source=source)   # zero counts dropped
        if found:
            totals.update(found)
            per_file[rel] = found
        if "duplicate_class" in tree and source.bodies:
            bodies[rel] = {}
            for offset, _, name in source.bodies:
                bodies[rel].setdefault(name, source.line(offset))
    for rel, copies in (duplicates(bodies) if "duplicate_class" in tree else {}).items():
        totals["duplicate_class"] += len(copies)
        per_file.setdefault(rel, collections.Counter())["duplicate_class"] += len(copies)
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
    judges itself (check reads the parser-judged checks against the whole file, `parsed_findings`). Of those, only
    `extern "C"` and string casts are judged in a piece; the rest need the whole file, its path or the whole tree."""
    code = _strip_comments(text)
    out = []
    for pattern in catalog:
        if (header and pattern.sources_only) or pattern.key in skip or pattern.key in TREE_CHECKS:
            continue
        if _parsed(pattern):
            judge = {"extern_c": lambda: [f'extern "C" {name}' for _, name in extern_c_debt(text)],
                     "string_cast": lambda: [found for _, found in string_casts(text)]}.get(pattern.key)
            out += [{"key": pattern.key, "label": pattern.label, "text": found, "group": pattern.group,
                     "blocks": pattern.blocks_port} for found in (judge() if judge else [])]
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
