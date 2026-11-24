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
import itertools
import math
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Container, Iterable

from .misowned import misowned_members
from .project import Project

SOURCE_SUFFIXES = {".c", ".cc", ".cp", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
CPP_SUFFIXES = {".cc", ".cp", ".cpp", ".cxx"}           # C++ source files
CXX_FILES = CPP_SUFFIXES | {".hh", ".hpp", ".hxx"}      # C++ files: sources and C++-only headers (.h is either)


@dataclass(frozen=True)
class Pattern:
    key: str
    label: str
    regex: re.Pattern
    group: str      # what kind of debt: linkage, layout, types, names, vtables, decompiler, asm
    blocks_port: bool = True  # inside a function body, the function is not yet a readable behavior reference
    sources_only: bool = False  # counted in .c/.cpp files only (headers may legitimately contain it)
    needle: re.Pattern | None = None   # text every match contains: files without it are skipped (speed only)


def _p(key: str, label: str, regex: str, group: str, blocks_port: bool = True, flags: int = 0,
       sources_only: bool = False, needle: str | None = None) -> Pattern:
    return Pattern(key, label, re.compile(regex, flags), group, blocks_port, sources_only,
                   re.compile(needle) if needle else None)


_EXTERN_PATTERN = r'\bextern\s+"C"'
_NEVER = r"(?!)"   # judged by a parser (PARSED) or over the whole tree (TREE_CHECKS), not by a pattern
# Placeholder offsets in names; real words spelled in hex digits are names, not offsets.
_HEX_OFFSET = (r"(?:0x)?(?!(?i:add|bad|bed|cab|dab|dad|ebb|fab|fad|fed|fee|ace|bee|cafe|face|fade|dead|deaf|beef|"
               r"babe|bead|cede|dace|abbe)\b)[0-9A-Fa-f]{1,4}\b")
_BYTE_TYPE = r"(?:u8|s8|char|unsigned\s+char|signed\s+char|uint8_t|int8_t|byte|undefined1?)"
_BYTE_CAST = r"\(\s*(?:const\s+)?" + _BYTE_TYPE + r"\s*\*\s*\)\s*(?:\(\s*[\w.\->]+\s*\)|[\w.\->]+)\s*"
_PLUS_OFFSET = r"\+\s*(?:0x[0-9A-Fa-f]+|\d+)\b(?!\s*[\[(])"
_THIS_INIT = (r"(?:\(\s*(?:const\s+)?(?:(?:struct|class)\s+)?[A-Za-z_][\w:]*\s*\*\s*\)"
              r"|(?:reinterpret|static)_cast\s*<[^>]*\*\s*>\s*)\(?\s*this\b")   # (T *)this, static_cast<T *>(this)
_SELF_THIS = r"self\s*=\s*this\s*;"   # self = this; (any other name set to a bare this is often a cursor)
# The integer types a pointer is cast to and back from.
_INT_TYPE = r"(?:[su]addr|u32|s32|u?intptr_t|int|long|unsigned(?:\s+(?:int|long))?)"

# Defaults cover CodeWarrior (GameCube/Wii) and Clang/GCC (Itanium ABI) decomps and both m2c and Ghidra output.
# A project adds or replaces patterns in its manifest (`quality.patterns`: key -> {label, regex, group}).
DEFAULT_PATTERNS: tuple[Pattern, ...] = (
    # a C module's header declares its functions in a guarded extern "C" block (the contract's rule 6), and a
    # definition gives what its file owns the original's C name; a source file's declaration of what another file
    # defines, or a C name on a C++ function, is the debt (`extern_c_debt`)
    _p("extern_c", 'extern "C" declarations of what another file defines', _EXTERN_PATTERN, "linkage",
       blocks_port=False, sources_only=True),
    # a header's extern "C" on a function a C++ unit defines (and no C unit): C linkage on what is a member or a
    # C++ function (`extern_c_functions` against the config's symbols and splits)
    _p("header_extern_c", 'extern "C" on C++ functions in headers (extern "C" void widget_update(TWidget *);)',
       _NEVER, "linkage", blocks_port=False),
    # a prototype or `extern` at file scope of a source file, or inside a function body, for what another file
    # defines: it belongs in that file's header (`local_decl_debt`, `block_decls`)
    _p("local_decl", "prototypes and externs in source files and function bodies (void heap_free(void *);)", _NEVER,
       "linkage", blocks_port=False, sources_only=True),
    # a member written as a C function on a `self` receiver (`self_params`)
    _p("self_param", "self receivers in C++ files (void widget_draw(TWidget *self))", _NEVER, "linkage",
       blocks_port=False),
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
    _p("offset_member", "offset-named members (unk_30, m_c, field_96, set_field_378, ->f30, ->x7A, ->b9)",
       r"\b(?:m_|unk_?|unknown_?|field_?|mbr_)" + _HEX_OFFSET +
       r"|\b[A-Za-z]\w*?_(?:field|unk|unknown)_?" + _HEX_OFFSET +
       r"|(?:->|\.)\s*f(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{2,4}\b|\b[a-z]\w*Field_?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{1,4}\b"
       r"|(?:->|\.)\s*(?!f[0-9A-Fa-f]{2,4}\b)(?![usf](?:8|16|32|64)\b)(?!m[0-3][0-3]\b)(?!ip\d+\b)(?!sp[0-9A-F])"
       r"[a-z]{1,2}(?=[0-9A-F])(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{2,4}\b"
       r"|(?:->|\.)\s*[bfhw][0-9A-F]\b", "layout"),   # one hex digit: byte, field, half or word at 0-F
    # a padding field a function body reads or writes has a meaning (`pad_accesses`)
    _p("pad_access", "padding fields read or written (p->pad_3E = 0)", _NEVER, "layout"),
    _p("size_assert", "hand-written size asserts (typedef char check[sizeof(T) == 8 ? 1 : -1];)", _NEVER, "layout",
       blocks_port=False),
    _p("blob_type", "size-named blob types (ByteBlock_28)", r"\bByteBlock_?(?:0x)?[0-9A-Fa-f]{1,4}\b", "layout",
       needle=r"ByteBlock"),
    # judged over every file (`overlay_types`)
    _p("overlay_type", "structs only reached by casts (struct PhaseView { u8 pad[0x28]; s32 phase; };)", _NEVER,
       "layout"),
    _p("fp_cast", "calls through function-pointer casts ((void (*)(T *))p)",
       r"\(\s*[A-Za-z_][\w:\s\*&<>,]*\(\s*\*+\s*\)\s*\([^()]*\)\s*\)\s*[\w(*&]", "types"),
    # counted on the text with its string literals kept (`string_casts`)
    _p("string_cast", "string literals cast to integers ((saddr)\"file.gvm\")",
       r"\(\s*" + _INT_TYPE + r"\s*\)\s*\"", "types"),
    _p("ghidra_type", "Ghidra placeholder types (undefined4, code *)", r"\bundefined[1248]?\b", "types"),
    _p("address_type", "address-named types (Obj_800EB910 *, TUnk_804806E8::, VObj_18_...)",
       r"\b(?:struct|class|union)\s+[A-Za-z]\w*?_[0-9A-Fa-f]{8}\w*"
       r"|\b(?!(?:lbl|fn|FUN|func|sub|DAT|PTR|dat|jumptable|switch)_)[A-Za-z]\w*?_[0-9A-Fa-f]{8}\w*(?=\s*(?:[*&]|::|<))",
       "types"),
    _p("retype_macro", "#define re-typings of globals or functions",
       r"#\s*define\s+(\w+)\s+\(\s*\*\s*\([^)]*\*\s*\)\s*&\s*\1\s*\)|#\s*define\s+(\w+)\s+\(\s*\([^)]*\(\s*\*\s*\)\s*\([^)]*\)\s*\)\s*\2\s*\)",
       "types"),
    # a lower-case object-like macro standing in for an expression (re-typing macros are counted above)
    _p("alias_macro", "lower-case object macros (#define obj ((T *)this))",
       r"(?m)^[ \t]*#[ \t]*define[ \t]+(?!_|nullptr\b)([a-z]\w*)[ \t]+"
       r"(?!\(\s*\*\s*\([^)]*\*\s*\)\s*&\s*\1\s*\)|\(\s*\([^)]*\(\s*\*\s*\)\s*\([^)]*\)\s*\)\s*\1\s*\))\S[^\n]*",
       "types", needle=r"define[ \t]+[a-z]"),
    _p("this_alias", "aliases of this (TWidget *self = (TWidget *)this;)",
       r"\b[A-Za-z_][\w:]*\s*\*\s*(?:const\s+)?(?:\w+\s*=\s*" + _THIS_INIT + r"\s*\)?\s*;|" + _SELF_THIS + ")",
       "types", needle=r"this"),
    # an integer cast to a pointer (a round trip when the integer was a pointer), and a pointer cast to an integer
    _p("ptr_int_roundtrip", "casts between pointers and integers ((T *)(u32)p, (u32)(T *)p)",
       r"\(\s*(?:const\s+)?[A-Za-z_]\w*\s*\*+\s*\)\s*\(\s*" + _INT_TYPE + r"\s*\)"
       r"|\(\s*" + _INT_TYPE + r"\s*\)\s*\(\s*(?:const\s+)?[A-Za-z_]\w*\s*\*+\s*\)", "types"),
    _p("repeat_cast", "values cast to one type again and again (((TWidget *)p)->x = ((TWidget *)p)->y;)", _NEVER,
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
    _p("address_comment", "comments naming an address of the image or a placeholder (// moved from 0x8043E828, "
       "// was fn_80123456)", _NEVER, "decompiler", blocks_port=False),
    # a local or parameter named after a register (`register_names`), a decompiler's labels, a permuter's
    # variables, and statements that do nothing (`no_ops`)
    _p("register_name", "register-style locals and parameters (f32 f31; void f(s32 r3))", _NEVER, "decompiler"),
    _p("decomp_label", "decompiler labels (goto block_12;)",
       r"(?m)\bgoto\s+(?:block|loop|label|lbl|L|bb|jump|case|lab)_?[0-9A-Fa-f]+\b"
       r"|^\s*(?:block|loop|label|lbl|bb|lab)_?[0-9A-Fa-f]+\s*:(?!:)", "decompiler",
       needle=r"goto|(?:block|loop|label|lbl|bb|lab)_?[0-9A-Fa-f]+\s*:"),
    _p("permuter_var", "permuter variables (new_var2, phi_r3)", r"\bnew_var\d*\b|\bsaved_reg_\w+|\bphi_[rf]\d+\b",
       "decompiler", needle=r"new_var|saved_reg_|phi_"),
    _p("no_op", "no-op statements (x = x; if (1))", _NEVER, "decompiler", blocks_port=False),
    _p("data_label", "address-named data (lbl_8045A010, DAT_, Class__data_)",
       r"\b(?:lbl|DAT|PTR|dat)_[0-9A-Fa-f]{6,16}\b|\b\w+__data_[0-9A-Fa-f]{6,16}\b", "names"),
    _p("function_placeholder", "address-named functions (fn_, FUN_, sub_, Class__sub_)",
       r"\b(?:fn|FUN|func|sub)_[0-9A-Fa-f]{6,16}\b|\b\w+__sub_[0-9A-Fa-f]{6,16}\b", "names"),
    _p("address_in_name", "names built around an address (call_36A90_with_1)",
       r"\b(?!(?:lbl|fn|sub|func|dat|ptr|jumptable|switch|temp|var|arg|sp|text|data|bss|rodata)_[0-9A-F])"
       r"[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*_(?=[0-9A-F]*\d)[0-9A-F]{5,8}_[A-Za-z0-9]\w*\b", "names"),
    # any other identifier holding an address of the image (`address_idents`)
    _p("address_ident", "other address-named identifiers (Thing_80123456)", _NEVER, "names"),
    # a parameter named by a placeholder in a prototype or its definition and really named in the other
    # (`param_names`)
    _p("param_name_split", "placeholder parameters named on the other side (f(int arg0); / f(int count) {)", _NEVER,
       "names", blocks_port=False),
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
    # where units and classes live: a unit named after an address is a fragment not yet in its real unit (a header
    # counts only when no unit has its name, since one rename fixes both), a class declared in a C++ source file is
    # a stand-in or a layout kept out of its header, a class with a body in more than one file is a copy, and a
    # member whose body uses nothing of its class's hierarchy belongs to another class (`address_unit`,
    # `local_classes`, `duplicates`, `misowned.misowned_members`)
    _p("address_unit", "units and headers named after an address (TEnemy_80123456.cpp)", _NEVER, "placement",
       blocks_port=False),
    _p("local_class", "classes declared in C++ source files instead of a header", _NEVER, "placement",
       blocks_port=False, sources_only=True),
    _p("duplicate_class", "classes declared in more than one file", _NEVER, "placement", blocks_port=False),
    _p("misowned_member", "member functions that belong to another class", _NEVER, "placement", blocks_port=False),
    _p("inline_asm", "assembly in source (asm blocks, __asm__)",
       r"\basm\s*\{|\b__asm__\b|\basm\s+[\w\s\*&:~<>,]+?\w+\s*\([^;]*\)\s*\{", "asm"),
)
# How a report names each check, with what it looks like (a manifest's own pattern shows its label), and each
# group's title.
DISPLAY = {   # key -> (name, example)
    "extern_c": ('extern "C" declarations', 'extern "C" void TEnemy__update(void *);'),
    "header_extern_c": ('extern "C" on C++ functions in headers', 'extern "C" void widget_update(TWidget *);'),
    "local_decl": ("Prototypes and externs in source files", "void heap_free(void *);"),
    "self_param": ("self receivers in C++", "void widget_draw(TWidget *self)"),
    "mangled_member": ("Hand-mangled member names", "update__6TEnemyFv"),
    "mangled_free": ("Hand-mangled free functions", "helper__Fv"),
    "mangled_itanium": ("Itanium-mangled names", "_ZN6TEnemy6updateEv"),
    "flat_name": ("Members spelled as C names", "TEnemy__update"),
    "raw_offset": ("Byte-pointer offsets", "(u8 *)p + 0x30"),
    "offset_cast": ("Casts of pointer plus offset", "(Vec *)(p + 0x178)"),
    "punned_deref": ("Type-punned dereferences", "*(f32 *)&x, *(s32 *)(p + 0x18)"),
    "offset_member": ("Offset-named fields", "unk_30, m_c, field_96, set_field_378, ->x7A, ->b9"),
    "pad_access": ("Padding fields read or written", "p->pad_3E = 0"),
    "size_assert": ("Hand-written size asserts", "typedef char check[sizeof(T) == 8 ? 1 : -1];"),
    "blob_type": ("Size-named blob types", "ByteBlock_28"),
    "overlay_type": ("Structs only reached by casts", "struct PhaseView { u8 pad[0x28]; s32 phase; };"),
    "fp_cast": ("Function-pointer casts", "((void (*)(T *))p)(x)"),
    "string_cast": ("Strings cast to integers", '(saddr)"file.gvm"'),
    "ghidra_type": ("Ghidra types", "undefined4"),
    "address_type": ("Address-named types", "TUnk_804806E8"),
    "retype_macro": ("Re-typing macros", "#define g (*(T *)&g)"),
    "alias_macro": ("Lower-case object macros", "#define obj ((T *)this)"),
    "this_alias": ("Aliases of this", "TWidget *self = (TWidget *)this;"),
    "ptr_int_roundtrip": ("Casts between pointers and integers", "(T *)(u32)p, (u32)(T *)p"),
    "repeat_cast": ("Values cast to one type again and again", "((TWidget *)p)->x = ((TWidget *)p)->y;"),
    "decomp_temp": ("m2c temporaries", "temp_r3, var_f31"),
    "stack_local": ("Stack-slot locals", "sp1C"),
    "arg_name": ("Numbered parameters", "arg0, farg1"),
    "ghidra_temp": ("Ghidra temporaries", "iVar1, param_1"),
    "m2c_macro": ("m2c macros", "M2C_FIELD"),
    "address_comment": ("Address comments", "// moved from 0x8043E828, // was fn_80123456"),
    "register_name": ("Register-style names", "f32 f31; void f(s32 r3)"),
    "decomp_label": ("Decompiler labels", "goto block_12;"),
    "permuter_var": ("Permuter variables", "new_var2, phi_r3"),
    "no_op": ("No-op statements", "x = x; if (1)"),
    "data_label": ("Address-named data", "lbl_8045A010"),
    "function_placeholder": ("Address-named functions", "fn_80123456, TEnemy__sub_80123456"),
    "address_in_name": ("Names built on an address", "call_36A90_with_1"),
    "address_ident": ("Other address-named identifiers", "Thing_80123456"),
    "param_name_split": ("Placeholder parameters named on the other side", "f(int arg0); / f(int count) {"),
    "vtable_symbol": ("Vtable symbols in source", "__vt__6TEnemy"),
    "hand_vtable": ("Hand-written vtables", "void *TEnemy_vtable[] = {"),
    "filler_virtual": ("Filler virtuals", "virtual void reserved_3();"),
    "slot_name": ("Slot-numbered names", "vfunc_67, TEnemy__vt82"),
    "local_virtual": ("Virtuals in source files", "virtual void draw();"),
    "address_unit": ("Units named after an address", "TEnemy_80123456.cpp"),
    "local_class": ("Classes declared in source files", "struct EnemyView : TObject {"),
    "duplicate_class": ("Classes declared in more than one file", "class TEnemy {"),
    "misowned_member": ("Members that belong to another class", "TWidget::set_sound_volume(int)"),
    "inline_asm": ("Inline assembly", "asm { ... }"),
}
GROUP_TITLES = {"linkage": "Linkage", "layout": "Layout", "types": "Types", "decompiler": "Decompiler output",
                "names": "Names", "vtables": "Vtables", "placement": "Units and classes", "asm": "Assembly",
                "ownership": "Members in the wrong class (not in the total)"}
# Members written in the wrong class, read from the class declarations: reported beside the debt, not in its total.
OWNERSHIP = {   # key -> (name, example)
    "this_cast": ("Casts of this to an unrelated class", "((TObjPlayer *)this)->f()"),
    "subobject_call": ("Own member called on a sub-object", "TEnemy__f((char *)this + 0x3C)"),
}
_DEFAULTS = {p.key: p for p in DEFAULT_PATTERNS}
_STRING_CAST = re.compile(_DEFAULTS["string_cast"].regex.pattern + r'(?:\\.|[^"\\\n])*"')   # with the literal


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
        self._code = self._defs = self._bodies = self._line = self._kept = None
        self._prototypes: list = []
        self._matches: dict[tuple[str, str], list[re.Match]] = {}

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
            self._defs = definitions(self.text, self.code, self._prototypes)
        return self._defs

    @property
    def prototypes(self) -> list:
        """Function declarations ending in `;`, found with `defs`."""
        if self._defs is None:
            _ = self.defs
        return self._prototypes

    @property
    def bodies(self) -> list[tuple[int, str, str]]:
        if self._bodies is None:
            self._bodies = class_bodies(self.code) if _HAS_CLASS.search(self.text) else []
        return self._bodies

    def line(self, offset: int) -> int:
        if self._line is None:
            self._line = _line_index(self.code)
        return self._line(offset)

    @property
    def kept(self) -> str:
        """blank_comments(text): code and preprocessor lines kept, comments and literals blanked."""
        if self._kept is None:
            self._kept = blank_comments(self.text)
        return self._kept

    def matches(self, pattern: Pattern) -> list[re.Match]:
        """A pattern's matches on `kept`, found once (address_idents reads the address-named checks')."""
        key = (pattern.key, pattern.regex.pattern)
        if key not in self._matches:
            kept = self.kept
            self._matches[key] = [] if pattern.needle and not pattern.needle.search(kept) else \
                list(pattern.regex.finditer(kept))
        return self._matches[key]


def _extern_c_heads(text: str, code: str) -> Iterable[tuple[int, str, bool, bool]]:
    """(offset, head, has a body, in an `extern "C" {` block) of each declaration under `extern "C"`."""
    from .cxx import _matching
    for match in _EXTERN_C.finditer(text):
        if code[match.start():match.start() + 6] != "extern":   # in a comment or a string
            continue
        at = match.end()
        block = code[at:at + 1] == "{"
        stop = _matching(code, at) if block else len(code)
        for begin, end, body in _items(code, at + 1 if block else at, stop, single=not block):
            head = _drop_attributes(code[begin:end].split("{", 1)[0] if body else code[begin:end])
            if head.strip() and not _NOT_DECLARED.match(head):
                yield begin + len(head) - len(head.lstrip()), head, body, block


def _declarators(head: str) -> list[str]:
    """The pieces of a declaration between its top-level commas."""
    commas = _top_level(head, ",")
    return [head[a:b] for a, b in zip([0, *(i + 1 for i in commas)], [*commas, len(head)])]


def extern_c_debt(text: str, source: _Source | None = None) -> list[tuple[int, str]]:
    """(1-based line, name) of each `extern "C"` in a source file that is linkage debt: a declaration of a name the
    file does not define (a call-site prototype; it belongs in the owner's header), or a C name on a C++ function
    (a hand-mangled spelling). A definition under `extern "C"` (a body, an initializer, an object inside an
    `extern "C" { }` block) gives what this file owns its C name, and a forward declaration of one is fine."""
    if "extern" not in text:
        return []
    source = source or _Source(text)
    code = source.code
    mangled = [p.regex for p in DEFAULT_PATTERNS if p.key.startswith("mangled_")]
    defined, declared, debt = set(), [], []
    for lead, head, body, block in _extern_c_heads(text, code):
        initialized = bool(_top_level(head, "="))
        extern = bool(re.match(r"\s*extern\b", head))
        for piece in (head.split("=", 1)[0],) if initialized else _declarators(head):
            found = _declared(piece)
            if found is None:
                continue
            name, function = found
            if any(r.fullmatch(name) for r in mangled):
                debt.append((source.line(lead), name))
            elif body or initialized or (block and not extern and not function):
                defined.add(name)
            else:
                declared.append((source.line(lead), name))
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


def extern_c_functions(text: str, source: _Source) -> list[tuple[int, str]]:
    """(1-based line, name) of each function a header declares under `extern "C"` (header_extern_c judges them
    against the unit that defines each: C linkage is right for a C unit's functions, not a C++ unit's)."""
    out = []
    for lead, head, body, _ in _extern_c_heads(text, source.code):
        if body or _top_level(head, "="):
            continue
        for piece in _declarators(head):
            found = _declared(piece)
            if found and found[1]:
                out.append((source.line(lead), found[0]))
    return out


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


def local_decl_debt(text: str, source: _Source | None = None) -> tuple[list[tuple[int, str]], set[str]]:
    """(1-based line, declaration) of each prototype or `extern` at file scope of a source file, outside
    `extern "C"` (extern_c judges those), that names nothing the file defines: it belongs in the header of the
    file that defines it, which this file should include. Also the names the file defines (its functions and its
    data at file scope)."""
    from .cxx import _NOT_A_NAME
    source = source or _Source(text)
    code = source.code
    items: list[tuple[int, int, bool, bool]] = []
    _file_scope(text, code, 0, len(code), False, items)
    defined = {d.name.split("::")[-1] for d in source.defs}
    declared = []
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
        return [], defined
    return [(source.line(lead), found) for lead, name, found in declared if name not in defined], defined


_LITERAL_OR_COMMENT = re.compile(r'R"(?P<d>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=d)"|"(?:\\.|[^"\\\n])*"|'
                                 r"'(?:\\.|[^'\\\n])*'|//[^\n]*|/\*.*?\*/", re.S)
_ADDRESS = re.compile(r"\b(?:0[xX])?(8[0-5][0-9A-Fa-f]{6})\b")
_UNIT_ADDRESS = re.compile(r"_(8[0-5][0-9A-Fa-f]{6})")
_COMMENT_PLACEHOLDER = re.compile(r"\b(?:fn|lbl|sub|FUN|DAT|func|loc)_[0-9A-Fa-f]{6,8}\b|\w__sub_[0-9A-Fa-f]{6,8}\b")


def address_comments(text: str, image: tuple[int, int] | None) -> list[tuple[int, str]]:
    """(1-based line, comment) of each comment that names an address in the executable's image (`image_range`) or
    a placeholder name (fn_80123456): where code came from belongs in history, what it is belongs in its name.
    Other 0x8xxxxxxx values (masks, OS globals, heap addresses) are not code or data addresses; without an image
    only placeholders are read."""
    out, line = [], None
    for match in _LITERAL_OR_COMMENT.finditer(text):
        if match[0][0] != "/":
            continue
        address = next((a for a in _ADDRESS.finditer(match[0]) if image[0] <= int(a[1], 16) < image[1]),
                       None) if image else None
        placeholder = _COMMENT_PLACEHOLDER.search(match[0])
        if address or placeholder:
            line = line or _line_index(text)
            at = min(m.start() for m in (address, placeholder) if m)
            out.append((line(match.start() + at), " ".join(match[0].split())[:80]))
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


# Slipped decompiler shapes: what a byte match lets through that is still the decompiler's or the permuter's.

def _normal(found: str) -> str:
    return " ".join(found.split())[:80]


def _inside(spans: list[tuple[int, int]]):
    """offset -> whether it falls strictly inside one of the (sorted, disjoint) spans."""
    opens = [a for a, _ in spans]

    def test(offset: int) -> bool:
        index = bisect.bisect_left(opens, offset) - 1
        return index >= 0 and offset < spans[index][1]
    return test


def _outermost(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """The spans not inside another, sorted."""
    out: list[tuple[int, int]] = []
    for a, b in sorted(spans):
        if not out or a >= out[-1][1]:
            out.append((a, b))
    return out


def _in_bodies(source: _Source):
    return _inside(_outermost(d.span for d in source.defs))


_ADDRESS_IDENT = re.compile(r"\b[A-Za-z_]\w*?_(8[0-5][0-9A-Fa-f]{6})(?![0-9A-Fa-f])\w*\b")
_ADDRESS_NAMED = ("data_label", "function_placeholder", "address_type", "address_in_name")


def address_idents(source: _Source, image: tuple[int, int] | None) -> list[tuple[int, str]]:
    """(line, identifier) of each identifier holding an address of the image that the address-named checks
    (data, functions, types, names built on an address) do not count. Include guards (`..._H`) are skipped: they
    follow the header's name, which address_unit counts."""
    if not image:
        return []
    kept = source.kept
    found = [m for m in _ADDRESS_IDENT.finditer(kept)
             if image[0] <= int(m[1], 16) < image[1] and not m[0].endswith(("_H", "_H_"))]
    if not found:
        return []
    spans = sorted(m.span() for key in _ADDRESS_NAMED for m in source.matches(_DEFAULTS[key]))
    ends = list(itertools.accumulate((b for _, b in spans), max))
    starts = [a for a, _ in spans]
    line = _line_index(kept)
    out = []
    for m in found:
        index = bisect.bisect_left(starts, m.end()) - 1   # spans starting before the match ends
        if index >= 0 and ends[index] > m.start():
            continue
        out.append((line(m.start()), m[0][:80]))
    return out


_PAD_ACCESS = re.compile(r"(?:->|\.)\s*(?:m_)?pad_?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{1,4}\b"
                         r"|(?<![\w.>])(?:m_)?pad_?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{1,4}\s*(?:\[[^\]]*\]\s*)*"
                         r"(?:[-+*/|&^]?=(?!=)|\+\+|--)")


def pad_accesses(source: _Source) -> list[tuple[int, str]]:
    """(line, access) of each padding field a function body reads or writes: the field has a meaning."""
    code = source.code
    found = list(_PAD_ACCESS.finditer(code)) if "pad" in code else []
    if not found:
        return []
    inside = _in_bodies(source)
    return [(source.line(m.start()), _normal(m[0])) for m in found if inside(m.start())]


_SELF_PARAM = re.compile(r"[(,]\s*(?:const\s+)?[A-Za-z_][\w:]*\s*\*\s*(?:const\s+)?self\s*[,)]"
                         r"|\b[A-Za-z_][\w:]*\s*\*\s*(?!" + _SELF_THIS + r")self\s*=(?!\s*" + _THIS_INIT + r")")


# (T *)value: a name or a member chain, bare or in parentheses, that is the whole operand (not called, indexed,
# followed by -> or ., or by pointer arithmetic)
_CAST_OF = re.compile(r"\(\s*(?:const\s+)?((?:(?:struct|class|union)\s+)?[A-Za-z_][\w:]*)\s*(\*+)\s*(?:const\s*)?\)\s*"
                      r"(\(\s*)?(?<![\w.>])((?>[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*))(?(3)\s*\))"
                      r"(?!\s*(?:[\w(\[.:]|->|[-+](?![-+=>])))")
_BYTE_POINTEE = {"void", "u8", "s8", "char", "uint8_t", "int8_t", "byte"}


def repeat_casts(source: _Source) -> list[tuple[int, str]]:
    """(line, cast) of each cast of one name or member chain to one pointer type that a function body makes more
    than once: the value is declared as one type and used as another. Casts of this (this_cast), to byte and void
    pointers (raw_offset and offset_cast count their arithmetic) and of call results are left out."""
    code = source.code
    out = []
    for start, stop in _outermost(d.span for d in source.defs if d.span[1] > d.span[0]):
        seen = collections.defaultdict(list)
        for match in _CAST_OF.finditer(code, start, stop):
            pointee = re.sub(r"\b(?:struct|class|union)\s+", "", match[1])
            value = re.sub(r"\s+", "", match[4])
            if pointee not in _BYTE_POINTEE and not re.match(r"(?:this|NULL|nullptr)\b", value):
                seen[f"({pointee} {match[2]}){value}"].append(match.start())
        out += [(source.line(at), cast) for cast, offsets in seen.items() if len(offsets) > 1 for at in offsets]
    return sorted(out)


def self_params(rel: str, source: _Source) -> list[tuple[int, str]]:
    """(line, declaration) of each `self` receiver in a C++ file: a member written as a C function."""
    if Path(rel).suffix.lower() not in CXX_FILES or "self" not in source.text:
        return []
    kept = source.kept
    found = list(_SELF_PARAM.finditer(kept))
    if not found:
        return []
    line = _line_index(kept)
    return [(line(m.start()), _normal(m[0])) for m in found]


_SCALAR = (r"(?:(?:unsigned|signed)\s+)?(?:u8|s8|u16|s16|u32|s32|u64|s64|f32|f64|uaddr|saddr|int|char|short|long|"
           r"float|double|bool|BOOL|uintptr_t|intptr_t|size_t|unsigned|signed|void|vu8|vu16|vu32|vs32)")
# no r0-r2: under the PowerPC EABI r0 is scratch, r1 the stack pointer and r2 the SDA2 base, never a named local
_REGISTER = re.compile(r"\b(?:f(?:[0-9]|[12][0-9]|3[01])|r(?:[3-9]|[12][0-9]|3[01]))\b")
_TYPE_BEFORE = re.compile(r"\b(?:" + _SCALAR + r"|const|struct|class|[A-Z]\w*|[a-z]\w*_t)\s*[\*&]*\s*$")
_COMMA_BEFORE = re.compile(r",\s*[\*&]*\s*$")
_NOT_DECLARATOR = re.compile(r"\b(?:return|case|goto)\s*$")
_DECLARATION = re.compile(r"\s*(?:(?:static|const|register|volatile)\s+)*(?:" + _SCALAR + r"|[A-Z]\w*)\b[^();]*$")
_ASM_LINE = re.compile(r"^\s*(?!" + _SCALAR + r"\s)[a-z_][a-z0-9_]*\.?\s+[rf]\d+\s*,")   # fmr f30, f31
_ASM_BLOCK = re.compile(r"\basm\b[^;{]*\{")


def register_names(text: str, source: _Source) -> list[tuple[int, str]]:
    """(line, declaration) of each local or parameter declared with a register's name (r3, f31) outside assembly:
    where m2c saw the value live, not what it is. Fields are left out (u16 f4; often names its offset)."""
    from .cxx import _matching
    code = source.code
    found = list(_REGISTER.finditer(code))
    if not found:
        return []
    defs = source.defs
    in_scope = _inside(_outermost([d.span for d in defs] + [d.parens for d in defs + source.prototypes]))
    asm: list[tuple[int, int]] = []
    for match in _ASM_BLOCK.finditer(code):
        if not asm or match.start() >= asm[-1][1]:
            asm.append((match.start(), _matching(code, match.end() - 1)))
    in_asm = _inside(asm)
    lines = text.split("\n")
    out = []
    for m in found:
        before = code[max(0, m.start() - 60):m.start()]
        if not in_scope(m.start()) or in_asm(m.start()) or _NOT_DECLARATOR.search(before):
            continue
        if not _TYPE_BEFORE.search(before):
            # `f32 f30, f31;`: a comma counts only in a declaration statement
            start = max(code.rfind(c, 0, m.start()) for c in ";{}") + 1
            if not (_COMMA_BEFORE.search(before) and _DECLARATION.match(code, start, m.start())
                    and _DECLARATION.match(code[start:m.start()])):
                continue
        number = source.line(m.start())
        if _ASM_LINE.search(lines[number - 1]):
            continue
        out.append((number, _normal(lines[number - 1])))
    return out


_SIZE_ASSERT = re.compile(r"\btypedef\s+(?:char|int|u8|s8)\s+\w+\s*\[\s*\(?\s*[^;\]]*?\?\s*1\s*:\s*-\s*1\s*\)?\s*\]")


def _word(c: str) -> bool:
    return c.isalnum() or c == "_"


_SELF_ASSIGNED = re.compile(r"=\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*|\[\s*\w+\s*\])*)\s*;")
_CONSTANT_TEST = re.compile(r"if\s*\(\s*(?:0|1|true|false|TRUE|FALSE)\s*\)|while\s*\(\s*(?:0|false|FALSE)\s*\)")


def no_ops(source: _Source) -> list[tuple[int, str]]:
    """(line, statement) of each no-op: `x = x;`, `if (1)`, `while (0)` (a decompiler's or permuter's shape)."""
    code = source.code
    out = []
    for m in _SELF_ASSIGNED.finditer(code):
        end = m.start()
        while end and code[end - 1].isspace():
            end -= 1
        start = end - len(m[1])
        if start >= 0 and code[start:end] == m[1] and \
                not (start and (_word(code[start - 1]) or code[start - 1] in ".>*")):
            out.append((start, _normal(code[start:m.end()])))
    for m in _CONSTANT_TEST.finditer(code):
        if not (m.start() and _word(code[m.start() - 1])):
            out.append((m.start(), _normal(m[0])))
    return [(source.line(at), found) for at, found in sorted(out)]


_BLOCK_EXTERN = re.compile(r"(?m)^[ \t]+extern[ \t]+[^;{}]*;")
_BLOCK_PROTOTYPE = re.compile(
    r"(?m)^[ \t]+(?:static[ \t]+)?(?:const[ \t]+)?(?:" + _SCALAR +
    r"|[A-Z]\w*)(?:[ \t]*\*+[ \t]*|[ \t]+)[A-Za-z_]\w*[ \t]*\([ \t]*(?:void|(?:const[ \t]+)?"
    r"(?:struct[ \t]+)?(?:" + _SCALAR + r"|[A-Z]\w*)[ \t]*[\*&]*(?:[ \t]*\w+)?(?:[ \t]*,[ \t]*(?:const[ \t]+)?"
    r"(?:struct[ \t]+)?(?:" + _SCALAR + r"|[A-Z]\w*)[ \t]*[\*&]*(?:[ \t]*\w+)?)*)?[ \t]*\)[ \t]*;")
_MACRO_CALL = re.compile(r"\(\s*[A-Z_][A-Z0-9_]*\s*\)\s*;")   # f(MACRO); is a call, not a prototype


def block_decls(text: str, source: _Source, defined: Container[str]) -> list[tuple[int, str]]:
    """(line, declaration) of each prototype or `extern` declared inside a function body, of a name the file does
    not define (`defined`): it belongs in the header of the file that defines it."""
    code = source.code
    found = list(_BLOCK_EXTERN.finditer(code)) if "extern" in text else []
    for open_, end in _outermost(d.span for d in source.defs):
        found += [m for m in _BLOCK_PROTOTYPE.finditer(code, open_, end) if not _MACRO_CALL.search(m[0])]
    if not found:
        return []
    inside = _in_bodies(source)
    out = []
    for m in found:
        lead = m.start() + len(m[0]) - len(m[0].lstrip())
        if not inside(lead) or _EXTERN_C.match(text, lead):
            continue
        names = [_declared(piece[:equals[0]] if equals else piece)
                 for piece in _declarators(m[0].strip().rstrip(";")) for equals in [_top_level(piece, "=")]]
        if not all(name and name[0] in defined for name in names):
            out.append((source.line(lead), _normal(m[0])))
    return sorted(out)


def local_decls(text: str, source: _Source) -> list[tuple[int, str]]:
    """local_decl: prototypes and externs at file scope and in function bodies of names the file does not define."""
    found, defined = local_decl_debt(text, source)
    return sorted(found + block_decls(text, source, defined))


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


_CAST_TYPE = r"\(\s*(?:const\s+)?([A-Za-z_]\w*)\s*\*\s*\)\s*"
_THIS_CAST = re.compile(_CAST_TYPE + r"(?:\(\s*this\s*\)|this\b(?!\s*(?:->|\.|\[)))"
                        r"|\b(?:static|reinterpret)_cast\s*<\s*(?:const\s+)?([A-Za-z_]\w*)\s*\*\s*>\s*\(\s*this\s*\)")
_BYTE_THIS = (r"\(\s*\(?\s*(?:const\s+)?(?:u8|s8|char|unsigned\s+char|signed\s+char)\s*\*\s*\)\s*\(?\s*this\s*\)?"
              r"\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?")
_SUB_CALLS = (   # a member of the class called on `(u8 *)this + offset`: flat C name, hand-mangled, or through a cast
    ("flat", re.compile(r"\b([A-Z][A-Za-z0-9]*[a-z0-9])__[a-z_]\w*\s*\(\s*" + _BYTE_THIS)),
    ("mangled", re.compile(r"\b[A-Za-z_~]\w*?__(\d+)([A-Za-z_]\w*?)F\w*\s*\(\s*" + _BYTE_THIS)),
    ("cast", re.compile(r"\(\s*\(\s*([A-Za-z_]\w*)\s*\*\s*\)\s*" + _BYTE_THIS + r"\s*\)\s*->\s*~?\w+\s*\(")),
)
_CLASS_DECL = re.compile(r"\b(?:class|struct|union)\s+([A-Za-z_]\w*)\s*(?:final\s*)?(?::(?!:)\s*([^{;]*))?\{")
_TYPEDEF = re.compile(r"\btypedef\s+(?:(?:struct|class|union)\s+)?([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;")
_TYPEDEF_BODY = re.compile(r"\btypedef\s+(?:struct|class|union)\s*\w*\s*\{")
_USING = re.compile(r"\busing\s+([A-Za-z_]\w*)\s*=\s*(?:(?:struct|class|union)\s+)?([A-Za-z_]\w*)\s*;")


@dataclass
class ClassFacts:
    """What one file says about classes: those it declares with their direct bases, its typedef and using names,
    and its members' casts of `this` and calls on a sub-object of their own class."""
    bases: dict[str, set[str]]
    aliases: dict[str, str]
    this_casts: list[tuple[str, str, int]]     # (owner class, cast type, line)
    subobject_calls: list[tuple[str, int]]     # (call text, line)


def class_facts(rel: str, source: _Source) -> ClassFacts:
    from .cxx import _matching
    text = source.text
    bases: dict[str, set[str]] = collections.defaultdict(set)
    aliases: dict[str, str] = {}
    this_casts, calls = [], []
    if any(word in text for word in ("class", "struct", "union", "typedef", "using")):
        code = source.code
        for match in _CLASS_DECL.finditer(code):
            found = bases[match[1]]
            for base in (match[2] or "").split(","):
                base = re.sub(r"<.*", "", re.sub(r"\b(?:public|private|protected|virtual)\b", "", base))
                base = base.split("::")[-1].strip()
                if base:
                    found.add(base)
        for match in _TYPEDEF.finditer(code):
            aliases[match[2]] = match[1]
        for match in _USING.finditer(code):
            aliases[match[1]] = match[2]
        for match in _TYPEDEF_BODY.finditer(code):
            close = _matching(code, match.end() - 1)
            name = re.match(r"\s*([A-Za-z_]\w*)\s*;", code[close + 1:close + 200])
            if name:
                bases.setdefault(name[1], set())
    if "this" in text and (Path(rel).suffix.lower() not in HEADER_SUFFIXES or "{" in text):
        code = source.code
        if _THIS_CAST.search(code) or re.search(_BYTE_THIS, code):
            for definition in source.defs:
                owner, (start, end) = definition.owner, definition.span
                if owner is None:
                    continue
                body = code[start:end]
                for match in _THIS_CAST.finditer(body):
                    this_casts.append((owner, match[1] or match[2], source.line(start + match.start())))
                for kind, regex in _SUB_CALLS:
                    for match in regex.finditer(body):
                        target = match[2][:int(match[1])] if kind == "mangled" else match[1]
                        offset = int(match[3] if kind == "mangled" else match[2], 0)
                        if target == owner and offset:
                            calls.append((f"{owner}: {' '.join(match[0].split())}", source.line(start + match.start())))
    return ClassFacts(dict(bases), aliases, this_casts, calls)


class ClassMap:
    """Declared classes and their bases, merged over every file (a class declared twice keeps every base)."""

    def __init__(self, facts: Iterable[ClassFacts]):
        self.bases: dict[str, set[str]] = collections.defaultdict(set)
        self.aliases: dict[str, str] = {}
        for one in facts:
            for name, bases in one.bases.items():
                self.bases[name].update(bases)
            self.aliases.update(one.aliases)
        self._ancestors: dict[str, set[str]] = {}

    def resolve(self, name: str) -> str:
        seen = set()
        while name in self.aliases and name not in seen:
            seen.add(name)
            name = self.aliases[name]
        return name

    def ancestors(self, name: str) -> set[str]:
        if name not in self._ancestors:
            out, todo = set(), [name]
            while todo:
                for base in self.bases.get(todo.pop(), ()):
                    base = self.resolve(base)
                    if base not in out:
                        out.add(base)
                        todo.append(base)
            self._ancestors[name] = out
        return self._ancestors[name]

    def unrelated(self, owner: str, target: str) -> bool:
        """True only when both are declared classes and neither derives from the other."""
        owner, target = self.resolve(owner), self.resolve(target)
        if owner not in self.bases or target not in self.bases or owner == target:
            return False
        return target not in self.ancestors(owner) and owner not in self.ancestors(target)


def ownership(facts: ClassFacts, classes: ClassMap) -> list[tuple[int, str, str]]:
    """(line, key, text) of a file's members written in the wrong class: a cast of `this` to a class neither derived
    from nor a base of the member's own, and a member of its own class called on a sub-object of `this`."""
    out = [(line, "this_cast", f"{owner}: ({target} *)this")
           for owner, target, line in facts.this_casts if classes.unrelated(owner, target)]
    return out + [(line, "subobject_call", call[:120]) for call, line in facts.subobject_calls]


# --- parameter names, compared across files ----------------------------------------------------------------------
# A prototype pairs with the one definition of the same qualified name and parameter count. A parameter named by a
# placeholder on one side and a real name on the other is debt (param_name_split).

_PARAM_PLACEHOLDER = re.compile(
    r"^_*(?:[a-z]?arg_?\d+|a\d+|param_?\d+|p\d+|var_?[rf]?\d+\w*|temp_\w+|tmp_?\d*|sp[0-9A-Fa-f]+"
    r"|pad_?\w*|unk\w*|lbl_\w*|field_?[0-9A-Fa-f]+\w*|m_[0-9A-Fa-f]+|local_(?:res)?[0-9A-Fa-f]+|r\d+|f\d+|v\d+"
    r"|ptr_?\d*|unused\w*|\w*_[0-9A-Fa-f]{6,8}|[A-Za-z]|saved_r\d+|in_r\d+|in_f\d+)$")
_PARTNER_LINE = re.compile(r":\d+\)$")


def _placeholder(name: str, other: str) -> bool:
    """A decompiler-style parameter name (arg0, param_1, unk_4, a lone letter). A letter that starts the other
    side's real name abbreviates it (x / xPos) and is a name."""
    name, other = name.rstrip("_"), other.rstrip("_")
    return bool(_PARAM_PLACEHOLDER.match(name)) and (len(name) > 1 or not other.lower().startswith(name.lower())
                                                     or bool(_PARAM_PLACEHOLDER.match(other)))


def _param_names(code: str, span: tuple[int, int], line) -> tuple[tuple[str, int], ...]:
    """(name or "", line) of each parameter in the list whose parentheses are at span."""
    from .cxx import _NOT_A_NAME
    inner = code[span[0] + 1:span[1]]
    if inner.strip() in ("", "void"):
        return ()
    out, commas = [], _top_level(inner, ",")
    for a, b in zip([0, *(i + 1 for i in commas)], [*commas, len(inner)]):
        piece = inner[a:b]
        equals = _top_level(piece, "=")
        found = _declared(piece[:equals[0]] if equals else piece)
        name = found[0] if found and not found[1] and found[0] not in _NOT_A_NAME else ""
        out.append((name, line(span[0] + 1 + a + len(piece) - len(piece.lstrip()))))
    return tuple(out)


def signatures(source: _Source) -> list[tuple[bool, str, tuple[tuple[str, int], ...]]]:
    """(is a definition, qualified name, parameters) of each function prototype and definition in a file."""
    return [(definition, d.qualified, _param_names(source.code, d.parens, source.line))
            for definition, found in ((True, source.defs), (False, source.prototypes)) for d in found]


def param_names(files: Iterable[tuple[str, list]], counted: Container[str]) -> dict[str, list[tuple[int, str, str]]]:
    """param_name_split by the file holding the line to fix (the placeholder's), for files in `counted`."""
    defined, declared = collections.defaultdict(list), collections.defaultdict(list)
    for rel, sigs in files:
        for definition, name, params in sigs:
            (defined if definition else declared)[(name, len(params))].append((rel, params))
    out: dict[str, list[tuple[int, str, str]]] = collections.defaultdict(list)
    seen = set()
    for key, prototypes in declared.items():
        if len(defined.get(key, ())) != 1:
            continue
        def_rel, def_params = defined[key][0]
        for rel, params in prototypes:
            for (dn, dl), (fn, fl) in zip(params, def_params):
                if not dn or not fn or dn == fn:
                    continue
                weak = [n for n, o in ((dn, fn), (fn, dn)) if _placeholder(n, o)]
                if len(weak) != 1:
                    continue
                site, line, good, other, other_line = (rel, dl, fn, def_rel, fl) if weak[0] == dn else \
                    (def_rel, fl, dn, rel, dl)
                if site not in counted or (site, line, weak[0], good) in seen:
                    continue
                seen.add((site, line, weak[0], good))
                out[site].append((line, "param_name_split",
                                  f"{weak[0]} ({good} at {other.rsplit('/', 1)[-1]}:{other_line})"))
    return dict(out)


def identity(key: str, text: str) -> tuple[str, str]:
    """What a finding is matched by between revisions: (key, text), less a partner's line (other edits move it)."""
    return (key, _PARTNER_LINE.sub(")", text)) if key == "param_name_split" else (key, text)


# Checks a parser judges, with what it needs: "file" a whole file and its path, "image" the image's address range.
# Each takes (path or None, text, source, image) and gives [(1-based line, text of the finding)].
PARSED = {
    "extern_c": ((), lambda rel, text, source, image: [(n, f'extern "C" {name}')
                                                         for n, name in extern_c_debt(text, source)]),
    "local_decl": ((), lambda rel, text, source, image: local_decls(text, source)),
    "self_param": (("file",), lambda rel, text, source, image: self_params(rel, source)),
    "pad_access": ((), lambda rel, text, source, image: pad_accesses(source)),
    "size_assert": ((), lambda rel, text, source, image: [] if "typedef" not in text else
                    [(source.line(m.start()), _normal(m[0])) for m in _SIZE_ASSERT.finditer(source.code)]),
    "string_cast": ((), lambda rel, text, source, image: string_casts(text)),
    "address_comment": ((), lambda rel, text, source, image: address_comments(text, image)),
    "register_name": ((), lambda rel, text, source, image: register_names(text, source)),
    "no_op": ((), lambda rel, text, source, image: no_ops(source)),
    "address_ident": (("image",), lambda rel, text, source, image: address_idents(source, image)),
    "address_unit": (("file", "image"), lambda rel, text, source, image:
                     [] if Path(rel).suffix.lower() in HEADER_SUFFIXES else address_unit(rel, image)),
    "local_class": (("file",), lambda rel, text, source, image: local_classes(rel, source)),
    "repeat_cast": ((), lambda rel, text, source, image: repeat_casts(source) if "*)" in text else []),
}
# judged over every file at once: copies of a class (`duplicates`), a header's extern "C" on a function a C++ unit
# defines (`extern_c_functions` against the config), parameter names (`param_names`) and members that belong to
# another class (`misowned.misowned_members`, against the config) and structs only reached by casts
# (`overlay_types`). A header named after an address (address_unit) counts only when no unit has its name, since one
# rename fixes both.
TREE_CHECKS = {"duplicate_class", "header_extern_c", "param_name_split", "address_unit", "misowned_member",
               "overlay_type"}


def _parsed(pattern: Pattern) -> bool:
    """The pattern is judged by its parser (a manifest that replaces its regex judges it by the regex)."""
    return pattern.key in PARSED and pattern.regex.pattern == _DEFAULTS[pattern.key].regex.pattern


def _elsewhere(pattern: Pattern) -> bool:
    """The pattern is judged over the whole tree, not in one file."""
    return pattern.key in TREE_CHECKS and pattern.regex.pattern == _NEVER


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


def located(text: str, catalog: Iterable[Pattern], header: bool = False, rel: str | None = None,
            image: tuple[int, int] | None = None, source: _Source | None = None) -> list[tuple[int, str, str]]:
    """(1-based line, key, text) of every finding in a file (`rel` its path, which also says whether it is a header)
    or a piece of one. Comments and string literals are blanked with every line kept in place."""
    catalog = list(catalog)
    if rel is not None:
        header = Path(rel).suffix.lower() in HEADER_SUFFIXES
    source = source or _Source(text)
    line = None
    out = []
    for pattern in catalog:
        if (header and pattern.sources_only) or _parsed(pattern) or _elsewhere(pattern):
            continue
        for match in source.matches(pattern):
            line = line or _line_index(source.kept)
            out.append((line(match.start()), pattern.key, match[0][:80]))
    return out + parsed_findings(text, catalog, rel, header, image, source)


def count(text: str, catalog: Iterable[Pattern], header: bool = False, rel: str | None = None,
          image: tuple[int, int] | None = None, source: _Source | None = None) -> collections.Counter:
    """Debt per pattern in a file (`rel` its path, which also says whether it is a header) or a piece of one."""
    return collections.Counter(key for _, key, _ in located(text, catalog, header, rel, image, source))


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


@dataclass
class _Scan:
    counts: collections.Counter                   # finding counts by key
    bodies: dict[str, int]                        # class with a body here, not nested in another -> its line
    classes: ClassFacts
    found: list[tuple[int, str, str]] | None      # every finding (line, key, text), kept for changed files only
    c_functions: list[tuple[int, str]]            # a header's functions under extern "C": (line, name)
    signatures: list = field(default_factory=list)    # see signatures()
    overlays: list = field(default_factory=list)      # see plain_structs()
    blobs: dict = field(default_factory=dict)         # struct of byte arrays declared here -> its size


def _scan(rel: str, text: str, catalog: list[Pattern], image: tuple[int, int] | None, keep: bool = False) -> _Scan:
    source = _Source(text)
    found = located(text, catalog, rel=rel, image=image, source=source)
    bodies: dict[str, int] = {}
    for offset, _, name in source.bodies:
        bodies.setdefault(name, source.line(offset))
    header = Path(rel).suffix.lower() in HEADER_SUFFIXES
    c_functions = extern_c_functions(text, source) if header and "extern" in text else []
    tree = {p.key for p in catalog if _elsewhere(p)}
    return _Scan(collections.Counter(key for _, key, _ in found), bodies, class_facts(rel, source),
                 found if keep else None, c_functions, signatures(source) if "param_name_split" in tree else [],
                 *plain_structs(source))


def _checks(project: Project | None, repo: str | None) -> tuple[list[Pattern], set[str], list[str]]:
    """The catalog, its checks judged over the whole tree or from the config, and the ownership checks the manifest
    keeps."""
    catalog = patterns(project, repo)
    config = (project.config["repositories"][repo].get("quality", {}) if project and repo else {})
    tree = {p.key for p in catalog if _elsewhere(p)}
    return catalog, tree, [k for k in OWNERSHIP if k not in set(config.get("disable", []))]


_PAD_FIRST = re.compile(r"\s*(?:(?:unsigned|signed|const|volatile)\s+)*[A-Za-z_]\w*\s+"
                        r"(?:pad|unk|padding|gap|reserved|_)\w*\s*\[")
_BYTE_ARRAY = re.compile(r"\s*(?:const\s+)?(?:u8|s8|char|(?:un)?signed\s+char|u?int8_t)\s+\w+\s*((?:\[[^\]]+\]\s*)+)$")


def plain_structs(source: _Source) -> tuple[list[tuple[str, int, str]], dict[str, int]]:
    """Class bodies of plain fields (no member functions or nested bodies). Overlays: (name, line, `struct Name`) of
    those that start with padding or are a single array, the shapes of a view over part of something else and of a
    blob for copying bytes. Blobs: name -> size of those made only of byte arrays with literal sizes."""
    from .cxx import _matching
    out, blobs = [], {}
    code = source.code
    for offset, keyword, name in source.bodies:
        brace = code.index("{", offset)
        inner = re.sub(r"\b(?:public|private|protected)\s*:(?!:)", "", code[brace + 1:_matching(code, brace)])
        if re.search(r"[(){]", inner):
            continue
        fields = [part for part in inner.split(";") if part.strip()]
        if len(fields) == 1 and fields[0].rstrip().endswith("]") or len(fields) > 1 and _PAD_FIRST.match(fields[0]):
            out.append((name, source.line(offset), f"{keyword} {name}"))
        arrays = [_BYTE_ARRAY.match(part) for part in fields]
        if fields and all(arrays):
            try:
                blobs[name] = sum(math.prod(int(n, 0) for n in re.findall(r"\[\s*(\w+)\s*\]", a[1])) for a in arrays)
            except ValueError:
                pass
    return out, blobs


_BLOB_SIZE = re.compile(r"ByteBlock_?(?:0x)?([0-9A-Fa-f]{1,4})")


def renamed_blobs(before: Iterable[_Scan], after: dict[str, _Scan],
                  texts: dict[str, str]) -> dict[str, list[tuple[int, str, str]]]:
    """blob_type findings at each mention of a struct of byte arrays a change added in place of a size-named blob it
    removed: `struct ByteBlock_78 { u8 bytes[0x78]; };` renamed `struct BodyCopy { u8 data[0x78]; };` is still a
    blob. Only a change shows the rename, so these count in comparisons only."""
    from .cxx import blank
    before = list(before)
    sizes = lambda scans: {int(size[1], 16) for scan in scans for _, key, text in scan.found
                           if key == "blob_type" and (size := _BLOB_SIZE.search(text))}
    gone = sizes(before) - sizes(after[rel] for rel in texts)
    old = {name for scan in before for name in scan.bodies}
    names = {name for rel in texts for name, size in after[rel].blobs.items() if size in gone and name not in old}
    if not names:
        return {}
    mention = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(names))) + r")\b")
    out = {}
    for rel, text in texts.items():
        if mention.search(text):
            code = blank(text)
            line = _line_index(code)
            out[rel] = [(line(m.start()), "blob_type", m[0]) for m in mention.finditer(code)]
    return out


_TAG = r"(?:(?:const|volatile|struct|class|union)\s+)*"


def _type_use(code: str, start: int, end: int, name: str) -> str:
    """How one mention of a class name uses it: "declaration" (its body, a forward declaration, a typedef), "size",
    "cast" (a pointer cast to it, or a local holding one), or "typed" (anything else: a variable, member, parameter
    or return type, a base, a scope)."""
    before, after = code[max(0, start - 80):start], code[end:end + 160]
    if (re.search(r"\b(?:class|struct|union)\s*$", before) and re.match(r"\s*(?:final\s*)?[:{;]", after)
            or re.search(r"}\s*$", before) and re.match(r"\s*[;,]", after)
            or re.search(r"\btypedef\s+(?:struct|class|union)\s+(?:\w+\s*)?$", before) and re.match(r"\s*\w*\s*;", after)):
        return "declaration"
    if re.search(r"\b(?:sizeof|alignof)\s*\(\s*" + _TAG + "$", before):
        return "size"
    if (re.search(r"\(\s*" + _TAG + "$", before) and re.match(r"\s*\*+\s*(?:const\s*)?\)", after)
            or re.search(r"\b(?:static|reinterpret|const)_cast\s*<\s*" + _TAG + "$", before)):
        return "cast"
    if re.match(r"\s*\*\s*(?:const\s+)?\w+\s*=\s*(?:\(\s*" + _TAG + re.escape(name) + r"\s*\*|"
                r"(?:static|reinterpret)_cast\s*<\s*" + _TAG + re.escape(name) + r"\b)", after):
        return "cast"
    return "typed"


_CAST_TO = re.compile(r"(?:\(|_cast\s*<)\s*" + _TAG + r"([A-Za-z_]\w*)\s*\*")
_IDENT = re.compile(r"[A-Za-z_]\w*")


def overlay_types(texts: dict[str, str], scans: dict[str, _Scan]) -> dict[str, list[tuple[int, str, str]]]:
    """overlay_type findings by file: the overlays (plain_structs()) of the files in scans that no file of the
    revision (texts) uses as a type, only casts other pointers to."""
    from .cxx import blank
    names = {name for scan in scans.values() for name, _, _ in scan.overlays}
    if names:   # only a name some text casts to can be an overlay
        names &= {match[1] for text in texts.values() if "*" in text for match in _CAST_TO.finditer(text)}
    cast, typed = set(), set()
    for text in texts.values():
        found = set(_IDENT.findall(text)) & names if names else None
        if not found:
            continue
        code = blank(text)
        for match in re.finditer(r"\b(?:" + "|".join(map(re.escape, sorted(found))) + r")\b", code):
            if match[0] not in typed:
                use = _type_use(code, match.start(), match.end(), match[0])
                (cast if use == "cast" else typed if use == "typed" else set()).add(match[0])
    out = collections.defaultdict(list)
    for rel, scan in scans.items():
        out[rel] += [(line, "overlay_type", text) for name, line, text in scan.overlays
                     if name in cast and name not in typed]
    return {rel: found for rel, found in out.items() if found}


def text_relations(texts: dict[str, str], config: "Config | None", scans: dict[str, _Scan],
                   tree: set[str]) -> dict[str, list[tuple[int, str, str]]]:
    """Cross-file findings read again from the revision's texts, for the files in scans: members that belong to
    another class (`misowned_members()`, against the config) and structs only reached by casts (`overlay_types()`)."""
    out = collections.defaultdict(list)
    parts = [misowned_members(texts, config.pairs, scans) if "misowned_member" in tree and config else {},
             overlay_types(texts, scans) if "overlay_type" in tree else {}]
    for found in parts:
        for rel, items in found.items():
            out[rel] += items
    return dict(out)


def _relations(scans: dict[str, _Scan], tree: set[str], owned: list[str], config: "Config | None" = None,
               library: dict[str, list] | None = None, image: tuple[int, int] | None = None,
               members: dict[str, list[tuple[int, str, str]]] | None = None) -> dict[str, list[tuple[int, str, str]]]:
    """Findings that depend on more than one file, by the file holding them: copies of a class declared in more than
    one file, a header's extern "C" on functions a C++ unit defines, placeholder parameters named on the other side
    (library: signatures() of files read only to pair them), headers named after an address of the image that no
    unit shares a name with, the findings read again from the texts (members: `text_relations()`) and members in
    the wrong class (ownership)."""
    out: dict[str, list[tuple[int, str, str]]] = collections.defaultdict(list)
    if "duplicate_class" in tree:
        for rel, copies in duplicates({rel: scan.bodies for rel, scan in scans.items() if scan.bodies}).items():
            out[rel] += [(line, "duplicate_class", name) for line, name in copies]
    for rel, found in (members or {}).items():
        out[rel] += found
    if "param_name_split" in tree:
        files = [*sorted((rel, scan.signatures) for rel, scan in scans.items()),
                 *sorted((rel, sigs) for rel, sigs in (library or {}).items() if rel not in scans)]
        for rel, found in param_names(files, scans).items():
            out[rel] += found
    if "address_unit" in tree and image:
        units = {Path(rel).stem for rel in scans if Path(rel).suffix.lower() not in HEADER_SUFFIXES}
        for rel in scans:
            if Path(rel).suffix.lower() in HEADER_SUFFIXES and Path(rel).stem not in units:
                found = [(line, "address_unit", name) for line, name in address_unit(rel, image)]
                if found:
                    out[rel] += found
    if owned:
        classes = ClassMap(scan.classes for scan in scans.values())
        for rel, scan in scans.items():
            found = [f for f in ownership(scan.classes, classes) if f[1] in owned]
            if found:
                out[rel] += found
    if config is not None and "header_extern_c" in tree:
        for rel, scan in scans.items():
            found = [(line, "header_extern_c", f'extern "C" {name}') for line, name in scan.c_functions
                     if config.cxx_linkage(name)]
            if found:
                out[rel] += found
    return dict(out)


# The config (a dtk project's config.yml, with its symbols.txt and splits.txt): which unit defines each function.

_CONFIG_PATHS = re.compile(r"^(symbols|splits):\s*(\S+)", re.M)
_SPLIT_TEXT = re.compile(r"^\s+\.text\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)")
_SYMBOL = re.compile(r"^(\S+)\s*=\s*([.\w]+):(0x[0-9A-Fa-f]+);\s*//(.*)$")


def split_units(text: str) -> list[tuple[int, int, str]]:
    """(start, end, unit) of every unit's .text in a splits.txt, sorted."""
    out, unit = [], None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.endswith(":"):
            unit = line[:-1]
        elif unit:
            found = _SPLIT_TEXT.match(line)
            if found:
                out.append((int(found[1], 16), int(found[2], 16), unit))
    return sorted(out)


_MIDDLEWARE = re.compile(r"^MIDDLEWARE\b[^=\n]*=\s*\[.*?(0x[0-9A-Fa-f]+)", re.M | re.S)
_MIDDLEWARE_END = re.compile(r"^MIDDLEWARE_END\s*=\s*(0x[0-9A-Fa-f]+)", re.M)


def middleware(configure: str) -> tuple[int, int] | None:
    """Where configure.py links its prebuilt C libraries: from the first start in its MIDDLEWARE list to
    MIDDLEWARE_END (None when it does not say)."""
    start, end = _MIDDLEWARE.search(configure), _MIDDLEWARE_END.search(configure)
    return (int(start[1], 16), int(end[1], 16)) if start and end else None


@dataclass
class Config:
    linkage: dict[str, set[str]]                                   # function name -> the units defining it
    middleware: set[str] = field(default_factory=set)              # units of the prebuilt C libraries
    pairs: list[tuple[str, str]] = field(default_factory=list)     # (symbols.txt, splits.txt) texts

    def cxx_linkage(self, name: str) -> bool:
        """True when a C++ unit, and no C unit, defines the function. A middleware unit is never C++: the
        libraries are C, whatever the unit's file is called."""
        units = self.linkage.get(name, ())
        return any(Path(u).suffix.lower() in CPP_SUFFIXES and u not in self.middleware for u in units) and \
            not any(Path(u).suffix.lower() == ".c" for u in units)


def _config_dirs(project: Project, repo: str) -> list[str]:
    """Where the config.yml files are (the manifest's `quality.config`, else `config`)."""
    return list(project.config["repositories"][repo].get("quality", {}).get("config") or ["config"])


def _read(root: Path, revision: str | None, rels: list[str]) -> dict[str, str]:
    """The text of each file that exists at a revision (None: the working tree), by path."""
    if revision is None:
        return {rel: (root / rel).read_text(encoding="utf-8", errors="replace") for rel in rels
                if (root / rel).is_file()}
    if not rels:
        return {}
    result = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], capture_output=True, check=False,
                            input=b"".join(f"{revision}:{rel}\n".encode() for rel in rels))
    out, data, at = {}, result.stdout, 0
    for rel in rels:
        end = data.find(b"\n", at)
        header = data[at:end].split()
        at = end + 1
        if len(header) < 3 or header[-1] == b"missing":
            continue
        size = int(header[2])
        out[rel] = data[at:at + size].decode("utf-8", errors="replace")
        at += size + 1
    return out


def read_config(root: Path, revision: str | None, dirs: list[str]) -> Config:
    """Every config.yml's symbols.txt and splits.txt under `dirs` at a revision (None: the working tree): which unit
    defines each function, which units start in configure.py's middleware range, and the two files' texts."""
    if revision is None:
        configs = sorted(p.relative_to(root).as_posix() for d in dirs if (root / d).is_dir()
                         for p in (root / d).rglob("config.yml"))
    else:
        listing = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "-z", "--name-only", revision, "--",
                                  *dirs], capture_output=True, check=False)
        configs = sorted(rel for rel in listing.stdout.decode("utf-8", "surrogateescape").split("\0")
                         if rel.endswith("config.yml"))
    pairs = []
    for text in _read(root, revision, configs).values():
        paths = dict(_CONFIG_PATHS.findall(text))
        if "symbols" in paths:
            pairs.append((paths["symbols"], paths.get("splits")))
    texts = _read(root, revision, sorted({p for pair in pairs for p in pair if p}))
    config = Config(collections.defaultdict(set))
    libraries = middleware(_read(root, revision, ["configure.py"]).get("configure.py", ""))
    for symbols_path, splits_path in sorted(set(pairs)):
        config.pairs.append((texts.get(symbols_path, ""), texts.get(splits_path, "") if splits_path else ""))
        units = split_units(texts.get(splits_path, "")) if splits_path else []
        starts = [u[0] for u in units]
        if libraries:
            config.middleware.update(unit for start, _, unit in units if libraries[0] <= start < libraries[1])
        for line in texts.get(symbols_path, "").splitlines():
            match = _SYMBOL.match(line.strip())
            if not match or match[2] != ".text" or not re.search(r"\btype:function\b", match[4]):
                continue
            index = bisect.bisect_right(starts, int(match[3], 16)) - 1
            if index >= 0 and units[index][0] <= int(match[3], 16) < units[index][1]:
                config.linkage[match[1]].add(units[index][2])
    return config


def _config(project: Project, repo: str, revision: str | None, tree: set[str]) -> Config | None:
    """The config at a revision, when a check reads it."""
    if not tree & {"header_extern_c", "misowned_member"}:
        return None
    return read_config(project.root(repo), revision, _config_dirs(project, repo))


def _totals(scans: dict[str, _Scan], related: dict[str, list[tuple[int, str, str]]]) -> collections.Counter:
    totals: collections.Counter = collections.Counter()
    for scan in scans.values():
        totals.update(scan.counts)
    for found in related.values():
        totals.update(key for _, key, _ in found)
    return totals


def _library_roots(project: Project, repo: str) -> list[str]:
    """Where the files read only to pair a prototype with its definition and to type the members misowned_member
    judges are (the manifest's `quality.library`, else libs)."""
    return list(project.config["repositories"][repo].get("quality", {}).get("library", ["libs"]))


def _library(root: Path, revision: str | None, roots: list[str]) -> dict[str, str]:
    """The source files under `roots` at a revision (None: the working tree), by path."""
    if not roots:
        return {}
    return dict(_revision_files(root, revision, roots, []) if revision else _tree_files(root, roots, []))


def _signatures(texts: dict[str, str]) -> dict[str, list]:
    return {rel: signatures(_Source(text)) for rel, text in texts.items()}


def describe(key: str, catalog: Iterable[Pattern] = ()) -> dict[str, str]:
    """A check's key, name, example, group and category (its group's title), for a report."""
    if key in OWNERSHIP:
        name, example, group = *OWNERSHIP[key], "ownership"
    else:
        pattern = next((p for p in catalog if p.key == key), None) or _DEFAULTS.get(key)
        group = pattern.group if pattern else "custom"
        name, example = DISPLAY.get(key) or ((pattern.label if pattern else key), "")
    return {"key": key, "name": name, "example": example, "group": group,
            "category": GROUP_TITLES.get(group, group.capitalize())}


def audit(project: Project, repo: str, paths: list[str] | None = None, revision: str | None = None,
          top: int = 15) -> dict[str, Any]:
    """Counts per pattern for the working tree (or a revision), the files holding the most debt, and the members in
    the wrong class (beside the total, not in it)."""
    catalog, tree, owned = _checks(project, repo)
    roots, exclude = _paths(project, repo, paths)
    root = project.root(repo)
    texts = dict(_revision_files(root, revision, roots, exclude) if revision else _tree_files(root, roots, exclude))
    image = image_range(project, repo)
    scans = {rel: _scan(rel, text, catalog, image) for rel, text in texts.items()}
    config = _config(project, repo, revision, tree)
    other = _library(root, revision, _library_roots(project, repo)) \
        if tree & {"param_name_split", "misowned_member", "overlay_type"} else {}
    library = _signatures(other) if "param_name_split" in tree else None
    members = text_relations(texts | other, config, scans, tree)
    related = _relations(scans, tree, owned, config, library, image, members)
    totals = _totals(scans, related)
    keys = {p.key for p in catalog}
    per_file = {}
    for rel, scan in scans.items():
        found = scan.counts + collections.Counter(key for _, key, _ in related.get(rel, []) if key in keys)
        if found:
            per_file[rel] = found
    groups = collections.Counter()
    for pattern in catalog:
        groups[pattern.group] += totals[pattern.key]
    worst = sorted(per_file.items(), key=lambda item: -sum(item[1].values()))[:top]
    return {"repo": repo, "revision": revision or "working tree", "paths": roots, "files": len(scans),
            "files_with_debt": len(per_file),
            "counts": [{**describe(p.key, catalog), "label": p.label, "count": totals[p.key]} for p in catalog],
            "ownership": [{**describe(k), "label": OWNERSHIP[k][0], "count": totals[k]} for k in owned],
            "groups": dict(groups), "total": sum(totals[p.key] for p in catalog),
            "worst_files": [{"path": rel, "total": sum(c.values()), "top": c.most_common(3)} for rel, c in worst]}


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), "-c", "core.quotePath=false", *args], capture_output=True,
                            check=False)
    if result.returncode:
        raise ValueError(f"git {args[0]}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout.decode("utf-8", errors="surrogateescape")


Hunk = tuple[range, range]   # a diff hunk: the lines `before` removed, the lines `after` added


def _diff(root: Path, before: str, after: str | None, roots: list[str],
          exclude: list[re.Pattern]) -> dict[str, list[Hunk]]:
    """{source file that differs between `before` and `after` (None: the working tree, untracked files included):
    its hunks}; an untracked file is one hunk adding all of it."""
    out: dict[str, list[Hunk]] = {}
    current = old = None
    header = False
    for line in _git(root, "diff", "-U0", "--text", "--no-renames", "--no-color", "--no-ext-diff", before,
                     *([after] if after else []), "--", *roots).splitlines():
        if line.startswith("diff --git "):
            current, header, old = None, True, None
        elif header and line.startswith("--- "):   # ---/+++ are headers only before the first @@
            old = _diff_path(line[4:])
        elif header and line.startswith("+++ "):
            current = _diff_path(line[4:]) or old
            if current is not None and _keep(current, exclude):
                out.setdefault(current, [])
            else:
                current = None
        elif line.startswith("@@") and current is not None:
            header = False
            hunk = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if hunk:
                old_at, old_n, new_at, new_n = (int(n) if n is not None else 1 for n in hunk.groups())
                out[current].append((range(old_at, old_at + old_n), range(new_at, new_at + new_n)))
    if not after:
        for rel in _git(root, "ls-files", "-z", "-o", "--exclude-standard", "--", *roots).split("\0"):
            if rel and _keep(rel, exclude) and (root / rel).is_file():
                lines = len((root / rel).read_text(encoding="utf-8", errors="replace").splitlines())
                out[rel] = [(range(0), range(1, lines + 2))]
    return out


def _diff_path(field: str) -> str | None:
    """The path of a diff's ---/+++ line less its a/ or b/ (None for /dev/null). Git quotes a path holding special
    characters and ends one holding a space with a tab."""
    field = field.rstrip("\t")
    if field == "/dev/null":
        return None
    if len(field) > 1 and field[0] == field[-1] == '"':
        field = field[1:-1]
    return field[2:]


def _placed(counts: collections.Counter, found: list[tuple[str, tuple[int, str, str]]]) \
        -> list[tuple[str, tuple[int, str, str]]]:
    """The findings in `found` (taken in path and line order) that account for `counts`, a multiset of identities."""
    left, out = collections.Counter(counts), []
    for rel, f in sorted(found, key=lambda item: (item[0], item[1][0])):
        if left[identity(f[1], f[2])] > 0:
            left[identity(f[1], f[2])] -= 1
            out.append((rel, f))
    return out


def _hunk(hunks: dict[str, list[Hunk]], rel: str, line: int, side: int) -> int | None:
    """The hunk of rel holding line among the lines `before` removed (side 0) or `after` added (side 1)."""
    found = hunks.get(rel, ())
    index = bisect.bisect_right(found, line, key=lambda hunk: hunk[side].start) - 1   # sorted, disjoint per side
    return index if index >= 0 and line in found[index][side] else None


def compare(project: Project, repo: str, before: str, after: str | None = None,
            paths: list[str] | None = None) -> dict[str, Any]:
    """Debt at `before` (a revision) and `after` (a revision, or the working tree), check by check: the tree's count
    at each, and what the change between them removed and added. Findings are matched by their text, so code that
    only moves (between functions or files) counts as neither, and neither does a hunk that rewrites a debt line
    without adding a finding of its check (a rename on the line). Also the findings the change added on its own lines,
    and the members in the wrong class (beside the total, not in it). A header's extern "C" is judged against the
    config at `after` on both sides, so only header edits move it; a member that belongs to another class against
    each side's own."""
    catalog, tree, owned = _checks(project, repo)
    roots, exclude = _paths(project, repo, paths)
    root = project.root(repo)
    image = image_range(project, repo)
    hunks = _diff(root, before, after, roots, exclude)
    head_config = _config(project, repo, after, tree)
    changed = set(hunks)
    head_texts = dict(_revision_files(root, after, roots, exclude) if after else _tree_files(root, roots, exclude))
    head = {rel: _scan(rel, text, catalog, image, keep=rel in changed) for rel, text in head_texts.items()}
    wanted = sorted(changed) if len(changed) <= 500 else roots
    base_texts = {rel: text for rel, text in (_revision_files(root, before, wanted, exclude) if changed else ())
                  if rel in changed}
    base_changed = {rel: _scan(rel, text, catalog, image, keep=True) for rel, text in base_texts.items()}
    base = {rel: scan for rel, scan in head.items() if rel not in changed} | base_changed
    head_library = base_library = head_members = base_members = None
    head_other: dict[str, str] = {}
    base_other: dict[str, str] = {}
    if tree & {"param_name_split", "misowned_member", "overlay_type"}:
        library_roots = _library_roots(project, repo)
        head_other = _library(root, after, library_roots)
        moved = set(_diff(root, before, after, library_roots, [])) if library_roots else set()
        moved_texts = _library(root, before, sorted(moved))
        base_other = {rel: text for rel, text in head_other.items() if rel not in moved} | moved_texts
    if "param_name_split" in tree:
        head_library = _signatures(head_other)
        base_library = {rel: sigs for rel, sigs in head_library.items() if rel not in moved} | \
            _signatures(moved_texts)
    if tree & {"misowned_member", "overlay_type"}:
        # a member's class is judged against each side's own config, since a rename changes symbols.txt and the
        # source together
        base_config = _config(project, repo, before, tree) if head_config is not None else None
        head_members = text_relations(head_texts | head_other, head_config, head, tree)
        base_members = text_relations({rel: text for rel, text in head_texts.items() if rel not in changed} |
                                      base_texts | base_other, base_config, base, tree)
    head_related = _relations(head, tree, owned, head_config, head_library, image, head_members)
    if "blob_type" in {p.key for p in catalog}:
        for rel, found in renamed_blobs(base_changed.values(), head,
                                        {rel: head_texts[rel] for rel in changed if rel in head}).items():
            head_related[rel] = head_related.get(rel, []) + found
    base_related = _relations(base, tree, owned, head_config, base_library, image, base_members)
    head_totals, base_totals = _totals(head, head_related), _totals(base, base_related)

    # Findings across files can change in files the change did not touch (a class gained a base, a class's other
    # copy went away), so they are matched over the whole tree.
    rise: collections.Counter = collections.Counter(
        (key, text) for rel in changed if rel in head for _, key, text in head[rel].found)
    fall: collections.Counter = collections.Counter(
        (key, text) for scan in base_changed.values() for _, key, text in scan.found)
    rise.update(identity(key, text) for found in head_related.values() for _, key, text in found)
    fall.update(identity(key, text) for found in base_related.values() for _, key, text in found)
    rise, fall = rise - fall, fall - rise
    added, removed = collections.Counter(), collections.Counter()
    for (key, _), n in rise.items():
        added[key] += n
    for (key, _), n in fall.items():
        removed[key] += n

    # Where they are: the rise on lines the change added (and in files a cross-file finding moved in), the fall on
    # lines it removed. A hunk that replaces lines nets each check within it, so rewriting a debt line (renaming a
    # variable on it) is neither added nor removed debt.
    risen, fallen = [], []
    for rel in sorted(changed & head.keys()):
        lines = {n for _, add in hunks[rel] for n in add}
        risen += [(rel, f) for f in head[rel].found + head_related.get(rel, []) if f[0] in lines]
    risen += [(rel, f) for rel, found in head_related.items() if rel not in changed for f in found]
    for rel, scan in base_changed.items():
        lines = {n for gone, _ in hunks[rel] for n in gone}
        fallen += [(rel, f) for f in scan.found + base_related.get(rel, []) if f[0] in lines]
    replaced = collections.Counter((rel, _hunk(hunks, rel, f[0], 0), f[1]) for rel, f in _placed(fall, fallen))
    placed = _placed(rise, risen)
    # A cross-file finding can appear on a line the change kept (its partner changed): list it there.
    rest = rise - collections.Counter(identity(f[1], f[2]) for _, f in placed)
    listed = {id(f) for _, f in placed}
    kept = [(rel, f) for rel in sorted(changed & head.keys()) for f in head_related.get(rel, []) if id(f) not in listed]
    new = []
    for rel, (line, key, text) in placed + _placed(rest, kept):
        at = (rel, _hunk(hunks, rel, line, 1), key)
        if at[1] is not None and replaced[at] > 0:
            replaced[at] -= 1
            added[key] -= 1
            removed[key] -= 1
        else:
            new.append({"key": key, "path": rel, "line": line, "text": text})

    def row(key: str, label: str) -> dict[str, Any]:
        return {**describe(key, catalog), "label": label, "before": base_totals[key], "after": head_totals[key],
                "delta": head_totals[key] - base_totals[key], "removed": removed[key], "added": added[key]}

    def commit(revision: str | None) -> str | None:
        return _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").strip() if revision else None

    rows = [row(p.key, p.label) for p in catalog]
    return {"repo": repo, "before": before, "after": after or "working tree", "before_commit": commit(before),
            "after_commit": commit(after), "files_changed": len(changed), "rows": rows,
            "ownership": [row(k, OWNERSHIP[k][0]) for k in owned],
            "total": {k: sum(r[k] for r in rows) for k in ("before", "after", "delta", "removed", "added")},
            "worse": [r for r in rows if r["delta"] > 0], "new": new}


def findings(text: str, catalog: Iterable[Pattern], header: bool = False, skip: Iterable[str] = ()) -> list[dict]:
    """Every match in a piece of source (one line or a function body), for check and port readiness; `blocks`
    says whether it hides what the code does (spelling debt such as a hand-mangled call does not). In a header,
    what is debt only in a source file (a class declared with virtuals) is none. `skip` names patterns the caller
    judges itself (check reads the parser-judged checks against the whole file, `parsed_findings`). Of those,
    `extern "C"`, string casts, register names, no-ops and padding accesses are judged in a piece; the rest need the
    whole file, its path, the whole tree or the config."""
    code = _strip_comments(text)
    out = []
    for pattern in catalog:
        if (header and pattern.sources_only) or pattern.key in skip or _elsewhere(pattern):
            continue
        if _parsed(pattern):
            judge = {"extern_c": lambda: [f'extern "C" {name}' for _, name in extern_c_debt(text)],
                     "string_cast": lambda: [found for _, found in string_casts(text)],
                     "register_name": lambda: [found for _, found in register_names(text, _Source(text))],
                     "no_op": lambda: [found for _, found in no_ops(_Source(text))],
                     "pad_access": lambda: [found for _, found in pad_accesses(_Source(text))]}.get(pattern.key)
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
