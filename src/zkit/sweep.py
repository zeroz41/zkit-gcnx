"""Variant sweep for near-misses (Switch clang, GameCube CodeWarrior): single-site source rewrites.

A function whose candidate differs from the original only by register choice, instruction order or operand
order usually has a source spelling that clang compiles to the original's code: the other operand order of a
commutative operator, `a = a + b` for `a += b`, a loop counting up instead of down, an `if` with its branches
swapped, a counter of another integer type, two independent statements the other way round, and how a value is
held (an explicit copy, a named temporary, a re-read instead of a cached local, an out parameter updated in place,
a record's arithmetic member by member), which decides the order of float operands. The sweep parses the
function with a host clang's JSON AST (the project's compiler may be too old to write one), rewrites one site at
a time, compiles every rewrite with the unit's exact command, and climbs to the spelling with the fewest
differing words. A rewrite need not keep the meaning: a byte-identical result proves itself, and anything else
is only a step. Records no attempts; the result is a candidate for `zkit try`."""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

COMMUTATIVE = {"+", "*", "&", "|", "^", "==", "!="}
FLIPPED = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}
COMPOUND = {"+=": "+", "-=": "-", "*=": "*", "|=": "|", "&=": "&", "^=": "^", "<<=": "<<", ">>=": ">>"}
INTEGERS = ("int", "unsigned int", "long", "unsigned long", "short", "unsigned short", "char", "unsigned char")
FLAGS = ("bool", "unsigned char", "int")        # a flag local: the type decides how it is kept and tested
SIMPLE = re.compile(r"^[\w.\->\[\]]+$")       # an operand that needs no parentheses


@dataclass(frozen=True)
class Rewrite:
    """One rewrite: what it does, and the text edits (start, end, replacement) that do it."""
    what: str
    edits: tuple[tuple[int, int, str], ...]

    def apply(self, text: str) -> str:
        for start, end, replacement in sorted(self.edits, reverse=True):
            text = text[:start] + replacement + text[end:]
        return text


def _span(node: dict) -> tuple[int, int] | None:
    """A node's [start, end) in the parsed file, or None for one a macro wrote (its spelling is elsewhere)."""
    r = node.get("range") or {}
    begin, end = r.get("begin") or {}, r.get("end") or {}
    if "spellingLoc" in begin or "spellingLoc" in end or "offset" not in begin or "offset" not in end:
        return None
    return begin["offset"], end["offset"] + end.get("tokLen", 0)


def _children(node: dict) -> list[dict]:
    return [c for c in node.get("inner", ()) if isinstance(c, dict)]


def _strip(node: dict) -> dict:
    """Below implicit casts and parentheses the source spells nothing of."""
    while node.get("kind") in ("ImplicitCastExpr", "ExprWithCleanups", "MaterializeTemporaryExpr") and \
            _children(node):
        node = _children(node)[0]
    return node


def _wrap(text: str) -> str:
    return text if SIMPLE.match(text) else f"({text})"


def definitions(ast_text: str) -> list[dict]:
    """The function declarations of a `-ast-dump=json -ast-dump-filter` dump (one JSON object per match)."""
    decoder, out, at = json.JSONDecoder(), [], 0
    while True:
        start = ast_text.find("{", at)
        if start < 0:
            return out
        try:
            node, at = decoder.raw_decode(ast_text, start)
        except json.JSONDecodeError:
            at = start + 1
            continue
        if isinstance(node, dict):
            out.append(node)


def body_of(decls: Iterable[dict], text: str, name: str, symbol: str | None = None) -> dict | None:
    """The body (CompoundStmt) of the definition of `name` (the function's unqualified name, or its `symbol` when
    the source spells the mangled name with C linkage) in the parsed text; of several (methods of other classes,
    overloads) the one whose mangled name is `symbol`, when the dump names one."""
    decls = list(decls)
    if symbol and any(d.get("mangledName") == symbol for d in decls):
        decls = sorted(decls, key=lambda d: d.get("mangledName") != symbol)
    for decl in decls:
        if decl.get("kind") not in ("FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl"):
            continue
        if decl.get("name") not in (name, symbol):
            continue
        body = next((c for c in _children(decl) if c.get("kind") == "CompoundStmt"), None)
        span = _span(body) if body else None
        if span and text[span[0]:span[0] + 1] == "{" and text[span[1] - 1:span[1]] == "}":
            return body
    return None


def rewrites(text: str, body: dict, components: Callable[[str], tuple[str, ...] | None] | None = None) \
        -> list[Rewrite]:
    """Every single-site rewrite of the function body; `components` names a record's scalar members (`Vec3` ->
    x, y, z) for the rewrites that write a record's arithmetic out member by member."""
    out: list[Rewrite] = []
    low, high = _span(body)
    values = _Values(text, body, components or (lambda name: None))

    def inside(span) -> bool:
        return span is not None and low <= span[0] and span[1] <= high

    def visit(node: dict, parent: dict | None) -> None:
        span = _span(node)
        if node is not body and not inside(span):
            return                                    # a macro's expansion: its source is the macro's
        kind = node.get("kind")
        kids = _children(node)
        if kind == "BinaryOperator" and len(kids) == 2:
            _binary(text, node, kids, out)
        elif kind == "CompoundAssignOperator" and len(kids) == 2:
            _compound(text, node, kids, out)
        elif kind == "UnaryOperator" and node.get("opcode") in ("++", "--") and parent is not None and \
                parent.get("kind") in ("CompoundStmt", "ForStmt") and kids:
            inner = _span(kids[0])
            if inner and span:
                operand = text[inner[0]:inner[1]]
                op = node["opcode"]
                replacement = f"{op}{operand}" if node.get("isPostfix") else f"{operand}{op}"
                out.append(Rewrite(f"{text[span[0]:span[1]]} -> {replacement}", ((span[0], span[1], replacement),)))
        elif kind == "IfStmt" and node.get("hasElse") and len(kids) >= 3:
            _if_swap(text, node, kids, out)
        elif kind == "DeclStmt" and len(kids) == 1 and kids[0].get("kind") == "VarDecl":
            _integer_type(text, kids[0], out)
        elif kind == "ForStmt":
            _for_direction(text, node, out)
        if kind in ("IfStmt", "WhileStmt", "DoStmt", "ConditionalOperator") and kids:
            _condition(text, kids[1] if kind == "DoStmt" and len(kids) > 1 else kids[0], out)
        if kind == "BinaryOperator" and node.get("opcode") in ("&&", "||") and len(kids) == 2:
            for side in kids:
                _condition(text, side, out)
            if _independent(kids[0], kids[1]):
                a, b = _span(kids[0]), _span(kids[1])
                if a and b and a[1] <= b[0]:
                    left, middle, right = text[a[0]:a[1]], text[a[1]:b[0]], text[b[0]:b[1]]
                    out.append(Rewrite(f"{left} {node['opcode']} {right} swapped",
                                       ((a[0], b[1], right + middle + left),)))
        if kind == "CompoundStmt":
            _adjacent(text, kids, out)
            _temporaries(text, kids, out)
            values.statements(kids, out)
        if kind == "CXXOperatorCallExpr":
            values.operator(node, out)
        elif kind in ("CallExpr", "CXXMemberCallExpr"):
            values.call_arguments(node, out)
        for kid in kids:
            visit(kid, node)
    visit(body, None)
    return out


def _binary(text: str, node: dict, kids: list[dict], out: list[Rewrite]) -> None:
    op = node.get("opcode")
    a, b = _span(kids[0]), _span(kids[1])
    if not a or not b or a[1] > b[0]:
        return
    left, middle, right = text[a[0]:a[1]], text[a[1]:b[0]], text[b[0]:b[1]]
    if op in COMMUTATIVE:
        out.append(Rewrite(f"{left} {op} {right} -> {right} {op} {left}", ((a[0], b[1], right + middle + left),)))
    elif op in FLIPPED and op in middle:
        flipped = middle.replace(op, FLIPPED[op], 1)
        out.append(Rewrite(f"{left} {op} {right} -> {right} {FLIPPED[op]} {left}",
                           ((a[0], b[1], right + flipped + left),)))
    elif op == "=":
        rhs = _strip(kids[1])
        inner = _children(rhs)
        if rhs.get("kind") == "BinaryOperator" and len(inner) == 2 and f"{rhs.get('opcode')}=" in COMPOUND:
            c, d = _span(inner[0]), _span(inner[1])
            if c and d and text[c[0]:c[1]].replace(" ", "") == left.replace(" ", ""):
                compound = f"{left} {rhs['opcode']}= {text[d[0]:d[1]]}"
                out.append(Rewrite(f"{text[a[0]:b[1]]} -> {compound}", ((a[0], b[1], compound),)))


def _condition(text: str, cond: dict, out: list[Rewrite]) -> None:
    """A tested value spelled the other way: `x != 0` / `x != nullptr` as `x`, and a bare `x` as `x != 0`."""
    span = _span(cond)
    if not span:
        return
    node = _strip(cond)
    kids = _children(node)
    if node.get("kind") == "BinaryOperator" and node.get("opcode") == "!=" and len(kids) == 2:
        zero = _strip(kids[1])
        lhs = _span(kids[0])
        if lhs and (zero.get("kind") == "CXXNullPtrLiteralExpr" or
                    zero.get("kind") == "IntegerLiteral" and zero.get("value") == "0"):
            out.append(Rewrite(f"{text[span[0]:span[1]]} -> implicit", ((span[0], span[1], text[lhs[0]:lhs[1]]),)))
    elif node.get("kind") in ("DeclRefExpr", "MemberExpr") and cond.get("kind") == "ImplicitCastExpr":
        spelled = text[span[0]:span[1]]
        zero = "nullptr" if "*" in (node.get("type") or {}).get("qualType", "") else "0"
        out.append(Rewrite(f"{spelled} -> {spelled} != {zero}", ((span[0], span[1], f"{spelled} != {zero}"),)))


def _compound(text: str, node: dict, kids: list[dict], out: list[Rewrite]) -> None:
    op = node.get("opcode")
    a, b = _span(kids[0]), _span(kids[1])
    if op not in COMPOUND or not a or not b:
        return
    left, right = text[a[0]:a[1]], text[b[0]:b[1]]
    plain = f"{left} = {left} {COMPOUND[op]} {_wrap(right)}"
    out.append(Rewrite(f"{left} {op} {right} -> {plain}", ((a[0], b[1], plain),)))


def _if_swap(text: str, node: dict, kids: list[dict], out: list[Rewrite]) -> None:
    cond, then, other = kids[0], kids[1], kids[2]
    spans = [_span(cond), _span(then), _span(other), _span(node)]
    if None in spans or then.get("kind") != "CompoundStmt" or other.get("kind") != "CompoundStmt":
        return
    (c0, c1), (t0, t1), (e0, e1), (n0, n1) = spans
    condition = text[c0:c1]
    stripped = _strip(cond)
    if stripped.get("kind") == "UnaryOperator" and stripped.get("opcode") == "!" and _children(stripped):
        inner = _span(_children(stripped)[0])
        negated = text[inner[0]:inner[1]] if inner else f"!({condition})"
    else:
        negated = f"!({condition})"
    head = text[n0:c0]                                # `if (`
    swapped = f"{head}{negated}) {text[e0:e1]} else {text[t0:t1]}"
    out.append(Rewrite(f"if ({condition}) swapped", ((n0, n1, swapped),)))


def _integer_type(text: str, var: dict, out: list[Rewrite]) -> None:
    qual = (var.get("type") or {}).get("qualType", "")
    span, loc = _span(var), var.get("loc") or {}
    if qual not in INTEGERS + FLAGS or not span or "offset" not in loc or "spellingLoc" in loc:
        return
    spelled = text[span[0]:loc["offset"]].rstrip()
    if spelled not in INTEGERS + FLAGS:               # a typedef or a qualified type: leave it
        return
    for other in (FLAGS if spelled == "bool" else INTEGERS[:4]):
        if other != spelled:
            out.append(Rewrite(f"{spelled} {var.get('name')} -> {other}",
                               ((span[0], span[0] + len(spelled), other),)))


def _referenced(node: dict, ident: str) -> bool:
    if node.get("kind") == "DeclRefExpr" and (node.get("referencedDecl") or {}).get("name") == ident:
        return True
    return any(_referenced(c, ident) for c in _children(node))


def _for_direction(text: str, node: dict, out: list[Rewrite]) -> None:
    """`for (T v = E; v != 0; v--)` with v unused in the body <-> `for (T v = 0; v < E; v++)`."""
    kids = node.get("inner", [])
    if len(kids) != 5 or not all(isinstance(k, dict) for k in (kids[0], kids[2], kids[3], kids[4])):
        return
    init, cond, inc, body = kids[0], kids[2], kids[3], kids[4]
    decl = _children(init)
    if init.get("kind") != "DeclStmt" or len(decl) != 1 or decl[0].get("kind") != "VarDecl" or not _children(decl[0]):
        return
    var, name = decl[0], decl[0].get("name")
    vspan, start, bspan = _span(var), _span(node), _span(body)
    value = _span(_children(var)[0])
    if not vspan or not start or not bspan or not value or _referenced(body, name):
        return
    spelled = text[vspan[0]:(var.get("loc") or {}).get("offset", vspan[0])].rstrip()
    initial = text[value[0]:value[1]]
    stripped = _strip(cond)
    parts = _children(stripped)
    if stripped.get("kind") != "BinaryOperator" or len(parts) != 2:
        return
    lhs, rhs = _strip(parts[0]), _strip(parts[1])
    rhs_span = _span(parts[1])
    counting_down = stripped.get("opcode") in ("!=", ">") and rhs.get("kind") == "IntegerLiteral" and \
        rhs.get("value") == "0" and inc.get("opcode") == "--"
    counting_up = stripped.get("opcode") in ("<", "!=") and initial.strip() == "0" and inc.get("opcode") == "++"
    if not (lhs.get("kind") == "DeclRefExpr" and (lhs.get("referencedDecl") or {}).get("name") == name):
        return
    head = (start[0], bspan[0])
    if counting_down:
        new = f"for ({spelled} {name} = 0; {name} < {_wrap(initial)}; {name}++) "
        out.append(Rewrite(f"for {name} down -> up", ((head[0], head[1], new),)))
    elif counting_up and rhs_span:
        bound = text[rhs_span[0]:rhs_span[1]]
        for test in ("!= 0", "> 0"):
            new = f"for ({spelled} {name} = {bound}; {name} {test}; {name}--) "
            out.append(Rewrite(f"for {name} up -> down ({test})", ((head[0], head[1], new),)))


STATEMENTS = ("BinaryOperator", "CompoundAssignOperator", "CXXOperatorCallExpr", "DeclStmt", "UnaryOperator")


def _statement_end(text: str, end: int) -> int | None:
    semicolon = text.find(";", end)
    return semicolon + 1 if semicolon >= 0 and not text[end:semicolon].strip() else None


VALUES = INTEGERS + ("bool", "float", "double")


def _uses(node: dict, name: str, found: list[dict]) -> list[dict]:
    if node.get("kind") == "DeclRefExpr" and (node.get("referencedDecl") or {}).get("name") == name:
        found.append(node)
    for kid in _children(node):
        _uses(kid, name, found)
    return found


def _local_name(text: str, lhs: str) -> str | None:
    """A local's name for a value stored to `lhs` (`pVec->x` -> `x`, `m_total` -> `total`), unused in the text."""
    words = re.findall(r"[A-Za-z_]\w*", lhs)
    if not words:
        return None
    base = re.sub(r"^(m_|s_|p)(?=[A-Za-z])", "", words[-1]) or words[-1]
    base = base[0].lower() + base[1:]
    for candidate in [base] + [f"{base}{n}" for n in range(2, 9)]:
        if not re.search(rf"\b{re.escape(candidate)}\b", text):
            return candidate
    return None


def _temporaries(text: str, kids: list[dict], out: list[Rewrite]) -> None:
    """A single-use local written into its use (when nothing between touches what it reads), and a stored value
    held in a local first: how values are held decides clang's register choice and schedule."""
    for at, kid in enumerate(kids):
        decls = _children(kid)
        if kid.get("kind") == "DeclStmt" and len(decls) == 1 and decls[0].get("kind") == "VarDecl" and \
                _children(decls[0]) and (decls[0].get("type") or {}).get("qualType") in VALUES:
            var, name = decls[0], decls[0].get("name")
            value, whole = _span(_children(var)[0]), _span(kid)
            later = kids[at + 1:]
            uses = [u for k in later for u in _uses(k, name, [])]
            if not value or not whole or len(uses) != 1 or not _span(uses[0]):
                continue
            holder = next(i for i, k in enumerate(later) if _uses(k, name, []))
            reads, writes = set(), set()
            if not _effects(_children(var)[0], reads, writes) or \
                    not all(_independent(_children(var)[0], k) for k in later[:holder]):
                continue
            use = _span(uses[0])
            end = whole[1] if text[whole[1] - 1:whole[1]] == ";" else (_statement_end(text, whole[1]) or whole[1])
            while end < len(text) and text[end] in " \t":
                end += 1
            if text[end:end + 1] == "\n":
                end += 1
            start = whole[0]
            while start > 0 and text[start - 1] in " \t":
                start -= 1
            inlined = _wrap(text[value[0]:value[1]])
            out.append(Rewrite(f"inline {name}", ((start, end, ""), (use[0], use[1], inlined))))
        stripped = _strip(kid)
        parts = _children(stripped)
        if kid.get("kind") == "BinaryOperator" and kid.get("opcode") == "=" and len(parts) == 2:
            rhs = _strip(parts[1])
            qual = (parts[1].get("type") or {}).get("qualType", "")
            a, b = _span(parts[0]), _span(parts[1])
            if qual not in VALUES or rhs.get("kind") not in ("BinaryOperator", "UnaryOperator", "CallExpr",
                                                             "CXXMemberCallExpr", "ConditionalOperator") or \
                    not a or not b:
                continue
            lhs = text[a[0]:a[1]]
            name = _local_name(text, lhs)
            line = text.rfind("\n", 0, a[0]) + 1
            indent = text[line:a[0]] if not text[line:a[0]].strip() else ""
            if name is None:
                continue
            held = f"{qual} {name} = {text[b[0]:b[1]]};\n{indent}{lhs} = {name}"
            out.append(Rewrite(f"hold `{lhs}`'s value in {name}", ((a[0], b[1], held),)))


CALLS = ("CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "CXXConstructExpr", "CXXNewExpr",
         "CXXDeleteExpr")
WRITES = ("=", "++", "--") + tuple(COMPOUND)


def _effects(node: dict, reads: set[str], writes: set[str], target: bool = False) -> bool:
    """The names (locals, members) a statement reads and writes; False when it calls anything (a call may touch
    whatever the other statement does)."""
    kind = node.get("kind")
    if kind in CALLS:
        return False
    name = None
    if kind == "DeclRefExpr":
        name = (node.get("referencedDecl") or {}).get("name")
    elif kind == "MemberExpr":
        name = "." + str(node.get("name"))
    elif kind == "VarDecl":
        writes.add(str(node.get("name")))
    if name:
        (writes if target else reads).add(name)
    kids = _children(node)
    if kind in ("BinaryOperator", "CompoundAssignOperator") and node.get("opcode") in WRITES and kids:
        return _effects(kids[0], reads, writes, True) and _effects(kids[0], reads, writes) and \
            all(_effects(k, reads, writes) for k in kids[1:])
    if kind == "UnaryOperator" and node.get("opcode") in ("++", "--") and kids:
        return _effects(kids[0], reads, writes, True) and _effects(kids[0], reads, writes)
    if kind == "UnaryOperator" and node.get("opcode") == "*" and target and kids:
        writes.add("*")                               # a store through a pointer: any memory
        return _effects(kids[0], reads, writes)
    if kind == "ArraySubscriptExpr" and target:
        writes.add("*")
    if kind in ("ArraySubscriptExpr",) or (kind == "UnaryOperator" and node.get("opcode") == "*"):
        reads.add("*")
    return all(_effects(k, reads, writes, target and kind in ("MemberExpr", "ImplicitCastExpr", "ParenExpr"))
               for k in kids)


def _independent(one: dict, two: dict) -> bool:
    r1, w1, r2, w2 = set(), set(), set(), set()
    if not _effects(one, r1, w1) or not _effects(two, r2, w2):
        return False
    return not (w1 & (r2 | w2) or w2 & r1)


def _adjacent(text: str, kids: list[dict], out: list[Rewrite]) -> None:
    """Two neighbouring statements that touch nothing of each other's, the other way round (store order follows
    source order)."""
    for first, second in zip(kids, kids[1:]):
        if first.get("kind") not in STATEMENTS or second.get("kind") not in STATEMENTS:
            continue
        if not _independent(first, second):
            continue
        a, b = _span(first), _span(second)
        if not a or not b:
            continue
        a_end = a[1] if first.get("kind") == "DeclStmt" else _statement_end(text, a[1])
        b_end = b[1] if second.get("kind") == "DeclStmt" else _statement_end(text, b[1])
        if a_end is None or b_end is None or a_end > b[0]:
            continue
        one, gap, two = text[a[0]:a_end], text[a_end:b[0]], text[b[0]:b_end]
        out.append(Rewrite(f"swap `{one.strip()}` / `{two.strip()}`", ((a[0], b_end, two + gap + one),)))


# How a value is held. LLVM's Reassociate puts the lower-ranked operand of every commutative operation first (float
# ones too): a fresh load ranks by its place among its block's loads and calls, a computed value by its depth, and
# source order only breaks ties. Swapping the source operands then changes nothing; what decides the order is
# whether an operand is still a load when Reassociate runs (memory that escapes and is read again after another
# write) or a value forwarded from a store. These rewrites change that: an explicit copy of a record operand, a
# temporary held in a named local, a local's uses read again from what it copied, a returned record written
# through an out parameter (in place when an input is that same object), and a record's arithmetic written out
# member by member in the caller (where a rank tie keeps the source order; inside the operator, InstCombine has
# already put the load before the argument).

ARITHMETIC = {"operator+": "+", "operator-": "-", "operator*": "*", "operator/": "/"}
ASSIGNING = {"operator+=": "+=", "operator-=": "-=", "operator*=": "*=", "operator/=": "/="}
HELD = ("ImplicitCastExpr", "ExprWithCleanups", "MaterializeTemporaryExpr", "CXXBindTemporaryExpr", "ParenExpr")
LVALUES = ("DeclRefExpr", "MemberExpr", "ArraySubscriptExpr")
CALLED = ("CallExpr", "CXXMemberCallExpr")
COMPUTED = CALLED + ("CXXOperatorCallExpr",)
SEQUENCED = ("CompoundStmt", "LambdaExpr", "ConditionalOperator", "IfStmt", "ForStmt", "WhileStmt", "DoStmt",
             "SwitchStmt", "CXXForRangeStmt")    # below these a subexpression is not evaluated once, first
EXPRESSIONS = ("ExprWithCleanups", "CXXOperatorCallExpr", "CXXMemberCallExpr", "CallExpr", "BinaryOperator",
               "CompoundAssignOperator", "DeclStmt", "ReturnStmt")
COMPARING = ("operator==", "operator!=", "operator<=", "operator>=")


def _bare(node: dict) -> dict:
    """Below the casts, temporaries, parentheses and elided copies the value itself."""
    while True:
        kids = _children(node)
        if kids and (node.get("kind") in HELD or node.get("kind") == "CXXConstructExpr" and node.get("elidable")
                     and len(kids) == 1):
            node = kids[0]
        else:
            return node


def _qual(node: dict) -> str:
    return re.sub(r"^(?:(?:const|volatile) )+|\s*&+$", "", (node.get("type") or {}).get("qualType") or "").strip()


def _record(node: dict) -> str | None:
    """The unqualified name of a node's record type (`const math::Vec3 &` -> `Vec3`); None for a scalar, a pointer, a
    template or a function type."""
    names = []
    for key in ("qualType", "desugaredQualType"):
        spelled = (node.get("type") or {}).get(key)
        if spelled is None:
            continue
        qual = re.sub(r"^(?:(?:const|volatile) )+|\s*&+$", "", spelled).strip()
        match = re.fullmatch(r"(?:\w+::)*(\w+)", qual)
        if not match or qual in VALUES or qual in ("void", "nullptr_t", "std::nullptr_t"):
            return None
        names.append(match.group(1))
    return names[0] if names else None


def _lvalue(node: dict) -> bool:
    return node.get("kind") in LVALUES or node.get("kind") == "UnaryOperator" and node.get("opcode") == "*"


def _root(node: dict) -> dict | None:
    """The variable an lvalue names or is a member of (`pos.y` -> `pos`); None through a pointer."""
    node = _bare(node)
    while node.get("kind") == "MemberExpr" and not node.get("isArrow") and _children(node):
        node = _bare(_children(node)[0])
    return node if node.get("kind") == "DeclRefExpr" else None


def _callee(node: dict) -> str | None:
    kids = _children(node)
    head = _bare(kids[0]) if kids else {}
    return head.get("name") if head.get("kind") == "MemberExpr" else (head.get("referencedDecl") or {}).get("name")


def _arguments(call: dict) -> list[dict]:
    """A call's spelled arguments (defaults the source leaves out are not)."""
    return [a for a in _children(call)[1:] if a.get("kind") != "CXXDefaultArgExpr"]


def record_members(decls: Iterable[dict], name: str) -> tuple[str, ...] | None:
    """The members of record `name` when it holds nothing else than two to four of one arithmetic type (no bases,
    no unions): what writing its arithmetic out member by member spells."""
    found = set()
    for decl in decls:
        if decl.get("kind") not in ("CXXRecordDecl", "RecordDecl") or decl.get("name") != name or \
                not decl.get("completeDefinition"):
            continue
        kids = _children(decl)
        fields = [k for k in kids if k.get("kind") == "FieldDecl"]
        types = {(f.get("type") or {}).get("qualType") for f in fields}
        if decl.get("bases") or any(k.get("kind") in ("CXXRecordDecl", "RecordDecl") and not k.get("isImplicit")
                                    for k in kids) or \
                not 2 <= len(fields) <= 4 or len(types) != 1 or types.pop() not in VALUES or \
                not all(f.get("name") for f in fields):
            found.add(None)
            continue
        found.add(tuple(f["name"] for f in fields))
    return found.pop() if len(found) == 1 else None


class _Values:
    """The value-holding rewrites of one function body (see above)."""

    def __init__(self, text: str, body: dict, components: Callable[[str], tuple[str, ...] | None]):
        self.text, self.components = text, components
        self.low, self.high = _span(body)

    def source(self, node: dict) -> str | None:
        span = _span(node)
        return self.text[span[0]:span[1]] if span else None

    def spelled(self, name: str, node: dict | None = None) -> str:
        """A record's name as the function or the node's type spells it, most qualified (`math::Vec3`)."""
        found = [q + name for q in re.findall(rf"(?<![\w:])((?:\w+::)*){re.escape(name)}\b",
                                              self.text[self.low:self.high])]
        if node is not None and re.fullmatch(rf"(?:\w+::)*{re.escape(name)}", _qual(node)):
            found.append(_qual(node))
        return max(found, key=len, default=name)

    def indent(self, at: int) -> str:
        line = self.text.rfind("\n", 0, at) + 1
        return self.text[line:at] if not self.text[line:at].strip() else ""

    def members(self, node: dict) -> tuple[str, tuple[str, ...]] | None:
        name = _record(node)
        members = self.components(name) if name else None
        return (self.spelled(name, node), members) if members else None

    # an operator's operands -------------------------------------------------------------------------------------
    def operator(self, node: dict, out: list[Rewrite]) -> None:
        kids, op = _children(node), _callee(node)
        if op not in ARITHMETIC or len(kids) != 3:
            return
        for operand in kids[1:]:
            self.copy(operand, out)
        span, whole = _span(node), self.source(node)
        for spelled, parts in self.member_forms(node, kids):
            replacement = f"{spelled}({', '.join(parts)})"
            out.append(Rewrite(f"{whole} -> {replacement}", ((span[0], span[1], replacement),)))

    def call_arguments(self, node: dict, out: list[Rewrite]) -> None:
        for argument in _arguments(node):
            if argument.get("kind") == "ImplicitCastExpr":         # bound to a const reference: a copy binds too
                self.copy(argument, out)

    def copy(self, operand: dict, out: list[Rewrite]) -> None:
        """A record lvalue read through an explicit copy (`m_a` -> `Vec3(m_a)`): the copy's loads are fresh."""
        bare = _bare(operand)
        span, name = _span(bare), _record(bare)
        if not _lvalue(bare) or not span or not name:
            return
        spelled = self.text[span[0]:span[1]]
        replacement = f"{self.spelled(name, bare)}({spelled})"
        out.append(Rewrite(f"{spelled} -> {replacement}", ((span[0], span[1], replacement),)))

    def member_forms(self, node: dict, kids: list[dict]) -> list[tuple[str, list[str]]]:
        """`a op b` of records written member by member: `Vec3(a.x op b.x, ...)`, a scalar operand on either side
        of a product."""
        result = self.members(node)
        if result is None:
            return []
        spelled, members = result
        op = ARITHMETIC[_callee(node)]

        def part(operand: dict) -> tuple[bool, str] | None:
            bare = _bare(operand)
            written = self.source(bare)
            if written is None:
                return None
            if _record(bare) is not None:
                return (True, _wrap(written)) if _record(bare) == _record(node) and _lvalue(bare) else None
            return (False, _wrap(written)) if _qual(operand) in VALUES and _effects(bare, set(), set()) else None

        a, b = part(kids[1]), part(kids[2])
        if not a or not b or not (a[0] or b[0]):
            return []

        def of(p: tuple[bool, str], member: str) -> str:
            return f"{p[1]}.{member}" if p[0] else p[1]
        forms = [(spelled, [f"{of(a, m)} {op} {of(b, m)}" for m in members])]
        if op == "*" and a[0] != b[0]:
            forms.append((spelled, [f"{of(b, m)} {op} {of(a, m)}" for m in members]))
        return forms

    # statements -------------------------------------------------------------------------------------------------
    def statements(self, kids: list[dict], out: list[Rewrite]) -> None:
        for at, kid in enumerate(kids):
            if kid.get("kind") not in EXPRESSIONS or not _span(kid):
                continue
            expr = _bare(kid)
            if expr.get("kind") == "CXXOperatorCallExpr":
                self.assignment(kid, expr, out)
            elif expr.get("kind") in CALLED:
                self.in_place(kids[at - 1] if at else None, kid, expr, out)
            elif kid.get("kind") == "DeclStmt":
                self.declared(kid, kids[at + 1:], out)
            self.named(kid, out)

    def assignment(self, kid: dict, expr: dict, out: list[Rewrite]) -> None:
        parts, op = _children(expr), _callee(expr)
        span = _span(kid)
        if len(parts) != 3 or not span:
            return
        target, value = parts[1], _bare(parts[2])
        lhs = self.source(target)
        if lhs is None:
            return
        indent = self.indent(span[0])
        if op == "operator=" and value.get("kind") in CALLED and _record(value) == _record(target) and \
                _lvalue(_bare(target)):
            call = self.out_parameter(value, lhs)
            if call:
                out.append(Rewrite(f"{self.source(kid)} -> {call}", ((span[0], span[1], call),)))
        if op == "operator=" and value.get("kind") == "CXXOperatorCallExpr" and _callee(value) in ARITHMETIC:
            for _, form in self.member_forms(value, _children(value)):
                result = self.members(target)
                if result and len(result[1]) == len(form):
                    each = f";\n{indent}".join(f"{lhs}.{m} = {f}" for m, f in zip(result[1], form))
                    out.append(Rewrite(f"{self.source(kid)} member by member: {each}", ((span[0], span[1], each),)))
        if op in ASSIGNING:
            result, written = self.members(target), self.source(_bare(parts[2]))
            other = _bare(parts[2])
            if result is None or written is None:
                return
            if _record(other) is not None:
                if _record(other) != _record(target) or not _lvalue(other):
                    return
                rhs = [f"{_wrap(written)}.{m}" for m in result[1]]
            elif _qual(parts[2]) in VALUES and _effects(other, set(), set()):
                rhs = [_wrap(written)] * len(result[1])
            else:
                return
            each = f";\n{indent}".join(f"{lhs}.{m} {ASSIGNING[op]} {r}" for m, r in zip(result[1], rhs))
            out.append(Rewrite(f"{self.source(kid)} member by member: {each}", ((span[0], span[1], each),)))

    def out_parameter(self, call: dict, target: str) -> str | None:
        """`f(args)` with its result written through a first out parameter: `f(target, args)`."""
        head = self.source(_children(call)[0]) if _children(call) else None
        arguments = [self.source(a) for a in _arguments(call)]
        if head is None or None in arguments:
            return None
        return f"{head}({', '.join([target] + arguments)})"

    def declared(self, kid: dict, later: list[dict], out: list[Rewrite]) -> None:
        decls = _children(kid)
        if len(decls) != 1 or decls[0].get("kind") != "VarDecl" or not _children(decls[0]):
            return
        var, name = decls[0], decls[0].get("name")
        span, loc = _span(kid), (var.get("loc") or {}).get("offset")
        init = _children(var)[0]
        value = _bare(init)
        if not span or loc is None or "&" in (var.get("type") or {}).get("qualType", ""):
            return
        spelled = self.text[span[0]:loc].rstrip()
        if value.get("kind") in CALLED and _record(value) == _record(var):
            call = self.out_parameter(value, name)
            if call:
                held = f"{spelled} {name};\n{self.indent(span[0])}{call};"
                out.append(Rewrite(f"{self.source(kid)} -> {held}", ((span[0], span[1], held),)))
        if value.get("kind") == "CXXConstructExpr" and len(_children(value)) == 1:
            value = _bare(_children(value)[0])                 # a copy: what it copies
        if _lvalue(value) and _effects(value, set(), set()):
            self.reread(name, self.source(value), later, out)

    def reread(self, name: str, origin: str | None, later: list[dict], out: list[Rewrite]) -> None:
        """The uses of a local copy read from what holds the same value: what it copied (until it is first
        written: `v.y` -> `from.y` for `Vec3 v = from`) and where it was stored (after `m_rate =
        rate`, until it is written again: `rate` -> `m_rate`). A reread member stays a load for Reassociate."""
        uses = [u for k in later for u in _uses(k, name, [])]
        written: list[tuple[int, int, int, int]] = []
        stored: list[tuple[int, str]] = []
        for k in later:
            self.writes(k, name, written)
            self.stores(k, name, stored)
        roots = {(w[2], w[3]) for w in written}
        reads = [_span(u) for u in uses if _span(u) and _span(u) not in roots]
        holders = ([(self.low, origin)] if origin is not None else []) + stored
        for at, holder in holders:
            until = min((w[1] for w in written if w[0] >= at), default=None)    # the next write, its value read
            these = [r for r in reads if r[0] >= at and (until is None or r[0] < until)]
            replacement = _wrap(holder)
            lines = [self.text.count("\n", 0, span[0]) + 1 for span in these]
            for span, line in zip(these, lines):
                out.append(Rewrite(f"re-read {holder} for {name} (line {line})", ((span[0], span[1], replacement),)))
            if len(these) > 1:
                out.append(Rewrite(f"re-read {holder} for {name} (lines {', '.join(map(str, lines))})",
                                   tuple((s[0], s[1], replacement) for s in these)))

    def stores(self, node: dict, name: str, found: list) -> None:
        """(end, target) of every `target = name` (target an lvalue that calls nothing)."""
        kind, kids = node.get("kind"), _children(node)
        pair = kids[:2] if kind == "BinaryOperator" and node.get("opcode") == "=" else \
            kids[1:3] if kind == "CXXOperatorCallExpr" and _callee(node) == "operator=" else []
        if len(pair) == 2 and _span(node):
            value, target = _bare(pair[1]), _bare(pair[0])
            if value.get("kind") == "DeclRefExpr" and (value.get("referencedDecl") or {}).get("name") == name and \
                    _lvalue(target) and _effects(target, set(), set()) and self.source(target):
                found.append((_span(node)[1], self.source(target)))
        for kid in kids:
            self.stores(kid, name, found)

    def writes(self, node: dict, name: str, found: list) -> None:
        """(start, end, root start, root end) of what writes the local `name` (an assignment, ++/--, an address,
        a non-const reference or method)."""
        kind, kids = node.get("kind"), _children(node)
        target = None
        if kind in ("BinaryOperator", "CompoundAssignOperator") and node.get("opcode") in WRITES and kids:
            target = kids[0]
        elif kind == "UnaryOperator" and node.get("opcode") in ("++", "--", "&") and kids:
            target = kids[0]
        elif kind == "CXXOperatorCallExpr" and len(kids) > 1 and (_callee(node) or "").endswith("=") and \
                _callee(node) not in COMPARING:
            target = kids[1]
        elif kind == "CXXMemberCallExpr" and kids and _children(kids[0]) and \
                _children(kids[0])[0].get("kind") != "ImplicitCastExpr":
            target = _children(kids[0])[0]                      # a non-const method of it
        if kind in CALLED:
            for argument in _arguments(node):
                root = _root(argument) if argument.get("kind") != "ImplicitCastExpr" else None
                if root and (root.get("referencedDecl") or {}).get("name") == name and _span(root):
                    found.append((*_span(node), *_span(root)))
        root = _root(target) if target else None
        if root and (root.get("referencedDecl") or {}).get("name") == name and _span(root) and _span(node):
            found.append((*_span(node), *_span(root)))
        for kid in kids:
            self.writes(kid, name, found)

    def in_place(self, before: dict | None, kid: dict, call: dict, out: list[Rewrite]) -> None:
        """`f(out, in)` with `out` a local record and `in` another value of its type: `out = in; f(out, out)`, so
        that the call reads what it writes (in place) - with the object of a method held first when it is a
        temporary, which keeps the order the statement evaluated them in."""
        span = _span(kid)
        arguments = _arguments(call)
        locals_ = [a for a in arguments if a.get("kind") == "DeclRefExpr" and _record(a) and
                   (a.get("referencedDecl") or {}).get("kind") == "VarDecl"]
        if not span:
            return
        indent = self.indent(span[0])
        hoists = [None]
        if call.get("kind") == "CXXMemberCallExpr":
            head = _children(_children(call)[0])
            object_ = head[0] if head else {}
            if object_.get("kind") in HELD and _bare(object_).get("kind") in COMPUTED and _record(_bare(object_)):
                hoists.append(_bare(object_))
        for local in locals_:
            name = (local.get("referencedDecl") or {}).get("name")
            for other in arguments:
                if other is local or _record(other) != _record(local) or not _span(_bare(other)):
                    continue
                if _root(other) and (_root(other).get("referencedDecl") or {}).get("name") == name:
                    continue
                value = _bare(other)
                declared = self.uninitialised(before, name)
                for hoist in hoists:
                    edits = [(_span(value), name)]
                    prefix = ""
                    if hoist is not None:
                        held = _local_name(self.text, _callee(hoist) if hoist.get("kind") in CALLED else
                                           _record(hoist).lower())
                        if held is None:
                            continue
                        edits.append((_span(hoist), held))
                        prefix = f"{self.spelled(_record(hoist), hoist)} {held} = {self.source(hoist)};\n{indent}"
                    start = declared[0] if declared else span[0]
                    assign = f"{declared[1]} {name} = {self.source(value)};" if declared else \
                        f"{name} = {self.source(value)};"
                    body = self.text[span[0]:span[1]]
                    for (s, e), replacement in sorted(edits, reverse=True):
                        body = body[:s - span[0]] + replacement + body[e - span[0]:]
                    new = f"{prefix}{assign}\n{indent}{body}"
                    what = f"{self.source(call)} in place on {name}" + (" (object held first)" if hoist else "")
                    out.append(Rewrite(what, ((start, span[1], new),)))

    def uninitialised(self, node: dict | None, name: str) -> tuple[int, str] | None:
        """(start, spelled type) of `T name;` (no initial value) when `node` is that declaration."""
        decls = _children(node) if node and node.get("kind") == "DeclStmt" else []
        if len(decls) != 1 or decls[0].get("name") != name or not _span(node):
            return None
        init = _children(decls[0])
        if init and not (init[0].get("kind") == "CXXConstructExpr" and not _children(init[0])):
            return None
        loc = (decls[0].get("loc") or {}).get("offset")
        return (_span(node)[0], self.text[_span(node)[0]:loc].rstrip()) if loc is not None else None

    def named(self, kid: dict, out: list[Rewrite]) -> None:
        """A computed record temporary of the statement held in a named local first (`T held = expr;`)."""
        span = _span(kid)
        if not span:
            return
        found: list[dict] = []

        def walk(node: dict) -> None:
            if node.get("kind") in SEQUENCED or node.get("kind") == "BinaryOperator" and \
                    node.get("opcode") in ("&&", "||", ","):
                return
            if node.get("kind") == "MaterializeTemporaryExpr":
                value = _bare(node)
                if value.get("kind") in COMPUTED and _record(value) and _span(value):
                    found.append(value)
            for child in _children(node):
                walk(child)
        walk(kid)
        indent = self.indent(span[0])
        for value in found:
            base = _callee(value) if value.get("kind") in CALLED else _record(value).lower()
            held = _local_name(self.text, base or "value")
            if held is None:
                continue
            written = self.source(value)
            insert = f"{self.spelled(_record(value), value)} {held} = {written};\n{indent}"
            where = _span(value)
            out.append(Rewrite(f"hold {written} in {held}", ((span[0], span[0], insert), (where[0], where[1], held))))


REGISTERS = 0x001F03FF          # Rm, Rn, Rd/Rt: what register allocation changes in most AArch64 encodings
PPC_REGISTERS = 0x03FFF800      # rD/rS, rA, rB (frD, frA, frB): the same for PowerPC's big-endian words


@dataclass(frozen=True)
class Score:
    """How far a compiled function is from the original: identical, else the edit distances of the aligned
    instruction streams with registers masked (`shape`: a wrong or missing instruction) and whole (`words`: a
    register too), then the size gap. Aligned, an inserted instruction costs one step, not the shift of every
    later word that counting differing words at equal offsets charges."""
    exact: bool
    shape: int
    words: int
    size_gap: int = 0

    def key(self) -> tuple:
        return (not self.exact, self.shape, self.words, self.size_gap)

    @property
    def text(self) -> str:
        return "identical" if self.exact else f"{self.shape} instructions, {self.words} words apart"


FAILED = Score(False, 1 << 30, 1 << 30, 1 << 30)


def _distance(a: list[int], b: list[int]) -> int:
    from difflib import SequenceMatcher
    same = sum(block.size for block in SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks())
    return len(a) + len(b) - 2 * same


def score(original_path: Path, built_path: Path, name: str, labels=None) -> Score:
    """The `Score` of `name` compiled (built_path) against the original's object; relocated words compare by
    their opcode byte (what they reach is the link's to prove), and `objects.function_diff` decides identity."""
    import struct
    from . import objects
    from .elf import Elf
    diff = objects.function_diff(original_path, built_path, name, labels=labels, limit=0)
    if diff.get("missing"):
        return FAILED
    if diff.get("exact"):
        return Score(True, 0, 0, 0)
    streams = []
    mask = REGISTERS
    for path in (original_path, built_path):
        elf = Elf.load(path)
        if elf.endian == ">":
            mask = PPC_REGISTERS
        symbol = objects._find(elf, name)
        section = elf.sections[symbol.section]
        raw = elf.data(section)[symbol.value:symbol.value + symbol.size]
        relocated = objects._relocs(elf, section, symbol.value, symbol.value + symbol.size, {})
        words = list(struct.unpack(f"{elf.endian}{len(raw) // 4}I", raw[:len(raw) // 4 * 4]))
        words = [w >> 24 | 1 << 40 if offset * 4 in relocated else w for offset, w in enumerate(words)]
        streams.append(words)
    shapes = [[w & ~mask if w < 1 << 32 else w for w in words] for words in streams]
    gap = abs(diff.get("size", 0) - diff.get("compiled_size", 0))
    return Score(False, _distance(*shapes), _distance(*streams), gap)


def _combined(one: Rewrite, two: Rewrite) -> Rewrite | None:
    edits = sorted(one.edits + two.edits)
    if any(a[1] > b[0] for a, b in zip(edits, edits[1:])):
        return None                                   # overlapping sites: not one text
    return Rewrite(f"{one.what}; {two.what}", tuple(edits))


def climb(text: str, propose: Callable[[str], list[Rewrite]], evaluate: Callable[[str], Score],
          jobs: int = 4, rounds: int = 12, seconds: float = 600.0, pairs: int = 6) -> dict[str, Any]:
    """Steepest ascent: every rewrite of the current text is compiled (each distinct text once) and the best one
    that improves the score is taken, until the function is identical, nothing improves, or the rounds or time
    run out. On a plateau, pairs of the `pairs` best single rewrites are tried before giving up (two changes that
    only help together, like a loop's direction and its counter's type). Deterministic: no random moves."""
    started = time.monotonic()
    cache: dict[str, Score] = {}

    def measured(sources: list[str]) -> list[Score]:
        fresh = [s for s in dict.fromkeys(sources) if s not in cache]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            for source, result in zip(fresh, pool.map(evaluate, fresh)):
                cache[source] = result
        return [cache[s] for s in sources]

    best = measured([text])[0]
    history: list[dict[str, Any]] = [{"step": "candidate", "score": best.text}]
    for _ in range(rounds):
        if best.exact or time.monotonic() - started > seconds:
            break
        options = propose(text)
        if not options:
            break
        texts = [o.apply(text) for o in options]
        ranked = sorted(zip(measured(texts), range(len(options))), key=lambda r: r[0].key())
        result, index = ranked[0]
        chosen = options[index]
        if result.key() >= best.key() and pairs > 1:
            top = [options[i] for _, i in ranked[:pairs]]
            combos = [c for i, a in enumerate(top) for b in top[i + 1:] if (c := _combined(a, b))]
            if combos:
                scored = sorted(zip(measured([c.apply(text) for c in combos]), combos), key=lambda r: r[0].key())
                if scored[0][0].key() < result.key():
                    result, chosen = scored[0]
        if result.key() >= best.key():
            break
        text, best = chosen.apply(text), result
        history.append({"step": chosen.what, "score": best.text})
    return {"text": text, "exact": best.exact, "score": best.text, "history": history,
            "variants_compiled": len(cache), "seconds": round(time.monotonic() - started, 1)}


def host_clang() -> str | None:
    """A clang that writes JSON ASTs (clang 9 or newer): ZKIT_SWEEP_CLANG, else clang++ on the PATH."""
    return os.environ.get("ZKIT_SWEEP_CLANG") or shutil.which("clang++") or shutil.which("clang")


MWCC_SHIM = """\
double __fabs(double); float __fabsf(float); double __frsqrte(double); float __fres(float);
double __fnabs(double); float __fnabsf(float); double __fmadd(double, double, double);
float __fmadds(float, float, float); double __fmsub(double, double, double); float __fmsubs(float, float, float);
double __fnmadd(double, double, double); float __fnmadds(float, float, float); double __fnmsub(double, double, double);
float __fnmsubs(float, float, float); double __fsel(double, double, double); float __fsels(float, float, float);
int __cntlzw(unsigned int); int __rlwinm(int, int, int, int); int __rlwimi(int, int, int, int, int);
void __sync(void); void __eieio(void); void __isync(void); void __dcbf(void *, int); void __dcbt(void *, int);
void __dcbst(void *, int); void __dcbz(void *, int); void __dcbi(void *, int); void __icbi(void *, int);
int __lhbrx(void *, int); int __lwbrx(void *, int); void __sthbrx(unsigned short, void *, int);
void __stwbrx(unsigned int, void *, int); unsigned int __mulhwu(unsigned int, unsigned int);
int __mulhw(int, int); void *__alloca(unsigned long); void *__memcpy(void *, const void *, unsigned long);
"""


def _mwcc_parse_flags(argv: list[str], shim: Path) -> list[str]:
    """CodeWarrior's flags as a host clang's: big-endian PowerPC, its include paths, defines and language."""
    keep = ["--target=powerpc-eabi", "-nostdinc", "-fno-builtin", "-fno-short-enums", "-fno-exceptions",
            "-fno-rtti", "-fsigned-char", "-include", str(shim)]
    lang = None
    args = argv[1:]
    for i, arg in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if arg in ("-i", "-I", "-ir") and nxt:
            keep.append(f"-I{nxt}")
        elif arg.startswith("-i") and len(arg) > 2 and not arg.startswith("-inline"):
            keep.append(f"-I{arg[2:]}")
        elif arg.startswith("-I") and len(arg) > 2 and arg != "-I-":
            keep.append(arg)
        elif arg in ("-d", "-D", "-define") and nxt:
            keep.append(f"-D{nxt}")
        elif arg.startswith("-D") and len(arg) > 2:
            keep.append(arg)
        elif arg.startswith("-lang"):
            lang = arg.split("=", 1)[-1] if "=" in arg else nxt
        elif arg == "-char" and nxt == "unsigned":
            keep[keep.index("-fsigned-char")] = "-funsigned-char"
    if lang in ("c++", "cplus", "cpp", "ec++"):
        keep += ["-x", "c++", "-std=c++98"]
    elif lang == "c":
        keep += ["-x", "c"]
    return keep


def parse_command(argv: list[str], clang: str, source: Path, name: str,
                  includes: list[Path] | None = None) -> list[str]:
    """The unit's compile flags (target, standard, includes, defines) for a syntax-only JSON dump of `name`;
    `includes` (header copies, the unit's folder) are searched before the command's own include paths, as the
    compile searches them."""
    first = [f"-I{folder}" for folder in includes or []]
    if any("mwcc" in Path(a).name.lower() for a in argv[:3]):
        shim = source.parent / "mwcc_intrinsics.h"
        if not shim.exists():
            shim.write_text(MWCC_SHIM, encoding="utf-8")
        keep = _mwcc_parse_flags(argv, shim)
        if source.suffix in (".cpp", ".cp", ".cc", ".cxx") and "-x" not in keep:
            keep += ["-x", "c++", "-std=c++98"]
        return [clang, *first, *keep, "-fsyntax-only", "-Wno-everything", "-ferror-limit=0", "-Xclang",
                "-ast-dump=json", "-Xclang", f"-ast-dump-filter={name}", str(source)]
    keep: list[str] = []
    skip = False
    for i, arg in enumerate(argv[1:], 1):
        if skip:
            skip = False
            continue
        if arg in ("-o", "-working-directory", "-MF", "-MT"):
            skip = True
            continue
        if arg == "-c" or not arg.startswith("-"):
            continue
        if arg.startswith(("-I", "-D", "-U", "-std=", "--target=", "-nostdlibinc", "-isystem", "-include",
                           "-fno-exceptions", "-fno-rtti", "-fms-extensions", "-fshort-wchar")):
            keep.append(arg)
    return [clang, *first, *keep, "-fsyntax-only", "-Wno-everything", "-Xclang", "-ast-dump=json", "-Xclang",
            f"-ast-dump-filter={name}", str(source)]


def sweep(project, target: str, query: str, candidate: Path, out: Path | None = None, jobs: int | None = None,
          rounds: int = 12, seconds: float = 600.0, includes: list[Path] | None = None) -> dict[str, Any]:
    """Sweep the rewrites of one function in `candidate` (a file `zkit try` takes) and write the best text;
    `includes` are header copies searched before the tree's headers, in the parse and in every compile."""
    from . import bridge, objects
    from .candidate import _compile, _planned_source, _scratch, compile_command
    from .index import connect, containing, refresh
    clang = host_clang()
    if clang is None:
        raise ValueError("the sweep parses with a host clang (9 or newer): put clang++ on the PATH or set "
                         "ZKIT_SWEEP_CLANG")
    refresh(project)
    found = bridge.resolve(project, query, target, limit=2)
    if len(found) != 1:
        raise ValueError(f"{query} names {'no' if not found else 'more than one'} function; use its address")
    row = containing(connect(project), target, found[0])
    if row is None:
        raise ValueError(f"{query} is not inside a known function")
    unit = objects.objdiff_units(project, target).get(row["unit"] or "")
    if unit is None:
        raise ValueError(f"{row['address']} belongs to no objdiff unit ({row['unit']})")
    root = project.root(project.target(target)["repository"])
    original = root / unit["target_path"]
    labels = objects.label_reader(project, target)
    simple = _simple_name(row["demangled"] or row["name"])
    argv, _, _ = compile_command(project, target, unit)
    unit_source = (unit.get("metadata") or {}).get("source_path") or _planned_source(project, target, unit)
    # the compile's search order: header copies, then the unit's folder (its quoted includes)
    searched = [*(includes or []), *([(root / unit_source).parent] if unit_source else [])]
    text = candidate.read_text(encoding="utf-8", errors="replace")
    work_root = Path(tempfile.mkdtemp(prefix="zkit-sweep-", dir=_scratch(project, target)))

    def propose(source: str) -> list[Rewrite]:
        path = work_root / f"parse{candidate.suffix or '.cpp'}"
        path.write_text(source, encoding="utf-8")
        dump = subprocess.run(parse_command(argv, clang, path, simple, searched), capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)
        body = body_of(definitions(dump.stdout), source, simple, row["name"])
        return rewrites(source, body, components) if body else []

    records: dict[str, tuple[str, ...] | None] = {}

    def components(name: str) -> tuple[str, ...] | None:
        """A record's scalar members, from a dump of its definition in the parsed text (once per name)."""
        if name not in records:
            path = work_root / f"parse{candidate.suffix or '.cpp'}"
            dump = subprocess.run(parse_command(argv, clang, path, name, searched), capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=120)
            records[name] = record_members(definitions(dump.stdout), name)
        return records[name]

    def evaluate(source: str) -> Score:
        with tempfile.TemporaryDirectory(dir=work_root) as work:
            built, _, _ = _compile(project, target, unit, source, Path(work), includes)
            return FAILED if built is None else score(original, built, row["name"], labels)

    try:
        if not propose(text):
            raise ValueError(f"no definition of {simple} with a body found in {candidate} (or nothing to rewrite)")
        result = climb(text, propose, evaluate, jobs or max(1, (os.cpu_count() or 2) // 2), rounds, seconds)
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    destination = out or root / "build" / "sweep" / f"{row['address']}{candidate.suffix or '.cpp'}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(result.pop("text"), encoding="utf-8")
    from .index import address_text
    return {"address": address_text(row["address"]), "function": row["name"], "unit": row["unit"],
            "candidate": str(candidate), **({"includes": [str(f) for f in includes]} if includes else {}),
            "written": str(destination), **result}


def _simple_name(demangled: str) -> str:
    """The unqualified name of a demangled function (`ns::A::update(int)` -> `update`, `~A` for a destructor)."""
    depth, cut = 0, len(demangled)
    for at, c in enumerate(demangled):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif c == "(" and depth == 0:
            cut = at
            break
    head = demangled[:cut]
    depth, start = 0, 0
    for at, c in enumerate(head):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif depth == 0 and head.startswith("::", at):
            start = at + 2
    name = head[start:]
    return re.sub(r"<.*>$", "", name) if not name.startswith("operator") else name
