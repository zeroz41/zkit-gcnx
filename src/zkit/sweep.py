"""Variant sweep for near-misses (Switch clang, GameCube CodeWarrior): single-site source rewrites.

A function whose candidate differs from the original only by register choice, instruction order or operand
order usually has a source spelling that clang compiles to the original's code: the other operand order of a
commutative operator, `a = a + b` for `a += b`, a loop counting up instead of down, an `if` with its branches
swapped, a counter of another integer type, two independent statements the other way round, and how a value is
held (an explicit copy, a named temporary, a re-read instead of a cached local, an out parameter updated in place,
a record's arithmetic member by member), which decides the order of float operands, a named local for a
condition's temporary, its first call or a returned pointer, an index loop over a container as a range-for (a
pointer walk) and back, and one exit through a result local for early returns. The sweep
parses the function with a host clang's JSON AST (the project's compiler may be too old to write one), rewrites
one site at a time, compiles every rewrite with the unit's exact command, and climbs to the spelling with the fewest
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
from dataclasses import dataclass, field
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
            _range_for(text, node, _children(parent) if parent and parent.get("kind") == "CompoundStmt" else [],
                       body, out)
        elif kind == "CXXForRangeStmt":
            _index_loop(text, node, body, out)
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
    _single_exit(text, body, out)
    if len(values.assigns) > 1:                       # every such temporary named: one only may change nothing
        whole: Rewrite | None = values.assigns[0]
        for one in values.assigns[1:]:
            whole = _combined(whole, one) if whole else None
        if whole:
            out.append(Rewrite(f"assign all {len(values.assigns)} condition temporaries to locals", whole.edits))
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


def _line(text: str, start: int, end: int) -> tuple[int, int]:
    """A statement's [start, end) widened to its whole line when nothing else stands on it."""
    head = text.rfind("\n", 0, start) + 1
    tail = text.find("\n", end)
    tail = len(text) if tail < 0 else tail
    if text[head:start].strip() or text[end:tail].strip():
        return start, end
    return head, tail + 1


def _same(text: str, one: tuple[int, int], two: str) -> bool:
    return re.sub(r"\s+", "", text[one[0]:one[1]]) == re.sub(r"\s+", "", two)


def _sized(text: str, node: dict) -> str | None:
    """The container `c` of a `c.size()` / `p->size()` call (`*p`), or None."""
    call = _strip(node)
    member = _children(call)[0] if call.get("kind") == "CXXMemberCallExpr" and _children(call) else {}
    objects = _children(member)
    if member.get("kind") != "MemberExpr" or member.get("name") != "size" or len(_children(call)) != 1 or \
            not objects or _strip(objects[0]).get("kind") == "CXXThisExpr":
        return None
    span = _span(objects[0])
    if not span:
        return None
    return f"*{_wrap(text[span[0]:span[1]])}" if member.get("isArrow") else text[span[0]:span[1]]


def _element(text: str, node: dict, index: str, container: str) -> bool:
    """`node` reads element `index` of `container`: `c[i]`, `c.begin()[i]` or `c.data()[i]`."""
    node = _strip(node)
    kids = _children(node)
    if node.get("kind") == "CXXOperatorCallExpr" and len(kids) == 3:
        callee, target, at = _strip(kids[0]), _span(kids[1]), _strip(kids[2])
        return (callee.get("referencedDecl") or {}).get("name") == "operator[]" and \
            at.get("kind") == "DeclRefExpr" and (at.get("referencedDecl") or {}).get("name") == index and \
            target is not None and _same(text, target, container)
    if node.get("kind") != "ArraySubscriptExpr" or len(kids) != 2:
        return False
    base, at = _strip(kids[0]), _strip(kids[1])
    if at.get("kind") != "DeclRefExpr" or (at.get("referencedDecl") or {}).get("name") != index:
        return False
    member = _children(base)[0] if base.get("kind") == "CXXMemberCallExpr" and _children(base) else {}
    objects = _children(member)
    if member.get("kind") != "MemberExpr" or member.get("name") not in ("begin", "data") or not objects:
        return False
    span = _span(objects[0])
    spelled = text[span[0]:span[1]] if span else ""
    return bool(span) and (_same(text, span, container) if not member.get("isArrow") else
                           re.sub(r"\s+", "", f"*{_wrap(spelled)}") == re.sub(r"\s+", "", container))


def _elements(text: str, node: dict, index: str, container: str, found: list[dict]) -> bool:
    """Every read of `index` below `node` is an element of `container` (collected in `found`)."""
    if _element(text, node, index, container):
        found.append(_strip(node))
        return True
    if node.get("kind") == "DeclRefExpr" and (node.get("referencedDecl") or {}).get("name") == index:
        return False
    return all(_elements(text, kid, index, container, found) for kid in _children(node))


def _names(node: dict, found: set[str]) -> set[str]:
    if node.get("name"):
        found.add(node["name"])
    if (node.get("referencedDecl") or {}).get("name"):
        found.add(node["referencedDecl"]["name"])
    for kid in _children(node):
        _names(kid, found)
    return found


def _fresh(text: str, whole: dict, base: str) -> str:
    """A local's name not yet used in the function `whole` (its body in `text`)."""
    span, taken = _span(whole) or (0, len(text)), _names(whole, set())
    text = text[span[0]:span[1]]
    for name in [base] + [f"{base}{n}" for n in range(2, 9)]:
        if name not in taken and not re.search(rf"\b{name}\b", text):
            return name
    return f"{base}9"


def _range_for(text: str, node: dict, siblings: list[dict], whole: dict, out: list[Rewrite]) -> None:
    """`for (T i = 0; i < c.size(); i++)` (or `i < n` with `n = c.size()` counted first) whose body reads `i`
    only as an element of `c` (`c[i]`, `c.begin()[i]`) -> `for (E x : c)`: a pointer walk to the end instead of
    an index. A leading `E x = c[i];` becomes the loop variable; else the elements become `item`, held by
    reference (`auto&`) or, for a scalar, by value."""
    kids = node.get("inner", [])
    if len(kids) != 5 or not all(isinstance(k, dict) and k for k in (kids[0], kids[2], kids[3], kids[4])):
        return
    init, cond, inc, body = kids[0], _strip(kids[2]), kids[3], kids[4]
    decls = _children(init)
    if init.get("kind") != "DeclStmt" or not 1 <= len(decls) <= 2 or not all(d.get("kind") == "VarDecl" and
                                                                              _children(d) for d in decls):
        return
    index = decls[0].get("name")
    zero = _strip(_children(decls[0])[0])
    if zero.get("kind") != "IntegerLiteral" or zero.get("value") != "0":
        return
    stepped = _strip(_children(inc)[0]) if _children(inc) else {}
    if inc.get("kind") != "UnaryOperator" or inc.get("opcode") != "++" or \
            (stepped.get("referencedDecl") or {}).get("name") != index:
        return
    parts = _children(cond)
    if cond.get("kind") != "BinaryOperator" or cond.get("opcode") not in ("<", "!=") or len(parts) != 2 or \
            (_strip(parts[0]).get("referencedDecl") or {}).get("name") != index:
        return
    bound, removed = _strip(parts[1]), []
    container = _sized(text, bound)
    if container is None and bound.get("kind") == "DeclRefExpr":
        count = (bound.get("referencedDecl") or {}).get("name")
        held = [d for d in decls[1:] if d.get("name") == count]
        if held:                                      # for (T i = 0, n = c.size(); i < n; i++)
            container = _sized(text, _children(held[0])[0])
        else:                                         # T n = c.size(); just before, read by the loop only
            for sibling in siblings:
                one = _children(sibling)
                if sibling.get("kind") == "DeclStmt" and len(one) == 1 and one[0].get("name") == count and \
                        _children(one[0]) and len(_uses(whole, count, [])) == 1:
                    container = _sized(text, _children(one[0])[0])
                    removed = [_line(text, *_span(sibling))] if container and _span(sibling) else []
        if container is None:
            return
    elif len(decls) != 1:
        return
    if container is None or not _span(body) or not _span(node):
        return
    found: list[dict] = []
    if not _elements(text, body, index, container, found) or not found or any(_span(f) is None for f in found):
        return
    start, (b0, b1) = _span(node)[0], _span(body)
    statements = _children(body) if body.get("kind") == "CompoundStmt" else []
    first = _children(statements[0]) if statements and statements[0].get("kind") == "DeclStmt" else []
    if len(found) == 1 and len(first) == 1 and first[0].get("kind") == "VarDecl" and _children(first[0]) and \
            _strip(_children(first[0])[0]) is found[0] and _span(first[0]) and _span(statements[0]):
        var = first[0]                                # for (...) { E x = c[i]; ... } -> for (E x : c)
        spelled = text[_span(var)[0]:(var.get("loc") or {}).get("offset", 0)].rstrip()
        drop = _line(text, *_span(statements[0]))
        kinds = [spelled] + ([f"const {spelled}&"] if not spelled.endswith(("&", "*")) and
                             not spelled.startswith("const ") else [])
        for kind in kinds:
            head = f"for ({kind} {var['name']} : {container}) "
            out.append(Rewrite(f"for {index} over {container} -> for ({kind} {var['name']} : {container})",
                               ((start, b0, head), (drop[0], drop[1], ""),
                                *((a, b, "") for a, b in removed))))
        return
    name = _fresh(text, whole, "item")
    qual = (found[0].get("type") or {}).get("qualType", "")
    kinds = ([qual] if qual in VALUES or re.fullmatch(r"[\w:]+ \*", qual) else []) + ["auto&"]
    for kind in kinds:
        head = f"for ({kind} {name} : {container}) "
        edits = [(start, b0, head), *((a, b, "") for a, b in removed)]
        edits += [(*_span(f), name) for f in found]
        out.append(Rewrite(f"for {index} over {container} -> for ({kind} {name} : {container})", tuple(edits)))


def _index_loop(text: str, node: dict, whole: dict, out: list[Rewrite]) -> None:
    """`for (E x : c)` over a named container -> `for (int i = 0; i < c.size(); i++) { E x = c[i]; ... }`
    (an array's length for an array): an index instead of a pointer walk."""
    kids = node.get("inner", [])
    if len(kids) != 8 or not all(isinstance(k, dict) and k for k in (kids[1], kids[6], kids[7])):
        return
    ranged = _children(_children(kids[1])[0]) if _children(kids[1]) else []
    loop = _children(kids[6])
    if not ranged or len(loop) != 1 or loop[0].get("kind") != "VarDecl":
        return
    expr, var, body = ranged[0], loop[0], kids[7]
    span, vspan, bspan, nspan = _span(expr), _span(var), _span(body), _span(node)
    if not span or not vspan or not bspan or not nspan or not _plain(expr):
        return
    container = text[span[0]:span[1]]
    sized = re.search(r"\[(\d+)\]$", (_strip(expr).get("type") or {}).get("qualType", ""))
    bound = sized.group(1) if sized else f"{_wrap(container)}.size()"
    index = _fresh(text, whole, "i")
    spelled = text[vspan[0]:(var.get("loc") or {}).get("offset", vspan[0])].rstrip()
    indent = re.match(r"[ \t]*", text[text.rfind("\n", 0, nspan[0]) + 1:]).group(0)
    reads = [f"{_wrap(container)}[{index}]"] + ([] if sized else [f"{_wrap(container)}.begin()[{index}]"])
    for read in reads:
        held = f"{spelled} {var.get('name')} = {read};"
        head = f"for (int {index} = 0; {index} < {bound}; {index}++) "
        if body.get("kind") == "CompoundStmt":
            edits = ((nspan[0], bspan[0], head), (bspan[0] + 1, bspan[0] + 1, f"\n{indent}    {held}"))
        else:
            edits = ((nspan[0], bspan[0], f"{head}{{\n{indent}    {held}\n{indent}    "),
                     (bspan[1], bspan[1], f"\n{indent}}}" if text[bspan[1]:bspan[1] + 1] != ";" else ""))
            if text[bspan[1]:bspan[1] + 1] == ";":
                edits = (edits[0], (bspan[1] + 1, bspan[1] + 1, f"\n{indent}}}"))
        out.append(Rewrite(f"for ({spelled} {var.get('name')} : {container}) -> index loop over {read}", edits))


def _calls(node: dict) -> bool:
    """The expression calls something or writes (an assignment, ++ / --)."""
    kind = node.get("kind")
    if kind in ("CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "CompoundAssignOperator") or \
            kind == "BinaryOperator" and node.get("opcode") == "=" or \
            kind == "UnaryOperator" and node.get("opcode") in ("++", "--"):
        return True
    return any(_calls(k) for k in _children(node))

def _plain(node: dict) -> bool:
    """An expression naming an object without calling anything (a local, a member, `*p`): read twice safely."""
    node = _strip(node)
    kind = node.get("kind")
    if kind == "DeclRefExpr" or kind == "CXXThisExpr":
        return True
    if kind == "MemberExpr" or kind == "UnaryOperator" and node.get("opcode") == "*" or kind == "ParenExpr":
        return all(_plain(k) for k in _children(node))
    return False


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


# One exit. Several `return v;` reach the return block as a phi of their values, and SimplifyCFG may fold those
# into the branches (a `mov w0, #1` before a store); a result local assigned on each path and returned once
# keeps the stores and the materialised value where the source assigns them. The rewrite nests what follows an
# early return into the `if` (its condition negated) or its `else`.

LITERALS = ("IntegerLiteral", "CXXBoolLiteralExpr", "FloatingLiteral", "CXXNullPtrLiteralExpr", "GNUNullExpr",
            "CharacterLiteral")
NEGATED = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def _returns(node: dict) -> bool:
    """Whether a statement holds a `return` of its function (a lambda's are its own)."""
    if node.get("kind") == "ReturnStmt":
        return True
    return node.get("kind") != "LambdaExpr" and any(_returns(k) for k in _children(node))


def _exits(node: dict | None) -> bool:
    """Whether every path through a statement returns."""
    kind, kids = (node or {}).get("kind"), _children(node or {})
    if kind == "ReturnStmt":
        return True
    if kind == "CompoundStmt":
        return any(_exits(k) for k in kids)
    return kind == "IfStmt" and bool(node.get("hasElse")) and len(kids) == 3 and _exits(kids[1]) and _exits(kids[2])


def _constant(node: dict) -> bool:
    node = _strip(_bare(node))
    if node.get("kind") == "UnaryOperator" and node.get("opcode") in ("-", "+") and _children(node):
        return _constant(_children(node)[0])
    return node.get("kind") in LITERALS or node.get("kind") == "DeclRefExpr" and \
        (node.get("referencedDecl") or {}).get("kind") == "EnumConstantDecl"


class _SingleExit:
    """`return` statements of one body lowered into assignments of a result local (see above)."""

    def __init__(self, text: str, name: str, default: str, unit: str):
        self.text, self.name, self.default, self.unit = text, name, default, unit

    def end(self, node: dict) -> int:
        """Where a statement ends, its `;` included."""
        span = _span(node)
        if self.text[span[1] - 1:span[1]] == ";":
            return span[1]
        closed = self.text[span[1] - 1:span[1]] == "}" and node.get("kind") in SEQUENCED
        return span[1] if closed else (_statement_end(self.text, span[1]) or span[1])

    def lead(self, node: dict) -> int:
        """The start of a statement's first line, with the `//` comment lines just above it."""
        start = self.text.rfind("\n", 0, _span(node)[0]) + 1
        if self.text[start:_span(node)[0]].strip():
            return _span(node)[0]
        while start > 0:
            above = self.text.rfind("\n", 0, start - 1) + 1
            if not self.text[above:start].strip().startswith("//"):
                break
            start = above
        return start

    def lines(self, start: int, end: int, base: str, indent: str) -> list[str]:
        """Source lines moved from indentation `base` to `indent`."""
        out = []
        for line in self.text[start:end].split("\n"):
            if not line.strip():
                continue
            out.append(indent + (line[len(base):] if line.startswith(base) else line.lstrip()))
        return out

    def base(self, node: dict) -> str:
        line = self.text.rfind("\n", 0, _span(node)[0]) + 1
        return self.text[line:_span(node)[0]] if not self.text[line:_span(node)[0]].strip() else ""

    def negated(self, cond: dict) -> str:
        bare, written = _strip(cond), self.text[_span(cond)[0]:_span(cond)[1]]
        while bare.get("kind") == "ParenExpr" and _children(bare):
            bare = _strip(_children(bare)[0])
        kids = _children(bare)
        if bare.get("kind") == "UnaryOperator" and bare.get("opcode") == "!" and kids and _span(kids[0]):
            inner = _span(kids[0])
            return self.text[inner[0]:inner[1]]
        op = bare.get("opcode")
        if bare.get("kind") == "BinaryOperator" and op in NEGATED and len(kids) == 2 and _span(kids[0]) and \
                _span(kids[1]):
            types = {_qual(k) for k in kids}
            if op in ("==", "!=") or all(t in INTEGERS or t.endswith("*") for t in types):
                a, b = _span(kids[0]), _span(kids[1])
                return f"{self.text[a[0]:a[1]]} {NEGATED[op]} {self.text[b[0]:b[1]]}"
        return f"!{_wrap(written)}"

    def branch(self, node: dict | None, indent: str) -> list[str] | None:
        if node is None:
            return []
        return self.lower(_children(node) if node.get("kind") == "CompoundStmt" else [node], indent)

    def lower(self, statements: list[dict], indent: str) -> list[str] | None:
        """The statements with every return an assignment and what follows a return nested; None when a return
        cannot be lowered (in a loop or a switch, or code that only some paths reach)."""
        out: list[str] = []
        for at, node in enumerate(statements):
            rest = statements[at + 1:]
            if not _span(node):
                return None
            if not _returns(node):
                out += self.lines(self.lead(node), self.end(node), self.base(node), indent)
                continue
            out += self.lines(self.lead(node), _span(node)[0], self.base(node), indent)       # its comments
            kids = _children(node)
            if node.get("kind") == "ReturnStmt":
                if rest or not kids or not _span(kids[0]):
                    return None
                value = self.text[_span(kids[0])[0]:_span(kids[0])[1]]
                return out + ([f"{indent}{self.name} = {value};"] if value != self.default else [])
            if node.get("kind") != "IfStmt" or node.get("hasInit") or node.get("hasVar") or \
                    node.get("isConstexpr") or len(kids) < 2 or not _span(kids[0]):
                return None
            cond, then, other = kids[0], kids[1], kids[2] if node.get("hasElse") and len(kids) > 2 else None
            deeper = indent + self.unit
            then_lines, other_lines = self.branch(then, deeper), self.branch(other, deeper)
            tail = self.lower(rest, deeper)
            if then_lines is None or other_lines is None or tail is None:
                return None
            then_exits, other_exits = _exits(then), other is not None and _exits(other)
            if then_exits and not other_exits:
                other_lines += tail
            elif other_exits and not then_exits:
                then_lines += tail
            elif rest:
                return None                           # reached by some paths only, or by none
            written = self.text[_span(cond)[0]:_span(cond)[1]]
            if then_lines:
                out += [f"{indent}if ({written}) {{", *then_lines]
                out += [f"{indent}}} else {{", *other_lines, f"{indent}}}"] if other_lines else [f"{indent}}}"]
            elif other_lines:
                out += [f"{indent}if ({self.negated(cond)}) {{", *other_lines, f"{indent}}}"]
            elif not _effects(cond, set(), set()):
                return None                           # a test whose calls would be lost
            return out                                # what followed is nested above
        return out


def _single_exit(text: str, body: dict, out: list[Rewrite]) -> None:
    """Several `return v;` -> `T result = default; ... result = v; ... return result;` (the default the last
    return's constant)."""
    statements = _children(body)
    if not statements or statements[-1].get("kind") != "ReturnStmt" or not _children(statements[-1]):
        return
    returns: list[dict] = []

    def collect(node: dict) -> None:
        if node.get("kind") == "ReturnStmt":
            returns.append(node)
        elif node.get("kind") != "LambdaExpr":
            for kid in _children(node):
                collect(kid)
    collect(body)
    values = [_children(r)[0] if _children(r) else None for r in returns]
    final = values[-1]
    if len(returns) < 2 or None in values or not _constant(final) or not _span(final) or \
            any(v.get("valueCategory") not in (None, "prvalue") or _record(v) for v in values):
        return
    spelled = (final.get("type") or {}).get("qualType", "")
    if not spelled or spelled == "void" or "(" in spelled:
        return
    first = next(i for i, s in enumerate(statements) if _returns(s))
    if first == len(statements) - 1 or not all(_span(s) for s in statements[first:]):
        return
    name = _local_name(text[_span(body)[0]:_span(body)[1]], "result")       # a file's other `result`s may stay
    default = text[_span(final)[0]:_span(final)[1]]
    exit_ = _SingleExit(text, name or "", default, "")
    opening = text.rfind("\n", 0, _span(body)[0]) + 1
    outer = re.match(r"[ \t]*", text[opening:]).group(0)
    indent = exit_.base(statements[first])
    exit_.unit = indent[len(outer):] if indent.startswith(outer) and len(indent) > len(outer) else "    "
    lowered = exit_.lower(statements[first:-1], indent) if name else None
    if lowered is None:
        return
    start, end = exit_.lead(statements[first]), exit_.end(statements[-1])
    new = "\n".join([f"{indent}{spelled} {name} = {default};", *lowered, f"{indent}return {name};"])
    out.append(Rewrite(f"one exit through {name}", ((start, end, new),)))


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
        self.assigns: list[Rewrite] = []
        self.names: list[str] = []

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
        for at, kid in enumerate(kids):
            if _span(kid):
                self.assigned(kid, out)
                self.pointer(kid, kids[at + 1:], out)
                self.first_call(kid, out)

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

    @staticmethod
    def tested(kid: dict, loops: bool) -> list[dict]:
        """What a statement evaluates first: an expression statement itself, an `if`'s or a `switch`'s
        condition (a `while`'s with `loops`: evaluated again each time)."""
        kids = _children(kid)
        if kid.get("kind") in EXPRESSIONS:
            return [kid]
        if kid.get("kind") in ("IfStmt", "SwitchStmt") + (("WhileStmt",) if loops else ()) and kids and \
                not kid.get("hasInit") and not kid.get("hasVar"):
            return [kids[0]]
        return []

    def held_name(self, callee: str | None, fallback: str, taken: Iterable[str] = ()) -> str | None:
        """A local's name for what `callee` returns: its name without `get` (`getItem` -> `item`), else the
        type's (`Item` -> `item`)."""
        base = re.sub(r"^[Gg]et(?:_(?=[A-Za-z])|(?=[A-Z]))", "", callee or "")
        return _local_name(" ".join([self.text, *taken]), base if callee and base != callee else fallback)

    def assigned(self, kid: dict, out: list[Rewrite]) -> None:
        """A computed record temporary that a condition evaluates (an `if`'s or a `while`'s, or an operand of
        && / || / ?:) assigned to a local declared just before the statement: `T held; if (a && (held =
        f()).x)`. A named object gets lifetime markers, so its stack slot is shared with the block's others."""
        span = _span(kid)
        found: list[dict] = []

        def walk(node: dict, conditional: bool) -> None:
            kind = node.get("kind")
            if kind == "LambdaExpr" or kind in SEQUENCED and kind != "ConditionalOperator":
                return
            if kind == "MaterializeTemporaryExpr" and conditional:
                value = _bare(node)
                if value.get("kind") in COMPUTED and _record(value) and _span(value):
                    found.append(value)
            inner = conditional or kind == "ConditionalOperator" or \
                kind == "BinaryOperator" and node.get("opcode") in ("&&", "||")
            for child in _children(node):
                walk(child, inner)
        for root in self.tested(kid, True):
            walk(root, kid.get("kind") not in EXPRESSIONS)
        indent = self.indent(span[0])
        for value in found:
            held = self.held_name(_callee(value) if value.get("kind") in CALLED else None, _record(value),
                                  self.names)                 # unique: they may all be applied together
            if held is None:
                continue
            written = self.source(value)
            insert = f"{self.spelled(_record(value), value)} {held};\n{indent}"
            where = _span(value)
            self.names.append(held)
            self.assigns.append(Rewrite(f"assign {written} to {held} declared before the statement",
                                        ((span[0], span[0], insert), (where[0], where[1], f"({held} = {written})"))))
            out.append(self.assigns[-1])

    def pointer(self, kid: dict, later: list[dict], out: list[Rewrite]) -> None:
        """A returned pointer the statement reaches through (`f(x)->m = v`) held in a named local first: `T* p =
        f(x); p->m = v`, and with the same call's later `f(x)->` in the block read from it too."""
        span = _span(kid)
        found: dict[str, dict] = {}

        def walk(node: dict) -> None:
            kind = node.get("kind")
            if kind in SEQUENCED or kind == "BinaryOperator" and node.get("opcode") in ("&&", "||", ","):
                return
            if kind == "MemberExpr" and node.get("isArrow") and _children(node):
                base = _bare(_children(node)[0])
                if base.get("kind") in CALLED and _span(base) and _qual(base).endswith("*") and \
                        "(" not in _qual(base):
                    found.setdefault(self.source(base), base)
            for child in _children(node):
                walk(child)
        for root in self.tested(kid, False):
            walk(root)
        indent = self.indent(span[0])
        for written, call in found.items():
            qual = (call.get("type") or {}).get("qualType", "")
            match = re.fullmatch(r"((?:const |volatile )*)(?:\w+::)*(\w+) \*", qual)
            spelled = f"{match.group(1)}{self.spelled(match.group(2))}*" if match else qual
            pointee = match.group(2) if match else "value"
            held = self.held_name(_callee(call), pointee[0].lower() + pointee[1:])
            if held is None:
                continue
            insert = f"{spelled} {held} = {written};\n{indent}"
            where = _span(call)
            line = self.text.count("\n", 0, span[0]) + 1
            out.append(Rewrite(f"hold {written} in {held} (line {line})",
                               ((span[0], span[0], insert), (where[0], where[1], held))))
            again = [(m.start(), m.end() - 2) for k in [kid, *later] if _span(k)
                     for m in re.finditer(re.escape(written) + r"\s*->", self.text[:_span(k)[1]])
                     if m.start() >= _span(k)[0] and m.start() != where[0]]
            if again:
                edits = [(span[0], span[0], insert), (where[0], where[1], held)]
                edits += [(s, s + len(written), held) for s, _ in again]
                out.append(Rewrite(f"hold {written} in {held} (line {line}, all {len(edits) - 1} uses)",
                                   tuple(edits)))


    def first_call(self, kid: dict, out: list[Rewrite]) -> None:
        """The call an `if`'s or a `switch`'s condition makes first (the condition, the left operand of && / ||
        or of a comparison, below a `!`) held in a named scalar local before the statement: `bool flag = f(x);
        if (!flag && p)`. The call is then no longer ordered with the rest, so the operands may swap."""
        if kid.get("kind") in EXPRESSIONS:
            return
        for node in self.tested(kid, False):
            junction = None                           # the && / || whose left operand holds the call
            while True:
                node = _bare(node)
                kids = _children(node)
                if node.get("kind") == "BinaryOperator" and node.get("opcode") in ("&&", "||") and len(kids) == 2:
                    junction = node
                if node.get("kind") == "ParenExpr" and kids or \
                        node.get("kind") == "UnaryOperator" and node.get("opcode") == "!" and kids or \
                        node.get("kind") == "BinaryOperator" and len(kids) == 2 and \
                        node.get("opcode") in ("&&", "||", "==", "!=", "<", ">", "<=", ">="):
                    node = kids[0]
                    continue
                break
            qual = _qual(node)
            if node.get("kind") not in CALLED or not _span(node) or \
                    not (qual in VALUES or re.fullmatch(r"(?:\w+::)*\w+ \*", qual)):
                continue
            span, where = _span(kid), _span(node)
            fallback = "flag" if qual == "bool" else "value"
            held = self.held_name(_callee(node), fallback)
            if held is None:
                continue
            written = self.source(node)
            spelled = qual if qual in VALUES else f"{self.spelled(qual[:-2].split('::')[-1])}*"
            insert = f"{spelled} {held} = {written};\n{self.indent(span[0])}"
            out.append(Rewrite(f"hold {written} in {held} before the condition",
                               ((span[0], span[0], insert), (where[0], where[1], held))))
            sides = [_span(k) for k in _children(junction)] if junction else []
            if len(sides) == 2 and None not in sides and sides[0][1] <= sides[1][0] and \
                    not _calls(_children(junction)[1]) and sides[0][0] <= where[0] and where[1] <= sides[0][1]:
                (a0, a1), (b0, b1) = sides            # nothing left to order: the other test may come first
                left = self.text[a0:where[0]] + held + self.text[where[1]:a1]
                swapped = self.text[b0:b1] + self.text[a1:b0] + left
                out.append(Rewrite(f"hold {written} in {held} before the condition, test it last",
                                   ((span[0], span[0], insert), (a0, b1, swapped))))

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
    wrong: frozenset = field(default=frozenset(), compare=False)    # the original's words left unpaired

    def key(self) -> tuple:
        return (not self.exact, self.shape, self.words, self.size_gap)

    @property
    def text(self) -> str:
        return "identical" if self.exact else f"{self.shape} instructions, {self.words} words apart"


FAILED = Score(False, 1 << 30, 1 << 30, 1 << 30)


def _distance(a: list[int], b: list[int]) -> int:
    return _aligned(a, b)[0]


def _aligned(a: list[int], b: list[int]) -> tuple[int, frozenset]:
    """The edit distance of two word streams and the indices of `a`'s words left unpaired."""
    from difflib import SequenceMatcher
    blocks = SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks()
    paired = {i for block in blocks for i in range(block.a, block.a + block.size)}
    return len(a) + len(b) - 2 * len(paired), frozenset(range(len(a))) - paired


def score(original_path: Path, built_path: Path, name: str, labels=None, built_name: str | None = None) -> Score:
    """The `Score` of `name` compiled (built_path, as `built_name` when it is named differently there) against the
    original's object; relocated words compare by their opcode byte (what they reach is the link's to prove), and
    `objects.function_diff` decides identity."""
    import struct
    from . import objects
    from .elf import Elf
    diff = objects.function_diff(original_path, built_path, name, built_name, labels=labels, limit=0)
    if diff.get("missing"):
        return FAILED
    if diff.get("exact"):
        return Score(True, 0, 0, 0)
    streams = []
    mask = REGISTERS
    for path, wanted in ((original_path, name), (built_path, built_name or name)):
        elf = Elf.load(path)
        if elf.endian == ">":
            mask = PPC_REGISTERS
        symbol = objects._find(elf, wanted)
        section = elf.sections[symbol.section]
        raw = elf.data(section)[symbol.value:symbol.value + symbol.size]
        relocated = objects._relocs(elf, section, symbol.value, symbol.value + symbol.size, {})
        words = list(struct.unpack(f"{elf.endian}{len(raw) // 4}I", raw[:len(raw) // 4 * 4]))
        words = [w >> 24 | 1 << 40 if offset * 4 in relocated else w for offset, w in enumerate(words)]
        streams.append(words)
    shapes = [[w & ~mask if w < 1 << 32 else w for w in words] for words in streams]
    gap = abs(diff.get("size", 0) - diff.get("compiled_size", 0))
    words, wrong = _aligned(*streams)
    return Score(False, _distance(*shapes), words, gap, wrong)


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
    only help together, like a loop's direction and its counter's type), and pairs of up to `pairs` worse ones
    with those that keep the score (at most 4 * pairs * pairs). Deterministic: no random moves."""
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
            # a worse rewrite (first those that pair a word of the original's the current text leaves unpaired)
            # with one that keeps the score: a change that only shows together with another (a counter's type
            # that lets a re-read be hoisted), bounded
            worse = sorted(((s, i) for s, i in ranked if best.key() < s.key() < FAILED.key()),
                           key=lambda r: (not best.wrong - r[0].wrong, r[0].key()))[:pairs]
            level = dict.fromkeys([i for _, i in ranked[:pairs]] + [i for s, i in ranked if s.key() == best.key()])
            wider = [c for p in level for _, w in worse if w != p and (c := _combined(options[w], options[p]))]
            combos += wider[:4 * pairs * pairs]
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
          rounds: int = 12, seconds: float = 600.0, includes: list[Path] | None = None,
          symbol: str | None = None) -> dict[str, Any]:
    """Sweep the rewrites of one function in `candidate` (a file `zkit try` takes) and write the best text;
    `includes` are header copies searched before the tree's headers, in the parse and in every compile.
    `symbol` is the function's name in the candidate when it differs from the original's (a placeholder the
    candidate already defines under its mangled name, ahead of the rename)."""
    from . import bridge, objects
    from .elf import Elf
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
    unit = objects.unit_holding(project, target, row)
    if unit is None:
        raise ValueError(f"{row['address']} belongs to no objdiff unit ({row['unit']})")
    root = project.root(project.target(target)["repository"])
    original = root / unit["target_path"]
    labels = objects.label_reader(project, target)
    built_name = symbol or row["name"]
    if symbol:
        simple = _symbol_simple_name(symbol)
    else:
        simple = _simple_name(row["demangled"] or row["name"])
    argv, _, _ = compile_command(project, target, unit)
    unit_source = (unit.get("metadata") or {}).get("source_path") or _planned_source(project, target, unit)
    # the compile's search order: header copies, then the unit's folder (its quoted includes)
    searched = [*(includes or []), *([(root / unit_source).parent] if unit_source else [])]
    text = candidate.read_text(encoding="utf-8", errors="replace")
    work_root = Path(tempfile.mkdtemp(prefix="zkit-sweep-", dir=_scratch(project, target)))

    parsed: dict[str, Any] = {}

    def propose(source: str) -> list[Rewrite]:
        path = work_root / f"parse{candidate.suffix or '.cpp'}"
        path.write_text(source, encoding="utf-8")
        dump = subprocess.run(parse_command(argv, clang, path, simple, searched), capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)
        body = body_of(definitions(dump.stdout), source, simple, built_name)
        parsed.update(body=body, errors=_errors(dump.stderr) if dump.returncode else [])
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
            return FAILED if built is None else score(original, built, row["name"], labels, built_name)

    try:
        if not propose(text):
            reason = (f"; the host clang's parse failed: {'; '.join(parsed['errors'])}" if parsed.get("errors")
                      else "")
            if parsed.get("body") is not None:
                raise ValueError(f"no rewrite applies to {simple} in {candidate}{reason}")
            raise ValueError(f"no definition of {simple} with a body found in {candidate}{reason}")
        with tempfile.TemporaryDirectory(dir=work_root) as work:
            built, _, messages = _compile(project, target, unit, text, Path(work), includes)
            if built is None:
                raise ValueError(f"{candidate} does not compile with its unit's command: "
                                 f"{'; '.join(_errors(messages)) or 'no messages'}")
            if objects._find(Elf.load(built), built_name) is None:
                from .nxlink import placeholder_partner
                partner = None if symbol else placeholder_partner(
                    built_name, [s.name for s in Elf.load(built).symbols if s.kind == "func"])
                if partner is None:
                    raise ValueError(f"{candidate} compiles but defines no {built_name}"
                                     + ("" if symbol else "; name the candidate's symbol with --symbol"))
                built_name = partner
        result = climb(text, propose, evaluate, jobs or max(1, (os.cpu_count() or 2) // 2), rounds, seconds)
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    destination = out or root / "build" / "sweep" / f"{row['address']}{candidate.suffix or '.cpp'}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    best_text = result.pop("text")
    destination.write_text(best_text, encoding="utf-8")
    from .index import address_text
    if best_text != text:                            # kept with what `zkit try` measures, for a later retry
        from . import misses
        from .candidate import compare
        try:
            measured = compare(project, target, unit, row["name"], best_text, None, includes)
        except Exception:  # noqa: BLE001 - keeping the result is a side effect
            measured = {}
        if measured.get("compiled"):
            misses.record_quietly(project, target, best_text, includes,
                                  [{"address": address_text(row["address"]), "function": row["name"],
                                    "unit": row["unit"], "exact": measured.get("exact"),
                                    "differences": measured.get("differences"),
                                    "reloc_only": measured.get("reloc_only")}], "sweep", str(destination))
    return {"address": address_text(row["address"]), "function": row["name"], "unit": row["unit"],
            **({"symbol": symbol} if symbol else {}),
            "candidate": str(candidate), **({"includes": [str(f) for f in includes]} if includes else {}),
            "written": str(destination), **result}


def _errors(messages: str, limit: int = 3) -> list[str]:
    """The first `limit` error lines of a compiler's messages."""
    return [line.strip() for line in (messages or "").splitlines() if "error" in line.lower()][:limit]


def _symbol_simple_name(symbol: str) -> str:
    """The unqualified name a mangled symbol declares: Itanium (Switch) first, then CodeWarrior, whose
    `__ct__9TClassFv` llvm-cxxfilt leaves alone."""
    from .index import cw_demangle
    from .platform import demangle_itanium
    return _simple_name(demangle_itanium([symbol])[0] or cw_demangle(symbol) or symbol)


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
