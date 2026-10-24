"""Variant sweep for near-misses (Switch clang, GameCube CodeWarrior): single-site source rewrites.

A function whose candidate differs from the original only by register choice, instruction order or operand
order usually has a source spelling that clang compiles to the original's code: the other operand order of a
commutative operator, `a = a + b` for `a += b`, a loop counting up instead of down, an `if` with its branches
swapped, a counter of another integer type, two independent statements the other way round. The sweep parses the
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
    the source spells the mangled name with C linkage) in the parsed text."""
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


def rewrites(text: str, body: dict) -> list[Rewrite]:
    """Every single-site rewrite of the function body."""
    out: list[Rewrite] = []
    low, high = _span(body)

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


def parse_command(argv: list[str], clang: str, source: Path, name: str) -> list[str]:
    """The unit's compile flags (target, standard, includes, defines) for a syntax-only JSON dump of `name`."""
    if any("mwcc" in Path(a).name.lower() for a in argv[:3]):
        shim = source.parent / "mwcc_intrinsics.h"
        if not shim.exists():
            shim.write_text(MWCC_SHIM, encoding="utf-8")
        keep = _mwcc_parse_flags(argv, shim)
        if source.suffix in (".cpp", ".cp", ".cc", ".cxx") and "-x" not in keep:
            keep += ["-x", "c++", "-std=c++98"]
        return [clang, *keep, "-fsyntax-only", "-Wno-everything", "-ferror-limit=0", "-Xclang", "-ast-dump=json",
                "-Xclang", f"-ast-dump-filter={name}", str(source)]
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
    return [clang, *keep, "-fsyntax-only", "-Wno-everything", "-Xclang", "-ast-dump=json", "-Xclang",
            f"-ast-dump-filter={name}", str(source)]


def sweep(project, target: str, query: str, candidate: Path, out: Path | None = None, jobs: int | None = None,
          rounds: int = 12, seconds: float = 600.0) -> dict[str, Any]:
    """Sweep the rewrites of one function in `candidate` (a file `zkit try` takes) and write the best text."""
    from . import bridge, objects
    from .candidate import _compile, _scratch, compile_command
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
    text = candidate.read_text(encoding="utf-8", errors="replace")
    work_root = Path(tempfile.mkdtemp(prefix="zkit-sweep-", dir=_scratch(project, target)))

    def propose(source: str) -> list[Rewrite]:
        path = work_root / f"parse{candidate.suffix or '.cpp'}"
        path.write_text(source, encoding="utf-8")
        dump = subprocess.run(parse_command(argv, clang, path, simple), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120)
        body = body_of(definitions(dump.stdout), source, simple, row["name"])
        return rewrites(source, body) if body else []

    def evaluate(source: str) -> Score:
        with tempfile.TemporaryDirectory(dir=work_root) as work:
            built, _, _ = _compile(project, target, unit, source, Path(work))
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
            "candidate": str(candidate),
            "written": str(destination), **result}


def _simple_name(demangled: str) -> str:
    """The unqualified name of a demangled function (`fw::A::update(int)` -> `update`, `~A` for a destructor)."""
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
