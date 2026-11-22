"""A source file carved into the units a target's split gives it.

A split can give one source file's code to several units: its plain name and later pieces named `file_<address>`
(`units.PIECE`), when another build of the program compiled what one build had in one file as several. A piece
with no source file of its own compiles nothing, so the functions there that the file defines cannot match. Carving
moves each such function's definition from the file into the piece's own source, `<file>_<address>.<ext>`, which
starts with the file's preamble (what comes before its first definition: includes, declarations) and keeps the
namespace blocks each definition sat in.

A function is found in the file by its demangled name: the qualified name the definition spells and as many
parameters. A name two definitions of the file fit (overloads with as many parameters), a definition inside a class
body (an inline member, which moves with its class), code a piece's functions share with the plain unit (one
definition two units hold) and functions the file does not define (a template's or a header's inline, which any
unit that uses it emits) stay where they are and are reported. Whether the carved sources compile and match is for
the build and its report to say; nothing here edits a file without `write`.
"""

from __future__ import annotations

import collections
import re
from dataclasses import dataclass, field

from . import cxx
from .units import PIECE

class Uncarved(ValueError):
    """Why a file's definitions cannot be carved out cleanly."""


@dataclass
class Piece:
    unit: str                                   # the piece's unit, `dir/file_<address>`
    base: str                                   # the source it is carved from, relative to the repository
    source: str                                 # the piece's own source to write, relative to the repository
    moves: list[tuple[str, cxx.Definition]] = field(default_factory=list)   # (function, definition)
    left: dict[str, list[str]] = field(default_factory=lambda: collections.defaultdict(list))  # reason -> functions


def _qualified(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _demangled(names: list[str]) -> dict[str, tuple[str, int] | None]:
    """name -> (qualified name, parameter count) of each Itanium name; None for what does not demangle to a
    function."""
    from .itanium import parameters
    from .platform import demangle_itanium
    out: dict[str, tuple[str, int] | None] = {}
    for name, text in zip(names, demangle_itanium(names)):
        parsed = parameters(text) if text else None
        if parsed is None:
            out[name] = None if name.startswith("_Z") else (name, -1)   # a C name: any arity
            continue
        qualified, params, _ = parsed
        count = 0 if params in ([], ["void"]) else len(params)
        out[name] = (_qualified(qualified), count)
    return out


def _unit_functions(project, target: str) -> dict[str, list[str]]:
    """unit -> the named functions the target's split puts in its code ranges, in address order."""
    import bisect
    from .program import Program
    from .score import placeholder
    from .structure import CODE_SECTIONS, splits
    rows, _ = splits(project, target)
    code = sorted((start, end, unit) for unit, section, start, end in rows if section in CODE_SECTIONS)
    starts = [r[0] for r in code]
    out: dict[str, list[str]] = collections.defaultdict(list)
    program = Program.from_project(project, target)
    base = getattr(program, "base", 0) or 0
    for f in sorted(program.functions, key=lambda f: f.address):
        if placeholder(f.name):
            continue
        for address in {f.address, f.address - base}:
            i = bisect.bisect_right(starts, address) - 1
            if i >= 0 and code[i][0] <= address < code[i][1]:
                out[code[i][2]].append(f.name)
                break
    return out


def plan(project, target: str, only: list[str] | None = None) -> list[Piece]:
    """What carving would move for each piece unit with no source of its own whose file has one."""
    config = project.target(target)
    root = project.root(config["repository"])
    source_dir = "src"                           # where `build` compiles each unit's source from
    functions = _unit_functions(project, target)
    pieces: list[Piece] = []
    for unit in sorted(functions):            # a split's units are source paths: `dir/file_<address>.cpp`
        if only and unit not in only and unit.rsplit(".", 1)[0] not in only:
            continue
        match = PIECE.search(unit)
        if not match or (root / source_dir / unit).is_file():
            continue
        base = unit[:match.start()] + unit[match.end():]
        if (root / source_dir / base).is_file():
            pieces.append(Piece(unit, f"{source_dir}/{base}", f"{source_dir}/{unit}"))
    by_base: dict[str, list[Piece]] = collections.defaultdict(list)
    for piece in pieces:
        by_base[piece.base].append(piece)
    for base, group in by_base.items():
        text = (root / base).read_text(encoding="utf-8", errors="replace")
        definitions = [d for d in cxx.definitions(text)]
        index: dict[str, list[cxx.Definition]] = collections.defaultdict(list)
        for d in definitions:
            index[_qualified(d.qualified)].append(d)
        own = set(functions.get(base[len(source_dir) + 1:], ()))       # the plain unit's: a definition it also holds stays
        names = sorted({n for p in group for n in functions[p.unit]} | own)
        parsed = _demangled(names)

        def find(name: str) -> tuple[cxx.Definition | None, str]:
            key = parsed.get(name)
            if key is None:
                return None, "not a function name"
            qualified, count = key
            fits = [d for d in index.get(qualified, ()) if count < 0 or cxx.arity(d.params) == count]
            if not fits:                          # `ns::f` defined as `f` inside `namespace ns {`, or the reverse
                fits = [d for k, ds in index.items() if k.endswith("::" + qualified) or qualified.endswith("::" + k)
                        for d in ds if count < 0 or cxx.arity(d.params) == count]
            if not fits:
                return None, "not defined in the file"
            if len(fits) > 1:
                return None, "two definitions fit"
            if fits[0].in_class:
                return None, "defined inside its class"
            return fits[0], ""

        held = {find(n)[0] for n in own} - {None}
        for piece in group:
            seen = set()
            for name in functions[piece.unit]:
                definition, reason = find(name)
                if definition is None:
                    piece.left[reason].append(name)
                elif definition in held:
                    piece.left["the plain unit holds it too"].append(name)
                elif definition not in seen:
                    seen.add(definition)
                    piece.moves.append((name, definition))
    return pieces


def _enclosing(blocks: list[cxx.Block], first: int, last: int) -> tuple[cxx.Block, ...]:
    """The namespace and `extern "C"` blocks around lines first..last, outermost first."""
    return tuple(b for b in blocks if b.kind in ("namespace", "extern") and b.open < first and last < b.end)


def _opening(lines: list[str], chain: tuple[cxx.Block, ...], index: int) -> str:
    block = chain[index]
    if block.kind == "extern":
        return 'extern "C" {'
    outer = next((b.name for b in reversed(chain[:index]) if b.kind == "namespace" and b.name), "")
    own = block.name[len(outer) + 2:] if outer and block.name.startswith(outer + "::") else block.name
    near = "".join(lines[max(0, block.open - 1):block.open + 1])
    inline = "inline " if own and re.search(rf"\binline\s+namespace\s+{re.escape(own)}\b", near) else ""
    return f"{inline}namespace {own} {{" if own else "namespace {"


@dataclass(eq=False)
class _Item:
    """A piece of the file after its preamble: a function definition, a type, a declaration or data."""
    start: int                                  # first line, the comment above it included
    end: int                                    # last line
    names: frozenset                            # the plain names it declares (none for a member's definition)
    kind: str                                   # function, type, declaration, data or using
    internal: bool                              # each unit may have its own copy (a type, a prototype, static)
    definition: cxx.Definition | None = None
    declaration: str = ""                       # what declares it for another unit: a prototype, `extern ...;`
    members: list = field(default_factory=list)  # a condition's items


_WORD = re.compile(r"[A-Za-z_]\w*")


def _cut(text: str) -> str:
    """A declaration's text before its initializer (`=` or `{` outside parentheses) or `;`."""
    depth = 0
    for i, char in enumerate(text):
        if char in "([<":
            depth += 1
        elif char in ")]>" and depth:
            depth -= 1
        elif char in "={;" and not depth:
            return text[:i]
    return text


def _statement(text: str, anonymous: bool) -> tuple[frozenset, str, bool, str]:
    """(names, kind, internal, declaration) of a statement at namespace scope (comments and literals blanked)."""
    t = " ".join(text.split())
    if re.match(r"using\s+namespace\b", t):
        return frozenset(), "using", True, ""
    m = re.match(r"using\s+(\w+)\s*=", t) or re.match(r"using\s+(?:typename\s+)?[\w:]*::(~?\w+)\s*;", t)
    if m:                                       # an alias, or a using-declaration of another scope's name
        return frozenset([m[1]]), "type", True, ""
    if t.startswith("typedef"):
        m = re.search(r"\(\s*\*\s*(\w+)\s*\)", t) or re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*;\s*$", t)
        return frozenset([m[1]] if m else []), "type", True, ""
    m = re.match(r"enum\b(?:\s+(?:class|struct)\b)?\s*(\w*)", t)
    if m:
        body = re.search(r"\{(.*)\}", t)
        enumerators = re.findall(r"(?:^|,)\s*(\w+)", body[1]) if body else []
        return frozenset([n for n in [m[1], *enumerators] if n]), "type", True, ""
    m = re.match(r"(?:struct|class|union)\s+(\w+)\s*;$", t)
    if m:
        return frozenset([m[1]]), "type", True, ""
    if re.match(r"template\s*[^\s<]", t):           # an explicit instantiation: emits code where it is
        m = re.search(r"([\w:]+)\s*<", t)
        name = m[1].rsplit("::", 1)[-1] if m else ""
        return frozenset([name] if name else []), "instantiation", False, f"extern {t}"
    head = _cut(t).strip()
    words = set(_WORD.findall(head))
    if head.endswith(")") or re.search(r"\)\s*(?:const|noexcept)\s*$", head):
        m = re.search(r"(~?[\w:]+)\s*\(", head)
        name = m[1] if m else ""
        return frozenset([name] if name and "::" not in name else []), "declaration", True, ""
    m = re.search(r"([\w:]+)\s*(?:\[[^\]]*\]\s*)*$", head)
    name = m[1] if m else ""
    if not name or "::" in name:                # a class's static member: its class declares it
        return frozenset(), "data", False, ""
    internal = anonymous or bool(words & {"static", "const", "constexpr"}) and "extern" not in words
    return frozenset([name]), "data", internal, "" if internal else f"extern {head};"


def _prototype(code: list[str], d: cxx.Definition) -> str:
    """A function definition's head as a declaration, `void f(int a);`, or "" when it is not plain."""
    text = "\n".join(code[d.start:d.open + 1])
    at = text.find("(", text.find(d.name.rsplit("::", 1)[-1]))
    if at < 0:
        return ""
    depth = 0
    for i in range(at, len(text)):
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        if depth == 0:
            brace = text.find("{", i)
            head = " ".join(text[:brace].split()) if brace >= 0 else ""
            return f"{head};" if head and ":" not in head[head.rfind(")"):] else ""
    return ""


def _items(lines: list[str], code: list[str], every: list[cxx.Definition], blocks: list[cxx.Block],
           first: int) -> list[_Item]:
    """The file after its preamble as items, in line order."""
    covered: set[int] = set()
    items: list[_Item] = []

    def anonymous(start: int, end: int) -> bool:
        return any(b.kind == "namespace" and not b.name for b in _enclosing(blocks, start, end))

    for d in every:
        if d.in_class or d.start < first:
            continue
        start = cxx.comment_start(lines, d.start)
        head = " ".join(code[d.start:d.line + 1])[:200]
        # each unit may define its own: a static, a template or an inline function, or one in an anonymous namespace
        internal = anonymous(d.start, d.end) or bool(re.search(r"\b(static|inline|template)\b",
                                                               head.split(d.name)[0]))
        free = "::" not in d.name
        items.append(_Item(start, d.end, frozenset([d.name] if free else []), "function", internal, d,
                           _prototype(code, d) if free and not internal else ""))
        covered |= set(range(start, d.end + 1))
    outermost = [b for b in blocks if b.kind == "class" and b.open >= first
                 and not any(o.kind == "class" and o.open < b.open and b.end <= o.end for o in blocks)]
    for b in outermost:
        head = b.open if code[b.open][:code[b.open].find("{")].strip() else b.open - 1
        start = cxx.comment_start(lines, head)
        items.append(_Item(start, b.end, frozenset([b.name.rsplit("::", 1)[-1]]), "type", True))
        covered |= set(range(start, b.end + 1))
    for b in blocks:
        if b.kind in ("namespace", "extern") and b.open >= first:
            covered |= {b.open, b.end}
            if not code[b.open][:code[b.open].find("{")].strip():
                covered.add(b.open - 1)
    statement: list[int] = []
    opened: list[int] = []
    regions: list[tuple[int, int]] = []         # (#if line, #endif line) of each condition outside definitions
    for i in range(first, len(lines)):
        if i in covered:
            continue
        directive = re.match(r"\s*#\s*(\w+)", lines[i])
        if directive:                               # outside every definition: only a condition's lines are placed
            if statement or directive[1] not in ("if", "ifdef", "ifndef", "elif", "else", "endif"):
                raise Uncarved(f"a preprocessor line after the preamble (line {i + 1})")
            if directive[1].startswith("if"):
                opened.append(i)
            elif directive[1] == "endif":
                if not opened:
                    raise Uncarved(f"an #endif with no #if (line {i + 1})")
                regions.append((opened.pop(), i))
            continue
        if not statement and not code[i].strip():
            continue
        statement.append(i)
        text = " ".join(code[j] for j in statement)
        if text.rstrip().endswith(";") and text.count("{") == text.count("}") and text.count("(") == text.count(")"):
            start = cxx.comment_start(lines, statement[0])
            names, kind, internal, declaration = _statement(text, anonymous(statement[0], i))
            items.append(_Item(start, i, names, kind, internal, declaration=declaration))
            statement = []
    if statement:
        raise Uncarved(f"a statement that does not end (line {statement[0] + 1})")
    if opened:
        raise Uncarved(f"an #if with no #endif (line {opened[0] + 1})")
    # what a condition holds goes where it goes as one, the condition's lines with it
    for top, bottom in sorted(r for r in regions if not any(o[0] < r[0] and r[1] < o[1] for o in regions)):
        inside = [item for item in items if top < item.start and item.end < bottom]
        if any(b.kind in ("namespace", "extern") and (top < b.open < bottom or top < b.end < bottom) for b in blocks):
            raise Uncarved(f"an #if around a namespace's edge (line {top + 1})")
        if not inside:
            continue
        items = [item for item in items if item not in inside]
        group = _Item(cxx.comment_start(lines, top), bottom, frozenset().union(*(i.names for i in inside)),
                      "condition", all(i.internal for i in inside))
        group.members = inside
        items.append(group)
    return sorted(items, key=lambda item: item.start)


def _alone(code: list[str], definition: cxx.Definition) -> bool:
    """Whether nothing but the definition is on its first and last lines (comments and literals blanked): no code
    before its declarator, nothing but `;` after the brace closing its body."""
    last = definition.name.rsplit("::", 1)[-1]
    at = code[definition.line].find(last)
    before = code[definition.start][:at] if definition.start == definition.line else code[definition.start]
    if at < 0 or ";" in before or "}" in before:
        return False
    tail = code[definition.end]
    if definition.open != definition.end:
        return tail.strip() in ("}", "};")
    # a body on one line: the brace closing the line's first top-level `{` ends the line
    depth, opened = 0, -1
    for i, char in enumerate(tail):
        if char == "{":
            if depth == 0:
                opened = i
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return tail[i + 1:].strip() in ("", ";") and opened >= 0
            if depth < 0:
                return False
    return False


def carve(text: str, definitions: list[cxx.Definition]) -> tuple[str, str]:
    """(the file without the definitions, a source with the file's preamble, the definitions and what they use
    from the file, in their namespace blocks); Uncarved says why when carving cannot place them cleanly.

    What the definitions use from the file after its preamble (a helper, a table, a type) moves with them when
    nothing left in the file uses it; when something does, the source gets its own copy of what each unit may have
    one of (a type, a static or const, a prototype) and a declaration of the rest (`extern` data, a function's
    prototype). A function moved out that the file still calls is declared in its place."""
    lines = text.splitlines(keepends=True)
    code = cxx.blank(text).splitlines()
    code += [""] * (len(lines) - len(code))
    every, blocks = cxx.scan(text)
    # the preamble ends at the first function defined outside a class, or at the namespace block it sits in:
    # includes, declarations and the file's own classes before it are what every piece compiles against
    functions = [d for d in every if not d.in_class]
    if not functions or not definitions:
        raise Uncarved("nothing to carve")
    head = min(functions, key=lambda d: d.start)
    first = cxx.comment_start(lines, min([head.start] + [b.open for b in _enclosing(blocks, head.start, head.end)]))
    while first > 0 and re.match(r"\s*(inline\s+)?(namespace\b|extern\b)", code[first - 1] + lines[first - 1]) \
            and "{" not in code[first - 1]:
        first -= 1
    items = _items(lines, code, every, blocks, first)
    moved = []
    for d in definitions:
        item = next((i for i in items if i.definition == d or any(m.definition == d for m in i.members)), None)
        others = [o for o in every if o != d and not (o.end < d.start or o.start > d.end)
                  and not (o.start > d.open and o.end <= d.end)]
        if item is None:
            raise Uncarved(f"{d.qualified} is in the preamble")
        if others or not _alone(code, d):
            raise Uncarved(f"{d.qualified} shares a line with other code")
        if item not in moved:
            moved.append(item)
    tokens = {id(item): set(_WORD.findall(" ".join(code[item.start:item.end + 1]))) for item in items}
    for item in items:
        if item.declaration:
            tokens[id(item), "declaration"] = set(_WORD.findall(item.declaration))
    # what the moved definitions use, and what that uses in turn
    action = {id(item): "move" for item in moved}
    need = set().union(*(tokens[id(item)] for item in moved))
    changed = True
    while changed:
        changed = False
        for item in items:
            if id(item) in action or not (item.names & need or item.kind == "using"):
                continue
            if item.kind == "using" and item.start > max(m.start for m in moved):
                continue
            declare = item.kind == "function" and not item.internal
            action[id(item)] = "declare" if declare else "move"
            need |= tokens[id(item), "declaration"] if declare else tokens[id(item)]
            changed = True
    # what the file keeps using stays there: a copy of an internal one in each unit, a declaration of the rest
    while True:
        # what the file still uses: what its items name, other than what they declare themselves (a template's
        # explicit instantiation or a prototype names its function without using it)
        left = set().union(*(tokens[id(item)] - item.names for item in items if action.get(id(item)) is None
                             or action[id(item)] in ("copy", "declare")),
                           *(tokens[id(item), "declaration"] - item.names for item in items
                             if action.get(id(item)) == "move+declare"))
        flip = [item for item in items if action.get(id(item)) == "move" and (item.names & left or item.kind == "using")]
        if not flip:
            break
        for item in flip:
            if item.internal or item.kind == "using":
                action[id(item)] = "copy"
            elif item.declaration and item not in moved:
                action[id(item)] = "declare"
            elif item in moved and item.declaration:
                action[id(item)] = "move+declare"   # the file still calls it: declared where it was
            else:                                   # data the file keeps that nothing can declare
                raise Uncarved(f"{', '.join(sorted(item.names)) or 'data'} is used by both and cannot be declared")
    piece, chain = ["".join(lines[:first]).rstrip("\n") + "\n"], ()
    for item in items:
        how = action.get(id(item))
        if how is None:
            continue
        enclosing = _enclosing(blocks, item.start, item.end)
        if enclosing != chain:
            if chain:
                piece.append("\n" + "}" * len(chain) + "\n")
            if enclosing:
                piece.append("\n" + "\n".join(_opening(lines, enclosing, i) for i in range(len(enclosing))) + "\n")
            chain = enclosing
        body = item.declaration if how == "declare" else "".join(lines[item.start:item.end + 1]).rstrip("\n")
        piece.append("\n" + body + "\n")
    if chain:
        piece.append("\n" + "}" * len(chain) + "\n")
    out: list[str] = []
    gone = {i for item in items if action.get(id(item), "").startswith("move")
            for i in range(item.start, item.end + 1)}
    starts = {item.start: item for item in items if action.get(id(item)) == "move+declare"}
    for i, line in enumerate(lines):
        if i in starts:
            out.append(starts[i].declaration + "\n")
        if i in gone:
            continue
        if not line.strip() and out and not out[-1].strip() and (i - 1 in gone or i + 1 in gone):
            continue                                # one blank line where a definition was
        out.append(line)
    return "".join(out), "".join(piece)


def write(project, target: str, pieces: list[Piece]) -> list[tuple[Piece, str]]:
    """Each piece's source written and its definitions taken out of its file; (piece, "") for each written,
    (piece, why) for each left alone."""
    root = project.root(project.target(target)["repository"])
    by_base: dict[str, list[Piece]] = collections.defaultdict(list)
    for piece in pieces:
        if piece.moves:
            by_base[piece.base].append(piece)
    done: list[tuple[Piece, str]] = []
    for base, group in by_base.items():
        text = (root / base).read_text(encoding="utf-8", errors="replace")
        for piece in group:
            # the definitions found by the plan, found again in the text as it is now (earlier pieces cut it)
            now = {(d.qualified, d.params): d for d in cxx.definitions(text)}
            wanted = [now.get((d.qualified, d.params)) for _, d in piece.moves]
            if None in wanted:
                done.append((piece, "the file changed"))
                continue
            try:
                text, source = carve(text, wanted)
            except Uncarved as why:
                done.append((piece, str(why)))
                continue
            (root / piece.source).write_text(source, encoding="utf-8")
            done.append((piece, ""))
        (root / base).write_text(text, encoding="utf-8")
    return done
