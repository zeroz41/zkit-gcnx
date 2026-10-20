"""C/C++ function definitions and the blocks around them, found by brace matching, for the port checks (any
indentation, any line layout).

Comments, string and character literals and preprocessor lines are blanked first, so braces and parentheses in
them do not count. A `{` at file, namespace, class or `extern "C"` scope opens a function body when the text since
the previous statement is a declarator: a name and its parameter list, which may span lines, then qualifiers or a
constructor's initializer list. Namespaces, classes, structs, unions and `extern "C"` blocks are entered; enums,
initializers and lambdas bound to a variable are skipped. This reads ordinary source; it is not a compiler:
macros are not expanded, so a function-like macro followed by a brace reads as a function named after the macro.
"""

from __future__ import annotations

import bisect
import dataclasses
import re
from dataclasses import dataclass

_BLANK = re.compile(r'R"(?P<d>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=d)"|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|'
                    r'//[^\n]*|/\*.*?\*/|^[ \t]*#(?:[^\n]*\\\n)*[^\n]*', re.S | re.M)
_STRUCTURE = re.compile(r"[{};]")
_BRACES = re.compile(r"[{}]")
_ACCESS = re.compile(r"^\s*(?:(?:public|private|protected)\s*:(?!:)\s*)+")
_TEMPLATE = re.compile(r"\btemplate\s*<")
_OPERATOR = re.compile(r"\boperator\s*(?:\(\s*\)|\[\s*\]|[^\s(]+)")
_NOT_A_NAME = {"decltype", "noexcept", "__attribute__", "alignas", "__declspec", "throw", "requires", "sizeof",
               "if", "for", "while", "switch", "return", "catch", "void", "int", "char", "bool", "float", "double",
               "auto", "const", "unsigned", "signed", "long", "short"}
_CLASS_HEAD = re.compile(r"\b(?:class|struct|union)\b(?:\s+(?:\[\[[^\]]*\]\]\s*|alignas\s*\([^)]*\)\s*)*"
                         r"(?P<name>[A-Za-z_][\w:]*))?\s*(?:final\s*)?(?::(?!:)[^{;]*)?$")
_COMMENTS = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)
_NAME_BEFORE = re.compile(r"((?:[A-Za-z_]\w*\s*(?:<[^<>(){};]*>)?\s*::\s*)*~?[A-Za-z_]\w*)\s*$")


@dataclass(frozen=True)
class Definition:
    name: str        # as spelled in the declarator: helper, Class::method, operator==
    scope: str       # enclosing namespaces and classes joined by :: ("" at file scope)
    in_class: bool   # defined inside a class body (an inline member)
    start: int       # 0-based line where the declarator starts (return type, template line)
    line: int        # 0-based line holding the name
    open: int        # 0-based line of the body's opening brace
    end: int         # 0-based line of the body's closing brace
    params: str      # parameter list text, whitespace collapsed
    body: str        # text between the braces without comments, whitespace collapsed

    @property
    def qualified(self) -> str:
        """The name it defines: `void Flag::build() {` inside `namespace gf {` defines gf::Flag::build."""
        return f"{self.scope}::{self.name}" if self.scope else self.name


@dataclass(frozen=True)
class Block:
    kind: str        # namespace, class or extern
    name: str        # enclosing scopes and its own name joined by :: ("" for an anonymous or extern block)
    open: int        # 0-based line of the opening brace
    end: int         # 0-based line of the closing brace (the last line when it is not closed)


def blank(text: str) -> str:
    """text with comments, literals and preprocessor lines replaced by spaces; offsets and newlines are kept."""
    return _BLANK.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), text)


def _strip_angles(text: str, at: int) -> int:
    """Index past the `<...>` that opens at `at` (balanced), or `at` + 1."""
    depth = 0
    for index in range(at, len(text)):
        if text[index] == "<":
            depth += 1
        elif text[index] == ">":
            depth -= 1
            if depth == 0:
                return index + 1
        elif text[index] in "{};":
            break
    return at + 1


def _clean_head(head: str) -> str:
    """The declarator text with template headers and operator names made inert (same length)."""
    out = head
    for match in _TEMPLATE.finditer(head):
        stop = _strip_angles(head, match.end() - 1)
        out = out[:match.start()] + " " * (stop - match.start()) + out[stop:]
    return _OPERATOR.sub(lambda m: "operator" + "_" * (len(m[0]) - 8), out)


def _groups(head: str) -> list[tuple[int, int]]:
    """(open, close) of every top-level parenthesis group."""
    out, depth, start = [], 0, 0
    for index, char in enumerate(head):
        if char == "(":
            if depth == 0:
                start = index
            depth += 1
        elif char == ")" and depth:
            depth -= 1
            if depth == 0:
                out.append((start, index))
    return out


def _declarator(head: str) -> tuple[int, int, int] | None:
    """(name start, params open, params close) when head declares a function, else None."""
    clean = _clean_head(head)
    groups = _groups(clean)
    if not groups:
        return None
    # A constructor's initializer list starts at a single ':' after the parameter list.
    colon = next((m.start() for m in re.finditer(r"(?<!:):(?!:)", clean) if m.start() > groups[0][1]), None)
    candidates = []
    for open_, close in groups:
        if colon is not None and open_ > colon:
            break
        found = _NAME_BEFORE.search(clean[:open_])
        if found and found[1].split("::")[-1].strip().lstrip("~") not in _NOT_A_NAME:
            candidates.append((found.start(1), open_, close))
    if not candidates:
        return None
    name, open_, close = candidates[-1]
    depth = 0
    for char in clean[:name]:  # '=' outside angle brackets before the name: an initializer, not a function
        depth += char == "<"
        depth -= char == ">" and depth > 0
        if char == "=" and depth == 0:
            return None
    after, depth = clean[close + 1:], 0
    for index, char in enumerate(after):  # `= default`/`= 0` end in ';'; an '=' here is an initializer
        depth += char == "("
        depth -= char == ")" and depth > 0
        if char == "=" and depth == 0 and after[index - 1:index] not in ("=", "<", ">", "!") \
                and after[index + 1:index + 2] != "=":
            return None
    return name, open_, close


def _matching(code: str, at: int) -> int:
    """Offset of the brace closing the one at `at` (or the end of the text)."""
    depth = 0
    for match in _BRACES.finditer(code, at):
        depth += 1 if match[0] == "{" else -1
        if depth == 0:
            return match.start()
    return len(code)


def definitions(text: str) -> list[Definition]:
    """Every function definition in a C/C++ source text, outermost first, in file order."""
    return scan(text)[0]


def scan(text: str) -> tuple[list[Definition], list[Block]]:
    """definitions(), and every namespace, class and `extern "C"` block, outermost first, in file order."""
    code = blank(text)
    starts = [0] + [m.end() for m in re.finditer(r"\n", code)]
    line = lambda offset: bisect.bisect_right(starts, offset) - 1
    out: list[Definition] = []
    entered: list[Block] = []
    scopes: list[tuple[str, str, int]] = []   # (kind, name, index in entered) of the blocks open here

    def enter(kind: str, name: str, at: int) -> None:
        scopes.append((kind, name, len(entered)))
        entered.append(Block(kind, "::".join(n for _, n, _ in scopes if n) if name else "", line(at), line(len(code))))

    def leave(at: int) -> None:
        index = scopes.pop()[2]
        entered[index] = dataclasses.replace(entered[index], end=line(at))

    head_start, position = 0, 0
    while True:
        match = _STRUCTURE.search(code, position)
        if match is None:
            break
        at, char = match.start(), match[0]
        if char == ";":
            head_start = position = at + 1
            continue
        if char == "}":
            if scopes:
                leave(at)
            head_start = position = at + 1
            continue
        raw = code[head_start:at]
        access = _ACCESS.match(raw)
        offset = head_start + (access.end() if access else 0)
        head = code[offset:at]
        clean = _clean_head(head)
        if re.search(r"\benum\b", clean):
            position = head_start = _matching(code, at) + 1
            continue
        klass = _CLASS_HEAD.search(clean)
        if klass and "=" not in clean[:klass.start()]:
            enter("class", (klass["name"] or "").rsplit("::", 1)[-1], at)
            head_start = position = at + 1
            continue
        found = _declarator(head) if "(" in head else None
        if found and re.search(r"(?<!:):(?!:)", clean[found[2]:]) and re.search(r"[\w>]\s*$", head):
            position = _matching(code, at) + 1   # `member{value}` inside a constructor's initializer list
            continue
        if found:
            name_at, open_, close = found
            end = _matching(code, at)
            first = offset + len(head) - len(head.lstrip())
            scope = "::".join(name for _, name, _ in scopes if name)
            out.append(Definition(
                name=re.sub(r"\s+", "", head[name_at:open_]), scope=scope,
                in_class=bool(scopes) and scopes[-1][0] == "class", start=line(first), line=line(offset + name_at),
                open=line(at), end=line(end), params=" ".join(head[open_ + 1:close].split()),
                body=" ".join(_COMMENTS.sub(lambda m: m[0] if m[0][0] in "\"'" else " ", text[at + 1:end]).split())))
            head_start = position = end + 1
            continue
        if "(" not in clean and re.search(r"\bnamespace\b", clean):
            name = re.search(r"\bnamespace\s+([\w:]*)", clean)
            enter("namespace", name[1] if name else "", at)
        elif re.fullmatch(r"\s*extern\s*", clean):  # extern "C" (the string is blanked)
            enter("extern", "", at)
        else:
            position = _matching(code, at) + 1   # enum body, initializer, lambda or a stray block: not a scope
            head_start = position
            continue
        head_start = position = at + 1
    return out, entered


def arity(params: str) -> int:
    """How many parameters a parameter list's text declares (`void` and an empty list declare none)."""
    if params.strip() in ("", "void"):
        return 0
    depth, count = 0, 1
    for char in params:
        if char in "(<[":
            depth += 1
        elif char in ")>]" and depth:
            depth -= 1
        elif char == "," and not depth:
            count += 1
    return count


def comment_start(lines: list[str], start: int) -> int:
    """First line of the comment block (and template/attribute lines) directly above line `start`."""
    while start > 0 and lines[start - 1].strip().startswith(("//", "/*", "*", "template", "[[")):
        start -= 1
    return start
