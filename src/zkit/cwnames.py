"""CodeWarrior's C++ names (the cfront-style mangling GameCube and Wii games use), both directions.

`method__<n>ClassF<params>`: a member (`C` before `F` for a const method), `name__F<params>`: a free function,
`__ct`/`__dt`: constructor and destructor, `Q<k><n>A<n>B`: a nested name. Parameter codes: v i s c l x f d b w e
for void int short char long long-long float double bool wchar_t `...`, U and S for unsigned and signed, P R for
pointer and reference, C V for const and volatile, A<n>_ for an array, F<params>_<result> for a function type,
M<class> for a pointer to member, <n>Name for a class, T<i> to repeat parameter i and N<k><i> to repeat it k
times. `parse` turns a symbol into parts, `str()` gives the C++ spelling, `mangle` writes the symbol back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

BUILTIN = {"v": "void", "i": "int", "s": "short", "c": "char", "l": "long", "x": "long long", "f": "float",
           "d": "double", "b": "bool", "w": "wchar_t", "e": "..."}
SPECIAL = {"__ct": "{c}", "__dt": "~{c}"}


@dataclass(frozen=True)
class Type:
    code: str                       # the mangled spelling, kept so a name re-mangles exactly
    text: str                       # the C++ spelling

    def __str__(self) -> str:
        return self.text


@dataclass
class Name:
    method: str                     # as mangled: `run_task`, `__ct`, `__dt`, `__as`
    scope: list[str] = field(default_factory=list)   # enclosing classes, outermost first
    const: bool = False
    params: list[Type] | None = None   # None: no signature in the symbol

    @property
    def cls(self) -> str | None:
        return self.scope[-1] if self.scope else None

    @property
    def qualified(self) -> str:
        return "::".join(self.scope)

    @property
    def head(self) -> str:
        """`Class::method` without the signature."""
        method = SPECIAL.get(self.method, "{m}").format(c=self.cls or "", m=self.method)
        return f"{self.qualified}::{method}" if self.scope else method

    def __str__(self) -> str:
        head = self.head
        if self.params is None:
            return head
        args = "" if [p.code for p in self.params] == ["v"] else ", ".join(map(str, self.params))
        return f"{head}({args})" + (" const" if self.const else "")


class _Reader:
    def __init__(self, text: str):
        self.text, self.at = text, 0

    def peek(self, n: int = 1) -> str:
        return self.text[self.at:self.at + n]

    def take(self, n: int = 1) -> str:
        out = self.text[self.at:self.at + n]
        if len(out) < n:
            raise ValueError("truncated name")
        self.at += n
        return out

    def number(self) -> int:
        match = re.match(r"\d+", self.text[self.at:])
        if not match:
            raise ValueError("expected a length")
        self.at += len(match[0])
        return int(match[0])

    def done(self) -> bool:
        return self.at >= len(self.text)


def _class_name(reader: _Reader) -> list[str]:
    """`<n>Name` or `Q<k><n>A<n>B...`."""
    if reader.peek() == "Q":
        reader.take()
        count = int(reader.take())
        return [reader.take(reader.number()) for _ in range(count)]
    return [reader.take(reader.number())]


def _type(reader: _Reader, previous: list[Type]) -> list[Type]:
    """One parameter (or several, for an N repeat), returning the types it stands for."""
    start = reader.at
    code = reader.peek()
    if code == "T":                                   # the repeated parameter keeps its code: names re-mangle exactly
        reader.take()
        index = int(reader.take())
        return [Type(f"T{index}", previous[index - 1].text)]
    if code == "N":
        reader.take()
        count, index = int(reader.take()), int(reader.take())
        repeated = previous[index - 1].text
        return [Type(f"N{count}{index}", repeated)] + [Type("", repeated)] * (count - 1)
    text = _spell(_declarator(reader), "")
    return [Type(reader.text[start:reader.at], text)]


# A type is read as a template with one `{}` where a declarator goes, so pointers to arrays and functions come out
# the way C++ writes them: `float (&{})[3]`, `void (*{})(int)`.

def _spell(template: str, name: str) -> str:
    return re.sub(r"\s+", " ", template.replace("{}", name)).replace("( ", "(").replace(" )", ")").strip()


def _declarator(reader: _Reader) -> str:
    qualifiers = []
    while reader.peek() in ("C", "V", "U", "S"):
        qualifiers.append({"C": "const", "V": "volatile", "U": "unsigned", "S": "signed"}[reader.take()])
    code = reader.peek()
    if code in ("P", "R"):
        reader.take()
        inner = _declarator(reader)
        mark = "*" if code == "P" else "&"
        suffix = (" " + " ".join(q for q in qualifiers if q in ("const", "volatile"))) if qualifiers else ""
        if re.search(r"\{\}[\[(]", inner):
            return inner.replace("{}", f" ({mark}{suffix.strip()}{{}})")
        return inner.replace("{}", (mark if inner.replace("{}", "").rstrip().endswith(("*", "&")) else " " + mark)
                             + suffix + "{}")
    if code == "A":
        reader.take()
        count = reader.number()
        reader.take()                                          # _
        return _declarator(reader).replace("{}", f"{{}}[{count}]")
    if code == "M":                                            # pointer to member: M<class><type>
        reader.take()
        owner = "::".join(_class_name(reader))
        return _declarator(reader).replace("{}", f" {owner}::*{{}}")
    if code == "F":                                            # function type: F<params>_<result>
        reader.take()
        params = _params(reader, until="_")
        reader.take()
        args = ", ".join(str(p) for p in params)
        return _declarator(reader).replace("{}", f"{{}}({args})")
    if code.isdigit() or code == "Q":
        base = "::".join(_class_name(reader))
    elif code in BUILTIN:
        reader.take()
        base = BUILTIN[code]
    else:
        raise ValueError(f"unknown type code {code!r}")
    return " ".join([*qualifiers, base]) + "{}"


def _params(reader: _Reader, until: str | None = None) -> list[Type]:
    out: list[Type] = []
    while not reader.done() and (until is None or reader.peek() != until):
        out.extend(_type(reader, out))
    return out


def parse(symbol: str) -> Name | None:
    """The parts of a CodeWarrior symbol, or None for a plain C name or one this grammar does not cover."""
    split = re.match(r"^(?P<method>.+?)__(?=[0-9QFC])", symbol)
    if not split or not split["method"].strip("_") and split["method"] not in ("__ct", "__dt"):
        return None
    method = split["method"]
    if method.startswith("_") and method not in SPECIAL and not re.match(r"^__[a-z]{2}$", method):
        return None
    reader = _Reader(symbol[split.end():])
    try:
        scope = _class_name(reader) if reader.peek() and (reader.peek().isdigit() or reader.peek() == "Q") else []
        const = False
        if reader.peek() == "C":
            reader.take()
            const = True
        if reader.done():
            return Name(method, scope, const, None) if scope else None
        if reader.take() != "F":
            return None
        params = _params(reader)
    except (ValueError, IndexError):
        return None
    return Name(method, scope, const, params)


def mangle(name: Name) -> str:
    out = name.method + "__"
    if name.scope:
        out += _mangle_scope(name.scope)
    if name.const:
        out += "C"
    if name.params is not None:
        out += "F" + "".join(p.code for p in name.params)
    return out


def _mangle_scope(scope: list[str]) -> str:
    if len(scope) == 1:
        return f"{len(scope[0])}{scope[0]}"
    return f"Q{len(scope)}" + "".join(f"{len(part)}{part}" for part in scope)


def member(method: str, cls: str, like: Name | None = None) -> str:
    """A member's symbol for `cls`, with `like`'s signature (an override shares its base's)."""
    return mangle(Name(method, [cls], like.const if like else False, like.params if like else None))
