"""A decomp-permuter scratch for one GameCube function: the last step for a near-miss whose only gap is register
allocation or instruction scheduling, which hand edits do not close.

decomp-permuter (github.com/simonlindholm/decomp-permuter) brute-forces equivalent source permutations and scores
each against the original. The scratch holds what it reads: base.c (the seed, reduced to the C its parser takes),
target.o (the unit's target object), compile.sh (the unit's exact build command, so candidates compile byte for
byte as the build does), settings.toml and function.txt. Scoring disassembles only the chosen function, with branch
destinations relative to its start, because target objects hold whole units.

The permuter parses base.c as C (pycparser). C++ seeds are lowered for the parser only: project headers are
inlined, extern "C" wrappers dropped, class definitions, member calls, default arguments and section declspecs are
shown to the parser as C while the compiler receives the original text (the permuter's late-literal pragmas), and
compile.sh compiles the result as C++ inside extern "C". Seeds with other C++-only syntax need a C-shaped candidate.

    zkit permute 0x8000FF3C --seed best.cpp          # write the scratch, print the run command
    zkit permute 0x8000FF3C --seed best.cpp --run    # run it (--stop-on-zero, 180 s) and verify every zero

The seed is compiled first: an exact seed or one that differs only in relocations (data ownership) is not a
permuter job. A zero score is never taken on trust: each zero-score output is compiled again with the unit's
command, exactly as compile.sh wrapped it, and compared with the target object (`zkit try`'s comparison).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from .project import Project

TYPES_PRELUDE = (
    "typedef signed char s8;\ntypedef unsigned char u8;\n"
    "typedef signed short s16;\ntypedef unsigned short u16;\n"
    "typedef signed long s32;\ntypedef unsigned long u32;\n"
    "typedef signed long long s64;\ntypedef unsigned long long u64;\n"
    "typedef float f32;\ntypedef double f64;\n"
    "typedef int BOOL;\ntypedef unsigned long size_t;\n"
    "#ifndef NULL\n#define NULL 0\n#endif\n"
)
CXX_SUFFIXES = {".cpp", ".cc", ".cp", ".cxx", ".c++"}
DEP_FLAGS = {"-MMD", "-MD", "-MP", "-M", "-MM"}
DEP_ARGS = {"-MF", "-MT", "-MQ"}


def find_permuter(project: Project) -> Path | None:
    """The project file's `permuter`, $PERMUTER_DIR, the checkout `zkit build --download` fetched, or a
    decomp-permuter checkout beside a repository."""
    candidates = [project.config.get("permuter"), os.environ.get("PERMUTER_DIR")]
    candidates += [str(project.root(repo) / "build/tools/decomp-permuter") for repo in project.config["repositories"]]
    candidates += [str(project.root(repo).parent / "decomp-permuter") for repo in project.config["repositories"]]
    for candidate in candidates:
        if candidate and (Path(candidate).expanduser() / "permuter.py").is_file():
            return Path(candidate).expanduser().resolve()
    return None


def include_dirs(argv: list[str], workdir: Path) -> list[Path]:
    """The -i/-I folders of a compile command, resolved against its working directory."""
    found: list[Path] = []
    for index, arg in enumerate(argv):
        value = None
        if arg in ("-i", "-I", "-ir") and index + 1 < len(argv):
            value = argv[index + 1]
        elif arg.startswith("-I") and len(arg) > 2:
            value = arg[2:]
        if value:
            found.append((workdir / value).resolve())
    return found


def inline_project_includes(text: str, folders: list[Path], seen: set | None = None) -> str:
    """Inline the headers the unit's include folders hold, quoted or bracketed as CodeWarrior searches them with
    -nosyspath (the permuter preprocesses with -nostdinc and no include path). Each header is inlined once; their
    own `types.h` includes are dropped because the caller's prelude covers them."""
    seen = set() if seen is None else seen

    def replace(match):
        name = match[1]
        path = next((folder / name for folder in folders if (folder / name).is_file()), None)
        if name == "types.h" or path is None:
            return match[0]
        if name in seen:
            return ""
        seen.add(name)
        body = re.sub(r'(?m)^[ \t]*#\s*include\s+"types\.h"[ \t]*$', "", path.read_text(errors="replace"))
        return inline_project_includes(body, folders, seen)

    return re.sub(r'(?m)^[ \t]*#\s*include\s+["<]([^">]+)[">][ \t]*$', replace, text)


def reduce_to_c(text: str, folders: list[Path]) -> str:
    """A C++ or extern-"C" seed as C the permuter parses, with the compiler still seeing the original text."""
    text = inline_project_includes(text, folders)
    text = re.sub(r'#\s*include\s+"types\.h"', TYPES_PRELUDE.rstrip(), text, count=1)
    text = re.sub(r'(?m)^[ \t]*#\s*include\s+"types\.h"[ \t]*$', "", text)
    # Remove the matching linkage braces, never the last function's brace. Seeds may contain several linkage
    # blocks, a single-declaration linkage specifier, or a trailing pragma after the final block.
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    masked = tokens.sub(lambda m: " " * len(m[0]), text)
    cuts = []
    for match in re.finditer(r'\bextern\s+"C"\s*', text):
        if masked[match.start():match.start() + 6] != "extern":
            continue
        end = match.end()
        if end < len(text) and masked[end] == "{":
            depth, cursor = 1, end + 1
            while cursor < len(masked) and depth:
                depth += (masked[cursor] == "{") - (masked[cursor] == "}")
                cursor += 1
            if depth:
                raise ValueError("unbalanced C linkage block")
            cuts.extend([(match.start(), end + 1), (cursor - 1, cursor)])
        else:
            cuts.append((match.start(), end))
    for start, end in sorted(cuts, reverse=True):
        text = text[:start] + text[end:]
    text = text.rstrip() + "\n"
    # C++ makes a struct tag a type name; pycparser's C grammar needs the typedef when declarations use `Foo *`,
    # forward declarations (`struct Vtx;`) included.
    struct_names = sorted(set(re.findall(r"\b(?:struct|class)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?=[:{;*\s])", text)))
    aliases = [f"typedef struct {name} {name};" for name in struct_names
               if not re.search(rf"\btypedef\s+struct\s+{re.escape(name)}\s+{re.escape(name)}\s*;", text)]
    if aliases:
        text = "\n".join(aliases) + "\n" + text
    # pycparser has no `bool`; it parses C99 `_Bool`, which compile.sh maps back (`#define _Bool bool`).
    text = re.sub(r"\bbool\b", "_Bool", text)
    text = hide_section_declspecs(preserve_virtual_calls(preserve_default_arguments(text)))
    # The target compiler already checked layout assertions, and host C's pointer and long sizes can differ, so
    # they must not gate the parser; the permuter's preprocessor has no system include path either.
    text = re.sub(r"^\s*#include\s*<stddef.h>\s*$", "", text, flags=re.M)
    return re.sub(r"^\s*typedef char \w+_offset\[[^;]+;", "", text, flags=re.M)


def preserve_default_arguments(text: str) -> str:
    """Simple C++ default-argument declarations: the parser sees an unspecified parameter list (which admits both
    omitted and explicit arguments), the compiler the original declaration and so the original defaults."""
    pattern = re.compile(r"(?m)^([ \t]*(?:extern[ \t]+)?[\w* \t]+?)\b(\w+)\(([^()\n]*=[^()\n]*)\);[ \t]*$")

    def replace(match):
        if "virtual" in match[1].split():
            return match[0]
        literal = base64.b64encode(match[0].encode()).decode()
        return ("#pragma _permuter latedefine start\n" + match[1] + match[2] + "();\n"
                "#pragma _permuter latedefine end\n" + f"#pragma _permuter b64literal {literal}")

    return pattern.sub(replace, text)


def _late_literal(original: str, parser_text: str = "") -> str:
    """The parser sees `parser_text` only; the compiler sees `original` only."""
    literal = base64.b64encode(original.encode()).decode()
    late = ("#pragma _permuter latedefine start\n" + parser_text.rstrip() + "\n"
            "#pragma _permuter latedefine end\n") if parser_text.strip() else ""
    return "\n" + late + f"#pragma _permuter b64literal {literal}\n"


_METHOD_DECL = re.compile(r"^\s*(?:virtual\s+)?([A-Za-z_][\w\s*]*?)\s*\b(\w+)\s*\(([^()]*)\)\s*(?:const\s*)?;\s*$")


def preserve_virtual_calls(text: str) -> str:
    """C++ class definitions and member calls shown to the C parser without changing the ABI.

    A struct with a base class, `virtual` or member functions is a C syntax error, and the permuter's type passes
    need every accessed field. Each such definition becomes a parser-only flattened C struct (base fields first)
    while the compiler receives the original text. A member call `((Cls *)x)->m(...)` or `p->m(...)` on a
    `Cls *p` becomes a typed macro call for the parser that expands to the original dispatch, so no helper function
    is emitted or inlined. Definitions with nested braces or complex declarators stay untouched."""
    fields, methods, plain = {}, {}, {}
    rewrites = []
    for match in re.finditer(r"\b(struct|class)\s+(\w+)\s*(?::\s*(?:public\s+)?(\w+)\s*)?\{([^{}]*)\}\s*;", text):
        keyword, name, base, body = match[1], match[2], match[3], match[4]
        body = re.sub(r"\b(?:public|private|protected)\s*:", "", body)
        own_fields, own_methods, ok = [], {}, True
        for stmt in re.findall(r"[^;]*;", re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)):
            if "(" not in stmt:
                own_fields.append(stmt.strip())
                continue
            decl = _METHOD_DECL.match(stmt)
            if not decl or decl[2] == name or "~" in stmt or "operator" in stmt:
                ok = False
                break
            own_methods[decl[2]] = (decl[1].strip(), decl[3].strip())
        if not ok or (base and base not in fields):
            continue
        fields[name] = (fields[base] if base else []) + own_fields
        methods[name] = dict(methods.get(base, {}), **own_methods)
        if base or own_methods or keyword == "class":
            rewrites.append(match)
        else:
            plain[name] = True
    if not rewrites:
        return text
    classes = {m[2] for m in rewrites}
    callable_ = {cls: methods[cls] for cls in classes if methods[cls]}
    changes, macros, prototypes = [], {}, {}

    def call_args(start):
        depth, cursor = 1, start
        while cursor < len(text) and depth:
            depth += (text[cursor] == "(") - (text[cursor] == ")")
            cursor += 1
        return (cursor, text[start:cursor - 1].strip()) if not depth else (None, None)

    def add_call(cls, method, receiver, start, args_start):
        cursor, args = call_args(args_start)
        if cursor is None:
            return
        ret, params = callable_[cls][method]
        params = [] if params in ("", "void") else [p.strip() for p in params.split(",")]
        if any(not re.fullmatch(r"[\w\s*]+", p) for p in params):
            return
        macro = f"ZKIT_VCALL_{cls}_{method}"
        names = [f"_arg{i}" for i in range(len(params))]
        definition = (f"#define {macro}(_self" + "".join(", " + n for n in names)
                      + f") ((({cls} *)(_self))->{method}(" + ", ".join("(" + n + ")" for n in names) + "))\n")
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", cursor)
        if line_end < 0:
            line_end = len(text)
        line = text[line_start:line_end]
        if line.lstrip().startswith("#"):
            # Re-reducing emitted C++ sees our own macro body: rebuild its parser declaration and macro once;
            # rewriting its inner member call in place would make a self-recursive #define.
            if line.strip() != definition.strip():
                return
            changes.append((line_start, line_end, ""))
        else:
            changes.append((start, cursor, macro + "(" + receiver + (", " + args if args else "") + ")"))
        macros[macro] = definition
        prototypes[macro] = f"{ret} {macro}(void *" + "".join(", " + p for p in params) + ");"

    # ((Cls *) expr)->method(args)
    for match in re.finditer(r"\(\(\s*(\w+)\s*\*\s*\)\s*", text):
        cls = match[1]
        if cls not in callable_:
            continue
        depth, end = 1, match.end()
        while end < len(text) and depth:
            depth += (text[end] == "(") - (text[end] == ")")
            end += 1
        tail = re.match(r"\s*->\s*(\w+)\s*\(", text[end:])
        if depth or not tail or tail[1] not in callable_[cls]:
            continue
        add_call(cls, tail[1], text[match.end():end - 1].strip(), match.start(), end + tail.end())
    # var->method(args) where `Cls *var` is declared (parameter or local)
    typed: dict[str, set] = {}
    for cls in callable_:
        for decl in re.finditer(rf"\b{re.escape(cls)}\s*\*\s*(\w+)\s*[=;,)]", text):
            typed.setdefault(decl[1], set()).add(cls)
    for var, owners in typed.items():
        if len(owners) != 1:
            continue
        cls = next(iter(owners))
        for call in re.finditer(rf"(?<![\w.>]){re.escape(var)}\s*->\s*(\w+)\s*\(", text):
            if call[1] in callable_[cls]:
                add_call(cls, call[1], var, call.start(), call.end())
    # Overlapping receiver/call expressions need a more complete parser.
    changes.sort()
    if any(a[1] > b[0] for a, b in zip(changes, changes[1:])):
        return text
    for match in rewrites:
        flat = fields[match[2]] or ["char _zkit_empty;"]
        changes.append((match.start(), match.end(),
                        _late_literal(match[0], f"struct {match[2]} {{ " + " ".join(flat) + " };")))
    for start, end, replacement in sorted(changes, reverse=True):
        text = text[:start] + replacement + text[end:]
    if macros:
        literal = base64.b64encode("".join(macros.values()).encode()).decode()
        prefix = ("#pragma _permuter latedefine start\n" + "\n".join(prototypes.values())
                  + "\n#pragma _permuter latedefine end\n" + f"#pragma _permuter b64literal {literal}\n")
        definition = re.search(r"(?m)^[A-Za-z_][\w* \t]*?\b\w+\s*\([^;{}]*\)\s*\{", text)
        if definition:
            text = text[:definition.start()] + prefix + text[definition.start():]
    return text


def hide_section_declspecs(text: str) -> str:
    """`__declspec(section ".x") T name... ;` is CodeWarrior syntax: the parser gets the plain declaration
    (initializer included), the compiler the original text."""
    out, pos = [], 0
    for match in re.finditer(r'(?m)^[ \t]*(?:[\w*]+[ \t]+)*?(__declspec\s*\(\s*section\s+"[^"]*"\s*\)\s*)', text):
        if match.start() < pos:
            continue
        depth, cursor = 0, match.end()
        while cursor < len(text):
            ch = text[cursor]
            depth += (ch in "{(") - (ch in "})")
            cursor += 1
            if ch == ";" and depth == 0:
                break
        else:
            continue
        original = text[match.start():cursor]
        out.append(text[pos:match.start()])
        out.append(_late_literal(original, original.replace(match[1], "", 1)).strip("\n"))
        pos = cursor
    out.append(text[pos:])
    return "".join(out)


def compile_argv(argv: list[str], source_arg: str, source_dir: Path, workdir: Path) -> list[str]:
    """The unit's command with the permuter's input and output in place of its source and object, and the unit's
    own folder searched first so its quoted includes resolve as in the tree."""
    from .candidate import _rel
    out: list[str] = []
    skip = replaced = False
    for index, arg in enumerate(argv):
        if skip:
            skip = False
            continue
        if arg in DEP_FLAGS:
            continue
        if arg in DEP_ARGS:
            skip = True
            continue
        if arg == "-o" and index + 1 < len(argv):
            out += ["-o", "$OUTPUT"]
            skip = True
            continue
        if arg.startswith("-o") and len(arg) > 2:
            out += ["-o", "$OUTPUT"]
            continue
        if arg == source_arg or Path(arg).as_posix() == Path(source_arg).as_posix():
            out.append("$WRAPPED")
            replaced = True
            continue
        out.append(arg)
    if not replaced:
        raise ValueError("Could not find the unit's source in its compile command")
    if "-c" not in out:
        out.insert(out.index("$WRAPPED"), "-c")
    if "-o" not in out:
        out += ["-o", "$OUTPUT"]
    first_flag = next((i for i, a in enumerate(out) if a.startswith("-")), len(out))
    return out[:first_flag] + ["-i", _rel(source_dir, workdir)] + out[first_flag:]


def compile_script(argv: list[str], workdir: Path, cxx: bool) -> str:
    """compile.sh: $1 is the permuter's C, $3 the object to write. A C++ unit compiles it as C++ inside extern "C"
    (with `_Bool` mapped back to `bool`), keeping the C linkage the reduced seed was parsed with."""
    suffix = ".cpp" if cxx else ".c"
    command = " ".join('"$WRAPPED"' if a == "$WRAPPED" else '"$OUTPUT"' if a == "$OUTPUT" else shlex.quote(a)
                       for a in argv)
    wrap = ("printf '#define _Bool bool\\nextern \"C\" {\\n' > \"$WRAPPED\"\n"
            'cat "$INPUT" >> "$WRAPPED"\n'
            "printf '\\n}\\n' >> \"$WRAPPED\"\n") if cxx else 'cp "$INPUT" "$WRAPPED"\n'
    return ("#!/usr/bin/env bash\nset -e\n"
            'INPUT="$(realpath "$1")"\n'
            'OUTPUT="$(realpath "$3")"\n'
            f'WRAPPED="${{OUTPUT}}{suffix}"\n'
            "trap 'rm -f \"$WRAPPED\"' EXIT\n"
            + wrap +
            f"cd {shlex.quote(str(workdir))}\n"
            f"{command}\n")


def settings(name: str, objdump: str) -> str:
    """settings.toml. Target objects hold whole units, so only the chosen function is scored. The weights turn off
    padding variables, empty statements and bare variable references: they can hide a missing type or expression
    without giving source worth banking."""
    command = shlex.join([sys.executable, "-m", "zkit.permute", objdump, name])
    return (f"func_name = {json.dumps(name)}\n"
            'compiler_type = "mwcc"\n'
            f"objdump_command = {json.dumps(command)}\n"
            "\n[weight_overrides]\n"
            "perm_pad_var_decl = 0\n"
            "perm_empty_stmt = 0\n"
            "perm_refer_to_var = 0\n")


def run_command(permuter: Path, scratch_dir: Path, jobs: int | None = None) -> list[str]:
    """Stack slots and branch destinations count toward the score; it stops at the first zero."""
    return [sys.executable, str(permuter / "permuter.py"), "--stop-on-zero", "--stack-diffs",
            "--no-ignore-branch-targets", *(["-j", str(jobs)] if jobs else []), str(scratch_dir)]


def default_jobs() -> int:
    return min(16, max(1, (os.cpu_count() or 4) - 2))


def wrapped(source: str, cxx: bool) -> str:
    """A permuter output as the candidate compile.sh compiled."""
    return '#define _Bool bool\nextern "C" {\n' + source + "\n}\n" if cxx else source


def scratch(project: Project, target: str, query: str, seed: Path | None = None, out: Path | None = None) -> dict:
    """Write the permuter scratch for one function; returns where everything went and how to run it."""
    from . import bridge, objects
    from .candidate import compile_command
    from .index import address_text, connect, containing, refresh
    from .inspect_dol import _objdump
    from .platform import for_target
    config = project.target(target)
    if for_target(config).name != "gamecube":
        raise ValueError("zkit permute is for GameCube targets (CodeWarrior)")
    objdump = _objdump(project)
    if objdump is None:
        raise ValueError("No PowerPC objdump (powerpc-eabi-objdump): `zkit build --download` fetches binutils, or "
                         "set ZKIT_OBJDUMP")
    refresh(project)
    db = connect(project)
    found = bridge.resolve(project, query, target, limit=2)
    if len(found) != 1:
        raise ValueError(f"{query} names {'no' if not found else 'more than one'} function; use its address")
    row = containing(db, target, found[0])
    if row is None:
        raise ValueError(f"{query} is not inside a known function")
    unit = objects.objdiff_units(project, target).get(row["unit"] or "")
    if unit is None or not (unit.get("metadata") or {}).get("source_path"):
        raise ValueError(f"{address_text(row['address'])} has no unit with a source file yet ({row['unit']}): give "
                         "it its owning unit first")
    root = project.root(config["repository"])
    target_o = root / unit["target_path"]
    if not target_o.is_file():
        raise ValueError(f"Target object missing: {target_o} (build the project first)")
    argv, workdir, source_arg = compile_command(project, target, unit)
    source = root / unit["metadata"]["source_path"]
    seed_path = seed.resolve() if seed else source
    folders = [source.parent.resolve()] + include_dirs(argv, workdir)
    name = row["name"]
    from .candidate import compare
    seed_text = seed_path.read_text(errors="replace")
    checked = compare(project, target, unit, name, seed_text)
    if not checked.get("compiled"):
        raise ValueError(f"The seed does not compile with the unit's command:\n{checked.get('errors', '')}")
    if checked.get("exact"):
        raise ValueError(f"{name} is already exact with this seed: nothing to permute (bank it)")
    if checked.get("reloc_only"):
        raise ValueError(f"{name} differs from the original only in relocations: that is data ownership "
                         "(`zkit compiled` names the symbols), not a permuter job")
    folder = (out or root / "build" / "permuter" / re.sub(r"[^\w.-]", "_", name)).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "base.c").write_text(reduce_to_c(seed_text, folders), encoding="utf-8")
    (folder / "target.o").write_bytes(target_o.read_bytes())
    (folder / "function.txt").write_text(name + "\n", encoding="utf-8")
    script = folder / "compile.sh"
    script.write_text(compile_script(compile_argv(argv, source_arg, source.parent, workdir), workdir,
                                     source.suffix.lower() in CXX_SUFFIXES), encoding="utf-8")
    script.chmod(0o755)
    (folder / "settings.toml").write_text(settings(name, objdump), encoding="utf-8")
    permuter = find_permuter(project)
    command = run_command(permuter or Path("decomp-permuter"), folder)
    return {"function": name, "address": address_text(row["address"]), "unit": row["unit"],
            "seed": str(seed_path), "seed_differences": checked.get("differences"), "target": str(target_o),
            "scratch": str(folder), "cxx": source.suffix.lower() in CXX_SUFFIXES,
            "permuter": str(permuter) if permuter else None, "run": shlex.join(command)}


def run(project: Project, target: str, data: dict, jobs: int | None = None, seconds: int = 180) -> dict:
    """Run the permuter on a written scratch for at most `seconds`, then verify every zero-score output."""
    import shutil
    import signal
    import time
    from . import objects
    from .candidate import compare
    permuter = find_permuter(project)
    if permuter is None:
        raise ValueError("decomp-permuter not found: `zkit build --download` fetches it (or clone it beside the decomp, "
                         "set $PERMUTER_DIR, or set `permuter` in the project file)")
    folder = Path(data["scratch"])
    for old in folder.glob("output-*"):
        shutil.rmtree(old)
    command = run_command(permuter, folder, jobs or default_jobs())
    started = time.monotonic()
    with (folder / "run.log").open("w") as log:
        process = subprocess.Popen(command, cwd=project.root(project.target(target)["repository"]), stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=seconds)
            timed_out = False
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    text = (folder / "run.log").read_text(errors="replace").replace("\r", "\n")
    if code and not list(folder.glob("output-*")):
        lines = [line for line in text.splitlines() if line.strip() and not line.startswith("  ")]
        raise ValueError(f"The permuter stopped (exit {code}) before scoring anything; {folder / 'run.log'} ends:\n"
                         + "\n".join(lines[-6:]))
    unit = objects.objdiff_units(project, target)[data["unit"]]
    suffix = ".cpp" if data["cxx"] else ".c"
    verified = []
    for output in sorted(folder.glob("output-0-*/source.c")):
        candidate = output.with_name("candidate" + suffix)
        candidate.write_text(wrapped(output.read_text(errors="replace"), data["cxx"]), encoding="utf-8")
        checked = compare(project, target, unit, data["function"], candidate.read_text(encoding="utf-8"))
        state = ("exact" if checked.get("exact") else "relocations only" if checked.get("reloc_only")
                 else "compile error" if not checked.get("compiled") else f"{checked.get('differences')} differences")
        verified.append({"candidate": str(candidate), "state": state})
    base = re.search(r"base score = (\d+)", text)
    better = [int(a) for a in re.findall(r"score! \((\d+) vs \d+\)", text)]
    base_score = int(base[1]) if base else None
    return dict(data, seconds=round(time.monotonic() - started), timed_out=timed_out, base_score=base_score,
                best_score=min(better + ([base_score] if base_score is not None else [])) if base or better else None,
                verified=verified, log=str(folder / "run.log"))


def normalize(output: str, name: str) -> str:
    """Branch destinations relative to the function: a candidate object often starts the function at zero, the
    target object at its place in the unit. Equal branches score equally at either offset; branches to different
    instructions never disappear from the score."""
    header = re.search(r"^([0-9a-fA-F]+) <" + re.escape(name) + r">:$", output, re.M)
    if not header:
        return output
    base = int(header[1], 16)
    instruction = re.compile(r"^(\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+){4}b[\w+.-]*\s+)([^\n]*)$", re.M)

    def branch(match):
        operand = re.sub(r"\b([0-9a-fA-F]+)(?=\s+<)", lambda m: format(int(m[1], 16) - base, "x"), match[2])
        return match[1] + operand

    return instruction.sub(branch, output)


def main(argv: list[str]) -> int:
    """The permuter's objdump_command: `python -m zkit.permute OBJDUMP NAME OBJECT`."""
    objdump, name, obj = argv
    result = subprocess.run([objdump, "-dr", "-EB", "-mpowerpc", "-M", "broadway", "--disassemble=" + name, obj],
                            capture_output=True, text=True)
    sys.stdout.write(normalize(result.stdout, name))
    sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
