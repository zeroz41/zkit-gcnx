import support  # noqa: F401  (isolates config, cache and state)
import subprocess
import tempfile
import unittest
from pathlib import Path

from zkit import sweep

CLANG = sweep.host_clang()
FLAGS = ["--target=aarch64-none-elf", "-O2", "-fno-exceptions", "-fno-rtti", "-ffreestanding",
         "-ffunction-sections", "-c"]

SOURCE = """struct Node { Node *next; };
struct Holder { int total; int count; Node *nodes[8]; void run(int n, int v); };
void Holder::run(int n, int v) {
    for (unsigned int pairs = n >> 1; pairs != 0; pairs--) {
        total += v * 2;
    }
    count = count + v;
    bool flag = v > 3;
    if (flag) {
        total = 1;
    } else {
        total = 2;
    }
    nodes[0] = 0;
    count += 1;
    total++;
}
"""


def parse(text: str, name: str):
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "a.cpp"
        path.write_text(text, encoding="utf-8")
        command = sweep.parse_command(["cc", "--target=aarch64-none-elf", "-std=gnu++14", "-c", "x.cpp"], CLANG,
                                      path, name)
        dump = subprocess.run(command, capture_output=True, text=True, check=True)
    return sweep.body_of(sweep.definitions(dump.stdout), text, name)


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
class RewriteTests(unittest.TestCase):
    def setUp(self):
        body = parse(SOURCE, "run")
        self.assertIsNotNone(body)
        self.found = {r.what: r for r in sweep.rewrites(SOURCE, body)}

    def test_each_family_offers_its_rewrite(self):
        for what in ("v * 2 -> 2 * v", "count = count + v -> count += v", "total += v * 2 -> total = total + (v * 2)",
                     "total++ -> ++total", "if (flag) swapped", "bool flag -> unsigned char",
                     "for pairs down -> up", "flag -> flag != 0", "inline flag",
                     "hold `count`'s value in count2"):
            self.assertIn(what, self.found)

    def test_a_rewrite_still_compiles(self):
        for rewrite in self.found.values():
            text = rewrite.apply(SOURCE)
            with tempfile.TemporaryDirectory() as temp:
                (Path(temp) / "a.cpp").write_text(text, encoding="utf-8")
                result = subprocess.run([CLANG, "--target=aarch64-none-elf", "-fsyntax-only",
                                         str(Path(temp) / "a.cpp")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{rewrite.what}: {result.stderr}")

    def test_the_loop_counts_up_to_what_it_counted_down_from(self):
        text = self.found["for pairs down -> up"].apply(SOURCE)
        self.assertIn("for (unsigned int pairs = 0; pairs < (n >> 1); pairs++)", text)

    def test_only_statements_touching_nothing_of_each_others_swap(self):
        swaps = [w for w in self.found if w.startswith("swap")]
        self.assertIn("swap `nodes[0] = 0;` / `count += 1;`", swaps)
        dependent = """struct A { int a; int b; void f(int i); };
void A::f(int i) {
    --i;
    a = i;
    b = a;
}
"""
        body = parse(dependent, "f")
        self.assertEqual([r.what for r in sweep.rewrites(dependent, body) if r.what.startswith("swap")], [])


@unittest.skipUnless(CLANG, "needs a host clang")
class ScoreTests(unittest.TestCase):
    def test_an_inserted_instruction_costs_one_step(self):
        """The same function with one more instruction at its start: every later word moved, one step apart."""
        body = ["ldp w8, w9, [x0]", "add w8, w8, w9, lsl #1", "ldp w10, w11, [x0, #8]", "add w8, w8, w10",
                "madd w0, w11, w9, w8", "ret"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, words in (("a", body), ("b", ["nop", *body])):
                lines = ["\t.text", "\t.globl f", "\t.type f, %function", "f:", *(f"\t{w}" for w in words),
                         "\t.size f, .-f", ""]
                (root / f"{name}.s").write_text("\n".join(lines), encoding="utf-8")
                subprocess.run([CLANG, "--target=aarch64-none-elf", "-c", str(root / f"{name}.s"), "-o",
                                str(root / f"{name}.o")], check=True, capture_output=True)
            result = sweep.score(root / "a.o", root / "b.o", "f")
            self.assertFalse(result.exact)
            self.assertEqual((result.shape, result.words, result.size_gap), (1, 1, 4))
            self.assertTrue(sweep.score(root / "a.o", root / "a.o", "f").exact)


class ClimbTests(unittest.TestCase):
    def test_the_climb_takes_the_best_rewrite_until_identical(self):
        """A text scored by how many of its tokens differ from the goal: each round takes the best rewrite."""
        goal = "a b c d"

        def evaluate(text: str) -> sweep.Score:
            wrong = sum(x != y for x, y in zip(text.split(), goal.split()))
            return sweep.Score(wrong == 0, wrong, wrong)

        def propose(text: str) -> list[sweep.Rewrite]:
            out = []
            for at, token in enumerate(text):
                if token.isalpha() and token != "a":
                    previous = chr(ord(token) - 1)
                    out.append(sweep.Rewrite(f"{token}->{previous}", ((at, at + 1, previous),)))
            return out
        result = sweep.climb("a c d e", propose, evaluate, jobs=1, rounds=10)
        self.assertTrue(result["exact"])
        self.assertEqual(result["text"], goal)
        self.assertEqual([h["step"] for h in result["history"]][1:], ["c->b", "d->c", "e->d"])

    def test_two_rewrites_that_only_help_together_are_tried_as_a_pair(self):
        goal = "x y"

        def evaluate(text: str) -> sweep.Score:
            exact = text == goal
            return sweep.Score(exact, 0 if exact else 1, 0 if exact else 1)

        def propose(text: str) -> list[sweep.Rewrite]:
            return [sweep.Rewrite("first", ((0, 1, "x"),)), sweep.Rewrite("second", ((2, 3, "y"),))] \
                if text != goal else []
        result = sweep.climb("p q", propose, evaluate, jobs=1, rounds=3)
        self.assertTrue(result["exact"])
        self.assertEqual(result["history"][1]["step"], "first; second")

    def test_a_worse_rewrite_pairs_with_one_that_keeps_the_score(self):
        """Eight rewrites change nothing; one (S) only shows together with another (W) that alone is worse."""
        def evaluate(text: str) -> sweep.Score:
            if "S" in text and "W" in text:
                return sweep.Score(True, 0, 0)
            return sweep.Score(False, 5, 5, 0, frozenset({3})) if "W" in text else \
                sweep.Score(False, 1, 1, 0, frozenset({7}))

        def propose(text: str) -> list[sweep.Rewrite]:
            return [sweep.Rewrite(f"{c} up", ((at, at + 1, c.upper()),)) for at, c in enumerate(text) if c.islower()]
        result = sweep.climb("abcdefghsw", propose, evaluate, jobs=1, rounds=3, pairs=6)
        self.assertTrue(result["exact"])
        self.assertEqual(result["history"][1]["step"], "w up; s up")


if __name__ == "__main__":
    unittest.main()


def test_mwcc_parse_flags(tmp_path):
    from zkit.sweep import parse_command
    argv = ["build/tools/wibo", "build/compilers/GC/2.6/mwcceppc.exe", "-nodefaults", "-proc", "gekko", "-i",
            "build/GPOE8P/include", "-i", "include", "-d", "VERSION=1", "-char", "unsigned", "-lang=c++", "-c",
            "src/a.cpp", "-o", "build/a"]
    cmd = parse_command(argv, "clang++", tmp_path / "parse.cpp", "f")
    assert "--target=powerpc-eabi" in cmd and "-funsigned-char" in cmd
    assert "-Ibuild/GPOE8P/include" in cmd and "-Iinclude" in cmd and "-DVERSION=1" in cmd
    assert cmd[cmd.index("-x") + 1] == "c++" and (tmp_path / "mwcc_intrinsics.h").exists()
    assert "-proc" not in cmd and "gekko" not in cmd


def test_header_copies_come_before_the_commands_include_paths(tmp_path):
    from zkit.sweep import parse_command
    copies = [tmp_path / "copies", tmp_path / "unit"]
    clang = parse_command(["cc", "--target=aarch64-none-elf", "-Iinclude", "-c", "x.cpp"], "clang++",
                          tmp_path / "parse.cpp", "f", copies)
    assert clang.index(f"-I{copies[0]}") < clang.index(f"-I{copies[1]}") < clang.index("-Iinclude")
    mwcc = parse_command(["wibo", "mwcceppc.exe", "-i", "include", "-c", "src/a.cpp", "-o", "build/a"],
                         "clang++", tmp_path / "parse.cpp", "f", copies)
    assert mwcc.index(f"-I{copies[0]}") < mwcc.index(f"-I{copies[1]}") < mwcc.index("-Iinclude")


def test_sweep_takes_include_folders():
    from zkit.cli import build_parser
    args = build_parser().parse_args(["sweep", "0x10", "a.cpp", "--include", "one", "--include", "two"])
    assert args.include == [Path("one"), Path("two")]


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_sweep_parses_and_compiles_with_the_header_copies(tmp_path):
    """The parse finds the function only through a header copy and the unit folder's quoted include, and every
    compile is handed the same copies."""
    from types import SimpleNamespace
    from unittest import mock
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "local.h").write_text("struct Local { int v; };\n", encoding="utf-8")
    copies = tmp_path / "copies"
    copies.mkdir()
    (copies / "holder.h").write_text("struct Holder { int a; int b; void run(int n); };\n", encoding="utf-8")
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text('#include "holder.h"\n#include "local.h"\n'
                         "void Holder::run(int n) { Local l; l.v = n; a = n + b; b += l.v; }\n", encoding="utf-8")
    project = SimpleNamespace(target=lambda name: {"repository": "decomp"}, root=lambda repo: root)
    unit = {"name": "a", "target_path": "orig/a.o", "metadata": {"source_path": "src/a.cpp"}}
    row = {"address": 0x10, "name": "_ZN6Holder3runEi", "demangled": "Holder::run(int)", "unit": "a"}
    seen = []

    def compile_(project, target, unit, text, work, includes=None):
        seen.append(includes)
        return (Path(work) / "a.o" if len(seen) == 1 else None), "", ""
    with mock.patch("zkit.index.refresh"), mock.patch("zkit.index.connect"), \
            mock.patch("zkit.elf.Elf.load"), mock.patch("zkit.objects._find", return_value=object()), \
            mock.patch("zkit.index.containing", return_value=row), \
            mock.patch("zkit.bridge.resolve", return_value=[0x10]), \
            mock.patch("zkit.objects.objdiff_units", return_value={"a": unit}), \
            mock.patch("zkit.objects.label_reader"), \
            mock.patch("zkit.candidate.compile_command",
                       return_value=(["cc", "--target=aarch64-none-elf", "-std=gnu++14", "-c", "src/a.cpp"],
                                     root, "src/a.cpp")), \
            mock.patch("zkit.candidate._scratch", return_value=tmp_path), \
            mock.patch("zkit.candidate._compile", side_effect=compile_):
        result = sweep.sweep(project, "main", "0x10", candidate, out=tmp_path / "best.cpp", jobs=1, rounds=1,
                             includes=[copies])
    assert seen and all(includes == [copies] for includes in seen)
    assert result["includes"] == [str(copies)] and (tmp_path / "best.cpp").is_file()


def test_sweep_takes_the_candidates_symbol():
    from zkit.cli import build_parser
    args = build_parser().parse_args(["sweep", "0x10", "a.cpp", "--symbol", "_ZN6Holder3runEi"])
    assert args.symbol == "_ZN6Holder3runEi"


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_a_placeholder_is_swept_under_the_name_the_candidate_defines(tmp_path):
    """The original still names the function by its placeholder; the candidate defines it as a method ahead of
    the rename: the parse finds that method and every score reads the built object under its mangled name."""
    from types import SimpleNamespace
    from unittest import mock
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("struct Holder { int a; int b; void run(int n); };\n"
                         "void Holder::run(int n) { a = n + b; b += n; }\n", encoding="utf-8")
    project = SimpleNamespace(target=lambda name: {"repository": "decomp"}, root=lambda repo: root)
    unit = {"name": "a", "target_path": "orig/a.o", "metadata": {"source_path": "src/a.cpp"}}
    row = {"address": 0x10, "name": "fn_10", "demangled": "fn_10", "unit": "a"}
    scored = []

    def compile_(project, target, unit, text, work, includes=None):
        built = Path(work) / "a.o"
        built.write_bytes(b"")
        return built, "", ""

    def score_(original, built, name, labels=None, built_name=None):
        scored.append((name, built_name))
        return sweep.FAILED
    with mock.patch("zkit.index.refresh"), mock.patch("zkit.index.connect"), \
            mock.patch("zkit.index.containing", return_value=row), \
            mock.patch("zkit.bridge.resolve", return_value=[0x10]), \
            mock.patch("zkit.objects.objdiff_units", return_value={"a": unit}), \
            mock.patch("zkit.objects.label_reader"), \
            mock.patch("zkit.candidate.compile_command",
                       return_value=(["cc", "--target=aarch64-none-elf", "-std=gnu++14", "-c", "src/a.cpp"],
                                     root, "src/a.cpp")), \
            mock.patch("zkit.candidate._scratch", return_value=tmp_path), \
            mock.patch("zkit.candidate._compile", side_effect=compile_), \
            mock.patch("zkit.elf.Elf.load"), \
            mock.patch("zkit.objects._find", side_effect=lambda elf, name: name == "_ZN6Holder3runEi" or None), \
            mock.patch("zkit.sweep.score", side_effect=score_):
        result = sweep.sweep(project, "main", "0x10", candidate, out=tmp_path / "best.cpp", jobs=1, rounds=1,
                             symbol="_ZN6Holder3runEi")
    assert scored and all(pair == ("fn_10", "_ZN6Holder3runEi") for pair in scored)
    assert result["symbol"] == "_ZN6Holder3runEi"


def _refusal(tmp_path, source, compiled=True, defines=True):
    """What the sweep refuses `source` with, its compile and the built object's symbols faked."""
    from types import SimpleNamespace
    from unittest import mock
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True, exist_ok=True)
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text(source, encoding="utf-8")
    project = SimpleNamespace(target=lambda name: {"repository": "decomp"}, root=lambda repo: root)
    unit = {"name": "a", "target_path": "orig/a.o", "metadata": {"source_path": "src/a.cpp"}}
    row = {"address": 0x10, "name": "_ZN6Holder3runEi", "demangled": "Holder::run(int)", "unit": "a"}

    def compile_(project, target, unit, text, work, includes=None):
        return (Path(work) / "a.o", "", "") if compiled else (None, "", "a.cpp:2:1: error: expected ';'")
    with mock.patch("zkit.index.refresh"), mock.patch("zkit.index.connect"), \
            mock.patch("zkit.index.containing", return_value=row), \
            mock.patch("zkit.bridge.resolve", return_value=[0x10]), \
            mock.patch("zkit.objects.objdiff_units", return_value={"a": unit}), \
            mock.patch("zkit.objects.label_reader"), \
            mock.patch("zkit.candidate.compile_command",
                       return_value=(["cc", "--target=aarch64-none-elf", "-std=gnu++14", "-c", "src/a.cpp"],
                                     root, "src/a.cpp")), \
            mock.patch("zkit.candidate._scratch", return_value=tmp_path), \
            mock.patch("zkit.candidate._compile", side_effect=compile_), \
            mock.patch("zkit.elf.Elf.load"), \
            mock.patch("zkit.objects._find", return_value=object() if defines else None):
        try:
            sweep.sweep(project, "main", "0x10", candidate, out=tmp_path / "best.cpp", jobs=1, rounds=1)
        except ValueError as error:
            return str(error)
    return None


HOLDER = "struct Holder { int a; int b; void run(int n); };\n"


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_the_sweep_says_why_it_cannot_start(tmp_path):
    """A parse error, a body with nothing to rewrite, a compile error and a missing symbol are told apart."""
    assert "parse failed" in _refusal(tmp_path, HOLDER + "void Holder::run(int n) { a = n + }\n")
    assert "no rewrite applies" in _refusal(tmp_path, HOLDER + "void Holder::run(int n) {}\n")
    swept = HOLDER + "void Holder::run(int n) { a = n + b; b += n; }\n"
    assert "does not compile" in _refusal(tmp_path, swept, compiled=False)
    assert "--symbol" in _refusal(tmp_path, swept, defines=False)


VALUES_SOURCE = """struct Vec3 {
    float x, y, z;
    Vec3() {}
    Vec3(float x, float y, float z) : x(x), y(y), z(z) {}
    Vec3 operator+(const Vec3& v) const { return Vec3(x + v.x, y + v.y, z + v.z); }
    Vec3 operator*(float s) const { return Vec3(x * s, y * s, z * s); }
    Vec3& operator+=(const Vec3& v) { x += v.x; y += v.y; z += v.z; return *this; }
};
struct Quat {
    float x, y, z, w;
    static Quat inverse(const Quat& q);
    Vec3 rotate(const Vec3& v) const;
    void rotate(Vec3& out, const Vec3& v) const;
};
void place(const Vec3& v);
struct Body { Vec3 m_pos; Vec3 m_target; float m_speed; Quat m_rot; void step(const Vec3& from, float d); };
void Body::step(const Vec3& from, float d) {
    Vec3 pos = from;
    float speed = m_speed;
    Vec3 target;
    Quat::inverse(m_rot).rotate(target, m_target + pos);
    pos = m_rot.rotate(pos);
    m_pos = from * d + m_pos;
    m_pos += target;
    m_speed = speed;
    place(pos * speed);
}
"""


def _members(name):
    return {"Vec3": ("x", "y", "z")}.get(name)


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_value_rewrites_change_what_an_operand_is():
    """How a value is held (a copy, a named temporary, a re-read, an out parameter, member-wise arithmetic)
    decides whether an operand is a load or a computed value when Reassociate orders it."""
    found = {r.what: r for r in sweep.rewrites(VALUES_SOURCE, parse(VALUES_SOURCE, "step"), _members)}
    for what in ("Quat::inverse(m_rot).rotate(target, m_target + pos) in place on target (object held first)",
                 "pos = m_rot.rotate(pos) -> m_rot.rotate(pos, pos)", "m_pos -> Vec3(m_pos)",
                 "from * d -> Vec3(from.x * d, from.y * d, from.z * d)",
                 "from * d -> Vec3(d * from.x, d * from.y, d * from.z)",
                 "hold Quat::inverse(m_rot) in inverse2", "re-read from for pos (line 21)",
                 "re-read m_speed for speed (line 26)"):
        assert what in found, (what, sorted(found))
    assert any(w.startswith("m_pos += target member by member: m_pos.x += target.x;") for w in found)
    assert not any(w.startswith("re-read from for pos (line 26)") for w in found)   # pos was written by then
    in_place = found["Quat::inverse(m_rot).rotate(target, m_target + pos) in place on target (object held first)"]
    assert "Quat inverse2 = Quat::inverse(m_rot);\n    Vec3 target = m_target + pos;\n    inverse2.rotate(target, " \
        "target);" in in_place.apply(VALUES_SOURCE)
    for rewrite in found.values():
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "a.cpp").write_text(rewrite.apply(VALUES_SOURCE), encoding="utf-8")
            result = subprocess.run([CLANG, "--target=aarch64-none-elf", "-fsyntax-only", str(Path(temp) / "a.cpp")],
                                    capture_output=True, text=True)
        assert result.returncode == 0, f"{rewrite.what}: {result.stderr}"


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_a_records_members_are_read_from_its_definition(tmp_path):
    path = tmp_path / "a.cpp"
    path.write_text(VALUES_SOURCE, encoding="utf-8")

    def members(name):
        command = sweep.parse_command(["cc", "--target=aarch64-none-elf", "-c", "x.cpp"], CLANG, path, name)
        dump = subprocess.run(command, capture_output=True, text=True, check=True)
        return sweep.record_members(sweep.definitions(dump.stdout), name)
    assert members("Vec3") == ("x", "y", "z") and members("Quat") == ("x", "y", "z", "w")
    assert members("Body") is None                    # members of several types: nothing to write member-wise


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_the_body_is_the_definition_with_the_symbols_mangled_name():
    text = ("struct A { int calc(); };\nstruct B { int calc(); };\n"
            "int A::calc() { return 1; }\nint B::calc() { return 2; }\n")
    body = parse(text, "calc")
    assert text[sweep._span(body)[0]:].startswith("{ return 1; }")
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "a.cpp"
        path.write_text(text, encoding="utf-8")
        command = sweep.parse_command(["cc", "--target=aarch64-none-elf", "-c", "x.cpp"], CLANG, path, "calc")
        dump = subprocess.run(command, capture_output=True, text=True, check=True)
    body = sweep.body_of(sweep.definitions(dump.stdout), text, "calc", "_ZN1B4calcEv")
    assert text[sweep._span(body)[0]:].startswith("{ return 2; }")


HELD_SOURCE = """struct Item { int handle; int pad[3]; };
Item fetch(int i);
struct Data { bool mask; int count; };
Data *getData(int i);
bool find(int &out, int n, int key) {
    int seen = n * 2;
    // only the large ones
    if (seen > 4) {
        if (!getData(n)->mask) {
            return false;
        }
        out = seen;
        if (key != 0) {
            out = key;
            return true;
        }
    }
    return false;
}
int scan(int n, int key) {
    for (int i = 0; i < n; i++) {
        if (i != key && fetch(i).handle == key) {
            return i;
        }
        if (fetch(i + 1).handle == key) {
            return -2;
        }
    }
    return -1;
}
void mark(int i, bool m) {
    getData(i)->mask = m;
    getData(i)->count += 1;
}
"""


def _held(name):
    body = parse(HELD_SOURCE, name)
    assert body is not None
    return {r.what: r for r in sweep.rewrites(HELD_SOURCE, body)}


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_early_returns_become_one_exit_through_a_result():
    found = _held("find")
    expected = HELD_SOURCE.replace("""    // only the large ones
    if (seen > 4) {
        if (!getData(n)->mask) {
            return false;
        }
        out = seen;
        if (key != 0) {
            out = key;
            return true;
        }
    }
    return false;""", """    bool result = false;
    // only the large ones
    if (seen > 4) {
        if (getData(n)->mask) {
            out = seen;
            if (key != 0) {
                out = key;
                result = true;
            }
        }
    }
    return result;""")
    assert found["one exit through result"].apply(HELD_SOURCE) == expected
    assert not any(what.startswith("one exit") for what in _held("scan"))      # a return in a loop stays


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_condition_temporaries_and_returned_pointers_get_named_locals(tmp_path):
    scan, mark = _held("scan"), _held("mark")
    both = scan["assign all 2 condition temporaries to locals"].apply(HELD_SOURCE)
    assert "        Item item;\n        if (i != key && (item = fetch(i)).handle == key) {" in both
    assert "        Item item2;\n        if ((item2 = fetch(i + 1)).handle == key) {" in both
    assert "Data* data = getData(i);\n    data->mask = m;\n    getData(i)->count" in \
        mark["hold getData(i) in data (line 32)"].apply(HELD_SOURCE)
    assert "data->mask = m;\n    data->count += 1;" in \
        mark["hold getData(i) in data (line 32, all 2 uses)"].apply(HELD_SOURCE)
    for rewrite in [*scan.values(), *mark.values(), *_held("find").values()]:
        (tmp_path / "a.cpp").write_text(rewrite.apply(HELD_SOURCE), encoding="utf-8")
        result = subprocess.run([CLANG, "--target=aarch64-none-elf", "-fsyntax-only", str(tmp_path / "a.cpp")],
                                capture_output=True, text=True)
        assert result.returncode == 0, f"{rewrite.what}: {result.stderr}"


LOOP_SOURCE = """template <class T> struct List {
    T *m_items;
    unsigned long m_size;
    T *begin() { return m_items; }
    T *end() { return m_items + m_size; }
    unsigned long size() const { return m_size; }
    T &operator[](unsigned long i) { return m_items[i]; }
};
int use(unsigned short id);
bool release(int *p);
void drop(int *p);
struct Box {
    List<unsigned short> ids;
    int total;
    int sum();
    int first();
    void free(int *p);
};
int Box::sum() {
    unsigned long num = ids.size();
    for (unsigned long i = 0; i < num; i++) {
        total += use(ids.begin()[i]);
    }
    for (int i = 0; i < ids.size(); ++i) {
        unsigned short id = ids[i];
        total += id;
    }
    return total;
}
int Box::first() {
    for (unsigned short id : ids) {
        if (use(id)) {
            return id;
        }
    }
    return 0;
}
void Box::free(int *p) {
    if (!release(p) && p != nullptr) {
        drop(p);
    }
}
"""


def _loops(name):
    body = parse(LOOP_SOURCE, name)
    assert body is not None
    return {r.what: r for r in sweep.rewrites(LOOP_SOURCE, body)}


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_an_index_loop_over_a_container_walks_it_and_back(tmp_path):
    loops, walk = _loops("sum"), _loops("first")
    walked = loops["for i over ids -> for (unsigned short item : ids)"].apply(LOOP_SOURCE)
    assert "int Box::sum() {\n    for (unsigned short item : ids) {\n        total += use(item);\n    }" in walked
    assert "for (auto& item : ids) {\n        total += use(item);" in \
        loops["for i over ids -> for (auto& item : ids)"].apply(LOOP_SOURCE)
    declared = loops["for i over ids -> for (unsigned short id : ids)"].apply(LOOP_SOURCE)
    assert "    for (unsigned short id : ids) {\n        total += id;\n    }" in declared
    assert "for (const unsigned short& id : ids) {\n        total += id;" in \
        loops["for i over ids -> for (const unsigned short& id : ids)"].apply(LOOP_SOURCE)
    indexed = walk["for (unsigned short id : ids) -> index loop over ids[i]"].apply(LOOP_SOURCE)
    assert "    for (int i = 0; i < ids.size(); i++) {\n        unsigned short id = ids[i];\n        if (use(id))" \
        in indexed
    assert "unsigned short id = ids.begin()[i];" in \
        walk["for (unsigned short id : ids) -> index loop over ids.begin()[i]"].apply(LOOP_SOURCE)
    for rewrite in [r for r in [*loops.values(), *walk.values()] if " over " in r.what or "index loop" in r.what]:
        (tmp_path / "a.cpp").write_text(rewrite.apply(LOOP_SOURCE), encoding="utf-8")
        result = subprocess.run([CLANG, "--target=aarch64-none-elf", "-std=gnu++14", "-fsyntax-only",
                                 str(tmp_path / "a.cpp")], capture_output=True, text=True)
        assert result.returncode == 0, f"{rewrite.what}: {result.stderr}"


@unittest.skipUnless(CLANG, "needs a host clang that writes JSON ASTs")
def test_a_conditions_first_call_is_held_and_the_other_test_comes_first(tmp_path):
    found = _loops("free")
    held = "    bool flag = release(p);\n    if (!flag && p != nullptr) {"
    assert held in found["hold release(p) in flag before the condition"].apply(LOOP_SOURCE)
    last = found["hold release(p) in flag before the condition, test it last"].apply(LOOP_SOURCE)
    assert "    bool flag = release(p);\n    if (p != nullptr && !flag) {" in last
    for rewrite in [r for r in found.values() if "before the condition" in r.what]:
        (tmp_path / "a.cpp").write_text(rewrite.apply(LOOP_SOURCE), encoding="utf-8")
        result = subprocess.run([CLANG, "--target=aarch64-none-elf", "-std=gnu++14", "-fsyntax-only",
                                 str(tmp_path / "a.cpp")], capture_output=True, text=True)
        assert result.returncode == 0, f"{rewrite.what}: {result.stderr}"
