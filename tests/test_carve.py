from zkit import cxx
import pytest

from zkit.carve import Uncarved, carve

SOURCE = '''#include "a.h"

// a file-local class every function may use
struct Local { int x; };

namespace outer {
namespace inner {

// keeps its comment
void Thing::first() {
    work(1);
}

void Thing::second(int a) {
    work(a);
}

}  // namespace inner
}  // namespace outer

extern "C" void plain() {
}
'''


def _pick(text, *names):
    return [d for d in cxx.definitions(text) if d.name in names]


def test_carve_moves_definitions_with_their_namespaces_and_comment():
    rest, piece = carve(SOURCE, _pick(SOURCE, "Thing::first"))
    assert "first" not in rest and "Thing::second" in rest and "// keeps its comment" not in rest
    assert piece.startswith('#include "a.h"\n\n// a file-local class every function may use\nstruct Local { int x; };\n')
    assert "namespace outer {\nnamespace inner {\n\n// keeps its comment\nvoid Thing::first() {" in piece
    assert piece.rstrip().endswith("}\n\n}}") or piece.rstrip().endswith("}}")
    # what is moved is defined once, in the piece; what stays is defined once, in the file
    assert [d.qualified for d in cxx.definitions(piece)] == ["outer::inner::Thing::first"]
    assert [d.qualified for d in cxx.definitions(rest)] == ["outer::inner::Thing::second", "plain"]


def test_carve_keeps_the_order_and_reopens_blocks():
    rest, piece = carve(SOURCE, _pick(SOURCE, "Thing::second", "plain"))
    assert [d.qualified for d in cxx.definitions(piece)] == ["outer::inner::Thing::second", "plain"]
    assert [d.qualified for d in cxx.definitions(rest)] == ["outer::inner::Thing::first"]
    assert piece.index("}}") < piece.index('extern "C" void plain()')


def test_carve_refuses_a_definition_that_shares_a_line():
    text = '#include "a.h"\nvoid f() {} void g() {}\n'
    with pytest.raises(Uncarved):
        carve(text, _pick(text, "f"))


def test_carve_refuses_a_file_with_no_functions():
    text = '#include "a.h"\nstruct S { void f() {} };\n'
    with pytest.raises(Uncarved):
        carve(text, [])


def test_carve_refuses_code_before_the_declarator():
    text = '#include "a.h"\nvoid g() {\n}\nint x; void f() {\n}\n'
    with pytest.raises(Uncarved):
        carve(text, _pick(text, "f"))
    rest, piece = carve(text, _pick(text, "g"))
    assert "int x; void f()" in rest and "void g()" in piece


DEPENDENT = '''#include "a.h"

void first() {
}

static int helper(int a) {
    return a + 1;
}

static const int s_table[2] = {1, 2};
int g_count = 0;
struct Pair { int a, b; };

void stays() {
    g_count = s_table[0];
}

void moves() {
    Pair p = {helper(s_table[1]), g_count};
    called();
}

void called() {
}
'''


def test_carve_takes_what_the_definitions_use_from_the_file():
    rest, piece = carve(DEPENDENT, _pick(DEPENDENT, "moves"))
    # used only by what moves: moved
    assert "static int helper" in piece and "helper" not in rest
    assert "struct Pair" in piece and "Pair" not in rest
    # used by both: an internal table copied, external data declared
    assert "static const int s_table[2] = {1, 2};" in piece and "static const int s_table[2]" in rest
    assert "extern int g_count;" in piece and "int g_count = 0;" in rest
    # a function the file defines and the moved code calls: declared
    assert "void called();" in piece and "void called() {" in rest
    assert [d.name for d in cxx.definitions(piece)] == ["helper", "moves"]
    assert [d.name for d in cxx.definitions(rest)] == ["first", "stays", "called"]


def test_carve_declares_a_moved_function_the_file_still_calls():
    rest, piece = carve(DEPENDENT, _pick(DEPENDENT, "called"))
    assert "void called() {" in piece and "void called();" in rest
    assert rest.index("void called();") > rest.index("void moves()")


def test_carve_refuses_a_file_with_preprocessor_lines_after_its_preamble():
    text = '#include "a.h"\nvoid f() {\n}\n#define X 1\nvoid g() {\n}\n'
    with pytest.raises(Uncarved):
        carve(text, _pick(text, "g"))


def test_carve_moves_preprocessor_lines_inside_a_body():
    text = '#include "a.h"\nvoid f() {\n}\nvoid g() {\n#line 40\n    h(__LINE__);\n}\n'
    rest, piece = carve(text, _pick(text, "g"))
    assert "#line 40" in piece and "#line" not in rest


def test_carve_moves_a_condition_with_what_it_holds():
    text = '#include "a.h"\nvoid f() {\n}\n\n#ifdef X\nvoid g() {\n}\n#endif\n\nvoid h() {\n}\n'
    rest, piece = carve(text, _pick(text, "g"))
    assert "#ifdef X\nvoid g() {\n}\n#endif" in piece and "#if" not in rest and "void h()" in rest


TEMPLATE = '''#include "a.h"

template <typename T>
T twice(T a) {
    return a + a;
}

template int twice<int>(int);

void stays() {
}

int moves() {
    return twice<int>(1);
}
'''


def test_carve_moves_a_template_and_its_instantiation_with_their_only_user():
    rest, piece = carve(TEMPLATE, _pick(TEMPLATE, "moves"))
    assert "T twice(T a) {" in piece and "template int twice<int>(int);" in piece
    assert "twice" not in rest


def test_carve_copies_a_template_both_use_and_declares_its_instantiation():
    text = TEMPLATE.replace("void stays() {\n}", "void stays() {\n    twice<int>(2);\n}")
    rest, piece = carve(text, _pick(text, "moves"))
    assert "T twice(T a) {" in piece and "T twice(T a) {" in rest
    assert "extern template int twice<int>(int);" in piece and "template int twice<int>(int);" in rest


def test_carve_copies_a_using_declaration_both_use():
    text = '#include "a.h"\nnamespace n {\nusing other::Thing;\nvoid f() {\n    Thing::get();\n}\nvoid g() {\n    Thing::get();\n}\n}\n'
    rest, piece = carve(text, _pick(text, "g"))
    assert "using other::Thing;" in piece and "using other::Thing;" in rest
