"""The decomp-permuter scratch: the C++-to-C reduction, compile.sh, settings and scoring (needs no game)."""

import support  # noqa: F401  (isolates config, cache and state)
import base64
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from zkit import permute

OBJDUMP = os.environ.get("ZKIT_OBJDUMP") or shutil.which("powerpc-eabi-objdump") or "powerpc-eabi-objdump"
AS = Path(OBJDUMP).with_name("powerpc-eabi-as") if os.sep in OBJDUMP else Path(shutil.which("powerpc-eabi-as") or "powerpc-eabi-as")
PERMUTER = Path(os.environ.get("PERMUTER_DIR") or "decomp-permuter")
HAS_AS = AS.is_file()
HAS_PERMUTER = (PERMUTER / "src" / "scorer.py").is_file()


def reduce(text, folders=()):
    return permute.reduce_to_c(text, list(folders))


class PermuteHelperTests(unittest.TestCase):

    def test_compile_argv_swaps_source_and_object_and_drops_dependency_files(self):
        argv = ["wibo", "mwcceppc.exe", "-O4,p", "-i", "include", "-MMD", "-c", "src/game/a.cpp", "-o",
                "build/src/game/a.o", "-MF", "build/a.d"]
        out = permute.compile_argv(argv, "src/game/a.cpp", Path("/repo/src/game"), Path("/repo"))
        self.assertEqual(out, ["wibo", "mwcceppc.exe", "-i", "src/game", "-O4,p", "-i", "include", "-c", "$WRAPPED",
                               "-o", "$OUTPUT"])
        self.assertEqual(permute.include_dirs(argv, Path("/repo")), [Path("/repo/include")])

    @unittest.skipUnless(shutil.which("gcc"), "requires a host C compiler")
    def test_c_unit_compile_script_compiles_plain_c(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input.c"
            source.write_text("int chosen(_Bool x) { return x; }\n")
            script = root / "compile.sh"
            script.write_text(permute.compile_script(["gcc", "-c", "$WRAPPED", "-o", "$OUTPUT"], root, False))
            subprocess.run(["bash", str(script), str(source), "-o", str(root / "out.o")], check=True,
                           capture_output=True)
            self.assertTrue((root / "out.o").is_file())

    def test_run_command_scores_stack_and_branch_targets(self):
        command = permute.run_command(Path("/p"), Path("/s"), 4)
        self.assertEqual(command[1:], ["/p/permuter.py", "--stop-on-zero", "--stack-diffs", "--no-ignore-branch-targets", "-j", "4",
                                       "/s"])

    @unittest.skipUnless(HAS_PERMUTER,
                         'needs decomp-permuter ($PERMUTER_DIR)')
    def test_search_weights_disable_padding_without_disabling_real_rewrites(self):
        settings = tomllib.loads(permute.settings('chosen', OBJDUMP))
        code = (
            'import sys\nsys.path.insert(0, '
            + repr(str(PERMUTER.resolve())) + ')\n'
            'from src.helpers import get_default_randomization_weights, merge_randomization_weights\n'
            'weights = merge_randomization_weights(get_default_randomization_weights("mwcc"), '
            + repr(settings['weight_overrides']) + ')\n'
            'assert weights["perm_pad_var_decl"] == 0\n'
            'assert weights["perm_empty_stmt"] == 0\n'
            'assert weights["perm_refer_to_var"] == 0\n'
            'assert weights["perm_temp_for_expr"] > 0\n'
            'assert weights["perm_reorder_decls"] > 0\n'
        )
        result = subprocess.run([sys.executable, '-c', code],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(HAS_AS and HAS_PERMUTER,
                         'requires local PowerPC binutils and decomp-permuter')
    def test_branch_score_distinguishes_destinations_at_different_object_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, padding, destination in [('target', 128, 'value'),
                                               ('equal', 0, 'value'),
                                               ('wrong', 0, 'end')]:
                source = root / (name + '.s')
                prefix = ('.global preceding\n.type preceding,@function\n'
                          f'preceding:\n.space {padding}\n.size preceding,.-preceding\n') if padding else ''
                source.write_text(f'.text\n{prefix}.global chosen\n.type chosen,@function\n'
                                  f'chosen:\ncmpwi 3,0\nbeq {destination}\nli 3,1\nblr\n'
                                  'value:\nli 3,2\nend:\nblr\n.size chosen,.-chosen\n')
                subprocess.run([str(AS),
                                str(source), '-o', str(root / (name + '.o'))],
                               check=True, capture_output=True)
            settings = tomllib.loads(permute.settings('chosen', OBJDUMP))
            flags = permute.run_command(PERMUTER, root)
            code = ('import sys\nsys.path.insert(0, ' + repr(str(PERMUTER.resolve())) + ')\n'
                    'from src.scorer import Scorer\n'
                    'def score(name, ignore):\n'
                    ' s = Scorer(' + repr(str(root / 'target.o')) + ', stack_differences=True, '
                    'algorithm="difflib", debug_mode=False, ign_branch_targets=ignore, objdump_command='
                    + repr(settings['objdump_command']) + ')\n'
                    ' return s.score(' + repr(str(root)) + ' + "/" + name + ".o")[0]\n'
                    'assert score("equal", False) == 0\n'
                    'assert score("wrong", True) == 0\n'
                    'assert score("wrong", ' + repr('--no-ignore-branch-targets' not in flags) + ') > 0\n')
            checked = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('g++'),
                         'requires host C and C++ compilers')
    def test_default_arguments_survive_parser_and_keep_call_values(self):
        source = '''int helper(int value = 7);
int chosen(void) { return helper() + helper(3); }
'''
        reduced = reduce(source)
        parsed = subprocess.run(['cc', '-std=c99', '-x', 'c', '-fsyntax-only', '-'],
                                input=reduced, text=True, capture_output=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        restored, ignored = [], False
        for line in reduced.splitlines():
            if line == '#pragma _permuter latedefine start':
                ignored = True
            elif line == '#pragma _permuter latedefine end':
                ignored = False
            elif line.startswith('#pragma _permuter b64literal '):
                restored.append(base64.b64decode(line.split()[-1]).decode())
            elif not ignored:
                restored.append(line)
        program = '\n'.join(restored) + '''
int helper(int value) { return value; }
int main() { return chosen() == 10 ? 0 : 1; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'check'
            built = subprocess.run(['g++', '-x', 'c++', '-', '-o', str(binary)],
                                   input=program, text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertEqual(subprocess.run([str(binary)]).returncode, 0)

    @unittest.skipUnless(HAS_AS and HAS_PERMUTER,
                         'requires local PowerPC binutils and decomp-permuter')
    def test_runner_scores_real_stack_slot_differences(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, offset in [('target', 8), ('candidate', 12)]:
                source = root / (name + '.s')
                source.write_text('.text\n.global chosen\n.type chosen,@function\n'
                                  f'chosen:\nlwz 3,{offset}(1)\nblr\n.size chosen,.-chosen\n')
                subprocess.run([str(AS),
                                str(source), '-o', str(root / (name + '.o'))],
                               check=True, capture_output=True)
            settings = tomllib.loads(permute.settings('chosen', OBJDUMP))
            flags = permute.run_command(PERMUTER, root)
            code = ('import sys\nsys.path.insert(0, ' + repr(str(PERMUTER.resolve())) + ')\n'
                    'from src.scorer import Scorer\n'
                    'def score(stack):\n'
                    ' s = Scorer(' + repr(str(root / 'target.o')) + ', stack_differences=stack, '
                    'algorithm="difflib", debug_mode=False, ign_branch_targets=True, objdump_command='
                    + repr(settings['objdump_command']) + ')\n'
                    ' return s.score(' + repr(str(root / 'candidate.o')) + ')[0]\n'
                    'assert score(False) == 0\n'
                    'assert score(' + repr('--stack-diffs' in flags) + ') > 0\n')
            subprocess.run([sys.executable, '-c', code], check=True, capture_output=True)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('g++'),
                         'requires host C and C++ compilers')
    def test_virtual_dispatch_survives_c_parser_representation(self):
        source = '''typedef int Word;
struct VBase { char pad[24]; };
struct VObj : VBase { virtual Word m0(float, int); };
VObj *receiver(void);
Word chosen(void) { return ((VObj *) receiver())->m0(2.5f, 7); }
'''
        reduced = reduce(source)
        parsed = subprocess.run(['cc', '-x', 'c', '-fsyntax-only', '-'],
                                input=reduced, text=True, capture_output=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        # Expand the exact late-literal protocol used by decomp-permuter.
        restored, ignored = [], False
        for line in reduced.splitlines():
            if line == '#pragma _permuter latedefine start':
                ignored = True
            elif line == '#pragma _permuter latedefine end':
                ignored = False
            elif line.startswith('#pragma _permuter b64literal '):
                restored.append(base64.b64decode(line.split()[-1]).decode())
            elif not ignored:
                restored.append(line)
        program = '\n'.join(restored) + '''
int calls;
VObj object;
VObj *receiver(void) { ++calls; return &object; }
Word VObj::m0(float x, int y) { return (int)(x * 2) + y; }
int main() { return chosen() == 12 && calls == 1 ? 0 : 1; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'check'
            built = subprocess.run(['g++', '-x', 'c++', '-', '-o', str(binary)],
                                   input=program, text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertEqual(subprocess.run([str(binary)]).returncode, 0)

    @unittest.skipUnless(shutil.which('g++') and shutil.which('nm'),
                         'requires a host C++ compiler and nm')
    def test_generated_compile_script_preserves_c_linkage(self):
        with tempfile.TemporaryDirectory(prefix='permuter linkage ') as tmp:
            root = Path(tmp)
            source = root / 'input.c'
            source.write_text('int callee(int);\nint chosen(int x) { return callee(x); }\n')
            script = root / 'compile.sh'
            script.write_text(permute.compile_script(['g++', '-c', '$WRAPPED', '-o', '$OUTPUT'], root, True))
            obj = root / 'output.o'
            subprocess.run(['bash', str(script), str(source), '-o', str(obj)],
                           check=True, capture_output=True)
            symbols = subprocess.check_output(['nm', str(obj)], text=True)
            self.assertRegex(symbols, r'\bT chosen\b')
            self.assertRegex(symbols, r'\bU callee\b')
            self.assertFalse(obj.with_suffix('.o.cpp').exists())

    @unittest.skipUnless(HAS_AS,
                         'requires local PowerPC binutils')
    def test_score_disassembly_excludes_other_functions_in_tu(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'input.s'
            source.write_text('.text\n.global chosen, unrelated\n'
                              '.type chosen,@function\nchosen:\nli 3,1\nblr\n'
                              '.size chosen,.-chosen\n'
                              '.type unrelated,@function\nunrelated:\nli 3,2\nblr\n'
                              '.size unrelated,.-unrelated\n')
            obj = root / 'target.o'
            subprocess.run([str(AS),
                            str(source), '-o', str(obj)], check=True,
                           capture_output=True)
            settings = tomllib.loads(permute.settings('chosen', OBJDUMP))
            output = subprocess.check_output(
                shlex.split(settings['objdump_command']) + [str(obj)], text=True)
            self.assertIn('<chosen>:', output)
            self.assertNotIn('<unrelated>:', output)

    def test_reduce_lead_to_permuter_c_inlines_types_and_strips_cpp_wrapper(self):
        text = '''#include "types.h"

extern "C" {

struct Example { s32 value; };
void consume(Example *);

s32 fn_80000000(void) {
    return 1;
}

}
'''

        reduced = reduce(text)

        self.assertIn("typedef signed long s32;", reduced)
        self.assertIn("typedef struct Example Example;", reduced)
        self.assertIn("s32 fn_80000000(void)", reduced)
        self.assertNotIn('#include "types.h"', reduced)
        self.assertNotIn('extern "C"', reduced)

    def test_reduction_preserves_plain_function_closing_brace(self):
        source = 'int chosen(void) {\n    return 1;\n}\n'
        self.assertEqual(reduce(source), source)

    @unittest.skipUnless(shutil.which('cc'), 'requires a host C compiler')
    def test_reduction_balances_multiple_and_nested_linkage_blocks(self):
        source = '''extern "C" {
int callee(int);
extern "C" { int nested(void) { return 2; } }
}
extern "C" int chosen(void) { return callee(nested()); }
extern "C" {
const char *literal(void) { return "} extern \\\"C\\\" {"; }
}
#pragma pop
'''
        reduced = reduce(source)
        result = subprocess.run(['cc', '-x', 'c', '-fsyntax-only', '-'],
                                input=reduced, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('#pragma pop', reduced)

    @staticmethod
    def _restore_late_literals(reduced):
        """Expand decomp-permuter's late-literal protocol (compiler view)."""
        restored, ignored = [], False
        for line in reduced.splitlines():
            if line == '#pragma _permuter latedefine start':
                ignored = True
            elif line == '#pragma _permuter latedefine end':
                ignored = False
            elif line.startswith('#pragma _permuter b64literal '):
                restored.append(base64.b64decode(line.split()[-1]).decode())
            elif not ignored:
                restored.append(line)
        return '\n'.join(restored)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('g++'),
                         'requires host C and C++ compilers')
    def test_class_inheritance_and_section_data_survive_c_parser(self):
        source = '''struct Pad { char pad[4]; };
struct Entry : Pad {
    virtual void v0();
    virtual int v1(int);
    char pad8[8];
    float f24;
};
class Plain {
public:
    int a;
    int b;
};
__declspec(section ".data") int table[2] = {
    3, 4 };
Entry *lookup(void);
int chosen(Plain *p) {
    Entry *e = lookup();
    e->f24 = 1.0f;
    return e->v1(p->a + table[1]);
}
'''
        reduced = reduce(source)
        parsed = subprocess.run(['cc', '-x', 'c', '-fsyntax-only', '-'],
                                input=reduced, text=True, capture_output=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        # The parser view keeps every field (the permuter's type passes need them).
        self.assertIn('struct Entry { char pad[4]; char pad8[8]; float f24; };', reduced)
        program = self._restore_late_literals(reduced).replace(
            '__declspec(section ".data") ', '') + '''
Entry entry;
Entry *lookup(void) { return &entry; }
void Entry::v0() {}
int Entry::v1(int x) { return x * 2 + (f24 == 1.0f); }
int main() { Plain p; p.a = 1; p.b = 0; return chosen(&p) == 11 ? 0 : 1; }
'''
        self.assertIn('struct Entry : Pad', program)
        self.assertIn('class Plain', program)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'check'
            built = subprocess.run(['g++', '-x', 'c++', '-', '-o', str(binary)],
                                   input=program, text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertEqual(subprocess.run([str(binary)]).returncode, 0)

    def test_project_headers_are_inlined_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'include' / 'game').mkdir(parents=True)
            (root / 'include' / 'game' / 'A.h').write_text(
                '#include "types.h"\n#include "game/B.h"\nstruct A { B b; };\n')
            (root / 'include' / 'game' / 'B.h').write_text('struct B { s32 x; };\n')
            reduced = reduce('#include "types.h"\n#include "game/A.h"\n#include "game/B.h"\n'
                             's32 f(A *a) { return a->b.x; }\n', [root / 'include'])
        self.assertEqual(reduced.count('struct B { s32 x; };'), 1)
        self.assertEqual(reduced.count('typedef signed long s32;'), 1)
        self.assertNotIn('#include', reduced)

    def test_reduction_rejects_unbalanced_linkage(self):
        with self.assertRaisesRegex(ValueError, 'unbalanced C linkage'):
            reduce('extern "C" { int f(void) { return 1; }')


if __name__ == "__main__":
    unittest.main()
