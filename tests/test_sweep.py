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


if __name__ == "__main__":
    unittest.main()
