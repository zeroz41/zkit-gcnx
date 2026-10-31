import support  # noqa: F401  (isolates config, cache and state)
import tempfile
import unittest
from pathlib import Path

from test_delink import CLANG, LLD
from test_language_runs import build

# One compile of two source files (pool.cpp's code, then user.cpp's, as a unity build includes them): user.cpp's
# function inlines pool.cpp's `Pool::take`, so it cites both files' strings. other.cpp, compiled alone, calls the
# out-of-line copy.
REPORT = 'void report(const char *file, int line);\n'
POOL = """namespace lib { struct Pool { int used, size; int take(int n); int give(int n); }; }
int lib::Pool::take(int n) { if (used + n > size) report("C:/proj/src/lib/pool.cpp", 3); used += n; return used; }
int lib::Pool::give(int n) { if (n > used) report("C:/proj/src/lib/pool.cpp", 9); used -= n; return used; }
"""
USER = """namespace lib { struct User { Pool pool; int count; int grow(int n); int shrink(int n); }; }
int lib::User::grow(int n) { if (n > 99) report("C:/proj/src/lib/user.cpp", 1); count += 1; return pool.take(n) * 2; }
int lib::User::shrink(int n) { if (n < 0) report("C:/proj/src/lib/user.cpp", 5); count -= 1; return n * 3; }
"""
OTHER = """namespace lib { struct Other { Pool *pool; int fill(int n); }; }
int lib::Other::fill(int n) { if (n > 7) report("C:/proj/src/lib/other.cpp", 2); return pool->take(n) + 1; }
"""
SOURCES = {"pool.cpp": REPORT + POOL + USER, "other.cpp": REPORT + POOL.split("\n")[0] + "\n" + OTHER}


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class InlinedFileTests(unittest.TestCase):
    def test_a_function_citing_two_files_makes_them_one_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            at, owner = build(SOURCES, Path(tmp))
        take, give = at["_ZN3lib4Pool4takeEi"], at["_ZN3lib4Pool4giveEi"]
        grow, shrink = at["_ZN3lib4User4growEi"], at["_ZN3lib4User6shrinkEi"]
        fill = at["_ZN3lib5Other4fillEi"]
        self.assertEqual({owner[take], owner[give], owner[grow], owner[shrink]}, {owner[take]})
        self.assertNotEqual(owner[fill], owner[take])
        self.assertTrue(owner[fill].endswith("other.cpp"))
