import support  # noqa: F401  (isolates config, cache and state)
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_delink import CLANG, LLD
from zkit import itanium, nx
from zkit.elf import Elf
from zkit.gc import Symbol
from zkit.platform import Switch
from zkit.program import Program

SOURCE = """struct Base { virtual ~Base(); virtual int get() const; virtual void put(int v) = 0; int value; };
struct Mid : Base { ~Mid(); void put(int v) override; virtual void more(); };
struct Leaf : Mid { ~Leaf(); int get() const override; };
struct Iface { virtual ~Iface(); virtual void ping(); virtual void pong(); };
struct Multi : Mid, Iface { ~Multi(); void ping() override; void more() override; int extra; };
Base::~Base() {}
int Base::get() const { return value; }
Mid::~Mid() {}
void Mid::put(int v) { value = v * 3; }
void Mid::more() { value += 7; }
Leaf::~Leaf() {}
int Leaf::get() const { return value * 2; }
Iface::~Iface() {}
void Iface::ping() {}
void Iface::pong() {}
Multi::~Multi() {}
void Multi::ping() { extra = 1; }
void Multi::more() { extra = value; }
Base *make(int k) { if (k == 0) return new Mid(); if (k == 1) return new Leaf(); return new Multi(); }
void *operator new(unsigned long size);
void operator delete(void *p) noexcept;
"""
FLAGS = ["--target=aarch64-none-elf", "-fPIC", "-O2", "-fno-exceptions", "-fno-rtti", "-std=gnu++14",
         "-ffreestanding", "-fasynchronous-unwind-tables", "-c"]


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class ItaniumClassTests(unittest.TestCase):
    """Classes read back from a module's Itanium tables, without RTTI."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.temp.name)
        (root / "a.cpp").write_text(SOURCE, encoding="utf-8")
        subprocess.run([CLANG, *FLAGS, str(root / "a.cpp"), "-o", str(root / "a.o")], check=True, capture_output=True)
        subprocess.run([LLD, "-shared", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                        str(root / "a.o"), "-o", str(root / "main.elf")], check=True, capture_output=True)
        module = nx.load(root / "main.elf")
        symbols = [Symbol(s.name, ".text" if s.kind == "func" else ".data", s.value, "function" if s.kind == "func"
                          else "object", s.size, "global") for s in Elf.load(root / "main.elf").symbols
                   if s.name and s.size and s.kind in ("func", "object") and 0 < s.section < 0xFF00]
        cls.program = Program.from_symbol_list(Switch(), module, symbols)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_bases_from_the_tables(self):
        classes = itanium.recover(self.program)
        self.assertEqual(classes["Mid"].bases, [(0, "Base")])            # Base::get inherited, put overridden
        self.assertEqual(classes["Leaf"].bases, [(0, "Mid")])            # the nearest of the ancestors that fit
        self.assertEqual([b for _, b in classes["Multi"].bases], ["Mid", "Iface"])   # Iface::pong inherited
        self.assertEqual(classes["Multi"].groups[1].offset, classes["Multi"].bases[1][0])

    def test_headers_compile_to_the_same_tables(self):
        def compile(source, obj, include):
            return subprocess.run([CLANG, "--target=aarch64-none-elf", "-fno-rtti", "-fno-exceptions", "-std=gnu++14",
                                   "-O0", f"-I{include}", "-c", str(source), "-o", str(obj)], capture_output=True,
                                  text=True)
        result = itanium.check(self.program, compile, self.root / "proof")
        self.assertEqual(result["differences"], [])
        self.assertEqual(sum(v for k, v in result["counts"].items() if k.startswith("table equal")), 5)
        header = (self.root / "proof" / "include" / "classes" / "Multi.h").read_text()
        self.assertIn("class Multi : public ::Mid, public ::Iface {", header)
        self.assertIn("virtual void ping();", header)
        self.assertNotIn("virtual int get", header)                      # inherited: not redeclared


class HeaderDebtTests(unittest.TestCase):
    def test_a_header_declares_virtuals_a_source_file_must_not(self):
        from zkit import quality
        line = "    virtual void update(fw::UpdateInfo const&);"
        keys = {f["key"] for f in quality.findings(line, quality.DEFAULT_PATTERNS)}
        self.assertIn("local_virtual", keys)                              # in a .cpp: a stand-in class
        keys = {f["key"] for f in quality.findings(line, quality.DEFAULT_PATTERNS, header=True)}
        self.assertNotIn("local_virtual", keys)                           # in its class's header: the class


if __name__ == "__main__":
    unittest.main()
