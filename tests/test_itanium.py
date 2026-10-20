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


def adrp(rd, pc, address):
    pages = (address >> 12) - (pc >> 12)
    return 0x90000000 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5 | rd
def ldr(rt, rn, offset): return 0xF9400000 | offset // 8 << 10 | rn << 5 | rt
def add(rd, rn, imm): return 0x91000000 | imm << 10 | rn << 5 | rd
def str_(rt, rn, offset): return 0xF9000000 | offset // 8 << 10 | rn << 5 | rt
def str_pre(rt, rn, offset): return 0xF8000C00 | (offset & 0x1FF) << 12 | rn << 5 | rt
def stp(rt, rt2, rn, offset): return 0xA9000000 | (offset // 8 & 0x7F) << 15 | rt2 << 10 | rn << 5 | rt
def mov(rd, rm): return 0xAA0003E0 | rm << 16 | rd
def branch(pc, target, link): return (0x94000000 if link else 0x14000000) | ((target - pc) >> 2 & 0x3FFFFFF)


class ObjectStoreTests(unittest.TestCase):
    """The address points straight-line AArch64 stores into an object, followed through moves, write-back and calls."""

    def test_stores_calls_and_write_back(self):
        from zkit.aarch64 import THIS, object_stores
        at = 0x1000
        words = [adrp(8, at, 0x2010), ldr(8, 8, 0x10), add(8, 8, 16),    # the table the GOT slot holds, + 16
                 mov(19, 0), str_(8, 19, 0),                               # this, through x19
                 add(10, 8, 0x30), str_pre(10, 0, 8),                     # a second group at this + 8; x0 moves
                 branch(at + 28, 0x5000, True),                            # x0 is this + 8; x8 and x10 forgotten
                 str_(8, 19, 0),
                 adrp(9, at + 36, 0x4020), add(9, 9, 0x20), stp(9, 31, 0, 0),   # into what the call returned
                 mov(0, 19), branch(at + 52, 0x6000, False)]               # a tail call with this
        self.assertEqual(object_stores(words, at, {0x2010: 0x3000}.get), [
            ("store", at + 16, THIS, 0, 0x3010), ("store", at + 24, THIS, 8, 0x3040),
            ("call", at + 28, 0x5000, THIS, 8), ("store", at + 44, at + 28, 0, 0x4020),
            ("call", at + 52, 0x6000, THIS, 0)])


class StoredBaseTests(unittest.TestCase):
    """Primary bases from the tables code stores, weighed against the table prefix (`itanium._bases`)."""

    @staticmethod
    def classes(tables: dict[str, list[str]]):
        """Classes from {class: its slots}, each slot `Owner::method` (a `/n` suffix: another function)."""
        functions, named, classes = {}, {}, {}
        for name, slots in tables.items():
            for slot in slots:
                if slot not in functions:
                    functions[slot] = 0x1000 + 4 * len(functions)
                    owner, method = slot.split("/")[0].split("::")
                    named[functions[slot]] = itanium.Method(owner, method, "", False, False, slot)
            classes[name] = itanium.ItClass(name, 0x8000 + 0x100 * len(classes),
                                            [itanium.Group(0, 0, [functions[s] for s in slots])])
        return classes, named, functions

    def test_a_base_no_slot_names_comes_from_the_destructor(self):
        classes, named, f = self.classes({"Single": ["Single::~Single", "Single::~Single/0"],
                                          "Fade": ["Fade::~Fade", "Fade::~Fade/0"]})
        itanium._bases(classes, named)
        self.assertEqual(classes["Fade"].bases, [])                       # destructors alone: no prefix to read
        itanium._bases(classes, named, [("Fade", ["Single"], "destructor", f["Fade::~Fade"])])
        self.assertEqual(classes["Fade"].bases, [(0, "Single")])
        self.assertEqual(classes["Fade"].evidence, {0: [("destructor", f["Fade::~Fade"])]})
        self.assertEqual(classes["Single"].bases, [])

    def test_the_nearest_proven_ancestor_wins(self):
        classes, named, f = self.classes({
            "Plugin": ["Plugin::~Plugin", "Plugin::~Plugin/0", "Plugin::reload", "Plugin::run"],
            "Disp": ["Disp::~Disp", "Disp::~Disp/0", "Plugin::reload", "Disp::run"],
            "Color": ["Color::~Color", "Color::~Color/0", "Plugin::reload", "Color::run"],
            "Node": ["Node::~Node", "Node::~Node/0", "Node::visit"],
            "Leaf": ["Leaf::~Leaf", "Leaf::~Leaf/0", "Leaf::visit"],
            "Tip": ["Tip::~Tip", "Tip::~Tip/0", "Leaf::visit"]})
        itanium._bases(classes, named, [
            ("Color", ["Plugin", "Disp"], "destructor", f["Color::~Color"]),   # nearer than the prefix's Plugin
            ("Tip", ["Node"], "destructor", f["Tip::~Tip"]),                    # Leaf's empty destructor dropped
            ("Leaf", ["Node"], "destructor", f["Leaf::~Leaf"])])
        self.assertEqual(classes["Disp"].bases, [(0, "Plugin")])
        self.assertEqual(classes["Color"].bases, [(0, "Disp")])
        self.assertEqual(classes["Color"].evidence, {0: [("destructor", f["Color::~Color"])]})
        self.assertEqual(classes["Tip"].bases, [(0, "Leaf")])
        self.assertEqual(classes["Tip"].evidence, {0: [("table prefix", None)]})
        self.assertEqual(classes["Leaf"].bases, [(0, "Node")])            # Tip derives from Leaf: not between

    def test_siblings_that_could_stand_between_prove_nothing(self):
        classes, named, f = self.classes({"Shape": ["Shape::~Shape", "Shape::~Shape/0", "Shape::draw"],
                                          "Square": ["Square::~Square", "Square::~Square/0", "Square::draw"],
                                          "Circle": ["Circle::~Circle", "Circle::~Circle/0", "Circle::draw"]})
        itanium._bases(classes, named, [("Square", ["Shape"], "destructor", f["Square::~Square"]),
                                        ("Circle", ["Shape"], "destructor", f["Circle::~Circle"])])
        self.assertEqual((classes["Square"].bases, classes["Circle"].bases), ([], []))   # Square : Circle fits too


STORED = """void hook();
void attach(void *object);
void *pool(unsigned long size);
__attribute__((noinline)) void *operator new(unsigned long size) { return pool(size); }
void operator delete(void *p) noexcept;
template <class T> struct Single { Single() { attach(this); } virtual ~Single() { hook(); } };
struct Fade : Single<Fade> { Fade(); ~Fade(); int frames; };
Fade::Fade() : frames(0) {}
Fade::~Fade() {}
Fade *makeFade() { return new Fade(); }
struct Shape { virtual ~Shape(); virtual void draw(); };
struct Square : Shape { void draw() override; };
struct Circle : Shape { void draw() override; };
Shape::~Shape() { hook(); }
void Shape::draw() {}
void Square::draw() { hook(); }
void Circle::draw() { hook(); hook(); }
Shape *makeSquare() { return new Square(); }
Shape *makeCircle() { return new Circle(); }
struct Node { virtual ~Node(); virtual void visit(); int id; };
struct Leaf : Node { void visit() override; };
struct Tip : Leaf { ~Tip(); };
Node::~Node() { hook(); }
void Node::visit() {}
void Leaf::visit() { hook(); }
Tip::~Tip() { hook(); }
Node *makeTip() { return new Tip(); }
namespace game { namespace menu { struct menu : Single<game::menu::menu> { menu(); ~menu(); int open; }; } }
game::menu::menu::menu() : open(0) {}
game::menu::menu::~menu() {}
game::menu::menu *makeMenu() { return new game::menu::menu(); }
template <class T> struct List : Single<List<T> > { List(); ~List(); T *head; };
template <class T> List<T>::List() : head(0) {}
template <class T> List<T>::~List() {}
struct Ev { int id; };
struct Se { int id; };
List<Ev> *makeEvents() { return new List<Ev>(); }
List<Se> *makeSounds() { return new List<Se>(); }
template <class T, unsigned long N> struct Box { T items[N]; };
struct Driver { virtual ~Driver(); virtual void report(Box<int, 4ul> &a, Box<char, 8ul> &b); };
Driver::~Driver() { hook(); }
void Driver::report(Box<int, 4ul> &a, Box<char, 8ul> &b) { a.items[0] = b.items[0]; }
Driver *makeDriver() { return new Driver(); }
"""


@unittest.skipUnless(CLANG and LLD, "needs clang++ and ld.lld to build an AArch64 module")
class StoredBaseModuleTests(unittest.TestCase):
    """A module whose constructors, destructors and new-expressions store their bases' tables: a singleton base
    with only destructor slots (no prefix to read), siblings, and an intermediate class with an empty destructor."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.temp.name)
        (root / "a.cpp").write_text(STORED, encoding="utf-8")
        subprocess.run([CLANG, *FLAGS, str(root / "a.cpp"), "-o", str(root / "a.o")], check=True, capture_output=True)
        subprocess.run([LLD, "-shared", "-Bsymbolic", "--no-relax", "--eh-frame-hdr", "--unresolved-symbols=ignore-all",
                        str(root / "a.o"), "-o", str(root / "main.elf")], check=True, capture_output=True)
        module = nx.load(root / "main.elf")
        symbols = [Symbol(s.name, ".text" if s.kind == "func" else ".data", s.value, "function" if s.kind == "func"
                          else "object", s.size, "global") for s in Elf.load(root / "main.elf").symbols
                   if s.name and s.size and s.kind in ("func", "object") and 0 < s.section < 0xFF00]
        cls.program = Program.from_symbol_list(Switch(), module, symbols)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_bases_the_code_stores(self):
        classes = itanium.recover(self.program)
        self.assertEqual(classes["Fade"].bases, [(0, "Single<Fade>")])
        self.assertEqual({how for how, _ in classes["Fade"].evidence[0]},
                         {"constructor", "destructor", "new-expression"})
        self.assertEqual(classes["Leaf"].bases, [(0, "Node")])
        self.assertEqual(classes["Tip"].bases, [(0, "Leaf")])               # its destructor stores Node's only
        self.assertEqual([classes[n].bases for n in ("Square", "Circle", "Single<Fade>")], [[], [], []])
        row = itanium.audit(self.program, "Fade")["rows"][0]
        self.assertTrue(row["bases"][0]["evidence"][0].startswith("constructor 0x"))

    def test_headers_with_those_bases_compile_to_the_same_tables(self):
        def compile(source, obj, include):
            return subprocess.run([CLANG, "--target=aarch64-none-elf", "-fno-rtti", "-fno-exceptions", "-std=gnu++14",
                                   "-O0", f"-I{include}", "-c", str(source), "-o", str(obj)], capture_output=True,
                                  text=True)
        result = itanium.check(self.program, compile, self.root / "proof")
        self.assertEqual(result["differences"], [])
        self.assertIn("class Fade : public ::Single<Fade> {",
                      (self.root / "proof" / "include" / "classes" / "Fade.h").read_text())
        # a class named like its namespace, a template whose base names its instance, two instances of one
        # template in a signature: each compiles to its table too
        self.assertIn("class menu : public ::Single< ::game::menu::menu> {",
                      (self.root / "proof" / "include" / "classes" / "game" / "menu" / "menu.h").read_text())
        self.assertIn("class List : public ::Single<List<T0>> {",
                      (self.root / "proof" / "include" / "classes" / "List.h").read_text())


class TableExtentTests(unittest.TestCase):
    def test_a_table_s_slots_stop_at_the_next_named_object(self):
        """A table of three slots (its symbol says 0x28 bytes) followed by a named array of function pointers:
        the array is not its slots. With no name after it, slots run on past a short symbol size."""
        from types import SimpleNamespace
        segment = SimpleNamespace(offset=0x1000, size=0x100)
        functions = {0x100: 0, 0x140: 1, 0x180: 2, 0x1C0: 3}
        pointers = {0x1010: 0x100, 0x1018: 0x140, 0x1020: 0x180, 0x1028: 0x1C0, 0x1030: 0x100}
        image = SimpleNamespace(section_at=lambda a: segment if 0x1000 <= a < 0x1100 else None, pointers=pointers,
                                imports={}, u64=lambda a: 0)
        def program(objects):
            return SimpleNamespace(image=image, function_index=functions, objects=objects, cache={})
        from zkit.program import DataObject
        table = DataObject(0x1000, 0x28, "_ZTV1A", ".data")
        array = DataObject(0x1028, 0x10, "_ZN1A7s_callsE", ".data")
        slots = itanium._groups(program([table, array]), 0x1000, 0x28)[0].slots
        self.assertEqual(slots, [0x100, 0x140, 0x180])
        slots = itanium._groups(program([table, DataObject(0x1028, 0x10, "lbl_1028", ".data")]), 0x1000, 0x28)
        self.assertEqual(slots[0].slots, [0x100, 0x140, 0x180, 0x1C0, 0x100])


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
