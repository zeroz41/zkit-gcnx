# Architecture

zkit has three jobs: read an original executable and recover its structure (the work a decomp's splitter and
delinker do), measure a decomp against it, and give agents the evidence and rules to finish the decomp and port
it. Everything game-specific lives in the project file ([project-file.md](project-file.md)); the code is the same
for every game.

## Layers

```
interfaces   cli.py · server.py (MCP) · render.py (text) · hooks · skills
                │ one function per answer, called the same way from the CLI and MCP
answers      bridge.py (lookup, refs, port-plan, check) · inspect_dol.py (asm, data) · asmfile.py (m2c) · decompile.py (Ghidra) · permute.py (decomp-permuter)
             structure.py (unit, gaps, blocked) · objects.py (compiled vs original) · candidate.py (try)
             progress.py (reports, baselines, page) · quality.py · hygiene.py · session.py · activity.py
             native.py · fidelity.py · tiers.py · architecture.py · coverage.py (ports)
                │
structure    delink.py (objects per unit) · link.py (a DOL relinked) · nxlink.py (a Switch module rebuilt)
             units.py (unit boundaries)
             vtables.py · classes.py (classes)
             analyze.py (all of it into a folder) · score.py · mwmap.py (CodeWarrior maps) · cwnames.py (names)
             mapalign.py (a map of another build of the same code, where it lines up)
                │
program      program.py: functions, data objects, sections, small-data bases, references between them
                │
machine      ppc.py (PowerPC control flow and relocations) · ppcflow.py (register flows: this, allocations)
             aarch64.py (AArch64 references and relocations) · rtti.py (Itanium RTTI)
                │
images       platform.py (GameCube, Switch) · gc.py (DOL, disc images, splits/symbols files) · nx.py (NSO and
             ELF modules) · nxdata.py (a module's data objects) · elf.py (ELF objects)
                │
index        index.py: SQLite + FTS5 in zkit's cache: functions, calls, cites, text lines of every repo
```

### Images and platforms

`platform.py` hides what differs between consoles: how the original is opened, its address space (GameCube
0x80000000 images; Switch modules at 0x7100000000), how its code is decoded, how data pointers are recognised and
which Ghidra language reads it. A GameCube target is a DOL, read directly or from inside a disc image. A Switch
target is an NSO (LZ4 or zstd segments) or an ELF of one, loaded and relocated: MOD0, the dynamic section, symbols,
RELA/RELR/JMPREL, init arrays, exception-frame function bounds and PLT stubs, and where the linker's own tables
lie. `nxdata.py` finds a stripped module's data objects: every address its code forms, loads or stores through and
every address a relocated pointer holds starts one, up to the next, with a string cut at its NUL and a scalar the
code only reads at one width that wide; the linker's tables are no program object.

### Machine code

`ppc.py` splits a function into basic blocks and follows register values along every path: a block starts with
what all of its predecessors agree on, and code no known path reaches starts knowing only the small-data bases.
That is what makes the relocations it recovers exact: `lis`/low-half pairs (including `addic`), small-data
accesses through r2/r13, calls and branches that leave the function, and recursive calls. The general registers
each instruction writes come from one exact table, so a float register field is never taken for a general one.
`aarch64.py` does the same for ADRP pairs, GOT loads, literal loads and branches.

### Delinking

`delink.py` cuts the original into one relocatable ELF object per unit of a split, laid out as the compiler
emitted it: code and data ranges in order, every reference a relocation against a symbol, relocated fields cleared,
objdiff's `.note.split` carrying each symbol's original address. The machine decides the object format
(big-endian ELF32 with CodeWarrior's section flags for GameCube, little-endian ELF64 for Switch), how code is read,
and which data words are pointers: on Switch the module's own dynamic relocations say so; on GameCube every
aligned word that lands in the image is one, except inside string data and unaligned code addresses. Each data
pointer carries its evidence (a function start, a jump-table case, an object, a place inside a function); a
pointer into the middle of a function is reported, since it means a start the symbols lack or a wrong boundary.
A REL module (`rel.py`) needs no evidence of that kind: its relocation tables name every reference, and only the
calls makerel applied inside one section are read from the bytes. `rel.py` also writes RELs, from a parsed one or
from a partially linked ELF as makerel does.

The gate it is held to: on a large GameCube decomp, every function of every fully matched unit equals the compiled
object (bytes and relocations; relocations to the same constant under another name count as equal), and every data
pointer of those units is found. For RELs, on one game's 757 modules: every function of their fully matched
units agrees with the compiled object, and every REL written back (from itself,
and from its partially linked ELF) is byte-identical to the original.

### Linking

`link.py` puts a GameCube executable back together with the project's own CodeWarrior linker (the command its
build.ninja links with) and requires the DOL it writes to equal the original byte for byte. Each unit is one
object: delinked, the compiled object of a unit the report proves complete, or both combined, the original unit
with each exact function's code and relocations taken from the compiled object, so linked code follows matched code
function by function. mwld lays sections out symbol by symbol in command-line order, so the objects tile every
section (gap units for what no unit claims, fill symbols over bytes no symbol covers, the linker's own tables left
to it), one link order agrees with every section's address order, and each delinked section takes the smallest
alignment that lands it on its original address. A combined function whose compiled relocations reach other
addresses than the original's stays delinked: the report can call a function exact whose calls go elsewhere.

`nxlink.py` rebuilds a Switch module the same way without its linker, whose dynamic tables, GOT and import stubs
could not be made to come out identical: each compiled section goes where the original holds it (by the name it
defines, the unit's own copy when a name has several; a section no name places where the original's code reaches
it; a template's COMDAT copy only in the unit that kept it), each literal of a mergeable section where the
original's reference finds the same bytes, and each relocation resolves as the module's linker resolved it (a
call to an import through its stub, a GOT load through the slot whose dynamic relocation holds the target, a
pointer in data only where the original carries a dynamic relocation to the same address). The rebuilt module
must equal the original and, on an NSO, each segment must hash to its header's SHA-256. A unit whose functions all
match is linked when its object covers every byte of its ranges, alignment padding aside, and all of it linked
identically; the build then marks it complete in objdiff's report, with its data matched (objdiff cannot pair a
unit's string literals, which clang merges with every other unit's; the link places each one), keeping objdiff's
own data counts under `zkit_link` for when it stops linking. The link catches what objdiff's per-function view
cannot: a `__FILE__` that differs from the original's string, a function the object defines outside its unit.

### Units, classes and names

`units.py` proposes unit boundaries from evidence in the original: CodeWarrior gives every unit its own copy of
each literal, so two copies of one value separate their users and one copy shared by neighbours joins them; data
only one run of code uses belongs to it; source paths cited by the code name a unit, and outrank data: data one
run uses across two cited files is shared (a template's table, an inline's static), not one unit's. One file cited
under two spellings (a path relative to an include folder, another build's unit name) is the full path that ends
in the shorter one. On an ELF, a unit's own static initializer (one that tests no guard first; a guarded one is a
template's static member, kept from whichever unit came first) is the unit's last function, and each initializer
array entry is that unit's data. Another build's units count where the code states nothing: a boundary only they
give yields to a citation change or an initializer between the same two citing functions, and a unit only they name
after the file its neighbour's own code cites is named by its class (the qualifier of a constructor or destructor
in its functions' Itanium names) or by its address. The linker's own sections (`.dynamic`, `.eh_frame`...) are
nobody's, and a unit's data starts on a word only where the compiler aligns every object's sections so
(CodeWarrior; clang's strings are byte-aligned). `--check` compares an existing
split against the same evidence: folds (two units holding one unit's data), splits (one unit holding two copies of
one literal) and data claims (data in no unit that one unit's code alone uses).

A data object's size is its own: discovery ends a jump table at its last case, a literal string (used by its
address, never loaded) at its NUL, and a small-data object code only loads and stores whole at one width at that
width, leaving the zero padding before an aligned next object to the gap; nothing shrinks past an address the code
or data reaches inside it. Data no code uses that only one unit's data points to (a table's strings) is that unit's.

`mapalign.py` takes units, names and sizes from a CodeWarrior map of another build of the same code (a debug build's
map shipped on the disc), only where that build holds the same object. Both builds link in one order, so their
functions are aligned in order by size and spacing; a run counts when its sizes are improbable by chance beyond the
places the search tried. An object whose every function lines up takes its name, its functions' names and its code
range, and places its data pieces where the original's own references (from its code, then from its placed data)
land on the map's symbols; an object whose code differs but whose neighbours line up takes its name and code range
only. `units.propose` takes these units as given and weighs their data against the other claims in link order, so a
placement the original contradicts gives way; on a decomp in progress, units with a source stay as they are. On
Double Dash (a debug build's map), 318 of the original's units come from the map and the relink stays
byte-identical.

`signatures.py` takes names from other builds. A donor function's shape is its instruction words with every
relocated field cleared (PowerPC's, or what `aarch64.code_relocations` relocates) and what each relocation names; a
target function takes a donor name by its shape, by what matched functions refer to and by the slots of class
tables (CodeWarrior's, or Itanium's `_ZTV` read through a module's relocations), each only where the evidence
admits one name, and a name two pieces of evidence dispute is withdrawn. A table's slots pair with the donor's by
the code in them, never by index: an update that adds or removes a virtual moves every slot after it, and the
table can keep its length. Texts compare without a drive letter, which is the build machine's. Code that differs
from a donor sibling's only in immediates (a field offset, a virtual's slot, a constant) names nothing by its
shape alone, since an update that moves a field moves them. A donor read from an original keeps its layout and its
functions' masked words, so between two named functions the code in between is the donor's code in between, less
what the linker dropped: copies of one shape, and siblings of one family, pair in order, changed code one to one,
by the callees, data and texts it shares, or by how alike it is (aligned in order, at least sixteen words, clearly
ahead of every other pairing in the gap), and a changed function's one unnamed callee is its donor's one
unclaimed callee. `analyze.py` writes the names and the
data they bring with the donor's sizes, and gives each named function's donor unit to `units.py` as evidence like
a cited file (never a weak function's: the linker keeps an inline from whichever unit comes first). Without a
symbols file a Switch module is read from its own tables, so a fresh analysis never inherits names.

`vtables.py` finds class tables as data whose words have CodeWarrior's table shape (RTTI and offset words, then
one function pointer per slot) and that the code stores into an object, or that holds a destructor; a dispatch
table has the shape but is only read. `classes.py` recovers constructors (the last table a function stores into
`this` is its class's), destructors (a slot that stores its own table first), bases and members (constructor calls
on `this` and `this + k`), sizes (`new` with a constant size reaching a constructor) and fields (accesses through
`this`), and writes declarations a compiler turns back into the original tables. `--prove` compiles them
with the project's own compiler and compares tables, pointer offsets and sizes. Names are only what evidence
proves: a table is `__vt__<class>`, a CodeWarrior destructor `__dt__<class>Fv`; a constructor or virtual method
keeps its placeholder until its parameters are known, because a mangled name claims a signature. On Switch,
`itanium.py` reads the classes from a module's `_ZTV` tables without RTTI: a primary base is a table that is a
prefix of the class's own, or the nearest ancestor whose table the class's constructors, destructors and
new-expressions store at offset 0 of the object before (after, in a destructor) its own, where no other class
could stand between them. Each base names the evidence that proved it. A function only one class's table holds
is named by its slot: in its base's destructor slots it is the class's destructor (`D1`, then `D0`, where its code
proves it is not a base's folded into it), elsewhere the method every named function in that slot below the
class that declares it is, spelled for its own class.

`score.py` measures a proposed split against a reference (another split or a CodeWarrior linker map): function
starts and sizes, names, unit boundaries, vtables and data ownership, with the reference's fully matched units
counted separately as proven.

### Measuring a decomp

`objects.py` compares compiled objects with the original's, function by function (the differing words, both
disassemblies), and proves a change kept every object identical apart from intended renames. `candidate.py`
compiles a candidate outside the tree with its unit's exact build command. `progress.py` reads objdiff reports:
matched and linked code and data bytes, exact functions and units, and changes keyed by address so a rename or a
fold is not a regression; `report.html` is a self-contained page of the same, which every build writes to
`build/progress/index.html` beside a copy of each report it shows, titled by the manifest's `title` and
`subtitle`; a target with one module (a Switch `main`) is browsed by source folder. `zkit report --readme` writes
a small table of the totals between `<!-- progress -->` markers in the decomp's README (adding them when missing).

### The index and the evidence tools

`index.py` keeps one incremental SQLite database per project in zkit's cache: functions (from the objdiff report,
the symbols, or the original's own tables), every direct call decoded from the original, every original address the
configured repos cite, and full-text windows of their docs and source. Every query refreshes it first (a no-op
refresh is a fraction of a second), so answers include edits other sessions just made. Addresses are the join key:
they survive renames, unit folds and file moves.

| Tool | Says | Does not say |
| --- | --- | --- |
| `lookup` | The report's state of the function holding an address; direct callers and callees from the original; data pointing at it; where it is mentioned | That the build is fresh, or virtual-call edges |
| `asm` / `data` | Original bytes, with small-data and address pairs resolved | Anything about the rebuilt binary |
| `compiled` / `try` | Whether a compiled function equals the original, and where it differs | Why it differs |
| `unit` | A unit's ranges, functions, data and the references crossing its boundary; `--blocked` and `--gaps` | Why a link fails (order and alignment need a link attempt) |
| `delink` / `units` / `classes` / `analyze` | What the original proves about its structure, with the evidence | Anything the evidence does not reach; those stay placeholders |
| `link` | Whether the units, compiled where matched, relink to the original, and the first byte where they do not | Whether a unit is right where the delinked original stands in for it |
| `progress` | objdiff's numbers and what changed since a baseline | That the build is current |
| `quality` / `hygiene` | Decompiler debt in the source; what must not be committed | Whether a name is right |
| `check` / `gate` | Rule hits on added lines; the repo's finish gate | Semantics; whether the gate passes until it is run |
| port tools | Which original functions native code cites and whether the decomp is ready (exact, named, clean) for them; where native behavior probably differs; which tests cover a change | That ported code is correct: a citation is a mention, not a verification |

### Discipline

`quality.py` measures decompiler debt in the source (hand-mangled names, raw pointer offsets, fake vtables,
address-named types, decompiler temporaries) at any revision and between revisions. `hygiene.py` enforces what
must not be committed or left behind: AI-only documents, dated session notes, one-off scripts, original game
files, AI identities and co-author trailers, long commit messages, stray branches and worktrees. `session.py`
records each session's start (heads, progress baseline) so the finish gate can judge what this session changed.
The contracts (`zkit contract decomp|port`) are the rules agents follow; the skills tell them when to call what.

## Decisions

- **Evidence or nothing.** A tool reports what the original or the build proves and labels the rest; no answer
  guesses a name, a boundary or a behavior.
- **Measured against truth.** Structure recovery is scored against fully matched units and real symbol maps, and
  against what the tools zkit replaces produce; a change that scores worse does not ship.
- **Read-only by default.** Only `handoff`, `report`, `delink`, `link`, `analyze`, `objects --save` and
  `cache --prune` write, and only to zkit's own folders or the folder named (`link` runs the project's linker
  there; on Switch it also marks the units it proves in the report). Builds, banking and emulators stay with each repo's own tools and the user's permission model.
- **Downloads on request, pinned, per platform.** Only `--download` uses the network. Each tool is pinned to a
  hash or commit, and a target fetches only the tools its platform runs (GameCube: CodeWarrior, wibo, binutils,
  m2c, decomp-permuter; Switch: LLVM and the project's own clang; both: objdiff-cli). A new tool is added to the
  platform that uses it, never to every project.
- **Compact text first**, JSON on request (`--json`, `response_format=json`), with output budgets so an answer
  never floods an agent's context.
- **Installed as a normal command.** `uv tool install` puts `zkit` on PATH; the plugins call it by name and the
  hooks never fail a session start.
