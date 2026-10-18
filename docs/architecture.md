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
structure    delink.py (objects per unit) · link.py (the original relinked) · units.py (unit boundaries)
             vtables.py · classes.py (classes)
             analyze.py (all of it into a folder) · score.py · mwmap.py (CodeWarrior maps) · cwnames.py (names)
                │
program      program.py: functions, data objects, sections, small-data bases, references between them
                │
machine      ppc.py (PowerPC control flow and relocations) · ppcflow.py (register flows: this, allocations)
             aarch64.py (AArch64 references and relocations) · rtti.py (Itanium RTTI)
                │
images       platform.py (GameCube, Switch) · gc.py (DOL, disc images, splits/symbols files) · nx.py (NSO and
             ELF modules) · elf.py (ELF objects)
                │
index        index.py: SQLite + FTS5 in zkit's cache: functions, calls, cites, text lines of every repo
```

### Images and platforms

`platform.py` hides what differs between consoles: how the original is opened, its address space (GameCube
0x80000000 images; Switch modules at 0x7100000000), how its code is decoded, how data pointers are recognised and
which Ghidra language reads it. A GameCube target is a DOL, read directly or from inside a disc image. A Switch
target is an NSO (LZ4 or zstd segments) or an ELF of one, loaded and relocated: MOD0, the dynamic section, symbols,
RELA/RELR/JMPREL, init arrays, exception-frame function bounds and PLT stubs.

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
pointer of those units is found. For RELs, on Twilight Princess's 757 modules: every function of their fully matched
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

### Units, classes and names

`units.py` proposes unit boundaries from evidence in the original: CodeWarrior gives every unit its own copy of
each literal, so two copies of one value separate their users and one copy shared by neighbours joins them; data
only one run of code uses belongs to it; source paths cited by the code name a unit. `--check` compares an existing
split against the same evidence: folds (two units holding one unit's data), splits (one unit holding two copies of
one literal) and data claims (data in no unit that one unit's code alone uses).

`vtables.py` finds class tables as data whose words have CodeWarrior's table shape (RTTI and offset words, then
one function pointer per slot) and that the code stores into an object, or that holds a destructor; a dispatch
table has the shape but is only read. `classes.py` recovers constructors (the last table a function stores into
`this` is its class's), destructors (a slot that stores its own table first), bases and members (constructor calls
on `this` and `this + k`), sizes (`new` with a constant size reaching a constructor) and fields (accesses through
`this`), and writes declarations a compiler turns back into the original tables. `--prove` compiles them
with the project's own compiler and compares tables, pointer offsets and sizes. Names are only what evidence
proves: a table is `__vt__<class>`, a CodeWarrior destructor `__dt__<class>Fv`; a constructor or virtual method
keeps its placeholder until its parameters are known, because a mangled name claims a signature.

`score.py` measures a proposed split against a reference (another split or a CodeWarrior linker map): function
starts and sizes, names, unit boundaries, vtables and data ownership, with the reference's fully matched units
counted separately as proven.

### Measuring a decomp

`objects.py` compares compiled objects with the original's, function by function (the differing words, both
disassemblies), and proves a change kept every object identical apart from intended renames. `candidate.py`
compiles a candidate outside the tree with its unit's exact build command. `progress.py` reads objdiff reports:
matched and linked code and data bytes, exact functions and units, and changes keyed by address so a rename or a
fold is not a regression; `report.html` is a self-contained page of the same.

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
  there). Builds, banking and emulators stay with each repo's own tools and the user's permission model.
- **Downloads on request, pinned, per platform.** Only `--download` uses the network. Each tool is pinned to a
  hash or commit, and a target fetches only the tools its platform runs (GameCube: CodeWarrior, wibo, binutils,
  m2c, decomp-permuter; Switch: LLVM and the project's own clang; both: objdiff-cli). A new tool is added to the
  platform that uses it, never to every project.
- **Compact text first**, JSON on request (`--json`, `response_format=json`), with output budgets so an answer
  never floods an agent's context.
- **Installed as a normal command.** `uv tool install` puts `zkit` on PATH; the plugins call it by name and the
  hooks never fail a session start.
