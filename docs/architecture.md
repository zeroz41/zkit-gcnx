# Design

## Shape

```
skills (zkit-resume / -recover-function / -port-system / -finish)
        │ tell the agent when to call what
MCP server (server.py) ── CLI (cli.py) ── SessionStart hook (`hook session-start`)
        │ thin; text by default, --json / response_format=json for data
bridge.py  structure.py  session.py  activity.py  inspect_dol.py      ← answers
        │
index.py (SQLite + FTS5, ~/.cache/zkit/<id>-<hash>.sqlite)
        │ functions · calls · cites · lines · files
gc.py (DOL or .iso/.gcm, bl decode, dtk symbols/splits/asm)   native.py (include graph, CTest)   project.py (manifest, safe paths)
onboard.py (init: dtk config.yml -> project file, project selection by folder)
        │
repos named in the manifest + the original executable
```

All game knowledge lives in the project file (`zkit init` writes it; see [manifest.md](manifest.md)) and an
optional lessons folder. The code works for any dtk/objdiff GameCube project, with or without REL modules, with or
without a native port, and for a non-GameCube project without `targets` (then only docs, search, activity,
handoffs and gates apply). [manifest.md](manifest.md) has a full example with a native port.

## The index

| Table | Source | Refresh |
| --- | --- | --- |
| `functions` | objdiff `report.json` (name, demangled, match %, unit, source, linked), DOL and RELs. REL functions are keyed `(module_id << 32) \| offset` and shown as `module+0xOFFSET`; DOL addresses keep their plain values. Falls back to dtk `symbols.txt` (DOL only), with a CodeWarrior `Class::method` demangle. | When the report's size or mtime changes |
| `calls` | Every `bl` inside every DOL function, decoded from the **original** DOL; for REL functions, every `bl` in dtk's relocated asm (`build/<ver>/<module>/asm`), resolved to DOL or same-module functions | When the DOL, the function table or dtk's split output (`config.json`) changes |
| `cites` | Every `8xxxxxxx` address in configured `cite_paths`. Matched on hex boundaries, so `Original801977D4` and `Foo_80011824` count. | Per file, by mtime and size |
| `lines` | FTS5 over 6-line windows overlapping by 3, for configured `index_paths` | Per file; deletes by rowid range |

The first build of a large decomp plus port (10.4k files) takes about 11 s; a fresh dtk project with 48k
functions and 757 RELs about 6 s, 5 s of it reading dtk's REL asm. A no-op refresh is about 0.1-0.3 s, and every
query runs one first, so it sees edits made by other sessions.

**Addresses are the join key.** They survive renames, TU merges and file moves, which file
paths and symbol names do not: native docs still cite removed `MyClass_80141D1C.cpp`-style
paths.

## What each answer means

| Command | Says | Does not say |
| --- | --- | --- |
| `lookup` | The report's current state for the function containing an address; the DOL's direct callers and callees; where it is mentioned | That the build is fresh (check `brief`'s report age), or anything about virtual-call edges |
| `port-plan` | For each original callee: does native **code** (`code_paths`, not docs) cite it, is the decomp exact, and is it ready (named on evidence, no decompiler shapes in its body or its own name, see `quality`); SDK/runtime units (`library_categories`) are `platform` | That the native code is correct. A cite is a mention, not a verification |
| `demand` | Cited functions that need a match, a name or a link, ranked by how many native files cite them | Which of them is easiest to match |
| `asm` / `data` | Original bytes. With a PowerPC objdump, DOL code is disassembled from the DOL with r2/r13 from `__init_registers` (or `sda_bases`) and `lis`+low pairs resolved; otherwise, and always for RELs, dtk's relocated asm is shown, with float constants decoded. `data` reads the DOL only | Anything about the rebuilt binary; REL data |
| `check` | Rule hits on **added lines only** (git diff plus untracked files), or on every line of the given files/folders: native citations (unresolved, not ready in any tier, missing at a new exact-tier function in any layout), forbidden patterns, include boundaries, constants; decomp debt. A problem the replaced lines already had is debt | Semantics. It is a fast pre-commit lint, not review |
| `reuse` | Free functions (≤40 lines, any style) with the same name and body (comments and spacing ignored) across files, split into identical copies and same-body-different-types (template/interface candidates), plus files that name several sibling variants | Whether sharing is correct. These are candidates |
| `activity` | Processes whose cwd is inside a repo (Linux: /proc; macOS/Windows: psutil); lock holders from `/proc/locks` on Linux only (the lock is never taken); dirty files with ages; unmerged branches; worktrees | Who owns a dirty file (age is the hint) |
| `gate` | The manifest's canonical finish list, and which repo copies lack or add commands | Whether the gate passes. Run it |
| `architecture` | Project-configured C/C++ include boundary checks, exact source lines, resolved headers and explicit exceptions (also applied to the changed lines by `check`) | Semantic coupling, ownership, preprocessor evaluation or a complete architecture proof |
| `coverage` | Dynamic reference/stage inventory joins, duplicates, missing identities, prerequisite gaps and source hashes | Import validity, runtime admission, successful tests or system completion |
| `unit` | A unit's splits.txt ranges, the report's state of its functions, its data symbols with the units whose code or data points at them, the data its code uses that another unit (or no split) holds, and section neighbours. `--blocked`: units whose functions are all exact but not all linked, with those references. `--gaps`: per section, the bytes no split claims (extents from symbols.txt) and the units whose code uses each range | Why a link actually fails (order, alignment, padding and missing runtime symbols need a link attempt), or which fold is right. References are straight-line decoded forms, so register-passed and indexed accesses are missed |
| `classes` | For each function held by named `__vt__` tables: whether its class name is among them; strong when the named class has its own named vtable without it; the holding class when there is one | The base class of several holders (no RTTI), or anything about non-virtual methods. Unnamed `lbl_` tables are only counted |
| `stale` (native) | Programs from `build.ninja` link statements older than a source compiled into them (`compile_commands.json`), or a header such a source includes | Generated sources, content packages or data read at run time. It reads file times; it never builds |
| `test-plan` (MCP: `impact` with names) | Exact CTest names, recursive setup/cleanup fixture closure, historical costs and optional consolidated CMake prebuild commands | Test execution, coverage, rebuild cost or speedup. Complex/environment-dependent fixtures remain under CTest; required fixtures are never disabled |
| `impact` (native) | Files that directly `#include` the change (the consumers to re-test); CTest names whose test sources include it (or its pair, or the header a split source is named after) at distance 1 (direct), 2 (near) or 3+ (broad, named), whose commands name an edited file, or whose program links an object built from it (linked: a sample of one test per program when nothing closer reaches the file); exact `ctest -R` commands first, fixture tests and prebuilds from the test plan, and programs older than their sources. `--budget`: every direct test, then the cheapest test of each program not yet exercised, then cheapest first; the rest deferred with a command. `gate` prints the direct tests of the current diff as the owning checks | Script imports and dynamically formed paths; build-fixture time; whether a linked program actually runs the changed code |
| `lookup` data refs | Every pointer to the function's start inside the original's data sections, named by holder symbol and offset. The same slot in many `__vt__*` tables means an inherited base-class virtual | Virtual calls made through registers (`bctrl`) at runtime |
| `consts` (native, GameCube) | For each float literal in a native function that cites originals (at the definition or at its declaration in the file's own header): whether that value, or literal arithmetic folded as the compiler does, is among the constants those originals, their direct callees, or a cited data object (whole table) load; or two of them combined. Powers of two and trivial values are skipped | Whether a *verified* constant is used in the right place, or integer immediates |
| `drift` (native) | Cited functions whose decomp match, readiness, name or body changed since the accepted baseline (or match state against an old report via `since`), grouped by native file | When the native code was written; a re-verify list is a prompt, not a verdict |
| `grounding` (native) | Per folder and per unit (a source with its own header): share of cited original functions that are ready references, byte-exact and named in the decomp, with the main reasons; units ranked by those shares, near-miss/unsourced constants, no test program compiling or linking them and no recipe, with actions (CLI alias `suspects`); exact-tier units that cite no original | That a matched function was ported correctly; it ranks where to look |

## Project file

See [manifest.md](manifest.md) for every field. How `impact` maps tests:
- `compile_commands.json` gives source → target.
- The CTest catalog gives target → test names, skipping build fixtures.
- For a multi-suite executable selected by `--flag`, the dispatcher line containing `"--flag"` names the
  function it calls, and the test source defining that function owns the case.
- `X.cpp` and `X.hpp` are treated as one unit, so code that a `.cpp` consumes is still reached through the
  tests that include its header.
- Include candidates are resolved once per query and shared across source files. Each query still reads
  current files; no persistent graph can hide edits or file moves.
- Literal file arguments in CTest commands resolve from `WORKING_DIRECTORY` (the build directory by default).
  Script imports and indirect runtime coverage remain outside this graph.
- A `.cpp` without a header of its own that includes a header of its folder it is named after
  (`GameWorldSounds.cpp` -> `GameWorld.hpp`) is treated as that header's unit: split implementation files.
- Large selections are split into anchored commands (a shared prefix and suffix written once; CMake's regex
  allows only a few groups), never widened to a label. Tests are grouped by their first CTest label, or by the
  manifest's `tests.label_order`. JSON supplies `command_argvs`, `build_targets` and `fixtures`.
  Build targets are discovered from compiler output paths; wrappers/renamed executable targets may be absent.
- Recorded durations exclude build fixtures; missing costs are counted, not represented as measured zero.
  Optional parallel prebuilds use the selected targets. Repository finish requirements remain authoritative.

## Native-port design and completion

MCP initialization and session guidance explicitly scope native architecture to porting. Shared owners,
interfaces at real service boundaries, composition, original-format/protocol adapters and automated import
dependency handling are expected; behavior must come from authored commands/data and original evidence,
not content identity or shape. Matching decomp preserves original layout, translation units and compiler
constraints. The generic toolkit supplies checks; each project supplies its policy and format selectors.

The architecture audit reads selected current source files and resolves literal include paths. Comments and
raw strings cannot create fake directives. It considers all conditional branches and reports macro/external
limits. The inventory audit compares current extracted identities across declared stages, with provenance,
missing inputs, duplicates and dependency gaps visible. Both are read-only and available through CLI and MCP.
Neither substitutes for native live-path verification or the project's own importer.

## Architecture and test planning

The project manifest's `required_docs` supplies its architecture, layout and quality contracts. Both brief formats
show those references and missing files. The resume and port skills require reading them and identifying the
owner, dependency direction and extension boundary before editing. This exposes the project's contract; it does
not prove an implementation follows it or replace the repository's own architecture checks.

`test-plan <repo> <exact names...> --jobs N` resolves CTest fixtures recursively, reports missing/disabled tests,
and keeps setup/cleanup fixtures in the emitted CTest selection. It suggests a union of build targets only for
plain, independent CMake build fixtures with the same working directory/configuration. Commands with custom
options, environment overrides or dependencies are left to CTest. Nothing is built or executed. Costs include
known fixture durations separately; they are historical observations, not a forecast of fresh compilation.

## Installation provenance

`doctor` parses enabled state and reports the running package path, plugin cache versions and changed skill/hook
files relative to an editable checkout. This is an on-disk inventory, not proof an existing client reloaded the
plugin. User configuration can be overridden per project. The legacy `home` setting is unused.
`setup --refresh-agents --plugin-source <checkout>` explicitly refreshes both clients through their plugin CLIs;
it does not remove duplicate checkouts. A setup dry run with an existing manifest writes no configuration.

## Decisions

- **No second router.** A repo's own work router (the `router` setting in the project file) stays the
  authority; the brief only shows its result, its age, and recent lane yield.
- **No execution through MCP** (builds, banking, emulators). Those need the user's
  sandbox and permission model, and each repo already has a transactional tool for them.
  The only write is the handoff note, and it goes to the toolkit's own state directory.
- **Compact text first.** The prototype's JSON brief was 7.8 KB. The text brief is about 4 KB with
  more content, and the JSON form stays available for scripts.
- **Lessons live in the toolkit repo, not in agent memory.** Claude's memory directory depends
  on the launch directory, and Codex has its own. A checked-in folder is visible to every
  client and can be reviewed.
- **Installed as a normal command.** `uv tool install` puts `zkit` on PATH on every OS; the plugins call it by
  name (no shell scripts), and the hooks never fail a session start.
