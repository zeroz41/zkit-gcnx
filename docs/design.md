# Design

## Shape

```
skills (zkit-resume / -recover-function / -port-system / -finish)
        │ tell the agent when to call what
MCP server (server.py) ── CLI (cli.py) ── SessionStart hook (`hook session-start`)
        │ thin; text by default, --json / response_format=json for data
bridge.py  session.py  activity.py  inspect_dol.py      ← answers
        │
index.py (SQLite + FTS5, ~/.cache/gcn-zkit/<id>-<hash>.sqlite)
        │ functions · calls · cites · lines · files
gc.py (DOL or .iso/.gcm, bl decode, dtk symbols/splits/asm)   native.py (include graph, CTest)   project.py (manifest, safe paths)
onboard.py (init: dtk config.yml -> project file, project selection by folder)
        │
repos named in the manifest + the original executable
```

All game knowledge lives in the project file (`gcn-zkit init` writes it; see [manifest.md](manifest.md)) and an
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
| `port-plan` | For each original callee: does native **code** (`code_paths`, not docs) cite it, and is the decomp exact? | That the native code is correct. A cite is a mention, not a verification |
| `demand` | Cited functions that need a match, a name or a link, ranked by how many native files cite them | Which of them is easiest to match |
| `asm` / `data` | Original bytes. With a PowerPC objdump, DOL code is disassembled from the DOL with r2/r13 from `__init_registers` (or `sda_bases`) and `lis`+low pairs resolved; otherwise, and always for RELs, dtk's relocated asm is shown, with float constants decoded. `data` reads the DOL only | Anything about the rebuilt binary; REL data |
| `check` | Rule hits on **added lines only** (git diff plus untracked files) | Semantics. It is a fast pre-commit lint, not review |
| `reuse` | Identical normalized bodies of free functions (≤40 lines) across files, plus files that name several sibling variants | Whether sharing is correct. These are candidates |
| `activity` | Processes whose cwd is inside a repo (Linux: /proc; macOS/Windows: psutil); lock holders from `/proc/locks` on Linux only (the lock is never taken); dirty files with ages; unmerged branches; worktrees | Who owns a dirty file (age is the hint) |
| `gate` | The manifest's canonical finish list, and which repo copies lack or add commands | Whether the gate passes. Run it |
| `test-plan` | Exact CTest names, recursive setup/cleanup fixture closure, historical costs and optional consolidated CMake prebuild commands | Test execution, coverage, rebuild cost or speedup. Complex/environment-dependent fixtures remain under CTest; required fixtures are never disabled |
| `impact` (native) | Files that directly `#include` the change (the consumers to re-test); CTest names whose test sources include it at distance 1 (direct) or 2 (near), or whose commands name an edited script/file; exact `ctest -R` commands, build targets and fixture names | Behavior reached only through linked libraries or hub headers (counted as "broad"); script imports and dynamically formed paths; build-fixture time |
| `lookup` data refs | Every pointer to the function's start inside the original's data sections, named by holder symbol and offset. The same slot in many `__vt__*` tables means an inherited base-class virtual | Virtual calls made through registers (`bctrl`) at runtime |
| `consts` (native) | For each float literal in a native function that cites originals: whether that value is among the constants those originals, their direct callees, or a cited data object (whole table) load. Powers of two and trivial values are skipped | Whether a *verified* constant is used in the right place, or integer immediates |
| `suspects` (native) | Files ranked by 3×unmatched cited originals + 4×near-miss constants + 1×unsourced + 2×untested + 1×no recipe, ×1.5 on gameplay paths, with actions | Proof that a file is wrong; it ranks where to look |
| `drift` (native) | Cited functions whose decomp match/name/body changed since the accepted baseline (or an old report via `--since`), grouped by native file | When the native code was written; a re-verify list is a prompt, not a verdict |
| `grounding` (native) | Per folder and file: share of cited original functions that are byte-exact, linked or semantically named in the decomp; the files resting on the most unmatched ones | That a matched function was ported correctly |

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
- Large selections are split into anchored commands, never widened to a label. GPU-labelled cases remain
  visible as GPU even when also labelled local. JSON supplies `command_argvs`, `build_targets` and `fixtures`.
  Build targets are discovered from compiler output paths; wrappers/renamed executable targets may be absent.
- Recorded durations exclude build fixtures; missing costs are counted, not represented as measured zero.
  Optional parallel prebuilds use the selected targets. Repository finish requirements remain authoritative.

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
- **Installed as a normal command.** `uv tool install` puts `gcn-zkit` on PATH on every OS; the plugins call it by
  name (no shell scripts), and the hooks never fail a session start.
