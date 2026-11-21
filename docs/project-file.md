# The project file

`zkit init` writes one JSON file per decomp to `~/.config/zkit/projects/<id>.json` (Windows:
`%USERPROFILE%\.config\zkit\projects`). You rarely need to touch it. Edit it to add your repo's rules, its finish
steps, lint checks or a native port. Running `init` again refreshes what it detected and keeps your edits.

zkit picks the project from the folder you are in, using the first match:

1. `--project <file>`
2. `$ZKIT_PROJECT`
3. a `zkit.project.json` in this folder or a parent (to keep the file in the repo)
4. a registered project whose repository, or a git worktree of it, contains this folder
5. the default project (`zkit use <file>`)

`zkit projects` lists them and marks the one in use. The session hook only speaks inside a registered repo.

## Minimal example

```json
{
  "schema_version": 1,
  "id": "mygame-game01",
  "repositories": {
    "decomp": {"root": "/path/to/mygame", "role": "decomp", "index_paths": ["README.md", "docs", "include", "src"]}
  },
  "targets": {
    "game01": {"repository": "decomp", "module": "main", "symbols": "config/GAME01/symbols.txt",
               "report": "build/GAME01/report.json", "original": "orig/GAME01/sys/main.dol"}
  }
}
```

Relative `root` paths are relative to the project file. All other paths are relative to their repository.

## Targets (the original game)

| Field | Meaning |
| --- | --- |
| `platform` | `gamecube` (default) or `switch`. |
| `original` | GameCube: the DOL, or a `.iso`/`.gcm` disc image (the DOL is read in place). Switch: the NSO, or an ELF of it; when the NSO is missing, `zkit build` (and `zkit extract`) writes it from the game's packages (`.nsp`, `.xci`: the game and its updates; or a `.nup`, which holds titles already decrypted) in `packages`, or else in its folder or one above it in the repository: the file of a program NCA's partitions (the ExeFS) whose SHA-1 is `sha1` (without `sha1`, the only one named as `original` is), decrypted with `prod.keys` (not needed for a `.nup`) found beside the packages, in `~/.switch` or in an emulator's usual folder. Needed for asm, data, callers, xrefs, delinking and every structure tool. |
| `packages` | Switch: the folder (or a list of folders) in the repository where the game's packages go for the original to be extracted, with their subfolders, e.g. `roms`. Default: the original's folder and each one above it. |
| `base` | Switch: the module's load address (default `0x7100000000`). Addresses are written with it. |
| `symbols` | The `symbols.txt` (names, sizes, scopes and data symbols; the format existing decomps keep). |
| `splits` | The `splits.txt` (units and their section ranges). Needed for `unit`, `units --check`, `delink`, `link` and the owner unit of a data address. `link` also reads `mw_comment_version` and `force_active` from a `config.yml` next to it, and the link command from the repository's `build.ninja`. |
| `report` | objdiff `report.json`. Match state, source files and REL functions. Without it, functions come from `symbols.txt` (or, on Switch, the module's own tables). |
| `objdiff` | objdiff's project file (default `objdiff.json`): which compiled object belongs to which unit, for `compiled`, `objects` and `try`. |
| `functions` | Switch: an optional CSV of known functions (address, size, name) when there is no symbols file. |
| `module` | Name of the main module in the report (default `main`). |
| `rels` | `false` to leave REL modules out. By default every REL in the report is indexed. |
| `modules` | GameCube: the REL files (or folders of them) the game loads, when they are not on the disc beside `original`. |
| `host` | A REL target: the DOL target that loads it (its symbols name the module's references into the DOL). |
| `provisional_name_pattern` | Regex for auto names (default: `fn_`, `lbl_`, `FUN_`, `sub_` + address, ...). |
| `categories` | objdiff progress categories, `[{"id", "name"?, "paths": [glob, ...]}]`: `zkit build` writes them into `objdiff.json`, and each unit is in every category whose `paths` match its path under `src/` (`*` crosses folders; a pattern ending in `/` takes the folder's whole tree). Reports and the progress page then count by category instead of by first folder; the build notes units no category takes. |
| `library_categories` | objdiff progress categories whose units are SDK/runtime libraries (default `sdk`, `runtime`, `msl`). `port-plan` marks their functions `platform`; their hand-written assembly counts as its own reference. |
| `sda_bases` | `{"r2": "0x...", "r13": "0x..."}` when `__init_registers` can't be decoded. |
| `build` | How `zkit build` compiles the target (defaults per platform): `compiler` (GameCube: a CodeWarrior version folder under `compilers`, e.g. `GC/1.3.2`; Switch: a clang path or name), `cflags`, `extra_cflags`, `includes`, `ldflags`, `compilers`, `linker`, `wrapper` (what runs the Windows compilers outside Windows, default wibo), `objdiff_cli`, `compiler_version` (Switch: a string `clang --version` must contain, or a list of them when hosts get different releases proven to compile alike), `source_root` (Switch: the folder the original's `__FILE__` strings start with, e.g. `D:/project/src`; each unit then compiles from a copy under `<build dir>/rooted` whose first line, `#line 1 "<source_root>/<unit>"`, names it as the original's build did, so its citations match on every system; a `units` pattern may give a library built elsewhere its own), `relax` (Switch: `true` when the original's linker relaxed address pairs, as lld does without `--no-relax`: the GOT load of a symbol the module defines became `adrp` + `add`, and an `adrp` + `add` near its target became `nop` + `adr`. The delinked objects then read a `nop` + `adr` whose target is outside its function as the `adrp` + `add` it was, the report's views and every diff of a compiled object take its GOT loads as lld kept them (the module's imports, which the delink lists in `imports.txt`, keep theirs), and `link` relaxes each pair by lld's rules at the original's addresses), `trap` (Switch: the instruction word, in hex, that the original's compiler wrote for a trap where clang writes `brk #1`, such as `"0x00008002"` for `udf #0x8002`. A forked toolchain may encode `__builtin_trap` and the trap clang puts in the deleting destructor of an abstract class this way. Each compile, `zkit try` and `zkit sweep` then write the trap words of the object's code sections so; compile_commands.json keeps the compiler's own command), and `units`: per-unit overrides by glob. `compiler_download` pins the compiler for `zkit build --download` to fetch, check and unpack: one archive for every host (`{"url", "sha256", "folder"?, "strip"?, "members"?}`; default folder `build/compilers/<archive name>`, one leading folder stripped) or archives per host (`{"folder", "linux-x86_64": archive or [archives], "macos-x86_64": ..., "windows-x86_64": ...}`, so one `compiler` path, such as `build/compilers/clang/bin/clang++`, names it on every host; `.exe` may be left off on Windows; an Arm Mac or Windows without its own takes the x86-64 one). An archive is a zip, tarball, Debian package (its data) or NSIS installer (LLVM's Windows releases: the files it installs, read without running it, nothing stripped); an archive's own `folder` puts it elsewhere, such as a library the compiler loads from its `lib` folder. `clang_plugins` (Switch, also per unit) loads zkit's clang pass plugins into every compile, for an original toolchain whose optimizer differs from the stock clang release in one known rule; each is built once with the host C++ compiler (`$CXX`, else `c++`) against the clang's own release headers into `build/tools/clang-plugins` (LLVM 3.9-8, legacy pass manager; on macOS its LLVM symbols resolve against clang when it loads). A Windows `clang.exe` exports none of LLVM's symbols and can load no plugin, so there a plugin's rule is a byte patch to the official release's binary (`clang_plugins/<plugin>.patches.json`, by the binary's SHA-256): the build writes a patched copy beside it, `<name>-<plugin>.exe` (clang drops a trailing `-<word>` from its name to find its mode, so `clang++-bare_return_atexit.exe` still compiles C++), checks each edit's old bytes and the copy's SHA-256, and compiles those units with it; it rewrites the copy when it is missing or changed. For a `clang.exe` zkit has no patch for, the units build without the plugins and the build says they may not match. Patches: `bare-return-atexit` for LLVM 3.9.1's win64 release. `bare-return-atexit`: a guarded static's `__cxa_atexit` registration is removed only when its destructor's body is a bare `ret` (LLVM 9's rule; LLVM 8 and older also remove it when the destructor only calls empty ones, such as empty base destructors). `clang_patches` (Switch, also per unit) names zkit's rules for a part of clang no plugin reaches, such as one code generation pass, for an original toolchain built without or with a different version of it; each is held only as byte patches to official releases' binaries (`clang_patches/<rule>.json`, by the binary's SHA-256) and applies on every system: the build writes a patched copy beside the official binary as for a Windows plugin patch (`clang++-<rule>`; on Windows the plugins' patches come first, `clang++-<plugins>+<rules>.exe`), checks each edit's old bytes and the copy's SHA-256, and compiles those units with it. For a binary zkit has no patch for, the units build with the official one and the build says they may not match. Rules: `no-large-offset-merge` (LLVM 22.1.8: Linux and Windows x86-64, macOS Arm64): AArch64's load/store optimizer without its fifth step, which turns a constant offset built in a register for a register-offset load or store (`mov`, `movk`, `ldr w0, [x8, x9]`) into an `add` of its high part and an immediate-offset access (`add x8, x8, #hi, lsl #12`, `ldr w0, [x8, #lo]`); no option turns that step off. `header_patches` (Switch, also per unit) names zkit's rules for a header of an official library release (pinned in `compiler_download`, such as libc++'s headers) that the original's toolchain shipped written otherwise; each is held only as text edits to exact releases' copies (`header_patches/<rule>.json`: the header's path as the compiler finds it, and patches by the copy's SHA-256): the build finds the header in the target's `includes` (the first that has it), checks each edit's text (found once) and the result's SHA-256, writes the edited copy under `build/tools/header-patches/<rules>`, and searches that folder before the includes, so every other header reads as before (a header that uses `#include_next` cannot be one). For a copy zkit has no patch for, the units build with the release's header and the build says they may not match. Rules: `vector-destruct-end-first` (libc++ 19.1.7): std::vector's tail destruction loops `while (__soon_to_be_end != __new_last)`, where libc++ 16 to 22 write the operands the other way round; clang keeps their order in the loop's compare. |

**Downloads.** `zkit build --download` (or `zkit configure --download`) fetches only what is missing, into the
repository's `build/` folder: the CodeWarrior bundle into `compilers`, `compiler_download`'s archive, and the
pinned tools: objdiff-cli (`build/tools`), and for GameCube wibo (`build/tools`), GNU binutils for powerpc-eabi
(`build/binutils`), m2c and decomp-permuter (`build/tools`, source checkouts at a pinned commit); for Switch,
llvm-objdump and llvm-cxxfilt from a pinned LLVM release (`build/llvm`). `--download-build-tools` fetches only
what building needs (the compilers, wibo, objdiff-cli), not the tools only analysis uses (binutils, m2c,
decomp-permuter, LLVM). A release is refused unless its SHA-256 is
the pinned one, a checkout unless git resolves it to the pinned commit. A tool set here (`wrapper`, `objdiff_cli`,
`m2c`, `permuter`, `objdump`) or already on PATH is never fetched. `build/tools/versions.json` records the
versions fetched; a zkit that pins newer ones fetches them again.

**REL modules.** REL functions have no fixed address, so they are written `module+0xOFFSET` (for example
`mymodule+0x1D0`). zkit reads the REL files themselves: every reference a module makes is in its relocation tables,
and the calls inside one of its sections are in its bytes. Its calls into the DOL, into other modules and within
itself, and its references to DOL globals come from there, so DOL lookups list REL callers, `xrefs` lists REL
readers, and `asm` shows a REL function with every relocated field named. The files are every `.rel` (Yaz0 or not)
in the extracted disc beside `original` (its folder, or the one above `sys/`; a disc image itself is not searched,
`zkit new` extracts one), or what `modules` lists; data a game keeps in files of its own named `.rel` is told apart
by the header. A REL can also be a target of its own (`original` the `.rel`, `host`
the DOL target, its own `symbols` and `splits`, whose `Sections:` block names its sections): `delink` then cuts it
into one object per unit. `zkit rel info FILE` shows what a REL holds; `zkit rel make PLF... --dol ELF --out DIR`
writes the RELs of partially linked modules, as makerel does (`--like` keeps the original header's name offset and
section count).

## Repositories

| Field | Meaning |
| --- | --- |
| `role` | `decomp` or `native`. A `native` repo enables the port tools (`port-plan`, `demand`, `grounding`, `consts`, `drift`, `tiers`, `reuse`; `impact` and `stale` with a `tests` block). |
| `index_paths`, `index_exclude` | What `search` covers (folders or files; exclude takes regexes). |
| `cite_paths`, `code_paths` | Where original addresses (`8xxxxxxx`) count as citations, and which of those are code. |
| `address_pattern` | Regex with one hex group for citations (default: GameCube RAM `8[01]xxxxxx`). |
| `architecture` | Optional native-port include policy: `scan`, `include_roots`, `documents`, and `rules` (`id`, `sources`, `forbidden_includes`, optional `allow_includes`, `reason`). Patterns are regexes; include rules test both spelling and resolved repository-relative paths. |
| `coverage` | Named, project-owned inventory comparisons; see below. Populations and game-format selectors belong here, never in toolkit code. |
| `required_docs` | Repository-relative paths to current architecture/design guides, source layout, engineering/performance standards and contracts. Both brief formats list them and mark missing files. Keep game policy in these documents, not toolkit code. |
| `rules` | Short rules shown in every brief. Keep them short; the repo's `AGENTS.md` stays the contract. |
| `start`, `finish` | Commands shown in the brief. `finish` is the gate `zkit-finish` runs. |
| `finish_sources` | `[{path, after, until}]` sections of docs that must list the same finish commands (`gate` reports drift). |
| `checks` | Lint for `zkit check`: `source_globs`; `forbidden: [{pattern, paths, message}]`; native citations: `require_citation` (new exact-tier functions need an original address, at the definition or its declaration in the file's own header), `citation_min_lines` (shorter functions are exempt, default 6), `citation_exempt` (regex of the marker that declares a function native-only; none by default), `resolve_citations` (`false` silences unresolved-address warnings), `bare_citations` (message shown for `0x`-prefixed citations, when the project cites bare hex), `hold_rule` (`error`, `warning` or `off`: citing decomp that is not ready, in any tier). |
| `quality` | Decomp source debt (`zkit quality`): `paths` and `exclude` (regexes) to measure, `disable` to drop catalog patterns, `patterns: {key: {regex, label, group}}` to add your own, `gate` (`error` makes added debt fail `check`). |
| `hygiene` | What must not be committed (`zkit hygiene`, the commit hooks): `identity` (`Name <email>`, default the repository's git config; `any` for a repository that takes other people's commits, where only AI identities are refused), `subject_max` (72), `body` (commit bodies allowed, default no), `agent_docs` and `dated_docs` (`forbid` or `allow`), `max_docs`, `script_roots`, `script_users`, `ignore`, `forbidden_files`, `allowed_files`, `max_file_kb`, `progress_table` (`forbid` when progress is published by CI: `zkit report --readme` skips the README and any generated `Matched`/`Linked` table is an error). |
| `locks`, `builders` | Build lock files and extra build-tool regexes that `wait` and `activity` watch. |
| `gate_commands` | Extra regexes for your own tools, so `gate` can compare the finish steps your docs list. |
| `router` | `{brief, lane_stats}`: JSON files your own work router writes (`{"next": {"lane", "commands"}}`); the brief shows its lane. |
| `status_doc`, `status_section` | Native: the doc whose active-work section the brief excerpts. |
| `fidelity_tiers` | Native: ordered `{tier, pattern, meaning, verify}`, first match wins; tiers are `exact`, `equivalent`, `liberty`, `infrastructure`. A path no pattern matches is `exact`. |
| `tests` | `{build_dir, include_roots}` with CTest registration and a CMake `compile_commands.json` for `impact`; exact-name plans (`impact` with names, CLI `test-plan`) only need the CTest catalog. Optional `catalog` names a saved JSON catalog relative to the repo; `scan` and `test_paths` (default `tests/`) say where sources and test sources are; `label_order` lists CTest labels to group tests by first (default: each test's first label). Optional `apps` lists the programs people run (for `stale` and the finish gate). A Ninja `build.ninja` adds the link closure: `stale`, and tests whose program links a changed object. |

## Top level

| Field | Meaning |
| --- | --- |
| `m2c` | How to run m2c for `zkit m2c` (GameCube): a command, a path to `m2c.py`, or an argv list such as a project's own adapter `[".venv/bin/python", "tools/m2c_runner.py", "../m2c"]`, run from the decomp root (default: `m2c` on PATH, then an m2c checkout beside a repository). |
| `permuter` | A decomp-permuter checkout for `zkit permute` (GameCube; default: `$PERMUTER_DIR`, then `../decomp-permuter` beside a repository). |
| `knowledge` | Folder of lesson notes (`*.md` with `title/applies/kind` front matter) for `zkit lessons`. |
| `variants` | Named groups of sibling names for `reuse --variants`. |
| `processes` | Extra program names (regexes) that `activity` reports, such as your emulator or test runner. |
| `long_running` | Regexes for processes the brief warns about after 45 minutes. |
| `agents_anywhere` | `true` to report Claude/Codex sessions in any folder, not only inside or above the repos. |

## Full example: a decomp and a PC port

```json
{
  "schema_version": 1,
  "id": "mygame",
  "knowledge": "/path/to/my-zkit-notes/lessons",
  "repositories": {
    "decomp": {
      "root": "/path/to/mygame-decomp", "role": "decomp",
      "index_paths": ["README.md", "docs", "include", "src"],
      "cite_paths": ["docs"],
      "rules": ["Only count a match once it's in the unit that owns the address."],
      "start": ["python configure.py", "ninja"],
      "finish": ["python configure.py && ninja", "git commit"],
      "locks": ["build/.build.lock"],
      "checks": {"source_globs": ["^src/.*\\.(c|cpp|h)$"],
                 "forbidden": [{"pattern": "asm\\s*\\{", "paths": "^src/", "message": "No hand-written assembly."}]}
    },
    "native": {
      "root": "/path/to/mygame-port", "role": "native",
      "index_paths": ["README.md", "docs", "src", "tests"],
      "cite_paths": ["src", "docs", "tests"], "code_paths": ["src"],
      "status_doc": "docs/status.md",
      "rules": ["Cite the original address (8-digit hex) at every ported function."],
      "finish": ["cmake --build build", "ctest --test-dir build"],
      "checks": {"source_globs": ["^src/.*\\.(cpp|hpp)$"], "require_citation": true,
                 "citation_exempt": "INTENTIONAL-DIVERGENCE|NATIVE:"},
      "fidelity_tiers": [
        {"tier": "liberty", "pattern": "^src/ui/"},
        {"tier": "equivalent", "pattern": "^src/render/"},
        {"tier": "infrastructure", "pattern": "^src/platform/"},
        {"tier": "exact", "pattern": "^src/"}],
      "tests": {"build_dir": "build", "include_roots": ["src"]}
    }
  },
  "targets": {
    "game01": {"repository": "decomp", "module": "main", "symbols": "config/GAME01/symbols.txt",
               "report": "build/GAME01/report.json", "original": "orig/GAME01/sys/main.dol"}
  },
  "processes": ["my-emulator"],
  "definition_comment_stops": ["MY_TOOL_MARKER"]
}
```

`definition_comment_stops` lists comment markers your tools write above a function that are not part of it, so
`lookup --body` and `drift` leave them out.

Keep a project file with your own rules, lessons and evals outside this repo (for example next to your decomp), and
point `knowledge` at your lessons folder. `zkit setup <file>` registers it, indexes, and connects Claude Code and
Codex (`zkit use <file>` only registers it).

## Native-port architecture and inventory audits

`zkit check` applies these rules to the lines a change adds (an include the replaced lines already had is
reported as debt); `zkit check native src/simulation` checks every line of a selected system, and
`zkit architecture native --all` reports every include of the configured roots with explicit exceptions,
unresolved quoted headers, system `<...>` headers and macro includes. It checks literal C/C++ includes,
including conditional branches. It is not a compiler or semantic architecture proof. It does not apply
native design refactors to matching decomp.

```json
"architecture": {
  "scan": ["engine"],
  "include_roots": ["engine"],
  "documents": ["native:docs/architecture.md"],
  "rules": [{
    "id": "simulation-device-boundary",
    "sources": "^engine/simulation/",
    "forbidden_includes": "(^|/)device/|^GraphicsAPI/",
    "allow_includes": ["(^|/)device/Events.hpp$"],
    "reason": "Simulation consumes native events; device ownership stays in the backend."
  }]
}
```

`zkit coverage native effects` compares identities read from current project files at every call.
Reference and stage inventories support `regex` with a named `id` capture, or `json` selecting an array
with `pointer` and each identity with `id_pointer` (empty pointers select the whole value). Files may be
repository-relative paths or globs; optional `repo` selects another configured repository. String and
integer identities are accepted. Duplicate identities and empty inventories are errors unless explicitly
permitted with `unique: false` or `allow_empty: true`; unmatched file globs remain errors. Source hashes and
per-identity locations are returned in JSON. Stages must follow their prerequisites; no converter is executed.

```json
"coverage": {
  "effects": {
    "boundary": "Original-derived effect inventory through conversion and runtime registration; execution excluded.",
    "reference": {"files": ["evidence/effects.json"], "format": "json", "pointer": "/effects", "id_pointer": "/id"},
    "stages": [
      {"id": "converted", "inventory": {"files": ["data/effects/*.json"], "format": "json", "pointer": "/ids"}},
      {"id": "registered", "requires": ["converted"], "inventory": {"files": ["build/registered-effects.json"], "format": "json"}}
    ]
  }
}
```

Each stage defaults to requiring `reference`; list prior stage ids in `requires` to expose identities that
appear downstream without their prerequisite. Additional identities are listed separately. Declare the real
population and exclusions: do not choose selectors or allow-empty settings just to make a report green.
`inventory_covered` means the declared identities are present without extraction errors or prerequisite gaps.
It never sets `system_complete` true. Valid decoding, resource lifetime, live admission, original behavior and
successful verification need their own independent evidence and the project's existing import/test tools.
