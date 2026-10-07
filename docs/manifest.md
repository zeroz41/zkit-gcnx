# The project file

`gcn-zkit init` writes one JSON file per decomp to `~/.config/gcn-zkit/projects/<id>.json` (Windows:
`%USERPROFILE%\.config\gcn-zkit\projects`). You rarely need to touch it. Edit it to add your repo's rules, its finish
steps, lint checks or a native port. Running `init` again refreshes what it detected and keeps your edits.

gcn-zkit picks the project from the folder you are in, using the first match:

1. `--project <file>`
2. `$ZKIT_PROJECT`
3. a `zkit.project.json` in this folder or a parent (to keep the file in the repo)
4. a registered project whose repository, or a git worktree of it, contains this folder
5. the default project (`gcn-zkit use <file>`)

`gcn-zkit projects` lists them and marks the one in use. The session hook only speaks inside a registered repo.

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
| `symbols` | dtk `symbols.txt` of the main DOL. Names and data symbols. |
| `report` | objdiff `report.json`. Match state, source files and REL functions. Without it, functions come from `symbols.txt`. |
| `original` | The DOL, or a `.iso`/`.gcm` disc image (the DOL is read in place). Needed for asm, data, callers and xrefs in the DOL. |
| `module` | Name of the main module in the report (dtk `config.yml` `name`, default `main`). |
| `rels` | `false` to leave REL modules out. By default every REL in the report is indexed. |
| `provisional_name_pattern` | Regex for auto names (default: `fn_`, `lbl_`, `FUN_`, `sub_` + address, ...). |
| `sda_bases` | `{"r2": "0x...", "r13": "0x..."}` when `__init_registers` can't be decoded. |

**REL modules.** REL functions have no fixed address, so they are written `module+0xOFFSET` (for example
`mymodule+0x1D0`). Their calls into the DOL and their references to DOL globals come from dtk's relocated
disassembly (`build/<GAMEID>/<module>/asm/`). DOL lookups therefore list REL callers, and `xrefs` lists REL readers.

## Repositories

| Field | Meaning |
| --- | --- |
| `role` | `decomp` or `native`. A `native` repo enables the port tools (`port-plan`, `demand`, `impact`, `grounding`, `suspects`, `consts`, `drift`, `tiers`, `reuse`). |
| `index_paths`, `index_exclude` | What `search` covers (folders or files; exclude takes regexes). |
| `cite_paths`, `code_paths` | Where original addresses (`8xxxxxxx`) count as citations, and which of those are code. |
| `address_pattern` | Regex with one hex group for citations (default: GameCube RAM `8[01]xxxxxx`). |
| `required_docs` | Repository-relative paths to current architecture/design guides, source layout, engineering/performance standards and contracts. Both brief formats list them and mark missing files. Keep game policy in these documents, not toolkit code. |
| `rules` | Short rules shown in every brief. Keep them short; the repo's `AGENTS.md` stays the contract. |
| `start`, `finish` | Commands shown in the brief. `finish` is the gate `zkit-finish` runs. |
| `finish_sources` | `[{path, after, until}]` sections of docs that must list the same finish commands (`gate` reports drift). |
| `checks` | Lint for `gcn-zkit check`: `source_globs`, `require_citation`, `citation_exempt`, `forbidden: [{pattern, paths, message}]`. |
| `locks`, `builders` | Build lock files and extra build-tool regexes that `wait` and `activity` watch. |
| `gate_commands` | Extra regexes for your own tools, so `gate` can compare the finish steps your docs list. |
| `router` | `{brief, lane_stats}`: JSON files your own work router writes (`{"next": {"lane", "commands"}}`); the brief shows its lane. |
| `status_doc`, `status_section` | Native: the doc whose active-work section the brief excerpts. |
| `fidelity_tiers` | Native: ordered `{tier, pattern}`; tiers are `exact`, `equivalent`, `liberty`, `infrastructure`. |
| `tests` | `{build_dir, include_roots}` with CTest registration and a CMake `compile_commands.json` for `impact`; `test-plan` only needs the configured CTest catalog. Optional `catalog` names a saved JSON catalog relative to the repo. |

## Top level

| Field | Meaning |
| --- | --- |
| `knowledge` | Folder of lesson notes (`*.md` with `title/applies/kind` front matter) for `gcn-zkit lessons`. |
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
point `knowledge` at your lessons folder. `gcn-zkit setup <file>` registers it, indexes, and connects Claude Code and
Codex (`gcn-zkit use <file>` only registers it).
