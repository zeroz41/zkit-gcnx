# zkit

zkit is a toolkit for matching decompilations of GameCube and Switch games, and for native ports built from
them. It works from the original executable itself: it cuts it into translation units, turns each unit back into
the relocatable object its compiler wrote, recovers classes and names, and measures your compiled code against
it. On top of that it gives AI coding agents (Claude Code and Codex) the evidence they need to match, name and
port code without guessing, and the rules for what may be committed.

It runs locally and never uses the network.

## What it does

- **Reads originals**: GameCube DOLs (also straight from a disc image) and Switch NSO/ELF modules (LZ4 and zstd
  segments, dynamic symbols and relocations, exception-frame function bounds, PLT stubs).
- **Delinks**: one relocatable object per unit of a split, as the compiler emitted it, with every reference
  turned back into a relocation. These are the targets objdiff compares your compiled objects with. PowerPC
  code is read along its control flow, so an address is never paired across a path it does not take. On the 3,602
  fully matched units of a 27,000-function GameCube decomp, every one of the 17,607 functions agrees with the
  compiled object (983 differ only in a symbol's name), and all 7,054 data pointers checked are found (one
  extra word is taken for a pointer).
- **Finds units**: proposes translation-unit boundaries from evidence in the original (a CodeWarrior unit keeps
  its own copy of each literal, data only one run of code uses, source paths the code cites), and checks an
  existing split for units that should be folded or split and data no unit claims.
- **Recovers classes**: class tables, constructors, destructors and base classes from the code; writes a header
  per class and proves them with the project's compiler (tables, pointer offsets and sizes).
- **Scores** a split against a reference (another split or a CodeWarrior linker map) and an objdiff report.
- **Reports progress**: matched and linked code and data bytes, exact functions and units, per category, as text
  or a browsable HTML page, with changes tracked by address so renames and folds don't hide regressions.
- **Serves agents**: an MCP server and a CLI over the decomp, the original and the port (below).

- **Starts projects**: `zkit new` makes a repository from the original alone: a GameCube disc is extracted (its
  Yaz0 files and RARC archives unpacked), the project is registered, and the functions, units, symbols, splits,
  class headers and every unit's target object are written.

Being built: GameCube function discovery from a bare executable (until it lands, GameCube structure tools start
from an existing `symbols.txt`; Switch modules carry their own function bounds), relinking to a byte-identical
executable with function-level linking, REL modules, and library naming.

## Install

You need [uv](https://docs.astral.sh/uv/getting-started/installation/) and git.

```sh
uv tool install git+https://github.com/zeroz41/gc-switch-tool-zkit
cd path/to/your-decomp
zkit setup                          # the decomp
zkit setup --native ../your-port    # or the decomp and its port
```

`setup` writes the project file (in zkit's own config folder, never in your repo), builds the index, and installs
the plugin for Claude Code and Codex, whichever you have. Restart them in the project folder. `zkit doctor`
checks everything and prints the fix for anything missing.

Optional: [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) 11.3+ for `zkit decompile`
(GameCube also needs the [GameCube Loader](https://github.com/Cuyler36/Ghidra-GameCube-Loader/releases)
extension for its Gekko language), installed with
`uv tool install --force 'zkit[ghidra] @ git+https://github.com/zeroz41/gc-switch-tool-zkit'`.

## Use

### Structure

| You want | Command |
| --- | --- |
| A new decomp from the original | `zkit new game.iso mygame/`, `zkit new main.nso mygame/` |
| Functions, sections and data objects from a bare DOL, as a symbols.txt | `zkit discover --out symbols.txt` |
| Target objects for every unit (and objdiff's project file) | `zkit delink --out build/target --objdiff objdiff.json` |
| The original rebuilt with the project's linker, every exact function from compiled code, checked byte for byte | `zkit link --out build/link` |
| Units proposed from the original | `zkit units`, `zkit units --splits splits.txt` |
| What is wrong with the current split | `zkit units --check` |
| Classes against the current names | `zkit classes` |
| A header per class, proven with the compiler | `zkit classes --headers include/classes --prove` |
| Names from other builds (libraries every game links, a debug build's map), cached once per donor | `zkit signatures build sdk --image other.dol --symbols other/symbols.txt`, `--map game.MAP`, `--objects libs/` |
| Names those donors prove for this game | `zkit signatures match`, `zkit names --signatures` |
| A fresh split, symbols and headers in one folder | `zkit analyze --out fresh/` |
| Renames made in the source, back into the symbols | `zkit apply`, `zkit apply --write` |
| How close a split is to a reference | `zkit score fresh/ config/ --report build/report.json` |
| Progress, and what changed since a baseline | `zkit progress`, `zkit progress --since session --check` |
| A browsable progress page | `zkit report --out build/progress` |

### Agents

Agents get a short brief at session start and these skills: `zkit-resume`, `zkit-recover-function`,
`zkit-clean-source`, `zkit-port-system`, `zkit-start-project` and `zkit-finish`. A short prompt is enough:

```
Continue the decomp. Use zkit-resume, then zkit-recover-function. Go for big wins.
Naming, folding and data matching are all wanted; move code to its real units.
Try to discover new wins and better methods if stuck or slowed down. Finish with zkit-finish.
```

```
Continue the port on the next milestone in its status doc. Use zkit-resume, then zkit-port-system.
Shared systems, clean architecture, no one-off hard-coded fixes (prefer full shapes and real fixes).
If you match decomp functions or find behavior, give it back to the decomp repo.
Don't run processes that use all the RAM, and don't rerun the same tests over and over. Finish with zkit-finish.
```

```
Clean up the decomp source in large proven steps. Use zkit-clean-source. Finish with zkit-finish.
```

The rules behind the skills: `zkit contract decomp` and `zkit contract port`.

### Evidence

Run them in your repo. They only read, except `handoff`, `report`, `delink`, `link`, `analyze`, `apply --write`,
`objects --save`, `signatures build` and `cache --prune`, which write to zkit's own folders, the symbols file or
the folder you name.

| You want | Command |
| --- | --- |
| Where things stand, who else is working, what was left | `zkit brief` |
| Everything about a function | `zkit lookup 0x80012345` or `zkit lookup MyClass::update` |
| Where the source defines and uses it | `zkit refs 0x80012345` |
| Original instructions or data | `zkit asm 0x80012345`, `zkit data 0x80345678 --type f32 --count 8` |
| m2c's C for an original function (GameCube) | `zkit m2c 0x80012345` |
| Ghidra's C for an original function | `zkit decompile 0x80012345` |
| An assembly file for a decompiler (GameCube) | `zkit asmfile 0x80012345 --out fn.s` |
| A compiled function against the original | `zkit compiled 0x80012345` |
| Check a candidate outside the tree | `zkit try 0x80012345 candidate.cpp` |
| A unit, exact units that don't link, unclaimed data | `zkit unit game/MyClass`, `zkit unit --blocked`, `zkit unit --gaps` |
| Decompiler debt left in the source | `zkit quality`, `zkit quality --since HEAD~20` |
| Prove a change kept every object identical | `zkit objects --save`, build, `zkit objects --compare` |
| What must not be committed or left behind | `zkit hygiene` |
| What to run before ending | `zkit gate` |
| A note for the next session | `zkit handoff decomp "matched X; next: Y"` (no text prints the last note) |

With a port:

| You want | Command |
| --- | --- |
| Is the decomp ready for this feature, and what to reuse | `zkit port-plan 0x80012345` |
| What the port is waiting on from the decomp | `zkit demand` |
| Where the port probably differs from the original | `zkit suspects`, `zkit consts src/combat` |
| What changed in the decomp that the port must re-check | `zkit drift` |
| The tests that cover a change | `zkit impact` |
| Is the build older than the code? | `zkit stale` |
| Lint the change against the project's rules | `zkit check` |

`zkit install git-hook --write <repo>` adds a pre-commit check and a commit-message check (one short line, the
project's identity, no AI co-author).

## Update or remove

- Update: `uv tool upgrade zkit`, then `zkit setup --refresh-agents` and restart the agents.
- Remove: `uv tool uninstall zkit`, `claude plugin uninstall zkit@zkit`, `codex plugin remove zkit@zkit`, and
  delete `~/.config/zkit`, `~/.cache/zkit` and `~/.local/state/zkit`.

## More

- [docs/architecture.md](docs/architecture.md): how zkit is built and what each answer does and doesn't prove.
- [docs/project-file.md](docs/project-file.md): the project file (targets, rules, finish gate, checks, hygiene,
  ports).

GPL-3.0.
