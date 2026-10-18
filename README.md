# zkit

zkit is a toolkit for matching decompilations of GameCube and Switch games, and for native ports built from
them. It works from the original executable alone: it finds the functions and data, cuts the program into
translation units, turns each unit back into the object its compiler wrote, recovers classes and names, and
links everything back into a byte-identical executable, taking every function you have matched from your
compiled code. It also gives AI coding agents (Claude Code and Codex) the evidence they need to match, name and
port code without guessing, and the rules for what may be committed.

It runs locally and never uses the network.

## Results

Measured on Phantasy Star Online Episode I & II Plus (GameCube, 27,572 functions), Twilight Princess and Animal
Crossing:

| | Result |
| --- | --- |
| Analysis from the bare DOL (PSO / TP / AC) | completes on all three |
| Function starts found, against real symbols (PSO / TP / AC) | 99.99% / 99.99% / 99.93% |
| Function sizes exact (PSO / TP / AC) | 99.98% / 99.98% / 99.83% |
| Classes (vtables, constructors, destructors, bases) recovered from PSO | 1,406 |
| Delinked functions of PSO's 3,602 fully matched units that agree with the compiled objects | 17,607 of 17,607 |
| PSO relinked from delinked and compiled objects | byte-identical (SHA-1 `0d85744b…`) |
| PSO code linked from compiled objects | **89.11%** (every exact function, not only whole matched units) |
| REL modules read and written back byte-identical (TP's 757 and PSO's) | 758 of 758 |

The PSO relink takes 23 seconds; discovery on the bare DOL 6.

## What it does

- **Reads originals**: GameCube disc images (files extracted, Yaz0 and RARC unpacked), DOLs and REL modules;
  Switch NSO modules (LZ4 and zstd segments, dynamic symbols and relocations, exception-frame function bounds).
- **Discovers** functions, sections, small-data bases and data objects from a bare DOL, without stopping on
  shared epilogues, jump tables or padding (`zkit discover`).
- **Finds units** from evidence in the original (a CodeWarrior unit keeps its own copy of each literal, data only
  one run of code uses, source paths the code cites), and checks an existing split for units that should be folded
  or split and data no unit claims (`zkit units`).
- **Recovers classes** from the code and writes a header per class, proven with the project's own compiler
  (`zkit classes`).
- **Names** functions and data from other builds: libraries every game links, or a debug build's map
  (`zkit signatures`), and carries renames made in the source back into the symbols (`zkit apply`).
- **Delinks** each unit into the relocatable object its compiler emitted, following PowerPC control flow so an
  address is never paired across a path it does not take (`zkit delink`); REL modules are cut from their own
  relocation tables.
- **Links** the executable back with the project's own linker, each partly matched unit made of its compiled
  exact functions and the original's code for the rest, and checks the DOL byte for byte (`zkit link`).
- **Starts and builds projects**: `zkit new` makes a repository from a disc, a DOL or an NSO (README, commit hooks,
  pinned original, symbols, splits, class headers, target objects); `zkit build` compiles, delinks, reports and
  links it with ninja.
- **Decompiler input**: m2c-ready assembly written from the original (`zkit asmfile`, `zkit m2c`), and Ghidra's C
  next to it (`zkit decompile`).
- **Reports progress** from objdiff reports: matched and linked code and data, exact functions and units, tracked
  by address so renames and folds don't hide regressions (`zkit progress`, `zkit report`).

Not finished yet: relinking a whole Switch module and writing its NSO back out; disassembly still uses GNU
binutils' `powerpc-eabi-objdump`.

## Install

You need [uv](https://docs.astral.sh/uv/getting-started/installation/), git, and ninja to build projects.

```sh
uv tool install git+https://github.com/zeroz41/gc-switch-tool-zkit
```

Start a new decomp from your own copy of a game:

```sh
zkit new game.iso mygame/       # or main.dol, or a Switch main NSO
cd mygame && zkit build
```

Or point zkit at an existing decomp (and optionally its port):

```sh
cd path/to/your-decomp
zkit setup                          # the decomp
zkit setup --native ../your-port    # or the decomp and its port
```

`setup` writes the project file (in zkit's own config folder, never in your repo), builds the index, and installs
the plugin for Claude Code and Codex, whichever you have. Restart them in the project folder. `zkit doctor`
checks everything and prints the fix for anything missing.

Optional: [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) 11.3+ for `zkit decompile`
(GameCube also needs the [GameCube Loader](https://github.com/Cuyler36/Ghidra-GameCube-Loader/releases)
extension), installed with `uv tool install --force 'zkit[ghidra] @ git+https://github.com/zeroz41/gc-switch-tool-zkit'`;
[m2c](https://github.com/matt-kempster/m2c) for `zkit m2c`.

## Use

### Structure

| You want | Command |
| --- | --- |
| A new decomp from the original | `zkit new game.iso mygame/` |
| Build it: target objects, compiled units, report, relinked executable | `zkit build` |
| Functions, sections and data objects from a bare DOL | `zkit discover --out symbols.txt` |
| Target objects for every unit, and objdiff's project file | `zkit delink --out build/target --objdiff objdiff.json` |
| The executable relinked, every exact function from compiled code, checked | `zkit link --out build/link` |
| Units proposed from the original; what is wrong with the current split | `zkit units`, `zkit units --check` |
| Classes against the current names; a proven header per class | `zkit classes`, `zkit classes --headers include/classes --prove` |
| Names from another build or the libraries every game links | `zkit signatures build sdk --image other.dol --symbols other/symbols.txt`, `zkit signatures match` |
| Renames made in the source, back into the symbols | `zkit apply`, `zkit apply --write` |
| A fresh split, symbols and headers in one folder | `zkit analyze --out fresh/` |
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

These only read, except `handoff`, `report`, `new`, `build`, `delink`, `link`, `analyze`, `apply --write`,
`objects --save`, `signatures build` and `cache --prune`, which write to zkit's own folders, the project or the
folder you name.

| You want | Command |
| --- | --- |
| Where things stand, who else is working, what was left | `zkit brief` |
| Everything about a function | `zkit lookup 0x80012345` or `zkit lookup MyClass::update` |
| Where the source defines and uses it | `zkit refs 0x80012345` |
| Original instructions or data | `zkit asm 0x80012345`, `zkit data 0x80345678 --type f32 --count 8` |
| m2c's or Ghidra's C for an original function | `zkit m2c 0x80012345`, `zkit decompile 0x80012345` |
| A compiled function against the original | `zkit compiled 0x80012345` |
| Check a candidate outside the tree | `zkit try 0x80012345 candidate.cpp` |
| A unit, exact units that don't link, unclaimed data | `zkit unit game/MyClass`, `zkit unit --blocked`, `zkit unit --gaps` |
| Decompiler debt left in the source | `zkit quality`, `zkit quality --since HEAD~20` |
| Prove a change kept every object identical | `zkit objects --save`, build, `zkit objects --compare` |
| What must not be committed or left behind | `zkit hygiene` |
| What to run before ending | `zkit gate` |
| A note for the next session | `zkit handoff decomp "matched X; next: Y"` |

With a port:

| You want | Command |
| --- | --- |
| Is the decomp ready for this feature, and what to reuse | `zkit port-plan 0x80012345` |
| What the port is waiting on from the decomp | `zkit demand` |
| How proven the port is, and where it probably differs from the original | `zkit grounding`, `zkit consts src/combat` |
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
- [docs/project-file.md](docs/project-file.md): the project file (targets, build, rules, checks, hygiene, ports).

GPL-3.0.
