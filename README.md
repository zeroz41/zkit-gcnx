# gcn-zkit

Makes AI coding agents (Claude Code, Codex) fast and accurate on two kinds of GameCube work:

- **Decompiling** a game with [decomp-toolkit](https://github.com/encounter/decomp-toolkit) (dtk).
- **Porting** it: writing a PC version whose behavior matches the decomp, number for number.

## Quick start

You need [uv](https://docs.astral.sh/uv/getting-started/installation/), git, and a dtk decomp you've built once. Then:

```sh
uv tool install git+https://github.com/zeroz41/gcn-zkit
cd path/to/your-decomp
gcn-zkit setup                          # just the decomp
gcn-zkit setup --native ../your-port    # or the decomp plus your PC port
```

Restart Claude Code or Codex in the decomp or port folder and ask:

```
Continue the decomp. Use zkit-resume, then zkit-recover-function. Finish with zkit-finish.
```

or, for the port:

```
Continue the port. Use zkit-resume, then zkit-port-system. Finish with zkit-finish.
```

That's it. The rest of this page explains what you get, more prompts, and how to fix things if a step doesn't work.

## What it is

A local tool that joins your decomp, the original game (with its REL modules) and, if you have one, your PC port. It
answers what an agent needs in one call.

**For the decomp:**

- **lookup**: any function by address or name. Its match %, the file and line that define it (including inline
  methods in headers), every caller (including from RELs), callees, and the vtables that hold it. On a vtable or table,
  every slot it points to.
- **asm / data**: the original instructions with symbols and constants resolved, and the original data.
- **xrefs**: who reads or writes a global.
- **names**: find functions by name, file or match state, for example the closest near-misses.

**For a port that must behave like the original** (the port cites the original addresses it implements, like
`// 800C1C4C`):

- **port-plan**: before porting a feature, the original's call tree, with each step marked: reuse what the port
  already has, decompile it first, or port it.
- **suspects / consts / drift**: where the port probably behaves slightly differently from the real game. That covers
  code built on functions the decomp hasn't matched yet, numbers that don't match the constants the original loads,
  and port code written against decomp code that has changed since.
- **grounding / demand**: how much of the port rests on proven decomp code, and which decomp functions the port is
  waiting on.
- **impact / check / tiers**: the exact tests to run for a change, lint against the port's rules, and which code must
  match the original exactly and which is free to differ (rendering, UI).

**For every session:** the **brief** is handed to each new agent. It covers progress, other agents and builds running,
uncommitted work, and the last session's notes, so no session starts from zero.

It works on brand-new, in-progress and finished decomps, with or without a port. It runs on your machine, only reads
your files, and never uses the network.

## Does it help?

Same model, same questions, with and without gcn-zkit ([details](docs/validation.md)):

| Project | Without gcn-zkit | With gcn-zkit |
| --- | --- | --- |
| Brand new decomp, 0% matched, 757 RELs (5 questions) | 5/5 right, 82 s, $0.46 | 5/5 right, 61 s, $0.56 |
| Same game, 41% matched (2 questions) | 2/2 right¹, 15 s, $0.13 | 2/2 right, 20 s, $0.15 |
| Same game, fully matched (2 questions) | 2/2 right, 37 s, $0.21 | 2/2 right, 18 s, $0.16 |
| A 72%-matched decomp with a PC port built to match it (4 questions) | 3/4 right, 308 s, $0.83 | 4/4 right, 66 s, $0.56 |

Single questions on a small decomp come out about even, because dtk's output is already searchable text. The gains
grow with the project, and are largest with a PC port, where questions span the decomp, the original and the port at
once.

It's also checked against real work: 3,938 calls that agents made on the decomp-plus-port project, replayed on this
version and the previous one. This version answers every one the previous one did, plus the ones it missed:
definition lines agents otherwise found by hand, and lookups that mix names and addresses.

¹ Graded as a miss for leaving out a compiler-generated function on purpose; its numbers were right.

## Requirements

| You need | Windows | macOS | Linux |
| --- | --- | --- | --- |
| **uv** (installs gcn-zkit and its Python) | `powershell -c "irm https://astral.sh/uv/install.ps1 \| iex"` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **git** | [git-scm.com](https://git-scm.com/downloads/win) | `xcode-select --install` | your package manager (`sudo apt install git`, ...) |
| **A dtk decomp, built once** | `python configure.py`, then `ninja` in the decomp (its README lists what that needs) | same | same |
| Claude Code or Codex (optional) | [Claude Code](https://docs.claude.com/en/docs/claude-code), [Codex](https://github.com/openai/codex) | same | same |

uv brings the right Python and every package gcn-zkit needs. The decomp's own build downloads dtk, the compilers and
binutils. No decomp yet? Start one from [dtk-template](https://github.com/encounter/dtk-template).

## Install and set up, step by step

1. Install the command: `uv tool install git+https://github.com/zeroz41/gcn-zkit`.
   If `gcn-zkit` is then "not found", run `uv tool update-shell` and open a new terminal.
2. In your decomp's folder, run `gcn-zkit setup`. It indexes the decomp (a few seconds to a minute) and connects
   Claude Code and Codex, whichever you have.
3. Restart them. In Codex, accept the startup-hook prompt once.
4. Run `gcn-zkit doctor`. Anything that isn't OK comes with the command that fixes it.

For more decomps, run `setup` in each one. gcn-zkit picks the right one from the folder you're in.

Have your own project file, with your rules, finish steps, lessons or a port (see [docs/manifest.md](docs/manifest.md))?
Keep it outside this repo and run `gcn-zkit setup path/to/your.project.json`. That's the same full install.

## Use

Your agent starts with the brief, the tools and four skills: `zkit-resume`, `zkit-recover-function`, `zkit-finish`,
and `zkit-port-system` for PC ports. The brief carries required architecture/standards references, the repo's rules, finish steps, other agents and
leftover work, so a short prompt is enough. Paste one of these:

**Decompiling:**

```
Continue the decomp. Use zkit-resume, then zkit-recover-function.
Go for big wins. If the port is waiting on functions, work the zkit demand list.
Keep any verified work you find. Finish with zkit-finish.
```

**Working on the PC port:**

```
Continue the port on the next milestone in its status doc.
Use zkit-resume, then zkit-port-system: check zkit grounding for the system,
run zkit port-plan before porting, and reuse the code that already owns the behavior.
Automate import dependencies through the project pipeline; check configured architecture and coverage.
Test the live path with zkit impact. Finish with zkit-finish.
```

**Finding behavior in the port that's slightly off from the real game:**

```
Use zkit-port-system. Run zkit suspects and zkit drift on the port. For the top items:
decompile-first ones go to the decomp first (zkit-recover-function), then re-port and
re-test with zkit impact. Fix near-miss constants against the original. Finish with zkit-finish.
```

To leave a note when you stop early, say: *"zkit handoff: what you did and what's next."* The next session sees it.

### Commands you can run yourself

Run these inside the repo. They only read, except `handoff`.

| You want to know | Type |
| --- | --- |
| Where things stand, who else is working, what's left over | `gcn-zkit brief` |
| Is everything set up? (each problem comes with its fix) | `gcn-zkit doctor` |
| Everything about a function | `gcn-zkit lookup MyClass::update` or `gcn-zkit lookup 0x80012345` |
| A function in a REL | `gcn-zkit lookup mymodule+0x1D0` |
| What's in a vtable | `gcn-zkit lookup __vt__7MyClass` |
| The closest near-misses in a file | `gcn-zkit names --unit my_file --below 100 --sort match` |
| Original disassembly / data | `gcn-zkit asm 0x80012345` / `gcn-zkit data 0x80345678 --type str` |
| Who reads or writes a global | `gcn-zkit xrefs g_gameState` |
| Search docs and source | `gcn-zkit search player jump` |
| Is someone else building? Wait until it's free | `gcn-zkit wait decomp` |
| Other agents, builds, locks, stranded worktrees | `gcn-zkit activity` |
| Check a port system against its configured include boundaries | `gcn-zkit architecture native src/world` |
| Find missing import/integration entries in a declared inventory | `gcn-zkit coverage native effects` |
| Validate exact tests and plan their parallel prebuilds (no execution) | `gcn-zkit test-plan native movement collision --jobs 4` |
| What must run before ending a session | `gcn-zkit gate` |
| Leave a note for the next session | `gcn-zkit handoff decomp "matched X; next: Y"` |

With a PC port (`setup --native`), run these inside the port:

| You want to know | Type |
| --- | --- |
| What to reuse, port or decompile first for a feature | `gcn-zkit port-plan 0x80012345` |
| What the port is waiting on from the decomp | `gcn-zkit demand` |
| Which systems rest on unproven decomp code | `gcn-zkit grounding` |
| **Where the port probably behaves slightly wrong, and what to do** | `gcn-zkit suspects` |
| Are the port's numbers the real game's numbers? | `gcn-zkit consts src/combat` |
| What changed in the decomp that the port must re-check | `gcn-zkit drift` (after re-checking: `gcn-zkit drift --accept`) |
| Which tests cover my change, and who else uses that code | `gcn-zkit impact` |
| What must match the original exactly, and where I'm free | `gcn-zkit tiers src/camera` |
| Is my change breaking the repo's rules? | `gcn-zkit check` |
| Copy-pasted code that should be shared | `gcn-zkit reuse` |

Optional: block commits that break the port's rules with `gcn-zkit install git-hook --write <port folder>`
(`git commit --no-verify` skips it once). The rules, finish steps and lint checks live in the project file; see
[docs/manifest.md](docs/manifest.md).

## Update or remove

- **Update:** `uv tool upgrade gcn-zkit`, then `gcn-zkit setup --refresh-agents` in each decomp.
  From a local checkout: `uv tool install --force --editable /path/to/gcn-zkit`, then
  `gcn-zkit setup /path/to/project.json --refresh-agents --plugin-source /path/to/gcn-zkit`.
  Restart both agents. `gcn-zkit doctor` shows the loaded Python path and plugin cache versions/content.
- **Remove:** `uv tool uninstall gcn-zkit`, then `claude plugin uninstall gcn-zkit@gcn-zkit` and/or
  `codex plugin remove gcn-zkit@gcn-zkit`. To also remove its notes and index, delete `~/.config/gcn-zkit`,
  `~/.cache/gcn-zkit` and `~/.local/state/gcn-zkit` (on Windows these are in your user folder).

## Troubleshooting

| Problem | Fix |
| --- | --- |
| "not a decomp-toolkit project" | Run it in the decomp folder, the one with `configure.py` and `config/<GAMEID>/config.yml`. |
| No match %, source files or REL functions | Build the decomp once (`python configure.py`, then `ninja`), then `gcn-zkit setup` again. |
| The agent doesn't list gcn-zkit | Check that `gcn-zkit --version` works in a new terminal, then fully restart the agent. |
| No brief at session start | Start the agent inside the decomp folder. Elsewhere gcn-zkit stays silent on purpose. |

## More

- [docs/design.md](docs/design.md): how it works, and what each answer does and doesn't prove
- [docs/manifest.md](docs/manifest.md): the project file `setup` writes (rules, finish steps, lint checks, PC ports)
- [docs/validation.md](docs/validation.md): tests and measurements
- Tested on Linux and Windows. CI runs the tests on Linux, macOS and Windows.

GPL-3.0 licensed.
