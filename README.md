# zkit

zkit is a command-line tool for decompiling GameCube and Switch games, and for building native ports from those
decomps. It also gives AI coding agents (Claude Code, Codex, or any MCP agent) the evidence they need to work on a
decomp without guessing.

## What it does

- **Starts a decomp from your own copy of a game.** Give it a disc image and it finds the functions, splits the
  program into units (source files), recovers classes and names, and relinks everything into a byte-identical
  executable. If the disc ships a linker map of another build (some games carry a debug build's `.MAP`), zkit
  takes unit names, function names and data sizes from it wherever that build matches yours.
- **Builds and checks the decomp.** It fetches the compilers and tools the platform needs, compiles your source,
  compares it with the original function by function (objdiff), and relinks the game to prove nothing broke.
- **Helps you match functions.** It shows the original code, gives a starting C version (m2c, Ghidra), compiles
  candidates without touching your tree, and runs decomp-permuter on near-misses.
- **Keeps the work honest.** Progress is counted by original address, so renames and file moves never look like
  losses, and a finish gate checks what a session leaves behind.


It runs locally. It only uses the network when you ask it to download tools (`zkit build --download`), and each
download is pinned and checked against its hash.

## Install

You need [uv](https://docs.astral.sh/uv/getting-started/installation/), git and ninja. Then:

```sh
uv tool install git+https://github.com/zeroz41/gc-switch-tool-zkit
```

The compilers and tools a project needs are fetched into that project's `build/` folder by
`zkit build --download`. Only the tools for the game's platform are fetched.

To let your agent use zkit, install the plugin (tools, skills and a session brief):

```sh
# Claude Code
claude plugin marketplace add zeroz41/gc-switch-tool-zkit
claude plugin install zkit@zkit

# Codex
codex plugin marketplace add zeroz41/gc-switch-tool-zkit
codex plugin add zkit@zkit
```

Any other MCP agent can use `zkit serve`. `zkit setup` (below) installs the plugin for you.

## Update

```sh
uv tool upgrade zkit
zkit setup --refresh-agents
```

## Use

**A new decomp**, from your own copy of the game:

```sh
zkit new game.iso mygame/
cd mygame
zkit build --download
```

**An existing decomp** (and its port, if there is one):

```sh
zkit setup ~/code/mygame-decomp
zkit setup ~/code/mygame-decomp --native ~/ports/mygame-port
```

If you have a linker map from another build of the same game, `zkit units --map map.MAP` shows what it would
change, and `--write` applies it. Units that already have source in `src/` are never changed.

**With an agent**, open it in the project folder and give it a short prompt:

```
Continue the decomp. Use zkit-resume, then zkit-recover-function. Go for big wins.
Naming, folding and data matching are all wanted; move code to its real units. Finish with zkit-finish.
```

```
Continue the port on the next milestone in its status doc. Use zkit-resume, then zkit-port-system.
Shared systems, no one-off fixes. Give matched functions and found behavior back to the decomp. Finish with zkit-finish.
```

```
Clean up the decomp source in large proven steps. Use zkit-clean-source. Finish with zkit-finish.
```

**By hand**, the commands you'll use most:

| | |
| --- | --- |
| `zkit brief` | where things stand |
| `zkit lookup 0x80012345` | everything about a function |
| `zkit m2c 0x80012345` | a C starting point for a GameCube function |
| `zkit try 0x80012345 f.cpp` | compile a candidate and compare it with the original |
| `zkit compiled 0x80012345` | your built function against the original |
| `zkit progress` | how much is matched and linked |
| `zkit report --readme` | the browsable progress page, and the progress table in your README |
| `zkit build` | build, check and relink the project |
| `zkit gate` | what to run before you stop |

`zkit --help` lists everything, and `zkit doctor` checks your setup and says how to fix what's missing.

## Remove

`uv tool uninstall zkit`, remove the zkit plugin from your agent, and delete `~/.config/zkit`, `~/.cache/zkit`
and `~/.local/state/zkit`.

More: [how zkit works](docs/architecture.md), [the project file](docs/project-file.md). GPL-3.0.
