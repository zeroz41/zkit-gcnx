# zkit

zkit helps you decompile GameCube and Switch games and build native ports from them. It works from the original
game file alone: it finds the functions, splits the program into units, recovers classes and names, and links
everything back into a byte-identical executable. It also gives AI coding agents the evidence
they need to work without guessing.

It runs locally and only uses the network when you ask it to download compilers (`zkit build --download`).

## Results

On Phantasy Star Online Episode I & II Plus (GameCube, 27,572 functions):

- 99.99% of function starts and 99.97% of function sizes found from the bare DOL.
- 1,406 classes recovered from the code.
- The executable relinked byte-identical in 23 seconds, with 89.11% of its code taken from compiled source.

Twilight Princess and Animal Crossing come out about the same.

## Install

You need [uv](https://docs.astral.sh/uv/getting-started/installation/) and git, and ninja to build projects.

```sh
uv tool install git+https://github.com/zeroz41/gc-switch-tool-zkit
```

Start a new decomp from your own copy of a game:

```sh
zkit new game.iso mygame/
cd mygame && zkit build
```

Or use an existing decomp (and its port, if it has one):

```sh
cd path/to/your-decomp
zkit setup                          # the decomp
zkit setup --native ../your-port    # the decomp and its port
```

### Connect your agent

`zkit setup` installs the zkit plugin (tools, skills and a session brief) in your agent. To do it yourself, for
example after `zkit new`, add `zeroz41/gc-switch-tool-zkit` as a plugin marketplace in your agent and install
`zkit@zkit` from it.

Restart your agent in the project folder. `zkit doctor` checks everything and tells you how to fix
what's missing.

## Use with agents

A short prompt is enough:

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
Find where the port behaves differently from the original. Use zkit-port-system.
Run zkit grounding and zkit drift, fix what they find, and test with zkit impact. Finish with zkit-finish.
```

```
Clean up the decomp source in large proven steps. Use zkit-clean-source. Finish with zkit-finish.
```

## Commands

`zkit --help` lists them all. The ones you'll use most:

| | |
| --- | --- |
| `zkit brief` | where things stand |
| `zkit lookup 0x80012345` | everything about a function |
| `zkit compiled 0x80012345` | your compiled function against the original |
| `zkit progress` | how much is matched and linked |
| `zkit build` | build, check and relink the project |
| `zkit gate` | what to run before you stop |

## Update or remove

- Update: `uv tool upgrade zkit`, then `zkit setup --refresh-agents`.
- Remove: `uv tool uninstall zkit`, remove the zkit plugin from your agent, and delete `~/.config/zkit`,
  `~/.cache/zkit` and `~/.local/state/zkit`.

More: [how zkit works](docs/architecture.md), [the project file](docs/project-file.md).

GPL-3.0.
