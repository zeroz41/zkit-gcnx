# zkit

zkit helps AI coding agents (Claude Code and Codex) work on matching decompilations of console games, and on
native ports written from them, without guessing. It supports GameCube/Wii projects built with
[decomp-toolkit](https://github.com/encounter/decomp-toolkit) and [objdiff](https://github.com/encounter/objdiff),
and Switch projects built with clang.

It indexes your decomp, the original executable and your port, and answers what an agent would otherwise grep or
script for: where a function is defined and who calls it, the original bytes and data, how a compiled function
differs from the original, what a session changed, and whether a port is about to rest on decomp code that isn't
clean yet. It also carries the rules: what "done" means, how candidates are written and proven, and what must
never be committed.

It runs locally, reads your files, and never uses the network.

## Install

You need [uv](https://docs.astral.sh/uv/getting-started/installation/) and git.

```sh
uv tool install git+https://github.com/zeroz41/gcn-zkit
cd path/to/your-decomp
zkit setup                          # the decomp
zkit setup --native ../your-port    # or the decomp and its port
```

`setup` writes the project file (in zkit's own config folder, never in your repo), builds the index, and installs
the plugin for Claude Code and Codex, whichever you have. Restart them in the project folder. `zkit doctor`
checks everything and prints the fix for anything missing.

Optional: [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) 11.3+ for `zkit decompile`
(GameCube also needs the [GameCube Loader](https://github.com/Cuyler36/Ghidra-GameCube-Loader/releases)
extension for its Gekko language), installed with `uv tool install --force 'zkit[ghidra] @
git+https://github.com/zeroz41/gcn-zkit'`.

## Use

Agents get a short brief at session start and these skills: `zkit-resume`, `zkit-recover-function`,
`zkit-clean-source`, `zkit-port-system`, `zkit-start-project` and `zkit-finish`. A short prompt is enough:

```
Continue the decomp. Use zkit-resume, then zkit-recover-function. Finish with zkit-finish.
```

```
Continue the port on the next milestone in its status doc. Use zkit-resume, then zkit-port-system.
Finish with zkit-finish.
```

```
Clean up the decomp source in large proven steps. Use zkit-clean-source. Finish with zkit-finish.
```

The rules behind the skills: `zkit contract decomp` and `zkit contract port`.

### Commands

Run them in your repo. They only read, except `handoff`, `report`, `objects --save` and `cache --prune`, which
write to zkit's own folders or the folder you name.

| You want | Command |
| --- | --- |
| Where things stand, who else is working, what was left | `zkit brief` |
| Everything about a function | `zkit lookup 0x80012345` or `zkit lookup MyClass::update` |
| Where the source defines and uses it | `zkit refs 0x80012345` |
| Original instructions or data | `zkit asm 0x80012345`, `zkit data 0x80345678 --type f32 --count 8` |
| Ghidra's C for an original function | `zkit decompile 0x80012345` |
| A compiled function against the original | `zkit compiled 0x80012345` |
| Check a candidate outside the tree | `zkit try 0x80012345 candidate.cpp` |
| A unit, exact units that don't link, unclaimed data | `zkit unit game/MyClass`, `zkit unit --blocked`, `zkit unit --gaps` |
| Progress, and what changed since a baseline | `zkit progress`, `zkit progress --since session --check` |
| A browsable progress page | `zkit report --out build/progress` |
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
- [docs/project-file.md](docs/project-file.md): the project file (rules, finish gate, checks, hygiene, ports).

GPL-3.0.
