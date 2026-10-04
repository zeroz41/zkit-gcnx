# Validation

How gcn-zkit is tested, and what was measured for this release.

## Run the checks yourself

```sh
uv run --with-editable . python -m unittest discover -s tests   # 69 tests, synthetic fixtures, no game files needed
python tools/smoke.py                                           # every command against your registered projects
python tools/replay.py extract --since 2026-01-01 --out calls.json   # your agents' real zkit calls
python tools/replay.py compare --old ../old/src --new src --corpus calls.json --project <project file>
python tools/ab_eval.py --suite ../my-evals --cwd ../my-decomp  # same model and tasks, with and without zkit
claude plugin validate .
```

The tests build a small fake decomp and port with a hand-assembled DOL, an objdiff report, dtk asm for a REL and a git
repo, and cover lookup, callers across DOL and RELs, asm, data, xrefs, init and project selection, definitions in
headers and `.inc` files, the port tools (port-plan, demand, check, impact, grounding, consts, suspects, drift),
build waiting, handoffs, hooks and the MCP server over stdio.

`replay compare` and `ab_eval` keep each version's config, cache and state separate, so they never touch your real
setup.

## Results for this release

**Projects.** Two real projects:

- a large game with 757 REL modules, tested at three stages: bootstrapped from the disc with dtk-template (0% matched,
  98% of functions auto-named), an older snapshot at 41% matched, and the finished decomp at 100%;
- a 72%-matched decomp with a PC port that cites the original addresses it implements.

**Setup and speed.**

| Project | `setup` from nothing | Query (warm, median) | Session brief |
| --- | --- | --- | --- |
| New decomp, 48k functions, 757 RELs | 6 s | 90-200 ms | 0.2 s |
| Same game, 41% | 15 s (3,001 source files) | 110-210 ms | 0.7 s |
| Same game, finished | 18 s (3,867 source files) | 120-215 ms | 0.7 s |
| Decomp plus port | 10 s (9,517 files) | 150-400 ms | 0.7-0.9 s |

**Correctness against an independent decoder** (grep over dtk's asm and objdiff's report, not zkit): callers of a
function across the DOL and RELs, caller counts for its callees (1 to 1,555 each), and references to a global from 554
REL modules all matched exactly. Of 400 random functions in the finished decomp, 375 had their definition found, all
on the right line (285 in the unit's file, 90 inline in a header or in an `.inc` the unit includes), 16 were labeled
compiler-generated, and 9 (templates, anonymous namespaces) were not found.

**Agents, with and without gcn-zkit** (Sonnet, graded by 3 Sonnet judges against independently derived answers):

| Project | Without | With |
| --- | --- | --- |
| New decomp (5 tasks) | 5/5, 26 turns, 82 s, $0.46 | 5/5, 20 turns, 61 s, $0.56 |
| 41% (2 tasks) | 1/2 (the miss left out a compiler-generated function on purpose; numbers right), 15 s, $0.13 | 2/2, 20 s, $0.15 |
| Finished (2 tasks) | 2/2, 37 s, $0.21 | 2/2, 18 s, $0.16 |
| Decomp plus port (4 tasks) | 3/4, 34 turns, 308 s, $0.83 | 4/4, 17 turns, 66 s, $0.56 |

On a small decomp, single questions are about even: dtk's asm is searchable text, so grep is a strong baseline for
one-hop questions. The gains come from joins the files don't have: match state, names, sources, citations from a port,
and session state.

**Against the previous version, on real work.** 3,938 distinct calls that Claude Code and Codex agents made on the
decomp-plus-port project, replayed on both versions:

| | Previous | This version |
| --- | --- | --- |
| answered | 3,796 | 3,867 |
| "no match" | 79 | 15 |
| errors | 63 | 56 |
| answers that got worse | - | 0 |

Every path the agents used was compared one by one: port-plan, demand, check, impact, grounding, consts, suspects,
drift, tiers, recipes, lookup, asm, data, names, xrefs, search, read, brief, activity, gate and lessons. Each gave the
same answer or a better one. Differences traced to the live repos changing between the two runs matched once rerun
together. In the transcripts, the missing definition lines this version adds had been followed by a manual grep or
file read 43 times, and every previously failing mixed lookup by a retry. Three rounds of four agent tasks gave 12/12
for both versions at the same time and cost (50 vs 54 turns, 190 vs 186 s, $1.71 each). Under 8 concurrent MCP
clients the two are equal (p50 about 0.1 s).

**Windows.** Run with the official Windows builds of uv, Python and Git (under Wine, not a physical machine).
`uv tool install` brought Python and every dependency by itself; setup, brief, lookups (DOL and REL), asm, xrefs, data,
names, doctor and the session hook all gave the Linux answers, and the test suite passes (the 4 Linux-only build-wait
tests are skipped). The first run found and fixed real Windows bugs: open database files blocking cleanup, git output
decoded with the wrong encoding, `C:/` vs `C:\\` worktree paths, and backslashes in stored paths.

**macOS.** Not run on a Mac. The process listing used there (psutil) was run on Linux and passes the build-wait tests.
Paths through symlinks (macOS's temp folder is one) are handled.
