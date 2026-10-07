# Validation

How gcn-zkit is tested, and what was measured for this release.

## Run the checks yourself

```sh
uv run --with-editable . python -m unittest discover -s tests   # synthetic fixtures, no game files needed
python tools/smoke.py                                           # every command against your registered projects
python tools/replay.py extract --since 2026-01-01 --until 2026-10-07 --repo-root /my/repo --out calls.json   # your agents' real zkit calls
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

## Current measurements (0.6.0)

The feature review revisited the owner's composition/reuse requests, automatic future-asset import requests,
protocol-to-native boundary complaints and quest identity/shape concerns, then inspected the actual architecture
contract, technical debt, importer and installed catalogs. It selected executable include-policy checks and
cross-stage inventory comparisons. Existing lookup/port-plan/reuse, test-plan and importer publication already
cover adjacent work; the toolkit does not introduce a second game importer or execute it through MCP.

**Independent evidence.** Six project-provided include rules scanned 1,919 files and 7,350 literal includes,
reporting four upward edges matching the repository's documented debt. Each source line and target was checked.
A declared catalog population of 26 non-external scripts matched the original executable's table/string reads
through the unchanged original-data tool. The coverage audit found five installed mission identities and named
21 missing identities. This is installation coverage, not quest behavior or arbitrary-file compatibility.

**Planning cost.** Five fresh CLI runs after warmup, warm OS cache, same Linux/Core Ultra 7 265K/Python 3.13.5
workstation as 0.5.0. Full include audit median 0.909 s (1,472 output bytes); one collision-system scope 0.212 s
(1,014 bytes); catalog coverage 0.179 s (969 bytes). No baseline tool provided these audits; these are query costs,
not claimed speedups or agent time savings.

Synthetic checks use a differently named project/layout and test relative/external includes, comments/raw strings,
explicit exceptions, current edits, newly discovered identities, missing/duplicate inventory records, stage-order
gaps, path containment and CLI/MCP agreement. New identities and files are discovered without changing code or
fixed content lists. All 94 tests and 37 real-project/synthetic smoke checks passed; all four skills and
the plugin/marketplace manifests validated. No game sources or packages were modified.

**Agent evaluation limitation.** Automatic approval review rejected the live model comparison because it could
send repository content to an external service. Local deterministic validation proceeded; no new live agent
score, skill-following success rate or agent-level productivity improvement is claimed for this release.

## Previous release measurements (0.5.0)

The workflow review used local Codex and Claude Code records from October 1–7, 2026, plus both repositories'
contracts/status/debt and Claude's saved notes. The recent replay window starts October 4. Approval-review echoes,
unrelated project directories and state-changing calls are excluded from the scoped corpus. Extraction recognizes
static calls, not arbitrary JavaScript expressions or dynamically built shell commands; this is not a complete
session-cost accounting. Project-specific queries and private transcript references stay outside this generic repo.

**Regression checks.** All 85 synthetic tests and all 35 project/synthetic smoke checks passed on Linux.
Both modified skills passed the skill validator, and Claude validated the marketplace and plugin manifest.
The current release was not rerun on Windows or macOS.

**Recent-call replay.** The scoped corpus has 4,051 distinct calls (4,821 observations): 3,111 from Claude Code
and 940 from Codex. Both versions used the same corrected replay harness and current repository state. The additive test planner
and architecture-reference brief changes were verified separately after this replay.
Hard failures fell from 27 to 20: seven observed request shapes now work, with no newly failing calls.
Six additional impact calls now map literal CTest input files. There remain 21 no-result responses and
20 failures, including nine references to removed scratch directories/worktrees, malformed extracted commands,
missing symbols, and requests for bytes absent from the executable. The replay is a compatibility check,
not proof of complete answer equivalence or a recreation of each historical working tree.
The 51 MCP impact calls had medians of 1.450 s and 0.990 s; overall output grew from 14.94 to 15.33 million
characters. Ordered replay timing is secondary to the alternating-process benchmark below.

**Tool latency.** Five measured pairs per case, alternating old/new order after an unmeasured warmup pair, fresh CLI
process per call, isolated toolkit caches/state, warm OS file cache. Intel Core Ultra 7 265K, Linux x86-64,
Python 3.13.5. Process startup and query refresh are included. Read-only benchmark and agent work ran concurrently,
so these are workstation observations, not hardware-independent budgets.

| Real workflow | 0.4.0 median | 0.5.0 median | Answer check |
| --- | ---: | ---: | --- |
| Shared locomotion impact | 1.633 s | 1.125 s | Same 38 selected tests and consumers |
| Script test registration | 1.412 s | 0.983 s | Previously unmapped; now finds the catalog's one test |
| Shared graphics-header impact | 1.675 s | 1.128 s | Same 29 selected tests and consumers |
| Lobby scenery impact | 1.601 s | 1.152 s | Same 39 selected tests and consumers |
| Three-function decomp lookup | 0.303 s | 0.310 s | Identical JSON evidence |
| Original float read | 0.170 s | 0.164 s | Identical JSON evidence |
| Original call-tree plan | 0.290 s | 0.302 s | Identical JSON evidence |

The impact cases improved by 28–33%; the decomp differences are small and do not establish an improvement.
Every emitted selection was independently matched against CTest's configured catalog. A synthetic 400-name
selection verifies splitting without admitting an unrelated render check. JSON impact output grows because it
now includes executable argument arrays, build targets, fixture names and unknown-cost counts; output size is
not presented as a token saving.

Reproduce on project-owned cases (`name` plus CLI `argv`, with no writes):

```sh
python tools/benchmark.py --old ../old/src --new src --project /my/project.json \
  --cases /my/cases.json --out /my/benchmark-results --repeat 5
```

**Exact test planning.** A 38-check real selection expands to six required build fixtures. The new `test-plan`
matched CTest's own `--show-only=json-v1` expansion exactly and consolidated the same six fixture targets into
one optional parallel prebuild command, leaving CTest fixtures enabled. Five warm in-process plans had a median
of 0.251 s. The text plan was 1,904 UTF-8 bytes versus 54,568 bytes for that selection's raw CTest catalog.
This measures planning and output size; it does not establish compilation speedup. Synthetic checks cover
nested cleanup/setup fixtures, cycles, missing/disabled names, command preservation and CLI/MCP equivalence.
Project-required architecture references are tested with arbitrary document names in both brief formats,
including missing documents. Skill compliance and architecture quality still require review.

**Agent comparison.** Two read-only tasks, one run per arm, same Sonnet model, with three independent grader votes
against original-byte and CTest-catalog evidence. All arms answered both correctly. No-toolkit: 11 turns,
71 s, $0.181; 0.4.0: 7 turns, 22 s, $0.143; 0.5.0: 7 turns, 139 s, $0.096. The new arm's original-byte task spent
123 of 127 seconds in model/API time. The script-registration agents all chose grep rather than impact.
These trials validate continued answer quality and show **no demonstrated agent-level speedup**. They do not
validate the revised skill's milestone decisions. Direct tool benchmarks establish the impact-query improvement.

**Limits.** No native gameplay, original executable or content package was changed. The review does not fix the
gameplay gaps in the project docs or establish runtime parity. Transport aliases are backed by observed failed
calls; unknown arguments remain errors. Handoff compatibility is tested only against synthetic temporary state.

## Previous release baseline (0.4.0)

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
for both versions at the same time and cost (50 vs 54 turns, 190 vs 186 s, $1.71 each). With 8 concurrent requests on one MCP
stdio session the two are equal (p50 about 0.1 s).

**Windows.** Run with the official Windows builds of uv, Python and Git (under Wine, not a physical machine).
`uv tool install` brought Python and every dependency by itself; setup, brief, lookups (DOL and REL), asm, xrefs, data,
names, doctor and the session hook all gave the Linux answers, and the test suite passes (the 4 Linux-only build-wait
tests are skipped). The first run found and fixed real Windows bugs: open database files blocking cleanup, git output
decoded with the wrong encoding, `C:/` vs `C:\\` worktree paths, and backslashes in stored paths.

**macOS.** Not run on a Mac. The process listing used there (psutil) was run on Linux and passes the build-wait tests.
Paths through symlinks (macOS's temp folder is one) are handled.
