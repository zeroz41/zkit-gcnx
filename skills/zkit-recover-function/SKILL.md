---
name: zkit-recover-function
description: Recover functions or classes into a matching decomp (GameCube CodeWarrior or Switch clang) - byte match, in the owning translation unit, as a real member of its class, named on evidence, linked. Use for any matching, naming, folding, data or linking work on a project set up with zkit.
---

# Recover a function

The rules are `zkit contract decomp`; this is the loop. objdiff's report decides what matches.

1. **Check the ground first.** `zkit lookup <addr>` gives match/link/name state, owning unit and file:line,
   callers, callees and vtable slots. If the unit is a placeholder, its compiler unknown, or the class has no
   header with its virtual block, fix that first (`zkit unit`, `zkit classes`); matching into a wrong layout is
   what produced weeks of cleanup.
2. **Evidence.** `zkit asm` (original bytes, references resolved); the decompiler seed: on GameCube
   `zkit m2c` (it adds Ghidra's reading where m2c fails or emits goto), on Switch `zkit decompile` (Ghidra; m2c
   reads PowerPC only); `zkit data` for tables and constants, `zkit xrefs` for globals, `zkit refs` for where
   the source already declares or calls it.
3. **Write a real member.** Use the class header's fields and the shared declarations of the callees. No
   `extern "C"` on `void *`, raw offsets, hand-mangled names, private prototypes, re-typing macros, fake classes
   for virtual calls. Unknown fields get `m_<offset>` members in the header, at the offset the code compiles to.
4. **Check it outside the tree.** `zkit try <addr> <candidate>` compiles with the unit's exact command and shows
   the differing words, both disassemblies and any decompiler debt. Four attempts per function, enforced.
   `zkit try --unit` judges a whole unit file and lists what it gained and lost against the tree's build;
   `--include <dir>` puts edited header copies ahead of the tree's; `zkit probe <unit> <file>` compiles any
   experiment with the unit's command and prints its code (never hand-copied flags).
   - register-allocation or scheduling only: a flag sweep, or on GameCube `zkit permute <addr> --seed
     <candidate> --run` (decomp-permuter; every zero-score output is checked against the target object);
   - relocation only: data ownership (`zkit compiled <addr>` names the symbols; `zkit unit --gaps`);
   - control flow: try the other decompiler's structure once, then record the blocker.
5. **Bank only what is identical and debt-free**, through the repo's banking tool, one tree build at a time.
6. **Name on evidence** (the contract's "Names" rules). One inherited slot keeps one name across all overrides; a
   rename changes every spelling, callers included.
7. **Link.** A unit is done when it links: `zkit build` relinks the executable (GameCube: mwld and the DOL's
   SHA-1; Switch: every compiled section placed into the module, its segment hashes checked) and marks the units
   it proves. `zkit unit --blocked` lists exact units that don't, with the link's reasons or the cross-unit data
   holding them. A link catches what a per-function match cannot: a `__FILE__` string that differs, a function
   the object defines outside its unit.
8. **Report the truth.** `zkit progress --since session` gives the session's real delta by address. Report
   matched, placed, named and linked separately; a byte match alone does not finish a class.

Workers: spawn them as `zkit:zkit-worker`, not general-purpose. It carries the contract's rules, the evidence
commands and the cost rules, and none of the tool schemas and skill listings a general agent re-reads on every turn
(about a quarter of the context per turn). Give each one its unit or functions, its scratch folder and the commit its
header copies start from; the project's own rules go in a brief file it reads once.

Keep workers short. Every turn re-reads the whole context, so an agent's cost grows with the square of its length:
one worker run to 500 turns costs several times what five fresh ones doing the same work cost. Give a worker one
unit (or a handful of functions), have it keep its state in its files (candidate, a short NOTES file of what was
tried and what blocks) and return after about 60 tool calls or when done. Continue unfinished work with a fresh
worker pointed at those files, not by messaging the long-lived one. Ask for short reports; the coordinator's
context grows the same way, so it reads results from files and diffs, not transcripts, and keeps its state in notes
so it can compact early (in Claude Code, an `autoCompactWindow` of about 200000) instead of running near the
window.

Finish with `zkit-finish`.
