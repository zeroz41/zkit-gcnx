---
name: zkit-recover-function
description: Recover functions or classes into a matching decomp (GameCube decomp-toolkit, or a Switch clang project) - byte match, in the owning translation unit, as a real member of its class, named on evidence, linked. Use for any matching, naming, folding, data or linking work on a project set up with zkit.
---

# Recover a function

The rules are `zkit contract decomp`; this is the loop. objdiff's report decides what matches.

1. **Check the ground first.** `zkit lookup <addr>` gives match/link/name state, owning unit and file:line,
   callers, callees and vtable slots. If the unit is a placeholder, its compiler unknown, or the class has no
   header with its virtual block, fix that first (`zkit unit`, `zkit classes`); matching into a wrong layout is
   what produced weeks of cleanup.
2. **Evidence.** `zkit asm` (original bytes, references resolved), `zkit decompile` (Ghidra) next to the
   project's decompiler seed, `zkit data` for tables and constants, `zkit xrefs` for globals, `zkit refs` for
   where the source already declares or calls it.
3. **Write a real member.** Use the class header's fields and the shared declarations of the callees. No
   `extern "C"` on `void *`, raw offsets, hand-mangled names, private prototypes, re-typing macros, fake classes
   for virtual calls. Unknown fields get `m_<offset>` members in the header, at the offset the code compiles to.
4. **Check it outside the tree.** `zkit try <addr> <candidate>` compiles with the unit's exact command and shows
   the differing words, both disassemblies and any decompiler debt. Four attempts per function, enforced.
   - register-allocation only: permuter or flag sweep, not hand edits;
   - relocation only: data ownership (`zkit compiled <addr>` names the symbols; `zkit unit --gaps`);
   - control flow: try the other decompiler's structure once, then record the blocker.
5. **Bank only what is identical and debt-free**, through the repo's banking tool, one tree build at a time.
6. **Name on evidence** (contract rule 13). One inherited slot keeps one name across all overrides; a
   rename changes every spelling, callers included.
7. **Link.** A unit is done when it links: `zkit unit --blocked` lists exact units that don't, with the
   cross-unit data holding them.
8. **Report the truth.** `zkit progress --since session` gives the session's real delta by address. Report
   matched, placed, named and linked separately; a byte match alone does not finish a class.

Workers: subagents don't get the brief. Give each one the addresses, this skill's steps 2-4, and the line
"use `zkit lookup|asm|decompile|data|xrefs|refs|try` via Bash, several addresses per call; edit only your own
candidate files; never build the tree or edit src/include/config".

Finish with `zkit-finish`.
