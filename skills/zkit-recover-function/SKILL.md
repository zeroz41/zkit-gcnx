---
name: zkit-recover-function
description: Recover GameCube functions or classes into a matching decomp (decomp-toolkit/objdiff project) - byte match, put it in the right translation unit, name it on evidence, link it - using gcn-zkit evidence plus the project's own compiler and objdiff. Use for any decomp work on a project set up with gcn-zkit.
---

# Recover a function into the decomp

The repo's own build and objdiff decide what matches. zkit supplies evidence and keeps sessions consistent.
Native-port architecture guidance does not restructure matching decomp: preserve original ownership/layout,
translation-unit placement and compiler constraints. Composition/interface refactors belong in the native port
unless the matching project itself requires a compatible structural correction.

1. **Evidence.** Start with `zkit_lookup <address|name>`. It shows match, link and name state, the owning unit and `file:line`, every direct caller (including callers in REL modules) with a per-class count, the callees, vtable slots holding the function, and any native-port files that cite it.
   - `zkit_asm` shows the original instructions with references resolved to symbols and float constants shown as values. REL functions are written `module+0xOFFSET` (for example `mymodule+0x1D0`).
   - Read the project's m2c seed and `zkit_decompile` (Ghidra's C for the same original bytes) side by side, and start from whichever shape fits. Where m2c fails or emits `goto`, Ghidra's loops and branches were closer to the matched source in 111 of 160 differing functions; elsewhere m2c's switches, returns and calls usually were. Ghidra's output needs retyping (`undefined4`, `param_N`, current names are already substituted) before it compiles; objdiff still decides the match.
   - `zkit_data` reads the tables a function uses; `zkit_xrefs` shows who reads or writes a global, including from RELs.
   - **Workers.** Subagents do not get the session brief. Put this in every worker prompt: "Use the gcn-zkit CLI via Bash for evidence (`gcn-zkit lookup|asm|decompile|data|names|xrefs <addr ...>`, several addresses per call; `decompile` is Ghidra's C, read it next to m2c, especially where m2c emits `goto`) instead of grepping symbols.txt or parsing the DOL/report.json." With that line, workers used zkit for 84% of lookups; without it, 22%.
2. **Name only on evidence.** An auto name (`fn_80012345`, `lbl_...`) is provisional. Rename only when the callers, a vtable slot or a typed `this` agree. `zkit_lookup` lists them: one slot shared by many vtables means an inherited base-class virtual, so don't name it after one subclass. Many callers of the same kind (for example, every actor's draw function) are good evidence of what a helper does. Update the class header and every reference in the same change.
   - `zkit_classes` lists methods whose class name the vtables contradict (strong: the named class has its own vtable without them) and virtuals with no class that only one class's vtables hold. Check it before accepting a `Class__sub_` prefix or naming a class pass; filter with `class_name` or `unit`.
3. **Candidate.** Write the code with the owning unit's compiler settings and the real headers. Check it the way the repo does (objdiff, the repo's diff tool, or decomp.me).
4. **Stop rules.** Follow the repo's budget if it has one (it is in the brief's rules). Before writing a function off on control-flow differences, read its `zkit_decompile` output: plateau verdicts recorded from m2c alone do not cover it. Then stop rather than grind branch order by hand.
5. **Link and place data.** `zkit_unit <unit|address|function>` shows a unit's split ranges, functions still to match or name, its data symbols used by other units, literals and globals its code uses from elsewhere, and each section's neighbours. Use it instead of grepping splits.txt/symbols.txt (agents did that 2,289 times in one week).
   - `zkit_unit blocked=true` lists every unit whose functions are all exact but not linked, with those cross-unit references. On a real decomp it covered every unit the repo's own link attempts recorded as blocked and named the holding unit for 21 of 22 missing-symbol failures.
   - `zkit_unit gaps=true` (optionally `section=".sdata2"`) shows split coverage per section and every unclaimed range with the units that use it. A range used by one unit is a claim candidate (21 of 24 such candidates were later claimed by that code); the repo's split rules decide.
6. **Build.** One whole-tree build at a time: run `gcn-zkit wait decomp` (MCP `zkit_wait`) instead of polling with sleep, then build. Don't create wrapper files or overlapping splits to force a match.
7. **Tell the next session.** If you matched or renamed functions a native port cites, say so in the handoff; with a port configured, `zkit_drift` will then list the port files to re-check.
8. **Report each layer separately:** matched, in the right unit, named with evidence, linked. A byte match alone does not make a class complete.

Finish with the `zkit-finish` skill.
