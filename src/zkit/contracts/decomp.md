# Decomp contract

Rules for a matching decompilation, from the first commit. Each one exists because breaking it cost weeks of
repair on a 27,000-function decomp. A project may tighten them; it should not loosen them.

## What done means

1. A function is done when it is byte-identical, lives in the translation unit that owns its address, is a real
   member of its class (or a genuinely free function) declared once in a header, and is named on evidence.
2. A unit is done when every function and data section matches and the build links it from source. Linked bytes
   are a headline number next to matched bytes.
3. objdiff's report is the only measure. Progress is compared by original address (`zkit progress --since`), so
   renames, folds and splits never look like losses and a real loss always shows.

## Before matching an area

4. **Units come from boundary evidence.** Every address has exactly one home from the start: a unit per original
   object where the evidence shows its bounds (compiler or flag changes, static-initializer and init-array
   entries, vtable and literal-pool order, alignment), one placeholder unit per contiguous unknown range otherwise.
   Never per-function slices, wrapper files, selector blocks or overlapping splits.
5. **Libraries first.** Identify SDK, runtime and middleware code (and their versions) before partitioning game
   code; import pinned donor sources where the version matches.
6. **Compiler and flags per unit.** Identify them before matching (prologue patterns, a probe on untouched seeds);
   splits and folds inherit them, and a change is kept only when every function already exact stays exact.
7. **A unit owns its data.** When a unit is created it claims the data only its code references: tables, literal
   pools, strings, `.bss`. Symbol sizes and scopes follow the compiled object after every build.
8. **Classes before members.** Build the class graph from the executable (vtables and the constructors and
   destructors that install them, RTTI and class-name strings, allocation sizes). Each class gets one header with
   its proven base and the complete virtual block in slot order before its methods are matched.

## Writing a candidate

9. **Write source, not decompiler output.** A candidate is a member of its class, using the class header's fields
   and the shared declarations of what it calls. Never `extern "C"` bodies on `void *`, raw pointer-plus-offset
   reads, hand-mangled names, private prototypes, re-typing macros, fake local classes for virtual calls, or
   hand-written vtables. `zkit try` compiles a candidate with the unit's exact command and reports both the byte
   difference and any such debt; only a candidate that is identical and debt-free goes into the tree.
10. **Read two decompilers.** Start from the decompiler seed and Ghidra's reading side by side; where one
    emits `goto` or fails, the other is usually closer.
11. **Stop rules.** Hand work starts at 96% or closer. Four attempts per function (enforced), and two edits that
    do not improve the difference mean stop. Register-allocation-only gaps go to the permuter or a flag sweep;
    relocation-only gaps are data ownership, not code; control-flow gaps are not ground by hand.
12. Bodies stay in address order inside their unit. Banking is a transaction: one build per batch, rolled back on
    any address-keyed loss.

## Names

13. Names come from evidence, strongest first: strings tied to the object (class names, RTTI, diagnostics), a
    symbol-rich build or a donor of the same version, the vtable a constructor installs, `this` flowing from proven
    methods, allocation sizes, then what the body demonstrably does. Callers and neighbours corroborate; they never
    decide ownership.
14. A placeholder (`fn_<addr>`, `TUnk_<vtable>`, `m_<offset>`) stays until evidence replaces it. A role goes in a
    comment, not in a name. One inherited virtual has one name across every override.
15. A rename changes every file that spells the symbol in the same step, callers included.

## Proving a change

16. A change that must not change code (cleanup, rename, header move) is proven by object identity:
    `zkit objects --save`, change, build, `zkit objects --compare`. Cleanup is measured on the tree with
    `zkit quality --since`, never with a tool's own summary.
17. A rewrite rejected for one bad site is narrowed to the functions whose code changed, not dropped per file.
18. When two consecutive waves of a lane yield fewer than about fifty items, build a tool that covers the whole
    category or stop; do not fix items one at a time.

## Working together

19. One tree build at a time; tools that write the tree take the lock themselves. Workers edit only their own
    copies and run isolated checks; one coordinator banks, builds and commits. Parallelism follows the machine's
    available memory.
20. Commits are one short line in plain words, under the developer's own identity, with no AI co-author trailer.
    Agent instructions, session logs and scratch scripts are never committed; the repository holds its README,
    contributor guide and architecture docs.
