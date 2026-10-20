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
   Never per-function slices, wrapper files, selector blocks or overlapping splits. A generated gap unit
   (`auto_*`) is reported debt, never a destination for new code.
5. **Libraries first.** Identify SDK, runtime and middleware code (and their versions) before partitioning game
   code; import pinned donor sources where the version matches.
6. **Language per unit, from evidence.** A unit is C++ when its code has members (`this` flowing into a recovered
   class), calls the C++ runtime (allocation, array construction, member-function pointers, global destructor
   registration) or has a static initializer; library code identified against donor objects keeps its own
   language; the rest is C until code says otherwise. A function's linkage follows its unit: a C module has one
   header declaring its functions in a guarded `extern "C"` block that C++ units include; C++ functions carry
   C++ names. A function or object whose original name is a C name is defined under `extern "C"` in the unit
   that owns its address, even a C++ one; that is its linkage, not debt. Never `extern "C"` at a call site (a
   declaration of what another file defines), never a C name on a C++ function.
7. **Compiler and flags per unit.** Identify them before matching (prologue patterns, a probe on untouched seeds);
   splits and folds inherit them, and a change is kept only when every function already exact stays exact.
   The tools come pinned from `zkit build --download`, which fetches only what the target's platform uses: never
   LLVM for a GameCube project, never CodeWarrior, wibo or binutils for a Switch one. Never fetch a tool by hand
   or for a platform the project does not target.
8. **A unit owns its data.** When a unit is created it claims the data only its code references: tables, literal
   pools, strings, `.bss`. A symbol only its own unit references is local. Sizes come from types and access
   widths, never from the distance to the next label; alignment padding belongs to the gap, not to a symbol.
9. **Classes before members.** Build the class graph from the executable (vtables and the constructors and
   destructors that install them, RTTI and class-name strings, allocation sizes). Each class gets one header with
   its proven base and the complete virtual block in slot order before its methods are matched. The compiler
   emits the vtable from that declaration; source never names, declares or indexes a vtable.

## Writing a candidate

10. **Write source, not decompiler output.** A candidate is a member of its class, using the class header's fields
   and the shared declarations of what it calls. Never `extern "C"` bodies on `void *`, raw pointer-plus-offset
   reads, hand-mangled names, private prototypes, re-typing macros, fake local classes for virtual calls, or
   hand-written vtables. `zkit try` compiles a candidate with the unit's exact command and reports both the byte
   difference and any such debt; only a candidate that is identical and debt-free goes into the tree.
   Every function and global is declared once, in the header of the class or module that owns it: no `extern`
   declarations inside `.cpp` files, no catch-all "external" or "misc" headers.
11. **Start from the proven decompiler.** On GameCube, m2c's seed (`zkit m2c`); where m2c fails or emits
    `goto`, take loop and branch shape from Ghidra's reading, which it adds. On Switch, Ghidra's reading
    (`zkit decompile`).
12. **Stop rules.** Hand work starts at 96% or closer. Four attempts per function (enforced), and two edits that
    do not improve the difference mean stop. Register-allocation-only gaps go to the permuter (`zkit permute`, GameCube) or a flag sweep;
    relocation-only gaps are data ownership, not code; control-flow gaps are not ground by hand.
13. Bodies stay in address order inside their unit. Banking is a transaction: one build per batch, rolled back on
    any address-keyed loss.

## Names

14. Names come from evidence, strongest first: strings tied to the object (class names, RTTI, diagnostics), a
    symbol-rich build or a donor of the same version, the vtable a constructor installs, `this` flowing from proven
    methods, allocation sizes, then what the body demonstrably does. Callers and neighbours corroborate; they never
    decide ownership.
15. A placeholder (`fn_<addr>`, `TUnk_<vtable>`, `m_<offset>`) stays until evidence replaces it. A role goes in a
    comment, not in a name. One inherited virtual has one name across every override.
16. A name spreads along its relations in the same step: a virtual's name to every override in that slot, a class
    name to its vtable, constructor, destructor and the data it owns, a parameter type to the callers that pass
    it. One proof names everything it proves.
17. A rename changes every file that spells the symbol in the same step, callers included.

## Proving a change

18. A change that must not change code (cleanup, rename, header move) is proven by object identity:
    `zkit objects --save`, change, build, `zkit objects --compare`. Cleanup is measured on the tree with
    `zkit quality --since`, never with a tool's own summary.
19. A rewrite rejected for one bad site is narrowed to the functions whose code changed, not dropped per file.
20. When two consecutive waves of a lane yield fewer than about fifty items, build a tool that covers the whole
    category or stop; do not fix items one at a time.

## Working together

21. One tree build at a time; tools that write the tree take the lock themselves. Workers edit only their own
    copies and run isolated checks; one coordinator banks, builds and commits. Parallelism follows the machine's
    available memory.
22. Commits are one short line in plain words, under the developer's own identity, with no AI co-author trailer.
    Agent instructions, session logs and scratch scripts are never committed; the repository holds its README,
    contributor guide and architecture docs.
