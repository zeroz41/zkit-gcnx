# Port contract

Rules for a native port written from a matching decompilation. The port reproduces what the original does,
in an architecture of its own. Libraries, languages, file formats, frame caps and presentation targets are
per-project decisions, kept in the project's own decisions file and never written here as rules.

Terms: the **original** is the shipped program and data; the **reference** is the matching decomp of it; the
**port** is the native program; **baseline mode** is the port with every enhancement off.

## 1. Behavior authority

1. Behavior comes only from reference code that is byte-matched, named and clean: no decompiler temporaries,
   raw offsets or placeholder callees in the functions it rests on. `zkit port-plan` marks each function;
   decompiler readings and near-matches are leads, never authority.
2. **Hold rule.** When the reference is unclear about anything a system does (an unmatched function, a field of
   unknown meaning, an unknown caller or order), the port does not implement that part. It stays an explicit,
   reported unsupported boundary until the reference is clean. No stand-in values, no temporary guesses.
3. Every ported function cites the original address it implements. Before a system is called done, none of its
   citations point at reference code that is not ready (`zkit check` reports them).

## 2. Accuracy without the original's architecture

4. Port what the original observably does, not how it was built. Fixed memory pools, global singletons,
   hand-rolled vtables, frame-coupled loops and polling written around old hardware are not carried over unless
   they are observable.
5. For each system, record which original mechanisms are observable and keep exactly those: tick rate and update
   order, random-number draws and their order, integer widths and overflow, float precision and operation
   order where results depend on it, timing of events, and data values.
6. A shim that replays the original's SDK or GPU calls is allowed as a test oracle or inside an importer that
   converts original data. It is never the runtime architecture.

## 3. Fidelity tiers

7. **Exact** (game behavior and data): same results as the original for the same inputs, compared by trace to
   the first divergence.
8. **Presentation** (rendering, audio, UI layout): any implementation, but in baseline mode the output matches
   the original at its aspect and cadence, within a tolerance each check states.
9. **Liberty** (owner-designed additions: higher frame rates, widescreen, new UI, graphics upgrades, quality of
   life): opt-in, listed in one registry, and proven not to change exact or presentation output when off.
10. **Platform** (windows, devices, files, sockets, threads, backends): free choice, outside this contract.
11. Every intentional difference carries a searchable marker in code and an entry in the registry. An unmarked
    difference is a bug.

## 4. Ownership and structure

12. **Original sharing first.** Before implementing anything for one consumer, find the original's shared
    function and all its callers (`zkit lookup`, `zkit xrefs`). Port the shared owner once, then map every caller
    as ported or listed as unsupported. A per-consumer copy of shared behavior is rejected.
13. One owner per piece of mutable state. Immutable definitions are separate from runtime instances.
    References between entities are validated handles.
14. Composition first: behavior that varies by content is data plus composed components (an actor owns its
    shadow, health, movement and attack parts). Inheritance only where substitution genuinely holds.
15. Simulation never depends on presentation, platform, device or protocol code; an include-boundary check
    enforces it. Simulation runs headless and deterministically from recorded input.

## 5. Time

16. Simulation advances only in the original's ticks and never reads frame time or wall clock.
17. Presentation samples previous and current state through one shared mechanism, so every object renders at any
    frame rate. A check runs presenters at the original cadence and at two higher rates and requires identical
    state at tick boundaries. Baseline mode offers the original cadence.

## 6. Content

18. Original formats are parsed only by the importer. The runtime loads versioned, validated native packages
    (source checksum, importer version, dependencies).
19. Importers are generic per format, driven by the original's own tables and loaders. The runtime never chooses
    behavior by content identity (area, quest, actor, sound or texture id); counts come from data.
20. Mods and server-delivered content enter through the same importer and validator. Unsupported records are
    rejected and reported, never approximated.

## 7. Network

21. The native session interface (requests, events, authority) is protocol-free and defined from the game's own
    state changes. Protocol adapters only translate between the wire and that interface, own no game state and
    are selected at one registration point. A protocol-free test provider drives the same gameplay checks.

## 8. Fixing bugs

22. A fix lands where the original computes the behavior; if that place is shared, the fix is shared. A fix
    scoped to one actor, area or object is rejected unless the original is scoped that way (cite it).
23. A reported bug first becomes a check built from original evidence that fails; then it is fixed. Expected
    values written from the port's own output are not evidence.

## 9. Evidence and regression

24. Expected values for original behavior come only from original evidence: a capture from the original
    executable (its header records the executable's hash, the driver, the cases and the output hash) or an
    independent decode of original data. They are never generated, edited or repaired from the port's output;
    changing one means capturing the original again.
25. Every assertion is labelled original or native. A native assertion never supports a fidelity claim, and no
    test asserts behavior the original evidence does not show. Behavior without evidence is an unsupported
    boundary: the port refuses it and the test asserts the refusal.
26. Captures use case grids over branches, rounding and overflow edges, random draws and object retirement, run
    through the real caller path, and compare at the first divergence.
27. Each system has baseline goldens captured from the original: a deterministic start state, recorded input,
    proof the scenario was reached, and frames, audio and state compared within a stated tolerance. They run on
    every presentation, clock or shared-owner change, and a baseline regression is never accepted. Synthetic
    renderer tests are unit tests, not presentation evidence.
28. A registered frame-rate sweep runs every presenter at the original cadence, two higher rates and uncapped:
    simulation state at tick boundaries is identical across rates.
29. A reported bug first gets a check that fails on the unfixed build in the reporter's own scenario. A check that
    passes before the fix did not reproduce the report.
30. A claim names its scenario, enters through the ordinary game path, drives scripted input and asserts the
    visible outcome, listing every stub or shortcut. Booting or reaching a menu proves nothing more. Test totals,
    inventory coverage and match percentages never show a system is done.
31. One shared harness owns comparison, capture and measurement, wired into the build; no per-feature scripts.

## 10. Test sizing and hygiene

32. While iterating, run the tests the change reaches (`zkit impact`, within a time budget that still covers every
    test program); before anyone runs the program, confirm it is newer than its sources (`zkit stale`).
33. Before a commit: the fast tier, the full impact selection, the owning live scenario, and one other user of
    each changed shared owner. Display, timing and matrix runs only by the triggers in section 11.
34. A fast-tier test takes about a second, the tier minutes at most; longer scenario tests carry their own label.
35. Nothing draws on the user's display or plays through their audio: display and GPU checks run in a test-owned
    virtual display with a null audio sink. Every process a test starts is killed on exit, timeout or cancel.
    Builds and tests across concurrent sessions share one budget sized from total and available memory and
    cores, and the same limits work on an 8 GB machine.
36. Main has no known-red and no flaky tests; a skip is never a pass; a check counts only if it is registered,
    asserts a result and runs in a gate. Fixtures hold observations, never original bytes, with provenance, and
    stay within a size budget.

## 11. Performance

37. Budgets are absolute milliseconds per hardware tier (frame mean and p99, per-phase main-thread time, load time,
    resident memory); frame rate is derived, never the budget. A tier claim needs a measurement on that tier.
38. Every standard scene has a deterministic work profile checked on every commit: no heap allocation on tick and
    frame paths after warm-up, and exact work counters (draws, uploads, entities visited, resident bytes) against
    a tracked baseline that changes only with an explained diff.
39. A timing run is required only when the diff touches the declared hot paths or moves a counter. Timing uses
    one method: release build, idle machine, owned virtual display, warm-up discarded, before and after
    alternated at least twice, real configuration asserted. A regression fails on a budget breach or a change
    beyond the measured run-to-run noise; there is no accept-anyway escape.
40. An optimization proves its output unchanged (same trace, same baseline frames) next to its speedup. Results
    live in a tracked machine-readable baseline per scene, rewritten in place, never as tables in documents.

## 12. Enhancements

41. An enhancement starts only when its system's baseline has no open exact or presentation gap. It ships off
    by default, with a baseline comparison proving it inert when off. Experiments stay on branches.

## 13. Repository

42. Committed docs: the README (what it is, how to build, how to use), this contract, the decisions file and one
    present-tense document per system. No session logs, audits, pass counts or local paths; agent instructions
    stay local.
43. Every committed tool is wired into the build, the tests or a documented workflow; one-off and agent scripts
    are not committed.
44. Commits are one short line in plain words under the developer's identity, never with an AI co-author.
    Merged branches and worktrees are removed; the tree is clean at the end of a session.

## 14. Done

45. A system is done when its reference functions are ready and cited, every original caller is mapped, its
    exact trace and baseline golden pass, its live scenario passes, it has no identity branches, the boundary
    check is clean, the registry is current and its system document is updated in place.
