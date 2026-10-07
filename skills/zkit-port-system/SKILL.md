---
name: zkit-port-system
description: Implement or repair original-game behavior in a native port / reimplementation of a GameCube game so it matches the real game and reuses shared systems. Use for gameplay, actor, item, quest, area or effect work, fidelity drift, or reuse refactors in a native port configured in gcn-zkit.
---

# Port a system faithfully, through shared owners

**Fidelity tiers decide what "correct" means** (`zkit_tiers native <paths>` gives each file's tier; anything not listed is EXACT):
- **EXACT** covers behavior: combat, movement, enemies, item use, NPC chat and dialogue, quests, progression, camera, animation timing, sound (requests, envelopes, pitch, pan, reverb, music) and all gameplay data.
  - Reproduce the decomp. No improvements unless the owner approves one as an `INTENTIONAL-DIVERGENCE`.
  - Everything below applies in full.
- **EQUIVALENT** covers rendering: scene, particles, shading, lighting, shadows.
  - The SDL implementation can be completely different, but the observable result must behave like the original: what is drawn, when, where, color, order and lifetime.
  - Verify by comparing output (fidelity recipe or off-screen capture) and with performance numbers, not by copying code shapes.
  - Constants that drive timing or color must still match.
- **LIBERTY** covers UI, menus and new graphics features.
  - This is the owner's design. Never put gameplay rules here; call the exact systems.
  - Mark differences `INTENTIONAL-DIVERGENCE`. No decomp citations are required.
- **INFRASTRUCTURE** is SDL, platform, save and loader plumbing. Unit tests only, and it must not decide gameplay.

0. **Keep the requested milestone in scope.** Start from its current status, required architecture/design and quality contracts, relevant system docs and reported live symptom. Establish the intended owner, file placement, allowed dependency direction, lifetime and extension seams before editing; a narrow change still follows the project-wide architecture. Scope `zkit_suspects`, `zkit_grounding` and `zkit_consts` to that system's paths. Use project-wide audits when requested or when evidence shows a shared dependency needs one. A ranking or unmatched citation is a triage hint, not proof of incorrect behavior or an instruction to replace the milestone with decomp work.
   - For reported drift, identify the original caller, data, update order and lifetime before changing a leaf function. Capture the reported scenario as a regression; a component host may exclude the cause.
   - Recover missing dependencies through the repo's own decomp workflow. Exact matching and original-execution comparisons are distinct evidence; state each boundary and any hosts/exclusions. Never infer parity from match percentages or citation counts.
   - Accept a drift baseline only after reviewing every change it would acknowledge. Preserve unrelated unreviewed entries.
1. **Trace the original first.** Run `zkit_port_plan <original entry addr|name>` (depth 2-3). It walks the original direct-call tree and marks each callee:
   - **reuse:** the port already implements it (files listed). Extend that owner; do not write a second copy.
   - **reuse-unverified:** the port implements it, but the decomp is not exact yet. Treat its native semantics as suspect.
   - **decompile-first:** recover it in the decomp before porting (`zkit-recover-function`). Never guess.
   - **shared-port:** the original calls it from many places. Port it once into a shared owner.
   - **port:** exact in the decomp and not yet in the port.

   Also run `zkit_lookup` on the entry point for its callers (who drives it, in what order) and use `zkit_asm`/`zkit_data` for constants and tables. Vtable calls are not in the tree: read the asm for `bctrl`.
   Subagents do not get the session brief: tell every worker to use the gcn-zkit CLI via Bash (`gcn-zkit lookup|asm|data|xrefs <addr ...>`) instead of reading the DOL or symbols.txt with scripts (84% vs 22% zkit use, measured). Before building in the shared decomp tree, `gcn-zkit wait decomp`, then build under its lock.
2. **Find the existing owner.**
   - `zkit_search` the system name in native docs and source.
   - `zkit_reuse native` shows copied helpers and the central files that enumerate variants.
   - Use composition (actors own their shadow, health, status, movement and attack components), interfaces or inheritance where ownership is demonstrated. A variant (another enemy, weapon tier, quest or area) should be data plus composed behavior. It should not copy a controller, and it must never add an area/episode/family branch to shared code.
3. **Respect the extension seams** the repo's rules describe (content definitions, mod or server data). Establish the boundary before implementation: formats and protocol opcodes belong in adapters; native owners consume validated definitions/events. Content identity must not replace authored behavior. Verify a second existing consumer of a changed shared mechanism. Don't add unrequested protocols or content, but preserve their declared interfaces.
4. **Implement.**
   - Cite the original address (bare 8-digit hex) at every ported function.
   - Mark native-only code `INTENTIONAL-DIVERGENCE` (or the marker the repo's rules name).
   - Keep definitions immutable, mutable state with a single owner, and no allocation in tick/frame paths.
5. **Check before testing.** Re-run `zkit_consts <file>` after changing constants; it should report them verified. `zkit_check native` lints your diff:
   - citations that don't resolve or point at unmatched decomp;
   - new gameplay functions without a citation;
   - the repo's forbidden patterns (area-specific branches, banned constructs);
   - `/tmp` paths or dated sections in docs.
6. **Verify like the game is played.**
   - Run `zkit_impact native`. It lists the other code that includes what you changed (the consumers you must not break) and the exact `ctest -R` commands for the tests covering it, direct ones first. Run those instead of a whole label or a render matrix.
   - A missing impact mapping may be a linked-library or script-import limitation. Inspect the owning catalog and recipes before adding a check. Impact reports exact test commands, optional build targets and unmeasured costs; use `zkit_test_plan` with exact CTest names to validate registration, see fixture costs and prebuild only the required targets when useful. Keep the repo's mandatory finish gate.
   - Also run the original-comparison recipe (`zkit_recipes`). Never regenerate expected output from native code.
   - Test the ordinary saved-character route, and also re-test one other consumer of any shared code you changed.
   - Rendering checks run off-screen (virtual desktop), scoped to the change; kill what you start.
7. **Feed back.** If you recovered decomp evidence, bank it in the decomp. Update the owning system doc in place, and rewrite `docs/status.md`.

Finish with `zkit-finish`. Report source-traced, original-executed, native-integrated and presentation evidence separately.
