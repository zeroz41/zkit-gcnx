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

0. **Find what is probably off.**
   - `zkit_suspects native` ranks files whose behavior most likely deviates, and gives the next action for each:
     - **decompile-first:** the cited originals are not exact. Recover them, then re-port.
     - **near-miss constant:** a literal within 2% of a constant the original really loads. Almost always a slip.
     - **unsourced constant:** a value no cited original loads. Cite where it comes from, or prove it.
     - missing test, or missing original-execution recipe.
   - `zkit_drift` lists native files written against decomp code that has since become exact or changed. Re-check them against the current decomp, then `zkit_drift accept=true`.
   - `zkit_consts <path>` checks a file's literals against the original constants.
   - Fix these before building on top of them.
0b. **Know how solid the ground is.** `zkit_grounding native <folder>` shows what share of the original functions that system cites are byte-exact in the decomp. Below about 60%, the native behavior rests on unproven decomp: recover the listed weakest functions first (`zkit-recover-function`, or `zkit_demand`), especially in combat and statuses.
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
3. **Respect the extension seams** the repo's rules describe (content definitions, mod or server data). Don't add features that weren't asked for, but don't hardcode around those seams either.
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
   - If it reports a file with no direct or near test, add or register a check.
   - Also run the original-comparison recipe (`zkit_recipes`). Never regenerate expected output from native code.
   - Test the ordinary saved-character route, and also re-test one other consumer of any shared code you changed.
   - Rendering checks run off-screen (virtual desktop), scoped to the change; kill what you start.
7. **Feed back.** If you recovered decomp evidence, bank it in the decomp. Update the owning system doc in place, and rewrite `docs/status.md`.

Finish with `zkit-finish`. Report source-traced, original-executed, native-integrated and presentation evidence separately.
