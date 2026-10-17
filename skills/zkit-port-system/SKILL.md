---
name: zkit-port-system
description: Implement or repair original-game behavior in a native port / reimplementation of a GameCube game so it matches the real game and reuses shared systems. Use for gameplay, actor, item, quest, area or effect work, fidelity drift, or reuse refactors in a native port configured in zkit.
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
   - **decompile-first:** recover it in the decomp before porting (`zkit-recover-function`). Never guess. `zkit_decompile` reads what it does while you plan; that reading is not proof.
   - **shared-port:** the original calls it from many places. Port it once into a shared owner.
   - **port:** exact in the decomp and not yet in the port.

   Also run `zkit_lookup` on the entry point for its callers (who drives it, in what order) and use `zkit_asm`/`zkit_data` for constants and tables. Vtable calls are not in the tree: read the asm for `bctrl`.
   Subagents do not get the session brief: tell every worker to use the zkit CLI via Bash (`zkit lookup|asm|decompile|data|xrefs <addr ...>`; `decompile` is Ghidra's C for an original function) instead of reading the DOL or symbols.txt with scripts (84% vs 22% zkit use, measured). Before building in the shared decomp tree, `zkit wait decomp`, then build under its lock.
2. **Find the existing owner.**
   - `zkit_search` the system name in native docs and source.
   - `zkit_reuse native` shows copied helpers and the central files that enumerate variants. If configured, `zkit_architecture` checks the changed system against the project's include boundaries; investigate each finding against the actual contract.
   - Define interfaces at real ownership/service boundaries. Keep mutable state with one owner; compose reusable movement, combat, effects and interaction behavior where the evidence supports it. Keep orchestration small. Inheritance needs a valid substitutable contract; neither a new interface nor a copied subsystem is the default answer to every variation.
   - Use composition (actors own their shadow, health, status, movement and attack components), interfaces or inheritance where ownership is demonstrated. A variant (another enemy, weapon tier, quest or area) should be data plus composed behavior. Extend its existing definition/controller seam. Do not route shared behavior by one asset identity, filename, geometry shape or hand-picked content list. If the original encodes a meaningful distinction, recover and represent it explicitly in the owning data or behavior.
3. **Respect the extension seams** the repo's rules describe (content definitions, mod or server data). Establish the boundary before implementation: formats and protocol opcodes belong in adapters; native owners consume validated definitions/events. Content identity must not replace authored behavior. Verify a second existing consumer of a changed shared mechanism. Don't add unrequested protocols or content, but preserve their declared interfaces.
4. **Automate the content path and complete the requested system.**
   - Enumerate the supported source inventory from original tables, archives or authored commands. Separate discovered, decoded, converted, admitted, live-integrated and verified entries. With a configured inventory, `zkit_coverage` detects missing/duplicate entries and stage gaps; it does not prove behavior.
   - Extend the project importer to discover dependencies and apply the same converters, validation and registration to newly discovered content. Use deterministic provenance, staged output, rollback/preservation on failure and repeatable reimports. Do not require another native code patch for each ordinary data variant. Unknown commands/resources remain explicit errors, not guessed behavior or silent skips.
   - Finish recoverable dependencies within the requested system: importer, native definitions/IO, resource lifetime, shared runtime owner, ordinary live entry path and registered checks. A few working examples, a successful batch command or an inventory count do not establish full support. Investigate available missing dependencies instead of repeatedly deferring them as unsupported; name a concrete blocker when completion is impossible.
5. **Implement.**
   - Cite the original address (bare 8-digit hex) at every ported function.
   - Mark native-only code `INTENTIONAL-DIVERGENCE` (or the marker the repo's rules name).
   - Keep definitions immutable, mutable state with a single owner, and no allocation in tick/frame paths.
6. **Check before testing.** Re-run `zkit_consts <file>` after changing constants; it should report them verified. `zkit_check native` lints your diff:
   - citations that don't resolve or point at unmatched decomp;
   - new gameplay functions without a citation;
   - the repo's forbidden patterns (area-specific branches, banned constructs);
   - `/tmp` paths or dated sections in docs.
7. **Verify like the game is played.**
   - Run `zkit_impact native`. It lists the other code that includes what you changed (the consumers you must not break) and the exact `ctest -R` commands for the tests covering it, direct ones first. Run those instead of a whole label or a render matrix. Measured on 40 real commits: impact selected 94% of the tests each commit itself changed, with a median of 9 fixture builds; the habitual `-L 'unit|reference'` sweep found 32% while building 187 fixtures. Size checks to the change: no performance or render matrix for a small fix unless it touches those paths. While iterating, `zkit_impact native budget=120` keeps every direct test, then covers each remaining test program with its cheapest near test, then fills cheapest first within 120 s of recorded time; the deferred rest has its own command for a shared or risky change. Before committing a shared change, run the full impact selection: on a real weapon-header change it found 3 failing checks that the `unit|reference` sweep (705 tests, all passing) cannot see. Where the finish gate asks for "owning local checks", `zkit_gate native` prints the exact command for the current diff.
   - A missing impact mapping may be a linked-library or script-import limitation. Inspect the owning catalog and recipes before adding a check. Impact reports exact test commands, optional build targets and unmeasured costs; use `zkit_test_plan` with exact CTest names to validate registration, see fixture costs and prebuild only the required targets when useful. Keep the repo's mandatory finish gate.
   - Also run the original-comparison recipe (`zkit_recipes`). Never regenerate expected output from native code.
   - Test the ordinary live route and another existing consumer of changed shared code. Include an unfamiliar valid data variant through the common import/runtime path, malformed/unsupported inputs and resource retirement. Verify which part of the declared inventory the checks exercise; preserve independent expected results.
   - Rendering checks run off-screen (virtual desktop), scoped to the change; kill what you start.
   - Before asking anyone to run the game or a tool, `zkit_stale native` must show it up to date (it compares the program with every source and header compiled into it, as Ninja does). Rebuild if not; "did you rebuild?" is a real failure the owner hit.
8. **Feed back.** If you recovered decomp evidence, bank it in the decomp. Update the owning system doc in place, and rewrite `docs/status.md`.

Finish with `zkit-finish`. Report source-traced, original-executed, native-integrated and presentation evidence separately.
