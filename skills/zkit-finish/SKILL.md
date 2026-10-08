---
name: zkit-finish
description: End a session on a gcn-zkit project correctly - run the repo's finish gate, lint the diff, commit as the repo requires, and leave a handoff note. Use before stopping, when the user says wrap up, or when usage/time is about to run out.
---

# Finish a session

1. Run `zkit_gate <repo>` and execute every command it lists, in order, for each repo you changed. If it reports that copies of the gate disagree, follow the repo's `AGENTS.md`. If it reports a stale build of a configured app, rebuild it before you report the work as ready to run.
2. Decomp: rebuild and compare match progress with what you started from. No function may lose its match.
3. Native port (when configured):
   - `zkit_check native` must have no errors. Fix warnings on code you added, or justify them.
   - `zkit_impact native` lists the tests that cover your diff. Run them.
   - Review the port's architecture and completion boundary: shared owners/interfaces/composition, automatic import/dependency handling, ordinary live path and another consumer. If configured, run scoped `zkit_architecture` and the relevant `zkit_coverage` inventory. Resolve in-scope gaps; report concrete blockers and unverified stages. Passing checks, complete inventory presence and an intermediate commit do not by themselves complete a system.
   - If you re-checked the files `zkit_drift` listed, record the new baseline with `zkit_drift accept=true`, and only then.
4. Commit verified work, following the repo's rules (shown in the brief) for author identity and message format. Don't commit original game files.
5. Always call `zkit_handoff <repo> "<note>"`, especially when you stopped early. A good note gives:
   - what is verified and committed (commit id);
   - what is in progress (paths, addresses);
   - what failed and why;
   - the exact next command.

   The next session's brief shows it automatically.
6. Stop any emulator, test run or build you started that is still running (`zkit_activity` lists them).
