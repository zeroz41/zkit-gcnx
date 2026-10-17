---
name: zkit-finish
description: End a session on a zkit project correctly - run the repo's finish gate, prove nothing regressed, commit as the repo requires, leave nothing behind, report honestly and leave a handoff. Use before stopping, when the user says wrap up or end, or when usage/time is about to run out.
---

# Finish a session

1. **`zkit_gate <repo>`** for every repo you changed. Run each listed command. It also shows what this session
   changed: the progress delta since it started (by address), commits that break the commit rules, processes
   still running and what would be left behind.
2. **No losses.** Decomp: `zkit progress --since session --check` passes. Refactors: `zkit objects --compare`
   is identical. Port: `zkit check native` has no errors and the tests `zkit impact native` names pass.
3. **Commit** verified work: one short line in plain words, the identity the repo uses, no Co-Authored-By or
   "generated with" line, no tool summaries. Never commit agent instructions, session notes, scratch scripts or
   original game files.
4. **Leave it clean.** `zkit hygiene <repo>`: no uncommitted files you made, no stashes, no stray or merged
   branches, no worktrees you created, no processes you started. Stop emulators, test runs and builds you began.
5. **Report honestly.** For each thing the user asked for: done (with the evidence: commit, delta, test) or not
   done (and why). Never call something ready that you have not run; "should work" is not done.
6. **`zkit_handoff <repo> "<note>"`**: what is committed (ids), what is in progress (paths, addresses), what
   failed and why, the exact next command. A newer note from this session replaces the last one.
