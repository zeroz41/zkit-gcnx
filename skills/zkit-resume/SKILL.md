---
name: zkit-resume
description: Start or resume a session on a decomp (GameCube or Switch) or a native port built from one, set up with zkit. Use at the beginning of any "continue the decomp" / "continue the port" request, after a context compaction, or when work from an interrupted session may be lying around.
---

# Start a session

1. **Brief.** Use the `zkit brief` block already in context (the session-start hook injects it), or call
   `zkit_brief <repo>`. It has the repo's rules, other live sessions and builds, uncommitted and stranded work,
   the last handoff (`zkit handoff <repo>` prints it in full) and progress.
2. **Read the user's message twice.** Do what it asks. A handoff, an IDE selection or the demand list never
   replaces the request. If the user answered something earlier, don't ask it again.
3. **Leave other work alone.** Dirty files, branches and worktrees may belong to another live session. Don't
   commit, merge, stash or delete what you didn't make; ask if it blocks you.
4. **Read the contract.** The repo's README/CONTRIBUTING/architecture docs and the brief's required reading.
   `zkit contract decomp` or `zkit contract port` prints the toolkit's rules for that kind of work.
5. **Size the machine.** The brief shows other agents and builds. Keep parallel jobs within available memory,
   one tree build at a time (`zkit wait <repo>` instead of sleep loops), and nothing that opens a window.
6. **Use the tools, not greps.** `zkit lookup|names|refs|xrefs|asm|data|decompile|unit|compiled` answer what
   grepping symbols, splits, sources or binaries would, with several addresses per call.

Then use `zkit-recover-function`, `zkit-clean-source`, `zkit-port-system` or `zkit-start-project`, and finish
with `zkit-finish`.
