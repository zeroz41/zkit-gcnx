---
name: zkit-resume
description: Start or resume a session on a GameCube decomp (and optional native port) set up with gcn-zkit. Use at the beginning of any "continue the decomp" / "continue development" request, after a context compaction, or when work from an interrupted session may be lying around.
---

# Resume a session

1. **Brief.** If a `zkit brief` block is already in context (the session-start hook injects it), use it. Otherwise call `zkit_brief` (MCP) or run `gcn-zkit brief` in the repo. It shows the repo's rules, the finish gate, other live sessions and builds, uncommitted or stranded work, the last handoff notes and the decomp's progress.
2. **Unfinished work comes first.** If the brief shows uncommitted files, a worktree with changes, an unmerged branch or a handoff that says "staged, not done":
   - Files touched in the last ~20 minutes, or a live process in that repo, belong to another session. Leave them alone.
   - Otherwise check that work with the repo's own build and tests. Keep it and commit if it passes; if it fails, say why in a handoff note.
3. **Pick the work.**
   - Decomp: follow the repo's own plan or router if it has one. With a native port configured, `zkit_demand` lists the decomp functions the port cites that are unmatched or unnamed, which is the highest-value decomp work.
   - Native port: take the next milestone from the repo's status doc.
4. **Read the repo contract** (`AGENTS.md`, `CONTRIBUTING.md`, or the docs it names) before acting on any rule. The brief summarizes it; it does not replace it.
5. **Use the tools instead of rediscovering.** `zkit_lookup`, `zkit_names`, `zkit_xrefs`, `zkit_asm`, `zkit_data`, `zkit_search` and `zkit_read` replace grepping `symbols.txt`, parsing `report.json` or writing throwaway scripts that read the DOL. All take several addresses per call. `zkit_lessons` lists known traps when the project has any.

When the session ends or you are about to run out of budget, use the `zkit-finish` skill.
