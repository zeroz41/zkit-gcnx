---
name: zkit-resume
description: Start or resume a session on a GameCube decomp (and optional native port) set up with gcn-zkit. Use at the beginning of any "continue the decomp" / "continue development" request, after a context compaction, or when work from an interrupted session may be lying around.
---

# Resume a session

1. **Brief.** If a `zkit brief` block is already in context (the session-start hook injects it), use it. Otherwise call `zkit_brief` (MCP) or run `gcn-zkit brief` in the repo. It shows the repo's rules, the finish gate, other live sessions and builds, uncommitted or stranded work, the last handoff notes and the decomp's progress.
2. **Preserve unfinished work.** Dirty files, unmerged branches and handoffs are context, not ownership proof. File age does not authorize taking over work. Follow the repo's isolation policy, inspect the current branch/HEAD and identify work relevant to the request. Do not automatically merge abandoned branches or resume a paused milestone.
3. **Pick the work from the user's request.** An IDE selection, stale handoff or decomp demand list does not replace a native-port task.
   - Decomp: follow the repo's own router and bounded recovery workflow. `zkit_demand` helps prioritize original functions used by a port; it does not choose a new project.
   - Native port: carry the requested playable milestone through its recoverable dependencies and live integration. Recover shared mechanisms through composition/interfaces appropriate to their owners; automate source discovery and import dependencies through the project pipeline. Content identity or shape must not substitute for authored behavior. Carry import, native definitions, live integration and registered verification together. A component comparison or intermediate commit is a checkpoint, not completion of the milestone.
4. **Read the repo contract** (`AGENTS.md`, `CONTRIBUTING.md`, or the docs it names) before acting on any rule. Read the manifest’s required-reading references, including its architecture/design guide, source layout, engineering and performance standards. Identify the owning system, allowed dependencies and existing extension seams before selecting an implementation. For native porting, task scope narrows the work, not those requirements. Matching decomp preserves original structure, owning translation units and compiler constraints; do not apply native-engine refactors to matching code. The brief summarizes the contract; it does not replace it.
5. **Use the tools instead of rediscovering.** `zkit_lookup`, `zkit_names`, `zkit_xrefs`, `zkit_asm`, `zkit_data`, `zkit_search` and `zkit_read` replace grepping `symbols.txt`, parsing `report.json` or writing throwaway scripts that read the DOL. All take several addresses per call. `zkit_lessons` lists known traps when the project has any.

When the session ends or you are about to run out of budget, use the `zkit-finish` skill.
