---
name: zkit-start-project
description: Set up a new matching decomp (GameCube/Wii built with CodeWarrior, or Switch with clang) or a new native port of one, with the right structure from the first commit. Use when the user starts a decomp or port, or asks how a new one should be laid out.
---

# Start a project the right way

Most later repair work came from early shortcuts. Get these right before matching or porting anything.

**A decomp** (`zkit contract decomp`):
1. The original stays local: the user's own dump, never committed, with its hash pinned in the build.
2. Identify the toolchain: compiler and version, SDK and library versions (version strings, prologues, a seed
   probe). Pin donor sources for libraries before touching game code.
3. Partition every address into units from boundary evidence ("Units come from boundary evidence") and give each unit its data
   ("A unit owns its data"): `zkit units` proposes them, `zkit units --check` audits a split. Placeholder units for
   unknown ranges; no slices or wrappers, ever.
4. Build the class graph and generate headers with bases and full virtual blocks before matching methods:
   `zkit classes --headers include/classes --prove`.
5. Wire objdiff: `zkit delink --objdiff objdiff.json` writes every unit's target object and the project file, the
   build writes `report.json`, `zkit report` the page.
6. `zkit build --download` fetches the compilers and tools the target's platform needs, pinned and hash-checked,
   into `build/` (never committed). It never fetches another platform's tools; don't download any by hand.
7. `zkit init <repo>` writes the project file with strict hygiene and quality gates; `zkit install git-hook
   --write <repo>` enforces commit rules and the slop gate locally.

**A port** (`zkit contract port`):
1. Write the architecture document first: owners, interfaces, dependency direction, the import pipeline, the
   fidelity tiers and the per-project decisions (libraries, formats, frame caps) kept separate from the rules.
2. Behavior comes only from a clean decomp. List the systems to port and their readiness (`zkit port-plan`);
   anything not ready is decomp work first or an explicit unsupported boundary.
3. Set up the original-vs-port comparison path (captures from the original running in an emulator) and the
   test labels and budgets before the first gameplay feature.

**Both:** the repository holds README (what, build, use), contributor guide and architecture docs. Agent
instructions stay local (`.git/info/exclude`), as do session notes and scratch scripts. Commits are one short
line under the developer's identity, never with an AI co-author.
