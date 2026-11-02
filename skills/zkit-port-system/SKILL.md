---
name: zkit-port-system
description: Implement or repair original-game behavior in a native port built from a matching decomp (a source port that compiles the decomp's code against a native library, or a native rewrite), so it does exactly what the original does through shared systems. Use for gameplay, actor, item, quest, area, effect, network or presentation work, fidelity bugs, or reuse refactors in a port configured in zkit.
---

# Port a system

The rules are `zkit contract source-port` (a source port: the decomp's game code compiled natively against a
native library such as sonarlib, unchanged except at declared edits) or, for a native rewrite, `zkit contract
port`, plus the project's architecture document and decisions file (the brief's required reading). This is the
loop.

1. **Is the reference ready?** `zkit port-plan <entry addr|name>` walks the original call tree:
   - `port`, `shared-port`, `reuse`: the decomp is matched, named and clean; port it (shared-port into one
     shared owner, reuse by extending the owner that already exists);
   - `decompile-first`, `clean-first`, `reuse-unverified`: the decomp is not ready (the plan lists why).
     Recover or clean it in the decomp first (`zkit-recover-function`, `zkit-clean-source`), or leave that part
     an explicit unsupported boundary. Never fill the gap with a plausible guess;
   - `platform`: SDK/runtime library code; a source port links the native library in its place, a rewrite
     uses its own platform code.
2. **Find the original's sharing.** `zkit lookup` and `zkit xrefs` on the functions you port: who calls them,
   in what order, with what data. Port the shared owner once and map every original caller; the bug or feature
   for one object is almost always a shared mechanism. In a source port the seam is the middleware: a kit
   replaces the shared middleware owner's hardware-facing functions, never single call sites.
3. **Write down what is observable** for this system before coding: update order, tick timing, random draws
   and their order, integer and float behavior, data values. Keep those exactly. In a source port the game code
   keeps the original's structure, and every edit to a decomp file is one of the declared kinds, with the
   matching build still building and matching. In a rewrite everything else gets the project's own design
   (owners, composition, interfaces, data through the importer).
4. **Implement** with a citation of the original address at every ported function (in a rewrite) and the
   project's marker on every intentional difference. Content variety is data, not branches on an area, quest
   or actor id. Original formats stay in the importer; protocols stay in adapters that feed the native
   interface.
5. **Fix at the cause.** A reported bug becomes a failing check from original evidence first. Then fix it
   where the original computes it, for every consumer.
6. **Verify the claim, sized to it.** `zkit impact native` gives the tests covering the diff; run those and one
   other user of each shared owner you changed. Drive the claimed scenario through the live path and compare
   with a capture of the original. Presentation changes: baseline goldens, off-screen. Performance runs only for
   hot-path changes, measured before and after on the same machine. `zkit stale native` before anyone runs a
   build.
7. **Check.** `zkit check native` (no errors: unresolved or not-ready citations, missing citations, forbidden
   patterns, include boundaries, near-miss constants), `zkit consts <file>` for its numbers. `zkit grounding`
   shows how proven the port is overall and where it most likely differs; `zkit drift` what changed in the
   decomp under code already ported.
8. **Feed back.** Evidence found while porting goes into the decomp as matched, named code; update the system's
   document in place.

Report what was verified against the original, what was only built, and what stays unsupported, separately.
Finish with `zkit-finish`.
