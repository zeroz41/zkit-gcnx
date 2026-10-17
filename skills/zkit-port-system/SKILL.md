---
name: zkit-port-system
description: Implement or repair original-game behavior in a native port built from a matching decomp, so it does exactly what the original does through shared, well-structured systems. Use for gameplay, actor, item, quest, area, effect, network or presentation work, fidelity bugs, or reuse refactors in a port configured in zkit.
---

# Port a system

The rules are `zkit contract port` plus the project's architecture document and decisions file (the brief's
required reading). This is the loop.

1. **Is the reference ready?** `zkit port-plan <entry addr|name>` walks the original call tree:
   - `port`, `shared-port`, `reuse`: the decomp is matched, named and clean; port it (shared-port into one
     shared owner, reuse by extending the owner that already exists);
   - `decompile-first`, `clean-first`, `reuse-unverified`: the decomp is not ready. Recover or clean it in the
     decomp first (`zkit-recover-function`, `zkit-clean-source`), or leave that part an explicit unsupported
     boundary. Never fill the gap with a plausible guess.
2. **Find the original's sharing.** `zkit lookup` and `zkit xrefs` on the functions you port: who calls them,
   in what order, with what data. Port the shared owner once and map every original caller; the bug or feature
   for one object is almost always a shared mechanism.
3. **Write down what is observable** for this system before coding: update order, tick timing, random draws
   and their order, integer and float behavior, data values. Keep those exactly; everything else gets the
   project's own design (owners, composition, interfaces, data through the importer).
4. **Implement** with a citation of the original address at every ported function and the project's marker
   on every intentional difference. Content variety is data, not branches on an area, quest or actor id.
   Original formats stay in the importer; protocols stay in adapters that feed the native interface.
5. **Fix at the cause.** A reported bug becomes a failing check from original evidence first. Then fix it
   where the original computes it, for every consumer.
6. **Verify the claim, sized to it.** `zkit impact native` gives the tests covering the diff; run those and one
   other user of each shared owner you changed. Drive the claimed scenario through the live path and compare
   with a capture of the original. Presentation changes: baseline goldens, off-screen. Performance runs only for
   hot-path changes, measured before and after on the same machine. `zkit stale native` before anyone runs a
   build.
7. **Check.** `zkit check native` (no errors: unresolved or not-ready citations, missing citations, forbidden
   patterns, near-miss constants), `zkit consts` for numbers, `zkit architecture` for boundaries if configured.
8. **Feed back.** Evidence found while porting goes into the decomp as matched, named code; update the system's
   document in place.

Report what was verified against the original, what was only built, and what stays unsupported, separately.
Finish with `zkit-finish`.
