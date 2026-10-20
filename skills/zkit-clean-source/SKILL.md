---
name: zkit-clean-source
description: Clean up a matching decomp's source without changing a single byte - turn decompiler output (extern "C" bodies on void *, call-site prototypes, raw offsets, fake vtables, temporaries, placeholder names, re-typing macros) into real classes, members, fields and names, proven by object identity. Use when asked to clean, refactor, headerize or rename decomp source.
---

# Clean decomp source

Cleanup repairs what the matching workflow should have prevented (`zkit contract decomp`: "Classes before members", "Write source, not decompiler output"). Do it
in lanes that cover a whole category, prove every step, and measure on the tree.

1. **Measure first.** `zkit quality` shows the debt by kind and the worst files. Pick the category with the
   most items that one evidence rule can fix everywhere; not one file or one class at a time.
2. **Save the objects.** `zkit objects --save --label before` (and `zkit progress --since` has the session's
   baseline).
3. **Rewrite with one evidence rule** (a tool you write or the repo's lane), verifying per unit: compile the
   touched unit with its exact flags and compare objects. When a unit fails, narrow the rejection to the
   functions whose code changed and retry; blame the named culprit before collateral. A rename converts every
   caller in the same step.
4. **Prove the tree.** Build, then `zkit objects --compare --label before --rename-json <map>`: every object
   identical apart from intended renames, nothing gone. `zkit progress --since session --check`: no function,
   link or data range lost.
5. **Measure the result** with `zkit quality --since <commit>`. A tool's own summary line over-counts; report
   only the measured delta. If a category got worse (renames respelling callers), fix it before committing.
6. **Commit each proven step** with one short line ("Read TObjEnemy fields by name"), no tool summary, no
   trailer.
7. **Stop rule.** Two consecutive waves under about fifty items: widen the evidence rule or the rejection
   granularity, or stop and hand off.

Never edit a lane's code while a run of it is live, never run two lanes that share a scratch folder, and keep
parallel compiles within available memory.

Finish with `zkit-finish`.
