# Source-port contract

Rules for a source port of a matching decompilation: the decomp's game code compiles natively, unchanged except
at declared edit sites, and links against a native library instead of the console SDK. The library is
scaffolding, so a port changes the game as little as possible. A native rewrite, which uses the decomp as the
behavioral reference for new code, follows `zkit contract port` instead.

Terms: the **original** is the shipped program and data; the **decomp** is the matching decompilation of it; the
**matching build** is the decomp's own build of the original; the **port** is the same tree built natively; the
**library** is the native library the port links in place of the console SDK; a **kit** is a library module
that replaces a middleware library's hardware-facing functions and leaves its logic alone; a **seam file** is a
game file that calls the console API directly, outside any middleware.

## 1. Where a port lives

1. A port is a branch of the decomp's repository, or of a fork of it, with one added top-level directory: the
   native build, replacement seam files, the adapter (loop hookup, the game's kit configuration, interpolation
   hooks), the importer, the game's tests and the seam policy.
2. The matching build keeps working from the same tree. Upstream decomp fixes stay mergeable, and the matching
   build shows that edits to shared files did not change code generation.

## 2. Behavior authority

3. The game's behavior comes from the matched decomp, never from a reimplementation of it. The game code compiled
   into the port is the matched decomp itself, and this authority covers everything the port keeps from the
   original. `zkit port-plan` marks which functions are matched, named and clean enough to port from.
4. A function that exists only as assembly cannot be compiled for the host, so it is an unsupported boundary until
   it is matched.
5. Inline assembly gets a C fallback that transliterates it line for line onto helpers for the console's
   instructions and arithmetic and keeps its register names, so a reviewer reads one against the other and the
   fallback computes the console's bits. It lives beside the assembly it replaces. A feature whose assembly is not
   converted yet may be disabled and reported as unsupported.
6. The library and its kits contain no console vendor code or data. Decompiled SDK code is a behavioral reference
   for them only, and what is written from it cites its reference symbolically.

## 3. Structure and sharing

7. Game code keeps the original's structure, because changing it would break the matching build and upstream
   merges. It is not reorganized or optimized per port. The library, its kits and the port's own code have an
   architecture of their own.
8. **Original sharing first.** The seam is the middleware: a seam replaces the shared middleware owner, never
   single call sites.
9. A kit splits into format-level code, which converts the middleware's stable formats into native objects and
   is shared across games, and call-site glue for the game's version of the middleware's classes, which lives in
   the port.
10. The SDK's OS objects (message queues, threads, alarms, mutexes, conditions, interrupt state, the time base) are
    bound to the library's OS module once, in one kit. The port's glue defines the SDK's OS functions on that kit,
    so game code and the middleware built on them stay as the decomp has them. Each object stays the game's struct
    at the game's address. The exception covers the OS objects only: graphics, video, pad, disc and card stay
    middleware seams.
11. Game code includes only the library's public headers, kit headers and its own adapter headers, never backend
    or platform-layer headers.

## 4. Seams and glue

12. Each seam file is either substituted by a port file that calls the library through a kit or its core API, or
    listed in the seam policy as a remaining transitional site.
13. Console calls outside graphics are counted the same way. Most are short, and the port replaces them with core
    calls in Portability edits that keep the original call in the matching build.
14. The platform glue is the loop hookup (where a tick begins and ends, where frames are submitted), input mapping
    from the library's virtual controller to the game's pad-reading code, mounting the imported packages, and
    mapping the game's memory-card code to the library's save storage: usually one small file each.
15. The game's own main loop runs unchanged on a game thread. The port replaces only the wait that ends the game's
    frame, in the kit that owns it or in the game's loop, with the library's tick wait; other waits for vertical
    blank wait on the retrace clock. Every nested wait loop keeps working.
16. GameCube and Wii game threads are host threads under the console CPU model: one token, and an interrupt context
    that excludes them as the console did. Switch games use real threads and fibers; the token model does not
    apply to them.
17. Relocatable modules are linked statically. The adapter calls each module's prolog and epilog where the original
    loaded and unloaded it, and before calling a prolog again restores the module's initial data and clears its
    `.bss`. Static constructors that allocate from a game heap before the heap exists become Portability edits.
18. The game's global `operator new` and `delete` are wrapped: allocations from threads the game does not own, or
    before its heaps exist, go to the host allocator, and `delete` picks the allocator by address range.

## 5. The transitional GX front end

19. A port may link the transitional GX front end to compile listed seam files unchanged while they are converted.
    This replaces the rewrite-era rule that confines SDK and GPU shims to test oracles and importers.
20. The library and its kits never use the front end.
21. The seam policy lists every game file that calls it, and the seam audit reports the count and the call sites
    on every build. A port is **seam complete** when the list is empty. A kit's use of the stateless display-list
    decoder for display lists the game builds itself does not count against it.
22. Front-end draws still interpolate, through owner tagging, less precisely than draws with explicit identities.

## 6. Edits

23. Every edit to a decomp file is one of five declared kinds, and the seam audit tags and counts each:
    - **Seam call site:** a console call site becomes a library call, such as a GX state block that becomes a
      material created at init. The port substitutes the whole file, or guards the block.
    - **Portability:** widening a pointer field, a C fallback for inline assembly, byte-swapping on load. Portable
      code that still compiles to the same match, or a guard.
    - **Interpolation hook:** marking an object's draw boundary, or snapping on a teleport. A one-line call through
      a kit macro that expands to nothing in the matching build.
    - **Enhancement:** such as a culling hook that returns a wider drawing result for widescreen. Guarded and off
      by default.
    - **Change:** a new item, a rebalanced rule, a hook for new content. Guarded by the port build; on or off by
      default, as the port chooses.
24. After every edit the matching build still builds and matches.
25. File substitution is preferred to `#ifdef` blocks. When most of a file is seam, the port build compiles a
    replacement file instead, and the original file stays untouched.
26. An edit only the port needs is guarded by the port build's macro, with the original kept in the other branch
    for the matching build. An edit that compiles to the same code in both builds, such as a declaration retyped
    to an address typedef, needs no guard.
27. Edits stay minimal and tagged by kind, so the branch does not drift from upstream.

## 7. 64-bit and byte order

28. Ports target 64-bit little-endian hosts. A 32-bit x86 build is a transitional step to boot before pointer
    widening is done; a port is complete only as a 64-bit build. Big-endian hosts are not supported, and keeping
    allocations below 4 GB is not a fix.
29. Port builds take the console integer typedefs at fixed width from the library, and `size_t` from the host; the
    decomp's typedef headers are guarded so port builds include them. The matching build keeps its original types,
    which the original compiler's name mangling encodes.
30. Each unit builds with the host equivalent of its original `char` signedness, read from the decomp's own build.
    Flags that only affect code generation are ignored. Game units build with strict aliasing off, signed
    arithmetic wrapping and null checks kept after a dereference.
31. Size assertions that fail once pointers widen are guarded to the matching build.
32. A 32-bit field that holds a pointer is widened in the port, through address typedefs where the decomp has them,
    so the matching build is unchanged. Where the field is part of an on-disc layout, the importer widens the
    layout. Arena guards and sanitizer replays find the fields that were missed.
33. Integer division by zero, and of the most negative value by -1, goes through helpers that give the console's
    results.
34. Bitfields and byte views of integers are harmless in memory the game both writes and reads. Where such a
    structure crosses a data boundary the converters handle it, and the seam audit flags byte views in units that
    read raw data.

## 8. Content and data

35. Original formats on disc are read only by the importer. It converts structures to native layout once, at
    import time, with swap-and-widen converters generated from a schema of each structure (from DWARF where the
    decomp has it, or from headers). The game loads converted packages.
36. Offsets that the game relocates to pointers in place are stored as 64-bit pointers or widened offsets in the
    packages; the relocation code becomes a no-op or reads the widened table.
37. Big-endian data that arrives at run time (saves, link-cable data, peripheral cards) is converted where the game
    copies it in or out: whole structures by generated converters in both directions, single fields by big-endian
    load and store helpers.
38. Data the game builds at run time (display lists, textures the CPU writes, render-to-texture copies) goes
    through the same format modules at run time, cached by content hash.
39. Packages carry a version. The runtime refuses packages from an incompatible importer, and a new importer
    version imports again from the verified disc. Each output records the source file and offset that produced it.
40. A port is distributed as source only: nothing compiled from the game or derived from its data is distributed
    or committed. The player's build verifies the disc image against the disc IDs, revisions and per-file hashes the
    port declares, extracts the data linked into the executable, compiles, imports and bakes shaders on the
    player's machine. An unknown image stops the build with its ID and hash.
41. Saves live in the library's save store. The original save formats stay readable and writable, so saves move to
    and from emulators and consoles, and a port that keeps the game's card code runs it on a virtual memory card.

## 9. Floating point

42. A port that claims Exact-tier simulation builds game code with floating-point contraction off, without x87
    math and without fast-math flags.
43. Where the original compiler fused a multiply-add, the source says so through an explicit fused-operation macro,
    which expands to the plain expression in the matching build.
44. Console operations go through the library's tested helpers: reciprocal estimates, saturating float-to-integer
    conversion, single-precision arithmetic with the console's operand rounding, single loads and stores, and the
    non-IEEE mode.
45. Game code uses the decomp's own math library, never host libm; a link check rejects host libm symbols in game
    objects.
46. Sites are found by tools, not by reading code: a contraction audit comparing fused operations per function
    between the original and the port, float-cast-overflow sanitizer replays, and replay divergence.

## 10. Fidelity tiers

47. Every feature declares a tier:
    - **Exact:** at 1x render scale with enhancements off, output matches the original within the tolerances its
      checks state. Exact-tier simulation gives the original's state for the same inputs.
    - **Presentation:** changes how frames are shown, not what the game computes (interpolation, render scale,
      widescreen, upscaling, anti-aliasing).
    - **Liberty:** changes the look on purpose. A port's own Changes are Liberty.
    - **Platform:** exists only on the host (window modes, HDR output, present modes).
48. Each Presentation and Liberty feature has a setting. A port may turn Presentation features on by default; the
    library's Liberty features always start off, and the port chooses each Change's default.
49. Every intentional difference carries its tier's marker and an entry in the port's tier registry.
50. In the Exact tier the port runs at the console's video rate; a 60 Hz option is Liberty.

## 11. Simulation and time

51. Simulation runs only on ticks. Game code sees ticks only, and the library gives it no frame time. Nothing the
    simulation computes depends on the display rate.
52. Game draw code runs once per tick and records a retained frame with identity-tagged transforms, which the
    presenter blends at any rate. This is the default shared presentation mechanism; a port with its own renderer
    samples previous and current state instead.
53. Identity comes from kits for middleware-drawn objects, and from owner boundaries that interpolation hooks mark
    where the game dispatches drawing. Heuristic matching is off by default. Kits forget an owner when its object
    is destroyed, and the port snaps objects on teleports, respawns and warps.
54. The frame-rate sweep is the required check, whichever mechanism presents: the same input at 30, 60, 90, 120,
    144, 240 and 360 Hz, uncapped and with interpolation off, and each enhancement on and off at one rate.
    Simulation state is identical at every rate; at alpha 1 the presented frame is bit-identical to the frame
    without interpolation; presented frames never move backward except at recorded snaps; every snap has a
    recorded cause.
55. Deterministic mode runs every time source the game can observe on virtual time derived from the tick counter:
    the time base and calendar, alarms, audio-frame callbacks, retraces and their callbacks, read and card
    completions, and query results. Presentation, audio output and input sampling stay on real time.
56. The game thread does what the console's CPU did, once per tick: simulation and frame recording. Work that scales
    with display rate, resolution or effects is library code on the GPU or worker threads.

## 12. Changes to the game

57. A port does not have to reproduce the original. It may change rules, add content and systems, and replace
    whole parts, as Change edits or the port's own code, marked Liberty.
58. Library rules bind only the ports that claim the feature needing them. Parity tests cover only what a port keeps
    from the original and skip what it changes; native determinism still holds for all of it.

## 13. Evidence

59. Every fidelity claim is checked by a registered test. A run fails unless every registered test of its tiers ran
    and passed: a test that exists is not a test that passes.
60. Port goldens come from an input replay from boot, captured at chosen ticks with enhancements off, at 1x, through
    a virtual display and with a null audio sink. The reference is the original running the same input movie in
    an emulator, dumped at the same ticks.
61. A port that claims Exact-tier simulation passes two levels in deterministic mode. Native determinism: the same
    inputs give the same per-tick state on every host, compiler, optimization level and presentation rate (replay
    hash matrix, frame-rate sweep, state dumps that name the first differing variable, sanitizer replays). Parity
    with the original: traces of chosen variables from the original replaying the same input movie, compared at
    the first differing tick and variable.
62. Input movies replayed in the emulator are the parity corpus, and no game gets a determinism harness of its own.
    A claim reads "no divergence over N hours of corpus", with N published. Each difference that comes from the
    emulator's interrupt timing is listed and explained.
63. Game data is never committed. Port tests run locally or on private runners with the developer's own copy,
    never in public CI.

## 14. Seam audit

64. The seam audit reads the port's compile commands and its seam policy, and reports: console SDK headers included
    and SDK symbols referenced outside allowed files, by category; every transitional front-end call site;
    portability patterns (casts between pointers and 32-bit integers, `long` in edited code, size assertions, byte
    views of integers in units that read raw data); and every declared edit, by kind.
65. It runs on every build and fails when a count rises without a policy change. Its output is the port's burn-down
    metric, and its counts are published.

## 15. Planning and done

66. Before work starts, measure the seam: every console API the game uses, by category and file, and the
    readiness of the call trees the port rests on (`zkit port-plan`).
67. Work is done when its checks pass, not when its code exists. A port is seam complete when no listed file uses
    the front end, and complete only as a 64-bit build.
