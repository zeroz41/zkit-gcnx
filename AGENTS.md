# gcn-zkit development

Layers (see docs/design.md):
- `gc.py`: formats (DOL, disc image, dtk symbols/splits/asm).
- `index.py`: the incremental SQLite index (DOL and REL functions, calls, xrefs, cites, text).
- `bridge.py`, `session.py`, `activity.py`, `inspect_dol.py`, `native.py`, `fidelity.py`: the answers.
- `onboard.py`: `init` and project selection by folder.
- `render.py`: compact text.
- `cli.py` and `server.py`: thin transports.

Put new behaviour in an answer module, expose it from both the CLI and MCP, and add a synthetic test
(`tests/test_bridge.py` for a decomp + native port, `tests/test_generic.py` for a fresh dtk project with RELs).

This repo is for any GameCube decomp and port. Nothing game-specific goes in it: a game's rules, lessons, evals and
project file live with that game, outside this repo (see docs/manifest.md). `src/` must
work for any dtk project, with or without RELs or a native port. It must run on Linux, macOS and Windows: UTF-8
for every text read and write, `/` in stored paths, no shell syntax in plugin commands, and /proc-only code behind a
fallback. Tools stay read-only toward the repos; the only writes are the toolkit's own config, cache and handoff
notes. Don't add build, bank, merge or emulator execution through MCP.

Every answer states its limits; nothing claims runtime parity from a match or a citation. Measure changes on real
projects (`python tools/smoke.py`, `python tools/ab_eval.py`) and record results in docs/validation.md.
Test with `uv run --with-editable . python -m unittest discover -s tests`. Validate the plugin with
`claude plugin validate .`.
