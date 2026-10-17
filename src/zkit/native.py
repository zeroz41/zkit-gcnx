"""Native-port answers: which tests prove a change, and how well a system is grounded.

impact     changed files -> other code that includes them (the "other consumers" a shared change
           must be re-tested against) -> test executables that compile them -> CTest names,
           grouped by label, with recorded run times and ready-to-run commands.
grounding  for native files/folders: how many cited original functions are exact, linked,
           semantically named, unmatched or unresolved in the decomp, and which ported functions
           cite nothing.

Both read the build's own files (compile_commands.json, `ctest --show-only=json-v1`,
CTestCostData.txt). Nothing here builds or runs tests.
"""

from __future__ import annotations

import collections
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from .bridge import _changed_files, _normalize, _status, default_target
from .index import connect, containing, refresh
from .project import Project, under as _under

INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".inc"}


def _tests_config(project: Project, repo: str) -> dict:
    config = project.config["repositories"][repo].get("tests")
    if not config:
        raise ValueError(f"Repository {repo} has no `tests` block (build_dir, include_roots) in the manifest")
    return config


class IncludeGraph:
    """Quoted #include edges among the repo's sources, resolved like the compiler would."""

    def __init__(self, root: Path, roots: list[str], scan: list[str]):
        self.root = root
        self.roots = [root / r for r in roots]
        self.files: list[str] = []
        self.includers: dict[str, set[str]] = collections.defaultdict(set)
        for base in scan:
            for directory, dirs, names in os.walk(root / base):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d != "build"]
                for name in names:
                    if Path(name).suffix in SOURCE_SUFFIXES:
                        self.files.append(Path(directory, name).relative_to(root).as_posix())
        known = set(self.files)
        # Resolve each common include-root candidate once. Most includes are rooted at
        # src/ or tests/; pathlib.resolve/relative_to per edge dominated real queries.
        resolved: dict[tuple[str, str], str | None] = {}
        root_text = str(root)

        def resolve(base: str, target: str) -> str | None:
            key = (base, target)
            if key not in resolved:
                candidate = os.path.realpath(os.path.join(base, target))
                try:
                    relative = os.path.relpath(candidate, root_text).replace(os.sep, "/")
                except ValueError:  # Windows: another drive
                    relative = ""
                resolved[key] = relative if relative in known else None
            return resolved[key]

        roots_text = [str(r) for r in self.roots]
        for rel in self.files:
            try:
                text = (root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            here = os.path.dirname(os.path.join(root_text, rel))
            for target in INCLUDE.findall(text):
                for base in [here, *roots_text]:
                    name = resolve(base, target)
                    if name is not None:
                        self.includers[name].add(rel)
                        break

    def distances(self, seeds: set[str]) -> dict[str, int]:
        """Breadth-first include distance from the seeds (0 = the changed file or its pair)."""
        known = set(self.files)
        seen = {s: 0 for s in seeds}
        frontier = list(seeds)
        while frontier:
            nxt = []
            for node in frontier:
                for parent in self.includers.get(node, ()):
                    # X.cpp and X.hpp are one unit: code reaching X.cpp is tested through X.hpp's includers.
                    for member in _companions(parent, known):
                        if member not in seen:
                            seen[member] = seen[node] + 1
                            nxt.append(member)
            frontier = nxt
        return seen


def _companions(rel: str, known: set[str]) -> set[str]:
    """A .cpp change affects whoever includes its header; a header change, its .cpp."""
    stem = Path(rel).with_suffix("").as_posix()
    return {stem + s for s in SOURCE_SUFFIXES if stem + s in known} | {rel}


def _targets(build: Path, root: Path) -> dict[str, set[str]]:
    """source file -> CMake targets that compile it (from compile_commands.json)."""
    path = build / "compile_commands.json"
    out: dict[str, set[str]] = collections.defaultdict(set)
    if not path.is_file():
        return out
    for entry in json.loads(path.read_text(encoding="utf-8")):
        command = entry.get("command") or " ".join(entry.get("arguments", []))
        output = entry.get("output") or (re.search(r"-o\s+(\S+)", command) or [None, ""])[1]
        match = re.search(r"CMakeFiles[/\\]([^/\\]+)\.dir[/\\]", output or "")
        if not match:
            continue
        try:
            file = Path(entry["file"])
            if not file.is_absolute():
                file = Path(entry.get("directory", ".")) / file
            rel = file.resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        out[rel].add(match[1])
    return out


def _catalog(build: Path) -> list[dict]:
    result = subprocess.run(["ctest", "--test-dir", str(build), "--show-only=json-v1"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    if result.returncode:
        raise ValueError(f"ctest catalog failed in {build}: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout).get("tests", [])


def _costs(build: Path) -> dict[str, float]:
    path = build / "Testing" / "Temporary" / "CTestCostData.txt"
    costs = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) == 3:
                try:
                    costs[parts[0]] = float(parts[2])
                except ValueError:
                    pass
    return costs


def _programs(test: dict, build: Path) -> set[str]:
    """Executables a test runs: its program, or build-dir executables passed to a script."""
    names = set()
    build = build.resolve()  # CTest records paths as the build saw them, maybe through a symlink
    for index, part in enumerate(test.get("command") or []):
        if not part or not os.path.isabs(part):
            continue
        path = Path(os.path.realpath(part))
        if path.parent == build or (index == 0 and path.is_relative_to(build)):
            names.add(path.name)
    return names


CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


DEFINES = re.compile(r"^[\w:<>\s\*&]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{", re.M)


class _Sources:
    """Test-source texts and their top-level function definitions, read once per impact()."""

    def __init__(self, root: Path):
        self.root, self.text, self.defines = root, {}, {}

    def get(self, rel: str) -> str:
        if rel not in self.text:
            try:
                self.text[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                self.text[rel] = ""
            self.defines[rel] = set(DEFINES.findall(self.text[rel]))
        return self.text[rel]


def _case_sources(cache: _Sources, test: dict, sources: list[str]) -> list[str]:
    """For a multi-suite executable selected by a --flag, the source defining that suite.

    Matches the common dispatcher shape: a line comparing argv to "--flag", then a call
    such as runEnemyControllerTests(); the source that defines that function owns the case."""
    flags = [a for a in (test.get("command") or [])[1:] if a.startswith("--")]
    if not flags or len(sources) < 3:
        return sources
    for flag in flags:
        needle = f'"{flag}"'
        for rel in sources:
            text = cache.get(rel)
            index = text.find(needle)
            if index < 0:
                continue
            for name in CALL.findall(text[index + len(needle):index + len(needle) + 300]):
                owners = [r for r in sources if r != rel and (cache.get(r) is not None) and name in cache.defines[r]]
                if len(owners) == 1:
                    return owners
    return sources


def _command_files(test: dict, build: Path, root: Path) -> set[str]:
    """Literal source/script arguments in a CTest command; no inferred imports."""
    directory = next((p["value"] for p in test.get("properties", [])
                      if p["name"] == "WORKING_DIRECTORY"), str(build))
    directory = Path(directory)
    if not directory.is_absolute():
        directory = build / directory
    result = set()
    for arg in test.get("command") or []:
        if not arg or arg.startswith("-"):
            continue
        path = Path(arg)
        if not path.is_absolute():
            path = directory / path
        try:
            if path.is_file():
                result.add(path.resolve().relative_to(root).as_posix())
        except (OSError, ValueError):
            continue
    return result


def _test_commands(test_dir: str, names: list[str]) -> list[list[str]]:
    """Bound command size without widening a selection to an entire label."""
    chunks, chunk, length = [], [], 0
    for name in names:
        escaped = re.escape(name)
        if chunk and length + len(escaped) > 3000:
            chunks.append(chunk)
            chunk, length = [], 0
        chunk.append(escaped)
        length += len(escaped) + 1
    if chunk:
        chunks.append(chunk)
    return [["ctest", "--test-dir", test_dir, "-R", "^(" + "|".join(c) + ")$",
             "--output-on-failure", "--no-tests=error"] for c in chunks]


def _display_command(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)


def _fixture_build(test: dict, build: Path) -> tuple[tuple[str, ...], list[str]] | None:
    """Only consolidate independent, plain CMake build fixtures; preserve other setup."""
    props = {p['name']: p['value'] for p in test.get('properties', [])}
    command = test.get('command') or []
    if (not props.get('FIXTURES_SETUP') or
            any(props.get(p) for p in ('FIXTURES_REQUIRED', 'DEPENDS', 'ENVIRONMENT', 'ENVIRONMENT_MODIFICATION')) or
            not command or Path(command[0]).name.lower() not in ('cmake', 'cmake3', 'cmake.exe')):
        return None
    directory = Path(props.get('WORKING_DIRECTORY', str(build)))
    if not directory.is_absolute():
        directory = build / directory
    binary, configuration, targets = None, None, []
    index = 1
    while index < len(command):
        option = command[index]
        index += 1
        if option in ('--build', '--config') and index < len(command):
            if option == '--build':
                binary = command[index]
            else:
                configuration = command[index]
            index += 1
        elif option == '--target':
            while index < len(command) and not command[index].startswith('-'):
                targets.append(command[index])
                index += 1
        else:
            return None
    if not binary or not targets or set(targets) & {'all', 'clean', 'install'}:
        return None
    binary = Path(binary)
    if not binary.is_absolute():
        binary = directory / binary
    prefix = (command[0], '--build', str(binary.resolve()))
    if configuration:
        prefix += ('--config', configuration)
    return (str(directory.resolve()), *prefix), targets


def test_plan(project: Project, repo: str, names: list[str], jobs: int = 2) -> dict:
    """Resolve exact tests and their fixture closure; suggest commands without executing them."""
    if not names or any(not isinstance(n, str) or not n.strip() for n in names):
        raise ValueError('Pass one or more exact CTest names')
    if isinstance(jobs, bool) or jobs < 1 or jobs > 1024:
        raise ValueError('jobs must be between 1 and 1024')
    config = _tests_config(project, repo)
    root = project.root(repo)
    build = root / config.get('build_dir', 'build')
    catalog_file = config.get('catalog')
    catalog = (json.loads((root / catalog_file).read_text(encoding='utf-8')).get('tests', [])
               if catalog_file else _catalog(build))
    catalog = {t['name']: t for t in catalog}
    props = {n: {p['name']: p['value'] for p in t.get('properties', [])} for n, t in catalog.items()}
    selected = sorted(set(names))
    missing = [n for n in selected if n not in catalog]
    included = set(selected) - set(missing)
    pending = list(included)
    fixtures = set()
    unresolved = set()
    while pending:
        name = pending.pop()
        for fixture in props[name].get('FIXTURES_REQUIRED', []):
            if fixture in fixtures:
                continue
            fixtures.add(fixture)
            providers = {n for n, p in props.items() if fixture in p.get('FIXTURES_SETUP', [])}
            if not providers:
                unresolved.add(fixture)
            additions = providers | {n for n, p in props.items() if fixture in p.get('FIXTURES_CLEANUP', [])}
            pending.extend(sorted(additions - included))
            included.update(additions)
    disabled = sorted(n for n in included if props[n].get('DISABLED'))
    fixture_tests = sorted(included - set(selected))
    costs = _costs(build)

    def cost(test_names: list[str]) -> dict:
        return {'tests': len(test_names), 'recorded_seconds': round(sum(costs.get(n, 0) for n in test_names), 2),
                'unknown_costs': sum(n not in costs for n in test_names)}

    groups: dict[tuple[str, ...], dict] = {}
    for name in sorted(included):
        if name in disabled:
            continue
        recognized = _fixture_build(catalog[name], build)
        if recognized:
            key, targets = recognized
            group = groups.setdefault(key, {'targets': set(), 'fixtures': []})
            group['targets'].update(targets)
            group['fixtures'].append(name)
    prebuilds = []
    for key, group in groups.items():
        # Split unusually large target sets without introducing a broad build target.
        chunks, chunk, length = [], [], 0
        for name in sorted(group['targets']):
            if chunk and length + len(name) > 3000:
                chunks.append(chunk)
                chunk, length = [], 0
            chunk.append(name)
            length += len(name) + 1
        if chunk:
            chunks.append(chunk)
        for targets in chunks:
            argv = [*key[1:], '--parallel', str(jobs), '--target', *targets]
            prebuilds.append({'cwd': key[0], 'argv': argv, 'command': _display_command(argv),
                             'targets': targets, 'fixture_tests': group['fixtures']})
    ready = not (missing or disabled or unresolved)
    commands = _test_commands(str(build), selected) if ready else []
    return {'repo': repo, 'ok': ready, 'selected': selected, 'missing': missing, 'disabled': disabled,
            'unresolved_fixtures': sorted(unresolved), 'fixture_tests': fixture_tests,
            'costs': {'selected': cost([n for n in selected if n in catalog]), 'fixtures': cost(fixture_tests)},
            'prebuilds': prebuilds if ready else [], 'ctest_argvs': commands,
            'commands': [_display_command(c) for c in commands], 'executed': False,
            'limits': 'Exact configured names only; this does not discover coverage. Costs are historical serial sums, '
                      'not a wall-time estimate; unknown costs and rebuild work remain. Optional prebuilds consolidate '
                      'only independent plain CMake build fixtures. CTest still runs every required fixture. '
                      'Check build ownership before running commands; the repository finish gate still applies.'}


def impact(project: Project, repo: str, paths: list[str] | None = None, base: str = "HEAD",
           target: str | None = None, budget: float | None = None) -> dict[str, Any]:
    config = _tests_config(project, repo)
    root = project.root(repo)
    build = root / config.get("build_dir", "build")
    paths = [p for p in paths or [] if p.strip() not in ("", ".", "./")]  # "." = the whole working-tree diff
    changed = [_normalize(root, p) for p in paths] if paths else _changed_files(root, base)
    if not changed:
        return {"repo": repo, "changed": [], "note": "No changed source files (pass paths or --base)."}
    graph = IncludeGraph(root, config.get("include_roots", ["src", "tests", "."]),
                         config.get("scan", ["src", "tests"]))
    known = set(graph.files)
    code_prefix = tuple(project.config["repositories"][repo].get("code_paths", ["src/"]))
    test_prefix = tuple(config.get("test_paths", ["tests/"]))
    targets = _targets(build, root)
    catalog_file = config.get("catalog")  # saved `ctest --show-only=json-v1` output (tests, offline use)
    catalog = json.loads((root / catalog_file).read_text(encoding="utf-8")).get("tests", []) if catalog_file else _catalog(build)
    costs = _costs(build)
    by_program: dict[str, list[dict]] = collections.defaultdict(list)
    by_file: dict[str, list[dict]] = collections.defaultdict(list)
    programs: dict[str, set[str]] = {}
    for test in catalog:
        if test.get("command") and Path(test["command"][0]).name in ("cmake", "cmake3"):
            continue  # build fixtures
        programs[test["name"]] = _programs(test, build)
        for program in programs[test["name"]]:
            by_program[program].append(test)
        for file in _command_files(test, build, root):
            by_file[file].append(test)
    if not paths:
        changed = [p for p in changed if p in known or p in by_file]
    if not changed:
        return {"repo": repo, "changed": [], "note": "No changed source or registered command files."}
    program_sources: dict[str, list[str]] = collections.defaultdict(list)
    for source, owners in targets.items():
        if source.startswith(test_prefix):
            for owner in owners:
                program_sources[owner].append(source)
    resolved: dict[str, list[str]] = {}
    texts = _Sources(root)

    def case_sources(test: dict, program: str) -> list[str]:
        if test["name"] not in resolved:
            resolved[test["name"]] = _case_sources(texts, test, sorted(program_sources.get(program, [])))
        return resolved[test["name"]]

    per_file, all_tests = [], {}
    for rel in changed:
        seeds = _companions(rel, known)
        distance = graph.distances(seeds)
        consumers = sorted(d for d, n in distance.items() if n == 1 and d.startswith(code_prefix) and d not in seeds)
        test_sources = {d: n for d, n in distance.items() if d.startswith(test_prefix)}
        tests_here = {"direct": set(), "near": set(), "broad": set()}

        def record(test: dict, tier: str) -> None:
            tests_here[tier].add(test["name"])
            props = {p["name"]: p["value"] for p in test.get("properties", [])}
            previous = all_tests.get(test["name"], {}).get("tier", "broad")
            order = ["direct", "near", "broad"]
            all_tests[test["name"]] = {"labels": props.get("LABELS", []), "seconds": costs.get(test["name"]),
                                       "disabled": bool(props.get("DISABLED")),
                                       "tier": order[min(order.index(previous), order.index(tier))],
                                       "fixtures": props.get("FIXTURES_REQUIRED", [])}

        for test in by_file.get(rel, []):
            record(test, "direct")
        for source, n in test_sources.items():
            tier = "direct" if n <= 1 else "near" if n == 2 else "broad"
            for program in targets.get(source, ()):
                for test in by_program.get(program, []):
                    if source not in case_sources(test, program):
                        continue
                    record(test, tier)
        tests_here["near"] -= tests_here["direct"]
        tests_here["broad"] -= tests_here["direct"] | tests_here["near"]
        per_file.append({"file": rel, "consumers": consumers, "consumer_count": len(consumers),
                         "transitive_dependents": len(distance) - len(seeds),
                         "tests": {k: len(v) for k, v in tests_here.items()}})
    deferred: list[str] = []
    if budget is not None:
        # Direct tests always run. Near tests then fill the recorded-time budget: first the cheapest test of each
        # test program not yet exercised, then the cheapest of the rest; unmeasured tests go last. Cheapest-only
        # skipped whole programs, and a real failure hid in one of them.
        live = {n: i for n, i in all_tests.items() if not i["disabled"]}
        spent = sum(i["seconds"] or 0 for i in live.values() if i["tier"] == "direct")
        near = sorted((n for n, i in live.items() if i["tier"] == "near"),
                      key=lambda n: (all_tests[n]["seconds"] is None, all_tests[n]["seconds"] or 0, n))
        family = lambda n: tuple(sorted(programs.get(n) or ())) or (n,)
        covered = {family(n) for n, i in live.items() if i["tier"] == "direct"}
        first = []
        for name in near:
            if family(name) not in covered:
                covered.add(family(name))
                first.append(name)
        near = first + [n for n in near if n not in set(first)]
        for name in near:
            seconds = all_tests[name]["seconds"]
            if seconds is not None and spent + seconds <= budget:
                spent += seconds
            else:
                deferred.append(name)
                all_tests[name]["tier"] = "deferred"
    groups: dict[str, dict[str, list[str]]] = {"direct": collections.defaultdict(list),
                                               "near": collections.defaultdict(list)}
    broad = 0
    for name, info in sorted(all_tests.items()):
        if info["disabled"]:
            continue
        if info["tier"] == "broad":
            broad += 1
            continue
        if info["tier"] == "deferred":
            continue
        label = next((l for l in ("gpu", "unit", "reference", "local") if l in info["labels"]),
                     info["labels"][0] if info["labels"] else "unlabelled")
        groups[info["tier"]][label].append(name)
    commands, totals, command_argvs, build_targets, fixtures = {}, {}, {}, {}, {}
    compiled = set().union(*targets.values()) if targets else set()
    test_dir = config.get("build_dir", "build")
    for tier, labels in groups.items():
        for label, names in labels.items():
            seconds = sum(all_tests[n]["seconds"] or 0 for n in names)
            key = f"{tier}/{label}"
            totals[key] = {"tests": len(names), "serial_seconds": round(seconds, 1),
                           "unknown_costs": sum(all_tests[n]["seconds"] is None for n in names)}
            command_argvs[key] = _test_commands(test_dir, names)
            commands[key] = "\n".join(_display_command(a) for a in command_argvs[key])
            build_targets[key] = sorted(set().union(*(programs.get(n, set()) for n in names)) & compiled)
            fixtures[key] = sorted({f for n in names for f in all_tests[n]["fixtures"]})
    groups = {tier: dict(labels) for tier, labels in groups.items()}
    totals["broad"] = {"tests": broad, "note": "reach the change through hub headers; expand only for a concrete risk"}
    if budget is not None:
        totals["deferred"] = {"tests": len(deferred), "budget_seconds": budget,
                              "serial_seconds": round(sum(all_tests[n]["seconds"] or 0 for n in deferred), 1),
                              "unknown_costs": sum(all_tests[n]["seconds"] is None for n in deferred)}
        if deferred:
            command_argvs["deferred"] = _test_commands(test_dir, sorted(deferred))
            commands["deferred"] = "\n".join(_display_command(a) for a in command_argvs["deferred"])
    untested = [f["file"] for f in per_file if not f["tests"]["direct"] and not f["tests"]["near"]]
    return {"repo": repo, "changed": changed, "files": per_file, "groups": dict(groups), "totals": totals,
            "commands": commands, "untested_files": untested, "deferred": sorted(deferred),
            "command_argvs": command_argvs, "build_targets": build_targets, "fixtures": fixtures,
            "limits": "Coverage = test executables that compile a file including the change (transitively). "
                      "Tests driving code only through a linked library without including it are missed; "
                      "literal CTest script/file arguments are mapped, but script imports and dynamic paths are not. "
                      "Recorded test time excludes build fixtures and unknown costs. No mapping is not proof of no test. "
                      "This focused selection does not replace the repository's required finish gate."}


def grounding(project: Project, repo: str, paths: list[str] | None = None, target: str | None = None,
              limit: int = 25) -> dict[str, Any]:
    """Per folder/file: evidence quality of the original functions native code cites."""
    target = default_target(project, target)
    refresh(project, [repo])
    db = connect(project)
    code_prefix = tuple(project.config["repositories"][repo].get("code_paths", ["src/"]))
    prefixes = tuple(p.rstrip("/") for p in (paths or list(code_prefix)))
    rows = db.execute("SELECT address, path FROM cites WHERE repo=?", (repo,)).fetchall()
    per_file: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    weak: dict[str, list] = collections.defaultdict(list)
    cache: dict[int, Any] = {}
    for address, path in rows:
        if not _under(path, prefixes) or not path.startswith(code_prefix):
            continue
        if address not in cache:
            row = containing(db, target, address)
            cache[address] = _status(row) if row else None
        info = cache[address]
        counter = per_file[path]
        counter["cites"] += 1
        if info is None:
            counter["not_function"] += 1
            continue
        counter["exact"] += info["exact"]
        counter["linked"] += info["linked"]
        counter["provisional"] += info["provisional_name"]
        if not info["exact"]:
            counter["unmatched"] += 1
            weak[path].append(info["address"] + " " + info["name"])
    folders: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for path, counter in per_file.items():
        folders[str(Path(path).parent)].update(counter)

    def score(c: collections.Counter) -> dict:
        functions = c["cites"] - c["not_function"]
        return dict(c) | {"exact_pct": round(100 * c["exact"] / functions, 1) if functions else None,
                          "named_pct": round(100 * (functions - c["provisional"]) / functions, 1) if functions else None}

    from .tiers import tier_of
    folder_rows = sorted(({"folder": k, "tier": tier_of(project, repo, k + "/x.cpp"), **score(v)}
                          for k, v in folders.items()),
                         key=lambda r: (r["exact_pct"] if r["exact_pct"] is not None else 101, -r["cites"]))
    weakest = sorted(((p, sorted(set(v))) for p, v in weak.items()), key=lambda x: -len(x[1]))
    total = collections.Counter()
    for counter in per_file.values():
        total.update(counter)
    return {"repo": repo, "scope": list(prefixes), "total": score(total), "files_with_cites": len(per_file),
            "folders": folder_rows[:limit],
            "weakest_files": [{"path": p, "unmatched": len(v), "examples": v[:5]} for p, v in weakest[:limit]],
            "meaning": "exact_pct: share of cited original functions that are byte-exact in the decomp. "
                       "This does not verify native behavior, the live caller path, or uncited dependencies."}


NINJA_BUILD = re.compile(r"^build (.+?): (\S+)(.*)$")


def _ninja_links(build: Path) -> dict[str, tuple[str, list[str]]]:
    """output -> (rule, inputs) for every link/archive statement in the build's build.ninja."""
    path = build / "build.ninja"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace").replace("$\n", " ")
    links = {}
    for line in text.splitlines():
        if not line.startswith("build ") or "LINKER" not in line:
            continue
        line = line.replace("$ ", "\0").replace("$:", ":")
        match = NINJA_BUILD.match(line)
        if not match:
            continue
        inputs = match[3].split("||", 1)[0].replace("|", " ").split()
        for output in match[1].split():
            links[output.replace("\0", " ")] = (match[2], [i.replace("\0", " ") for i in inputs])
    return links


def stale(project: Project, repo: str, outputs: list[str] | None = None) -> dict[str, Any]:
    """Built programs older than a source compiled into them (or a header those sources include)."""
    config = _tests_config(project, repo)
    root = project.root(repo)
    build = root / config.get("build_dir", "build")
    links = _ninja_links(build)
    if not links:
        return {"repo": repo, "checked": False, "outputs": [],
                "note": f"No link statements in {build / 'build.ninja'}: staleness needs a Ninja build."}
    objects: dict[str, str] = {}
    compile_db = build / "compile_commands.json"
    if compile_db.is_file():
        for entry in json.loads(compile_db.read_text(encoding="utf-8")):
            output = entry.get("output")
            if not output:
                argv = entry.get("arguments") or shlex.split(entry.get("command", ""))
                output = next((argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-o"), None)
            if not output:
                continue
            directory = Path(entry.get("directory", build))
            file = Path(entry["file"])
            try:
                key = os.path.relpath(directory / output, build).replace(os.sep, "/")  # Ninja paths are build-relative
                objects[key] = (directory / file).resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                continue
    executables = [o for o, (rule, _) in links.items() if "EXECUTABLE" in rule and (build / o).is_file()]
    if outputs:
        wanted = {Path(o).name for o in outputs}
        selected = [o for o in executables if Path(o).name in wanted]
    else:  # configured apps (what a person runs), else every linked executable
        selected = [o for o in executables if Path(o).name in set(config["apps"])] if config.get("apps") else executables

    closures: dict[str, set[str]] = {}

    def sources(output: str, seen: set[str]) -> set[str]:
        if output in closures:
            return closures[output]
        found: set[str] = set()
        for item in links.get(output, ("", []))[1]:
            if item in objects:
                found.add(objects[item])
            elif item in links and item not in seen:
                found |= sources(item, seen | {item})
        closures[output] = found
        return found

    built = {o: (build / o).stat().st_mtime for o in selected}
    oldest = min(built.values(), default=0)
    newer_headers: dict[str, float] = {}
    for base in config.get("scan", ["src", "tests"]):
        for directory, dirs, names in os.walk(root / base):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "build"]
            for name in names:
                if Path(name).suffix in SOURCE_SUFFIXES - {".c", ".cc", ".cpp", ".cxx"}:
                    path = Path(directory, name)
                    when = path.stat().st_mtime
                    if when > oldest:
                        newer_headers[path.relative_to(root).as_posix()] = when
    reach: dict[str, set[str]] = {}
    if newer_headers:
        graph = IncludeGraph(root, config.get("include_roots", ["src", "tests", "."]), config.get("scan", ["src", "tests"]))
        reach = {h: set(graph.distances(_companions(h, set(graph.files)))) for h in newer_headers}
    rows = []
    for output in sorted(selected):
        compiled = sources(output, {output})
        newer = []
        for source in compiled:
            try:
                when = (root / source).stat().st_mtime
            except OSError:
                continue
            if when > built[output]:
                newer.append((when, source))
        newer += [(when, header) for header, when in newer_headers.items()
                  if when > built[output] and reach.get(header, set()) & compiled]
        newer.sort(reverse=True)
        rows.append({"output": output, "built": time.strftime("%Y-%m-%d %H:%M", time.localtime(built[output])),
                     "sources": len(compiled), "stale": bool(newer), "newer_count": len(newer),
                     "newer": [{"file": f, "minutes_after_build": round((w - built[output]) / 60, 1)}
                               for w, f in newer[:5]]})
    apps = set(config.get("apps", []))
    rows.sort(key=lambda r: (Path(r["output"]).name not in apps, not r["stale"], -built[r["output"]]))
    return {"repo": repo, "checked": True, "outputs": rows, "stale": sum(r["stale"] for r in rows),
            "limits": "Compares file times: a program is stale when a source linked into it, or a header such a source "
                      "includes, is newer than the program (what Ninja's own check does for these inputs). Generated "
                      "files, content packages and data read at run time are not compared; build to be sure."}
