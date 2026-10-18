"""Native-port build answers: which tests prove a change, and whether built programs are current.

impact     changed files -> other code that includes or links them (the "other consumers" a shared change
           must be re-tested against) -> test executables that compile or link them -> CTest names,
           grouped by tier and label, with recorded run times and ready-to-run commands.
test_plan  exact CTest names -> their fixture closure, costs and optional consolidated prebuilds.
stale      built programs older than a source or header compiled into them.

All read the build's own files (CMake's compile_commands.json, `ctest --show-only=json-v1`,
CTestCostData.txt, Ninja's build.ninja). Nothing here builds or runs tests.
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

from .bridge import _changed_files
from .project import Project

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

    def implemented(self, rel: str) -> set[str]:
        """Headers a source without a header of its own implements: the ones it includes from its own folder that
        it is named after (GameWorldSounds.cpp -> GameWorld.hpp), so its tests are that header's tests."""
        path = Path(rel)
        if path.suffix not in {".c", ".cc", ".cpp", ".cxx"} or len(_companions(rel, set(self.files))) > 1:
            return set()
        return {h for h, users in self.includers.items() if rel in users and Path(h).parent == path.parent
                and len(Path(h).stem) >= 3 and path.stem.startswith(Path(h).stem)}

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


CMAKE_SPECIAL = set("\\^$.|?*+()[]{}")


def _cmake_escape(text: str) -> str:
    """Escape for CMake's regex (ctest -R): only its special characters; '-' is literal there."""
    return "".join("\\" + c if c in CMAKE_SPECIAL else c for c in text)


def _test_regex(names: list[str]) -> str:
    """^(a|b)$ for exact names, with a prefix and suffix all of them share written once. CMake's regex allows
    few groups, so this is one group, never a nested trie."""
    prefix = os.path.commonprefix(names) if len(names) > 1 else ""
    suffix = os.path.commonprefix([n[len(prefix):][::-1] for n in names])[::-1] if len(names) > 1 else ""
    if any(len(n) <= len(prefix) + len(suffix) for n in names):  # a name would become an empty alternative
        prefix = suffix = ""
    middles = [n[len(prefix):len(n) - len(suffix)] for n in names]
    return f"^{_cmake_escape(prefix)}(" + "|".join(_cmake_escape(m) for m in middles) + f"){_cmake_escape(suffix)}$"


def _test_commands(test_dir: str, names: list[str], limit: int = 3000) -> list[list[str]]:
    """ctest commands selecting exactly these names, each regex within about `limit` characters (never widened to
    a whole label)."""
    chunks, chunk = [], []
    for name in names:
        if chunk and len(_test_regex(chunk + [name])) > limit:
            chunks.append(chunk)
            chunk = []
        chunk.append(name)
    if chunk:
        chunks.append(chunk)
    return [["ctest", "--test-dir", test_dir, "-R", _test_regex(c), "--output-on-failure", "--no-tests=error"]
            for c in chunks]


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


def _load_catalog(root: Path, config: dict, build: Path) -> list[dict]:
    """The CTest catalog: a saved `ctest --show-only=json-v1` file (`tests.catalog`), else ctest's live answer."""
    catalog_file = config.get("catalog")
    return (json.loads((root / catalog_file).read_text(encoding="utf-8")).get("tests", [])
            if catalog_file else _catalog(build))


def test_plan(project: Project, repo: str, names: list[str] | str, jobs: int = 2) -> dict:
    """Resolve exact tests and their fixture closure; suggest commands without executing them."""
    if isinstance(names, str):
        names = [n for n in re.split(r"[\s,]+", names) if n]
    if not names or any(not isinstance(n, str) or not n.strip() for n in names):
        raise ValueError('Pass one or more exact CTest names')
    if isinstance(jobs, bool) or jobs < 1 or jobs > 1024:
        raise ValueError('jobs must be between 1 and 1024')
    config = _tests_config(project, repo)
    root = project.root(repo)
    build = root / config.get('build_dir', 'build')
    return _plan(repo, _load_catalog(root, config, build), build, names, jobs)


def _plan(repo: str, tests: list[dict], build: Path, names: list[str], jobs: int) -> dict:
    catalog = {t['name']: t for t in tests}
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
    commands = _test_commands(str(build), [n for n in selected if n not in missing]) if ready else []
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
    """Changed files -> the code that includes or links them -> the exact CTest names that can run that code.

    Tiers: direct (a test source includes the change, or its pair X.cpp/X.hpp, or the header a split source is
    named after, at include distance 0-1, or a test command names the file), near (distance 2), linked (the
    test's program links an object built from the change), broad (distance 3 or more: counted and named, not
    selected). Direct tests always run and near tests are selected (with a budget: cheapest first, every program
    before repeats); linked tests are a sample (the cheapest test of each linking program) only for a file nothing
    else reaches, otherwise deferred like the rest, with their own command."""
    config = _tests_config(project, repo)
    root = project.root(repo)
    build = root / config.get("build_dir", "build")
    paths = [p for p in paths or [] if p.strip() not in ("", ".", "./")]  # "." = the whole working-tree diff
    from .bridge import expand_paths
    changed = expand_paths(root, paths) if paths else list(_changed_files(root, base))
    if not changed:
        return {"repo": repo, "changed": [], "note": "No changed source files (pass paths or base)."}
    graph = IncludeGraph(root, config.get("include_roots", ["src", "tests", "."]),
                         config.get("scan", ["src", "tests"]))
    known = set(graph.files)
    code_prefix = tuple(project.config["repositories"][repo].get("code_paths", ["src/"]))
    test_prefix = tuple(config.get("test_paths", ["tests/"]))
    targets = _targets(build, root)
    catalog = _load_catalog(root, config, build)
    costs = _costs(build)
    closures = {Path(output).name: sources for output, sources in link_closures(build, root).items()}
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
    order = ["direct", "near", "broad", "linked"]  # include evidence first; linking alone is the weakest

    def case_sources(test: dict, program: str) -> list[str]:
        if test["name"] not in resolved:
            resolved[test["name"]] = _case_sources(texts, test, sorted(program_sources.get(program, [])))
        return resolved[test["name"]]

    per_file, all_tests, sample = [], {}, set()
    for rel in changed:
        seeds = _companions(rel, known) | graph.implemented(rel)
        distance = graph.distances(seeds)
        consumers = sorted(d for d, n in distance.items() if n == 1 and d.startswith(code_prefix) and d not in seeds)
        test_sources = {d: n for d, n in distance.items() if d.startswith(test_prefix)}
        tests_here: dict[str, set[str]] = {tier: set() for tier in order}

        def record(test: dict, tier: str) -> None:
            tests_here[tier].add(test["name"])
            props = {p["name"]: p["value"] for p in test.get("properties", [])}
            previous = all_tests.get(test["name"], {}).get("tier", order[-1])
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
                    if source in case_sources(test, program):
                        record(test, tier)
        built_from = {s for s in seeds if not s.startswith(test_prefix)}  # a test source runs only in its suite
        linkers = sorted(name for name, sources in closures.items() if sources & built_from)
        for program in linkers:
            for test in by_program.get(program, []):
                record(test, "linked")
        for index, tier in enumerate(order[1:], 1):
            tests_here[tier] -= set().union(*(tests_here[t] for t in order[:index]))
        if not tests_here["direct"] and not tests_here["near"]:
            sample |= tests_here["linked"]  # nothing closer reaches this file: sample the programs linking it
        per_file.append({"file": rel, "consumers": consumers, "consumer_count": len(consumers),
                         "transitive_dependents": len(distance) - len(seeds), "linked_by": linkers,
                         "implements": sorted(seeds - _companions(rel, known)),
                         "tests": {k: len(v) for k, v in tests_here.items()}})
    live = {n: i for n, i in all_tests.items() if not i["disabled"]}
    family = lambda n: tuple(sorted(programs.get(n) or ())) or (n,)
    cheapest = lambda n: (all_tests[n]["seconds"] is None, all_tests[n]["seconds"] or 0, n)
    direct = [n for n, i in live.items() if i["tier"] == "direct"]
    covered = {family(n) for n in direct}
    linked_first, linked_rest = [], []
    for name in sorted((n for n, i in live.items() if i["tier"] == "linked"), key=cheapest):
        (linked_first if name in sample and family(name) not in covered else linked_rest).append(name)
        covered.add(family(name))
    candidates = sorted((n for n, i in live.items() if i["tier"] == "near"), key=cheapest) + linked_first
    deferred = list(linked_rest)
    notes = []
    if budget is not None:
        # Direct tests always run. Near tests and the linked sample then fill the recorded-time budget: first the
        # cheapest test of each program not yet exercised, then the cheapest of the rest; unmeasured tests last.
        spent = sum(live[n]["seconds"] or 0 for n in direct)
        if spent > budget or any(live[n]["seconds"] is None for n in direct):
            notes.append(f"direct tests alone need {spent:.1f} s recorded"
                         + (f" + {sum(live[n]['seconds'] is None for n in direct)} unmeasured" if any(
                             live[n]['seconds'] is None for n in direct) else "")
                         + f" against the {budget:g} s budget; they are never dropped")
        seen = {family(n) for n in direct}
        first = []
        for name in sorted(candidates, key=cheapest):
            if family(name) not in seen:
                seen.add(family(name))
                first.append(name)
        for name in first + [n for n in sorted(candidates, key=cheapest) if n not in set(first)]:
            seconds = live[name]["seconds"]
            if seconds is not None and spent + seconds <= budget:
                spent += seconds
            else:
                deferred.append(name)
    for name in deferred:
        all_tests[name]["tier"] = "deferred"
    label_order = config.get("label_order", [])
    groups: dict[str, dict[str, list[str]]] = {t: collections.defaultdict(list) for t in ("direct", "near", "linked")}
    broad = []
    for name, info in sorted(all_tests.items()):
        if info["disabled"] or info["tier"] == "deferred":
            continue
        if info["tier"] == "broad":
            broad.append(name)
            continue
        label = next((l for l in label_order if l in info["labels"]),
                     info["labels"][0] if info["labels"] else "unlabelled")
        groups[info["tier"]][label].append(name)
    commands, totals, command_argvs, build_targets, fixtures = {}, {}, {}, {}, {}
    compiled = set().union(*targets.values()) if targets else set()
    test_dir = str(build)
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
    groups = {tier: dict(labels) for tier, labels in groups.items() if labels}
    totals["broad"] = {"tests": len(broad), "names": broad[:30],
                       "note": "reach a changed file only at include distance 3 or more; run them for a shared change"}
    if deferred:
        totals["deferred"] = {"tests": len(deferred), "budget_seconds": budget,
                              "serial_seconds": round(sum(all_tests[n]["seconds"] or 0 for n in deferred), 1),
                              "unknown_costs": sum(all_tests[n]["seconds"] is None for n in deferred)}
        command_argvs["deferred"] = _test_commands(test_dir, sorted(deferred))
        commands["deferred"] = "\n".join(_display_command(a) for a in command_argvs["deferred"])
    selected = sorted(n for tier in groups.values() for names in tier.values() for n in names)
    plan = _plan(repo, catalog, build, selected, 2) if selected else None
    used = sorted({Path(p).name for n in selected for p in programs.get(n, ())} & set(closures))
    stale_programs = [r for r in stale(project, repo, used)["outputs"] if r["stale"]] if used else []
    untested = [f["file"] for f in per_file if not any(f["tests"][t] for t in ("direct", "near", "linked"))]
    return {"repo": repo, "changed": changed, "files": per_file, "groups": groups, "totals": totals,
            "commands": commands, "untested_files": untested, "deferred": sorted(deferred), "notes": notes,
            "command_argvs": command_argvs, "build_targets": build_targets, "fixtures": fixtures,
            "fixture_tests": plan["fixture_tests"] if plan else [], "prebuilds": plan["prebuilds"] if plan else [],
            "plan_blocked": {k: plan[k] for k in ("missing", "disabled", "unresolved_fixtures") if plan[k]}
            if plan else {},
            "stale_programs": [{"program": r["output"], "newer": r["newer"][:2]} for r in stale_programs],
            "limits": "Coverage = test programs that compile a file including the change (include distance) or "
                      "link an object built from it (Ninja link closure). Literal CTest script/file arguments are "
                      "mapped; script imports and dynamic paths are not. Recorded test time excludes build fixtures "
                      "and unknown costs. No mapping is not proof of no test. This focused selection does not "
                      "replace the repository's required finish gate. Needs CMake's compile_commands.json and CTest "
                      "(and build.ninja for the linked tier)."}


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


def _object_sources(build: Path, root: Path) -> dict[str, str]:
    """Ninja's build-relative object path -> repo-relative source, from compile_commands.json."""
    objects: dict[str, str] = {}
    compile_db = build / "compile_commands.json"
    if not compile_db.is_file():
        return objects
    for entry in json.loads(compile_db.read_text(encoding="utf-8")):
        output = entry.get("output")
        if not output:
            argv = entry.get("arguments") or shlex.split(entry.get("command", ""))
            output = next((argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-o"), None)
        if not output:
            continue
        directory = Path(entry.get("directory", build))
        try:
            key = os.path.relpath(directory / output, build).replace(os.sep, "/")  # Ninja paths are build-relative
            objects[key] = (directory / entry["file"]).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
    return objects


def link_closures(build: Path, root: Path) -> dict[str, set[str]]:
    """Linked executable (build-relative output) -> every source compiled into it, through static and shared
    libraries, from build.ninja's link statements and compile_commands.json. Empty without a Ninja build."""
    links = _ninja_links(build)
    objects = _object_sources(build, root)
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
    return {output: sources(output, {output}) for output, (rule, _) in links.items() if "EXECUTABLE" in rule}


def stale(project: Project, repo: str, outputs: list[str] | None = None) -> dict[str, Any]:
    """Built programs older than a source compiled into them (or a header those sources include)."""
    config = _tests_config(project, repo)
    root = project.root(repo)
    build = root / config.get("build_dir", "build")
    closures = link_closures(build, root)
    if not closures:
        return {"repo": repo, "checked": False, "outputs": [],
                "note": f"No executable link statements in {build / 'build.ninja'}: staleness needs a Ninja build."}
    executables = [o for o in closures if (build / o).is_file()]
    unknown: list[str] = []
    if outputs:
        wanted = {Path(o).name for o in outputs}
        selected = [o for o in executables if Path(o).name in wanted]
        unknown = sorted(wanted - {Path(o).name for o in selected})
    else:  # configured apps (what a person runs), else every linked executable
        selected = [o for o in executables if Path(o).name in set(config["apps"])] if config.get("apps") else executables
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
        compiled = closures[output]
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
            "unknown_programs": unknown,
            "limits": "Compares file times: a program is stale when a source linked into it, or a header such a source "
                      "includes, is newer than the program (what Ninja's own check does for these inputs). Generated "
                      "files, content packages and data read at run time are not compared; build to be sure."}
