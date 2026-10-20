"""Progress from objdiff reports: summaries, address-keyed regression checks, baselines and an offline page.

objdiff's counters are the only measures. A function or data range is identified by its module and original
address, so renames, folds and splits never look like a loss, and a real loss always shows.
"""

from __future__ import annotations

import gzip
import json
import re
import time
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from .project import Project

COUNTERS = ("total_code", "matched_code", "complete_code", "total_data", "matched_data", "complete_data",
            "total_functions", "matched_functions", "total_units", "complete_units")
CODE_SECTIONS = (".text", ".init", ".fini")
BSS_SECTIONS = (".bss", ".sbss", ".sbss2", ".common", ".tbss")
KEEP_BASELINES = 8


def number(value: Any) -> float:
    """objdiff writes uint64 counters as strings and omits zero fields."""
    if value in (None, ""):
        return 0.0
    return float(value)


def measures(raw: dict | None) -> dict[str, int]:
    raw = raw or {}
    return {key: int(number(raw.get(key))) for key in COUNTERS}


def is_code(section: str) -> bool:
    return section in CODE_SECTIONS or section.startswith(tuple(s + "." for s in CODE_SECTIONS))


def is_bss(section: str) -> bool:
    return section in BSS_SECTIONS or section.startswith(tuple(s + "." for s in BSS_SECTIONS))


def module_of(unit: dict, single: str | None = None) -> str:
    """The module a report unit belongs to: its metadata's, else the target's one module (`single`: objdiff's
    report drops the module_name the project gives), else the unit's first folder."""
    meta = unit.get("metadata") or {}
    if meta.get("module_name"):
        return str(meta["module_name"])
    if meta.get("module_id") not in (None, 0, "0"):
        return f"module{meta['module_id']}"
    return single or str(unit.get("name", "")).split("/", 1)[0] or "main"


def single_module(project: Project, target: str) -> str | None:
    """The module every unit of a target's objdiff project names, when they all name one (a Switch `main`, a DOL
    without RELs): a unit renamed into another folder stays in it."""
    config = project.target(target)
    path = project.file(config["repository"], config["objdiff"]) if config.get("objdiff") else None
    try:
        units = json.loads(path.read_text(encoding="utf-8")).get("units", []) if path and path.is_file() else []
    except (OSError, ValueError):
        return None
    modules = {(u.get("metadata") or {}).get("module_name") for u in units}
    return next(iter(modules)) if len(modules) == 1 and None not in modules else None


def address_text(address: int) -> str:
    return f"0x{address:08X}" if address < 1 << 32 else f"0x{address:X}"


def load(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    try:
        report = json.loads(raw)
    except ValueError as error:
        raise ValueError(f"{path} is not a complete objdiff report (rebuilding?): {error}") from error
    if not isinstance(report, dict) or "units" not in report:
        raise ValueError(f"{path} is not an objdiff report")
    return report


def _percent(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 4) if whole else 0.0


def _with_percents(counts: dict[str, int]) -> dict[str, Any]:
    out: dict[str, Any] = dict(counts)
    for kind in ("code", "data"):
        out[f"matched_{kind}_percent"] = _percent(counts[f"matched_{kind}"], counts[f"total_{kind}"])
        out[f"complete_{kind}_percent"] = _percent(counts[f"complete_{kind}"], counts[f"total_{kind}"])
    out["matched_functions_percent"] = _percent(counts["matched_functions"], counts["total_functions"])
    return out


def summary(report: dict) -> dict[str, Any]:
    """Totals for the report, each objdiff progress category and each module."""
    modules: dict[str, dict[str, int]] = {}
    for unit in report.get("units", []):
        counts = modules.setdefault(module_of(unit), dict.fromkeys(COUNTERS, 0))
        own = measures(unit.get("measures"))
        own["total_units"] = own["total_units"] or 1
        own["complete_units"] = own["complete_units"] or int(bool((unit.get("metadata") or {}).get("complete")))
        for key, value in own.items():
            counts[key] += value
    categories = [{"id": c.get("id"), "name": c.get("name") or c.get("id"),
                   "measures": _with_percents(measures(c.get("measures")))} for c in report.get("categories", [])]
    return {"version": report.get("version"), "overall": _with_percents(measures(report.get("measures"))),
            "categories": categories,
            "modules": [{"name": name, "measures": _with_percents(counts)} for name, counts in sorted(modules.items())]}


def _functions(report: dict, linked_only: bool = False, single: str | None = None) -> dict[tuple[str, int], dict]:
    out = {}
    for unit in report.get("units", []):
        if linked_only and not (unit.get("metadata") or {}).get("complete"):
            continue
        module = module_of(unit, single)
        for function in unit.get("functions") or []:
            address = (function.get("metadata") or {}).get("virtual_address")
            if address is None:
                continue
            key = (module, int(number(address)))
            if key in out:
                raise ValueError(f"Two functions at {module}:{address_text(key[1])}; the report is inconsistent")
            out[key] = function
    return out


def _data_ranges(report: dict, exact_only: bool = False, linked_only: bool = False, single: str | None = None) -> dict:
    """Original non-code intervals per (module, section), merged so a split or a fold is not a loss."""
    ranges: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for unit in report.get("units", []):
        if linked_only and not (unit.get("metadata") or {}).get("complete"):
            continue
        module = module_of(unit, single)
        for section in unit.get("sections") or []:
            name, size = str(section.get("name", "")), int(number(section.get("size")))
            if is_code(name) or not size:
                continue
            if exact_only and number(section.get("fuzzy_match_percent")) != 100:
                continue
            address = (section.get("metadata") or {}).get("virtual_address")
            if address is None or not int(number(address)):
                continue                                # 0: a report that does not place its sections
            start = int(number(address))
            ranges.setdefault((module, name), []).append((start, start + size))
    for key, rows in ranges.items():
        merged: list[tuple[int, int]] = []
        for start, end in sorted(rows):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        ranges[key] = merged
    return ranges


def _lost(old: dict, new: dict) -> list[dict]:
    """Parts of old's intervals that new does not cover."""
    out = []
    for (module, section), rows in sorted(old.items()):
        cover = new.get((module, section), [])
        for start, end in rows:
            cursor = start
            for first, last in cover:
                if last <= cursor:
                    continue
                if first >= end:
                    break
                if first > cursor:
                    out.append((module, section, cursor, first))
                cursor = max(cursor, min(last, end))
            if cursor < end:
                out.append((module, section, cursor, end))
    return [{"module": m, "section": s, "address": address_text(a), "size": b - a} for m, s, a, b in out]


def compare(before: dict, after: dict, single: str | None = None) -> dict[str, Any]:
    """What changed between two reports, by original address (in the target's one module when `single` names
    it). `failures` lists every loss."""
    old, new = _functions(before, single=single), _functions(after, single=single)
    old_exact = {k for k, f in old.items() if number(f.get("fuzzy_match_percent")) == 100}
    new_exact = {k for k, f in new.items() if number(f.get("fuzzy_match_percent")) == 100}
    old_linked, new_linked = _functions(before, True, single), _functions(after, True, single)

    def rows(keys, table):
        return [{"module": k[0], "address": address_text(k[1]), "name": table[k]["name"],
                 "match": number(table[k].get("fuzzy_match_percent"))} for k in sorted(keys)]

    metrics = {}
    first, last = measures(before.get("measures")), measures(after.get("measures"))
    for key in COUNTERS:
        metrics[key] = {"before": first[key], "after": last[key], "delta": last[key] - first[key]}
    exact_data_lost = _lost(_data_ranges(before, exact_only=True, single=single),
                            _data_ranges(after, exact_only=True, single=single))
    coverage_lost = _lost(_data_ranges(before, single=single), _data_ranges(after, single=single))
    linked_data_lost = _lost(_data_ranges(before, linked_only=True, single=single),
                             _data_ranges(after, linked_only=True, single=single))
    failures = []
    if old_exact - new_exact:
        failures.append(f"{len(old_exact - new_exact)} exact function(s) lost their match")
    if old.keys() - new.keys():
        failures.append(f"{len(old.keys() - new.keys())} function address(es) disappeared from the report")
    if old_linked.keys() - new_linked.keys():
        failures.append(f"{len(old_linked.keys() - new_linked.keys())} linked function(s) are no longer linked")
    if exact_data_lost:
        failures.append(f"{sum(r['size'] for r in exact_data_lost)} bytes of exact data regressed")
    if coverage_lost:
        failures.append(f"{sum(r['size'] for r in coverage_lost)} bytes of original data left the report")
    if linked_data_lost:
        failures.append(f"{sum(r['size'] for r in linked_data_lost)} bytes of linked data are no longer linked")
    for key in ("matched_code", "matched_data", "complete_code", "complete_data", "matched_functions"):
        if metrics[key]["delta"] < 0:
            failures.append(f"{key} fell by {-metrics[key]['delta']}")
    for key in ("total_code", "total_data", "total_functions"):
        if metrics[key]["delta"]:
            failures.append(f"{key} changed by {metrics[key]['delta']:+d}: the split or target changed; "
                            "compare reports of the same configuration")
    renamed = [{"module": k[0], "address": address_text(k[1]), "before": old[k]["name"], "after": new[k]["name"]}
               for k in sorted(old.keys() & new.keys()) if old[k]["name"] != new[k]["name"]]
    improved = [r for r in rows((old.keys() & new.keys()) - new_exact, new)
                if r["match"] > number(old[(r["module"], int(r["address"], 16))].get("fuzzy_match_percent"))]
    return {"metrics": metrics, "new_exact": rows(new_exact - old_exact, new),
            "regressed": rows(old_exact - new_exact, old), "improved": improved,
            "newly_linked": rows(new_linked.keys() - old_linked.keys(), new_linked),
            "unlinked": rows(old_linked.keys() - new_linked.keys(), old_linked),
            "exact_data_lost": exact_data_lost, "data_coverage_lost": coverage_lost,
            "linked_data_lost": linked_data_lost, "renamed": renamed, "failures": failures,
            "ok": not failures}


# Baselines: copies of a target's report kept in the toolkit's state directory, so a session can compare what it
# finishes with against what it started from without anyone remembering to save a file.

def _baseline_dir(project: Project, target: str) -> Path:
    from .activity import state_dir
    path = state_dir(project) / "baselines" / target
    path.mkdir(parents=True, exist_ok=True)
    return path


def report_path(project: Project, target: str) -> Path:
    config = project.target(target)
    if not config.get("report"):
        raise ValueError(f"Target {target} has no objdiff report configured")
    return project.file(config["repository"], config["report"])


def save_baseline(project: Project, target: str, label: str = "manual", only_if_changed: bool = True) -> dict | None:
    """Store the current report (gzip) with its time stamp; skip when the newest baseline has the same report."""
    path = report_path(project, target)
    if not path.is_file():
        return None
    stat = path.stat()
    stamp = f"{stat.st_size}:{stat.st_mtime_ns}"
    folder = _baseline_dir(project, target)
    existing = baselines(project, target)
    if only_if_changed and existing and existing[0].get("stamp") == stamp:
        return existing[0]
    raw = path.read_bytes()
    try:
        json.loads(raw)
    except ValueError:
        return None  # half-written during a rebuild
    when = datetime.now(timezone.utc)
    name = when.strftime("%Y%m%dT%H%M%S%fZ")
    (folder / f"{name}.json.gz").write_bytes(gzip.compress(raw, 6))
    meta = {"name": name, "time": when.isoformat(timespec="seconds"), "label": label, "stamp": stamp,
            "report_time": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds")}
    (folder / f"{name}.meta.json").write_text(json.dumps(meta) + "\n", encoding="utf-8")
    for old in existing[KEEP_BASELINES - 1:]:
        for suffix in (".json.gz", ".meta.json"):
            (folder / f"{old['name']}{suffix}").unlink(missing_ok=True)
    return meta


def baselines(project: Project, target: str) -> list[dict]:
    """Saved baselines, newest first."""
    out = []
    for meta in sorted(_baseline_dir(project, target).glob("*.meta.json"), reverse=True):
        try:
            out.append(json.loads(meta.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def baseline(project: Project, target: str, which: str | None = None) -> tuple[dict, dict]:
    """(meta, report) for a baseline: newest, a label such as session:claude:123, a name, or a report file path."""
    if which and Path(which).expanduser().is_file():
        path = Path(which).expanduser()
        return {"name": str(path), "label": "file"}, load(path)
    rows = baselines(project, target)
    if which:
        rows = [r for r in rows if which in (r["name"], r.get("label"))] or \
            [r for r in rows if str(r.get("label", "")).startswith(which)]
    if not rows:
        raise ValueError("No saved baseline" + (f" matching {which}" if which else "") +
                         ": `zkit progress --save` stores one (the session-start hook does it automatically)")
    meta = rows[0]
    return meta, load(_baseline_dir(project, target) / f"{meta['name']}.json.gz")


def since(project: Project, target: str, which: str | None = None) -> dict[str, Any]:
    meta, before = baseline(project, target, which)
    after = load(report_path(project, target))
    result = compare(before, after, single_module(project, target))
    result["baseline"] = meta
    result["report_age_h"] = round((time.time() - report_path(project, target).stat().st_mtime) / 3600, 2)
    return result


def progress(project: Project, target: str) -> dict[str, Any]:
    path = report_path(project, target)
    if not path.is_file():
        raise ValueError(f"No report at {path}: build the project (it writes objdiff's report)")
    data = summary(load(path))
    data["target"] = target
    data["report_age_h"] = round((time.time() - path.stat().st_mtime) / 3600, 2)
    return data


# A link's proof, written into the report

def apply_link(path: Path, linked: list[str]) -> bool:
    """Mark the units a link proved (zkit link: every byte of them placed from the compiled objects and found
    identical) complete in objdiff's report, with their data matched, and unmark the rest; the totals and
    categories are recounted from the units. objdiff's own data counts are kept under `zkit_link` so a unit that
    stops linking gets them back. True when the report changed."""
    report = load(path)
    before = json.dumps(report, sort_keys=True)
    names = set(linked)
    kept = report.setdefault("zkit_link", {}).setdefault("units", {})
    for unit in report.get("units", []):
        name = str(unit.get("name", ""))
        meta, own = unit.setdefault("metadata", {}), unit.setdefault("measures", {})
        sections = unit.get("sections") or []
        proven = name in names or name.split("/", 1)[-1] in names
        if name in kept:   # objdiff's values first, as if no link had marked it
            saved = kept.pop(name)
            own["matched_data"] = saved["matched_data"]
            for section in sections:
                if section.get("name") in saved["sections"]:
                    value = saved["sections"][section["name"]]
                    if value is None:
                        section.pop("fuzzy_match_percent", None)
                    else:
                        section["fuzzy_match_percent"] = value
        meta.pop("complete", None)
        for key in ("complete_code", "complete_data", "complete_units"):
            own.pop(key, None)
        if not proven:
            continue
        data = [x for x in sections if not is_code(str(x.get("name", "")))]
        kept[name] = {"matched_data": own.get("matched_data"),
                      "sections": {x.get("name"): x.get("fuzzy_match_percent") for x in data}}
        meta["complete"] = True
        own["matched_data"] = own.get("total_data", "0")
        for section in data:
            section["fuzzy_match_percent"] = 100.0
        own.update(complete_code=own.get("total_code", "0"), complete_data=own.get("total_data", "0"),
                   complete_units=1)
    if not kept:
        report.pop("zkit_link")
    _recount(report)
    if json.dumps(report, sort_keys=True) == before:
        return False
    path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    return True


def _recount(report: dict) -> None:
    """The report's matched-data and linked totals, and each category's, from its units."""
    def total(units: list[dict], into: dict) -> None:
        sums = {key: sum(int(number((u.get("measures") or {}).get(key))) for u in units)
                for key in ("total_code", "total_data", "matched_data", "complete_code", "complete_data")}
        into.update(matched_data=str(sums["matched_data"]), complete_code=str(sums["complete_code"]),
                    complete_data=str(sums["complete_data"]),
                    complete_units=sum(1 for u in units if (u.get("metadata") or {}).get("complete")))
        for key, whole in (("matched_data", "total_data"), ("complete_code", "total_code"),
                           ("complete_data", "total_data")):
            into[f"{key}_percent"] = 100.0 * sums[key] / sums[whole] if sums[whole] else 0.0
    units = report.get("units", [])
    total(units, report.setdefault("measures", {}))
    for category in report.get("categories", []):
        members = [u for u in units if category.get("id") in ((u.get("metadata") or {}).get("progress_categories")
                                                              or [])]
        total(members, category.setdefault("measures", {}))


# Offline page: the reports themselves (objdiff's own counters), browsable without any service.

def _unit_rows(report: dict, single: str | None = None) -> list[dict]:
    """The page's units. A one-module target (a Switch `main`) is browsed by source folder: a unit without
    objdiff categories takes its first folder as one, and a unit outside any folder stays in the module."""
    rows = []
    for index, unit in enumerate(report.get("units", [])):
        meta = unit.get("metadata") or {}
        folder = str(unit.get("name", "")).split("/", 1)[0] if "/" in str(unit.get("name", "")) else None
        functions = []
        for function in unit.get("functions") or []:
            info = function.get("metadata") or {}
            if info.get("virtual_address") is None:
                continue
            functions.append({"name": function.get("name"), "display": info.get("demangled_name"),
                              "address": int(number(info["virtual_address"])), "size": int(number(function.get("size"))),
                              "match": number(function.get("fuzzy_match_percent"))})
        sections = []
        for section in unit.get("sections") or []:
            name = str(section.get("name", ""))
            address = (section.get("metadata") or {}).get("virtual_address")
            sections.append({"name": name, "size": int(number(section.get("size"))),
                             "kind": "code" if is_code(name) else "bss" if is_bss(name) else "data",
                             "match": number(section.get("fuzzy_match_percent")),
                             "address": int(number(address)) if address is not None else None})
        addresses = [f["address"] for f in functions] or [s["address"] for s in sections if s["address"] is not None]
        rows.append({"id": index, "name": unit.get("name"), "module": module_of(unit, single),
                     "source": meta.get("source_path"), "linked": bool(meta.get("complete")),
                     "categories": meta.get("progress_categories") or ([folder] if single and folder else []),
                     "measures": measures(unit.get("measures")), "address": min(addresses) if addresses else None,
                     "functions": functions, "sections": sections})
    return rows


def _differences(report: dict, units: list[dict]) -> dict[str, dict[str, int]]:
    """Counters where the report's own totals are not the sum of its units' (objdiff's aggregates kept apart)."""
    reported = measures(report.get("measures"))
    summed = {key: sum(u["measures"][key] for u in units) for key in COUNTERS if key not in ("total_units",
                                                                                              "complete_units")}
    return {key: {"report": reported[key], "units": value} for key, value in summed.items() if reported[key] != value}


def page(reports: list[tuple[str, dict]], title: str, subtitle: str = "",
         modules: dict[str, str | None] | None = None) -> str:
    """One self-contained HTML file for one or more reports (labels such as target names); each report's own file
    is `<label>.json` beside it. `modules`: the one module of a label's target, when it has one."""
    payload = []
    for label, report in reports:
        units = _unit_rows(report, (modules or {}).get(label))
        totals = summary(report)
        if not totals["categories"]:   # a one-module target's folders, each with its units' totals
            folders: dict[str, dict[str, int]] = {}
            for unit in units:
                for folder in unit["categories"]:
                    counts = folders.setdefault(folder, dict.fromkeys(COUNTERS, 0))
                    for key, value in unit["measures"].items():
                        counts[key] += value if key not in ("total_units", "complete_units") else 0
                    counts["total_units"] += 1
                    counts["complete_units"] += unit["linked"]
            totals["categories"] = [{"id": name, "name": name, "measures": _with_percents(counts)}
                                    for name, counts in sorted(folders.items())]
        payload.append({"label": label, "file": f"{label}.json", "summary": totals, "units": units,
                        "differences": _differences(report, units)})
    data = json.dumps({"title": title, "subtitle": subtitle, "reports": payload,
                       "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")},
                      ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    template = resources.files("zkit").joinpath("report.html").read_text(encoding="utf-8")
    return template.replace("__TITLE__", _escape(title)).replace("__DATA__", data)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_page(project: Project, targets: list[str], out: Path, title: str | None = None) -> Path:
    reports = []
    for target in targets:
        path = report_path(project, target)
        if not path.is_file():
            raise ValueError(f"No report for {target} at {path}")
        reports.append((target, load(path)))
    out.mkdir(parents=True, exist_ok=True)
    for label, report in reports:  # the page links each report it shows
        (out / f"{label}.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    index = out / "index.html"
    subtitle = project.config.get("subtitle") or " · ".join(
        f"{label} ({project.target(label).get('platform', 'gamecube')})" for label, _ in reports)
    index.write_text(page(reports, title or project.config.get("title") or project.config["id"], subtitle,
                          {label: single_module(project, label) for label, _ in reports}), encoding="utf-8")
    return index


# The progress table in a decomp's README, between these markers.

README_START, README_END = "<!-- progress -->", "<!-- /progress -->"


def readme_block(reports: list[tuple[str, dict]]) -> str:
    """A small Markdown table per report: code and data matched and linked, exact functions, linked units."""
    lines = []
    for label, report in reports:
        m = measures(report.get("measures"))
        share = lambda part, whole: f"{100 * part / whole:.2f}%" if whole else "—"
        if len(reports) > 1:
            lines += [f"**{label}**", ""]
        code = share(m["matched_code"], m["total_code"]), share(m["complete_code"], m["total_code"])
        data = share(m["matched_data"], m["total_data"]), share(m["complete_data"], m["total_data"])
        lines += ["| | Matched | Linked |", "|:--|--:|--:|", f"| Code | {code[0]} | {code[1]} |",
                  f"| Data | {data[0]} | {data[1]} |",
                  f"| Functions | {m['matched_functions']:,} of {m['total_functions']:,} | |",
                  f"| Units | | {m['complete_units']:,} of {m['total_units']:,} |", ""]
    return "\n".join(lines).rstrip("\n")


def write_readme(project: Project, targets: list[str], path: Path) -> bool:
    """Rewrite the progress table between the README's markers from the current reports; True when it changed.
    A README without the markers gets a `## Progress` section with them before its first `##` heading."""
    reports = []
    for target in targets:
        report = report_path(project, target)
        if not report.is_file():
            raise ValueError(f"No report for {target} at {report}: build the project first")
        reports.append((target, load(report)))
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    start, end = text.find(README_START), text.find(README_END)
    if start < 0 or end < start:
        section = f"## Progress\n\n{README_START}\n{README_END}\n\n"
        heading = re.search(r"(?m)^## ", text)
        at = heading.start() if heading else len(text)
        text = text[:at] + ("" if not text[:at] or text[:at].endswith("\n\n") else
                            "\n" if text[:at].endswith("\n") else "\n\n") + section + text[at:]
        start, end = text.find(README_START), text.find(README_END)
    original = path.read_text(encoding="utf-8") if path.is_file() else None
    updated = text[:start + len(README_START)] + "\n" + readme_block(reports) + "\n" + text[end:]
    updated = updated.rstrip("\n") + "\n"
    if updated == original:
        return False
    path.write_text(updated, encoding="utf-8")
    return True
