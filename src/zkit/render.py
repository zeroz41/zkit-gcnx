"""Compact text for agents. Same data as --json, a fraction of the tokens."""

from __future__ import annotations

import re
from typing import Any

from .bridge import status_word


def _fn(info: dict, native: bool = True) -> str:
    if not info or not info.get("name"):
        return f"{info.get('address', '?')} (no function)"
    label = info.get("demangled") or info["name"]
    extra = f" native:{info['native_files']}" if native and info.get("native_files") else ""
    return f"{info['address']} {label} [{status_word(info)}]{extra}"


def _excerpt(text: str, limit: int, repo: str | None = None) -> str:
    """A note shortened at a sentence or word boundary, saying where the full text is."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit]
    stop = max(cut.rfind(". "), cut.rfind("; "))
    cut = cut[:stop + 1] if stop > limit // 2 else cut[:cut.rfind(" ")]
    return cut + f" … (full note: `zkit handoff {repo or '<repo>'}`)"


def _process_summary(procs: list[dict]) -> list[str]:
    agents = [p for p in procs if re.split(r"[/\\]", p["cmd"].split()[0])[-1].removesuffix(".exe") in ("claude", "codex")]
    tools = [p for p in procs if p not in agents]
    out = []
    if agents:
        kinds = {}
        for p in agents:
            kinds.setdefault(re.split(r"[/\\]", p["cmd"].split()[0])[-1].removesuffix(".exe"), []).append(str(p["pid"]))
        out.append("- live agent sessions: " + "; ".join(f"{k} x{len(v)} (pids {', '.join(v[:4])})" for k, v in kinds.items()))
    for p in tools[:8]:
        where = p["repo"] + (f"@{p['worktree'].rsplit('/', 1)[-1]}" if p.get("worktree") else "")
        out.append(f"- pid {p['pid']} [{where}] {p['age_min']}m cpu{p['cpu_pct']}% {p['cmd'][:90]}")
    if len(tools) > 8:
        out.append(f"- ... {len(tools) - 8} more tool processes (`zkit activity`)")
    return out


def brief(data: dict, compact: bool = False) -> str:
    if compact:
        return _brief_compact(data)
    out = [f"# zkit brief — {data['project']}  ({data['generated']})"]
    for name, measures in data.get("measures", {}).items():
        out.append(f"decomp {name}: {measures.get('matched_functions') or 0}/{measures.get('total_functions') or 0} funcs, "
                   f"code {measures.get('matched_code_percent', 0):.2f}%, linked "
                   f"{measures.get('complete_code_percent', 0):.2f}% (report {measures.get('report_age_h')}h old)")
    if data.get("warnings") or data.get("locks") or data.get("processes"):
        out.append("\n## Other activity")
        for warning in data.get("warnings", []):
            out.append(f"- WARN {warning}")
        for lock in data.get("locks", []):
            out.append(f"- lock {lock['repo']}:{lock['lock']} "
                       + (f"HELD by pid {lock['holder_pid']} {lock.get('holder_cmd') or ''}" if lock["held"]
                          else f"free ({lock.get('note')})"))
        out.extend(_process_summary(data.get("processes", [])))
    for name, repo in data["repos"].items():
        out.append(f"\n## {name} ({repo['role']}) — {repo['git'].get('branch')} @ {repo['git'].get('head')}")
        git = repo["git"]
        if git.get("dirty_count"):
            files = ", ".join(f"{d['path']}({d['age_min']}m)" for d in repo["dirty"][:6])
            out.append(f"- uncommitted: {git['dirty_count']} — {files}")
        for tree in repo.get("worktrees_with_changes", []):
            files = ", ".join((tree.get("modified", []) + tree.get("untracked", []))[:5])
            out.append(f"- worktree {tree['worktree']} [{tree.get('branch', 'detached')}] has "
                       f"{len(tree.get('modified', []))} modified + {len(tree.get('untracked', []))} new "
                       f"(not counting .venv/build) — stranded work? {files}")
        for branch in repo.get("unmerged_branches", [])[:5]:
            out.append(f"- branch {branch['branch']} +{branch['unmerged_commits']} unmerged ({branch['last']})")
        for note in repo.get("handoffs", []):
            out.append(f"- handoff {note['time']} ({note['author']}): {_excerpt(note['text'], 700, name)}")
        nxt = repo.get("next")
        if nxt:
            flag = " STALE (report newer; rerun the repo's router)" if nxt["stale_vs_report"] else ""
            yields = repo.get("lane_yield_last3") or {}
            own = yields.get(nxt["lane"])
            drained = own is not None and own.split("/")[0] == "0"
            state = f"DRAINED ({own} kept in its last 3 runs) — skip it; work `zkit demand` or the handoff's next step" \
                if drained else (f"yield {own}" if own else "no yield record")
            out.append(f"- router: lane `{nxt['lane']}` — {state} (brief {nxt['brief_age_h']}h old{flag})")
            if not drained:
                for command in nxt["commands"][:3]:
                    out.append(f"    {command}")
        if repo.get("lane_yield_last3"):
            ranked = sorted(repo["lane_yield_last3"].items(), key=lambda kv: -int(kv[1].split("/")[0]))
            out.append("- lane yield (kept/attempted, last 3 runs): " + ", ".join(f"{k} {v}" for k, v in ranked[:8]))
        if repo.get("tiers"):
            out.append("- fidelity tiers: " + ", ".join(f"{k} {v}" for k, v in repo["tiers"].items())
                       + " files — EXACT unless listed otherwise (`zkit tiers`)")
        ground = repo.get("grounding")
        if ground:
            weak = ", ".join(f"{w['folder']} {w['ready_pct']}%" for w in ground["weakest"])
            out.append(f"- grounding: cited originals {ground['total'].get('ready_pct')}% ready references "
                       f"({ground['total'].get('exact_pct')}% byte-exact) in the decomp; least ready: {weak} "
                       "(`zkit grounding`)")
        if repo.get("drift"):
            d = repo["drift"]
            out.append(f"- decomp drift: {d['changed']} cited function(s) changed since {d['since']}; re-verify "
                       + ", ".join(f"{r['path']}({r['functions']})" for r in d["files"]) + " (`zkit drift`)")
        if repo.get("status"):
            out.append("- status.md (Active work):")
            out.extend("    " + line for line in repo["status"].splitlines()[:14])
        if repo.get("required_reading"):
            out.append("- required reading (current architecture, standards and contracts govern implementation):")
            out.extend(f"    {d['reference']}" + (" [MISSING]" if not d['exists'] else "")
                       for d in repo['required_reading'])
        if repo.get("start"):
            out.append("- start: " + " ; ".join(f"`{c}`" for c in repo["start"]))
        if repo.get("audits"):
            audits = repo['audits']
            if audits['architecture_rules']:
                out.append(f"- include audit: `zkit architecture {name} <paths>` ({audits['architecture_rules']} rules)")
            for inventory in audits['coverage_inventories']:
                out.append(f"- inventory audit: `zkit coverage {name} {inventory['name']}` — {inventory['boundary']}")
        if repo.get("port_guidance"):
            out.append('- native-port architecture and completion: ' + repo['port_guidance'])
        if repo.get("rules"):
            out.append("- rules:")
            out.extend(f"  {i}. {rule}" for i, rule in enumerate(repo["rules"], 1))
        if repo.get("finish"):
            out.append("- finish gate:")
            out.extend(f"    {c}" for c in repo["finish"])
        if repo.get("lessons"):
            out.append("- lessons (`zkit lessons <id>`): " + "; ".join(l["id"] for l in repo["lessons"]))
    demand = data.get("port_demand")
    if demand:
        t = demand["totals"]
        out.append(f"\n## Port waiting on decomp — {t.get('cited_functions')} cited funcs, {t.get('exact')} exact, "
                   f"{t.get('provisional_name')} provisional names (`zkit demand`)")
        for row in demand["top"]:
            out.append(f"- {row['address']} {row['name']} needs {'+'.join(row['need'])} ({row['native_files']} native files)")
    return "\n".join(out)


def _brief_compact(data: dict) -> str:
    """Session-start summary of every repo in ~3 KB; `zkit_brief <repo>` gives one repo in full."""
    out = [f"# zkit brief — {data['project']}  ({data['generated']})"]
    for name, m in data.get("measures", {}).items():
        out.append(f"decomp {name}: {m.get('matched_functions') or 0}/{m.get('total_functions') or 0} funcs, code "
                   f"{m.get('matched_code_percent', 0):.2f}%, linked {m.get('complete_code_percent', 0):.2f}% "
                   f"(report {m.get('report_age_h')}h old)")
    for warning in data.get("warnings", []):
        out.append(f"- WARN {warning}")
    for lock in data.get("locks", []):
        if lock["held"]:
            out.append(f"- lock {lock['repo']}:{lock['lock']} HELD by pid {lock['holder_pid']} {lock.get('holder_cmd') or ''}")
    out.extend(_process_summary(data.get("processes", [])))
    for name, repo in data["repos"].items():
        git = repo["git"]
        out.append(f"\n## {name} ({repo['role']}) — {git.get('branch')} @ {git.get('head')}")
        if git.get("dirty_count"):
            out.append(f"- uncommitted: {git['dirty_count']} — " + ", ".join(
                f"{d['path']}({d['age_min']}m)" for d in repo["dirty"][:3]))
        stranded = repo.get("worktrees_with_changes", [])
        if stranded:
            out.append(f"- {len(stranded)} worktree(s) with uncommitted changes, e.g. {stranded[0]['worktree']}"
                       f" [{stranded[0].get('branch', 'detached')}]")
        if repo.get("unmerged_branches"):
            out.append(f"- {len(repo['unmerged_branches'])} unmerged branch(es): " + ", ".join(
                b["branch"] for b in repo["unmerged_branches"][:3]))
        for note in repo.get("handoffs", [])[:1]:
            out.append(f"- last handoff {note['time']} ({note['author']}): {_excerpt(note['text'], 500, name)}")
        nxt = repo.get("next")
        if nxt:
            own = (repo.get("lane_yield_last3") or {}).get(nxt["lane"])
            drained = own is not None and own.split("/")[0] == "0"
            out.append(f"- router lane `{nxt['lane']}`" + (f" DRAINED ({own} kept, last 3 runs)" if drained else
                                                         f" (yield {own})" if own else ""))
        if repo.get("grounding"):
            g = repo["grounding"]
            out.append(f"- grounding: cited originals {g['total'].get('ready_pct')}% ready, {g['total'].get('exact_pct')}% "
                       "exact; least ready " + ", ".join(f"{w['folder']} {w['ready_pct']}%" for w in g["weakest"][:3]))
        if repo.get("drift"):
            out.append(f"- decomp drift: {repo['drift']['changed']} cited function(s) to re-verify (`zkit drift`)")
        if repo.get("required_reading"):
            out.append("- required reading: " + "; ".join(
                d['reference'] + (" [MISSING]" if not d['exists'] else "") for d in repo['required_reading']))
        if repo.get('port_guidance'):
            out.append('- native port: shared owners and interfaces; composed behavior; automated import/dependency '
                       'discovery; authored data rather than identity/shape guesses. Complete the requested live '
                       'system and verify its boundary. Matching decomp keeps original layout/compiler constraints.')
        out.append(f"- rules, finish gate, status, lessons: `zkit_brief {name}` (MCP) or `zkit brief {name}`")
    demand = data.get("port_demand")
    if demand:
        t = demand["totals"]
        out.append(f"\n## Port waiting on decomp — {t.get('cited_functions')} cited, {t.get('exact')} exact, "
                   f"{t.get('provisional_name')} provisional names (`zkit demand`)")
        if demand.get("unchanged_since"):
            out.append(f"- the top of the list has not changed since {demand['unchanged_since']} "
                       f"({', '.join(r['address'] for r in demand['top'][:3])}); `zkit demand --offset 3` for others")
        else:
            for row in demand["top"][:3]:
                out.append(f"- {row['address']} {row['name']} needs {'+'.join(row['need'])} ({row['native_files']} native files)")
    return "\n".join(out)


def _cite_line(c: dict, width: int = 110) -> str:
    return f"  {c['repo']}:{c['path']}:{c['line']}  {c['text'][:width]}"


def _is_harness(c: dict) -> bool:
    return c["text"].lstrip().startswith("#define")


def lookup(data: dict) -> str:
    if data.get("batch") is not None:
        parts = [lookup(item) for item in data["batch"]]
        if data.get("truncated"):
            parts.append(f"... {data['truncated']} more queries not looked up (60 per call)")
        return "\n\n".join(parts)
    if not data.get("found"):
        s = data.get("symbol")
        if s:  # a data address: say what it is first, so it does not read as a failed lookup
            lines = [f"{data.get('address', data.get('query'))} is data, not code: {s['name']} ({s['section']}, "
                     f"size 0x{s['size']:X}" + (f", +0x{s['offset']:X} into it" if s['offset'] else "") + ")"]
        else:
            lines = [f"no function for {data.get('query')}: {data.get('hint', '')}"]
        owner = data.get("owner_unit")
        if owner:
            lines.append(f"  owner unit {owner['unit']} ({owner['section']} {owner['start']}-{owner['end']})")
        elif s and data.get("has_splits"):
            lines.append("  owner unit: none in splits.txt (decomp-toolkit gives it to an auto-generated unit)")
        if data.get("suggestions"):
            lines.append("  similar: " + ", ".join(data["suggestions"]))
        slots = data.get("slots") or []
        if slots:
            lines.append(f"pointers inside it ({len(slots)}" + (", first 48" if len(slots) > 48 else "") + "):")
            for slot in slots[:48]:
                lines.append(f"  +0x{slot['offset']:X} (slot {slot['offset'] // 4}) -> {slot['target']}"
                             + (f" [{slot['status']}]" if slot.get("status") else ""))
        rw = data.get("readers_writers") or []
        if rw:
            lines.append(f"code refs ({len(rw)}): " + ", ".join(
                f"{r.get('function', '?')}[{r['kind']}{'+0x%X' % r['offset'] if r['offset'] else ''}]" for r in rw[:16])
                + (" ..." if len(rw) > 16 else ""))
        for ref in (data.get("pointed_from") or [])[:8]:
            lines.append(f"  pointed to from {ref.get('symbol', '')}+0x{ref.get('offset', 0):X} @ {ref['holder']}")
        for cite in data.get("cites", [])[:12]:
            lines.append(f"  cited {cite['repo']}:{cite['path']}:{cite['line']}  {cite['text'][:110]}")
        for cite in data.get("mentions", [])[:8]:
            lines.append(f"  mentioned {cite['repo']}:{cite['path']}:{cite['line']}  {cite['text'][:110]}")
        return "\n".join(lines)
    if data.get("ambiguous"):
        return (f"{data['query']} matches {len(data['candidates'])}{' or more' if data.get('more') else ''} functions; "
                "use an address or the full name:\n" + "\n".join(f"  {_fn(c)}" for c in data["candidates"]))
    f = data["function"]
    if f.get("defined_in") and f.get("source_line"):  # an inline method found in a header
        kind = "inline in a header" if f["defined_in"].endswith((".h", ".hpp", ".hh")) else "included by the unit"
        where = f"{f['defined_in']}:{f['source_line']} ({kind}; unit source {f.get('source')})"
    elif f.get("defined_in"):
        where = f"{f.get('source')} — {f['defined_in']}"
    else:
        where = f"{f['source']}:{f['source_line']}" if f.get("source_line") else (f.get("source") or "no source unit")
    age = f" (report {data['report_age_h']}h old)" if data.get("report_age_h") is not None else ""
    out = [f"{_fn(f)} size 0x{f['size']:X}" + (f" (+0x{data['offset']:X})" if data.get("offset") else "") + age,
           f"  unit {f.get('unit')}  ->  decomp:{where}"]
    stale = data.get("report_stale") or {}
    if stale.get("sources_newer"):
        out.insert(0, f"STALE: {stale['sources_newer']} source file(s) changed after the report was written "
                      f"({stale['age_h']}h ago, e.g. {stale['examples'][0]}); match and link state may be out of date "
                      "until the decomp is rebuilt")
    callers = data["callers"]
    shown = callers["rows"][:20]
    out.append(f"callers ({callers['count']}" + (f", showing {len(shown)}" if callers["count"] > len(shown) else "") + "):")
    out.extend(f"  {_fn(c)}" for c in shown)
    if callers["count"] > len(shown) or len(callers.get("by_class", [])) > 1:
        out.append("  callers by class: " + ", ".join(f"{k} {v}" for k, v in callers.get("by_class", [])))
    slots = data.get("slots") or []
    if data.get("data_refs"):
        out.append(f"referenced from data ({len(data['data_refs'])}):")
        for slot in slots[:6]:
            tables = ", ".join(sorted({h['symbol'] if h['symbol'].startswith('__vt__') else
                                       f"{h['symbol']}" + (f" (owner {h['owners'][0]})" if h.get('owners') else "")
                                       for h in slot["holders"]})[:6])
            more = " ..." if slot["tables"] > 6 else ""
            out.append(f"  vtable slot +0x{slot['offset']:X} (slot {slot['slot']}) in {slot['tables']} table(s): {tables}{more}")
            out.append(f"    -> {slot['verdict']}")
        others = [r for r in data["data_refs"] if r.get("vtable_slot") is None]
        for ref in others[:8]:
            out.append(f"  {ref.get('symbol', '')}+0x{ref.get('offset', 0):X} @ {ref['address']}" if ref.get("symbol")
                       else f"  @ {ref['address']}")
    out.append(f"callees ({len(data['callees'])} direct):")
    out.extend(f"  {_fn(c)}" for c in data["callees"][:30])
    if data["native_cites"]:
        code = [c for c in data["native_cites"] if not c["path"].startswith("docs/") and not _is_harness(c)]
        harness = [c for c in data["native_cites"] if _is_harness(c)]
        docs = [c for c in data["native_cites"] if c["path"].startswith("docs/") and not _is_harness(c)]
        out.append(f"native cites ({len(data['native_cites'])}):")
        out.extend(_cite_line(c) for c in code[:15])
        if len(code) > 15:
            out.append(f"  ... {len(code) - 15} more code cites")
        out.extend(_cite_line(c) for c in docs[:6])
        if len(docs) > 6:
            out.append(f"  ... {len(docs) - 6} more doc cites in " + ", ".join(sorted({c['path'] for c in docs[6:]})[:6]))
        if harness:
            out.append(f"  ({len(harness)} harness #define hook line(s) in " + ", ".join(sorted({c['path'] for c in harness})[:3]) + ")")
    else:
        if data.get("has_native", True):
            out.append("native cites: none — not ported yet (or cited by another address)")
    if data["decomp_cites"]:
        out.append("decomp docs/reference:")
        out.extend(_cite_line(c) for c in data["decomp_cites"][:6])
        if len(data["decomp_cites"]) > 6:
            out.append(f"  ... {len(data['decomp_cites']) - 6} more in " + ", ".join(sorted({c['path'] for c in data['decomp_cites'][6:]})[:6]))
    if data.get("mentions"):
        out.append(f"mentioned in ({len(data['mentions'])}): " + ", ".join(
            sorted({f"{c['repo']}:{c['path']}" for c in data["mentions"]})[:8]))
    if data["recipes"]:
        out.append("fidelity recipes: " + ", ".join(data["recipes"]))
    if data.get("decompile"):
        out.append(f"Ghidra's C next to m2c: zkit decompile {f['address']} (MCP zkit_decompile)")
    if data.get("body"):
        lo, hi = data["body_lines"]
        out.append(f"body ({f.get('source')}:{lo}-{hi}):")
        out.append(data["body"])
    return "\n".join(out)


def port_plan(data: dict, legend: bool = True) -> str:
    if data.get("batch") is not None:
        parts = [port_plan(item, legend=False) for item in data["batch"]]
        limits = next((item["limits"] for item in data["batch"] if item.get("limits")), None)
        return "\n\n".join(parts + [_plan_legend(data["legend"], limits)])
    if not data.get("nodes"):
        return lookup(data) + (f"\n{data['note']}" if data.get("note") else "")
    root = dict(data["root"], native_files=None)
    out = [f"port plan for {_fn(root)}, depth {data.get('depth')}: "
           + ", ".join(f"{k} {v}" for k, v in data["summary"].items())]
    if data.get("note"):
        out.append(data["note"])
    for node in data["nodes"]:
        indent = "  " * node["depth"]
        files = f" -> {', '.join(node['native_files'][:3])}" if node["native_files"] else ""
        if node.get("native_docs"):
            files += f" (+{node['native_docs']} doc/test file(s) cite it)"
        indirect = f", {node['indirect_calls']} bctrl" if node.get("indirect_calls") else ""
        reference = ", reference: original assembly" if node.get("reference") == "assembly" else ""
        out.append(f"{indent}[{node['action']}] {node['address']} {node.get('demangled') or node['name']} "
                   f"({status_word(node)}, {node['original_callers']} callers{indirect}{reference}){files}")
        reasons = [r for r in node.get("not_ready") or [] if r != "not byte-exact"]
        if reasons and node["action"] != "platform":
            out.append(f"{indent}    not ready: " + "; ".join(reasons)[:300])
    if data.get("truncated_nodes"):
        out.append(f"... {data['truncated_nodes']} more nodes not expanded (lower depth or plan a callee)")
    if legend:
        out.append(_plan_legend(data["legend"], data.get("limits")))
    return "\n".join(out)


def _plan_legend(legend: dict, limits: str | None = None) -> str:
    return "legend: " + "; ".join(f"{k} = {v}" for k, v in legend.items()) + (f"\nlimits: {limits}" if limits else "")


def demand(data: dict) -> str:
    t = data["totals"]
    out = [f"port cites {t.get('cited_functions')} decomp functions: {t.get('exact')} exact, {t.get('linked')} linked, "
           f"{t.get('provisional_name')} provisional names; {data['unresolved_native_addresses']} cited addresses "
           "are not functions (data/typos — `zkit cites`)"]
    shown = len(data["rows"])
    out.append(f"{data.get('matching_rows', shown)} rows match the filter; showing {shown} from offset {data.get('offset', 0)}"
               + (f" (report {data['report_age_h']}h old)" if data.get("report_age_h") is not None else ""))
    out.append("address    size  state        need         files  name  (unit)")
    for row in data["rows"]:
        out.append(f"{row['address']} {row['size']:>5}  {status_word(row):<12} {'+'.join(row['need']):<12} "
                   f"{row['native_files']:>5}  {row['name']}  ({row.get('unit') or '-'}) e.g. {row['example_file']}")
    return "\n".join(out)


def search(data: dict) -> str:
    head = [] if data.get("mode") == "all words" else [f"(matched {data.get('mode')})"]
    return "\n".join(head + [f"{r['ref']}\n    {r['excerpt'].replace(chr(10), ' / ')[:220]}" for r in data["results"]]) \
        if data["results"] else ("no results (search covers the indexed docs and source text; for function or "
                                 "symbol names use `names --regex`)")


def check(data: dict, groups_shown: int = 40, refs_shown: int = 12) -> str:
    """Findings grouped by rule, original and message: the reason is printed once, then where it occurs."""
    out = [f"check {data['repo']} vs {data['base']}: " + ", ".join(f"{k}={v}" for k, v in data["stats"].items())
           + (" — OK" if data["ok"] else " — ERRORS")]
    groups: dict[tuple, list[dict]] = {}
    for f in data["findings"]:
        groups.setdefault((f["severity"], f["rule"], f.get("address", ""), f.get("name", ""), f["message"]), []).append(f)
    for (severity, rule, address, name, message), items in list(groups.items())[:groups_shown]:
        detail = f" {address} {name}".rstrip()
        message = message if len(message) <= 240 else message[:240] + "…"
        if len(items) == 1 and not items[0].get("line"):
            out.append(f"{severity:<7} {rule} {items[0]['ref']}{detail}: {message}")
            continue
        out.append(f"{severity:<7} {rule}{detail}: {message} ({len(items)}x)")
        if any(i.get("line") for i in items):
            out.extend(f"    {i['ref']}  {i.get('line', '')}"[:200] for i in items[:refs_shown])
        else:
            out.append("    at " + ", ".join(i["ref"] for i in items[:refs_shown]))
        if len(items) > refs_shown:
            out.append(f"    ... {len(items) - refs_shown} more")
    if len(groups) > groups_shown:
        rest = {}
        for severity, rule, *_ in list(groups)[groups_shown:]:
            rest[f"{severity} {rule}"] = rest.get(f"{severity} {rule}", 0) + 1
        out.append(f"... {len(groups) - groups_shown} more groups (" + ", ".join(f"{k} x{v}" for k, v in rest.items())
                   + f"; all {len(data['findings'])} findings with response_format=json, or narrow paths)")
    for rule, text in (data.get("help") or {}).items():
        out.append(f"{rule}: {text}")
    return "\n".join(out)


def reuse(data: dict) -> str:
    out = [f"reuse audit for {data['repo']}"]
    if data["identical_helpers"]:
        out.append("helper bodies defined in several files (identical: share one; same body over different "
                   "parameter types: a template or interface candidate):")
        for d in data["identical_helpers"]:
            kind = "" if d.get("kind", "identical") == "identical" else f" [{d['kind']}: {' | '.join(d['signatures'])}]"
            out.append(f"  {d['name']} x{d['copies']}{kind}: {', '.join(d['places'][:4])}")
    if data["same_name_helpers"]:
        out.append("same helper name in many files (check for drifted copies):")
        for d in data["same_name_helpers"][:15]:
            out.append(f"  {d['name']} in {d['files']} files: {', '.join(d['examples'][:3])}")
    sites = data["enumeration_sites"]
    if sites["terms"]:
        out.append(f"files naming at least {sites.get('needed', 2)} of {sites['terms']} ({sites['files']}) — central "
                   "sites a new variant edits:")
        for row in sites["rows"]:
            out.append(f"  {row['path']}: {', '.join(row['variants'])}")
    return "\n".join(out)


def activity(data: dict) -> str:
    fake = {"project": "", "generated": "", "repos": {}, "warnings": data["warnings"],
            "locks": [l for l in data["locks"] if l.get("held") or l.get("note")], "processes": data["processes"]}
    out = [brief(fake).split("\n", 1)[1] if fake["warnings"] or fake["locks"] or fake["processes"]
           else "no other agent/build/emulator processes in configured repos; no held locks"]
    for name, repo in data["repositories"].items():
        if not repo.get("git"):
            continue
        out.append(f"{name}: {repo['branch']} @ {repo['head']} — {repo['dirty_count']} uncommitted, "
                   f"{repo['stashes']} stash(es)")
        for d in repo["dirty"][:10]:
            out.append(f"   {d['state']:<2} {d['path']} ({d['age_min']}m ago)")
        for b in repo["unmerged_branches"]:
            out.append(f"   branch {b['branch']} +{b['unmerged_commits']} ({b['last']})")
        for w in repo["worktrees"]:
            out.append(f"   worktree {w['worktree']} [{w.get('branch', 'detached')}] "
                       + ("MISSING" if not w["exists"] else
                          f"{len(w.get('modified', []))} modified + {len(w.get('untracked', []))} new "
                          + ", ".join((w.get("modified", []) + w.get("untracked", []))[:4])))
    for note in data["handoffs"]:
        out.append(f"handoff {note['time']} [{note['repo']}] {note['author']}: {_excerpt(note['text'], 300, note['repo'])}")
    return "\n".join(out)


def gate(data: dict) -> str:
    out = [f"finish gate for {data['repo']}:"] + [f"  {c}" for c in data["finish"]]
    for d in data["drift"]:
        if d.get("missing_file"):
            out.append(f"drift: {d['source']} missing")
            continue
        out.append(f"drift: {d['source']} lacks {d['missing'] or '-'}; extra {d['extra'] or '-'}")
    owning = data.get("owning_tests")
    if owning:
        out.append(f"owning checks for this diff ({owning['tests']} direct test(s) of {owning['changed']} changed "
                   f"file(s), from zkit impact):")
        out.extend(f"  {command}" for command in owning["commands"])
    for app in data.get("stale_apps", []):
        newest = app["newer"][0]
        out.append(f"stale build: {app['output']} (built {app['built']}) is older than {app['newer_count']} source(s), "
                   f"newest {newest['file']}; rebuild before anyone runs it")
    review = data.get("session") or {}
    if review.get("error"):
        out.append(f"session review unavailable: {review['error']}")
    elif review:
        start = review.get("start")
        out.append("this session" + (f" (started {start['time']}):" if start else
                                     " (no start record; judging the last 5 commits):"))
        for target, delta_data in (review.get("progress") or {}).items():
            if delta_data.get("error"):
                out.append(f"  {target}: {delta_data['error']}")
                continue
            m = delta_data["metrics"]
            out.append(f"  {target}: exact functions {m['matched_functions']['delta']:+,}, matched code "
                       f"{m['matched_code']['delta']:+,} B, linked code {m['complete_code']['delta']:+,} B, matched data "
                       f"{m['matched_data']['delta']:+,} B" + ("" if delta_data["ok"] else " — LOSSES:"))
            out.extend(f"    FAIL {f}" for f in delta_data["failures"])
            out.extend(f"    lost: {r['address']} {r['name']}" for r in delta_data["regressed"][:10])
        hyg = review.get("hygiene") or {}
        for row in (hyg.get("commits") or {}).get("problems", [])[:10]:
            out.append(f"  commit {row['commit']} {row['subject'][:50]!r}: " + "; ".join(row["problems"]))
        tree = hyg.get("tree") or {}
        if tree.get("problems"):
            out.append("  leaves behind: " + "; ".join(tree["problems"][:8]))
        elif tree:
            out.append("  working tree clean")
        for proc in review.get("processes", [])[:8]:
            out.append(f"  still running since this session started: pid {proc['pid']} ({proc['age_min']}m) {proc['cmd']}")
    return "\n".join(out)


def stale(data: dict) -> str:
    if not data.get("checked"):
        return data.get("note", "not checked")
    rows = data["outputs"]
    out = [f"{data['stale']} of {len(rows)} built program(s) older than their sources:"]
    for r in [r for r in rows if r["stale"]][:25]:
        newest = r["newer"][0]
        out.append(f"  STALE {r['output']} built {r['built']}: {r['newer_count']} newer, e.g. {newest['file']} "
                   f"(+{newest['minutes_after_build']} min)")
    if data.get("unknown_programs"):
        out.append(f"  not a linked program in this build: {', '.join(data['unknown_programs'])}")
    fresh = [r["output"] for r in rows if not r["stale"]]
    if fresh:
        out.append(f"  up to date: {', '.join(fresh[:12])}" + (f" +{len(fresh) - 12}" if len(fresh) > 12 else ""))
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def decompiled(data: dict) -> str:
    if data.get("results") is None:
        return (f"{data['functions']} function(s) in {data['target']}: decompiled {data['decompiled_now']} now in "
                f"{data['seconds']} s, the rest were cached.\n{data['limits']}")
    out = []
    for r in data["results"]:
        if r.get("text"):
            head = f"// {r['address']} {r['name']} size 0x{r['size']:X}"
            if r.get("match") is not None:
                head += f" [{r['match']:.0f}% matched]"
            out.append(head + "\n" + r["text"])
        else:
            out.append(f"// {r['address']} {r.get('name') or ''}: {r.get('error')}".replace("  ", " "))
    tail = f"// {data['engine']}; {data['decompiled_now']} decompiled now, {data['seconds']} s. {data['limits']}"
    return "\n\n".join(out) + "\n\n" + tail


def disasm(data: dict) -> str:
    if data.get("batch") is not None:
        return "\n\n".join(disasm(item) for item in data["batch"])
    if not data.get("size"):
        return data.get("text", "")
    f = data.get("function")
    head = f"{data['address']} size 0x{data['size']:X}"
    if f:
        head += f" — {f.get('demangled') or f['name']} [{status_word(f)}]"
        if f.get("address") != data["address"] or data.get("function_size", f.get("size")) != data["size"]:
            head += f" (function {f['address']} size 0x{f['size']:X})"
    out = head + "\n" + data["text"]
    if data.get("truncated"):
        out += f"\n... truncated at {data['size'] // 4} lines; pass a start address and size for the rest"
    return out


def _batched(render, data: dict) -> str | None:
    if data.get("batch") is None:
        return None
    parts = [f"{item['query']}: error: {item['error']}" if "error" in item else render(item) for item in data["batch"]]
    return "\n\n".join(parts) + (f"\n\n{data['note']}" if data.get("note") else "")


def data_rows(data: dict) -> str:
    batched = _batched(data_rows, data)
    if batched is not None:
        return batched
    out = [f"{data['address']} {data['kind']}" + (f" (inside {data['inside_function']})" if data.get("inside_function") else "")]
    for row in data["rows"]:
        prefix = f"[{row['index']}] " if "index" in row else ""
        out.append(f"  {prefix}{row['address']}: " + ", ".join(str(v) for v in row["values"]))
    return "\n".join(out)


def names(data: dict) -> str:
    out = []
    for r in data["rows"]:
        if r.get("ambiguous"):
            out.append(f"{r['query']}: matches {len(r['ambiguous'])}{' or more' if r.get('more') else ''} functions: "
                       + "; ".join(f"{c['address']} {c.get('demangled') or c['name']}" for c in r["ambiguous"]))
        elif r.get("data"):
            s = r.get("symbol")
            out.append(f"{r.get('address') or r['query']} {s['name'] + ('+0x%X' % s['offset'] if s['offset'] else '') if s else '(no symbol)'}"
                       + (f" {s['section']} size 0x{s['size']:X}" if s else "") + "  [data]")
        elif r.get("found") is False:
            out.append(f"{r['query']}: no function or symbol" + (" at that address" if r.get("address") else " by that name"))
        else:
            offset = f" (+0x{r['offset']:X})" if r.get("offset") else ""
            out.append(f"{r['address']} {r.get('demangled') or r['name']}{offset} size 0x{r['size']:X} [{status_word(r)}] "
                       f"{r.get('unit') or ''}")
    if data.get("truncated"):
        out.append(f"... {data['truncated']} more (total {data['total']}; narrow with regex, unit or a range, or raise "
                   "limit)")
    return "\n".join(out) or "no matches"


def xrefs(data: dict) -> str:
    batched = _batched(xrefs, data)
    if batched is not None:
        return batched
    s = data.get("symbol")
    what = (f" {data['function']}" if data.get("function") else
            (f" in {s['name']}+0x{s['offset']:X}" if s.get("offset") else f" {s['name']}")
            + f" ({s['section']} size 0x{s['size']:X})" if s else "")
    kinds = ", ".join(f"{k} {v}" for k, v in sorted(data["kinds"].items()))
    total_data = data.get("data_total", len(data["data"]))
    inner = total_data - data.get("data_to_start", total_data)
    out = [f"xrefs to [{data['address']}, +0x{data['size']:X}){what}: {data.get('total', len(data['code']))} code refs"
           + (f" ({kinds})" if kinds else "") + f", {total_data} data pointers"
           + (f" ({inner} into it past the start: jump-table cases or interior addresses)" if inner and
              data.get("function") else "")]
    modules = data.get("modules") or []
    if modules:
        from_rels = sum(n for _, n in modules)
        out.append(f"main DOL: {data.get('total', 0) - from_rels} refs; REL modules: {from_rels} refs in {len(modules)} "
                   f"module(s), most: " + ", ".join(f"{m} x{n}" for m, n in modules[:10])
                   + (f" (+{len(modules) - 10} more; response_format=json lists all)" if len(modules) > 10 else ""))
        out.append("functions with the most refs:")
    for name, n in data["functions"][:30]:
        kinds = sorted({c['kind'] for c in data['code'] if c.get('function') == name})
        out.append(f"  {name}  x{n}" + (f" [{','.join(kinds)}]" if kinds else ""))
    for ref in data["data"][:12]:
        into = f" -> +0x{ref['into']:X}" if ref.get("into") else ""
        out.append(f"  pointer at {ref['holder']} {ref.get('symbol', '')}+0x{ref.get('offset', 0):X}{into}")
    if total_data > 12:
        out.append(f"  ... {total_data - 12} more pointers (response_format=json lists {len(data['data'])})")
    return "\n".join(out)


def renamed(data: dict) -> str:
    out = [f"{data['count']} symbol(s) renamed since {data['since']} ({data['commit']}):"]
    out.extend(f"  {r['address']} {r['old']} -> {r['new']}" for r in data["renamed"][:200])
    if data["count"] > 200:
        out.append(f"  ... {data['count'] - 200} more (--json)")
    return "\n".join(out)


def generic(data: Any) -> str:
    import json
    return json.dumps(data, indent=1, ensure_ascii=False)


def impact(data: dict, files_shown: int = 10) -> str:
    """Commands first (they are what gets run), then the selection, then per-file detail."""
    if data.get("selected") is not None:  # exact names: the test plan
        return test_plan(data)
    if not data.get("files"):
        return data.get("note", "nothing changed")
    out = [f"impact of {len(data['changed'])} changed file(s) in {data['repo']}:"]
    out.extend(f"note: {n}" for n in data.get("notes", []))
    stale = data.get("stale_programs", [])
    if stale:
        first = stale[0]["newer"][0]["file"] if stale[0]["newer"] else "its sources"
        out.append(f"BUILD FIRST: {len(stale)} program(s) the selection runs are older than their sources ("
                   + ", ".join(r["program"] for r in stale[:4]) + (" ..." if len(stale) > 4 else "")
                   + f"; e.g. {stale[0]['program']} < {first}); `zkit_stale` lists them")
    blocked = data.get("plan_blocked") or {}
    out.extend(f"BLOCKED {key}: {', '.join(values)}" for key, values in blocked.items())
    if data["commands"]:
        out.append("run (direct first, then near and linked; deferred only for a shared or risky change):")
        rank = {"direct": 0, "near": 1, "linked": 2, "deferred": 3}
        for key in sorted(data["commands"], key=lambda k: (rank.get(k.split("/")[0], 4), k)):
            total = data["totals"].get(key, {})
            seconds = f", ~{total['serial_seconds']} s recorded" if total.get("serial_seconds") is not None else ""
            unknown = f", {total['unknown_costs']} unmeasured" if total.get("unknown_costs") else ""
            out.append(f"  # {key}: {total.get('tests', '?')} tests{seconds}{unknown}")
            lines = data["commands"][key].split("\n")
            if key == "deferred" and len(lines) > 2:
                out.append(f"  ({len(lines)} commands; response_format=json has them in command_argvs.deferred)")
                continue
            out.extend("  " + line for line in lines)
    for step in data.get("prebuilds", []):
        out.append(f"  # optional prebuild of {len(step['fixture_tests'])} build fixture(s), cwd {step['cwd']}:")
        out.append(f"  {step['command']}")
    for tier in ("direct", "near", "linked"):
        for label, names in data["groups"].get(tier, {}).items():
            out.append(f"{tier}/{label}: {', '.join(names[:12])}" + (f" ... +{len(names) - 12}" if len(names) > 12 else ""))
    broad = data["totals"]["broad"]
    if broad["tests"]:
        out.append(f"broad ({broad['tests']}, include distance 3+, not selected): {', '.join(broad['names'][:12])}"
                   + (" ..." if broad["tests"] > 12 else ""))
    if data["untested_files"]:
        out.append("NO test compiles or links: " + ", ".join(data["untested_files"][:20])
                   + " — inspect the owning tests/recipes; a test may still drive it through data or a script.")
    for f in data["files"][:files_shown]:
        t = f["tests"]
        stems = sorted({c.rpartition(".")[0] for c in f["consumers"]})
        out.append(f"  {f['file']}: tests direct {t['direct']} / near {t['near']} / linked {t['linked']} / broad "
                   f"{t['broad']}; {len(stems)} direct consumer(s)" + (f": {', '.join(stems[:6])}" if stems else "")
                   + (" ..." if len(stems) > 6 else ""))
    if len(data["files"]) > files_shown:
        out.append(f"  ... {len(data['files']) - files_shown} more files (response_format=json)")
    out.append(f"limits: {data['limits']}")
    return "\n".join(out)


def architecture(data: dict) -> str:
    out = [f"architecture {data['repo']}: {data['files_checked']} files, {data['includes_checked']} includes, "
           f"{len(data['findings'])} boundary violations, {len(data['allowed_exceptions'])} allowed exceptions"]
    out.extend(f"{f['reference']} [{f['rule']}] {f['include']} -> {f['resolved'] or 'unresolved'}: {f['reason']}"
               for f in data['findings'][:80])
    if len(data['findings']) > 80:
        out.append('More findings available as JSON; narrow paths for a system-level review.')
    out.extend(f"ERROR {e['reference']}: {e['error']}" for e in data['errors'])
    out.append(f"unresolved quoted includes: {len(data['unresolved_includes'])}; system <...> includes: "
               f"{data.get('system_includes', 0)}; macro includes: {data['macro_includes']}")
    out.append('contracts: ' + ', '.join(data['documents']))
    out.append('limits: ' + data['limits'])
    return '\n'.join(out)


def coverage(data: dict) -> str:
    out = [f"coverage {data['repo']}/{data['name']}: {data['expected']} reference identities", data['boundary']]
    for stage in data['stages']:
        out.append(f"{stage['id']}: {stage['covered']}/{data['expected']} present, "
                   f"{len(stage['extra'])} outside reference, {len(stage['inventory']['duplicates'])} duplicated identities")
        if stage['missing']:
            out.append('  missing: ' + ', '.join(stage['missing'][:80]) + (' ... use JSON' if len(stage['missing']) > 80 else ''))
        for dependency, missing in stage['without_prerequisite'].items():
            out.append(f"  present without {dependency}: " + ', '.join(missing[:80]))
    out.extend('ERROR ' + e for e in data['errors'])
    out.append('inventory covered: ' + str(data['inventory_covered']).lower() + '; system completion: not established')
    out.append('limits: ' + data['limits'])
    return '\n'.join(out)


def test_plan(data: dict) -> str:
    found = [n for n in data['selected'] if n not in data['missing']]
    out = [f"test plan for {data['repo']}: {len(found)} selected checks"
           + (f" ({len(data['missing'])} not in the catalog)" if data['missing'] else "")
           + f", {len(data['fixture_tests'])} required setup/cleanup tests (nothing executed)"]
    for key in ('missing', 'disabled', 'unresolved_fixtures'):
        if data[key]:
            out.append(f"BLOCKED {key}: " + ', '.join(data[key]))
    if data['fixture_tests']:
        out.append('fixture tests CTest adds: ' + ', '.join(data['fixture_tests'][:20])
                   + (' ...' if len(data['fixture_tests']) > 20 else ''))
    for key, cost in data['costs'].items():
        out.append(f"{key}: {cost['recorded_seconds']} s recorded; {cost['unknown_costs']} unmeasured")
    for step in data['prebuilds']:
        out.append(f"optional prebuild ({len(step['fixture_tests'])} build fixtures; cwd {step['cwd']}):")
        out.append('  ' + step['command'])
    if data['commands']:
        out.append('then run with all fixtures retained:')
        out.extend('  ' + c for c in data['commands'])
    out.append('limits: ' + data['limits'])
    return '\n'.join(out)


def grounding(data: dict) -> str:
    t = data["total"]
    reasons = ", ".join(f"{r} x{n}" for r, n in t.get("top_reasons", []))
    out = [f"grounding of {data['repo']} {', '.join(data['scope'])}: {t['functions']} original functions cited "
           f"({t['cites']} citations in {data['units_with_cites']} units); {t['ready_pct']}% ready references, "
           f"{t['exact_pct']}% byte-exact, {t['named_pct']}% named on evidence; {t['unmatched']} not byte-exact, "
           f"{t['not_function']} citations of data/no function"]
    if reasons:
        out.append(f"  why not ready: {reasons}")
    out.extend(f"note: {n}" for n in data.get("notes", []))
    out.append("least ready folders (ready% / exact% / named% / functions, main reason):")
    for f in data["folders"]:
        reason = f["top_reasons"][0][0] if f["top_reasons"] else ""
        out.append(f"  {f['folder']:<44} {f['ready_pct']!s:>5}% {f['exact_pct']!s:>5}% {f['named_pct']!s:>5}%  "
                   f"{f['functions']:<5} {f.get('tier', ''):<11} {reason}")
    if "rows" in data:
        out.append(f"units most likely to behave slightly off ({data['units_ranked']} with signals; {data['weights']}):")
        for r in data["rows"]:
            flags = ("" if r["tested"] is not False else " UNTESTED") + ("" if r["recipe"] is not False else " no-recipe")
            out.append(f"{r['score']:>6}  [{r['tier']}] {r['path']} ({r['functions']} cited){flags}")
            out.extend(f"          - {action}" for action in r["actions"])
        uncited = data.get("uncited") or {}
        if uncited.get("units"):
            out.append(f"exact-tier units citing no original ({uncited['units']}): " + ", ".join(
                f"{r['path']} ({r['definition_lines']} lines)" for r in uncited["rows"][:10])
                       + (" ..." if uncited["units"] > 10 else ""))
        out.append(data["meaning"])
    return "\n".join(out)


def consts(data: dict) -> str:
    c = data["counts"]
    out = [f"constant audit {data['repo']}: {c.get('verified', 0)} verified against the original, {c.get('folded', 0)} "
           f"folded, {c.get('near', 0)} near-miss, {c.get('unsourced', 0)} unsourced, {c.get('trivial', 0)} trivial "
           f"skipped; {c.get('uncited_literals', 0)} literals in functions citing no original and "
           f"{c.get('not_judged_files', 0)} liberty/infrastructure files not judged"]
    for f in data["findings"][:60]:
        near = f" ~ original {f['near']}" if f["near"] else ""
        folded = f" = {f['folded']}" if f.get("folded") else ""
        out.append(f"{f['severity']:<7} {f['kind']:<9} {f['ref']}  {f['value']}{folded}{near}  [{f['tier']}]  "
                   f"{f['line'][:80]}")
    if len(data["findings"]) > 60:
        out.append(f"... {len(data['findings']) - 60} more (response_format=json, or narrow paths)")
    out.append(data["meaning"])
    return "\n".join(out)


def drift(data: dict) -> str:
    if data.get("baseline") in ("none", "accepted"):
        return f"drift: {data['note']} ({data['functions']} cited functions)"
    quiet = data.get("not_listed") or {}
    out = [f"decomp drift since {data['baseline']}: {len(data['changes'])} of {data['functions']} cited functions changed"
           + (" (not listed: " + ", ".join(f"{v} {k}" for k, v in quiet.items()) + ")" if quiet else "")]
    for r in data.get("reverify_files", [])[:15]:
        out.append(f"  re-verify {r['path']}  ({r['functions']} changed cited function(s))")
    for c in data["changes"][:20]:
        state = "" if c.get("ready", True) else "  [not ready: " + "; ".join(c.get("not_ready", []))[:120] + "]"
        out.append(f"  {c['address']} {c['name']}: {', '.join(c['changes'])}{state}  <- {', '.join(c['native'][:2])}")
    if len(data["changes"]) > 20:
        out.append(f"  ... {len(data['changes']) - 20} more (response_format=json)")
    out.append(data.get("note", ""))
    return "\n".join(out)


def tiers(data: dict) -> str:
    out = [f"fidelity tiers for {data['repo']}: " + ", ".join(f"{k} {v} files" for k, v in data["counts"].items())
           + f"; default {data.get('default', 'exact')}"]
    for t in data["tiers"]:
        out.append(f"  {t['tier'].upper():<15} {t['meaning']}\n  {'':<15} verify: {t.get('verify', '')}")
    if data["files"]:
        out.append("files:")
        out.extend(f"  {tier:<15} {path}" for path, tier in list(data["files"].items())[:200])
        if len(data["files"]) > 200:
            out.append(f"  ... {len(data['files']) - 200} more (response_format=json)")
        if data.get("outside_code_paths"):
            out.append(f"  {len(data['outside_code_paths'])} of these are outside the repo's code_paths: the port "
                       "tools do not judge them as ported code")
    else:
        out.append("folders:")
        for folder, counts in data["folders"].items():
            out.append(f"  {folder:<34} " + ", ".join(f"{k}:{v}" for k, v in counts.items()))
    return "\n".join(out)


def wait(data: dict) -> str:
    where = data["repo"] + (f" (worktree {data['worktree']})" if data.get("worktree") else "")
    waited = "; ".join(f"pid {b['pid']} {b['cmd'][:70]}" + (f" [holds {b['lock']}]" if b.get("lock") else "")
                       for b in data["waited_on"][:6])
    if data["idle"]:
        out = f"{where}: idle after {data['waited_s']} s" + (f" (waited on: {waited})" if waited else " (nothing was running)")
    else:
        busy = "; ".join(f"pid {b['pid']} {b['cmd'][:70]}" for b in data["still_busy"][:6])
        out = f"{where}: STILL BUSY after {data['waited_s']} s: {busy}"
    if data.get("locked_build"):
        out += f"\nadvisory only; build under the lock: {data['locked_build']}"
    return out


def unit(data: dict) -> str:
    batched = _batched(unit, data)
    if batched is not None:
        return batched
    if not data.get("found"):
        lines = [f"no unit for {data['query']}: {data.get('hint', '')}"]
        if data.get("candidates"):
            lines.append("  candidates: " + ", ".join(data["candidates"][:20]))
        return "\n".join(lines)
    f = data["functions"]
    out = [f"unit {data['unit']}: {f.get('exact', 0)}/{f.get('total', 0)} exact, {f.get('linked', 0)} linked, "
           f"{f.get('provisional', 0)} provisional names"]
    out.append("  sections: " + ", ".join(f"{s['section']} {s['start']}-{s['end']} (0x{s['size']:X})"
                                         for s in data["sections"]))
    for n in data["neighbours"]:
        gap = lambda g: "" if not g else f" +0x{g:X} unsplit"
        out.append(f"  {n['section']} neighbours: {n['before'] or '-'}{gap(n['gap_before'])} | "
                   f"{n['after'] or '-'}{gap(n['gap_after'])}")
    if data["pending"]:
        out.append(f"to match or name ({data['pending_total']}):")
        out.extend(f"  {_fn(r)}" for r in data["pending"][:20])
    shared = [d for d in data["data"] if d["refs_outside"]]
    out.append(f"data symbols: {data['data_total']}, {data['shared_data']} used by other units")
    for d in shared[:20]:
        out.append(f"  {d['address']} {d['name']} {d['section']} 0x{d['size']:X}: used by "
                   + ", ".join(f"{u} x{n}" for u, n in d["refs_outside"][:4]))
    if data["outgoing"]:
        out.append("this unit's code uses data owned elsewhere:")
    for o in data["outgoing"][:16]:
        more = f" (+{o['symbol_count'] - len(o['symbols'])})" if o["symbol_count"] > len(o["symbols"]) else ""
        out.append(f"  {o['unit']} {o['section']} x{o['refs']}{' [literal pool]' if o['literal'] else ''}: "
                   + ", ".join(o["symbols"]) + more)
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def blocked_units(data: dict) -> str:
    out = [f"{data['total']} unit(s) exact but not linked ({data['linked_units']} fully linked); fewest blockers first:"]
    for u in data["units"]:
        f = u["functions"]
        out.append(f"{u['unit']}: {f['exact']}/{f['total']} exact, {f['linked']} linked — " + "; ".join(u["reasons"]))
        for i in u["incoming"][:3]:
            out.append(f"  {i['symbol']} {i['section']} used by " + ", ".join(i["from"]))
        for lit in u["literals"][:2]:
            out.append(f"  literals in {lit['unit']} {lit['section']}: " + ", ".join(lit["symbols"]))
    if data["total"] > len(data["units"]):
        out.append(f"... {data['total'] - len(data['units'])} more (raise --limit)")
    out.append("`unit <name>` shows one in full. limits: " + data["limits"])
    return "\n".join(out)


def classes(data: dict) -> str:
    c = data.get("counts", {})
    out = [f"{data['classes']} classes recovered from the code ({data['named_tables']} with a __vt__ symbol)"]
    sections = [
        ("not_a_table", "__vt__ symbols that are not tables",
         lambda r: f"{r['address']} {r['symbol']} (starts {r['words']})"
                   + (f" -> the class's table is {r['real_table']}" if r.get("real_table") else "")),
        ("wrong_class", "filed under another class",
         lambda r: f"{r['address']} {r['current']} is {r['class']}'s {r['role']} -> {r['suggested']}"),
        ("spread", "one name per virtual slot",
         lambda r: f"{r['address']} {r['current']} overrides slot {r['slot']} = {r['slot_name']} -> {r['suggested']}"),
        ("role_named", "constructors and destructors named for a role",
         lambda r: f"{r['address']} {r['current']} is {r['class']}'s {r['role']} -> {r['suggested']}"),
        ("unnamed_class", "classes without a __vt__ symbol",
         lambda r: f"{r['vtable']} {r['class'] or '(no name evidence)'}: constructors {', '.join(n or '?' for n in r['constructors'][:3])}; destructor {r['destructor']}"
                   + (f" -> {r['suggested_symbol']}" if r['suggested_symbol'] else "")),
        ("slot_name_conflict", "virtual slots with competing names",
         lambda r: f"{r['root']} slot {r['slot']}: " + ", ".join(f"{n} x{k}" for n, k in r["names"].items())),
    ]
    for key, title, line in sections:
        rows = data.get(key) or []
        if not rows:
            continue
        out.append(f"{title} ({c.get(key, len(rows))}):")
        out.extend("  " + line(r) for r in rows)
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def classes_proof(data: dict) -> str:
    c = data["counts"]
    out = [f"{data['classes']} classes compiled: tables {c.get('table_equal', 0)} equal, "
           f"{c.get('table_differs', 0) + c.get('table_missing', 0)} different; pointer offsets "
           f"{c.get('pointer_equal', 0)} equal, {c.get('pointer_differs', 0)} different; sizes {c.get('size_equal', 0)} "
           f"equal, {c.get('size_differs', 0)} different"
           + (f"; {c['family_failed_to_compile']} families failed to compile" if c.get("family_failed_to_compile") else "")]
    for row in data["differences"]:
        detail = {k: v for k, v in row.items() if k not in ("class", "problem")}
        out.append(f"  {row['class']}: {row['problem']} {detail if detail else ''}".rstrip())
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def split_gaps(data: dict) -> str:
    out = ["split coverage by section:"]
    for s in data["sections"]:
        pct = 100 * s["claimed"] / s["size"] if s["size"] else 100
        out.append(f"  {s['section']} {s['start']}-{s['end']}: {pct:.1f}% claimed, {s['gaps']} gap(s), "
                   f"0x{s['unclaimed']:X} bytes unclaimed")
    out.append(f"unclaimed ranges with symbols: {data['total']} ({data['ready']} used by exactly one unit), "
               f"single-user first:")
    for r in data["ranges"]:
        users = ", ".join(f"{u} x{n}" for u, n in r["used_by"]) or "no decoded users"
        lead = f"-> {r['sole_user']}" if r["sole_user"] else f"used by {users}"
        out.append(f"  {r['section']} {r['start']}-{r['end']} (0x{r['size']:X}, {r['symbols']} symbols: "
                   f"{', '.join(r['names'][:3])}{'...' if r['symbols'] > 3 else ''}) {lead}")
    if data["total"] > len(data["ranges"]):
        out.append(f"... {data['total'] - len(data['ranges'])} more (--section or --limit)")
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def _bytes(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.2f}% ({part:,}/{whole:,})" if whole else "0% (0/0)"


def compiled(data: dict) -> str:
    if data.get("batch") is not None:
        return "\n\n".join(item["error"] if item.get("error") else compiled(item) for item in data["batch"])
    stale = f"\nnote: {data['stale']}" if data.get("stale") else ""
    return _compiled(data) + stale


def _compiled(data: dict) -> str:
    if "functions" in data:
        out = [f"unit {data.get('unit')}: {data['exact']}/{data['total']} functions identical to the original"
               + (f"; compiled-only: {', '.join(data['compiled_only'][:6])}" if data["compiled_only"] else "")
               + (f"; {len(data['gaps'])} splitter gap(s) not compiled (padding)" if data.get("gaps") else "")]
        for row in data["functions"]:
            if row.get("error"):
                out.append(f"  error   {row['function']}: {row['error']}")
            elif not row["exact"]:
                state = "missing" if row["missing"] else ("relocations only" if row["reloc_only"] else
                                                          f"{row['differences']} word(s) differ")
                out.append(f"  differs {row['function']} (0x{row['size']:X} bytes): {state}")
        return "\n".join(out)
    head = f"{data.get('address', '')} {data['function']} in {data.get('unit')}: "
    if data.get("missing"):
        return head + data["message"]
    if data["exact"]:
        return head + f"identical to the original (0x{data['size']:X} bytes, relocations included)"
    out = [head + f"{data['differences']} differing word(s); original 0x{data['size']:X} bytes, compiled "
                  f"0x{data['compiled_size']:X}" + (" — relocation targets only" if data["reloc_only"] else "")
           + (f" (report {data['report_match']:.2f}%)" if data.get("report_match") is not None else "")]
    for row in data["rows"]:
        note = ""
        if row.get("original_reloc") or row.get("compiled_reloc"):
            note = f"  reloc {row.get('original_reloc')} vs {row.get('compiled_reloc')}"
        if row.get("note"):
            note += f" ({row['note']})"
        out.append(f"  +0x{row['offset']:04X}  {row['original']} vs {row['compiled']}{note}")
    if data["differences"] > len(data["rows"]):
        out.append(f"  ... {data['differences'] - len(data['rows'])} more")
    if data.get("original_asm") and data.get("compiled_asm"):
        first = data.get("first_difference", 0)
        out.append(f"original | compiled from +0x{max(0, first - 8):X}:")
        pick = lambda lines: [l for l in lines if re.match(r"\s*[0-9a-f]+:", l)]
        a, b = pick(data["original_asm"]), pick(data["compiled_asm"])
        start = max(0, first // 4 - 2)
        for x, y in list(zip(a, b))[start:start + 16]:
            out.append(f"  {x.strip()[:60]:<60} | {y.strip()[:60]}")
    return "\n".join(out)


def candidate(data: dict) -> str:
    head = f"{data['address']} {data['function']} — attempt {data['attempt']}/{data['cap']}: "
    if not data.get("compiled"):
        return head + "does not compile\n" + data.get("errors", "")
    if data.get("exact"):
        out = [head + "IDENTICAL to the original" + ("" if data.get("bankable") else " (not bankable yet)")]
    else:
        body = compiled({**data, "unit": data.get("unit")})
        out = [head + body.split(": ", 1)[1].split("\n", 1)[0]] + body.split("\n")[1:]
    for item in data.get("debt", []):
        out.append(f"  debt: {item}")
    if data.get("bank_note"):
        out.append(f"  {data['bank_note']}")
    return "\n".join(out)


def objects_compare(data: dict) -> str:
    out = [f"objects vs saved copy {data['label']} ({data['saved']['time']}): {data['identical']} identical, "
           f"{data['changed_count']} changed, {len(data['new'])} new, {len(data['gone'])} gone"
           + (f"; {data['not_rebuilt']} not rebuilt since the copy" if data["not_rebuilt"] else "")
           + (" — OK" if data["ok"] else " — CHANGED")]
    for row in data["changed"]:
        out.append(f"  {row['object']}: " + "; ".join(row["problems"][:3]) + (f" (+{row['count'] - 3})" if row["count"] > 3 else ""))
    for path in data["gone"]:
        out.append(f"  gone: {path}")
    return "\n".join(out)


def score(data: dict) -> str:
    f, n, u, c, v, d = (data[k] for k in ("functions", "names", "units", "unit_cuts", "vtables", "data_ownership"))
    out = [f"functions: {f['starts_found']}% of the reference's starts found, {f['starts_correct']}% of the proposed "
           f"correct, {f['sizes_exact']}% sizes exact",
           f"names: {n['correct']:,} right, {n['wrong']:,} wrong of {n['proposed_named']:,} offered "
           f"({n['recall']}% of the reference's {n['reference_named']:,} real names)",
           f"units: {c['found']}% of the reference's boundaries found, {c['correct']}% of the proposed correct, "
           f"{c['inside_complete_units']:,} inside proven units; {u['exact']}% of units exact "
           f"({u['complete_exact']}% of proven ones)",
           f"vtables: {v['found']}% found, {v['named_correctly']}% named; data owned by the right unit: "
           f"{d['owned_by_the_right_unit']}%",
           "data objects: " + "; ".join(f"{s} {r['found']}%/{r['correct']}%" for s, r in data["data_objects"].items()
                                        if r["reference"]) + " (found/correct)"]
    return "\n".join(out)


def units_proposal(data: dict, limit: int = 30) -> str:
    c = data["counts"]
    named = ", ".join(f"{k} {v:,}" for k, v in c["named_by"].items())
    out = [f"{c['units']:,} units for {c['functions']:,} functions from {c['boundaries']:,} boundaries (named by {named}); "
           f"{c['data_ranges']:,} data ranges owned ({c['data_bytes']:,} bytes); {len(data['names'])} name proposals"]
    for unit in sorted(data["units"], key=lambda u: -u["functions"])[:limit]:
        out.append(f"  {unit['start']}-{unit['stop']}  {unit['functions']:>4} fn  {len(unit['data']):>3} data  "
                   f"{unit['unit']}  ({unit['named_by']})")
    if len(data["units"]) > limit:
        out.append(f"  ... {len(data['units']) - limit} more units (--json, or --splits FILE writes them all)")
    for name in data["names"][:12]:
        out.append(f"  name {name['address']} {name['current']} -> {name['proposed']}")
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def units_check(data: dict) -> str:
    out = [f"{data['folds_total']} folds, {data['splits_total']} splits, {data['claims_total']:,} data claims "
           f"({data['claimed_bytes']:,} bytes)"]
    if data["folds"]:
        out.append("folds (two units holding one unit's data):")
        out += [f"  {' + '.join(r['units'])}: {r['shared']} shared, e.g. {r['examples'][0]}" for r in data["folds"]]
    if data["splits"]:
        out.append("splits (one unit holding two copies of one literal):")
        out += [f"  {r['unit']}: {r['evidence']} pieces of evidence, boundary in {r['window'][0]}-{r['window'][1]} "
                f"({r['example']})" for r in data["splits"]]
    if data["claims"]:
        out.append("claims (data in no unit that one unit's code alone uses):")
        out += [f"  {r['address']} {r['object']} ({r['section']}, {r['size']} bytes) -> {r['unit']}"
                + (" [class table]" if r.get("vtable") else "") for r in data["claims"]]
    out.append("limits: " + data["limits"])
    return "\n".join(out)


def refs(data: dict) -> str:
    f = data.get("function")
    head = f"refs for {data['query']}" + (f" ({_fn(f)})" if f else "") + f": {data['total']} line(s); spellings " + \
        ", ".join(data["spellings"])
    out = [head]
    for row in data["rows"]:
        out.append(f"  {row['kind']:<11} {row['ref']}  {row['text'][:150]}")
    if data["total"] > len(data["rows"]):
        out.append(f"  ... {data['total'] - len(data['rows'])} more (--limit)")
    return "\n".join(out)


def progress(data: dict) -> str:
    m = data["overall"]
    out = [f"progress {data.get('target', '')} (report {data.get('report_age_h')}h old; objdiff counters)",
           f"  code matched {_bytes(m['matched_code'], m['total_code'])}, linked {_bytes(m['complete_code'], m['total_code'])}",
           f"  data matched {_bytes(m['matched_data'], m['total_data'])}, linked {_bytes(m['complete_data'], m['total_data'])}",
           f"  functions exact {m['matched_functions']:,}/{m['total_functions']:,}; "
           f"units linked {m['complete_units']:,}/{m['total_units']:,}"]
    for c in data.get("categories", []):
        x = c["measures"]
        out.append(f"  [{c['name']}] code {x['matched_code_percent']:.2f}% matched, {x['complete_code_percent']:.2f}% "
                   f"linked; data {x['matched_data_percent']:.2f}%; functions {x['matched_functions']:,}/{x['total_functions']:,}")
    if len(data.get("modules", [])) > 1:
        for mod in data["modules"]:
            x = mod["measures"]
            out.append(f"  module {mod['name']}: code {x['matched_code_percent']:.2f}% matched, "
                       f"{x['complete_code_percent']:.2f}% linked; {x['complete_units']}/{x['total_units']} units linked")
    out.append("  `zkit report --out build/progress` writes the browsable page")
    return "\n".join(out)


def delta(data: dict) -> str:
    base = data.get("baseline", {})
    out = [f"since {base.get('label', '?')} baseline {base.get('time', base.get('name', ''))}"
           f" (report {data.get('report_age_h')}h old): " + ("OK" if data.get("ok", data.get("regression_free")) else "REGRESSIONS")]
    for key in ("matched_functions", "matched_code", "complete_code", "matched_data", "complete_data"):
        v = data["metrics"][key]
        if v["delta"]:
            out.append(f"  {key}: {v['before']:,} -> {v['after']:,} ({v['delta']:+,})")
    if not any(data["metrics"][k]["delta"] for k in data["metrics"]):
        out.append("  no counter changed")
    for failure in data["failures"]:
        out.append(f"  FAIL {failure}")
    for label, key in (("lost match", "regressed"), ("unlinked", "unlinked"), ("new exact", "new_exact"),
                       ("newly linked", "newly_linked")):
        rows = data.get(key, [])
        for row in rows[:12]:
            out.append(f"  {label}: {row['address']} {row['name']}")
        if len(rows) > 12:
            out.append(f"  ... {len(rows) - 12} more {label}")
    for key in ("exact_data_lost", "linked_data_lost", "data_coverage_lost"):
        for row in data.get(key, [])[:8]:
            out.append(f"  {key}: {row['module']} {row['section']} {row['address']} +{row['size']}")
    if data.get("renamed"):
        out.append(f"  {len(data['renamed'])} function(s) renamed at the same address")
    return "\n".join(out)


def quality(data: dict) -> str:
    out = [f"source quality of {data['repo']} at {data['revision']}: {data['total']:,} items of decompiler debt in "
           f"{data['files_with_debt']:,} of {data['files']:,} files ({', '.join(data['paths'])})"]
    for row in sorted(data["counts"], key=lambda r: -r["count"]):
        if row["count"]:
            out.append(f"  {row['count']:>9,}  {row['label']}")
    if data.get("worst_files"):
        out.append("most debt:")
        for row in data["worst_files"]:
            top = ", ".join(f"{k} {v}" for k, v in row["top"])
            out.append(f"  {row['total']:>6,}  {row['path']}  ({top})")
    return "\n".join(out)


def quality_compare(data: dict) -> str:
    t = data["total"]
    out = [f"source quality {data['before']} -> {data['after']}: {t['before']:,} -> {t['after']:,} ({t['delta']:+,})"]
    for row in sorted(data["rows"], key=lambda r: r["delta"]):
        if row["delta"] or row["after"]:
            out.append(f"  {row['before']:>9,} -> {row['after']:>9,} ({row['delta']:+,})  {row['label']}")
    if data["worse"]:
        out.append("WORSE: " + ", ".join(r["label"] for r in data["worse"]))
    return "\n".join(out)


def hygiene(data: dict) -> str:
    out = [f"hygiene {data['repo']}: " + ("OK" if data["ok"] else "problems found")]
    commits = data.get("commits")
    if commits:
        out.append(f"commits ({commits['checked']} checked, identity {commits['identity'] or 'not configured'}): "
                   f"{len(commits['problems'])} with problems")
        for row in commits["problems"][:10]:
            out.append(f"  {row['commit']} {row['subject'][:60]!r}: " + "; ".join(row["problems"]))
        if len(commits["problems"]) > 10:
            out.append(f"  ... {len(commits['problems']) - 10} more")
    files = data.get("files")
    if files:
        out.append(f"tracked files: {files['tracked']:,} ({files['documents']} documents, {files['scripts']} scripts)"
                   + (": " + ", ".join(f"{k} {v}" for k, v in sorted(files["counts"].items())) if files["counts"] else ""))
        by_kind: dict[str, list] = {}
        for f in files["findings"]:
            by_kind.setdefault(f["kind"], []).append(f)
        for kind, rows in by_kind.items():
            for f in rows[:6]:
                out.append(f"  {f['severity']:<7} {kind:<16} {f['path']}: {f['message']}")
            if len(rows) > 6:
                out.append(f"  ... {len(rows) - 6} more {kind}")
    for row in (files or {}).get("history", []):
        out.append(f"  history  {row['path']} is in {row['commits']} commit(s) since {row['first']}: it stays in every "
                   "clone; keep agent files local (.git/info/exclude)")
    tree = data.get("tree")
    if tree:
        out.append("working tree: " + ("clean" if not tree["problems"] else "; ".join(tree["problems"])))
        for d in tree["dirty"][:8]:
            out.append(f"  {d['state']:<2} {d['path']}")
    return "\n".join(out)
