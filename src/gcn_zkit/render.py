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
            out.append(f"- handoff {note['time']} ({note['author']}): {note['text'][:400]}")
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
                       + " files — EXACT unless listed otherwise (`gcn-zkit tiers`)")
        ground = repo.get("grounding")
        if ground:
            weak = ", ".join(f"{w['folder']} {w['exact_pct']}%" for w in ground["weakest"])
            out.append(f"- grounding: cited originals {ground['total'].get('exact_pct')}% exact in the decomp; "
                       f"weakest: {weak} (`gcn-zkit grounding`)")
        if repo.get("drift"):
            d = repo["drift"]
            out.append(f"- decomp drift: {d['changed']} cited function(s) changed since {d['since']}; re-verify "
                       + ", ".join(f"{r['path']}({r['functions']})" for r in d["files"]) + " (`gcn-zkit drift`)")
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
                out.append(f"- include audit: `gcn-zkit architecture {name} <paths>` ({audits['architecture_rules']} rules)")
            for inventory in audits['coverage_inventories']:
                out.append(f"- inventory audit: `gcn-zkit coverage {name} {inventory['name']}` — {inventory['boundary']}")
        if repo.get("port_guidance"):
            out.append('- native-port architecture and completion: ' + repo['port_guidance'])
        if repo.get("rules"):
            out.append("- rules:")
            out.extend(f"  {i}. {rule}" for i, rule in enumerate(repo["rules"], 1))
        if repo.get("finish"):
            out.append("- finish gate:")
            out.extend(f"    {c}" for c in repo["finish"])
        if repo.get("lessons"):
            out.append("- lessons (`gcn-zkit lessons <id>`): " + "; ".join(l["id"] for l in repo["lessons"]))
    demand = data.get("port_demand")
    if demand:
        t = demand["totals"]
        out.append(f"\n## Port waiting on decomp — {t.get('cited_functions')} cited funcs, {t.get('exact')} exact, "
                   f"{t.get('provisional_name')} provisional names (`gcn-zkit demand`)")
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
            out.append(f"- last handoff {note['time']} ({note['author']}): {note['text'][:300]}")
        nxt = repo.get("next")
        if nxt:
            own = (repo.get("lane_yield_last3") or {}).get(nxt["lane"])
            drained = own is not None and own.split("/")[0] == "0"
            out.append(f"- router lane `{nxt['lane']}`" + (f" DRAINED ({own} kept, last 3 runs)" if drained else
                                                         f" (yield {own})" if own else ""))
        if repo.get("grounding"):
            g = repo["grounding"]
            out.append(f"- grounding: cited originals {g['total'].get('exact_pct')}% exact; weakest "
                       + ", ".join(f"{w['folder']} {w['exact_pct']}%" for w in g["weakest"][:3]))
        if repo.get("drift"):
            out.append(f"- decomp drift: {repo['drift']['changed']} cited function(s) to re-verify (`zkit drift`)")
        if repo.get("required_reading"):
            out.append("- required reading: " + "; ".join(
                d['reference'] + (" [MISSING]" if not d['exists'] else "") for d in repo['required_reading']))
        if repo.get('port_guidance'):
            out.append('- native port: shared owners and interfaces; composed behavior; automated import/dependency '
                       'discovery; authored data rather than identity/shape guesses. Complete the requested live '
                       'system and verify its boundary. Matching decomp keeps original layout/compiler constraints.')
        out.append(f"- rules, finish gate, status, lessons: `zkit_brief {name}` (MCP) or `gcn-zkit brief {name}`")
    demand = data.get("port_demand")
    if demand:
        t = demand["totals"]
        out.append(f"\n## Port waiting on decomp — {t.get('cited_functions')} cited, {t.get('exact')} exact, "
                   f"{t.get('provisional_name')} provisional names (`zkit demand`)")
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
        return "ambiguous — candidates:\n" + "\n".join(f"  {_fn(c)}" for c in data["candidates"])
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
        out.append(f"Ghidra's C next to m2c: gcn-zkit decompile {f['address']} (MCP zkit_decompile)")
    if data.get("body"):
        lo, hi = data["body_lines"]
        out.append(f"body ({f.get('source')}:{lo}-{hi}):")
        out.append(data["body"])
    return "\n".join(out)


def port_plan(data: dict) -> str:
    if data.get("batch") is not None:
        return "\n\n".join(port_plan(item) for item in data["batch"])
    if not data.get("nodes"):
        return lookup(data)
    root = dict(data["root"], native_files=None)
    out = [f"port plan for {_fn(root)} — " + ", ".join(f"{k}:{v}" for k, v in data["summary"].items())]
    for node in data["nodes"]:
        indent = "  " * node["depth"]
        files = f" -> {', '.join(node['native_files'][:3])}" if node["native_files"] else ""
        if node.get("native_docs"):
            files += f" (docs:{node['native_docs']})"
        indirect = f", {node['indirect_calls']} bctrl" if node.get("indirect_calls") else ""
        out.append(f"{indent}[{node['action']}] {node['address']} {node.get('demangled') or node['name']} "
                   f"({status_word(node)}, {node['original_callers']} callers{indirect}){files}")
    if data.get("truncated_nodes"):
        out.append(f"... {data['truncated_nodes']} more nodes not expanded (lower depth or plan a callee)")
    out.append("legend: " + "; ".join(f"{k} = {v}" for k, v in data["legend"].items()))
    return "\n".join(out)


def demand(data: dict) -> str:
    t = data["totals"]
    out = [f"port cites {t.get('cited_functions')} decomp functions: {t.get('exact')} exact, {t.get('linked')} linked, "
           f"{t.get('provisional_name')} provisional names; {data['unresolved_native_addresses']} cited addresses "
           "are not functions (data/typos — `gcn-zkit cites`)"]
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


def check(data: dict) -> str:
    out = [f"check {data['repo']} vs {data['base']}: " + ", ".join(f"{k}={v}" for k, v in data["stats"].items())
           + (" — OK" if data["ok"] else " — ERRORS")]
    for f in data["findings"][:60]:
        detail = f" {f.get('address', '')} {f.get('name', '')}".rstrip()
        out.append(f"{f['severity']:<7} {f['rule']:<20} {f['ref']}{detail}: {f['message']}")
    if len(data["findings"]) > 60:
        out.append(f"... {len(data['findings']) - 60} more (use --json)")
    return "\n".join(out)


def reuse(data: dict) -> str:
    out = [f"reuse audit for {data['repo']}"]
    if data["identical_helpers"]:
        out.append("identical helper bodies defined in several files (share one):")
        for d in data["identical_helpers"]:
            out.append(f"  {d['name']} x{d['copies']}: {', '.join(d['places'][:4])}")
    if data["same_name_helpers"]:
        out.append("same helper name in many files (check for drifted copies):")
        for d in data["same_name_helpers"][:15]:
            out.append(f"  {d['name']} in {d['files']} files: {', '.join(d['examples'][:3])}")
    sites = data["enumeration_sites"]
    if sites["terms"]:
        out.append(f"files naming several of {sites['terms']} ({sites['files']}) — central sites a new variant edits:")
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
        out.append(f"handoff {note['time']} [{note['repo']}] {note['author']}: {note['text'][:300]}")
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
        if r.get("data"):
            s = r.get("symbol")
            out.append(f"{r.get('address') or r['query']} {s['name'] + ('+0x%X' % s['offset'] if s['offset'] else '') if s else '(no symbol)'}"
                       + (f" {s['section']} size 0x{s['size']:X}" if s else "") + "  [data]")
        else:
            out.append(f"{r['address']} {r.get('demangled') or r['name']} size 0x{r['size']:X} [{status_word(r)}] {r.get('unit') or ''}")
    if data.get("truncated"):
        out.append(f"... {data['truncated']} more (total {data['total']}; narrow with --regex/--unit/--range or raise --limit)")
    return "\n".join(out) or "no matches"


def xrefs(data: dict) -> str:
    batched = _batched(xrefs, data)
    if batched is not None:
        return batched
    s = data.get("symbol")
    out = [f"xrefs to {data['address']}" + (f" {s['name']} ({s['section']} size 0x{s['size']:X})" if s else "")
           + f": {data.get('total', len(data['code']))} code refs " + str(data["kinds"]) + f", {len(data['data'])} data pointers"]
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
        out.append(f"  pointer at {ref['holder']} {ref.get('symbol', '')}+0x{ref.get('offset', 0):X}")
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


def impact(data: dict) -> str:
    if not data.get("files"):
        return data.get("note", "nothing changed")
    out = [f"impact of {len(data['changed'])} changed file(s) in {data['repo']}:"]
    for f in data["files"]:
        t = f["tests"]
        out.append(f"  {f['file']}: {len({c.rpartition('.')[0] for c in f['consumers']})} direct consumer(s), tests direct {t['direct']} / near {t['near']} "
                   f"(+{t['broad']} via hub headers)")
        stems: dict[str, list[str]] = {}
        for consumer in f["consumers"]:
            stem, _, ext = consumer.rpartition(".")
            stems.setdefault(stem, []).append(ext)
        for stem, exts in list(stems.items())[:10]:
            out.append(f"      consumer {stem}.{'/'.join(sorted(exts))}")
        if len(stems) > 10:
            out.append(f"      ... {len(stems) - 10} more consumers")
    for tier in ("direct", "near"):
        for label, names in data["groups"].get(tier, {}).items():
            total = data["totals"][f"{tier}/{label}"]
            unknown = total.get("unknown_costs", 0)
            out.append(f"{tier}/{label}: {len(names)} tests (~{total['serial_seconds']} s recorded"
                       + (f", {unknown} unmeasured" if unknown else "") + f"): {', '.join(names[:12])}"
                       + (" ..." if len(names) > 12 else ""))
    deferred = data["totals"].get("deferred")
    if deferred:
        out.append(f"budget {deferred['budget_seconds']:g} s: {deferred['tests']} near test(s) deferred "
                   f"(~{deferred['serial_seconds']} s recorded" + (f", {deferred['unknown_costs']} unmeasured" if
                   deferred["unknown_costs"] else "") + "); run them for a shared or risky change")
    if data["commands"]:
        out.append("run (direct first, then near; deferred last, if at all):")
        order = lambda k: (0 if k.startswith("direct") else 2 if k == "deferred" else 1, k)
        for key in sorted(data["commands"], key=order):
            targets = data.get("build_targets", {}).get(key, [])
            if targets:
                out.append(f"  # {key} build targets (optional parallel prebuild): " + ", ".join(targets))
            out.append(f"  # {key}\n  {data['commands'][key]}")
    if data["untested_files"]:
        out.append("NO direct/near mapping: " + ", ".join(data["untested_files"])
                   + " — inspect the owning tests/recipes; library-only coverage may be missed.")
    out.append(f"broad: {data['totals']['broad']['tests']} tests reach these files only through hub headers.")
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
    out.append(f"unresolved/external includes: {len(data['unresolved_includes'])}; macro includes: {data['macro_includes']}")
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
    out = [f"test plan for {data['repo']}: {len(data['selected'])} selected checks, "
           f"{len(data['fixture_tests'])} required setup/cleanup tests (nothing executed)"]
    for key in ('missing', 'disabled', 'unresolved_fixtures'):
        if data[key]:
            out.append(f"BLOCKED {key}: " + ', '.join(data[key]))
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
    out = [f"grounding of {data['repo']} {', '.join(data['scope'])}: {t.get('cites', 0)} citations in "
           f"{data['files_with_cites']} files; cited originals {t.get('exact_pct')}% byte-exact, {t.get('named_pct')}% "
           f"semantically named, {t.get('unmatched', 0)} unmatched, {t.get('not_function', 0)} not functions",
           "weakest folders (exact% / named% / cites):"]
    for f in data["folders"]:
        out.append(f"  {f['folder']:<44} {f['exact_pct']!s:>5}% {f['named_pct']!s:>5}%  {f['cites']:<5} {f.get('tier', '')}")
    out.append("files citing the most unmatched originals (recover these in the decomp first):")
    for w in data["weakest_files"]:
        out.append(f"  {w['path']} ({w['unmatched']}): {', '.join(w['examples'][:3])}")
    return "\n".join(out)


def consts(data: dict) -> str:
    c = data["counts"]
    out = [f"constant audit {data['repo']}: {c.get('verified', 0)} verified against the original, {c.get('near', 0)} near-miss, "
           f"{c.get('unsourced', 0)} unsourced, {c.get('trivial', 0)} trivial skipped; "
           f"{c.get('not_judged_files', 0)} liberty/infrastructure files not judged"]
    for f in data["findings"][:60]:
        near = f" ~ original {f['near']}" if f["near"] else ""
        tag = f["tier"]
        out.append(f"{f['severity']:<7} {f['kind']:<9} {f['ref']}  {f['value']}{near}  [{tag}]  {f['line'][:80]}")
    if len(data["findings"]) > 60:
        out.append(f"... {len(data['findings']) - 60} more (--json)")
    return "\n".join(out)


def suspects(data: dict) -> str:
    out = [f"likely slightly-off behavior in {data['repo']} ({data['files_ranked']} files with signals; {data['weights']}):"]
    for r in data["rows"]:
        flags = ("" if r["tested"] is not False else " UNTESTED") + ("" if r["recipe"] is not False else " no-recipe")
        out.append(f"{r['score']:>5}  [{r['tier']}] {r['path']}{flags}")
        for action in r["actions"]:
            out.append(f"         - {action}")
    return "\n".join(out)


def drift(data: dict) -> str:
    if data.get("baseline") in ("none", "accepted"):
        return f"drift: {data['note']} ({data['functions']} cited functions)"
    quiet = data.get("not_listed") or {}
    out = [f"decomp drift since {data['baseline']}: {len(data['changes'])} of {data['functions']} cited functions changed"
           + (" (not listed: " + ", ".join(f"{v} {k}" for k, v in quiet.items()) + ")" if quiet else "")]
    for r in data.get("reverify_files", [])[:15]:
        out.append(f"  re-verify {r['path']}  ({r['functions']} cited function(s) now exact or changed)")
    for c in data["changes"][:20]:
        out.append(f"  {c['address']} {c['name']}: {', '.join(c['changes'])}  <- {', '.join(c['native'][:2])}")
    if len(data["changes"]) > 20:
        out.append(f"  ... {len(data['changes']) - 20} more (--json)")
    out.append("after re-checking: gcn-zkit drift --accept")
    return "\n".join(out)


def tiers(data: dict) -> str:
    out = [f"fidelity tiers for {data['repo']}: " + ", ".join(f"{k} {v} files" for k, v in data["counts"].items())]
    for t in data["tiers"]:
        out.append(f"  {t['tier'].upper():<15} {t['meaning']}\n  {'':<15} verify: {t.get('verify', '')}")
    if data["files"]:
        out.append("files:")
        out.extend(f"  {tier:<15} {path}" for path, tier in data["files"].items())
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
    out = [f"class evidence from vtables: {c.get('consistent', 0)} consistent, "
           f"{c.get('contradicted_strong', 0)} strong + {c.get('contradicted_weak', 0)} weak contradictions, "
           f"{c.get('unclaimed', 0)} unclaimed single-class virtuals"]
    if data.get("contradicted"):
        out.append(f"named class not among the vtables holding it ({data['contradicted_total']}):")
    for r in data.get("contradicted", []):
        tables = ", ".join(r["classes"][:4]) + (f" +{r['class_count'] - 4}" if r["class_count"] > 4 else "")
        unnamed = f" +{r['unnamed_tables']} unnamed" if r["unnamed_tables"] else ""
        out.append(f"  [{r['strength']}] {r['address']} {r['name']} [{r['status']}] in {tables}{unnamed} -> {r['suggestion']}")
    if data.get("unclaimed"):
        out.append(f"no class in the name, one named class's vtables ({data['unclaimed_total']}):")
    for r in data.get("unclaimed", []):
        out.append(f"  {r['address']} {r['name']} [{r['status']}] -> {r['suggestion']}")
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
