"""Read objdiff evidence without treating a name or a match as full parity."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .index import address_text
from .project import Project, digest


def address(value: str | int) -> int:
    if isinstance(value, bool):
        raise ValueError("Address must be an integer or 0x-prefixed hexadecimal")
    if isinstance(value, str):
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", value):
            raise ValueError("String addresses must use 0x-prefixed hexadecimal")
        value = int(value, 16)
    if not isinstance(value, int) or not 0 <= value < 2**32:
        raise ValueError("Address must fit unsigned 32 bits")
    return value


def read_report(project: Project, target_name: str) -> tuple[dict, dict]:
    target = project.target(target_name)
    if not target.get("report"):
        raise ValueError(f"Target {target_name} has no objdiff report adapter")
    path = project.file(target["repository"], target["report"])
    raw = path.read_bytes()
    return json.loads(raw), {"reference": f"{target['repository']}:{target['report']}",
                             "sha256": hashlib.sha256(raw).hexdigest(),
                             "build_binding": "unattested; no source-to-build receipt"}


def target_identity(project: Project, name: str) -> dict:
    target = project.target(name)
    result = {"target": name, "module": target["module"],
              "revision": target.get("revision"), "platform": target.get("platform")}
    if not target.get("original"):
        return result | {"verified": False, "reason": "No original binary configured"}
    path = project.file(target["repository"], target["original"])
    if not path.is_file():
        return result | {"verified": False, "reason": "Original binary is missing"}
    actual = digest(path)
    expected = target.get("sha256")
    return result | {"sha256": actual, "expected_sha256": expected,
                     "verified": bool(expected) and actual == expected,
                     "reason": None if expected == actual else "Missing or mismatched expected SHA-256"}


def report_status(project: Project, target_name: str) -> dict[str, Any]:
    report, provenance = read_report(project, target_name)
    target = project.target(target_name)
    path = project.file(target["repository"], target["report"])
    newer = []
    for relative in project.config["repositories"][target["repository"]].get("build_inputs", []):
        base = project.file(target["repository"], relative)
        candidates = base.rglob("*") if base.is_dir() else [base]
        for candidate in candidates:
            if candidate.is_file() and candidate.stat().st_mtime_ns > path.stat().st_mtime_ns:
                newer.append(candidate.relative_to(project.root(target["repository"])).as_posix())
    return {"provenance": provenance, "measures": report.get("measures", {}),
            "measures_scope": "Whole report; may include more modules than the selected target",
            "newer_input_count": len(newer), "newer_inputs": sorted(newer)[:20],
            "freshness": "stale-by-mtime" if newer else "no-newer-inputs; build binding still unattested",
            "authority": "Numbers describe this report; neither fresh compilation nor DOL hash was rerun"}


def lookup(project: Project, target_name: str, value: str | int) -> dict[str, Any]:
    pc = address(value)
    target = project.target(target_name)
    report, provenance = read_report(project, target_name)
    found = []
    for unit in report.get("units", []):
        metadata = unit.get("metadata", {})
        if metadata.get("module_name") != target["module"]:
            continue
        for function in unit.get("functions", []):
            info = function.get("metadata", {})
            if info.get("virtual_address") is None:
                continue
            start = int(info["virtual_address"])
            size = int(function.get("size", 0))
            if start <= pc < start + size:
                source = metadata.get("source_path")
                found.append({
                    "address": address_text(start), "offset": pc - start, "size": size,
                    "name": function["name"], "demangled_name": info.get("demangled_name"),
                    "unit": unit["name"], "source": source,
                    "source_exists": bool(source) and project.file(target["repository"], source).is_file(),
                    "byte_exact_in_report": function.get("fuzzy_match_percent") == 100,
                    "match_percent": function.get("fuzzy_match_percent"),
                    "unit_complete_in_report": metadata.get("complete", False),
                    "semantic_name_verified": None, "class_header_verified": None,
                })
    if len(found) > 1:
        raise ValueError(f"Ambiguous overlapping report functions at {value} in {target['module']}")
    return {"identity": target_identity(project, target_name), "report": provenance,
            "function": found[0] if found else None,
            "limits": ["A report match does not prove current build, final linking, semantic ownership or runtime parity",
                       "Names remain provisional until caller, vtable or typed-this evidence confirms them"]}


def read_document(project: Project, reference: str, start: int = 1, lines: int = 80) -> dict:
    if start < 1 or not 1 <= lines <= 200:
        raise ValueError("Use start >= 1 and 1..200 lines")
    repository, _, relative = reference.partition(":")
    path = project.reference(reference)
    repo = project.config["repositories"][repository]
    permitted = any(path == project.file(repository, root) or
                    path.is_relative_to(project.file(repository, root))
                    for root in repo.get("search_paths", []) + repo.get("required_docs", []))
    if not permitted or path.suffix.lower() not in {".md", ".txt", ".c", ".h", ".cpp", ".hpp", ".json", ".py"}:
        raise ValueError("Document is outside configured text evidence paths")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Document exceeds the 2 MiB read limit")
    raw = path.read_bytes()
    content = raw.decode("utf-8").splitlines()
    return {"reference": reference, "sha256": hashlib.sha256(raw).hexdigest(),
            "start": start, "total_lines": len(content),
            "text": "\n".join(f"{i}: {line}" for i, line in enumerate(content[start-1:start-1+lines], start))}


def search(project: Project, query: str, limit: int = 10) -> dict:
    terms = query.lower().split()
    if not 1 <= len(terms) <= 8 or not 1 <= limit <= 30 or len(query) > 256:
        raise ValueError("Use 1..8 plain search terms, <=256 characters, and limit 1..30")
    results, skipped, seen = [], 0, set()
    suffixes = {".md", ".txt", ".c", ".h", ".cpp", ".hpp", ".json", ".py"}
    for repository, config in project.config["repositories"].items():
        for relative in config.get("search_paths", []):
            base = project.file(repository, relative)
            candidates = base.rglob("*") if base.is_dir() else [base]
            for path in candidates:
                if path in seen or not path.is_file() or path.suffix.lower() not in suffixes:
                    continue
                seen.add(path)
                if path.is_symlink() or not path.resolve().is_relative_to(project.root(repository)):
                    continue
                if path.stat().st_size > 2 * 1024 * 1024:
                    skipped += 1
                    continue
                raw = path.read_bytes()
                try:
                    content = raw.decode("utf-8")
                except UnicodeDecodeError:
                    skipped += 1
                    continue
                name = path.relative_to(project.root(repository)).as_posix()
                if not all(term in content.lower() or term in name.lower() for term in terms):
                    continue
                content_lines = content.splitlines()
                best = max(range(len(content_lines)),
                           key=lambda i: sum(term in content_lines[i].lower() for term in terms), default=0)
                score = sum(term in name.lower() for term in terms) * 10
                score += sum(term in (content_lines[best].lower() if content_lines else "") for term in terms)
                results.append({"reference": f"{repository}:{name}", "line": best + 1,
                                "sha256": hashlib.sha256(raw).hexdigest(), "score": score,
                                "excerpt": "\n".join(content_lines[max(0,best-1):best+4])[:1200]})
    results.sort(key=lambda row: (-row["score"], row["reference"]))
    return {"query": query, "total_hits": len(results), "results": results[:limit],
            "skipped_large_or_non_utf8": skipped,
            "scope": "Current configured text paths, all terms within a file; no persisted index"}
