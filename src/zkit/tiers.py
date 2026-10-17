"""Fidelity tiers: how faithful each native path must be, from the manifest.

The owner decides the tiers (repository `fidelity_tiers`, first pattern wins).
Tools use them to decide what to demand: citations and verified constants in
`exact` code, observable-behavior checks in `equivalent` code, and nothing
original-derived in `liberty`/`infrastructure` code.
"""

from __future__ import annotations

import collections
import re
from functools import lru_cache

from .project import Project, under as _under

DEFAULT = {"tier": "exact", "meaning": "No tiers configured: everything is held to the original.", "verify": ""}
JUDGED = ("exact", "equivalent")          # tiers whose behavior must follow the original
WEIGHT = {"exact": 1.5, "equivalent": 1.0, "liberty": 0.2, "infrastructure": 0.3}


@lru_cache(maxsize=64)
def _compiled(manifest: str, repo: str, spec: tuple) -> list:
    return [(re.compile(pattern), tier) for pattern, tier in spec]


def tiers(project: Project, repo: str) -> list[dict]:
    return project.config["repositories"][repo].get("fidelity_tiers", [])


def tier_of(project: Project, repo: str, path: str) -> str:
    rows = tiers(project, repo)
    if not rows:
        legacy = project.config["repositories"][repo].get("checks", {}).get("citation_required_paths")
        return "exact" if not legacy or re.search(legacy, path) else "liberty"
    for pattern, tier in _compiled(str(project.path), repo, tuple((r["pattern"], r["tier"]) for r in rows)):
        if pattern.search(path):
            return tier
    return "infrastructure"


def describe(project: Project, repo: str, tier: str) -> dict:
    for row in tiers(project, repo):
        if row["tier"] == tier:
            return row
    return DEFAULT | {"tier": tier}


def summary(project: Project, repo: str, paths: list[str] | None = None) -> dict:
    """Files per tier and per folder, so the owner can audit the mapping."""
    from .index import connect, refresh
    from .bridge import _is_code
    refresh(project, [repo])
    db = connect(project)
    files = [r[0] for r in db.execute("SELECT path FROM files WHERE repo=?", (repo,)) if _is_code(project, r[0])]
    if paths:
        files = [f for f in files if _under(f, paths) or f in paths]
    counts = collections.Counter()
    folders: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    per_file = {}
    for rel in sorted(files):
        tier = tier_of(project, repo, rel)
        per_file[rel] = tier
        counts[tier] += 1
        folders["/".join(rel.split("/")[:2])][tier] += 1
    return {"repo": repo, "counts": dict(counts),
            "folders": {k: dict(v) for k, v in sorted(folders.items())},
            "files": per_file if paths else {},
            "tiers": [describe(project, repo, t) for t in ("exact", "equivalent", "liberty", "infrastructure")
                      if any(r["tier"] == t for r in tiers(project, repo))]}
