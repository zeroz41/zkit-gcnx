"""Repository hygiene: what a session must not leave behind or commit.

The rules are the owner's, set per repository in the manifest's `hygiene` block; the defaults are strict:
- commits: one short line in plain language, the project's own identity, no AI co-author or generated trailers;
- tracked files: no agent-only documentation, no dated session narratives, no scripts nothing uses, no original
  game files, keys or large binaries, no local absolute paths;
- working tree: nothing uncommitted, no stray branches, stashes or worktrees at the end of a session.
Read-only: it reports, it never deletes or rewrites anything.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from .project import Project

AI_IDENTITY = re.compile(r"\b(claude|anthropic|codex|openai|chatgpt|copilot|gpt-\d|gemini|cursor|devin|aider)\b|"
                         r"noreply@(anthropic|openai)\.com", re.I)
TRAILER = re.compile(r"^(co-authored-by|generated-by|signed-off-by-ai)\s*:", re.I | re.M)
GENERATED_LINE = re.compile(r"generated with \[?(claude|codex)|🤖", re.I)
AGENT_DOCS = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules", "CODEX.md", "COPILOT.md")
AGENT_DIRS = (".claude/", ".codex/", ".agents/", ".cursor/", ".aider", ".gemini/")
AGENT_NAME = re.compile(r"(?i)(^|[/_-])(agent|worker|brief|handoff|prompt|session|subagent|llm|ai[-_]?notes?)"
                        r"([-_.]|s?\.md$)")
DATE_NAME = re.compile(r"(20\d\d)[-_]?(0[1-9]|1[0-2])[-_]?([0-2]\d|3[01])")
NARRATIVE = re.compile(r"(?im)^\s*(?:#+\s*)?(?:later|then|last|this|previous|next)\s+(?:on\s+)?"
                       r"(?:session|wave|round|pass)\b|\bsession\s+\d+\b|\(\s*20\d\d-\d\d-\d\d\s*\)|"
                       r"^#+.*\b20\d\d-\d\d-\d\d\b")
LOCAL_PATH = re.compile(r"(?<![\w.])(/home/[a-z_][\w-]*/|/Users/[\w.-]+/|/tmp/claude-|[A-Za-z]:\\Users\\)")
DOC_SUFFIXES = (".md", ".txt", ".rst", ".adoc")
SCRIPT_SUFFIXES = (".py", ".sh", ".ps1", ".bat", ".js", ".ts", ".rb", ".pl")
TEXT_SUFFIXES = DOC_SUFFIXES + SCRIPT_SUFFIXES + (".json", ".toml", ".yml", ".yaml", ".cmake", ".txt", ".ninja",
                                                   ".cfg", ".ini", ".c", ".cpp", ".h", ".hpp", ".in", "")
ORIGINAL_FILES = ("*.dol", "*.rel", "*.iso", "*.gcm", "*.rvz", "*.wbfs", "*.ciso", "*.nso", "*.nro", "*.nsp",
                  "*.xci", "*.nca", "*.keys", "prod.keys", "title.keys", "*.elf", "*.szs", "*.arc", "*.afs",
                  "*.bfsar", "*.sarc")

DEFAULTS: dict[str, Any] = {
    "identity": None,           # "Name <email>"; default: the repository's git config
    "subject_max": 72,
    "body": False,              # commit bodies allowed?
    "agent_docs": "forbid",     # or "allow" for a private working repository
    "dated_docs": "forbid",
    "max_docs": 12,             # markdown files outside third-party folders before it counts as bloat
    "script_roots": ["tools", "scripts"],
    "script_users": [],         # extra files whose references keep a script alive (build entry points)
    "ignore": ["third_party/", "libs/", "vendor/", "extern/", "subprojects/", "node_modules/"],
    "forbidden_files": list(ORIGINAL_FILES),
    "allowed_files": [],
    "max_file_kb": 2048,
}


def policy(project: Project, repo: str) -> dict[str, Any]:
    return {**DEFAULTS, **project.config["repositories"][repo].get("hygiene", {})}


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=60)
    if result.returncode:
        raise ValueError(f"git {' '.join(args[:2])} failed in {root}: {result.stderr.strip()[:200]}")
    return result.stdout


def _identity(root: Path, configured: str | None) -> str | None:
    if configured:
        return configured
    try:
        name = _git(root, "config", "user.name").strip()
        email = _git(root, "config", "user.email").strip()
    except ValueError:
        return None
    return f"{name} <{email}>" if name and email else None


def _generated_subject(subject: str) -> bool:
    """A tool's summary pasted as a subject: many counts and separators rather than a sentence."""
    numbers = len(re.findall(r"\d+", subject))
    separators = subject.count(",") + subject.count(";") + subject.count(":")
    return numbers >= 5 and separators >= 3 or "->" in subject and numbers >= 4


def judge(rules: dict, wanted: str | None, subject: str, body: str, people: dict[str, str]) -> list[str]:
    """Problems with one commit message and its identities under the repository's rules."""
    found = []
    for label, who in people.items():
        if not who:
            continue
        if AI_IDENTITY.search(who):
            found.append(f"{label} is an AI identity ({who})")
        elif wanted and who != wanted:
            found.append(f"{label} {who} is not {wanted}")
    if TRAILER.search(body) or GENERATED_LINE.search(body):
        found.append("AI co-author/generated trailer")
    text = TRAILER.sub("", body).strip()
    if text and not rules["body"]:
        lines = len([line for line in text.splitlines() if line.strip()])
        found.append(f"message has a body ({lines} line{'s' if lines != 1 else ''}); use one short line")
    if not subject.strip():
        found.append("empty subject")
    if len(subject) > rules["subject_max"]:
        found.append(f"subject is {len(subject)} characters (max {rules['subject_max']})")
    if _generated_subject(subject):
        found.append("subject reads as a tool summary, not a sentence")
    return found


def message(project: Project, repo: str, text: str) -> dict[str, Any]:
    """Judge a commit message before it is committed (the commit-msg hook): message text plus the identity git
    will record."""
    rules = policy(project, repo)
    root = project.root(repo)
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    while lines and not lines[0].strip():
        lines.pop(0)
    subject = lines[0].strip() if lines else ""
    body = "\n".join(lines[1:]).strip()
    people = {}
    for label, var in (("author", "GIT_AUTHOR_IDENT"), ("committer", "GIT_COMMITTER_IDENT")):
        try:
            ident = _git(root, "var", var).strip()
        except ValueError:
            continue
        people[label] = re.sub(r"\s+\d+\s+[-+]\d{4}$", "", ident)
    problems = judge(rules, _identity(root, rules["identity"]), subject, body, people)
    return {"subject": subject, "problems": problems, "ok": not problems}


def commits(project: Project, repo: str, revisions: str | None = None, limit: int = 30) -> dict[str, Any]:
    """Judge commit messages and identities in `revisions` (default: the last `limit` commits on HEAD)."""
    rules = policy(project, repo)
    root = project.root(repo)
    wanted = _identity(root, rules["identity"])
    args = ["log", "--format=%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%s%x1f%b%x1e"]
    args += [revisions] if revisions else [f"-{limit}"]
    try:
        raw = _git(root, *args)
    except ValueError:
        return {"identity": wanted, "checked": 0, "problems": [], "note": "no commits in range"}
    problems, checked = [], 0
    for record in raw.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        checked += 1
        sha, author, committer, subject, body = (record.split("\x1f") + [""] * 5)[:5]
        found = judge(rules, wanted, subject, body, {"author": author, "committer": committer})
        if found:
            problems.append({"commit": sha[:10], "subject": subject[:100], "problems": found})
    return {"identity": wanted, "checked": checked, "problems": problems}


def _tracked(root: Path) -> list[str]:
    return [p for p in _git(root, "ls-files", "-z").split("\0") if p]


def _ignored(rel: str, prefixes: list[str]) -> bool:
    return any(rel.startswith(p) for p in prefixes)


def _read(root: Path, rel: str, limit: int = 1_500_000) -> str:
    path = root / rel
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _git_ok(root: Path, *args: str) -> str:
    try:
        return _git(root, *args)
    except ValueError:
        return ""


def history(project: Project, repo: str) -> list[dict]:
    """Agent-only files that were ever committed (they stay in every clone even after deletion)."""
    rules = policy(project, repo)
    if rules["agent_docs"] != "forbid":
        return []
    root = project.root(repo)
    names = [*AGENT_DOCS, *(d.rstrip("/") for d in AGENT_DIRS)]
    out = []
    for name in names:
        listing = _git_ok(root, "log", "--all", "--format=%h", "--", name, f"**/{name}")
        commits = [c for c in listing.split() if c]
        if commits:
            out.append({"path": name, "commits": len(commits), "first": commits[-1]})
    return out


def files(project: Project, repo: str) -> dict[str, Any]:
    """Tracked content that the rules say should not be committed."""
    rules = policy(project, repo)
    root = project.root(repo)
    tracked = _tracked(root)
    ignore = rules["ignore"]
    allowed = rules["allowed_files"]
    findings: list[dict] = []

    def add(kind: str, path: str, message: str, severity: str = "error") -> None:
        if not any(fnmatch.fnmatch(path, a) for a in allowed):
            findings.append({"kind": kind, "path": path, "message": message, "severity": severity})

    # A target's own files (splits, symbols, function lists) are the project's data, not documents.
    data = {project.file(repo, config[key]).resolve() for config in project.config.get("targets", {}).values()
            if config.get("repository") == repo for key in ("splits", "symbols", "functions", "data_symbols")
            if config.get(key)}
    docs = [p for p in tracked if p.lower().endswith(DOC_SUFFIXES) and not _ignored(p, ignore)
            and not Path(p).name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
            and (root / p).resolve() not in data]
    texts = {p: _read(root, p) for p in tracked if p.lower().endswith(TEXT_SUFFIXES) and not _ignored(p, ignore)
             and Path(p).suffix.lower() not in (".c", ".cpp", ".h", ".hpp")}
    for path in tracked:
        name = Path(path).name
        if _ignored(path, ignore):
            continue
        if rules["agent_docs"] == "forbid" and (name in AGENT_DOCS or path.startswith(AGENT_DIRS)):
            add("agent-doc", path, "agent-only file is committed; keep agent rules in the toolkit's project file")
        if any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in rules["forbidden_files"]):
            add("original-file", path, "original game file, archive or key material is committed")
        try:
            size = (root / path).stat().st_size
        except OSError:
            continue
        if size > rules["max_file_kb"] * 1024:
            add("large-file", path, f"{size // 1024} KB tracked file", "warning")
    for path in docs:
        name = Path(path).name
        text = texts.get(path, "")
        if rules["agent_docs"] == "forbid" and name not in AGENT_DOCS and AGENT_NAME.search(path):
            add("agent-doc", path, "document named as an agent/session brief", "warning")
        if rules["dated_docs"] == "forbid" and DATE_NAME.search(name):
            add("dated-doc", path, "dated document: a session record, not documentation of how things are")
        elif rules["dated_docs"] == "forbid" and len(NARRATIVE.findall(text)) >= 3:
            add("narrative-doc", path, "reads as a session log (dated or 'later/next session' sections); "
                                      "documentation states how things are now", "warning")
    if len(docs) > rules["max_docs"]:
        findings.append({"kind": "doc-bloat", "path": f"{len(docs)} documents", "severity": "warning",
                         "message": f"{len(docs)} tracked documents (limit {rules['max_docs']}): the truth drifts "
                                    "across copies; keep a README and architecture docs"})
    # Documents nothing links to, and links/tool paths in documents that no longer exist.
    linked: set[str] = set()
    for path, text in texts.items():
        if not path.lower().endswith(DOC_SUFFIXES):
            continue
        base = Path(path).parent
        for target in re.findall(r"\]\(([^)#\s]+)", text):
            if "://" in target:
                continue
            linked.add(os.path.normpath(base / target).replace("\\", "/"))   # ../ links resolve too
        for ref in set(re.findall(r"(?<![\w./-])((?:tools|scripts|docs)/[\w./-]+\.(?:py|sh|md))", text)):
            if not (root / ref).exists():
                add("stale-reference", path, f"names {ref}, which no longer exists", "warning")
    entry = {"README.md", "CONTRIBUTING.md"}
    for path in docs:
        if Path(path).name in entry or Path(path).name in AGENT_DOCS:
            continue
        if path not in linked:
            add("orphan-doc", path, "no document links to it", "warning")
    # Scripts nobody references: not the build, not a test, not another script, not a document.
    scripts = [p for p in tracked if p.endswith(SCRIPT_SUFFIXES) and not _ignored(p, ignore)
               and any(p.startswith(r.rstrip("/") + "/") for r in rules["script_roots"])]
    users = {p: t for p, t in texts.items() if not any(f["path"] == p and f["kind"] in ("dated-doc", "agent-doc")
                                                       for f in findings)}
    for path in scripts:
        stem = Path(path).stem
        if stem in ("__init__", "__main__", "conftest"):
            continue
        token = re.compile(rf"(?<![\w-]){re.escape(stem)}(?![\w-])")
        if not any(other != path and token.search(text) for other, text in users.items()):
            add("unused-script", path, "nothing in the repository runs, imports or documents it", "warning")
    for path, text in texts.items():
        match = LOCAL_PATH.search(text)
        if match:
            add("local-path", path, f"contains a local absolute path ({match.group(0)}...)", "warning")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1
    return {"tracked": len(tracked), "documents": len(docs), "scripts": len(scripts), "counts": counts,
            "findings": findings}


def tree(project: Project, repo: str) -> dict[str, Any]:
    """What a finished session must not leave: uncommitted files, stashes, unmerged branches, stray worktrees."""
    from .activity import repository
    state = repository(project, repo, dirty_limit=40)
    root = project.root(repo)
    problems = []
    main = project.config["repositories"][repo].get("main_branch") or next(
        (b for b in ("main", "master") if _git_ok(root, "rev-parse", "--verify", "--quiet", f"refs/heads/{b}")), None)
    if main:
        merged = [b.strip().lstrip("*+ ").strip() for b in _git_ok(root, "branch", "--merged", main).splitlines()]
        for branch in merged:
            if branch and branch not in (main, state.get("branch")) and not branch.startswith("("):
                problems.append(f"branch {branch} is merged into {main} but still exists (git branch -d {branch})")
    if state.get("dirty_count"):
        problems.append(f"{state['dirty_count']} uncommitted or untracked file(s)")
    if state.get("stashes"):
        problems.append(f"{state['stashes']} stash(es)")
    for branch in state.get("unmerged_branches", []):
        problems.append(f"branch {branch['branch']} has {branch['unmerged_commits']} unmerged commit(s)")
    for worktree in state.get("worktrees", []):
        problems.append(f"worktree {worktree['worktree']}" + (" (missing: git worktree prune)"
                                                              if not worktree.get("exists") else ""))
    return {"branch": state.get("branch"), "head": state.get("head"), "dirty": state.get("dirty", []),
            "problems": problems}


def audit(project: Project, repo: str, revisions: str | None = None, limit: int = 30,
          parts: tuple[str, ...] = ("commits", "files", "tree")) -> dict[str, Any]:
    out: dict[str, Any] = {"repo": repo, "policy": policy(project, repo)}
    if "commits" in parts:
        out["commits"] = commits(project, repo, revisions, limit)
    if "files" in parts:
        out["files"] = files(project, repo)
        out["files"]["history"] = history(project, repo)
    if "tree" in parts:
        out["tree"] = tree(project, repo)
    errors = len(out.get("commits", {}).get("problems", [])) + \
        sum(1 for f in out.get("files", {}).get("findings", []) if f["severity"] == "error") + \
        len(out.get("tree", {}).get("problems", []))
    out["ok"] = errors == 0
    return out
