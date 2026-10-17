"""Project-defined include boundaries for native ports; never rewrites matching decomp."""
from __future__ import annotations

import os
from pathlib import Path
import re

from .bridge import _changed_files, _normalize
from .project import Project

SUFFIXES = {'.h', '.hpp', '.hh', '.hxx', '.c', '.cc', '.cpp', '.cxx', '.inc', '.inl'}
# Preserve ordinary string literals, but blank comments/raw strings (including their fake directives).
TOKENS = re.compile(r'R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=delimiter)"|'
                    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S)
INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', re.M)
DIRECTIVE = re.compile(r'^\s*#\s*include\b([^\n]*)', re.M)


def _code(text: str) -> str:
    return TOKENS.sub(lambda m: re.sub(r'[^\n]', ' ', m[0]) if m[0].startswith(('//', '/*', 'R"')) else m[0], text)


def audit(project: Project, repo: str, paths: list[str] | None = None, base: str = 'HEAD',
          all_files: bool = False) -> dict:
    config = project.config['repositories'][repo].get('architecture')
    if not config or not config.get('rules'):
        raise ValueError(f'{repo} has no architecture rules; configure rules from its own design contract')
    rules = []
    ids = set()
    for rule in config['rules']:
        if not rule.get('id') or rule['id'] in ids or not rule.get('reason'):
            raise ValueError('Architecture rules need unique ids and a reason')
        ids.add(rule['id'])
        allowed = rule.get('allow_includes', [])
        if not isinstance(allowed, list) or any(not isinstance(x, str) for x in allowed):
            raise ValueError('allow_includes must be a list of regular expressions')
        try:
            rules.append((rule, re.compile(rule['sources']), re.compile(rule['forbidden_includes']),
                          [re.compile(x) for x in allowed]))
        except re.error as error:
            raise ValueError(f"Invalid architecture regex in {rule['id']}: {error}") from error
    root = project.root(repo)
    roots = [project.file(repo, p) for p in config.get('include_roots', ['src'])]
    requested = config.get('scan', ['src']) if all_files else (paths or _changed_files(root, base))
    files, errors = set(), []
    for value in requested:
        path = project.file(repo, _normalize(root, value))
        if path.is_dir():
            for directory, folders, names in os.walk(path, followlinks=False):
                folders[:] = sorted(d for d in folders if not d.startswith('.') and d not in ('build', 'vendor'))
                for name in names:
                    if Path(name).suffix in SUFFIXES:
                        files.add((Path(directory) / name).relative_to(root).as_posix())
        elif path.is_file() and path.suffix in SUFFIXES:
            files.add(path.relative_to(root).as_posix())
        elif not path.exists() and (all_files or paths):
            errors.append({'reference': f'{repo}:{value}', 'error': 'Requested architecture scope does not exist'})
    resolved = {}
    findings, exceptions, unknown = [], [], []
    checked, edges, macro_includes = 0, 0, 0
    for rel in sorted(files):
        active = [rule for rule in rules if rule[1].search(rel)]
        if not active:
            continue
        checked += 1
        path = project.file(repo, rel)
        try:
            text = _code(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError) as error:
            errors.append({'reference': f'{repo}:{rel}', 'error': str(error)})
            continue
        matches = list(INCLUDE.finditer(text))
        macro_includes += len(list(DIRECTIVE.finditer(text))) - len(matches)
        for match in matches:
            target = match[1]
            key = (str(path.parent), target)
            if key not in resolved:
                resolved[key] = None
                for directory in [path.parent, *roots]:
                    candidate = (directory / target).resolve()
                    if candidate.is_relative_to(root) and candidate.is_file():
                        resolved[key] = candidate.relative_to(root).as_posix()
                        break
            destination = resolved[key]
            line = text.count('\n', 0, match.start()) + 1
            # Leading whitespace may include a newline; locate the directive itself.
            line += match[0][:match[0].index('#')].count('\n')
            edge = {'reference': f'{repo}:{rel}:{line}', 'include': target, 'resolved': destination}
            edges += 1
            if destination is None:
                unknown.append(edge)
            for rule, _, forbidden, allowed in active:
                if not any(forbidden.search(s) for s in (target, destination or '')):
                    continue
                row = {**edge, 'rule': rule['id'], 'reason': rule['reason']}
                if any(a.search(s) for a in allowed for s in (target, destination or '')):
                    exceptions.append(row)
                else:
                    findings.append(row)
    return {'repo': repo, 'scope': list(requested), 'rules': len(rules), 'files_checked': checked,
            'includes_checked': edges, 'findings': findings, 'allowed_exceptions': exceptions,
            'unresolved_includes': unknown, 'macro_includes': macro_includes, 'errors': errors,
            'ok': not findings and not errors, 'documents': config.get('documents', []),
            'limits': 'Literal C/C++ includes and configured policies only; all conditional branches are inspected. '
                      'Unresolved external/generated includes can only be checked by spelling; macros are not expanded. '
                      'No ownership, semantic coupling, compiler dependency or whole-architecture proof is inferred. '
                      'Matching decomp keeps original layout and compiler constraints; native-port rules do not refactor it.'}
