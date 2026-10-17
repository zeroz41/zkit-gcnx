"""Compare project-owned inventories across import/integration stages, without running converters."""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path
import re

from .project import Project


def _select(value, pointer: str):
    if not pointer:
        return value
    if not pointer.startswith('/'):
        raise ValueError('JSON pointer must be empty or start with /')
    for token in pointer[1:].split('/'):
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def inventory(project: Project, default_repo: str, spec: dict) -> dict:
    repo = spec.get('repo', default_repo)
    root = project.root(repo)
    patterns = spec.get('files')
    if not isinstance(patterns, list) or not patterns or any(not isinstance(p, str) for p in patterns):
        raise ValueError('Inventory files must be a nonempty list of repository-relative paths/globs')
    format = spec.get('format')
    if format not in ('regex', 'json'):
        raise ValueError('Inventory format must be regex or json')
    try:
        pattern = re.compile(spec['pattern'], re.M) if format == 'regex' else None
    except re.error as error:
        raise ValueError(f'Invalid inventory regex: {error}') from error
    if pattern is not None and 'id' not in pattern.groupindex:
        raise ValueError('Inventory regex needs a named (?P<id>...) capture')
    files, errors, evidence = set(), [], []
    for glob in patterns:
        if Path(glob).is_absolute() or '..' in Path(glob).parts:
            raise ValueError('Inventory globs must stay inside their repository')
        found = [p for p in root.glob(glob) if p.is_file()]
        if not found:
            errors.append(f'No files matched {repo}:{glob}')
        for path in found:
            files.add(project.file(repo, path.relative_to(root).as_posix()))
    records = collections.defaultdict(list)
    for path in sorted(files):
        reference = f'{repo}:{path.relative_to(root).as_posix()}'
        try:
            raw = path.read_bytes()
            text = raw.decode('utf-8')
            evidence.append({'reference': reference, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
            if format == 'regex':
                rows = [(m['id'], f'{reference}:{text.count(chr(10), 0, m.start()) + 1}')
                        for m in pattern.finditer(text)]
            else:
                values = _select(json.loads(text), spec.get('pointer', ''))
                if not isinstance(values, list):
                    raise ValueError('JSON inventory pointer must select an array')
                rows = [(_select(v, spec.get('id_pointer', '')), f'{reference}#{i}') for i, v in enumerate(values)]
            for value, location in rows:
                if isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value).strip():
                    raise ValueError(f'Invalid inventory identity at {location}')
                records[str(value)].append(location)
        except (OSError, UnicodeError, ValueError, KeyError, TypeError, IndexError) as error:
            errors.append(f'{reference}: {error}')
    duplicates = {key: places for key, places in records.items() if len(places) > 1}
    if duplicates and spec.get('unique', True):
        errors.append('Duplicate identities: ' + ', '.join(sorted(duplicates)))
    if not records and not spec.get('allow_empty', False):
        errors.append('Inventory has no identities; an empty scan is not complete coverage')
    return {'ids': sorted(records), 'locations': dict(records), 'duplicates': duplicates,
            'evidence': evidence, 'errors': errors}


def audit(project: Project, repo: str, name: str) -> dict:
    catalogs = project.config['repositories'][repo].get('coverage', {})
    if name not in catalogs:
        raise ValueError(f'Unknown coverage inventory {name!r}; choose from: {", ".join(catalogs)}')
    config = catalogs[name]
    if not config.get('boundary') or not config.get('stages'):
        raise ValueError('Coverage needs an explicit boundary and at least one stage')
    reference = inventory(project, repo, config['reference'])
    expected = set(reference['ids'])
    stages, found = [], {'reference': expected}
    errors = [f'reference: {e}' for e in reference['errors']]
    for spec in config['stages']:
        key = spec['id']
        if not key or key in found:
            raise ValueError('Coverage stage ids must be nonempty and unique')
        requires = spec.get('requires', ['reference'])
        if any(dep not in found for dep in requires):
            raise ValueError(f'Stage {key} requires an unknown or later stage')
        data = inventory(project, repo, spec['inventory'])
        actual = set(data['ids'])
        dependencies = {dep: sorted(actual - found[dep]) for dep in requires if actual - found[dep]}
        stages.append({'id': key, 'count': len(actual), 'covered': len(actual & expected),
                       'missing': sorted(expected - actual), 'extra': sorted(actual - expected),
                       'without_prerequisite': dependencies, 'inventory': data})
        found[key] = actual
        errors.extend(f'{key}: {e}' for e in data['errors'])
    covered = not errors and all(not s['missing'] and not s['without_prerequisite'] for s in stages)
    return {'repo': repo, 'name': name, 'boundary': config['boundary'], 'reference': reference,
            'expected': len(expected), 'stages': stages, 'errors': errors, 'ok': covered,
            'inventory_covered': covered, 'system_complete': False, 'documents': config.get('documents', []),
            'limits': 'Coverage is relative to the declared reference inventory and extraction selectors. '
                      'Presence does not prove valid imports, runtime admission, test execution or behavior. '
                      'Read provenance and excluded boundaries; do not infer whole-system completion. '
                      'Converters and game-format knowledge remain project-owned; this tool executes nothing.'}
