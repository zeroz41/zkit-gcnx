#!/usr/bin/env python3
"""Alternate fresh CLI processes on real, read-only cases using isolated toolkit state.

Cases are project-owned JSON: [{"name": "lookup", "argv": ["--json", "lookup", "..."]}].
The first pair warms each version's index; measured pairs alternate order. Startup and
per-command refresh are included; OS file caches are warm. Outputs are retained so faster
or shorter answers can be checked for lost evidence. This measures tools, not agent quality.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

from replay import _isolated_env, replayable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=5)
    args = parser.parse_args()
    if args.repeat < 2:
        parser.error('--repeat must be at least 2')
    cases = json.loads(args.cases.read_text(encoding='utf-8'))
    if not cases or any(not replayable({'kind': 'cli', 'argv': c['argv']}) for c in cases):
        parser.error('cases must contain only read-only toolkit commands')
    args.out.mkdir(parents=True, exist_ok=True)
    environments = {label: _isolated_env(src.resolve(), label, args.out / 'isolated')
                    for label, src in [('old', args.old), ('new', args.new)]}
    report = {'python': sys.version, 'platform': platform.platform(), 'project': str(args.project.resolve()),
              'project_sha256': hashlib.sha256(args.project.read_bytes()).hexdigest(),
              'repeat': args.repeat, 'cases': []}
    failed = False
    for index, case in enumerate(cases):
        samples = {'old': [], 'new': []}
        for trial in range(-1, args.repeat):
            for label in (('old', 'new') if trial % 2 else ('new', 'old')):
                command = [sys.executable, '-m', 'gcn_zkit.cli', '--project', str(args.project.resolve()), *case['argv']]
                start = time.perf_counter()
                result = subprocess.run(command, env=environments[label], capture_output=True,
                                        text=True, encoding='utf-8', timeout=120)
                seconds = time.perf_counter() - start
                failed |= result.returncode != 0
                output = args.out / f'{index}-{label}-{trial}.txt'
                output.write_text(result.stdout + result.stderr, encoding='utf-8')
                if trial >= 0:
                    samples[label].append({'seconds': seconds, 'exit': result.returncode,
                                           'bytes': len(result.stdout.encode('utf-8')), 'output': output.name})
        summary = {label: {'median_s': round(statistics.median(r['seconds'] for r in rows), 4),
                           'min_s': round(min(r['seconds'] for r in rows), 4),
                           'max_s': round(max(r['seconds'] for r in rows), 4),
                           'median_bytes': statistics.median(r['bytes'] for r in rows)}
                   for label, rows in samples.items()}
        report['cases'].append({**case, 'summary': summary, 'samples': samples})
        print(case['name'], json.dumps(summary), flush=True)
        (args.out / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
