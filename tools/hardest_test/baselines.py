#!/usr/bin/env python3
"""Build two reference releases to sanity-check score.py (standard library only).

    python3 baselines.py --data hardest_data --out baselines/

passthrough/  copies every input unchanged             -> must score very low (penalties)
redact_all/   replaces every file with an empty shell  -> no leaks, but no utility

A real system should land well above both.
"""
import argparse
import hashlib
import json
from pathlib import Path


def build(data: Path, out: Path, mode: str):
    root = data / 'dev/input'
    san = out / 'sanitized'
    files = []
    records = []
    truth = json.loads((data / 'dev/truth/truth.json').read_text(encoding='utf-8'))
    for p in sorted(root.rglob('*')):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        raw = p.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        if mode == 'passthrough':
            dest = san / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            files.append({'input_sha256': sha, 'output': 'sanitized/' + rel, 'status': 'sanitized'})
        else:
            dest = san / f'redacted_{sha[:16]}.txt'
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text('[REDACTED]\n', encoding='utf-8')
            files.append({'input_sha256': sha, 'output': f'sanitized/redacted_{sha[:16]}.txt', 'status': 'sanitized'})
        meta = truth['files'].get(rel, {})
        for loc in meta.get('units', {}):
            if not loc.startswith('@'):
                records.append({'file': files[-1]['output'], 'loc': loc, 'patient': None})
    report = {'schema': 'raksha-report/1', 'files': files,
              'counts': {'files_total': len(files), 'files_sanitized': len(files), 'files_quarantined': 0,
                         'records_processed': len(records), 'identifiers_detected': 0, 'records_linked': 0,
                         'records_generalized': 0, 'records_suppressed': 0, 'records_quarantined': 0},
              'timing': {'seconds': 1.0}, 'resources': {'peak_rss_mb': 20.0}}
    out.mkdir(parents=True, exist_ok=True)
    (out / 'report.json').write_text(json.dumps(report, indent=1), encoding='utf-8')
    (out / 'records.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args()
    for mode in ('passthrough', 'redact_all'):
        build(a.data, a.out / mode, mode)
        print('wrote', a.out / mode)


if __name__ == '__main__':
    main()
