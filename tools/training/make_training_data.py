#!/usr/bin/env python3
"""Turn generated datasets into labelled NER training data (standard library only).

    python3 make_training_data.py --out training_data --train-seeds 101 102 103 104 105 \\
        --dev-seeds 201 --test-seeds 301 --patients 200

For every record (text note, CSV/TSV row, JSON/FHIR leaf) it writes the exact
text and character-offset spans of every personal-data mention, plus "keep"
spans (doses, doctors, codes, vitals ...) that a model must NOT remove.

Outputs per split:
    <split>.jsonl   {"id","source","format","script","text","spans":[{start,end,label}],"keep":[{start,end,label}]}
    <split>.conll   one token per line: TOKEN<TAB>BIO-label, blank line between records

Do not train on the hardest-test seeds (2026, 4242) if you score on them.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABEL = {'PATIENT_NAME': 'PATIENT', 'RELATIVE_NAME': 'RELATIVE', 'STAFF_NAME': 'PERSON_OTHER', 'CANARY': 'PATIENT',
         'PHONE': 'PHONE', 'AADHAAR': 'AADHAAR', 'AADHAAR_VID': 'AADHAAR', 'ABHA_NUMBER': 'ABHA', 'ABHA_ADDRESS': 'ABHA_ADDRESS',
         'PAN': 'PAN', 'VOTER_ID': 'VOTER_ID', 'MRN': 'HOSPITAL_ID', 'INSURANCE_ID': 'INSURANCE_ID', 'PMJAY_ID': 'INSURANCE_ID',
         'EMAIL': 'EMAIL', 'DOB': 'DOB', 'HOUSE': 'HOUSE', 'LOCALITY': 'LOCALITY', 'LANDMARK': 'LANDMARK',
         'VILLAGE': 'VILLAGE', 'PIN': 'PIN'}
TOKEN = re.compile(r'[\wऀ-ॿ]+(?:[.\'’@/-][\wऀ-ॿ]+)*|[^\s\wऀ-ॿ]', re.UNICODE)


def read(path: Path) -> str:
    raw = path.read_bytes()
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return raw.decode('utf-16')
    try:
        return raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        return raw.decode('cp1252')


def leaves(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from leaves(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from leaves(v, path + (str(i),))
    elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
        yield path, str(node)


def records(meta, text):
    """Yield (loc, record_text) for one input file, rendered as readable text."""
    fmt = meta['format']
    if fmt in ('csv', 'tsv'):
        rows = list(csv.reader(io.StringIO(text), delimiter='\t' if fmt == 'tsv' else ','))
        if not rows:
            return
        header = rows[0]
        for i, row in enumerate(rows[1:]):
            if len(row) == len(header):
                yield f'row:{i}', '\n'.join(f'{h}: {v}' for h, v in zip(header, row))
    elif fmt in ('json', 'fhir'):
        data = json.loads(text)
        units = [l for l in meta['units'] if l.startswith('/')]
        if units:
            for loc in units:
                node = data
                for part in loc.strip('/').split('/'):
                    node = node[int(part)] if isinstance(node, list) else node[part]
                yield loc, '\n'.join(f"{'.'.join(p)}: {v}" for p, v in leaves(node))
        else:
            yield 'doc', '\n'.join(f"{'.'.join(p)}: {v}" for p, v in leaves(data))
    elif fmt == 'text':
        yield 'doc', text


def find_spans(text, items):
    """Place each (surface, label) at every occurrence; longest first, no overlaps."""
    taken, spans = [], []
    for surface, label in sorted(set(items), key=lambda x: -len(x[0])):
        if not surface or len(surface) < 2:
            continue
        for m in re.finditer(re.escape(surface), text):
            a, b = m.span()
            if a and (text[a - 1].isalnum() and surface[0].isalnum()):
                continue
            if b < len(text) and text[b].isalnum() and surface[-1].isalnum():
                continue
            if any(a < y and x < b for x, y in taken):
                continue
            taken.append((a, b))
            spans.append({'start': a, 'end': b, 'label': label})
    return sorted(spans, key=lambda s: s['start'])


def to_conll(text, spans):
    lines = []
    for m in TOKEN.finditer(text):
        a, b = m.span()
        tag = 'O'
        for s in spans:
            if s['start'] <= a and b <= s['end']:
                tag = ('B-' if a == s['start'] or not text[s['start']:a].strip() else 'I-') + s['label']
                break
        lines.append(f'{m[0]}\t{tag}')
    return '\n'.join(lines)


def export(data_dir: Path, split: str, seed: int, jf, cf, stats):
    truth = json.loads((data_dir / 'dev/truth/truth.json').read_text(encoding='utf-8'))
    root = data_dir / 'dev/input'
    for path, meta in truth['files'].items():
        if meta.get('expect') == 'quarantine' or meta['format'] not in ('csv', 'tsv', 'json', 'fhir', 'text'):
            continue
        try:
            text = read(root / path)
            recs = list(records(meta, text))
        except (ValueError, KeyError, IndexError, TypeError, csv.Error, RecursionError):
            continue
        for loc, rtext in recs:
            unit = meta['units'].get(loc) or meta['units'].get('doc')
            if not unit:
                continue
            pii = [(e['surface'], LABEL.get(e['type'], 'PII')) for e in unit['entities'] if e['channel'] not in ('filename', 'folder')]
            keep = [(p['text'], 'KEEP_' + p['kind'].upper()) for p in unit.get('preserve', [])]
            spans = find_spans(rtext, pii)
            keep_spans = [k for k in find_spans(rtext, keep) if not any(k['start'] < s['end'] and s['start'] < k['end'] for s in spans)]
            scripts = sorted({e['script'] for e in unit['entities']}) or ['latin']
            rec = {'id': f'{split}-{seed}-{path}#{loc}', 'source': path, 'format': meta['format'], 'script': scripts,
                   'text': rtext, 'spans': spans, 'keep': keep_spans}
            jf.write(json.dumps(rec, ensure_ascii=False) + '\n')
            cf.write(to_conll(rtext, spans) + '\n\n')
            stats['records'] += 1
            for s in spans:
                stats[s['label']] += 1
            stats['keep_spans'] += len(keep_spans)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--train-seeds', type=int, nargs='+', default=[101, 102, 103, 104, 105])
    ap.add_argument('--dev-seeds', type=int, nargs='+', default=[201])
    ap.add_argument('--test-seeds', type=int, nargs='+', default=[301])
    ap.add_argument('--patients', type=int, default=200)
    a = ap.parse_args()
    banned = {2026, 4242}
    if banned & set(a.train_seeds + a.dev_seeds + a.test_seeds):
        ap.error('seeds 2026 and 4242 are the hardest-test sets; do not train on them')
    a.out.mkdir(parents=True, exist_ok=True)
    summary = {}
    with tempfile.TemporaryDirectory() as tmp:
        for split, seeds in (('train', a.train_seeds), ('dev', a.dev_seeds), ('test', a.test_seeds)):
            stats = Counter()
            with (a.out / f'{split}.jsonl').open('w', encoding='utf-8') as jf, (a.out / f'{split}.conll').open('w', encoding='utf-8') as cf:
                for seed in seeds:
                    d = Path(tmp) / f'{split}_{seed}'
                    gen = HERE / 'generate.py' if (HERE / 'generate.py').is_file() else HERE.parent / 'hardest_test' / 'generate.py'
                    subprocess.run([sys.executable, str(gen), '--out', str(d), '--seed', str(seed),
                                    '--patients', str(a.patients)], check=True, stdout=subprocess.DEVNULL)
                    export(d, split, seed, jf, cf, stats)
            summary[split] = dict(stats.most_common())
            print(split, stats['records'], 'records,', sum(v for k, v in stats.items() if k not in ('records', 'keep_spans')), 'PII spans,',
                  stats['keep_spans'], 'keep spans')
    labels = sorted({k for s in summary.values() for k in s if k not in ('records', 'keep_spans')})
    (a.out / 'labels.json').write_text(json.dumps({'pii_labels': labels, 'counts': summary}, indent=1), encoding='utf-8')


if __name__ == '__main__':
    main()
