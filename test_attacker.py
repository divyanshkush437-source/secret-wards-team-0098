#!/usr/bin/env python3
"""Member 3 red-team harness. DEVELOPMENT ONLY: never imported by main.py.

Plays the attacker against our own release using the PRACTICE answer key and
voter-style registry from the team kit, and also times a scaled-up run.

    python3 test_attacker.py --kit /path/to/Secret-Wards-ToolKit --output out/
    python3 test_attacker.py --kit /path/to/kit --scale 6     # speed / RAM check

It prints aggregate numbers only (counts and rates), never names or values,
so its own output is safe to paste into the project brief.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

GENERIC = set('kumar kumari devi singh bano begum khatoon bibi lal prasad bai rani md mohd mohammad ji sahab bhai bhaiya papa mummy didi behenji amma'.split())


def norm(text: str) -> str:
    text = unicodedata.normalize('NFKC', text)
    text = ''.join(c for c in unicodedata.normalize('NFKD', text) if not unicodedata.combining(c))
    text = ''.join(str(int(c)) if c.isdecimal() else c for c in text)
    return text.casefold()


def read_release(output: Path):
    report = json.loads((output / 'report.json').read_text(encoding='utf-8'))
    texts = {}
    for f in (output / 'sanitized').rglob('*'):
        if f.is_file():
            raw = f.read_text(encoding='utf-8', errors='replace')
            texts[f.relative_to(output).as_posix()] = raw
    records = [json.loads(line) for line in (output / 'records.jsonl').read_text(encoding='utf-8').splitlines() if line]
    return report, texts, records


def decoded(text: str) -> str:
    extra = []
    for blob in re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', text):
        try:
            extra.append(base64.b64decode(blob, validate=True).decode('utf-8'))
        except Exception:
            pass
    return norm(text + '\n' + '\n'.join(extra))


# ------------------------------------------------------------------ linkage
def linkage(truth, report, records):
    by_sha = {f['input_sha256']: f['output'] for f in report['files']}
    claim = {(r['file'], r['loc']): r['patient'] for r in records}
    units = []
    for path, meta in truth['files'].items():
        out = by_sha.get(meta.get('sha256'))
        if not out:
            continue
        for loc, unit in meta.get('units', {}).items():
            units.append((unit.get('patient'), unit.get('link'), claim.get((out, loc))))
    pred = defaultdict(list)
    for i, (pt, link, psn) in enumerate(units):
        if psn:
            pred[psn].append(i)
    tp = fp = 0
    for members in pred.values():
        for a, b in combinations(members, 2):
            if units[a][0] and units[a][0] == units[b][0]:
                tp += 1
            else:
                fp += 1
    by_pt = defaultdict(list)
    for i, (pt, link, psn) in enumerate(units):
        if pt and link == 'required':
            by_pt[pt].append(i)
    need = found = 0
    for members in by_pt.values():
        for a, b in combinations(members, 2):
            need += 1
            found += bool(units[a][2]) and units[a][2] == units[b][2]
    p = tp / (tp + fp) if tp + fp else 1.0
    r = found / need if need else 1.0
    f05 = 1.25 * p * r / (0.25 * p + r) if p + r else 0.0
    homonym_ok = 0
    pairs = truth['traps'].get('homonym_pairs', [])
    for x, y in pairs:
        px = {u[2] for u in units if u[0] == x and u[2]}
        py = {u[2] for u in units if u[0] == y and u[2]}
        homonym_ok += not (px & py)
    return {'pair_precision': round(p, 4), 'pair_recall': round(r, 4), 'F0.5': round(f05, 4),
            'linkable_pairs': need, 'predicted_pairs': tp + fp,
            'homonym_pairs_separated': f'{homonym_ok}/{len(pairs)}',
            'units_claimed': sum(1 for u in units if u[2]), 'units_total': len(units)}


# ------------------------------------------------------------------ leaks
NAME_TYPES = {'PATIENT_NAME', 'RELATIVE_NAME'}


def leaks(truth, report, texts):
    by_sha = {f['input_sha256']: f['output'] for f in report['files']}
    out_norm = {k: decoded(v) for k, v in texts.items()}
    side = norm(json.dumps(report, ensure_ascii=False))
    per_type = Counter()
    total = Counter()
    canary_hits = 0
    canaries = []
    for path, meta in truth['files'].items():
        out = by_sha.get(meta.get('sha256'))
        text = out_norm.get(out, '')
        for unit in meta.get('units', {}).values():
            allowed = norm(' '.join(x['text'] for x in unit.get('preserve', [])))
            for e in unit.get('entities', []):
                kind = e['type']
                if e.get('canary'):
                    canaries.append(e)
                if kind in NAME_TYPES:
                    keys = [t for t in e.get('tokens', []) if t not in GENERIC and len(t) > 2]
                    keys = [norm(t) for t in keys if norm(t) not in allowed]
                    hit = any(re.search(r'(?<!\w)' + re.escape(k) + r'(?!\w)', text) for k in keys)
                elif kind in {'PHONE', 'AADHAAR', 'ABHA', 'MRN'}:
                    digits = re.sub(r'\D', '', norm(e['surface']))
                    if len(digits) < 6:
                        continue
                    hit = digits in re.sub(r'\D', '', text) and kind != 'MRN' or (kind == 'MRN' and digits in re.sub(r'[^0-9\n ]', '', text).replace(' ', ''))
                elif kind in {'EMAIL', 'PAN', 'VILLAGE', 'HOUSE', 'LOCALITY'}:
                    hit = norm(e['surface']) in text
                else:
                    continue
                total[kind] += 1
                per_type[kind] += bool(hit)
                script = e.get('script', 'latin')
                total['script:' + script] += 1
                per_type['script:' + script] += bool(hit)
    for c in truth.get('canaries', []):
        if norm(str(c)) in side:
            canary_hits += 1
    rates = {k: f'{per_type[k]}/{total[k]}' for k in sorted(total)}
    return {'leaked_over_mentions': rates, 'canary_in_report': canary_hits}


# ------------------------------------------------------------------ utility
def preserved(truth, report, texts):
    """Share of clinical preserve-probes (doses, vitals, labs, doctors ...) kept."""
    by_sha = {f['input_sha256']: f['output'] for f in report['files']}
    kept = total = 0
    by_kind = Counter()
    lost_kind = Counter()
    for meta in truth['files'].values():
        out = by_sha.get(meta.get('sha256'))
        text = norm(texts.get(out, '')) if out else ''
        if out and meta.get('format') in {'json', 'fhir'}:
            text += norm(json.dumps(json.loads(texts[out]), ensure_ascii=False))
        for unit in meta.get('units', {}).values():
            for probe in unit.get('preserve', []):
                total += 1
                by_kind[probe['kind']] += 1
                if norm(probe['text']) in text:
                    kept += 1
                else:
                    lost_kind[probe['kind']] += 1
    return {'clinical_probes_kept': f'{kept}/{total}', 'lost_by_kind': dict(lost_kind.most_common(6))}


# ------------------------------------------------------------------ dates
DATE_RE = re.compile(r'\d{1,4}[-/]\d{1,2}[-/]\d{2,4}')


def intervals(truth, report, texts):
    from privacy import parse_numeric
    by_sha = {f['input_sha256']: f['output'] for f in report['files']}
    ok = bad = 0
    for meta in truth['files'].values():
        out = by_sha.get(meta.get('sha256'))
        if not out or meta.get('format') != 'text':
            continue
        text = texts.get(out, '')
        order = 'MDY' if meta.get('date_hint') == 'mdy' else 'DMY'
        for unit in meta.get('units', {}).values():
            ds = [d for d in unit.get('dates', []) if d.get('anchor')]
            got = []
            for d in ds:
                m = re.search(re.escape(d['anchor']) + r'\s*(' + DATE_RE.pattern + ')', text)
                value = parse_numeric(m[1], order)[0] if m else None
                got.append((d['true'], value))
            for (t1, v1), (t2, v2) in combinations(got, 2):
                if v1 is None or v2 is None:
                    continue
                from datetime import date
                true_gap = (date.fromisoformat(t2) - date.fromisoformat(t1)).days
                if (v2 - v1).days == true_gap and str(v1) != t1:
                    ok += 1
                else:
                    bad += 1
    return {'date_pairs_interval_kept_and_shifted': f'{ok}/{ok + bad}'}


# ------------------------------------------------------------------ attack
AGE_BAND = re.compile(r'(?<!\d)(\d{1,3})-(\d{1,3})(?=\s*(?:Y|y|/|$|वर्ष|"))|(\d{2})\+')


def registry_attack(kit: Path, truth, report, texts, records):
    """Sweeney-style profile attack: pseudonym profile -> registry candidates.

    Evidence used: age band, gender, district strings visible in each
    pseudonym's records. Risk = probability mass on the true person
    (uniform over surviving candidates), as in docs/ATTACKS.md A2-A4.
    """
    import csv
    reg = list(csv.DictReader((kit / 'dev/attacker/registry.csv').open(encoding='utf-8')))
    districts = sorted({r['district'] for r in reg}, key=len, reverse=True)
    by_sha = {f['input_sha256']: f['output'] for f in report['files']}
    truth_patient = {}
    for meta in truth['files'].values():
        out = by_sha.get(meta.get('sha256'))
        for loc, unit in meta.get('units', {}).items():
            if unit.get('patient'):
                truth_patient[(out, loc)] = unit['patient']
    rid = {pt: info['rid'] for pt, info in truth['patients'].items()}
    profiles = defaultdict(list)
    for r in records:
        if r['patient']:
            profiles[r['patient']].append(r)
    risks, confident = [], 0
    for psn, recs in profiles.items():
        votes = Counter(truth_patient.get((r['file'], r['loc'])) for r in recs)
        pt = votes.most_common(1)[0][0]
        if not pt or pt not in rid:
            continue
        blob = ' '.join(_record_text(texts.get(r['file'], ''), r['loc'], psn) for r in recs)
        cands = reg
        dist = [d for d in districts if re.search(r'(?<!\w)' + re.escape(d) + r'(?!\w)', blob)]
        if dist:
            narrowed = [c for c in cands if c['district'] in dist]
            cands = narrowed or cands
        g = re.findall(r'(?<![A-Za-z])(?:/\s*|Sex:\s*|gender\W+)([MF])\b', blob)
        if g:
            narrowed = [c for c in cands if c['gender'] == g[0]]
            cands = narrowed or cands
        m = AGE_BAND.search(blob)
        if m:
            lo, hi = (int(m[1]), int(m[2])) if m[1] else (int(m[3]), 130)
            narrowed = [c for c in cands if lo - 1 <= int(c['age'] or -9) <= hi + 2]
            cands = narrowed or cands
        hit = any(c['rid'] == rid[pt] for c in cands)
        risk = (1 / len(cands)) if hit else 0.0
        risks.append(risk)
        confident += risk >= 0.5
    return {'profiles_attacked': len(risks),
            'mean_true_person_probability': round(sum(risks) / len(risks), 4) if risks else 0,
            'profiles_reidentified_conf>=0.5': confident}


def _record_text(text, loc, psn):
    if loc.startswith('row:'):
        lines = text.splitlines()
        return ' '.join(l for l in lines if psn in l)
    return text if psn in text else ''


# ------------------------------------------------------------------ scale
def scale_run(kit: Path, factor: int):
    """Copy the practice input `factor` times and time the real CLI."""
    src = kit / 'dev' / 'input'
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'input'
        for i in range(factor):
            shutil.copytree(src, root / f'copy{i}')
        out = Path(tmp) / 'out'
        env = dict(os.environ, RAKSHA_SECRET=os.environ.get('RAKSHA_SECRET', 'scale-test-secret'))
        start = time.monotonic()
        proc = subprocess.run([sys.executable, 'main.py', '--input', str(root), '--output', str(out)],
                              cwd=Path(__file__).resolve().parent, env=env, capture_output=True, text=True)
        elapsed = time.monotonic() - start
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        peak_mb = peak / (1048576 if sys.platform == 'darwin' else 1024)
        files = sum(1 for _ in root.rglob('*') if _.is_file())
        return {'input_files': files, 'exit': proc.returncode, 'seconds': round(elapsed, 2),
                'child_peak_rss_mb': round(peak_mb, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--kit', required=True, type=Path)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--scale', type=int, default=0)
    args = ap.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    result = {}
    if args.output:
        truth = json.loads((args.kit / 'dev/truth/truth.json').read_text(encoding='utf-8'))
        report, texts, records = read_release(args.output)
        result['linkage'] = linkage(truth, report, records)
        result['leaks'] = leaks(truth, report, texts)
        result['dates'] = intervals(truth, report, texts)
        result['utility'] = preserved(truth, report, texts)
        result['attack'] = registry_attack(args.kit, truth, report, texts, records)
    if args.scale:
        result['scale'] = scale_run(args.kit, args.scale)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
