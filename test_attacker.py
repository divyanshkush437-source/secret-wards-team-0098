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
    by_file = defaultdict(dict)
    for r in records:
        by_file[r['file']][r['loc']] = r['patient']

    def lookup(out, loc):
        # Same rule as the official scorer: exact locator, a JSON-pointer ancestor, or 'doc'.
        recs = by_file.get(out, {})
        if loc in recs:
            return recs[loc]
        if loc.startswith('/'):
            parts = loc.split('/')
            for i in range(len(parts) - 1, 1, -1):
                if '/'.join(parts[:i]) in recs:
                    return recs['/'.join(parts[:i])]
        return recs.get('doc')
    units = []
    for path, meta in truth['files'].items():
        out = by_sha.get(meta.get('sha256'))
        if not out:
            continue
        for loc, unit in meta.get('units', {}).items():
            if loc.startswith('@'):
                continue                  # file-level leak channels, not patient records
            units.append((unit.get('patient'), unit.get('link'), lookup(out, loc)))
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


# ------------------------------------------------------------------ kit self-check
def _kit_norm(s):
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


_KIT_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _kit_read(p: Path) -> str:
    try:
        raw = p.read_bytes()[: 50 * 1024 * 1024]
    except OSError:
        return ""
    text = raw.decode("utf-8", errors="replace")
    extra = []
    for m in _KIT_B64.finditer(text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return text + "\n" + "\n".join(extra) if extra else text


def kit_selfcheck(kit: Path, out: Path, show=0):
    """Same measures as the team kit's check_dev.py (exact-surface leak scan per
    entity, preserve probes, canaries anywhere in the output, pairwise linkage)."""
    truth = json.loads((kit / 'dev/truth/truth.json').read_text(encoding='utf-8'))
    san = out / 'sanitized'
    report = json.loads((out / 'report.json').read_text(encoding='utf-8'))
    renamed = {e.get('input_sha256'): e.get('output') for e in report.get('files') or []}
    leaks, kept, by_type_script = Counter(), Counter(), Counter()
    tot_script, by_script, tot_channel, by_channel = Counter(), Counter(), Counter(), Counter()
    examples = []
    pres_ok = pres_all = 0
    lost = Counter()
    copied_raw = 0
    for rel, f in truth['files'].items():
        declared = renamed.get(f['sha256'])
        out_rel = str(declared).replace('sanitized/', '', 1) if declared else rel
        p = san / out_rel
        exists = p.is_file()
        text = _kit_norm(_kit_read(p)) if exists else ''
        src = kit / 'dev/input' / rel
        if any(u['entities'] for u in f['units'].values()) and exists and f.get('expect') == 'either' \
                and src.is_file() and p.read_bytes() == src.read_bytes():
            copied_raw += 1
        fname = _kit_norm(out_rel)
        for loc, u in f['units'].items():
            for e in u['entities']:
                if e.get('type') == 'CANARY':
                    continue
                tot_script[e['script']] += 1
                tot_channel[e['channel']] += 1
                surface = _kit_norm(e['surface'])
                hay = fname if e['channel'] == 'filename' else text
                if not (exists or e['channel'] == 'filename') or not surface:
                    hit = False
                elif e['type'] in ('PATIENT_NAME', 'RELATIVE_NAME', 'VILLAGE') and e['channel'] != 'filename':
                    # Official rule (docs/SCORING.md): whole-word occurrences, minus those
                    # allowed inside preserve probes such as "Dr. Ramesh Tripathi".
                    pat = re.compile(r'(?<![\w\u0900-\u097f])' + re.escape(surface) + r'(?![\w\u0900-\u097f])')
                    allowed = sum(len(pat.findall(_kit_norm(pv['text']))) for uu in f['units'].values()
                                  for pv in uu.get('preserve') or [])
                    hit = len(pat.findall(hay)) > allowed
                else:
                    hit = surface in hay
                if hit:
                    leaks[e['type']] += 1
                    by_script[e['script']] += 1
                    by_channel[e['channel']] += 1
                    if len(examples) < show:
                        examples.append((e['type'], e['script'], e['channel'], rel, loc, e['surface']))
                else:
                    kept[e['type']] += 1
            if exists:
                for pv in u.get('preserve') or []:
                    pres_all += 1
                    ok = _kit_norm(pv['text']) in text
                    pres_ok += ok
                    if not ok:
                        lost[pv['kind']] += 1
    everything = []
    for dp, _, fn in os.walk(out):
        for n in fn:
            everything.append(n)
            everything.append(_kit_read(Path(dp) / n))
    everything = _kit_norm('\n'.join(everything))
    canaries = {_kit_norm(e['surface']) for f in truth['files'].values() for u in f['units'].values()
                for e in u['entities'] if e.get('type') == 'CANARY'}
    total = sum(leaks.values()) + sum(kept.values())
    return {'pii_leaked': f'{sum(leaks.values())}/{total}',
            'leaked_by_type': {t: f'{leaks[t]}/{leaks[t] + kept[t]}' for t in sorted(set(leaks) | set(kept))},
            'leaked_by_script': {s_: f'{by_script[s_]}/{tot_script[s_]}' for s_ in sorted(tot_script)},
            'leaked_by_channel': {c: f'{by_channel[c]}/{tot_channel[c]}' for c in sorted(tot_channel)},
            'canaries_found': f'{sum(1 for c in canaries if c and c in everything)}/{len(canaries)}',
            'medical_kept': f'{pres_ok}/{pres_all}', 'medical_lost_by_kind': dict(lost.most_common()),
            'raw_copies': copied_raw, 'examples': examples}


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
DATE_RE = re.compile(r'\d{1,4}[-/.](?:\d{1,2}|[A-Za-z]{3})[-/.]\d{2,4}')


def intervals(truth, report, texts):
    from datetime import date
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
                if m and value is None:
                    mm = re.fullmatch(r'(\d{1,2})-([A-Za-z]{3})-(\d{4})', m[1])
                    if mm and mm[2][:3].lower() in _MON:
                        value = date(int(mm[3]), _MON.index(mm[2][:3].lower()) + 1, int(mm[1]))
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


def record_text(out_root_texts, file, loc):
    """Text of one exported record: a CSV/TSV row, a JSON pointer target, or a doc."""
    import csv as _csv
    import io as _io
    text = out_root_texts.get(file, '')
    if loc.startswith('row:'):
        rows = list(_csv.reader(_io.StringIO(text), delimiter='\t' if file.endswith('.tsv') else ','))
        i = int(loc[4:]) + 1
        return ' '.join(rows[i]) if i < len(rows) else ''
    if loc.startswith('/'):
        try:
            node = json.loads(text)
            for part in loc.strip('/').split('/'):
                part = part.replace('~1', '/').replace('~0', '~')
                node = node[int(part)] if isinstance(node, list) else node[part]
            return json.dumps(node, ensure_ascii=False)
        except (ValueError, KeyError, IndexError, TypeError):
            return text
    return text


def candidates(reg, districts, blob):
    """Registry filters in the documented order; a filter that would empty the set is skipped."""
    cands = reg

    def narrow(keep):
        nonlocal cands
        got = [c for c in cands if keep(c)]
        cands = got or cands

    dist = [d for d in districts if re.search(r'(?<!\w)' + re.escape(d) + r'(?!\w)', blob)]
    if dist:
        narrow(lambda c: c['district'] in dist)
    g = re.findall(r'(?<![A-Za-z])(?:/\s*|Sex:\s*|gender\W+|Gender,?\s*)([MF])\b', blob)
    g += ['F' for _ in re.findall(r'"gender": "female"', blob)] + ['M' for _ in re.findall(r'"gender": "male"', blob)]
    if g:
        narrow(lambda c: c['gender'] == g[0])
    m = AGE_BAND.search(blob)
    if m:
        lo, hi = (int(m[1]), int(m[2])) if m[1] else (int(m[3]), 130)
        narrow(lambda c: lo - 1 <= int(c['age'] or -9) <= hi + 2)
    pins = re.findall(r'(?<!\d)([1-9]\d{5})(?!\d)', blob)
    if pins:
        narrow(lambda c: c['pin'] in pins)
    prefixes = re.findall(r'(?<!\d)([1-9]\d{2})(?:XXX|\*\*\*)', blob)
    if prefixes:
        narrow(lambda c: c['pin'][:3] in prefixes)
    return cands


def registry_attack(kit: Path, truth, report, texts, records):
    """Sweeney-style attack (docs/ATTACKS.md A2-A4), our approximation.

    Record level: every exported patient record is attacked on its own.
    Profile level: records sharing a pseudonym are pooled and attacked again.
    Evidence: district, gender, age band, PIN / PIN prefix visible in the output.
    Risk = probability mass on the true person (uniform over candidates).
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

    def risk(blob, pt):
        cands = candidates(reg, districts, blob)
        return (1 / len(cands)) if any(c['rid'] == rid[pt] for c in cands) else 0.0

    record_risks = []
    for r in records:
        pt = truth_patient.get((r['file'], r['loc']))
        if pt in rid:
            record_risks.append(risk(record_text(texts, r['file'], r['loc']), pt))
    profiles = defaultdict(list)
    for r in records:
        if r['patient']:
            profiles[r['patient']].append(r)
    profile_risks = []
    for psn, recs in profiles.items():
        pt = Counter(truth_patient.get((r['file'], r['loc'])) for r in recs).most_common(1)[0][0]
        if pt in rid:
            blob = ' '.join(record_text(texts, r['file'], r['loc']) for r in recs)
            profile_risks.append(risk(blob, pt))
    mean = lambda xs: round(sum(xs) / len(xs), 4) if xs else 0
    return {'records_attacked': len(record_risks),
            'record_mean_true_person_probability': mean(record_risks),
            'records_reidentified_conf>=0.5': sum(x >= 0.5 for x in record_risks),
            'profiles_attacked': len(profile_risks),
            'profile_mean_true_person_probability': mean(profile_risks),
            'profiles_reidentified_conf>=0.5': sum(x >= 0.5 for x in profile_risks)}


_NUM = re.compile(r'(?<![\d/.-])(\d{4})-(\d{2})-(\d{2})|(?<![\d/.-])(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?![\d/])')
_TXT = re.compile(r'(?<!\w)(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{4})', re.I)
_MON = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']


def dates_in(text):
    from datetime import date
    out = set()
    for m in _NUM.finditer(text):
        try:
            if m[1]:
                out.add(date(int(m[1]), int(m[2]), int(m[3])))
            else:
                a, b, y = int(m[4]), int(m[5]), int(m[6])
                for d, mo in ((a, b), (b, a)):        # the attacker tries both orders
                    try:
                        out.add(date(y, mo, d))
                    except ValueError:
                        pass
        except ValueError:
            pass
    for m in _TXT.finditer(text):
        try:
            out.add(date(int(m[3]), _MON.index(m[2][:3].lower()) + 1, int(m[1])))
        except ValueError:
            pass
    return out


def targeted_attack(kit: Path, truth, report, texts, records):
    """docs/ATTACKS.md A5: known visit date / condition / stay length / hospital,
    with global-shift recovery. Profiles = pseudonym groups + unlinked records."""
    import csv
    from datetime import date, timedelta
    reg = {r['rid']: r for r in csv.DictReader((kit / 'dev/attacker/registry.csv').open(encoding='utf-8'))}
    districts = sorted({r['district'] for r in reg.values()}, key=len, reverse=True)
    facts = [json.loads(l) for l in (kit / 'dev/attacker/known_facts.jsonl').read_text(encoding='utf-8').splitlines() if l]
    by_sha = {f['input_sha256']: f['output'] for f in report['files']}
    truth_patient = {}
    for meta in truth['files'].values():
        out = by_sha.get(meta.get('sha256'))
        for loc, unit in meta.get('units', {}).items():
            if unit.get('patient'):
                truth_patient[(out, loc)] = unit['patient']
    rid_of = {pt: info['rid'] for pt, info in truth['patients'].items()}
    groups = defaultdict(list)
    for i, r in enumerate(records):
        groups[r['patient'] or ('solo', i)].append(r)
    profiles = []
    for key, recs in groups.items():
        texts_ = [record_text(texts, r['file'], r['loc']) for r in recs]
        blob = ' '.join(texts_)
        intervals = set()
        for t in texts_:
            ds = sorted(dates_in(t))
            intervals.update((b - a).days for a in ds for b in ds if b > a)
        pt = Counter(truth_patient.get((r['file'], r['loc'])) for r in recs).most_common(1)[0][0]
        profiles.append({'blob': blob.casefold(), 'dates': dates_in(blob), 'intervals': intervals,
                         'rid': rid_of.get(pt), 'raw': blob})

    def consistent(p, person):
        dist = [d for d in districts if re.search(r'(?<!\w)' + re.escape(d) + r'(?!\w)', p['raw'])]
        if dist and person['district'] not in dist:
            return False
        g = re.findall(r'(?<![A-Za-z])(?:/\s*|Sex:\s*)([MF])\b', p['raw'])
        if g and g[0] != person['gender']:
            return False
        m = AGE_BAND.search(p['raw'])
        if m and person['age']:
            lo, hi = (int(m[1]), int(m[2])) if m[1] else (int(m[3]), 130)
            if not lo - 1 <= int(person['age']) <= hi + 2:
                return False
        return True

    cond_count = Counter()
    for f in facts:
        c = f.get('condition_hint')
        if c:
            cond_count[c] = sum(c.casefold() in p['blob'] for p in profiles)

    def weights(f, shift=0):
        person = reg.get(f['rid'])
        known = {date.fromisoformat(d) for d in f['visit_dates']}
        out = []
        for p in profiles:
            if person is None or not consistent(p, person):
                out.append(0.0)
                continue
            w = 0.0
            if known & {d + timedelta(days=shift) for d in p['dates']}:
                w += 1
            c = f.get('condition_hint')
            if c and c.casefold() in p['blob']:
                w += 8 if cond_count[c] <= 3 else 1
            if f.get('stay_days') and f['stay_days'] in p['intervals']:
                w += 1
            if w and f['hospital'].casefold() in p['blob']:
                w *= 2
            out.append(w)
        return out

    # Global-shift recovery from confidently identified people.
    offsets = Counter()
    for f in facts:
        w = weights(f)
        total = sum(w)
        for p, x in zip(profiles, w):
            if total and x / total >= 0.9:
                for d in p['dates']:
                    for k in f['visit_dates']:
                        offsets[((date.fromisoformat(k) - d).days, f['rid'])] += 1
    per_offset = Counter(o for o, _ in offsets)
    shift = next((o for o, n in per_offset.most_common() if n >= 2 and o != 0), 0)
    success, confident, decoy_claims, real = [], 0, 0, 0
    for f in facts:
        w = weights(f, shift)
        total = sum(w)
        if f['rid'] not in rid_of.values():
            decoy_claims += total > 0
            continue
        real += 1
        prob = sum(x for p, x in zip(profiles, w) if p['rid'] == f['rid']) / total if total else 0.0
        success.append(prob)
        confident += prob >= 0.5
    return {'known_people': real, 'mean_success_probability': round(sum(success) / len(success), 4) if success else 0,
            'identified_conf>=0.5': confident, 'global_shift_recovered': bool(shift), 'decoys_claimed': decoy_claims}


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
    ap.add_argument('--show', type=int, default=0, help='list this many leak examples (local debugging only)')
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
        result['targeted_attack'] = targeted_attack(args.kit, truth, report, texts, records)
        result['kit_selfcheck'] = kit_selfcheck(args.kit, args.output, args.show)
    if args.scale:
        result['scale'] = scale_run(args.kit, args.scale)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
