#!/usr/bin/env python3
"""Secret Wards HARDEST test scorer (Track 3). Standard library only.

    python3 score.py --data hardest_data --output my_output/
    python3 score.py --data hardest_data --output run1/ --output2 run2/ --output-other run3/ --show 25 --json score.json

--data          folder made by generate.py (contains dev/input, dev/truth, dev/attacker)
--output        your system's output folder (sanitized/, report.json, records.jsonl)
--output2       optional second run with the SAME secret   -> determinism check
--output-other  optional run with a DIFFERENT secret       -> cross-release linkability check
--logs          optional files your run printed (stdout/stderr) -> scanned for leaks

Leak detection is deliberately strict and adversarial, modelled on the
official docs/SCORING.md: both sides are normalised (NFKC, homoglyph fold,
zero-width removal, Indic digits -> ASCII, number words -> digits) and hidden
payloads (base64 incl. gzip, data URIs, percent-encoding, HTML entities,
\\uXXXX escapes) are decoded before matching. Doctor names and other preserve
probes are allowed occurrences. The total out of 100 approximates the
official weights; it is a practice guide, not the official score.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import gzip
import hashlib
import html
import io
import json
import math
import re
import unicodedata
import urllib.parse
from collections import Counter, defaultdict
from datetime import date
from itertools import combinations
from pathlib import Path

# ------------------------------------------------------------------ normalisation
CONFUSABLES = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'τ': 't', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H',
    'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'ⅼ': 'l', '‑': '-', '‐': '-'})
INVISIBLE = re.compile('[­​-‏⁠-⁤﻿͏]')
NUMBER_WORDS = {w: str(i) for i, ws in enumerate([
    ['zero', 'shunya', 'शून्य'], ['one', 'ek', 'एक'], ['two', 'do', 'दो'], ['three', 'teen', 'तीन'], ['four', 'char', 'chaar', 'चार'],
    ['five', 'paanch', 'panch', 'पांच', 'पाँच'], ['six', 'chhe', 'chhah', 'छह', 'छः'], ['seven', 'saat', 'सात'],
    ['eight', 'aath', 'आठ'], ['nine', 'nau', 'नौ']]) for w in ws}
_B64 = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
_UESC = re.compile(r'\\u([0-9a-fA-F]{4})')


def fold(text: str) -> str:
    if text.isascii():
        return ' '.join(text.casefold().split())
    text = unicodedata.normalize('NFKC', text)
    text = INVISIBLE.sub('', text).translate(CONFUSABLES)
    out = []
    for ch in text:
        if ch.isdecimal() and not ('0' <= ch <= '9'):
            out.append(str(unicodedata.decimal(ch)))
        else:
            out.append(ch)
    text = ''.join(out)
    # strip Latin diacritics only (Devanagari vowel signs are combining marks too)
    text = ''.join(c for c in unicodedata.normalize('NFKD', text)
                   if not (unicodedata.combining(c) and not ('ऀ' <= c <= 'ॿ')))
    return ' '.join(unicodedata.normalize('NFC', text).casefold().split())


def reveal(text: str, depth: int = 0) -> str:
    """Append decoded hidden payloads. Whole-text decoders (percent, HTML, \\u)
    run once; base64 pieces (incl. gzip and data URIs) are decoded recursively."""
    if depth > 2 or not text:
        return text
    extra = []
    if depth == 0:
        if '%' in text:
            u = text
            for _ in range(3):
                v = urllib.parse.unquote(u)
                if v == u:
                    break
                u = v
            if u != text:
                extra.append(u)
        if '&' in text:
            h = html.unescape(text)
            if h != text:
                extra.append(h)
        if '\\u' in text:
            extra.append(_UESC.sub(lambda m: chr(int(m[1], 16)), text))
    for m in _B64.finditer(text):
        tok = m[0]
        try:
            raw = base64.b64decode(tok + '=' * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        if raw[:2] == b'\x1f\x8b':
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                continue
        piece = raw.decode('utf-8', 'ignore')
        if piece and sum(c.isprintable() for c in piece) > 0.8 * len(piece):
            extra.append(reveal(piece, depth + 1))
    return text + '\n' + '\n'.join(extra) if extra else text


def digits_view(text: str) -> str:
    words = re.findall(r'[\wऀ-ॿ]+|[^\wऀ-ॿ]', fold(text))
    out = []
    for w in words:
        if w in NUMBER_WORDS:
            out.append(NUMBER_WORDS[w])
        elif w.isdigit():
            out.append(w)
        elif any(c.isdigit() for c in w):
            out.append('|' + ''.join(c for c in w if c.isdigit()))   # "uhid010026" -> 010026
        elif w.strip() and not w.isspace() and w not in '-./()+: ,\n\t':
            out.append('|')
    return re.sub(r'\|+', '|', ''.join(out))


def read_text(p: Path) -> str:
    try:
        raw = p.read_bytes()[:60_000_000]
    except OSError:
        return ''
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            return raw.decode('utf-16')
        except UnicodeDecodeError:
            pass
    return raw.decode('utf-8', 'replace')


# ------------------------------------------------------------------ dates
HI_MONTHS = ['जनवरी', 'फ़रवरी', 'मार्च', 'अप्रैल', 'मई', 'जून', 'जुलाई', 'अगस्त', 'सितंबर', 'अक्टूबर', 'नवंबर', 'दिसंबर']
EN_MON = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']


def _d(y, m, d):
    try:
        if y < 100:
            y += 2000 if y <= 30 else 1900
        return date(y, m, d)
    except ValueError:
        return None


def all_dates(text: str):
    """Every calendar date a reader could resolve, in any common Indian format (both D/M orders)."""
    t = fold(text)
    found = set()
    for m in re.finditer(r'(?<!\d)(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?!\d)', t):
        found.add(_d(int(m[1]), int(m[2]), int(m[3])))
    for m in re.finditer(r'(?<!\d)(\d{1,2})[-/.](\d{1,2})[-/.](\d{4}|\d{2})(?!\d)', t):
        a, b, y = int(m[1]), int(m[2]), int(m[3])
        found.add(_d(y, b, a))
        found.add(_d(y, a, b))
    for m in re.finditer(r"(?<!\d)(\d{1,2})(?:st|nd|rd|th)?[\s-]+([a-z]{3})[a-z]*[\s,-]+'?(\d{4}|\d{2})(?!\d)", t):
        if m[2] in EN_MON:
            found.add(_d(int(m[3]), EN_MON.index(m[2]) + 1, int(m[1])))
    for i, mon in enumerate(HI_MONTHS):
        for m in re.finditer(r'(\d{1,2})\s*' + re.escape(fold(mon)) + r'\s*(\d{4})', t):
            found.add(_d(int(m[2]), i + 1, int(m[1])))
    found.discard(None)
    return found


def date_after(text: str, anchor: str):
    t = fold(text)
    i = t.find(fold(anchor))
    if i < 0:
        return None
    window = t[i + len(fold(anchor)): i + len(fold(anchor)) + 40].lstrip(' "\':')
    ds = all_dates(window[:30])
    m = re.match(r'(\d{4})-(\d{2})-(\d{2})', window)
    if m:
        return _d(int(m[1]), int(m[2]), int(m[3]))
    m = re.match(r'(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})', window)
    if m:
        return _d(int(m[3]), int(m[2]), int(m[1]))
    return sorted(ds)[0] if ds else None


# ------------------------------------------------------------------ release loading
def load_release(out: Path):
    report = {}
    try:
        report = json.loads((out / 'report.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        pass
    records = []
    try:
        for line in (out / 'records.jsonl').read_text(encoding='utf-8').splitlines():
            if line.strip():
                records.append(json.loads(line))
    except (OSError, ValueError):
        pass
    files = {}
    san = out / 'sanitized'
    if san.is_dir():
        for p in sorted(san.rglob('*')):
            if p.is_file():
                files[p.relative_to(san).as_posix()] = p
    return report, records, files


_PARSED = {}


def _parsed(text, path, kind):
    key = (kind, path, len(text), hash(text[:200]), hash(text[-200:]))
    if key not in _PARSED:
        if len(_PARSED) > 64:
            _PARSED.clear()
        try:
            _PARSED[key] = (list(csv.reader(io.StringIO(text), delimiter='\t' if path.endswith('.tsv') else ','))
                            if kind == 'csv' else json.loads(text))
        except (csv.Error, ValueError):
            _PARSED[key] = None
    return _PARSED[key]


def record_text(text: str, path: str, loc: str) -> str:
    if loc.startswith('row:'):
        rows = _parsed(text, path, 'csv')
        if rows is None:
            return text
        try:
            i = int(loc[4:]) + 1
        except ValueError:
            return text
        return '\t'.join(rows[i]) if i < len(rows) else ''
    if loc.startswith('/'):
        try:
            node = _parsed(text, path, 'json')
            if node is None:
                return text
            for part in loc.strip('/').split('/'):
                part = part.replace('~1', '/').replace('~0', '~')
                node = node[int(part)] if isinstance(node, list) else node[part]
            return json.dumps(node, ensure_ascii=False)
        except (ValueError, KeyError, IndexError, TypeError):
            return text
    return text


# ------------------------------------------------------------------ scoring
def f_beta(p, r, b):
    return (1 + b * b) * p * r / (b * b * p + r) if p + r else 0.0


class Scorer:
    def __init__(self, data: Path, out: Path, show=0, logs=()):
        self.data, self.out, self.show = data, out, show
        self.truth = json.loads((data / 'dev/truth/truth.json').read_text(encoding='utf-8'))
        self.report, self.records, self.files = load_release(out)
        self.by_sha = {e.get('input_sha256'): e for e in self.report.get('files') or []}
        self.logs = '\n'.join(read_text(Path(x)) for x in logs)
        self.cache = {}
        self.examples = []

    def out_path(self, meta):
        e = self.by_sha.get(meta['sha256'])
        if e and e.get('output'):
            return str(e['output']).replace('sanitized/', '', 1)
        return meta['path'] if meta['path'] in self.files else None

    def text_of(self, rel):
        if rel not in self.cache:
            raw = read_text(self.files[rel]) if rel in self.files else ''
            full = reveal(raw)
            self.cache[rel] = (raw, fold(full), digits_view(full))
        return self.cache[rel]

    # ---- 1. detection
    def detection(self):
        leaks, total = Counter(), Counter()
        by_script, tot_script, by_ch, tot_ch, by_obf, tot_obf = (Counter() for _ in range(6))
        direct_leaks = set()
        out_names = fold(re.sub(r'[_\-./]', ' ', ' '.join(self.files)))
        for path, meta in self.truth['files'].items():
            rel = self.out_path(meta)
            exported = rel is not None
            raw, text, digs = self.text_of(rel) if exported else ('', '', '')
            allowed_text = fold(' '.join(pv['text'] for u in meta['units'].values() for pv in u.get('preserve', [])))
            for loc, u in meta['units'].items():
                for e in u['entities']:
                    if e['type'] == 'CANARY':
                        continue
                    hay, hay_d = (fold(re.sub(r'[_\-.]', ' ', rel or '')), digits_view(rel or '')) if e['channel'] == 'filename' else (text, digs)
                    if e['channel'] == 'folder':
                        hay, hay_d = out_names, ''
                    hit = self._hit(e, hay, hay_d, allowed_text) if (exported or e['channel'] in ('filename', 'folder')) else 0.0
                    k = e['type']
                    total[k] += 1
                    leaks[k] += hit
                    tot_script[e['script']] += 1
                    by_script[e['script']] += hit
                    tot_ch[e['channel']] += 1
                    by_ch[e['channel']] += hit
                    if e.get('obfuscation'):
                        tot_obf[e['obfuscation']] += 1
                        by_obf[e['obfuscation']] += hit
                    if hit and k in ('AADHAAR', 'ABHA_NUMBER', 'PHONE', 'PAN', 'EMAIL', 'MRN', 'PATIENT_NAME', 'VOTER_ID'):
                        direct_leaks.add((k, e.get('key') if e.get('match') != 'name' else ' '.join(e['tokens'])))
                    if hit and len(self.examples) < self.show:
                        self.examples.append(f"{k:14} {e['script']:8} {e['channel']:18} {e.get('obfuscation') or '':22} {path} :: {e['surface'][:50]!r}")
        weights = {'AADHAAR': 1, 'ABHA_NUMBER': 1, 'PHONE': 1, 'EMAIL': 1, 'MRN': 1, 'PAN': 1, 'PATIENT_NAME': 1, 'VOTER_ID': 1,
                   'RELATIVE_NAME': .8, 'DOB': .7, 'HOUSE': .6, 'LOCALITY': .6, 'LANDMARK': .5, 'VILLAGE': .5, 'PIN': .5,
                   'ABHA_ADDRESS': 1, 'INSURANCE_ID': 1, 'PMJAY_ID': 1, 'STAFF_NAME': .8}
        rec_type = sum(weights.get(k, .5) * (1 - leaks[k] / total[k]) for k in total) / sum(weights.get(k, .5) for k in total)
        rec_script = sum(1 - by_script[s] / tot_script[s] for s in tot_script) / len(tot_script)
        recall = 0.5 * rec_type + 0.5 * rec_script
        return {'recall': recall, 'leaked_total': sum(leaks.values()), 'mentions': sum(total.values()),
                'by_type': {k: (round(leaks[k], 1), total[k]) for k in sorted(total)},
                'by_script': {k: (round(by_script[k], 1), tot_script[k]) for k in sorted(tot_script)},
                'by_channel': {k: (round(by_ch[k], 1), tot_ch[k]) for k in sorted(tot_ch)},
                'by_obfuscation': {k: (round(by_obf[k], 1), tot_obf[k]) for k in sorted(tot_obf)},
                'direct_unique_leaks': len(direct_leaks)}

    @staticmethod
    def _count(pattern, s):
        return len(re.findall(pattern, s))

    def _hit(self, e, hay, hay_d, allowed_text):
        m = e.get('match')
        if m == 'name':
            toks = [fold(t) for t in e.get('tokens', []) if len(t) > 2]
            if not toks:
                return 0.0
            got = 0
            for t in toks:
                pat = r'(?<![\wऀ-ॿ])' + re.escape(t) + r'(?![\wऀ-ॿ])'
                if self._count(pat, hay) > self._count(pat, allowed_text):
                    got += 1
            return got / len(toks)
        if m == 'digits':
            key = e.get('key') or ''
            if len(key) >= 5 and key in hay_d:
                return 1.0
            if len(key) >= 6 and key in hay_d.replace('|', ''):
                return 1.0
            surf = fold(e['surface'])
            return 1.0 if surf and surf in hay else 0.0
        if m == 'dob':
            try:
                true = date.fromisoformat(e['key'])
            except (TypeError, ValueError):
                return 0.0
            return 1.0 if true in all_dates(hay) else 0.0
        key = fold(e.get('key') or e['surface'])
        if not key:
            return 0.0
        pat = r'(?<![\wऀ-ॿ])' + re.escape(key) + r'(?![\wऀ-ॿ])'
        return 1.0 if self._count(pat, hay) > self._count(pat, allowed_text) else 0.0

    # ---- canaries anywhere
    def canaries(self):
        pats = {c: [re.compile(r'(?<![\w])' + re.escape(fold(t)) + r'(?![\w])') for t in c.split()]
                for c in self.truth.get('canaries', [])}
        found = set()

        def scan(text):
            t = fold(text.replace('_', ' '))
            for c, ps in pats.items():
                if c not in found and any(p.search(t) for p in ps):
                    found.add(c)
        scan(' '.join(self.files) + '\n' + self.logs)
        for p in self.out.rglob('*'):
            if p.is_file():
                scan(p.as_posix())
                rel = p.relative_to(self.out / 'sanitized').as_posix() if (self.out / 'sanitized') in p.parents else None
                scan(self.text_of(rel)[1] if rel in self.files else reveal(read_text(p)))
        return [c for c in pats if c in found]

    # ---- 2. utility
    def utility(self):
        kept = total = 0
        lost = Counter()
        trap_ok, trap_all = Counter(), Counter()
        for path, meta in self.truth['files'].items():
            rel = self.out_path(meta)
            text = self.text_of(rel)[1] if rel else ''
            for u in meta['units'].values():
                for pv in u.get('preserve', []):
                    total += 1
                    ok = rel is not None and fold(pv['text']) in text
                    kept += ok
                    if not ok:
                        lost[pv['kind']] += 1
                    if pv.get('trap'):
                        trap_all[pv['trap']] += 1
                        trap_ok[pv['trap']] += ok
        ctx = sum(trap_ok[t] / trap_all[t] for t in trap_all) / len(trap_all) if trap_all else 1.0
        return {'probes_kept': kept, 'probes': total, 'lost_by_kind': dict(lost.most_common()),
                'contextual_precision': ctx, 'by_trap': {t: (trap_ok[t], trap_all[t]) for t in sorted(trap_all)}}

    def dates(self):
        ok = bad = unshifted = checked = 0
        for path, meta in self.truth['files'].items():
            rel = self.out_path(meta)
            if not rel:
                continue
            raw = self.text_of(rel)[0]
            for loc, u in meta['units'].items():
                rt = record_text(raw, rel, loc)
                ds = [d for d in u.get('dates', []) if d.get('anchor')]
                vals = [(d, date_after(rt, d['anchor'])) for d in ds]
                for d in u.get('dates', []):
                    checked += 1
                    if fold(d['surface']) in fold(rt):
                        unshifted += 1
                for (d1, v1), (d2, v2) in combinations(vals, 2):
                    if v1 is None or v2 is None:
                        bad += 1
                        continue
                    true_gap = (date.fromisoformat(d2['true']) - date.fromisoformat(d1['true'])).days
                    ok += (v2 - v1).days == true_gap
                    bad += (v2 - v1).days != true_gap
        return {'intervals_kept': ok, 'intervals': ok + bad, 'dates_left_unshifted': unshifted, 'dates_checked': checked}

    # ---- 3. linkage
    def linkage(self):
        claims = defaultdict(dict)
        for r in self.records:
            claims[str(r.get('file', '')).replace('sanitized/', '', 1)][r.get('loc')] = r.get('patient')

        def lookup(rel, loc):
            recs = claims.get(rel, {})
            if loc in recs:
                return recs[loc]
            if loc.startswith('/'):
                parts = loc.split('/')
                for i in range(len(parts) - 1, 1, -1):
                    if '/'.join(parts[:i]) in recs:
                        return recs['/'.join(parts[:i])]
            return recs.get('doc')

        units = []
        consistent = claimed = 0
        for path, meta in self.truth['files'].items():
            rel = self.out_path(meta)
            raw = self.text_of(rel)[0] if rel else ''
            for loc, u in meta['units'].items():
                if loc.startswith('@'):
                    continue
                y = lookup(rel, loc) if rel else None
                units.append((u.get('patient'), u.get('link'), y))
                if y:
                    claimed += 1
                    consistent += y in record_text(raw, rel, loc)
        tp = fp = 0
        pred = defaultdict(list)
        for i, (t, l, y) in enumerate(units):
            if y:
                pred[y].append(i)
        for m in pred.values():
            for a, b in combinations(m, 2):
                if units[a][0] and units[a][0] == units[b][0]:
                    tp += 1
                else:
                    fp += 1
        by_t = defaultdict(list)
        for i, (t, l, y) in enumerate(units):
            if t and l == 'required':
                by_t[t].append(i)
        need = sum(len(v) * (len(v) - 1) // 2 for v in by_t.values())
        found = sum(1 for v in by_t.values() for a, b in combinations(v, 2) if units[a][2] and units[a][2] == units[b][2])
        p = tp / (tp + fp) if tp + fp else (1.0 if not need else 0.0)
        r = found / need if need else 1.0
        # B-cubed over required records
        req = [i for i, u in enumerate(units) if u[0] and u[1] == 'required']
        bp = br = 0.0
        n_t = Counter(units[i][0] for i in req)
        n_y = Counter(units[i][2] for i in req if units[i][2])
        n_ty = Counter((units[i][0], units[i][2]) for i in req if units[i][2])
        for i in req:
            t, _, y = units[i]
            inter = n_ty[(t, y)] if y else 1
            bp += inter / (n_y[y] if y else 1)
            br += inter / n_t[t]
        b3 = f_beta(bp / len(req), br / len(req), 1) if req else 0.0
        psn_of = defaultdict(set)
        for t, l, y in units:
            if t and y:
                psn_of[t].add(y)
        traps = self.truth.get('traps', {})

        def separated(pairs):
            pairs = [x for x in pairs if isinstance(x, list) and len(x) == 2]
            return sum(not (psn_of[a] & psn_of[b]) for a, b in pairs), len(pairs)

        def linked(pts):
            ok = tot = 0
            for pt in pts:
                ids = [units[i][2] for i in by_t.get(pt, [])]
                pairs = list(combinations(ids, 2))
                tot += len(pairs)
                ok += sum(1 for a, b in pairs if a and a == b)
            return ok, tot

        trap = {'homonyms_separated': separated(traps.get('homonym_pairs', [])), 'twins_separated': separated(traps.get('twins', [])),
                'father_son_separated': separated(traps.get('father_son_same_name', [])),
                'shared_phone_family_separated': separated(traps.get('shared_phone_family', [])),
                'newborn_twins_separated': separated([x for x in traps.get('newborn', []) if isinstance(x, list)]),
                'cross_script_linked': linked(traps.get('cross_script', [])), 'fragmented_linked': linked(traps.get('fragmented', [])),
                'spelling_variants_linked': linked(traps.get('spelling_variants', [])),
                'married_name_change_linked': linked(traps.get('married_name_change', []))}
        frac = [a / b for a, b in trap.values() if b]
        return {'precision': p, 'recall': r, 'f05': f_beta(p, r, .5), 'b3f1': b3, 'pseudonym_consistency': (consistent, claimed),
                'traps': trap, 'trap_score': sum(frac) / len(frac) if frac else 0.0, 'linkable_pairs': need, 'predicted_pairs': tp + fp}

    # ---- 4. privacy attacks
    def attacks(self, raw=False):
        reg = list(csv.DictReader((self.data / 'dev/attacker/registry.csv').open(encoding='utf-8')))
        for x in reg:
            x['_name'], x['_village'] = fold(x['name']), fold(x['village'])
        districts = sorted({x['district'] for x in reg}, key=len, reverse=True)
        dist_f = [(d, fold(d)) for d in districts]
        rid_of = {pt: v['rid'] for pt, v in self.truth['patients'].items()}
        recs = []
        for path, meta in self.truth['files'].items():
            if raw:
                src = self.data / 'dev/input' / path
                text = read_text(src) if src.is_file() else ''
                rel = path
            else:
                rel = self.out_path(meta)
                text = self.text_of(rel)[0] if rel else ''
            for loc, u in meta['units'].items():
                if loc.startswith('@') or not u.get('patient') or u['patient'] not in rid_of:
                    continue
                psn = u['patient'] if raw else None
                recs.append((u['patient'], record_text(text, rel or path, loc), (rel, loc), psn))
        if not raw:
            claim = {(str(r.get('file', '')).replace('sanitized/', '', 1), r.get('loc')): r.get('patient') for r in self.records}
            recs = [(pt, t, k, claim.get(k)) for pt, t, k, _ in recs]

        by_phone, by_dist = defaultdict(list), defaultdict(list)
        for x in reg:
            if x['phone']:
                by_phone[x['phone']].append(x)
            by_dist[x['district']].append(x)

        def cands(blob):
            c = reg
            b = fold(blob)

            def narrow(keep):
                nonlocal c
                got = [x for x in c if keep(x)]
                c = got or c
            ph = set(re.findall(r'(?<!\d)[6-9]\d{9}(?!\d)', digits_view(blob).replace('|', ' ')))
            hits = [x for p in ph for x in by_phone.get(p, [])]
            if hits:
                c = hits
            dist = [d for d, fd in dist_f if fd in b]
            if dist:
                if c is reg:
                    c = [x for d in dist for x in by_dist[d]] or c
                else:
                    narrow(lambda x: x['district'] in dist)
            g = re.findall(r'(?<![a-z])(?:/\s*|sex:?\s*|gender"?:?\s*"?)(m|f|male|female)\b', b)
            if g:
                narrow(lambda x: x['gender'] == g[0][0].upper())
            m = re.search(r'(?<!\d)(\d{1,3})\s*-\s*(\d{1,3})(?=\s*(?:y|/|वर्ष|"|,|\t|$))', b) or re.search(r'(?<!\d)(\d{2,3})\+', b)
            if m and m.lastindex == 2:
                narrow(lambda x: int(m[1]) - 1 <= int(x['age'] or -9) <= int(m[2]) + 2)
            elif m:
                narrow(lambda x: int(x['age'] or -9) >= int(m[1]) - 1)
            else:
                a = re.search(r'(?:age|aayu|umar|आयु|उम्र)\D{0,12}(\d{1,3})(?!\d)|(?<!\d)(\d{1,3})\s*(?:yrs?|y)\s*/', b)
                if a:
                    v = int(a[1] or a[2])
                    narrow(lambda x: abs(int(x['age'] or -99) - v) <= 2)
            pins = set(re.findall(r'(?<!\d)([1-9]\d{5})(?!\d)', digits_view(blob).replace('|', ' ')))
            if pins:
                narrow(lambda x: x['pin'] in pins)
            pre = re.findall(r'(?<!\d)([1-9]\d{2})(?:xxx|\*\*\*)', b)
            if pre:
                narrow(lambda x: x['pin'][:3] in pre)
            vill = {x['_village'] for x in c if x['_village'] and x['_village'] in b}
            if vill:
                narrow(lambda x: x['_village'] in vill)
            names = [x for x in c if x['_name'] in b]
            return names or c

        def risk(blob, pt):
            c = cands(blob)
            return 1 / len(c) if any(x['rid'] == rid_of[pt] for x in c) else 0.0

        rec_r = [risk(t, pt) for pt, t, _, _ in recs]
        prof = defaultdict(list)
        for pt, t, k, psn in recs:
            if psn:
                prof[psn].append((pt, t))
        prof_r = []
        for psn, items in prof.items():
            pt = Counter(a for a, _ in items).most_common(1)[0][0]
            prof_r.append(risk(' '.join(t for _, t in items), pt))
        direct = sum(1 for x in rec_r if x >= 0.999) / len(rec_r) if rec_r else 0.0
        mean = lambda xs: sum(xs) / len(xs) if xs else 0.0
        return {'record_mean_risk': mean(rec_r), 'records_identified': sum(x >= .5 for x in rec_r), 'records': len(rec_r),
                'profile_identified': sum(x >= .5 for x in prof_r), 'profiles': len(prof_r), 'profile_mean_risk': mean(prof_r),
                'direct_exposure': direct, 'targeted': self.targeted(reg, dist_f, recs, rid_of)}

    def targeted(self, reg, dist_f, recs, rid_of):
        facts = [json.loads(l) for l in (self.data / 'dev/attacker/known_facts.jsonl').read_text(encoding='utf-8').splitlines() if l]
        regmap = {x['rid']: x for x in reg}
        groups = defaultdict(list)
        for i, (pt, t, k, psn) in enumerate(recs):
            groups[psn or ('solo', i)].append((pt, t))
        profiles = []
        for key, items in groups.items():
            blob = ' '.join(t for _, t in items)
            ivals = set()
            for _, t in items:
                ds = sorted(all_dates(t))
                ivals.update((b - a).days for a in ds for b in ds if b > a)
            profiles.append({'blob': fold(blob), 'dates': all_dates(blob), 'iv': ivals,
                             'rid': rid_of.get(Counter(a for a, _ in items).most_common(1)[0][0])})
        for p in profiles:
            p['dist'] = {d for d, fd in dist_f if fd in p['blob']}
        cc = {f.get('condition_hint'): sum(fold(f['condition_hint']) in p['blob'] for p in profiles) for f in facts if f.get('condition_hint')}
        succ, conf, decoys = [], 0, 0
        rids = set(rid_of.values())
        for f in facts:
            person = regmap.get(f['rid'])
            known = {date.fromisoformat(d) for d in f['visit_dates']}
            cond_f = fold(f['condition_hint']) if f.get('condition_hint') else None
            hosp_f = fold(f['hospital'])
            w = []
            for p in profiles:
                if person is None:
                    w.append(0.0)
                    continue
                dist = p['dist']
                if dist and person['district'] not in dist:
                    w.append(0.0)
                    continue
                x = 1.0 if known & p['dates'] else 0.0
                c = f.get('condition_hint')
                if cond_f and cond_f in p['blob']:
                    x += 8 if cc.get(c, 99) <= 3 else 1
                if f.get('stay_days') and f['stay_days'] in p['iv']:
                    x += 1
                if x and hosp_f in p['blob']:
                    x *= 2
                w.append(x)
            tot = sum(w)
            if f['rid'] not in rids:
                decoys += tot > 0
                continue
            pr = sum(x for p, x in zip(profiles, w) if p['rid'] == f['rid']) / tot if tot else 0.0
            succ.append(pr)
            conf += pr >= .5
        return {'known_people': len(succ), 'mean_success': sum(succ) / len(succ) if succ else 0.0,
                'identified': conf, 'decoys_claimed': decoys}

    # ---- 5. integrity
    def integrity(self):
        inputs = {m['sha256']: m for m in self.truth['files'].values()}
        n_inputs = len(self.truth['files'])
        entries = self.report.get('files') or []
        listed = {e.get('input_sha256') for e in entries}
        silent = sum(1 for sha in inputs if sha not in listed and inputs[sha]['path'] not in self.files)
        raw_copies = 0
        bad_format = 0
        for path, meta in self.truth['files'].items():
            rel = self.out_path(meta)
            src = self.data / 'dev/input' / path
            if meta.get('expect') == 'quarantine' and rel and rel in self.files and src.is_file():
                if self.files[rel].read_bytes() == src.read_bytes():
                    raw_copies += 1
        for rel, p in self.files.items():
            data = p.read_bytes()
            try:
                text = (data[3:] if data.startswith(b'\xef\xbb\xbf') else data).decode('utf-8')
            except UnicodeDecodeError:
                bad_format += 1
                continue
            if rel.endswith('.json'):
                try:
                    json.loads(text)
                except ValueError:
                    bad_format += 1
            elif rel.endswith(('.csv', '.tsv')):
                try:
                    rows = list(csv.reader(io.StringIO(text), delimiter='\t' if rel.endswith('.tsv') else ','))
                    if rows and len({len(r) for r in rows if r}) > 1:
                        bad_format += 1
                except csv.Error:
                    bad_format += 1
        quarantine = [m for m in self.truth['files'].values() if m.get('expect') == 'quarantine']
        q_ok = sum(1 for m in quarantine if not self.out_path(m) or self.by_sha.get(m['sha256'], {}).get('status') in ('quarantined', 'suppressed'))
        counts = self.report.get('counts') or {}
        honest = (counts.get('files_total') == n_inputs, counts.get('files_sanitized') == len(self.files))
        return {'silent_drops': silent, 'raw_copies': raw_copies, 'bad_format_files': bad_format, 'exported_files': len(self.files),
                'quarantine_handled': (q_ok, len(quarantine)), 'report_honest': honest, 'report_present': bool(self.report),
                'timing': (self.report.get('timing') or {}).get('seconds'), 'peak_rss_mb': (self.report.get('resources') or {}).get('peak_rss_mb')}


def same_release(a: Path, b: Path):
    fa = {p.relative_to(a).as_posix(): p for p in (a / 'sanitized').rglob('*') if p.is_file()}
    fb = {p.relative_to(b).as_posix(): p for p in (b / 'sanitized').rglob('*') if p.is_file()}
    keys = set(fa) | set(fb)
    same = sum(1 for k in keys if k in fa and k in fb and fa[k].read_bytes() == fb[k].read_bytes())
    ra, rb = (x / 'records.jsonl' for x in (a, b))
    rec_same = ra.is_file() and rb.is_file() and ra.read_bytes() == rb.read_bytes()
    return (same + rec_same) / (len(keys) + 1) if keys else 0.0


def main():
    ap = argparse.ArgumentParser(description='Score a Secret Wards release against the hardest test answer key.')
    ap.add_argument('--data', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--output2', type=Path, help='second run, same secret (determinism)')
    ap.add_argument('--output-other', type=Path, help='run with a different secret (cross-release linkability)')
    ap.add_argument('--logs', nargs='*', default=[], help='stdout/stderr captures to scan for leaks')
    ap.add_argument('--show', type=int, default=0, help='print this many example leaks')
    ap.add_argument('--json', type=Path, help='also write the full result as JSON')
    a = ap.parse_args()

    s = Scorer(a.data, a.output, a.show, a.logs)
    det, util, dates_, link = s.detection(), s.utility(), s.dates(), s.linkage()
    can = s.canaries()
    integ = s.integrity()
    att, raw_att = s.attacks(), s.attacks(raw=True)
    det_s = f_beta(util['contextual_precision'], det['recall'], 2)
    ident = 0.4 * link['f05'] + 0.3 * link['b3f1'] + 0.3 * link['trap_score'] if any(r.get('patient') for r in s.records) else 0.0
    ratio = lambda x, y: min(1.0, x / y) if y else (0.0 if not x else 1.0)
    risks = [att['direct_exposure'], ratio(att['record_mean_risk'], raw_att['record_mean_risk']),
             ratio(att['profile_identified'] / max(1, att['profiles']), raw_att['profile_identified'] / max(1, raw_att['profiles'])),
             ratio(att['targeted']['mean_success'], raw_att['targeted']['mean_success'])]
    a7 = None
    if a.output_other:
        other = load_release(a.output_other)[1]
        mine = {r.get('patient') for r in s.records if r.get('patient')}
        theirs = {r.get('patient') for r in other if r.get('patient')}
        a7 = len(mine & theirs) / len(mine) if mine else 0.0
        risks.append(a7)
    risk = sum(risks) / len(risks)
    utility = (0.55 * util['probes_kept'] / max(1, util['probes'])
               + 0.25 * (dates_['intervals_kept'] / dates_['intervals'] if dates_['intervals'] else 1.0)
               + 0.20 * (1 - dates_['dates_left_unshifted'] / max(1, dates_['dates_checked'])))
    privacy = (1 - risk) * min(1.0, utility / 0.40)
    cons = link['pseudonym_consistency']
    integrity = (0.25 * (1 - integ['bad_format_files'] / max(1, integ['exported_files']))
                 + 0.15 * (cons[0] / cons[1] if cons[1] else 0.0)
                 + 0.25 * (integ['quarantine_handled'][0] / max(1, integ['quarantine_handled'][1]))
                 + 0.15 * (0 if can else 1)
                 + 0.20 * (sum(integ['report_honest']) / 2))
    t, mem = integ['timing'] or 900, integ['peak_rss_mb'] or 4096
    loglin = lambda v, good, bad: 1.0 if v <= good else 0.0 if v >= bad else 1 - math.log(v / good) / math.log(bad / good)
    det_run = same_release(a.output, a.output2) if a.output2 else None
    eff = 0.3 * (1.0 if integ['report_present'] else 0.0) + 0.3 * loglin(t, 60, 900) + 0.2 * loglin(mem, 512, 4096) \
        + 0.2 * (det_run if det_run is not None else 1.0)
    penalties = (min(25, det['direct_unique_leaks']) + min(15, 3 * len(can)) + min(20, 5 * integ['raw_copies'])
                 + (10 if not integ['report_present'] or integ['silent_drops'] else 0))
    total = 100 * (0.20 * det_s + 0.15 * ident + 0.25 * privacy + 0.20 * utility + 0.10 * integrity + 0.10 * eff) - penalties

    pct = lambda x, y: f'{100 * x / y:5.1f}%' if y else '  n/a'
    print('=' * 78)
    print(' SECRET WARDS — HARDEST TEST SCORECARD (practice approximation of docs/SCORING.md)')
    print('=' * 78)
    print(f"\n1) DETECTION  score {det_s:.3f}   recall {det['recall']:.3f}   contextual precision {util['contextual_precision']:.3f}")
    print(f"   PII still visible: {det['leaked_total']:.0f} of {det['mentions']} mentions ({pct(det['leaked_total'], det['mentions'])})")
    for k, (l, n) in det['by_type'].items():
        print(f'     {k:16} {l:>7} / {n:<5} {pct(l, n)}')
    print('   by script:   ' + ', '.join(f'{k} {pct(*v).strip()}' for k, v in det['by_script'].items()))
    print('   by place:    ' + ', '.join(f'{k} {pct(*v).strip()}' for k, v in det['by_channel'].items()))
    print('   by disguise: ' + ', '.join(f'{k} {pct(*v).strip()}' for k, v in det['by_obfuscation'].items()))
    print(f"   canaries found in your output: {len(can)} of {len(s.truth.get('canaries', []))} {can if can else ''}")
    print(f"\n2) IDENTITY   score {ident:.3f}   precision {link['precision']:.3f}  recall {link['recall']:.3f}  F0.5 {link['f05']:.3f}  B-cubed F1 {link['b3f1']:.3f}")
    for k, (x, y) in link['traps'].items():
        print(f'     {k:32} {x} / {y}')
    print(f"\n3) PRIVACY    score {privacy:.3f}   risk {risk:.3f}  (vs raw input)")
    print(f"   records re-identified (>=0.5): {att['records_identified']} / {att['records']}   raw: {raw_att['records_identified']} / {raw_att['records']}")
    print(f"   profiles re-identified (>=0.5): {att['profile_identified']} / {att['profiles']}   raw: {raw_att['profile_identified']} / {raw_att['profiles']}")
    print(f"   targeted attack: {att['targeted']['identified']} / {att['targeted']['known_people']} known people (mean {att['targeted']['mean_success']:.2f})"
          f"   raw: {raw_att['targeted']['identified']} (mean {raw_att['targeted']['mean_success']:.2f})   decoys claimed {att['targeted']['decoys_claimed']}")
    if a7 is not None:
        print(f'   pseudonyms identical under another secret: {a7:.1%}')
    print(f"\n4) UTILITY    score {utility:.3f}   medical values kept {util['probes_kept']} / {util['probes']} ({pct(util['probes_kept'], util['probes'])})")
    print(f"   lost by kind: {util['lost_by_kind']}")
    print(f"   meaning traps kept: " + ', '.join(f'{k} {x}/{y}' for k, (x, y) in util['by_trap'].items()))
    print(f"   date intervals kept {dates_['intervals_kept']} / {dates_['intervals']};  dates left unshifted {dates_['dates_left_unshifted']} / {dates_['dates_checked']}")
    print(f"\n5) INTEGRITY  score {integrity:.3f}   bad-format files {integ['bad_format_files']} / {integ['exported_files']};"
          f"  quarantine handled {integ['quarantine_handled'][0]} / {integ['quarantine_handled'][1]};  raw copies {integ['raw_copies']};"
          f"  silent drops {integ['silent_drops']};  report honest {integ['report_honest']};  pseudonym in record {cons[0]} / {cons[1]}")
    print(f"\n6) EFFICIENCY score {eff:.3f}   {integ['timing']} s, {integ['peak_rss_mb']} MB" + (f', determinism {det_run:.1%}' if det_run is not None else ' (pass --output2 to check determinism)'))
    print(f"\n   penalties -{penalties}   (unique direct identifiers {det['direct_unique_leaks']}, canaries {len(can)}, raw copies {integ['raw_copies']})")
    print(f"\n   APPROXIMATE TOTAL: {total:.1f} / 100")
    if s.examples:
        print('\nExample leaks (type, script, place, disguise, file :: original text):')
        for ex in s.examples:
            print('   ' + ex)
    if a.json:
        a.json.write_text(json.dumps({'total': total, 'detection': det, 'utility': util, 'dates': dates_, 'linkage': link,
                                      'canaries_found': can, 'attack': att, 'raw_attack': raw_att, 'integrity': integ,
                                      'scores': {'detection': det_s, 'identity': ident, 'privacy': privacy, 'utility': utility,
                                                 'integrity': integrity, 'efficiency': eff, 'penalties': penalties}},
                                     ensure_ascii=False, indent=1, default=str), encoding='utf-8')


if __name__ == '__main__':
    main()
