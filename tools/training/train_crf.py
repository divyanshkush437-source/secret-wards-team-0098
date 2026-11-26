#!/usr/bin/env python3
"""Train and evaluate a baseline CRF de-identification tagger.  Needs: pip install python-crfsuite

    python3 train_crf.py --train train.jsonl --dev dev.jsonl --test test.jsonl --model crf.model
    python3 train_crf.py --model crf.model --test some_other.jsonl          # evaluate only

Reports, per evaluation file:
  * entity-level precision / recall / F1 (exact span + label), overall and per label
  * PII token recall  = share of personal-data tokens tagged as ANY PII label (what leaks)
  * keep false-positive rate = share of clinical "keep" tokens wrongly tagged as PII (over-redaction)
"""
from __future__ import annotations

import argparse
import json
import re
import time
import unicodedata
from collections import Counter

import pycrfsuite

TOKEN = re.compile(r'[\wऀ-ॿ]+(?:[.\'’@/-][\wऀ-ॿ]+)*|[^\s\wऀ-ॿ]', re.UNICODE)
INVISIBLE = re.compile('[­​-‏⁠﻿]')


def load(path):
    out = []
    for line in open(path, encoding='utf-8'):
        r = json.loads(line)
        text = r['text']
        toks, tags, keep, offs = [], [], [], []
        for m in TOKEN.finditer(text):
            a, b = m.span()
            offs.append((a, b))
            tag = 'O'
            for s in r['spans']:
                if s['start'] <= a and b <= s['end']:
                    tag = ('B-' if not text[s['start']:a].strip() else 'I-') + s['label']
                    break
            toks.append(m[0])
            tags.append(tag)
            keep.append(any(k['start'] <= a and b <= k['end'] for k in r.get('keep', [])))
        if toks:
            out.append((toks, tags, keep, rule_tags(text, offs)))
    return out


def shape(w):
    s = []
    for c in w[:10]:
        if c.isdigit():
            s.append('d')
        elif 'ऀ' <= c <= 'ॿ':
            s.append('h')
        elif c.isupper():
            s.append('A')
        elif c.isalpha():
            s.append('a')
        else:
            s.append(c)
    return re.sub(r'(.)\1+', r'\1+', ''.join(s))


def word_feats(w, p):
    n = unicodedata.normalize('NFKC', INVISIBLE.sub('', w))
    low = n.lower()
    digits = sum(c.isdigit() for c in n)
    return {p + 'w': low, p + 'shape': shape(n), p + 'title': n[:1].isupper() and n[1:].islower(),
            p + 'upper': n.isupper(), p + 'digits': min(digits, 13), p + 'alpha': n.isalpha(),
            p + 'deva': any('ऀ' <= c <= 'ॿ' for c in n), p + 'invisible': w != INVISIBLE.sub('', w),
            p + 'nonascii_latin': any(ord(c) > 127 and c.isalpha() and not ('ऀ' <= c <= 'ॿ') for c in w),
            p + 'suf3': low[-3:], p + 'pre3': low[:3]}


RULES = None


def load_rules(path):
    """Optional: use the team's rule detector (repo path) as features."""
    global RULES
    import sys
    sys.path.insert(0, path)
    from detector import detect_text
    RULES = detect_text


def rule_tags(text, offsets):
    """Tag each token with the rule detector's entity type (per 'key: value' line)."""
    if RULES is None:
        return [None] * len(offsets)
    marks = []
    pos = 0
    for line in text.split('\n'):
        key, sep, val = line.partition(': ')
        base = pos + (len(key) + 2 if sep else 0)
        body = val if sep else line
        try:
            for s in RULES(body, key if sep else '').spans:
                marks.append((base + s.start, base + s.end, s.entity_type))
        except (ValueError, TypeError):
            pass
        pos += len(line) + 1
    out = []
    for a, b in offsets:
        out.append(next((t for x, y, t in marks if x <= a and b <= y), 'O'))
    return out


def sent_feats(toks, rules=None):
    rules = rules or [None] * len(toks)
    feats = []
    for i, w in enumerate(toks):
        f = {'bias': 1.0}
        f.update(word_feats(w, ''))
        if rules[i] is not None:
            f['rule'] = rules[i]
            f['rule-1'] = rules[i - 1] if i else 'BOS'
            f['rule+1'] = rules[i + 1] if i + 1 < len(rules) else 'EOS'
        for k in (-3, -2, -1, 1, 2):
            j = i + k
            if 0 <= j < len(toks):
                f[f'{k}:w'] = toks[j].lower()
                f[f'{k}:shape'] = shape(toks[j])
            else:
                f[f'{k}:edge'] = True
        # the label of a "Header: value" line ("Patient Name:", "Mobile:") is strong context
        line_start = i
        while line_start > 0 and toks[line_start - 1] not in ('\n',):
            line_start -= 1
        try:
            colon = toks.index(':', max(0, i - 6), i + 1)
            f['field'] = ' '.join(t.lower() for t in toks[max(0, colon - 3):colon])
        except ValueError:
            pass
        feats.append({k: (str(v) if not isinstance(v, (bool, float)) else v) for k, v in f.items()})
    return feats


def entities(tags):
    ents, start, label = set(), None, None
    for i, t in enumerate(tags + ['O']):
        if t.startswith('B-') or t == 'O' or (t.startswith('I-') and t[2:] != label):
            if label is not None:
                ents.add((start, i, label))
            start, label = (i, t[2:]) if t != 'O' else (None, None)
    return ents


def evaluate(tagger, data, name):
    tp, fp, fn = Counter(), Counter(), Counter()
    pii_tok = pii_hit = keep_tok = keep_fp = 0
    for toks, gold, keep, rules in data:
        pred = tagger.tag(sent_feats(toks, rules))
        g, p = entities(gold), entities(pred)
        for e in p & g:
            tp[e[2]] += 1
        for e in p - g:
            fp[e[2]] += 1
        for e in g - p:
            fn[e[2]] += 1
        for gt, pt, k in zip(gold, pred, keep):
            if gt != 'O':
                pii_tok += 1
                pii_hit += pt != 'O'
            if k:
                keep_tok += 1
                keep_fp += pt != 'O'
    labels = sorted(set(tp) | set(fn) | set(fp))
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    P = T / (T + F) if T + F else 0.0
    R = T / (T + N) if T + N else 0.0
    f1 = 2 * P * R / (P + R) if P + R else 0.0
    print(f'\n== {name}: {len(data)} records')
    print(f'   entity-level  precision {P:.4f}  recall {R:.4f}  F1 {f1:.4f}')
    print(f'   PII tokens caught (any PII label): {pii_hit}/{pii_tok} = {pii_hit / max(1, pii_tok):.4f}')
    print(f'   clinical keep tokens wrongly flagged: {keep_fp}/{keep_tok} = {keep_fp / max(1, keep_tok):.4f}')
    print(f"   {'label':14} {'prec':>7} {'recall':>7} {'F1':>7} {'gold':>7}")
    for l in labels:
        p_ = tp[l] / (tp[l] + fp[l]) if tp[l] + fp[l] else 0.0
        r_ = tp[l] / (tp[l] + fn[l]) if tp[l] + fn[l] else 0.0
        f_ = 2 * p_ * r_ / (p_ + r_) if p_ + r_ else 0.0
        print(f'   {l:14} {p_:7.3f} {r_:7.3f} {f_:7.3f} {tp[l] + fn[l]:7d}')
    return {'precision': P, 'recall': R, 'f1': f1, 'pii_token_recall': pii_hit / max(1, pii_tok),
            'keep_fp_rate': keep_fp / max(1, keep_tok)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--train')
    ap.add_argument('--dev')
    ap.add_argument('--test', nargs='*', default=[])
    ap.add_argument('--model', default='crf.model')
    ap.add_argument('--c1', type=float, default=0.05)
    ap.add_argument('--c2', type=float, default=0.01)
    ap.add_argument('--iters', type=int, default=150)
    ap.add_argument('--rules', help='path to the team repo: use its rule detector as features')
    a = ap.parse_args()
    if a.rules:
        load_rules(a.rules)
    if a.train:
        t0 = time.time()
        trainer = pycrfsuite.Trainer(verbose=False)
        for toks, tags, _, rules in load(a.train):
            trainer.append(sent_feats(toks, rules), tags)
        trainer.set_params({'c1': a.c1, 'c2': a.c2, 'max_iterations': a.iters, 'feature.possible_transitions': True})
        trainer.train(a.model)
        print(f'trained {a.model} in {time.time() - t0:.0f} s')
    tagger = pycrfsuite.Tagger()
    tagger.open(a.model)
    results = {}
    for name in ([a.dev] if a.dev else []) + a.test:
        results[name] = evaluate(tagger, load(name), name)
    print('\n' + json.dumps(results, indent=1))


if __name__ == '__main__':
    main()
