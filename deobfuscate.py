"""Member 3: see through disguised personal data, keeping original offsets.

A "clean view" of a string removes invisible characters (zero-width, soft
hyphen, BOM, word joiner), folds fullwidth/compatibility forms, Cyrillic and
Greek look-alike letters and Indic digits to ASCII, and keeps a map from every
view position back to the original character. Detection can then run on the
view and every span is mapped back onto the exact original characters, so the
redaction removes the disguised text itself.

Also finds numbers that ordinary patterns miss: digits written one by one
("9 8 7 6 ..."), in number words (English, Hinglish, Hindi), in odd groupings
("091-679-246-1790", "9326.693.539") or split across a line break.
"""
from __future__ import annotations

import html
import re
import unicodedata
import urllib.parse

INVISIBLE = set('­͏؜ᅟᅠ឴឵᠎​‌‍‎‏'
                '‪‫‬‭‮⁠⁡⁢⁣⁤﻿')
CONFUSABLE = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
    'ɡ': 'g', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    'І': 'I', 'Ј': 'J', 'Ѕ': 'S', 'Ү': 'Y',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'ε': 'e',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P',
    'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
    'ⅼ': 'l', 'ⅰ': 'i', '‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-', ' ': ' ', ' ': ' ', ' ': ' ',
}
NUMBER_WORDS = {}
for _d, _words in enumerate([
        ['zero', 'shunya', 'sunya', 'शून्य', 'जीरो', 'ज़ीरो'], ['one', 'ek', 'एक'], ['two', 'do', 'दो'],
        ['three', 'teen', 'तीन'], ['four', 'char', 'chaar', 'चार'], ['five', 'paanch', 'panch', 'पांच', 'पाँच'],
        ['six', 'chhe', 'chhah', 'chah', 'छह', 'छः', 'छे'], ['seven', 'saat', 'सात'], ['eight', 'aath', 'आठ'],
        ['nine', 'nau', 'नौ']]):
    for _w in _words:
        NUMBER_WORDS[_w] = str(_d)


_ENCODED = re.compile(r'(?:%(?:25)*[0-9A-Fa-f]{2})+|&(?:#\d{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z]{2,8});')


def _decode_run(run: str) -> str:
    if run.startswith('%'):
        s = run
        for _ in range(3):                       # double percent-encoding
            t = urllib.parse.unquote(s)
            if t == s:
                break
            s = t
        return s
    return html.unescape(run)


def clean_view(text: str):
    """Return (view, index) where view[i] came from text[index[i][0]:index[i][1]]."""
    out, idx = [], []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in '%&':
            m = _ENCODED.match(text, i)
            if m:
                run = m[0]
                dec = _decode_run(run)
                if dec != run:
                    for c in dec:
                        if c in INVISIBLE:
                            continue
                        out.append(CONFUSABLE.get(c, c))
                        idx.append((i, m.end()))
                    i = m.end()
                    continue
        if ch in INVISIBLE:
            i += 1
            continue
        if ch in CONFUSABLE:
            rep = CONFUSABLE[ch]
        elif ch.isdecimal() and not ('0' <= ch <= '9'):
            rep = str(unicodedata.decimal(ch))
        elif ord(ch) > 127 and unicodedata.category(ch)[0] in 'LNPS' and not ('ऀ' <= ch <= 'ॿ'):
            norm = unicodedata.normalize('NFKC', ch)
            rep = norm if norm.isascii() and norm else ch
        else:
            rep = ch
        for c in rep:
            out.append(c)
            idx.append((i, i + 1))
        i += 1
    return ''.join(out), idx


def to_original(idx, start, end):
    """Map a half-open view span back to the original string."""
    if start >= end or end > len(idx):
        return None
    return idx[start][0], idx[end - 1][1]


# ----------------------------------------------------------------- numbers
_CONTEXT_KEEP = re.compile(r'(?i)(?:snomed(?:\s*ct)?|loinc|icd(?:-?10)?|batch|lot|sample|specimen|log|code|amount|rs\.?|inr|₹)\s*[:#.]?\s*$')
_SPACED = re.compile(r'(?<![\w])(?:\d[ \t]){9,11}\d(?![\w])')
_GROUPED = re.compile(r'(?<![\w.+])(?:\+?\(?0{0,2}91\)?[ .\-]?|0[ .\-]?)?\d{2,5}(?:[ .\-\n]\d{2,5}){1,4}(?![\w])')
_WORD = re.compile(r'[A-Za-zऀ-ॿ]+')


def _is_phone(d):
    if len(d) == 12 and d.startswith('91'):
        d = d[2:]
    elif len(d) == 13 and d.startswith('091'):
        d = d[3:]
    elif len(d) == 11 and d.startswith('0'):
        d = d[1:]
    return len(d) == 10 and d[0] in '6789', d


def _verhoeff_ok(num: str) -> bool:
    d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
         [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
         [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
         [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
    p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
         [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
         [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = d[c][p[i % 8][int(ch)]]
    return c == 0


def _classify(digits, separated):
    ok, core = _is_phone(digits)
    if ok:
        return 'PHONE', '+91' + core
    if len(digits) == 12 and digits[0] in '23456789' and (separated or _verhoeff_ok(digits)):
        return 'ID_AADHAAR', digits
    if len(digits) == 14:
        return 'ID_ABHA', digits
    return None


def number_spans(view: str):
    """(start, end, kind, normalized) in view coordinates."""
    out = []

    def add(a, b, digits, separated):
        if _CONTEXT_KEEP.search(view[max(0, a - 24):a]):
            return
        got = _classify(digits, separated)
        if got:
            out.append((a, b, got[0], got[1]))

    for m in _SPACED.finditer(view):
        add(m.start(), m.end(), re.sub(r'\D', '', m[0]), True)
    for m in _GROUPED.finditer(view):
        s = m[0]
        if re.fullmatch(r'\d{1,2}[./-]\d{1,2}[./-]\d{2,4}', s) or re.fullmatch(r'\d{4}[./-]\d{1,2}[./-]\d{1,2}', s):
            continue                                    # a date, not a number
        if '\n' in s and not re.fullmatch(r'\d{4}[ .\-]\d{4}\n\d{4}', s):
            continue                                    # line breaks only inside 4-4-4 groups
        add(m.start(), m.end(), re.sub(r'\D', '', s), True)
    # number words: a run of 10+ consecutive digit words
    words = [(m.start(), m.end(), NUMBER_WORDS.get(m[0].casefold())) for m in _WORD.finditer(view)]
    i = 0
    while i < len(words):
        if words[i][2] is None:
            i += 1
            continue
        j = i
        while j + 1 < len(words) and words[j + 1][2] is not None and not view[words[j][1]:words[j + 1][0]].strip(' ,-'):
            j += 1
        if j - i + 1 >= 10:
            add(words[i][0], words[j][1], ''.join(w[2] for w in words[i:j + 1]), True)
        i = j + 1
    return out
