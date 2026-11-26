"""Script-aware context scanning; no name list or downloaded model weights.
The optional spaCy Matcher is a cached trigger accelerator, never an NER model.
"""
import re
from functools import lru_cache
from .medical_whitelist import blocked_word
TOKEN = re.compile(r"[A-Za-z\u0900-\u0963\u0971-\u097f]+(?:['’-][A-Za-z\u0900-\u0963\u0971-\u097f]+)*\.?", re.UNICODE)

@lru_cache(maxsize=16)
def trigger_matcher(markers):
    try:
        import spacy
        from spacy.matcher import PhraseMatcher
    except ImportError:
        return None
    nlp = spacy.blank('xx')
    matcher = PhraseMatcher(nlp.vocab, attr='LOWER')
    matcher.add('CONTEXT', [nlp.make_doc(v) for v in markers])
    return nlp, matcher

@lru_cache(maxsize=64)
def marker_pattern(markers):
    # Devanagari vowel signs, nukta and virama are not \w in Python; treat them
    # as word characters so "मरीज" does not match inside "मरीज़".
    return re.compile(r'(?<![\w\u0900-\u097f])(?:' + '|'.join(re.escape(x) for x in sorted(markers, key=lambda x: (-len(x), x))) + r')(?![\w\u0900-\u097f])\s*[:=-]?\s*', re.I)

def marker_matches(text, markers):
    # Regex remains authoritative for punctuation and original offsets.
    return marker_pattern(tuple(markers)).finditer(text)

def is_name_token(value):
    return not blocked_word(value) and (value[0].isupper() or '\u0900' <= value[0] <= '\u097f')

def read_name(text, start, honorifics, allow_lower=False):
    matches = []
    cursor = start
    for _ in range(6):
        m = TOKEN.match(text, cursor)
        if not m or (m.end()<len(text) and text[m.end()].isdigit()) or blocked_word(m[0]) or m[0].casefold().rstrip('.') in honorifics:
            break
        if not allow_lower and not is_name_token(m[0]):
            break
        matches.append(m)
        gap = re.match(r'[ \t]*(?:,[ \t]*)?', text[m.end():])
        cursor = m.end() + gap.end()
        if cursor == m.end():
            break
    return (matches[0].start(), matches[-1].end()) if matches else None

def name_candidates(text, policy, field_hint=''):
    honor = {s.casefold() for s in policy['honorifics']}
    doctors = []
    for m in marker_matches(text, policy['doctor_prefixes']):
        span = read_name(text, m.end(), honor, True)
        if span:
            doctors.append((m.start(), span[1]))
    candidates = []
    for m in marker_matches(text, policy['relationship_markers']):
        if re.search(r'(?i)K/\s*$',text[max(0,m.start()-4):m.start()]):
            continue
        span = read_name(text, m.end(), honor, True)
        if span:
            candidates.append((*span, 'RELATIVE', .94))
    for m in marker_matches(text, ['patient', 'patient name', 'name', 'नाम', 'मरीज', 'रोगी']):
        span = read_name(text, m.end(), honor, ':' in m[0] or '=' in m[0])
        if span:
            candidates.append((*span, 'PERSON', .95))
    for m in marker_matches(text, policy['honorifics']):
        # Prefix honorifics (Shri/Smt) versus suffixes (ji/sahab).
        word = m[0].strip(' :=-').casefold()
        if word in {'shri', 'smt', 'श्री', 'श्रीमती', 'kumari'}:
            span = read_name(text, m.end(), honor, True)
            if span:
                candidates.append((*span, 'PERSON', .91))
        else:
            tokens = list(TOKEN.finditer(text, max(0, m.start()-80), m.start()))
            selected = []
            end = m.start()
            for token in reversed(tokens):
                if text[token.end():end].strip() or not is_name_token(token[0]):
                    break
                selected.append(token)
                end = token.start()
                if len(selected) == 4:
                    break
            if selected:
                candidates.append((selected[-1].start(), selected[0].end(), 'PERSON', .90))
    hint = re.sub(r'[_-]+', ' ', field_hint).casefold()
    if hint in {'name','patient','patient name','given','family','नाम','मरीज'}:
        span = read_name(text, len(text)-len(text.lstrip()), honor, True)
        if span:
            candidates.append((*span, 'PERSON', .88))
    if hint in {'guardian','relative','father name','mother name','spouse','attendant'}:
        span = read_name(text, len(text)-len(text.lstrip()), honor, True)
        if span:
            candidates.append((*span, 'RELATIVE', .90))
    for m in re.finditer(r"(?<!\w)([A-Z][a-z]+)(?:['’]s\s+attendant|\s+(?:ka|ki|ko)\s+(?:BP|condition|bukhar|dard))", text):
        candidates.append((*m.span(1), 'PERSON', .9))
    if policy['bare_name_detection'] and field_hint != '__clinical__':
        for token in TOKEN.finditer(text):
            if is_name_token(token[0]):
                span = read_name(text, token.start(), honor)
                if span and len(list(TOKEN.finditer(text[span[0]:span[1]]))) >= 2:
                    candidates.append((*span, 'PERSON', .66))
    return candidates, doctors

def normalize_name(value, honorifics):
    words = TOKEN.findall(value.replace(',', ' '))
    return ' '.join(w.rstrip('.').casefold() for w in words if w.rstrip('.').casefold() not in honorifics)

def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]

def resolve(spans):
    priority = {'DOB':10, 'EMAIL':10, 'ID_ABHA':10, 'ID_AADHAAR':9, 'ID_PAN':9, 'ID_UHID':9, 'PHONE':8, 'RELATIVE':7, 'PERSON':6, 'PINCODE':5, 'DATE':5, 'AGE':5, 'GENDER':5, 'LOCATION':1}
    chosen = []
    for span in sorted(spans, key=lambda s: (-priority[s.entity_type], -s.confidence, -(s.end-s.start), s.start, s.entity_type)):
        if not any(overlaps((span.start, span.end), (old.start, old.end)) for old in chosen):
            chosen.append(span)
    return sorted(chosen, key=lambda s: (s.start, s.end, s.entity_type))
