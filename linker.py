"""Member 3: cross-script patient linkage (pure standard library, deterministic).

Pipeline
--------
1. Every record is reduced to an ``Evidence`` object (names, relatives, strong
   identifiers, DOB, age, gender, places, ICD codes). Evidence is sensitive and
   lives only in RAM; nothing here logs or serialises it.
2. Names are made comparable across scripts: Devanagari is transliterated to
   Latin, common spelling variants are folded (Mohd/Md./Mohammad, Laxmi/Lakshmi,
   aa/a, ph/f ...), and tokens are compared with Jaro-Winkler.
3. Blocking: only records that share an identifier, a phone or a phonetic name
   key are compared, so cost stays close to linear.
4. Scoring is a Fellegi-Sunter style sum of agreement weights with hard vetoes
   (gender, DOB, birth year, conflicting full names).
5. Clustering is greedy single-link in descending score order, but a merge is
   refused if the *merged cluster* would contain a conflict. This prevents the
   classic transitive over-merge (A~B, B~C, but A and C are different people).

No name lists from the practice data are used; the only vocabulary is generic
Indian name particles (Kumar, Devi, Md. ...) which never identify anyone alone.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from itertools import combinations

# --------------------------------------------------------------------------
# Devanagari -> Latin transliteration (Hunterian-style, schwa-aware)
# --------------------------------------------------------------------------
_VOWELS = {
    'अ': 'a', 'आ': 'aa', 'इ': 'i', 'ई': 'ee', 'उ': 'u', 'ऊ': 'oo', 'ऋ': 'ri',
    'ए': 'e', 'ऐ': 'ai', 'ओ': 'o', 'औ': 'au', 'ऑ': 'o', 'ऍ': 'e',
}
_MATRAS = {
    'ा': 'aa', 'ि': 'i', 'ी': 'ee', 'ु': 'u', 'ू': 'oo', 'ृ': 'ri', 'े': 'e',
    'ै': 'ai', 'ो': 'o', 'ौ': 'au', 'ॉ': 'o', 'ॅ': 'e',
}
_CONSONANTS = {
    'क': 'k', 'ख': 'kh', 'ग': 'g', 'घ': 'gh', 'ङ': 'n', 'च': 'ch', 'छ': 'chh',
    'ज': 'j', 'झ': 'jh', 'ञ': 'n', 'ट': 't', 'ठ': 'th', 'ड': 'd', 'ढ': 'dh',
    'ण': 'n', 'त': 't', 'थ': 'th', 'द': 'd', 'ध': 'dh', 'न': 'n', 'प': 'p',
    'फ': 'ph', 'ब': 'b', 'भ': 'bh', 'म': 'm', 'य': 'y', 'र': 'r', 'ल': 'l',
    'व': 'v', 'श': 'sh', 'ष': 'sh', 'स': 's', 'ह': 'h', 'ळ': 'l',
    'क़': 'q', 'ख़': 'kh', 'ग़': 'g', 'ज़': 'z', 'ड़': 'r', 'ढ़': 'rh', 'फ़': 'f', 'य़': 'y',
}
_NUKTA_BASE = {'क': 'क़', 'ख': 'ख़', 'ग': 'ग़', 'ज': 'ज़', 'ड': 'ड़', 'ढ': 'ढ़', 'फ': 'फ़', 'य': 'य़'}
_VIRAMA, _NUKTA, _ANUSVARA, _CHANDRABINDU, _VISARGA = '्', '़', 'ं', 'ँ', 'ः'


def transliterate(text: str) -> str:
    """Transliterate Devanagari runs to Latin; other characters pass through."""
    text = unicodedata.normalize('NFC', text)
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in _CONSONANTS or ch in _NUKTA_BASE:
            if i + 1 < n and text[i + 1] == _NUKTA and ch in _NUKTA_BASE:
                ch = _NUKTA_BASE[ch]
                i += 1
            out.append(_CONSONANTS.get(ch, ''))
            nxt = text[i + 1] if i + 1 < n else ''
            if nxt == _VIRAMA:
                i += 2
                continue
            if nxt in _MATRAS:
                out.append(_MATRAS[nxt])
                i += 2
                continue
            # Inherent schwa. Hindi drops it word-finally unless the consonant
            # closes a conjunct (आदित्य -> aditya, but राम -> ram).
            word_end = not (nxt and ('ऀ' <= nxt <= 'ॿ') and nxt not in (_ANUSVARA, _CHANDRABINDU, _VISARGA))
            conjunct = i >= 1 and text[i - 1] == _VIRAMA
            if not word_end or conjunct or nxt in (_ANUSVARA, _CHANDRABINDU):
                out.append('a')
            i += 1
            continue
        if ch in _VOWELS:
            out.append(_VOWELS[ch])
        elif ch in (_ANUSVARA, _CHANDRABINDU):
            out.append('n')
        elif ch == _VISARGA:
            out.append('h')
        elif ch in _MATRAS:
            out.append(_MATRAS[ch])
        elif '०' <= ch <= '९':
            out.append(str(ord(ch) - 0x966))
        elif ch in (_VIRAMA, _NUKTA, '‌', '‍'):
            pass
        else:
            out.append(ch)
        i += 1
    return ''.join(out)


# --------------------------------------------------------------------------
# Name normalisation
# --------------------------------------------------------------------------
HONORIFICS = set('ji jee sahab saheb sahib didi bhai bhaiya babu shri sri shree smt shrimati kumari km kum mr mrs ms miss master baby behenji behen bahen amma mataji pitaji chacha chachi bibi begum sardar pt pandit late'.split())
# Generic particles: they never identify anyone on their own (see DATASET.md).
GENERIC = set('kumar kumari devi singh bano begum khatoon bibi lal prasad bai rani mohammad md mohd ram chand nath'.split())
_VARIANTS = {
    'md': 'mohammad', 'mohd': 'mohammad', 'mohamad': 'mohammad', 'mohammed': 'mohammad',
    'muhammad': 'mohammad', 'muhammed': 'mohammad', 'mohamed': 'mohammad', 'mohmmad': 'mohammad',
    'mohamd': 'mohammad', 'mhd': 'mohammad', 'kr': 'kumar', 'sinh': 'singh', 'sing': 'singh',
    'laxmi': 'lakshmi', 'laxman': 'lakshman',
}


def _strip_accents(text: str) -> str:
    return ''.join(c for c in unicodedata.normalize('NFKD', text) if not unicodedata.combining(c))


def simplify(token: str) -> str:
    """Phonetic folding applied identically to both scripts' Latin forms."""
    t = token
    t = re.sub(r'ay$', 'ai', t)                # vijay / vijai
    t = t.replace('x', 'ks').replace('q', 'k').replace('z', 'j').replace('w', 'v')
    t = re.sub(r'(?<=[a-z])h', '', t)          # kh->k, bh->b, sh->s, ph->p ...
    t = t.replace('f', 'p')
    t = re.sub(r'ee|ii|ie', 'i', t)
    t = re.sub(r'oo|uu', 'u', t)
    t = t.replace('aa', 'a')
    t = re.sub(r'au|ou', 'o', t).replace('ai', 'e')
    t = t.replace('ck', 'k').replace('c', 'k')
    t = re.sub(r'y$', 'i', t)
    t = re.sub(r'(.)\1+', r'\1', t)            # doubled letters
    t = re.sub(r'(?<=.)a$', '', t) if len(t) > 3 else t   # final schwa variation
    return t


def name_tokens(name: str) -> tuple:
    """Return normalised Latin tokens with honorifics removed (order kept)."""
    latin = _strip_accents(transliterate(name)).casefold()
    latin = latin.replace('.', ' ')
    tokens = []
    for raw in re.findall(r'[a-z]+', latin):
        if raw in HONORIFICS:
            continue
        tokens.append(_VARIANTS.get(raw, raw))
    return tuple(tokens)


def is_generic(token: str) -> bool:
    # Phonetic comparison only for transliterated spellings ("baano", "devee"),
    # so a real name such as "Chanda" is not mistaken for the particle "Chand".
    return token in GENERIC or (re.search(r'aa|ee|oo|ii|uu', token) is not None and simplify(token) in _GENERIC_SIMPLE)


def identifying(tokens) -> tuple:
    return tuple(t for t in tokens if len(t) > 1 and not is_generic(t))


_GENERIC_SIMPLE = {simplify(t) for t in GENERIC}


def place_key(token: str) -> str:
    """Spelling-tolerant key for village/locality tokens (schwa + vowel folding)."""
    s = simplify(token)
    return re.sub(r'(?<=[^aeiou])a(?=[^aeiou])', '', s)


def phonetic_key(token: str) -> str:
    s = simplify(token)
    if not s:
        return ''
    return (s[0] + re.sub(r'[aeiou]', '', s[1:]))[:4]


# --------------------------------------------------------------------------
# String similarity (Jaro-Winkler)
# --------------------------------------------------------------------------
def jaro_winkler(a: str, b: str) -> float:
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb:
        return 0.0
    window = max(la, lb) // 2 - 1
    ma = [False] * la
    mb = [False] * lb
    matches = 0
    for i, ca in enumerate(a):
        lo, hi = max(0, i - window), min(lb, i + window + 1)
        for j in range(lo, hi):
            if not mb[j] and b[j] == ca:
                ma[i] = mb[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    k = trans = 0
    for i in range(la):
        if ma[i]:
            while not mb[k]:
                k += 1
            if a[i] != b[k]:
                trans += 1
            k += 1
    jaro = (matches / la + matches / lb + (matches - trans / 2) / matches) / 3
    prefix = 0
    for ca, cb in zip(a[:4], b[:4]):
        if ca != cb:
            break
        prefix += 1
    return jaro + prefix * 0.1 * (1 - jaro)


def token_match(a: str, b: str) -> float:
    if len(a) == 1 or len(b) == 1:          # initials
        return 0.85 if a[0] == b[0] else 0.0
    sa, sb = simplify(a), simplify(b)
    if sa == sb:
        return 1.0
    # Hindi medial schwa: "mohanaganj" vs "mohanganj".
    da = re.sub(r'(?<=[^aeiou])a(?=[^aeiou])', '', sa)
    db = re.sub(r'(?<=[^aeiou])a(?=[^aeiou])', '', sb)
    if da == db and len(da) >= 3:
        return 0.95
    return max(jaro_winkler(sa, sb), jaro_winkler(da, db) - 0.03)


TOKEN_OK = 0.93
RELAXED_OK = 0.85      # only when the two records already share a hospital/national ID


def compare_names(a: tuple, b: tuple, ok: float = None) -> str:
    """Return 'full', 'partial', 'none' or 'conflict' for two token tuples.

    ``ok`` lowers the token threshold when other evidence (a shared hospital ID)
    already ties the records together, so spelling variants still agree."""
    ok = TOKEN_OK if ok is None else ok
    ia, ib = identifying(a), identifying(b)
    if not ia or not ib:
        return 'none'
    short, long_ = (ia, ib) if len(ia) <= len(ib) else (ib, ia)
    used = set()
    matched = 0
    initials = 0
    for t in short:
        best, best_j = 0.0, None
        for j, u in enumerate(long_):
            if j in used:
                continue
            s = token_match(t, u)
            if s > best:
                best, best_j = s, j
        if best >= ok or (best >= 0.85 and (len(t) == 1 or len(long_[best_j]) == 1)):
            used.add(best_j)
            matched += 1
            initials += best < ok
    if matched == 0:
        return 'conflict'
    if matched < len(short):
        return 'conflict' if len(short) >= 2 else 'none'
    if len(short) == len(long_) and len(a) >= 2 and len(b) >= 2 and not initials:
        return 'full'
    if len(short) >= 2 and len(long_) > len(short):
        return 'partial'          # extra middle name on one side
    if len(short) == len(long_) and initials:
        return 'partial'
    if len(short) == 1 and len(long_) >= 2:
        return 'partial'          # first name only vs full name
    if len(short) == 1 and len(long_) == 1:
        # "Mohammad Shahid" vs "Shahid": generic particles decide full vs partial.
        return 'full' if (len(a) >= 2 and len(b) >= 2) else 'partial'
    return 'partial'


# --------------------------------------------------------------------------
# Evidence and scoring
# --------------------------------------------------------------------------
@dataclass
class Evidence:
    names: set = field(default_factory=set)        # tuples of tokens (patient)
    relatives: set = field(default_factory=set)    # tuples of tokens
    ids: set = field(default_factory=set)          # ('UHID', 'SNJ26064427'), ...
    phones: set = field(default_factory=set)
    dobs: set = field(default_factory=set)         # ISO strings
    ages: set = field(default_factory=set)         # (age, reference_year or None)
    genders: set = field(default_factory=set)
    places: set = field(default_factory=set)       # simplified place tokens
    districts: set = field(default_factory=set)
    codes: set = field(default_factory=set)        # ICD-10 codes
    ambiguous: bool = False

    def usable(self) -> bool:
        if self.ambiguous:
            return False
        if self.ids:
            return True
        # A phone alone (visitor logs, attendant lists) is not a patient record:
        # also require a patient name.
        if self.phones and any(identifying(n) for n in self.names):
            return True
        if any(len(identifying(n)) >= 1 and len(n) >= 2 for n in self.names):
            return True
        # Fragmented identity: "Meera, W/o Rajan" -> first name + relative.
        return bool(self.relatives) and any(identifying(n) for n in self.names)

    def merge(self, other: 'Evidence') -> None:
        for name in ('names', 'relatives', 'ids', 'phones', 'dobs', 'ages', 'genders', 'places', 'districts', 'codes'):
            getattr(self, name).update(getattr(other, name))


def _birth_years(ev: Evidence) -> set:
    years = {int(d[:4]) for d in ev.dobs}
    for age, ref in ev.ages:
        if ref:
            years.add(ref - age)
    return years


def conflict(a: Evidence, b: Evidence) -> bool:
    if a.genders and b.genders and not (a.genders & b.genders):
        return True
    if a.dobs and b.dobs and not (a.dobs & b.dobs):
        return True
    ya, yb = _birth_years(a), _birth_years(b)
    if ya and yb and min(abs(x - y) for x in ya for y in yb) > 2:
        return True
    if not (ya and yb) and a.ages and b.ages:
        if min(abs(x[0] - y[0]) for x in a.ages for y in b.ages) > 3:
            return True
    full_a = [n for n in a.names if len(identifying(n)) >= 2]
    full_b = [n for n in b.names if len(identifying(n)) >= 2]
    ok = RELAXED_OK if a.ids & b.ids else None
    if full_a and full_b and not any(compare_names(x, y, ok) in ('full', 'partial') for x in full_a for y in full_b):
        return True
    return False


def _best_name(a: set, b: set, ok: float = None) -> str:
    order = {'full': 3, 'partial': 2, 'none': 1, 'conflict': 0}
    best = None
    for x in a:
        for y in b:
            r = compare_names(x, y, ok)
            if best is None or order[r] > order[best]:
                best = r
    return best or 'none'


WEIGHTS = {'id': 10, 'phone': 5, 'full': 5, 'partial': 3, 'conflict': -6,
           'relative': 4, 'dob': 4, 'age': 1, 'place': 2}
THRESHOLD = 7


def score(a: Evidence, b: Evidence) -> int:
    if conflict(a, b):
        return -100
    s = 0
    if a.ids & b.ids:
        s += WEIGHTS['id']
    if a.phones & b.phones:
        s += WEIGHTS['phone']
    name = _best_name(a.names, b.names, RELAXED_OK if a.ids & b.ids else None) if a.names and b.names else 'none'
    if name in WEIGHTS:
        s += WEIGHTS[name]
    if a.relatives and b.relatives and _best_name(a.relatives, b.relatives) in ('full', 'partial'):
        s += WEIGHTS['relative']
    if a.dobs & b.dobs:
        s += WEIGHTS['dob']
    if a.ages and b.ages and not conflict(Evidence(ages=a.ages), Evidence(ages=b.ages)):
        s += WEIGHTS['age']
    if a.places & b.places:
        s += WEIGHTS['place']
    for kind in ('AADHAAR', 'ABHA', 'PAN'):
        va = {v for k, v in a.ids if k == kind}
        vb = {v for k, v in b.ids if k == kind}
        if va and vb and not (va & vb):
            s -= 6                       # disagreeing national IDs: strong evidence against
    # A phone or identifier alone is not enough if the names disagree
    # (family members share phones; re-used IDs exist).
    if name == 'conflict':
        s = min(s, THRESHOLD - 1)
    # Names plus only weak demographics never link on their own unless the name
    # is a full match backed by a second clue.
    if not (a.ids & b.ids) and not (a.phones & b.phones) and name == 'none':
        s = min(s, THRESHOLD - 1)
    return s


class Linker:
    """Collect evidence per record key and resolve patient clusters."""

    BLOCK_CAP = 400

    def __init__(self):
        self.records = {}   # key -> Evidence

    def add(self, key, evidence: Evidence) -> None:
        if key in self.records:
            self.records[key].merge(evidence)
        else:
            self.records[key] = evidence

    def _blocks(self, keys):
        blocks = {}
        for key in keys:
            ev = self.records[key]
            bk = set()
            bk.update(('I',) + i for i in ev.ids)
            bk.update(('P', p) for p in ev.phones)
            for n in ev.names | ev.relatives:
                for t in identifying(n):
                    if len(t) >= 3:
                        bk.add(('N', phonetic_key(t)))
            for b in bk:
                blocks.setdefault(b, []).append(key)
        return blocks

    def resolve(self) -> dict:
        """Return {record_key: cluster_index or None} and keep cluster evidence."""
        keys = sorted((k for k, ev in self.records.items() if ev.usable()), key=repr)
        index = {k: i for i, k in enumerate(keys)}
        pairs = set()
        for bkey, members in sorted(self._blocks(keys).items(), key=lambda kv: repr(kv[0])):
            if len(members) > self.BLOCK_CAP and bkey[0] == 'N':
                continue
            members = sorted(set(members), key=lambda k: index[k])
            for x, y in combinations(members, 2):
                pairs.add((index[x], index[y]))
        scored = []
        for i, j in sorted(pairs):
            s = score(self.records[keys[i]], self.records[keys[j]])
            if s >= THRESHOLD:
                scored.append((-s, i, j))
        scored.sort()
        parent = list(range(len(keys)))
        cluster_ev = {i: _copy(self.records[k]) for i, k in enumerate(keys)}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(i, j):
            ri, rj = find(i), find(j)
            if ri == rj or conflict(cluster_ev[ri], cluster_ev[rj]):
                return
            keep, drop = (ri, rj) if ri < rj else (rj, ri)
            parent[drop] = keep
            cluster_ev[keep].merge(cluster_ev.pop(drop))

        # Pass 1: records carrying a hard identifier (hospital/national ID or phone).
        weak = {i for i, k in enumerate(keys) if not (self.records[k].ids or self.records[k].phones)}
        for _, i, j in scored:
            if i not in weak and j not in weak:
                union(i, j)
        # Pass 2: weak records ("Durga, W/o Shivendra") join only when exactly one
        # patient fits; two or more candidates means the note is ambiguous.
        partners = {}
        for _, i, j in scored:
            if i in weak:
                partners.setdefault(i, set()).add(j)
            if j in weak:
                partners.setdefault(j, set()).add(i)
        strong_roots = {find(i) for i in range(len(keys)) if i not in weak}
        ambiguous = set()
        for i in sorted(partners):
            roots = {find(j) for j in partners[i]} & strong_roots
            if len(roots) > 1:
                ambiguous.add(i)              # fits two or more identified patients
            elif len(roots) == 1:
                union(i, roots.pop())
        # Weak notes that match no identified patient may still join each other,
        # unless either of them is ambiguous.
        for _, i, j in scored:
            if i in weak and j in weak and not ({i, j} & ambiguous):
                if find(i) not in strong_roots and find(j) not in strong_roots:
                    union(i, j)
        self.cluster_evidence = cluster_ev
        result = {}
        for k in self.records:
            result[k] = find(index[k]) if k in index else None
        return result


def _copy(ev: Evidence) -> Evidence:
    out = Evidence()
    out.merge(ev)
    out.ambiguous = ev.ambiguous
    return out
