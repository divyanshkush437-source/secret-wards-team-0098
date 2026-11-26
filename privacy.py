"""Member 3: keyed pseudonyms and quasi-identifier transforms.

Everything is derived from RAKSHA_SECRET with HMAC-SHA256, so:
  * the same input + same secret gives byte-identical output (reproducible);
  * a different secret gives different pseudonyms AND different date shifts
    (no cross-release linkability);
  * pseudonyms are not reversible without the secret (no plain hashing, no
    embedded UHID/phone digits).

Settings live in config/privacy.json; defaults below are used if it is absent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import date, timedelta
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent / 'config' / 'privacy.json'
DEFAULTS = {
    'pseudonym_length': 8,
    'shift_min_days': 20,
    'shift_max_days': 200,
    'age_band_width': [10, 20, 20],     # per risk level 0/1/2
    'age_top_code': 85,                 # ages >= this become "85+"
    'k_threshold': 3,                   # min patients sharing a diagnosis code
    'registry_ratio': 4,                # attacker registry size / patient count (kit: 4-5x)
    'k_registry': 8,                    # min expected registry people per released cell
    'old_top_code': 65,                 # wider top code for very old patients who stay rare
    'rare_name_max_patients': 1,        # disease names held by <= this many patients are generalised
    'pin_prefix_digits': 3,             # PIN 226001 -> 226XXX at level 0
}


def load_config(path: Path = CONFIG_PATH) -> dict:
    config = dict(DEFAULTS)
    try:
        loaded = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return config
    if isinstance(loaded, dict):
        for key, value in loaded.items():
            if key in DEFAULTS and type(value) is type(DEFAULTS[key]):
                config[key] = value
    return config


_B32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # no 0/O/1/I confusion


def _mac(secret: bytes, label: str) -> bytes:
    return hmac.new(secret, label.encode('utf-8'), hashlib.sha256).digest()


def pseudonym(secret: bytes, anchor: str, length: int = 8) -> str:
    """Stable keyed pseudonym, e.g. PSN-7Q2K9DXA."""
    digest = int.from_bytes(_mac(secret, 'psn\x00' + anchor), 'big')
    chars = []
    for _ in range(length):
        digest, r = divmod(digest, len(_B32))
        chars.append(_B32[r])
    return 'PSN-' + ''.join(chars)


def shift_days(secret: bytes, subject: str, low: int = 20, high: int = 200) -> int:
    """Per-subject secret date offset in ±[low, high] days (never 0)."""
    value = int.from_bytes(_mac(secret, 'shift\x00' + subject)[:8], 'big')
    magnitude = low + value % (high - low + 1)
    return magnitude if (value >> 40) & 1 else -magnitude


def token(secret: bytes, kind: str, value: str, size: int = 12) -> str:
    """Opaque keyed token for values that must stay consistent (FHIR ids)."""
    raw = base64.b32encode(_mac(secret, kind + '\x00' + value)).decode('ascii')
    return raw[:size].lower()


# ---------------------------------------------------------------- dates
_MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
_FULL = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
         'september', 'october', 'november', 'december']


def parse_numeric(raw: str, order: str = 'DMY'):
    """Return (date, layout) for numeric dates; layout re-renders the string."""
    m = re.fullmatch(r'(\d{4})([-/.])(\d{1,2})([-/.])(\d{1,2})', raw)
    if m:
        y, mo, d = int(m[1]), int(m[3]), int(m[5])
        return _safe(y, mo, d), ('YMD', m[2], m[4], len(m[3]), len(m[5]), 4)
    m = re.fullmatch(r'(\d{1,2})([-/.])(\d{1,2})([-/.])(\d{4}|\d{2})', raw)
    if not m:
        return None, None
    a, b, y = int(m[1]), int(m[3]), int(m[5])
    if len(m[5]) == 2:
        y += 2000 if y <= 30 else 1900
    d, mo = (b, a) if order == 'MDY' else (a, b)
    return _safe(y, mo, d), (order, m[2], m[4], len(m[1]), len(m[3]), len(m[5]))


def _safe(y, mo, d):
    try:
        return date(y, mo, d)
    except ValueError:
        return None


def only_valid_order(raw: str):
    """'DMY' or 'MDY' if exactly one reading of a numeric date is valid."""
    dmy, _ = parse_numeric(raw, 'DMY')
    mdy, _ = parse_numeric(raw, 'MDY')
    if re.fullmatch(r'\d{4}\D.*', raw):
        return None
    if dmy and not mdy:
        return 'DMY'
    if mdy and not dmy:
        return 'MDY'
    return None


def _pad(n, width):
    return str(n).zfill(width) if width >= 2 else str(n)


def render_numeric(value: date, layout) -> str:
    kind, s1, s2, w1, w2, wy = layout
    year = str(value.year) if wy == 4 else str(value.year)[-2:]
    if kind == 'YMD':
        return f'{year}{s1}{_pad(value.month, w1)}{s2}{_pad(value.day, w2)}'
    if kind == 'MDY':
        return f'{_pad(value.month, w1)}{s1}{_pad(value.day, w2)}{s2}{year}'
    return f'{_pad(value.day, w1)}{s1}{_pad(value.month, w2)}{s2}{year}'


def shift_text_date(raw: str, days: int, order: str = 'DMY'):
    """Shift one date string, keeping its exact layout. None if unparseable."""
    value, layout = parse_numeric(raw, order)
    if value is not None:
        return render_numeric(value + timedelta(days=days), layout)
    m = re.fullmatch(r'(\d{1,2})(\s+|-)([A-Za-z]+)(\s+|-)(\d{4})', raw)
    if m and m[3][:3].lower() in _MONTHS:
        value = _safe(int(m[5]), _MONTHS.index(m[3][:3].lower()) + 1, int(m[1]))
        if value is None:
            return None
        new = value + timedelta(days=days)
        word = _FULL[new.month - 1] if len(m[3]) > 3 and m[3].lower() in _FULL else _MONTHS[new.month - 1]
        word = word.upper() if m[3].isupper() else word.capitalize() if m[3][0].isupper() else word
        return f'{_pad(new.day, len(m[1]))}{m[2]}{word}{m[4]}{new.year}'
    return None


# ---------------------------------------------------------------- ages
def age_band(age: int, level: int = 0, config: dict = DEFAULTS) -> str:
    """Truthful band containing the real age: 47 -> '45-49', 91 -> '85+'."""
    top = config['age_top_code']
    if level >= 3 and age >= config.get('old_top_code', 65):
        return f"{config.get('old_top_code', 65)}+"     # very old and still rare: wider top code
    if age >= top:
        return f'{top}+'
    width = config['age_band_width'][min(level, len(config['age_band_width']) - 1)]
    low = age // width * width
    high = min(low + width - 1, top - 1)
    return f'{low}-{high}'


def birth_year_band(year: int, level: int = 0, config: dict = DEFAULTS) -> str:
    cut = 2026 - config.get('old_top_code', 65)
    if level >= 3 and year <= cut:
        return f'{cut} or earlier'
    width = config['age_band_width'][min(level, len(config['age_band_width']) - 1)]
    low = year // width * width
    return f'{low}-{low + width - 1}'


def generalize_pin(pin: str, level: int = 0, config: dict = DEFAULTS) -> str:
    digits = config['pin_prefix_digits']
    if level >= 1 or len(pin) != 6:
        return '[PIN]'
    return pin[:digits] + 'X' * (6 - digits)


# ---------------------------------------------------------------- risk tiers
def risk_levels(subjects: dict, config: dict = DEFAULTS) -> dict:
    """Assign each subject a generalisation level (0, 1 or 2) by local recoding.

    subjects: {subject_id: {'codes': set, 'ages': set, 'gender': str|None,
                            'district': str|None, 'weight': 0 or 1}}

      level 0: 10-year age band, district kept, PIN -> 3-digit prefix
      level 1: 20-year age band, district kept, PIN removed
      level 2: 20-year age band, district and PIN removed

    The attacker holds a voter-style registry of the whole population, about
    ``registry_ratio`` times the patient count. We never see it, so we estimate
    how many registry people share a subject's released cell from the release
    itself:

        expected = ratio x patients(district) x share(gender) x share(age band)

    and pick the finest level whose expected cell holds at least ``k_registry``
    people (so the attacker's probability on the true person stays <= 1/k).
    Sparse districts, very old patients and rare bands are widened; dense cells
    keep their detail. Holding an ICD code that fewer than ``k_threshold``
    patients share (rare disease) forces level 2: the diagnosis is kept for
    clinical utility and the demographics around it are coarsened instead.
    """
    k = config['k_threshold']
    ratio = config.get('registry_ratio', 4)
    k_reg = config.get('k_registry', 5)
    people = [i for i in subjects.values() if i.get('weight', 1)] or list(subjects.values())
    total = len(people)
    code_count = {}
    for info in people:
        for code in info.get('codes', ()):
            code_count[code] = code_count.get(code, 0) + 1

    def first_age(info):
        ages = sorted(info.get('ages') or ())
        return ages[0] if ages else None

    district_n, gender_n, band_n = {}, {}, [{}, {}]
    aged = 0
    for info in people:
        district_n[info.get('district')] = district_n.get(info.get('district'), 0) + 1
        gender_n[info.get('gender')] = gender_n.get(info.get('gender'), 0) + 1
        age = first_age(info)
        if age is not None:
            aged += 1
            for level in (0, 1):
                b = age_band(age, level, config)
                band_n[level][b] = band_n[level].get(b, 0) + 1

    def expected(info, level):
        n = district_n.get(info.get('district'), 0) if level < 2 and info.get('district') else total
        g = info.get('gender')
        share_g = gender_n.get(g, 0) / total if g else 1.0
        age = first_age(info)
        share_b = band_n[min(level, 1)][age_band(age, min(level, 1), config)] / aged if age is not None and aged else 1.0
        return ratio * n * share_g * share_b

    levels = {}
    for sid, info in subjects.items():
        if any(code_count.get(c, 0) < k for c in info.get('codes', ())):
            levels[sid] = 2
            continue
        levels[sid] = next((lv for lv in (0, 1) if expected(info, lv) >= k_reg), 2)
        age = first_age(info)
        if levels[sid] == 2 and age is not None and age >= config['age_top_code']:
            # "85+" with no district can still be one or two people: widen to "65+".
            old = config.get('old_top_code', 65)
            g = info.get('gender')
            share_g = gender_n.get(g, 0) / total if g else 1.0
            if ratio * total * share_g * band_n[1].get(age_band(age, 1, config), 0) / max(aged, 1) < k_reg:
                levels[sid] = 3
    return levels


def k_anonymity_report(rows, quasi=('age_band', 'gender', 'district')):
    """Equivalence-class sizes over released quasi-identifiers (for tests/README)."""
    classes = {}
    for row in rows:
        key = tuple(row.get(q) for q in quasi)
        classes[key] = classes.get(key, 0) + 1
    sizes = sorted(classes.values())
    return {'classes': len(sizes), 'min_k': sizes[0] if sizes else 0,
            'unique': sum(1 for s in sizes if s == 1)}
