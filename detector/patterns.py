"""Compiled bounded candidates; calendar parsing has no current-date dependency."""
import re
from datetime import date, datetime
try:
    import phonenumbers
except ImportError:
    phonenumbers = None

EMAIL = re.compile(r'(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+', re.UNICODE)
PAN = re.compile(r'(?<!\w)[A-Z]{5}[0-9]{4}[A-Z](?!\w)')
AADHAAR = re.compile(r'(?<![\w\d])\d{4}[ -]?\d{4}[ -]?\d{4}(?![\w\d])')
ABHA = re.compile(r'(?<![\w\d])\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?![\w\d])')
PHONE = re.compile(r'(?<!\w)(?:(?:\+91[ .-]?|0)?[6-9६-९]\d{4}[ .-]?\d{5}|\(0\d{2,4}\)[ .-]?\d{6,8}|0\d{2,4}-\d{6,8})(?!\w)'
                   r'|\(\s*(?:\+?91[ -]?)?[6-9]\d{4}\s*\)[ .-]?\d{5}(?!\w)')   # "(73036) 71330"
NUM_DATE = re.compile(r'(?<![\w/.-])(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/](?:\d{4}|\d{2})|\d{1,2}\.\d{1,2}\.\d{4}|\d{4}\.\d{1,2}\.\d{1,2})(?![\w/-]|\.\d)')
TEXT_DATE = re.compile(r'(?<!\w)\d{1,2}(?:\s+|-)(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)(?:\s+|-)\d{4}(?!\w)', re.I)
ID_LABEL = re.compile(r'\b(?:UHID|MRN|IPD|OPD|Reg(?:istration)?\s*(?:No\.?)?|Insurance(?:\s*(?:ID|No\.?))?|Policy\s*(?:ID|No\.?))\s*[:=#-]?\s*([A-Za-z0-9][A-Za-z0-9/-]{1,39})\b', re.I)
PIN = re.compile(r'(?<!\d)[1-9]\d{5}(?!\d)')
AGE = re.compile(r'(?i)(?:\b(?:age|उम्र|आयु)\s*[:=-]?\s*(?P<label>\d{1,3})(?!\d)|(?<![\w.])(?P<years>\d{1,3})\s*(?:yrs?\b|years?\b|वर्ष)|(?<![\w.])(?P<compact>\d{1,3})(?=\s*/?\s*[MF]\b))')
GENDER = re.compile(r'(?i)(?<![\w\u0900-\u097f])(?:male|female|महिला|पुरुष)(?![\w\u0900-\u097f])|(?<![\w.])\d{1,3}\s*/?\s*(?P<compact_gender>[MF])\b')

def digits(text):
    return ''.join(str(int(c)) for c in text if c.isdecimal())

def normalize_phone(text):
    raw = digits(text)
    national = raw[2:] if len(raw) == 12 and raw.startswith('91') else raw
    national = national[1:] if national.startswith('0') else national
    if len(national) != 10:
        return None
    if phonenumbers is not None:
        try:
            parsed = phonenumbers.parse(text, 'IN')
            if not phonenumbers.is_possible_number(parsed):
                return None
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException:
            return None
    return '+91' + national

def normalize_date(value, pivot=30, order="DMY"):
    try:
        pieces = re.split(r'[-/.\s]+', value.strip())
        if pieces[1].isalpha():
            months = ['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec']
            d, m, y = int(pieces[0]), months.index(pieces[1][:3].lower()) + 1, int(pieces[2])
        elif len(pieces[0]) == 4:
            y, m, d = map(int, pieces)
        else:
            d, m, y = map(int, pieces)
            if order == "MDY": d, m = m, d
            if len(pieces[2]) == 2:
                y += 2000 if y <= pivot else 1900
        return date(y, m, d).isoformat()
    except (ValueError, IndexError):
        return None

STRUCTURED_ID = re.compile(r'(?i)(?<![\w])(?:[a-z]{2,8}[-/](?:[a-z]{2,5}[-/])?(?:\d{2,4}[-/])?\d{5,}|(?:uhid|mrn|adm)\d{5,}|(?:pmjay|pol)[-/][a-z0-9/-]{5,})(?![\w])')
# Hospital numbers with no separator: 2-6 CAPITAL letters + 5 or more digits (AGH0001081, IPD20261234).
# ICD-10 codes (one letter), LOINC codes and doses never have this shape.
PLAIN_ID = re.compile(r'(?<![\w])[A-Z]{2,6}\d{5,}(?![\w])')

MASKED_AADHAAR = re.compile(r'(?i)(?<!\w)[x*]{4}[ -]?[x*]{4}[ -]?\d{4}(?!\w)')
COMPACT_ID = re.compile(r'(?i)(?<!\w)[a-z]{2,8}\d{2,4}[-/]\d{5,}(?!\w)')

ISO_TIMESTAMP = re.compile(r'(?<!\w)(?P<date>\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?(?![\w:+.-])')

def normalize_timestamp_date(value):
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00')).date().isoformat()
    except ValueError:
        return None
