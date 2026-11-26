"""Offline detection only. Returned attributes are sensitive, not anonymized."""
from __future__ import annotations
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from .schema import EntitySpan, DetectionResult
from .field_hints import canonical_hint
from . import patterns as p
from .medical_whitelist import protected_ranges, blocked_word
from .context_rules import name_candidates, normalize_name, overlaps, resolve

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / 'config' / 'policy.yaml'

@lru_cache(maxsize=16)
def _load_policy(path, modified, size):
    try:
        content = Path(path).read_text(encoding='utf-8')
        try:
            policy = json.loads(content)  # JSON is a valid YAML subset.
        except ValueError:
            import yaml
            policy = yaml.safe_load(content)
        expected = json.loads(DEFAULT_POLICY.read_text(encoding='utf-8'))
        if not isinstance(policy, dict) or set(policy) != set(expected):
            raise ValueError
        for key in ('honorifics', 'relationship_markers', 'doctor_prefixes'):
            if not isinstance(policy[key], list) or not policy[key] or not all(isinstance(x, str) and x for x in policy[key]):
                raise ValueError
        if type(policy['max_text_length']) is not int or not 1 <= policy['max_text_length'] <= 10000000:
            raise ValueError
        if type(policy['two_digit_year_pivot']) is not int or not 0 <= policy['two_digit_year_pivot'] <= 99:
            raise ValueError
        if type(policy['bare_name_detection']) is not bool:
            raise ValueError
        if set(policy['enabled_ids']) != {'AADHAAR','ABHA','PAN','UHID'} or not all(type(v) is bool for v in policy['enabled_ids'].values()):
            raise ValueError
        if set(policy['actions']) != set(expected['actions']) or not all(v in {'PSEUDONYMIZE','REDACT','DATE_SHIFT','GENERALIZE','KEEP_META'} for v in policy['actions'].values()):
            raise ValueError
        return policy
    except Exception:
        raise ValueError('Invalid detector policy') from None

def _policy(path):
    try:
        target = Path(path) if path is not None else DEFAULT_POLICY
        stat = target.stat()
        return _load_policy(str(target.resolve()), stat.st_mtime_ns, stat.st_size)
    except Exception:
        raise ValueError('Invalid detector policy') from None

def _date_kind(text, start, hint):
    if re.search(r'(?i)\b(?:dob|date[ _]of[ _]birth|birth[ _]?date|born)\b|जन्म\s*तिथि', hint):
        return 'DOB'
    prefix = re.split(r'[;\n]', text[max(0,start-45):start])[-1]
    return 'DOB' if re.search(r'(?i)(?:dob|date of birth|born|जन्म\s*तिथि)\s*[:=-]?\s*$', prefix) else 'DATE'

def detect_text(text: str, field_hint: str = '', policy_path: str | None = None) -> DetectionResult:
    if not isinstance(text, str) or not isinstance(field_hint, str):
        raise TypeError('Detector requires string inputs')
    date_order = 'MDY' if re.search(r'(?i)MM[/-]DD',field_hint) else 'DMY'
    field_hint = canonical_hint(field_hint)
    policy = _policy(policy_path)
    if len(text) > policy['max_text_length']:
        raise ValueError('Detector input exceeds configured limit')
    candidates = []
    protection = protected_ranges(text)
    names, doctors = name_candidates(text, policy, field_hint)
    honors = {s.casefold() for s in policy['honorifics']}
    def add(start, end, kind, norm=None, confidence=.95):
        if start >= end:
            return
        if kind in {'PERSON','RELATIVE'} and any(overlaps((start,end), r) for r in doctors):
            return
        if any(overlaps((start,end), r) for r in protection):
            return
        raw = text[start:end]
        candidates.append(EntitySpan(start, end, kind, raw, raw if norm is None else norm, policy['actions'][kind], confidence))
    for start, end, kind, confidence in names:
        add(start, end, kind, normalize_name(text[start:end], honors), confidence)
    if policy['enabled_ids']['AADHAAR']:
        for m in p.MASKED_AADHAAR.finditer(text):
            add(*m.span(), 'ID_AADHAAR', 'MASKED:'+p.digits(m[0]), .9)
    for m in p.COMPACT_ID.finditer(text):
        if policy['enabled_ids']['UHID']: add(*m.span(), 'ID_UHID', m[0].upper(), .9)
    for m in p.EMAIL.finditer(text):
        add(*m.span(), 'EMAIL', m[0].casefold())
    for kind, pattern in [('PAN',p.PAN),('ABHA',p.ABHA),('AADHAAR',p.AADHAAR)]:
        if policy['enabled_ids'][kind]:
            for m in pattern.finditer(text):
                add(*m.span(), 'ID_'+kind, m[0] if kind == 'PAN' else p.digits(m[0]))
    if policy['enabled_ids']['UHID']:
        for m in p.STRUCTURED_ID.finditer(text):
            add(*m.span(), 'ID_UHID', m[0].upper(), .9)
        for m in p.ID_LABEL.finditer(text):
            if any(c.isdigit() for c in m[1]):
                add(*m.span(1), 'ID_UHID', m[1].upper())
        if re.fullmatch(r'(?i)(uhid|mrn|ipd|opd|reg(?:istration)?[ _-]?(?:no|id)?|insurance(?:[ _-]?(?:id|no))?)', field_hint.strip()):
            value = text.strip()
            if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/-]{1,39}', value) and any(c.isdigit() for c in value):
                add(len(text)-len(text.lstrip()), len(text.rstrip()), 'ID_UHID', value.upper(), .87)
    for m in p.PHONE.finditer(text):
        norm = p.normalize_phone(m[0])
        if norm:
            add(*m.span(), 'PHONE', norm)
    for pattern in (p.NUM_DATE, p.TEXT_DATE):
        for m in pattern.finditer(text):
            norm = p.normalize_date(m[0], policy['two_digit_year_pivot'], date_order)
            if norm:
                add(*m.span(), _date_kind(text,m.start(),field_hint), norm)
    for m in p.AGE.finditer(text):
        group = next(key for key in ('label','years','compact') if m[key] is not None)
        duration = group == 'years' and re.search(r'(?i)(?:\bfor|\bsince|\blast|\bpast|\bx|duration[:=]?)\s*$', text[max(0,m.start()-30):m.start()])
        duration = duration or (group == 'years' and re.match(r'(?i)\s*(?:back|ago)\b',text[m.end():]))
        if int(m[group]) <= 120 and not duration:
            add(*m.span(group), 'AGE', str(int(m[group])))
    if re.fullmatch(r'(?i)(age|उम्र|आयु)',field_hint.strip()) and text.strip().isdigit() and int(text.strip()) <= 120:
        add(len(text)-len(text.lstrip()),len(text.rstrip()),'AGE',str(int(text.strip())))
    for m in p.GENDER.finditer(text):
        group = 'compact_gender' if m['compact_gender'] else 0
        if group and int(re.match(r'\d+', m[0])[0]) > 120:
            continue
        add(*m.span(group), 'GENDER', 'F' if m[group].casefold() in {'f','female','महिला'} else 'M')
    if re.fullmatch(r'(?i)(sex|gender)',field_hint.strip()) and text.strip().upper() in {'F','M'}:
        add(len(text)-len(text.lstrip()),len(text.rstrip()),'GENDER',text.strip().upper())
    address_hint = bool(re.search(r'(?i)address|location|city|village|district|पता|जिला', field_hint))
    address_marker = r'(?i)(?<!\w)(?:address|village|vill\.?|gram|mohalla|gali|tehsil|taluka|block|post|dist(?:rict)?\.?|house\s*no\.?|makan\s*no\.?|h\.no\.?|ग्राम|गांव|मोहल्ला|तहसील|जिला|पता)(?!\w)\s*[:=-]?\s*'
    address_ranges = []
    for m in re.finditer(address_marker,text):
        tail = text[m.end():]
        boundary = re.search(r'[;\n]|\b(?:phone|mobile|age|dob|BP|diagnosis|PIN(?:CODE)?)\b',tail,re.I)
        end = m.end() + (boundary.start() if boundary else len(tail))
        end = len(text[:end].rstrip(' ,'))
        if end > m.end():
            address_ranges.append((m.end(),end))
    if address_hint and text.strip():
        address_ranges.append((len(text)-len(text.lstrip()),len(text.rstrip())))
    for m in p.PIN.finditer(text):
        local = text[max(0,m.start()-40):m.start()]
        if address_hint or re.search(r'(?i)pin(?:code)?\s*[:=-]?\s*$',local) or any(a <= m.start() < b for a,b in address_ranges) or re.search(r'(?i)pin',field_hint):
            add(*m.span(),'PINCODE',m[0])
    # Split location candidates around stronger PII and explicit PIN values;
    # resolving a nested PIN must not discard the entire street address.
    for start,end in address_ranges:
        cuts = sorted((s.start,s.end) for s in candidates if overlaps((start,end),(s.start,s.end)) and s.entity_type != 'PERSON')
        cursor = start
        for a,b in cuts + [(end,end)]:
            a = min(a,end)
            left,right = cursor,a
            while left < right and text[left] in ' ,': left += 1
            while right > left and text[right-1] in ' ,': right -= 1
            if left < right:
                # Address context outranks generic name guesses, but not explicit patient labels.
                candidates[:] = [s for s in candidates if not (s.entity_type == 'PERSON' and s.confidence < .9 and overlaps((left,right),(s.start,s.end)))]
                add(left,right,'LOCATION',text[left:right].casefold(),.87)
            cursor = max(cursor,b)
    result = DetectionResult(spans=resolve(candidates))
    def append_unique(values, value):
        if value not in values: values.append(value)
    fields = {'PERSON':'patient_names','RELATIVE':'relative_names','PHONE':'phones','DATE':'dates','LOCATION':'locations','PINCODE':'pincodes'}
    for span in result.spans:
        kind, value = span.entity_type, span.normalized
        if kind in fields:
            append_unique(getattr(result,fields[kind]),value)
        elif kind.startswith('ID_'):
            append_unique(result.ids.setdefault(kind[3:],[]),value)
        elif kind == 'DOB' and result.dob is None: result.dob = value
        elif kind == 'AGE' and result.age is None: result.age = int(value)
        elif kind == 'GENDER' and result.gender is None: result.gender = value
    return result

def detect_record(record: dict[str, Any], policy_path: str | None = None) -> dict[str, DetectionResult]:
    """Flat fields keep their keys. Nested fields use escaped RFC 6901 pointers.
    Offsets refer to each leaf string (or str(number)), never a JSON serialization.
    Keys must be inspected separately with detect_key_or_filename.
    """
    if not isinstance(record,dict) or not all(isinstance(k,str) for k in record):
        raise TypeError('Record must be a string-keyed dictionary')
    output = {}
    nested = any(isinstance(v,(list,dict)) for v in record.values())
    seen = set()
    def escape(value): return value.replace('~','~0').replace('/','~1')
    def walk(value,path,hint,depth):
        if depth > 64: raise ValueError('Record nesting exceeds configured limit')
        if isinstance(value,(dict,list)):
            if id(value) in seen: raise ValueError('Cyclic record is unsupported')
            seen.add(id(value))
            try:
                for key,item in (value.items() if isinstance(value,dict) else enumerate(value)):
                    if isinstance(value,dict) and not isinstance(key,str):
                        raise TypeError('Record keys must be strings')
                    walk(item,path+'/'+escape(str(key)),str(key) if isinstance(value,dict) else hint,depth+1)
            finally: seen.remove(id(value))
        elif value is None or isinstance(value,bool):
            output[path] = DetectionResult()
        elif isinstance(value,(str,int,float)):
            output[path] = detect_text(str(value),hint,policy_path)
        else:
            raise TypeError('Unsupported record value type')
    for key,value in record.items():
        walk(value,'/'+escape(key) if nested else key,key,0)
    return output

def detect_key_or_filename(label: str) -> list[EntitySpan]:
    """Analyze metadata without changing offsets. Conservative filename heuristic.
    Ambiguous metadata should be replaced wholesale by Member 1 with safe names.
    """
    if not isinstance(label,str): raise TypeError('Metadata must be a string')
    # Only replace separators, preserving length. Extension is excluded from guesses.
    view = label.replace('_',' ')
    spans = detect_text(view).spans
    _, doctors = name_candidates(view, _policy(None))
    stem_end = len(label)
    extension = re.search(r'\.(?:txt|csv|tsv|json|pdf|xml|docx)$',label,re.I)
    if extension: stem_end = extension.start()
    from .context_rules import TOKEN
    tokens = list(TOKEN.finditer(view,0,stem_end))
    runs = []
    current = []
    for token in tokens:
        if blocked_word(token[0]) or any(overlaps(token.span(),r) for r in doctors) or any(overlaps(token.span(),(s.start,s.end)) for s in spans):
            if current: runs.append(current)
            current = []
        elif current and view[current[-1].end():token.start()].strip(' -'):
            runs.append(current); current = [token]
        else:
            current.append(token)
    if current: runs.append(current)
    policy = _policy(None)
    for run in runs:
        if len(run) >= 2 or (len(run)==1 and (extension or re.search(r'patient|name',view,re.I))):
            a,b = run[0].start(),run[-1].end()
            spans.append(EntitySpan(a,b,'PERSON',label[a:b],normalize_name(view[a:b],set(policy['honorifics'])),'PSEUDONYMIZE',.60))
    return resolve([EntitySpan(s.start,s.end,s.entity_type,label[s.start:s.end],s.normalized,s.action,s.confidence) for s in spans])
