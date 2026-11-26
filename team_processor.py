"""Member 3: final processor = Member 2 detection + linkage + privacy layer.

Contract (see MEMBER3_READINESS.md): observe() -> finish() -> clean().
All evidence stays in RAM. Nothing here prints, logs or writes files.
"""
from __future__ import annotations

import re
from collections import Counter

from detector import detect_text
from detector import patterns as p
from detector.engine import _date_kind
from detector.schema import EntitySpan
from detector.context_rules import resolve, overlaps
from member2_processor import Processor as DetectorAdapter, DIRECT
import linker as L
import privacy as P

ICD = re.compile(r'(?<![A-Za-z0-9])[A-TV-Z][0-9]{2}(?:\.[0-9]{1,2})?(?![A-Za-z0-9.])')
REGION_KEYS = {'district', 'tehsil', 'taluka', 'jila', 'जिला', 'तहसील', 'state', 'block'}
VILLAGE_KEYS = re.compile(r'(?i)village|gaon|gram|mohalla|city|ग्राम|गांव')
PLACE_STOP = set('house makan ward mohalla tehsil distt district near opp road colony gali gram village vill post block nagar kalan khurd basti purwa ganj pur bazar mandir school tanki primary chowk'.split())
_PLACE_STOP_KEYS = {L.place_key(x) for x in PLACE_STOP}
FHIR_ID_KEYS = {'id', 'reference', 'fullUrl'}


def _id_key(span):
    kind = span.entity_type[3:]
    if kind == 'AADHAAR' and span.normalized.startswith('MASKED:'):
        return None                       # masked suffixes are not unique
    value = re.sub(r'[^0-9A-Za-z@.]', '', span.normalized).upper()
    if kind == 'UHID':
        value = re.sub(r'[^0-9A-Z]', '', value)
        if sum(c.isdigit() for c in value) < 4:
            return None
    return (kind, value) if value else None


_RELATIVE_KEY = re.compile(r'pita|pati|father|mother|husband|wife|spouse|guardian|relative|attendant|kin|abhibhavak|पिता|पति|अभिभावक')
_DOCTOR_KEY = re.compile(r'doctor|dr|consultant|physician|referred|ref|author|practitioner|nurse|staff|clerk|by$')


_RELATIVE_CONTEXT = re.compile(r"(?i)(?:pita|pati|father|mother|husband|wife|spouse|guardian|relative|attendant|kin|पिता|पति|पत्नी|माता|अभिभावक)(?:['’]s)?\W*(?:ka|ki|का|की)?\s*(?:naam|name|नाम)?\s*[:=-]?\s*$")


def romanised_hint(key):
    """Recognise unseen/romanised labels ("Naam", "Umar", "Janm Tithi")."""
    compact = re.sub(r'[^a-z\u0900-\u097f]', '', L.transliterate(key).casefold())
    if not compact or len(compact) > 40:
        return None
    if re.search(r'naam|name|nam$', compact):
        if _DOCTOR_KEY.search(compact) or re.search(r'hospital|lab|facility|drug|test|file|user', compact):
            return None
        return 'relative' if _RELATIVE_KEY.search(compact) else 'patient name'
    if re.fullmatch(r'(patient)?(umar|umr|umra|aayu|aayu|ayu)', compact):
        return 'age'
    if re.fullmatch(r'(ling|linga)', compact):
        return 'gender'
    if re.search(r'janm|janam', compact):
        return 'dob'
    if re.fullmatch(r'(jila|zila|zilla)', compact):
        return '__district__'
    if re.fullmatch(r'(mobile|phone|contact|mob)(no|number)?', compact):
        return ''
    return None


class Processor(DetectorAdapter):
    def __init__(self, secret):
        super().__init__(secret)
        self.config = P.load_config()
        self.linker = L.Linker()
        self.regions = set()
        self.file_order = {}
        self.assignment = {}
        self.cluster_psn = {}
        self.cluster_names = {}
        self.cluster_ids = {}
        self.levels = {}
        self._ctx = None
        self._generalized_record = False

    def _hint(self, key, path, inherited='', role=''):
        hint = super()._hint(key, path, inherited, role)
        if hint == 'patient name' and any(str(x).casefold() in {'contact', 'guardian', 'relatedperson', 'attendant', 'link'} for x in path):
            return 'relative'
        if hint == key and isinstance(key, str):
            alias = romanised_hint(key)
            if alias:
                return alias
        return hint

    def _key(self, key):
        # Recognised schema labels ("District", "Naam", "Patient Name") are not
        # personal data; only rename them if they hold a strong identifier.
        from detector.field_hints import canonical_hint
        if canonical_hint(key) != key or romanised_hint(key) is not None:
            if not any(s.entity_type in DIRECT - {'PERSON', 'RELATIVE'} for s in self._spans(key, '__clinical__')):
                return key
        return super()._key(key)

    # ------------------------------------------------------------ observe
    def observe(self, file_id, loc, data):
        evidence = L.Evidence()
        strong, weak = set(), set()
        strong_order = []
        dates = []
        raw_dates = []
        order_votes = self.file_order.setdefault(file_id, Counter())
        for path, text, hint in self._leaves(data):
            stripped = text.strip()
            if not stripped:
                continue
            key = path[-1] if path else ''
            if hint in {'__clinical__', '__district__'}:
                self.clinical_values.add(stripped)
            if hint == '__district__':
                self.district_values.add(stripped)
            if key.casefold() in REGION_KEYS or hint == '__district__':
                for t in L.name_tokens(stripped):
                    self.regions.add(L.place_key(t))
                evidence.districts.add(stripped.casefold())
            for m in p.NUM_DATE.finditer(text):
                raw_dates.append(m[0])
                vote = P.only_valid_order(m[0])
                if vote:
                    order_votes[vote] += 1
            evidence.codes.update(ICD.findall(text) if hint == '__clinical__' or 'iagnos' in key or '(' in text else ())
            spans = detect_text(text, hint).spans
            person_like = [s for s in spans if s.entity_type == 'PERSON' and s.confidence >= .85]
            strong_leaf = hint == 'patient name' 
            for span in spans:
                kind = span.entity_type
                if kind in {'PERSON', 'RELATIVE'} and span.confidence >= .85 and len(span.text.strip()) >= 3 and loc is not None:
                    # Envelope "name" fields describe facilities, not people.
                    self.names.add(span.text.strip())
                if kind == 'PERSON' and span in person_like and _RELATIVE_CONTEXT.search(text[max(0, span.start - 30):span.start].split('\n')[-1]):
                    tokens = L.name_tokens(span.text)
                    if L.identifying(tokens):
                        evidence.relatives.add(tokens)
                elif kind == 'PERSON' and span in person_like:
                    tokens = L.name_tokens(span.text)
                    if L.identifying(tokens):
                        if strong_leaf or span.confidence >= .95:
                            if tokens not in strong:
                                strong_order.append(tokens)
                            strong.add(tokens)
                        else:
                            weak.add(tokens)
                elif kind == 'RELATIVE' and span.confidence >= .85:
                    tokens = L.name_tokens(span.text)
                    if L.identifying(tokens):
                        evidence.relatives.add(tokens)
                elif kind.startswith('ID_') or kind == 'EMAIL':
                    k = _id_key(span) if kind != 'EMAIL' else ('EMAIL', span.normalized)
                    if k:
                        evidence.ids.add(k)
                elif kind == 'PHONE':
                    evidence.phones.add(span.normalized)
                elif kind == 'DOB':
                    evidence.dobs.add(span.normalized)
                elif kind == 'AGE':
                    evidence.ages.add(int(span.normalized))
                elif kind == 'GENDER':
                    evidence.genders.add(span.normalized)
                elif kind == 'DATE':
                    dates.append(span.normalized)
                elif kind == 'LOCATION':
                    self._places(evidence, span.text)
            if VILLAGE_KEYS.search(key) and hint != '__district__':
                self._places(evidence, stripped)
        if loc is None:
            return                      # export envelope: never a patient record
        evidence.ages = {(a, None) for a in evidence.ages}
        evidence.raw_dates = raw_dates
        evidence.iso_dates = dates
        # Labelled patient names ("Patient Name:", name columns, FHIR Patient)
        # outrank names found in narrative. Weak names that disagree with a
        # labelled name are other people (attendants, staff) and are ignored.
        # Several different *labelled* names -> we cannot tell whose record it is.
        evidence.relatives = {r for r in evidence.relatives if not any(L.compare_names(r, n) == 'full' for n in strong)}
        if len(strong) > 1 and all(len(n) == 1 for n in strong):
            # FirstName / LastName (or FHIR given/family) columns of one record.
            strong = {tuple(t for n in strong_order for t in n)}
        base = strong or weak
        multi = [n for n in base if len(L.identifying(n)) >= 2]
        base = {n for n in base if n in multi or not any(L.compare_names(n, m) == 'partial' for m in multi)}
        names = sorted(base)
        for x in range(len(names)):
            for y in range(x + 1, len(names)):
                if L.compare_names(names[x], names[y]) == 'conflict':
                    evidence.ambiguous = True
        evidence.names = set(base)
        if strong:
            evidence.names |= {w for w in weak if all(L.compare_names(w, n) != 'conflict' for n in strong)}
        if len(evidence.genders) > 1:
            evidence.ambiguous = True
        self.linker.add((file_id, loc), evidence)

    def _places(self, evidence, text):
        for t in L.name_tokens(text):
            s = L.place_key(t)
            if len(s) >= 4 and t not in PLACE_STOP and s not in _PLACE_STOP_KEYS:
                evidence.places.add(s)

    # ------------------------------------------------------------ finish
    def finish(self):
        super().finish()
        for (file_id, _), ev in self.linker.records.items():
            ev.places -= self.regions
            votes = self.file_order.get(file_id, Counter())
            order = 'MDY' if votes['MDY'] > votes['DMY'] else 'DMY'
            years = [int(d[:4]) for d in getattr(ev, 'iso_dates', [])] if order == 'DMY' else []
            for raw in getattr(ev, 'raw_dates', []):
                value, _ = P.parse_numeric(raw, order)
                if value:
                    years.append(value.year)
            ref = max(years) if years else None      # latest event; DOB is the earliest date
            ev.ages = {(a, ref) for a, _ in ev.ages}
        self.assignment = self.linker.resolve()
        clusters = {}
        for key, cid in self.assignment.items():
            if cid is not None:
                clusters.setdefault(cid, []).append(key)
        used = {}
        for cid in sorted(clusters):
            ev = self.linker.cluster_evidence[cid]
            anchor = repr((sorted(ev.ids), sorted(ev.names), sorted(ev.dobs), sorted(ev.phones)))
            psn = P.pseudonym(self.secret, anchor, self.config['pseudonym_length'])
            while psn in used:
                anchor += '+'
                psn = P.pseudonym(self.secret, anchor, self.config['pseudonym_length'])
            used[psn] = cid
            self.cluster_psn[cid] = psn
            self.cluster_names[cid] = ev.names
            self.cluster_ids[cid] = ev.ids
        subjects = {}
        for key, ev in self.linker.records.items():
            cid = self.assignment.get(key)
            sid = ('C', cid) if cid is not None else ('R', repr(key))
            info = subjects.setdefault(sid, {'codes': set(), 'ages': set(), 'gender': None, 'district': None})
            info['codes'].update(ev.codes)
            info['ages'].update(a for a, _ in ev.ages)
            if ev.genders and info['gender'] is None:
                info['gender'] = sorted(ev.genders)[0]
            if ev.districts and info['district'] is None:
                info['district'] = sorted(ev.districts)[0]
        self.levels = P.risk_levels(subjects, self.config)

    # ------------------------------------------------------------ clean
    def clean(self, file_id, loc, data):
        key = (file_id, loc)
        cid = self.assignment.get(key) if loc is not None else None
        psn = self.cluster_psn.get(cid) if cid is not None else None
        subject = psn or 'rec\x00' + file_id + '\x00' + str(loc)
        sid = ('C', cid) if cid is not None else ('R', repr(key))
        votes = self.file_order.get(file_id, Counter())
        self._ctx = {
            'psn': psn,
            'names': self.cluster_names.get(cid, set()),
            'ids': self.cluster_ids.get(cid, set()),
            'shift': P.shift_days(self.secret, subject, self.config['shift_min_days'], self.config['shift_max_days']),
            'level': self.levels.get(sid, 0),
            'order': 'MDY' if votes['MDY'] > votes['DMY'] else 'DMY',
            'key': '',
            'placed': False,
        }
        self._generalized_record = False
        try:
            value = self._value(data)
            if psn is not None and not self._contains(value, psn):
                value, psn = self._embed(value, psn, loc)
        finally:
            self._ctx = None
        if self._generalized_record:
            self.generalized += 1
        return value, psn

    @staticmethod
    def _contains(value, psn):
        import json
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        return re.search(r'(?<![A-Za-z0-9-])' + re.escape(psn) + r'(?![A-Za-z0-9-])', text) is not None

    @staticmethod
    def _embed(value, psn, loc):
        if isinstance(value, str):
            return 'Patient: ' + psn + '\n' + value, psn
        if isinstance(value, dict) and not str(loc).startswith('row:') and 'resourceType' not in value:
            if 'patient_pseudonym' not in value:
                value = dict(value)
                value['patient_pseudonym'] = psn
                return value, psn
        return value, None             # cannot embed safely -> do not claim a link

    # ------------------------------------------------------------ leaves
    def _value(self, data, path=(), hint='', depth=0):
        if self._ctx is not None and (isinstance(data, str) or (isinstance(data, (int, float)) and not isinstance(data, bool))):
            self._ctx['key'] = path[-1] if path else ''
            if isinstance(data, str):
                if path and path[-1].casefold() in {'source_path', 'sourcepath', 'filepath', 'file_path'}:
                    self.entities['METADATA'] += 1
                    return '[SOURCE_PATH]'
                return self._text(data, hint)
            spans = self._spans(str(data), hint)
            if any(s.entity_type in DIRECT for s in spans):
                self.entities['NUMERIC_ID'] += 1
                return 0 if isinstance(data, int) else 0.0
            if isinstance(data, int) and any(s.entity_type == 'AGE' and s.start == 0 and s.end == len(str(data)) for s in spans):
                self.entities['AGE'] += 1
                self._generalized_record = True
                return P.age_band(data, self._ctx['level'], self.config)
            return data
        return super()._value(data, path, hint, depth)

    def _extra_dates(self, text, hint, spans):
        """Month-first files: dates the DMY detector could not parse."""
        order = self._ctx['order'] if self._ctx else 'DMY'
        if order != 'MDY':
            return spans
        out = list(spans)
        for m in p.NUM_DATE.finditer(text):
            if any(overlaps(m.span(), (s.start, s.end)) for s in spans):
                continue
            value, _ = P.parse_numeric(m[0], 'MDY')
            if value:
                kind = _date_kind(text, m.start(), hint)
                out.append(EntitySpan(m.start(), m.end(), kind, m[0], value.isoformat(), 'DATE_SHIFT', .9))
        return resolve(out)

    def _sweep_patient_tokens(self, text, hint, spans):
        """Catch spelling variants of the linked patient's own name ("Zenab" for
        "Zainab") that the context detector missed. Doctors and clinical terms
        are protected exactly as in detection."""
        names = self._ctx['names'] if self._ctx else ()
        if not names or hint == '__clinical__':
            return spans
        wanted = {L.simplify(t) for n in names for t in L.identifying(n) if len(t) >= 3}
        if not wanted:
            return spans
        from detector.context_rules import TOKEN, name_candidates
        from detector.engine import _policy
        from detector.medical_whitelist import protected_ranges, blocked_word
        _, doctors = name_candidates(text, _policy(None), hint)
        blocked = doctors + protected_ranges(text) + [(s.start, s.end) for s in spans]
        extra = []
        for m in TOKEN.finditer(text):
            word = m[0].rstrip('.')
            if len(word) < 3 or blocked_word(word) or not (word[0].isupper() or '\u0900' <= word[0] <= '\u097f'):
                continue
            if any(overlaps(m.span(), r) for r in blocked):
                continue
            toks = L.name_tokens(word)
            if toks and any(L.token_match(toks[0], w) >= L.TOKEN_OK or L.simplify(toks[0]) == w for w in wanted):
                extra.append(EntitySpan(m.start(), m.start() + len(word), 'PERSON', word, word.casefold(), 'PSEUDONYMIZE', .9))
        return resolve(list(spans) + extra) if extra else spans

    def _is_patient_name(self, text):
        tokens = L.name_tokens(text)
        if not L.identifying(tokens):
            return False
        return any(L.compare_names(tokens, n) in ('full', 'partial') for n in self._ctx['names'])

    def _text(self, text, hint):
        if self._ctx is None:
            return super()._text(text, hint)
        ctx = self._ctx
        level = ctx['level']
        if hint == '__district__':
            if level >= 2 and text.strip():
                self.entities['DISTRICT'] += 1
                self._generalized_record = True
                return '[DISTRICT]'
            return text
        spans = self._extra_dates(text, hint, self._spans(text, hint))
        spans = self._sweep_patient_tokens(text, hint, spans)
        result = text
        for span in reversed(spans):
            kind = span.entity_type
            replacement = None
            if kind == 'PERSON':
                replacement = ctx['psn'] if ctx['psn'] and self._is_patient_name(span.text) else '[PERSON]'
            elif kind == 'RELATIVE':
                replacement = '[RELATIVE]'
            elif kind.startswith('ID_'):
                ident = _id_key(span)
                if ctx['psn'] and ident in ctx['ids'] and hint == 'uhid':
                    replacement = ctx['psn']
                    if len(span.text) * 2 >= len(text.strip()):
                        # "UHID-010610" -> "PSN-..." (whole reference cell)
                        self.entities[kind] += 1
                        return ctx['psn']
                elif ctx['key'] in FHIR_ID_KEYS:
                    replacement = 'id-' + P.token(self.secret, 'fhir', span.text)
                else:
                    replacement = '[' + kind + ']'
            elif kind in {'PHONE', 'EMAIL'}:
                replacement = '[' + kind + ']'
            elif kind == 'DATE':
                shifted = P.shift_text_date(span.text, ctx['shift'], ctx['order'])
                replacement = shifted if shifted is not None else '[DATE]'
                self._generalized_record = True
            elif kind == 'DOB':
                replacement = self._dob(span, level)
                self._generalized_record = True
            elif kind == 'AGE':
                replacement = P.age_band(int(span.normalized), level, self.config)
                self._generalized_record = True
            elif kind == 'PINCODE':
                replacement = P.generalize_pin(span.text, level, self.config)
                self._generalized_record = True
            elif kind == 'LOCATION':
                replacement = '[LOCATION]'
                if level < 2:
                    kept = [v for v in sorted(self.district_values) if re.search(r'(?<!\w)' + re.escape(v) + r'(?!\w)', span.text, re.I)]
                    if kept:
                        replacement += ' ' + ', '.join(kept)
                self._generalized_record = True
            if replacement is None:
                continue
            self.entities[kind] += 1
            result = result[:span.start] + replacement + result[span.end:]
        return result

    def _dob(self, span, level):
        try:
            year = int(span.normalized[:4])
        except ValueError:
            return '[DOB]'
        if self._ctx['key'] == 'birthDate':
            # FHIR needs a valid date: keep the format, shift within the patient.
            shifted = P.shift_text_date(span.text, self._ctx['shift'], self._ctx['order'])
            return shifted if shifted else str(year)
        return P.birth_year_band(year, level, self.config)
