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
from detector.medical_whitelist import blocked_word
from detector.context_rules import resolve, overlaps
from member2_processor import Processor as DetectorAdapter, DIRECT
import linker as L
import privacy as P
import deobfuscate as D

ICD = re.compile(r'(?<![A-Za-z0-9])[A-TV-Z][0-9]{2}(?:\.[0-9]{1,2})?(?![A-Za-z0-9.])')
REGION_KEYS = {'district', 'tehsil', 'taluka', 'jila', 'जिला', 'तहसील', 'state', 'block'}
VILLAGE_KEYS = re.compile(r'(?i)village|gaon|gram|mohalla|city|ग्राम|गांव')
PLACE_STOP = set('house makan ward mohalla tehsil distt district near opp road colony gali gram village vill post block nagar kalan khurd basti purwa ganj pur bazar mandir school tanki primary chowk street cross lane marg sector main bypass highway nh sh phase extension layout behind beside opposite'.split())
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


_RELATIVE_KEY = re.compile(r'pita|pati|father|mother|husband|wife|spouse|guardian|relative|attendant|kin|abhibhavak|rishtedar|पिता|पति|अभिभावक')
_DOCTOR_KEY = re.compile(r'doctor|dr|consultant|physician|referred|ref|author|practitioner|nurse|staff|clerk|by$')


_RELATIVE_CONTEXT = re.compile(r"(?i)(?:pita|pati|father|mother|husband|wife|spouse|guardian|relative|attendant|kin|पिता|पति|पत्नी|माता|अभिभावक)(?:['’]s)?\W*(?:ka|ki|का|की)?\s*(?:naam|name|नाम)?\s*[:=-]?\s*$")


_NAME_PART_KEY = re.compile(r'(?i)first|given|last|surname|family|middle|fore')
_PATH_KEY = re.compile(r'(?i)path|export(ed)?_?from|source_?(file|dir|folder)?$|folder|directory|^dir$|file_?name|location_on_disk')
_BY_KEY = re.compile(r'(?i)(exported|entered|created|uploaded|verified|updated|modified|recorded|collected|reported)_?by$|^(operator|clerk|user(name)?)$')
_DATA_URI = re.compile(r'(data:[\w/+.-]*(?:;[\w-]+=[\w-]+)*);base64,([A-Za-z0-9+/]+={0,2})')
_CHAT_SENDER = re.compile(r"\]\s*-?\s*$")      # "[11/09/26, 8:13 pm] Ajay Bhaiya:" is the sender, not the patient
_RELATIVE_AFTER = re.compile(r"(?i)\s*[(,-]\s*(?:attendant|relative|visitor|guardian|husband|wife|father|mother|son|daughter|brother|sister|bhai|pati|patni)\b")
_NAME_IN_KEY = re.compile(r"(?i:(?<![A-Za-z])(?:by|for|of|to|from|attendant|relative|patient|pt|name|naam|re|caller|contact)(?![A-Za-z]))[\s:_-]+([A-Z][a-z]+(?:[\s_]+[A-Z][a-z]+)+)")
_PERSON_URL = re.compile(r"(?i)maiden|mother|father|relative|kin|informant|contact|guardian|spouse|name|author|caregiver")
_TWIN = re.compile(r"(?i)\btwin\s*[-#:]?\s*([12ab])\b|(?:जुड़वां|जुड़वा)\s*([12])")


def romanised_hint(key):
    """Recognise unseen/romanised labels ("Naam", "Umar", "Janm Tithi")."""
    compact = re.sub(r'[^a-z\u0900-\u097f]', '', L.transliterate(key).casefold())
    if not compact or len(compact) > 40:
        return None
    if re.search(r'naam|name|nam$', compact):
        if _DOCTOR_KEY.search(compact) or re.search(r'hospital|lab|facility|drug|test|file|user', compact):
            return None
        return 'relative' if _RELATIVE_KEY.search(compact.replace('patient', '')) else 'patient name'
    if re.fullmatch(r'(patient)?(umar|umr|umra|aayu|aayu|ayu)', compact):
        return 'age'
    if re.fullmatch(r'(ling|linga)', compact):
        return 'gender'
    if re.search(r'janm|janam', compact):
        return 'dob'
    if re.fullmatch(r'(jila|zila|zilla|dist|distt|districtname)', compact):
        return '__district__'
    if re.search(r'nidan|nidaan|diagnos|rog$|bimari|beemari|lakshan|upchar|ilaj|dawa|dawai|aushadhi|jaanch|janch', compact):
        return '__clinical__'
    if re.search(r'esic|policy|insurance|member(id|no)|beneficiary|cardno|scheme(id|no)|tpa|pmjay|ayushman|uan', compact):
        return 'uhid'
    if re.search(r'locality|landmark|colony|residence|resident|addr|basti|mohalla|street|housename|houseno|town|tehsil|taluk|block|panchayat|^area$', compact):
        return 'address'
    if re.search(r'village|gaon|gaanv|gaanw|gram', compact):
        return 'address'
    if re.search(r'pincode|postal|zip', compact) or re.fullmatch(r'pin(code|kod|kd|no|number)?', compact):
        return 'pincode'
    if re.search(r'^(sex|gender|ling)', compact):
        return 'gender'
    if re.search(r'^(age|umar|umr|aayu)', compact):
        return 'age'
    if re.search(r'range|unit|value|result|code|loinc|test', compact):
        return None                      # lab/reference columns are clinical, never identifiers
    if re.search(r'(uhid|mrn|regno|regid|registration|ipno|ipdno|opdno|admissionno|patientid|ptid|ptref|patientref|ptreference|hospid|hospreg|cardno)', compact):
        return 'uhid'
    if re.search(r'dob|dateofbirth|birth', compact):
        return 'dob'
    if re.fullmatch(r'(mobile|phone|contact|mob)(no|number)?', compact):
        return ''
    return None


ICD_CHAPTERS = [('A00', 'B99', 'I: infectious'), ('C00', 'D49', 'II: neoplasm'), ('D50', 'D89', 'III: blood'),
                ('E00', 'E89', 'IV: endocrine'), ('F01', 'F99', 'V: mental'), ('G00', 'G99', 'VI: nervous system'),
                ('H00', 'H59', 'VII: eye'), ('H60', 'H95', 'VIII: ear'), ('I00', 'I99', 'IX: circulatory'),
                ('J00', 'J99', 'X: respiratory'), ('K00', 'K95', 'XI: digestive'), ('L00', 'L99', 'XII: skin'),
                ('M00', 'M99', 'XIII: musculoskeletal'), ('N00', 'N99', 'XIV: genitourinary'),
                ('O00', 'O9A', 'XV: pregnancy'), ('P00', 'P96', 'XVI: perinatal'), ('Q00', 'Q99', 'XVII: congenital'),
                ('R00', 'R99', 'XVIII: symptoms'), ('S00', 'T88', 'XIX: injury'), ('V00', 'Y99', 'XX: external cause'),
                ('Z00', 'Z99', 'XXI: health status')]
_TEXT_DX = re.compile(r'([A-Za-z\u0900-\u097f][A-Za-z\u0900-\u097f ,\'’()/-]{2,80}?)\s*\(\s*([A-TV-Z][0-9]{2}(?:\.[0-9]{1,2})?)\s*\)')


def icd_chapter(code):
    head = code[:3].upper()
    for lo, hi, name in ICD_CHAPTERS:
        if lo <= head <= hi:
            return name
    return 'other'


class Processor(DetectorAdapter):
    def __init__(self, secret):
        super().__init__(secret)
        self.config = P.load_config()
        self.linker = L.Linker()
        self.regions = set()
        self.file_order = {}
        self.file_group = {}
        self.assignment = {}
        self.cluster_psn = {}
        self.cluster_names = {}
        self.cluster_ids = {}
        self.levels = {}
        self._ctx = None
        self._generalized_record = False
        self.district_pattern = None
        self.slug_pattern = None
        self.dx_pairs = set()
        self.rare_dx_pattern = None
        self.rare_dx_label = {}

    def _hint(self, key, path, inherited='', role=''):
        if key in ('authorString', 'author_name', 'informant', 'caregiver'):
            return 'relative'
        hint = super()._hint(key, path, inherited, role)
        if isinstance(key, str) and re.search(r'(?i)MM[/-]DD', key):
            return hint                          # keep the declared month-first date order
        if hint == 'patient name' and any(str(x).casefold() in {'contact', 'guardian', 'relatedperson', 'attendant', 'link'} for x in path):
            return 'relative'
        if key in ('first', 'last', 'middle', 'surname', 'firstname', 'lastname') and inherited in ('patient name', 'relative'):
            return inherited
        if any(_RELATIVE_KEY.search(re.sub(r'[^a-z\u0900-\u097f]', '', L.transliterate(str(x)).casefold().replace('patient', '')))
               for x in path) and (hint == 'patient name' or romanised_hint(key) == 'patient name'):
            return 'relative'                    # {"abhibhavak": {"naam": ...}} is the guardian's name
        if hint == key and isinstance(key, str):
            alias = romanised_hint(key)
            if alias:
                return alias
        return hint

    def _key(self, key):
        # A name written into a header or key after a context word
        # ("verified by Zephro Anaktal", "note for Velmar Ostridge") is personal data.
        m = _NAME_IN_KEY.search(key)
        if m and not any(blocked_word(t) for t in re.split(r'[\s_]+', m[1])):
            return self._key_token(key)
        # Recognised schema labels ("District", "Naam", "Patient Name") are not
        # personal data; only rename them if they hold a strong identifier.
        from detector.field_hints import canonical_hint
        if canonical_hint(key) != key or romanised_hint(key) is not None:
            if not any(s.entity_type in DIRECT - {'PERSON', 'RELATIVE'} for s in self._spans(key, '__clinical__')):
                return key
        return super()._key(key)

    # ------------------------------------------------------------ disguises
    @staticmethod
    def _mapped(view_spans, text, idx):
        out = []
        for sp in view_spans:
            ab = D.to_original(idx, sp.start, sp.end)
            if ab:
                out.append(EntitySpan(ab[0], ab[1], sp.entity_type, text[ab[0]:ab[1]], sp.normalized, sp.action, sp.confidence))
        return out

    def _number_spans(self, text, view, idx):
        out = []
        for a, b, kind, norm in D.number_spans(view):
            ab = D.to_original(idx, a, b)
            if ab:
                out.append(EntitySpan(ab[0], ab[1], kind, text[ab[0]:ab[1]], norm, 'REDACT', .93))
        return out

    def _detect(self, text, hint):
        """Detector spans on the text and on its de-obfuscated view."""
        spans = list(detect_text(text, hint).spans)
        view, idx = D.clean_view(text)
        if view != text:
            spans += self._mapped(detect_text(view, hint).spans, text, idx)
        spans += self._number_spans(text, view, idx)
        return resolve(spans)

    def _spans(self, text, hint):
        spans = list(super()._spans(text, hint))
        if getattr(self, 'slug_pattern', None) is not None and hint not in ('__district__',):
            from detector.medical_whitelist import protected_ranges
            from detector.context_rules import name_candidates
            from detector.engine import _policy
            prot = protected_ranges(text) + name_candidates(text, _policy(None), hint)[1]
            for m in self.slug_pattern.finditer(text):
                if not any(overlaps(m.span(), r) for r in prot):
                    spans.append(EntitySpan(m.start(), m.end(), 'PERSON', m[0], m[0].casefold(), 'PSEUDONYMIZE', .9))
        if hint == '__clinical__' and self.name_pattern is not None:
            # Fields classed as clinical (title, display, system, procedure) can still
            # carry a full learned name ("Summary - Satyam Gautam", ".../satyam-gautam").
            from detector.medical_whitelist import protected_ranges
            from detector.context_rules import name_candidates
            from detector.engine import _policy
            prot = protected_ranges(text) + name_candidates(text, _policy(None), hint)[1]   # doctors stay
            for m in self.name_pattern.finditer(text):
                if re.search(r'[\s_-]', m[0]) and not any(overlaps(m.span(), r) for r in prot):
                    spans.append(EntitySpan(m.start(), m.end(), 'PERSON', m[0], m[0].casefold(), 'PSEUDONYMIZE', .9))
        view, idx = D.clean_view(text)
        if view != text:
            spans += self._mapped(super()._spans(view, hint), text, idx)
        spans += self._number_spans(text, view, idx)
        return resolve(spans)

    # ------------------------------------------------------------ observe
    def observe(self, file_id, loc, data):
        if isinstance(data, str):
            head = next((ln.strip() for ln in data.splitlines() if ln.strip()), '')
            self.file_group[file_id] = re.sub(r'[\d\W_]+', ' ', head.casefold())[:60].strip()
        elif loc is not None and str(loc).startswith('row:') and isinstance(data, dict):
            self.file_group.setdefault(file_id, 'cols:' + '|'.join(sorted(data))[:120])
        evidence = L.Evidence()
        strong, weak = set(), set()
        strong_order = []
        name_parts = []
        explicit_relatives = set()
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
            spans = self._detect(text, hint)
            strong_leaf = hint == 'patient name' 
            for span in spans:
                kind = span.entity_type
                person_like = kind == 'PERSON' and span.confidence >= .85
                if kind in {'PERSON', 'RELATIVE'} and span.confidence >= .85 and len(span.text.strip()) >= 3 and loc is not None:
                    # Envelope "name" fields describe facilities, not people.
                    self.names.add(span.text.strip())
                if kind in ('PERSON', 'RELATIVE'):
                    span = EntitySpan(span.start, span.end, kind, D.clean_view(span.text)[0], span.normalized, span.action, span.confidence)
                if person_like and (
                        _RELATIVE_CONTEXT.search(text[max(0, span.start - 30):span.start].split('\n')[-1])
                        or _RELATIVE_AFTER.match(text[span.end:span.end + 25])
                        or _CHAT_SENDER.search(text[max(0, span.start - 40):span.start].split('\n')[-1])):
                    tokens = L.name_tokens(span.text)
                    if L.identifying(tokens):
                        evidence.relatives.add(tokens)
                elif person_like:
                    tokens = L.name_tokens(span.text)
                    if L.identifying(tokens):
                        if strong_leaf and _NAME_PART_KEY.search(key or ''):
                            name_parts.append(tokens)          # FirstName / LastName / given / family columns
                        elif strong_leaf or span.confidence >= .95:
                            if tokens not in strong:
                                strong_order.append(tokens)
                            strong.add(tokens)
                        else:
                            weak.add(tokens)
                elif kind == 'RELATIVE' and span.confidence >= .85:
                    tokens = L.name_tokens(span.text)
                    if hint == 'relative':
                        explicit_relatives.add(tokens)
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
                    evidence.loc_texts = getattr(evidence, 'loc_texts', []) + [span.text]
            if VILLAGE_KEYS.search(key) and hint != '__district__':
                self._places(evidence, stripped)
        self._collect_diagnoses(data)
        for path_, text_, _ in self._leaves(data):
            for m in _TWIN.finditer(text_):
                evidence.twin = getattr(evidence, 'twin', set()) | {(m[1] or m[2]).lower()}
        if loc is None:
            return                      # export envelope: never a patient record
        evidence.ages = {(a, None) for a in evidence.ages}
        evidence.raw_dates = raw_dates
        evidence.iso_dates = dates
        # Labelled patient names ("Patient Name:", name columns, FHIR Patient)
        # outrank names found in narrative. Weak names that disagree with a
        # labelled name are other people (attendants, staff) and are ignored.
        # Several different *labelled* names -> we cannot tell whose record it is.
        evidence.relatives = {r for r in evidence.relatives if r in explicit_relatives or not any(L.compare_names(r, n) == 'full' for n in strong)}
        if name_parts:
            joined = tuple(t for part in name_parts for t in part)
            strong.add(joined)
            strong_order.append(joined)
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

    def _collect_diagnoses(self, data, depth=0):
        """Remember (ICD code, display text) pairs so rare disease names can be generalised."""
        if depth > 64:
            return
        if isinstance(data, dict):
            code, display = data.get('code'), data.get('display')
            if isinstance(code, str) and isinstance(display, str) and ICD.fullmatch(code.strip()):
                self.dx_pairs.add((code.strip().upper(), display.strip()))
            coding = data.get('coding')
            if isinstance(coding, list) and isinstance(data.get('text'), str):
                for c in coding:
                    if isinstance(c, dict) and isinstance(c.get('code'), str) and ICD.fullmatch(c['code'].strip()):
                        self.dx_pairs.add((c['code'].strip().upper(), data['text'].strip()))
            for v in data.values():
                self._collect_diagnoses(v, depth + 1)
        elif isinstance(data, list):
            for v in data:
                self._collect_diagnoses(v, depth + 1)
        elif isinstance(data, str) and '(' in data:
            for m in _TEXT_DX.finditer(data):
                display = re.split(r'[:;\n]|\b(?:and|with|of)\s*$', m[1])[-1].strip(' ,-')
                display = re.sub(r'^(?:diagnosis|dx|निदान|treated for|k/c/o|c/o)\s*[:-]?\s*', '', display, flags=re.I).strip()
                if len(display) >= 3:
                    self.dx_pairs.add((m[2].upper(), display))

    def _places(self, evidence, text):
        for t in L.name_tokens(text):
            s = L.place_key(t)
            if len(L.simplify(t)) >= 4 and t not in PLACE_STOP and s not in _PLACE_STOP_KEYS:
                evidence.places.add(s)

    def _order(self, file_id):
        """Date order of a file; ambiguous files borrow it from files with the same letterhead."""
        votes = self.file_order.get(file_id, Counter())
        if votes['MDY'] != votes['DMY']:
            return 'MDY' if votes['MDY'] > votes['DMY'] else 'DMY'
        group = self.file_group.get(file_id)
        if group:
            pooled = Counter()
            for f, g in self.file_group.items():
                if g == group:
                    pooled.update(self.file_order.get(f, Counter()))
            if pooled['MDY'] > pooled['DMY']:
                return 'MDY'
        return 'DMY'

    # ------------------------------------------------------------ finish
    def finish(self):
        super().finish()
        for (file_id, _), ev in self.linker.records.items():
            ev.places -= self.regions
            order = self._order(file_id)
            dob_set = set(ev.dobs)
            years = [int(d[:4]) for d in getattr(ev, 'iso_dates', []) if d not in dob_set] if order == 'DMY' else []
            for raw in getattr(ev, 'raw_dates', []):
                value, _ = P.parse_numeric(raw, order)
                if value and value.isoformat() not in dob_set and not any(value.isoformat()[4:] == d[4:] for d in dob_set):
                    years.append(value.year)
            ref = max(years) if years else None      # latest event date; a DOB is never the visit year
            ev.ages = {(a, ref) for a, _ in ev.ages}
        # Learned full names also in slug form: "K. Venkatesh" -> k-venkatesh, k.venkatesh, k_venkatesh.
        slugs = set()
        for n in self.names:
            toks = [t for t in re.split(r'[\s._-]+', n.strip()) if t]
            if len(toks) >= 2 and sum(len(t) for t in toks) >= 6:
                slugs.add(r'[\s._-]*'.join(re.escape(t) for t in toks))
        self.slug_pattern = re.compile(r'(?<![^\W_])(?:' + '|'.join(sorted(slugs, key=lambda x: (-len(x), x))) + r')(?![^\W_])', re.I) if slugs else None
        names = sorted({v for v in self.district_values if len(v) >= 3}, key=lambda v: (-len(v), v))
        self.district_pattern = re.compile(r'(?<!\w)(?:' + '|'.join(re.escape(v) for v in names) + r')(?!\w)', re.I) if names else None
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
            info = subjects.setdefault(sid, {'codes': set(), 'ages': set(), 'gender': None, 'district': None,
                                             'weight': 1 if cid is not None else 0})
            info['codes'].update(ev.codes)
            info['ages'].update(a for a, _ in ev.ages)
            if ev.genders and info['gender'] is None:
                info['gender'] = sorted(ev.genders)[0]
            if ev.districts and info['district'] is None:
                info['district'] = sorted(ev.districts)[0]
            if info['district'] is None and self.district_pattern is not None:
                # District written only in a free-text address ("Dist. Pratapgarh").
                for t in getattr(ev, 'loc_texts', []):
                    m = self.district_pattern.search(t)
                    if m:
                        info['district'] = m[0].casefold()
                        break
        self.levels = P.risk_levels(subjects, self.config)
        # Disease names held by very few patients point straight at one profile
        # for an attacker who knows the condition. Keep the exact ICD code (for
        # statistics) and replace the *name* with its ICD-10 chapter.
        limit = self.config.get('rare_name_max_patients', 1)
        code_patients = Counter()
        for info in subjects.values():
            if info.get('weight', 1):
                code_patients.update(info['codes'])
        rare_codes = {c for c, n in code_patients.items() if n <= limit}
        common_names = {d.casefold() for c, d in self.dx_pairs if c not in rare_codes}
        rare = {}
        for code, display in sorted(self.dx_pairs):
            if code in rare_codes and display.casefold() not in common_names and len(display) >= 4:
                rare[display.casefold()] = 'rare condition (ICD-10 ch. ' + icd_chapter(code) + ')'
        if rare:
            self.rare_dx_label = rare
            names = sorted(rare, key=lambda v: (-len(v), v))
            self.rare_dx_pattern = re.compile(r'(?<![\w\u0900-\u097f])(?:' + '|'.join(re.escape(v) for v in names) + r')(?![\w\u0900-\u097f])', re.I)

    def _fhir_links(self, data):
        """Remap resource IDs and their links together, before free-text detection."""
        if not isinstance(data, dict) or 'resourceType' not in data:
            return {}, {}
        import uuid
        nodes, stack = [], [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                nodes.append(node)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        ids = {n['id']: str(uuid.UUID(hex=P._mac(self.secret, 'fhir-resource\x00' + n['id']).hex()[:32]))
               for n in nodes if isinstance(n.get('id'), str)}
        urls = {}
        for node in nodes:
            resource = node.get('resource')
            if isinstance(node.get('fullUrl'), str) and isinstance(resource, dict) and resource.get('id') in ids:
                urls[node['fullUrl']] = 'urn:uuid:' + ids[resource['id']]
        return ids, urls

    # ------------------------------------------------------------ clean
    def clean(self, file_id, loc, data):
        key = (file_id, loc)
        cid = self.assignment.get(key) if loc is not None else None
        psn = self.cluster_psn.get(cid) if cid is not None else None
        subject = psn or 'rec\x00' + file_id + '\x00' + str(loc)
        sid = ('C', cid) if cid is not None else ('R', repr(key))
        votes = self.file_order.get(file_id, Counter())
        fhir_ids, fhir_urls = self._fhir_links(data)
        self._ctx = {
            'fhir_ids': fhir_ids, 'fhir_urls': fhir_urls,
            'psn': psn,
            'names': self.cluster_names.get(cid, set()),
            'ids': self.cluster_ids.get(cid, set()),
            'shift': P.shift_days(self.secret, subject, self.config['shift_min_days'], self.config['shift_max_days']),
            'level': self.levels.get(sid, 0),
            'order': self._order(file_id),
            'dobs': set(self.linker.cluster_evidence[cid].dobs) if cid is not None and cid in self.linker.cluster_evidence else
                    set(getattr(self.linker.records.get(key), 'dobs', set()) or set()),
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
    def _attachment(self, data, path, hint, depth):
        """Attachments the strict adapter would reject: gzip-compressed text is
        decompressed, cleaned and recompressed; anything else we cannot read
        safely (images, PDFs, unknown binaries) loses its data, which FHIR
        allows (Attachment.data is optional), instead of stopping the run."""
        import base64
        import binascii
        import gzip
        mime = str(data.get('contentType', '')).split(';', 1)[0].strip().casefold()
        rest = {k: v for k, v in data.items() if k != 'data'}
        cleaned = super()._value(rest, path, hint, depth) if rest else {}
        try:
            raw = base64.b64decode(data['data'], validate=True)
            if mime in ('application/gzip', 'application/x-gzip') or raw[:2] == b'\x1f\x8b':
                text = gzip.decompress(raw).decode('utf-8')
                if len(text) > 1000000:
                    raise ValueError
                cleaned['data'] = base64.b64encode(gzip.compress(self._text(text, '').encode(), mtime=0)).decode('ascii')
                self.entities['ATTACHMENT'] += 1
                return cleaned
        except (ValueError, UnicodeError, binascii.Error, OSError, EOFError):
            pass
        self.entities['ATTACHMENT_REMOVED'] += 1
        return cleaned

    def _value(self, data, path=(), hint='', depth=0):
        if (self._ctx is not None and isinstance(data, dict) and isinstance(data.get('url'), str)
                and _PERSON_URL.search(data['url']) and any(k.startswith('value') and isinstance(v, str) for k, v in data.items())):
            # FHIR extension carrying a person (mother's maiden name, informant ...).
            rest = {k: v for k, v in data.items() if not (k.startswith('value') and isinstance(v, str))}
            cleaned = super()._value(rest, path, hint, depth)
            for k, v in data.items():
                if k.startswith('value') and isinstance(v, str):
                    self._ctx['key'] = k
                    cleaned[k] = self._text(v, 'relative')
            return {k: cleaned[k] if k in cleaned else cleaned.get(self._key(k)) for k in data if k in cleaned or self._key(k) in cleaned}
        if (self._ctx is not None and isinstance(data, dict) and isinstance(data.get('data'), str)
                and ('contentType' in data or 'attachment' in path or data.get('encoding') == 'base64')
                and str(data.get('contentType', '')).split(';', 1)[0].strip().casefold() != 'text/plain'):
            return self._attachment(data, path, hint, depth)
        if self._ctx is not None and (isinstance(data, str) or (isinstance(data, (int, float)) and not isinstance(data, bool))):
            self._ctx['key'] = path[-1] if path else ''
            if isinstance(data, str):
                if path and path[-1] in FHIR_ID_KEYS:
                    ids, urls = self._ctx['fhir_ids'], self._ctx['fhir_urls']
                    replacement = None
                    if path[-1] == 'id' and data in ids:
                        replacement = ids[data]
                    elif data in urls:
                        replacement = urls[data]
                    elif path[-1] == 'reference':
                        if data.startswith('#') and data[1:] in ids:
                            replacement = '#' + ids[data[1:]]
                        elif '/' in data and data.rsplit('/', 1)[1] in ids:
                            prefix, rid = data.rsplit('/', 1)
                            replacement = prefix + '/' + ids[rid]
                    if replacement is not None:
                        self.entities['METADATA'] += 1
                        return replacement
                if path and (_PATH_KEY.search(path[-1]) and re.search(r'[/\\]', data)):
                    self.entities['METADATA'] += 1
                    return '[SOURCE_PATH]'           # export/source paths often embed a user's name
                if path and _BY_KEY.search(path[-1]):
                    return self._text(data, 'relative')   # exported_by / entered_by / uploaded_by: a person
                if path and path[-1].casefold() in {'source_path', 'sourcepath', 'filepath', 'file_path'}:
                    self.entities['METADATA'] += 1
                    return '[SOURCE_PATH]'
                return self._text(data, hint)
            spans = self._spans(str(data), hint)
            if any(s.entity_type in DIRECT for s in spans):
                self.entities['NUMERIC_ID'] += 1
                return 0 if isinstance(data, int) else 0.0
            if isinstance(data, int) and any(s.entity_type == 'PINCODE' for s in spans):
                self.entities['PINCODE'] += 1
                self._generalized_record = True
                return P.generalize_pin(str(data), self._ctx['level'], self.config)
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
        if not names:
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

    @staticmethod
    def _resolves_to(text, order):
        from detector import detect_text as _dt
        return {s.normalized for s in _dt(text).spans if s.entity_type in ('DATE', 'DOB')} | \
            ({P.parse_numeric(text, order)[0].isoformat()} if P.parse_numeric(text, order)[0] else set())

    def _clean_data_uri(self, m):
        import base64
        import binascii
        try:
            body = base64.b64decode(m[2], validate=True).decode('utf-8')
        except (binascii.Error, ValueError, UnicodeError):
            self.entities['ATTACHMENT_REMOVED'] += 1
            return m[1] + ';base64,'                       # unreadable payload: drop it
        self.entities['ATTACHMENT'] += 1
        return m[1] + ';base64,' + base64.b64encode(self._text(body, '').encode()).decode('ascii')

    def _is_patient_name(self, text):
        tokens = L.name_tokens(text)
        if not L.identifying(tokens):
            return False
        return any(L.compare_names(tokens, n) in ('full', 'partial') for n in self._ctx['names'])

    def _text(self, text, hint):
        if self._ctx is None:
            return super()._text(text, hint)
        if 'base64,' in text:
            text = _DATA_URI.sub(lambda m: self._clean_data_uri(m), text)
        ctx = self._ctx
        level = ctx['level']
        if hint == '__district__':
            if level >= 3 and text.strip():
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
                if shifted is not None and ctx.get('dobs') and self._resolves_to(shifted, ctx['order']) & ctx['dobs']:
                    shifted = '[DATE]'                     # a shifted date must never equal the real DOB
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
                if level < 3 and not VILLAGE_KEYS.search(ctx['key'] or ''):
                    # keep a district name only where it is written as the district
                    # ("Distt. Sitapur"), never a village that shares the name ("Gram Sitapur")
                    marker = r'(?:dist(?:t|rict)?\.?|jila|zila|janpad|जिला|ज़िला|जनपद)\s*[:.-]?\s*'
                    kept = [v for v in sorted(self.district_values)
                            if re.search(r'(?i)' + marker + re.escape(v) + r'(?!\w)', span.text)
                            or (hint == 'address' and re.fullmatch(r'(?i)\s*' + re.escape(v) + r'\s*', span.text) is None
                                and re.search(r'(?<!\w)' + re.escape(v) + r'\s*$', span.text) and ',' in span.text)]
                    if kept:
                        replacement += ' ' + ', '.join(kept)
                self._generalized_record = True
            if replacement is None:
                continue
            self.entities[kind] += 1
            result = result[:span.start] + replacement + result[span.end:]
        if self.rare_dx_pattern is not None:
            result, count = self.rare_dx_pattern.subn(lambda m: self.rare_dx_label[m[0].casefold()], result)
            if count:
                self.entities['RARE_DIAGNOSIS'] += count
                self._generalized_record = True
        if level >= 3 and self.district_pattern is not None:
            # High-risk patients: letterheads such as "Hospital, Barabanki" or
            # "Labs (Lucknow)" would otherwise reveal the home district.
            result, count = self.district_pattern.subn('[DISTRICT]', result)
            if count:
                self.entities['DISTRICT'] += count
                self._generalized_record = True
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
