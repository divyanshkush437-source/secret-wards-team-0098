"""Member 3 tests: linkage, pseudonyms, privacy transforms, canaries.

All fixtures are invented here (fictional canary names that exist in no name
list). Run with:  python3 -m unittest -q
"""
import base64
import contextlib
import hashlib
import io
import json
from datetime import date
from pathlib import Path
import tempfile
import unittest

import linker as L
import privacy as P
from main import run
from team_processor import Processor

CANARY = 'Zorvan Takreli'
CANARY_HI = 'ज़ोरवान टकरेली'
CANARY_PHONE = '9123456780'


class TransliterationTests(unittest.TestCase):
    def same(self, a, b):
        return L.compare_names(L.name_tokens(a), L.name_tokens(b))

    def test_cross_script_full_names(self):
        for hi, en in [('मोहम्मद आरिफ', 'Mohd. Arif'), ('जसप्रीत सिंह', 'Jaspreet Singh'),
                       ('रीना निषाद', 'Rina Nishad'), ('उषा तिवारी', 'Usha Tiwari'),
                       ('सलमा अंसारी', 'Salma Ansari'), ('फ़ातिमा बानो', 'Fatima Bano')]:
            self.assertEqual(self.same(hi, en), 'full', en)

    def test_spelling_variants(self):
        self.assertEqual(self.same('Md. Shahid', 'Mohammad Shahid'), 'full')
        self.assertEqual(self.same('Geeta Chauhan', 'Gita Chouhan'), 'full')
        self.assertEqual(self.same('Ashok Patel', 'Patel Ashok'), 'full')     # surname first
        self.assertEqual(self.same('Asha', 'Asha Rajput'), 'partial')         # first name only
        self.assertEqual(self.same('R. Sharma', 'Ramesh Sharma'), 'partial')  # initial

    def test_different_people(self):
        for a, b in [('Sunita Devi', 'Sunil Devi'), ('Asha Verma', 'Asha Rajput'),
                     ('Rakesh', 'Mukesh'), ('Anil', 'Sunil')]:
            self.assertEqual(self.same(a, b), 'conflict', (a, b))

    def test_honorifics_and_generic_tokens(self):
        self.assertEqual(L.identifying(L.name_tokens('Shri Ramesh Kumar ji')), ('ramesh',))


def ev(**kw):
    e = L.Evidence()
    for key, value in kw.items():
        if key == 'names':
            value = {L.name_tokens(v) for v in value}
        if key == 'relatives':
            value = {L.name_tokens(v) for v in value}
        setattr(e, key, set(value))
    return e


class LinkerTests(unittest.TestCase):
    def resolve(self, *records):
        linker = L.Linker()
        for i, r in enumerate(records):
            linker.add(('f', i), r)
        out = linker.resolve()
        return [out[('f', i)] for i in range(len(records))]

    def test_shared_uhid_links(self):
        a, b = self.resolve(ev(names=['Zorvan Takreli'], ids=[('UHID', 'ABC123456')]),
                            ev(names=['ज़ोरवान टकरेली'], ids=[('UHID', 'ABC123456')]))
        self.assertEqual(a, b)

    def test_name_plus_village_and_age(self):
        a, b = self.resolve(ev(names=['Zorvan Takreli'], places=['brindpur'], ages=[(47, 2026)], genders=['F']),
                            ev(names=['Zorvan Takreli'], places=['brindpur'], ages=[(47, 2026)]))
        self.assertEqual(a, b)

    def test_homonyms_stay_apart(self):
        a, b = self.resolve(ev(names=['Zorvan Takreli'], places=['brindpur'], ages=[(47, 2026)]),
                            ev(names=['Zorvan Takreli'], places=['katramau'], ages=[(23, 2026)]))
        self.assertNotEqual(a, b)

    def test_name_alone_is_not_enough(self):
        a, b = self.resolve(ev(names=['Zorvan Takreli']), ev(names=['Zorvan Takreli']))
        self.assertNotEqual(a, b)

    def test_family_phone_does_not_merge(self):
        a, b = self.resolve(ev(names=['Zorvan Takreli'], phones=['+919123456780']),
                            ev(names=['Mirelda Takreli'], phones=['+919123456780']))
        self.assertNotEqual(a, b)

    def test_fragmented_first_name_plus_relative(self):
        a, b = self.resolve(ev(names=['Mirelda Takreli'], relatives=['Tovan Takreli'], genders=['F']),
                            ev(names=['Mirelda'], relatives=['Tovan Takreli']))
        self.assertEqual(a, b)

    def test_no_transitive_overmerge(self):
        # A~B by UHID, B~C by phone+name, but A and C disagree on gender.
        a, b, c = self.resolve(ev(names=['Zorvan Takreli'], ids=[('UHID', 'X1234567')], genders=['M']),
                               ev(names=['Zorvan Takreli'], ids=[('UHID', 'X1234567')], phones=['+919999900000']),
                               ev(names=['Zorvan Takreli'], phones=['+919999900000'], genders=['F']))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_first_name_only_record_is_unlinked(self):
        (a,) = self.resolve(ev(names=['Zorvan']))
        self.assertIsNone(a)


class PrivacyTests(unittest.TestCase):
    def test_pseudonym_keyed_and_stable(self):
        a = P.pseudonym(b'secret-one', 'anchor')
        self.assertEqual(a, P.pseudonym(b'secret-one', 'anchor'))
        self.assertNotEqual(a, P.pseudonym(b'secret-two', 'anchor'))
        self.assertRegex(a, r'^PSN-[A-Z0-9]{8}$')
        plain = hashlib.sha256(b'anchor').hexdigest().upper()
        self.assertNotIn(a[4:], plain)

    def test_shift_range_and_secret(self):
        shifts = {P.shift_days(b's', str(i)) for i in range(200)}
        self.assertTrue(all(20 <= abs(d) <= 200 for d in shifts))
        self.assertGreater(len(shifts), 50)
        self.assertNotEqual(P.shift_days(b's1', 'x'), P.shift_days(b's2', 'x'))

    def test_shift_keeps_format_and_interval(self):
        cases = [('15-05-2026', '23-05-2026', 'DMY'), ('05/15/2026', '05/23/2026', 'MDY'),
                 ('2026-05-15', '2026-05-23', 'DMY'), ('15 May 2026', '23 May 2026', 'DMY')]
        for a, b, order in cases:
            sa, sb = P.shift_text_date(a, -47, order), P.shift_text_date(b, -47, order)
            self.assertEqual(len(sa), len(a))
            da = P.parse_numeric(sa, order)[0] if sa[2] in '-/' or sa[4] == '-' else None
            db = P.parse_numeric(sb, order)[0] if da else None
            if da:
                self.assertEqual((db - da).days, 8)
        self.assertEqual(P.shift_text_date('28/02/2024', 1), '29/02/2024')

    def test_age_bands_are_truthful(self):
        for age in range(0, 120):
            for level in (0, 1, 2):
                band = P.age_band(age, level)
                if band.endswith('+'):
                    self.assertGreaterEqual(age, int(band[:-1]))
                else:
                    lo, hi = map(int, band.split('-'))
                    self.assertTrue(lo <= age <= hi, (age, band))

    def test_rare_diagnosis_coarsens(self):
        subjects = {i: {'codes': {'I10'}, 'ages': {40}} for i in range(5)}
        subjects['rare'] = {'codes': {'A82.9'}, 'ages': {40}}
        levels = P.risk_levels(subjects)
        self.assertEqual(levels['rare'], 2)
        self.assertEqual(levels[0], 0)

    def test_sparse_cells_are_widened(self):
        # 40 patients in a dense district, 1 patient alone in a small one.
        subjects = {i: {'codes': set(), 'ages': {30 + i % 20}, 'gender': 'F' if i % 2 else 'M',
                        'district': 'denseville'} for i in range(40)}
        subjects['lonely'] = {'codes': set(), 'ages': {54}, 'gender': 'F', 'district': 'tinyvillage'}
        subjects['old'] = {'codes': set(), 'ages': {97}, 'gender': 'M', 'district': 'denseville'}
        levels = P.risk_levels(subjects)
        self.assertEqual(levels[0], 0)
        self.assertEqual(levels['lonely'], 2)      # district would single her out
        self.assertEqual(levels['old'], 2)         # 85+ is rare in any district

    def test_expected_registry_cell_reaches_k(self):
        subjects = {i: {'codes': set(), 'ages': {20 + i}, 'gender': 'F', 'district': 'd%d' % (i % 3)} for i in range(60)}
        levels = P.risk_levels(subjects)
        self.assertTrue(set(levels.values()) <= {0, 1, 2})

    def test_pin(self):
        self.assertEqual(P.generalize_pin('226001'), '226XXX')
        self.assertEqual(P.generalize_pin('226001', 2), '[PIN]')


def build_dataset(root: Path):
    (root / 'registration').mkdir(parents=True)
    (root / 'discharge').mkdir()
    (root / 'notes').mkdir()
    (root / 'fhir').mkdir()
    (root / 'registration' / 'zz_hospital.csv').write_text(
        'UHID,Patient Name,Gender,Age,DOB,Relative Name,Village,District,PIN,Mobile,Reg Date\n'
        f'ZZH/26/000123,{CANARY},F,47,12/04/1979,Tovan Takreli,Brindpur,Hardoi,241001,{CANARY_PHONE},03/05/2026\n'
        'ZZH/26/000124,Pellar Vonstrake,M,61,01/01/1965,Orik Vonstrake,Katramau,Hardoi,241002,9000011111,04/05/2026\n',
        encoding='utf-8')
    (root / 'discharge' / f'Discharge_{CANARY.replace(" ", "_")}_ZZH-26-000123.txt').write_text(
        'DISCHARGE SUMMARY\n'
        f'Patient Name: {CANARY}    Age/Sex: 47 Yrs/F\n'
        'UHID: ZZH/26/000123\n'
        'W/o Tovan Takreli\n'
        'Consultant: Dr. Ramesh Srivastava (MD Medicine)\n'
        'Date of Admission: 15-05-2026\n'
        'Date of Discharge: 24-05-2026\n'
        'Diagnosis: Dengue fever (A97.9)\n'
        'Tab Paracetamol 650 mg 1-0-1 x 5 days. Temp 101.2 F. BP 150/90 mmHg.\n', encoding='utf-8')
    (root / 'notes' / 'hindi_note.txt').write_text(
        f'नाम: {CANARY_HI}   आयु: 47 वर्ष\nUHID: ZZH/26/000123\nतारीख: 16/05/2026\nBukhar 102 F. Dolo 650 BD x 5 days.\n',
        encoding='utf-8')
    attachment = base64.b64encode(f'Patient {CANARY} reviewed'.encode()).decode()
    bundle = {'resourceType': 'Bundle', 'type': 'document', 'entry': [
        {'fullUrl': 'urn:uuid:p1', 'resource': {'resourceType': 'Patient', 'id': 'p1',
            'identifier': [{'system': 'urn:zzh', 'value': 'ZZH/26/000123'}],
            'name': [{'given': ['Zorvan'], 'family': 'Takreli'}], 'gender': 'female',
            'birthDate': '1979-04-12', 'telecom': [{'system': 'phone', 'value': CANARY_PHONE}]}},
        {'fullUrl': 'urn:uuid:e1', 'resource': {'resourceType': 'Encounter', 'id': 'e1',
            'subject': {'reference': 'urn:uuid:p1', 'display': CANARY},
            'period': {'start': '2026-05-15', 'end': '2026-05-24'}}},
        {'fullUrl': 'urn:uuid:d1', 'resource': {'resourceType': 'DocumentReference', 'id': 'd1',
            'subject': {'reference': 'urn:uuid:p1'},
            'content': [{'attachment': {'contentType': 'text/plain', 'data': attachment}}]}},
    ]}
    (root / 'fhir' / 'bundle_1.json').write_text(json.dumps(bundle, ensure_ascii=False), encoding='utf-8')
    (root / 'notes' / 'meta.json').write_text(json.dumps({'visits': [
        {'patient_ref': 'ZZH/26/000123', 'visit_date': '2026-05-15', f'note_{CANARY}': 'ok', 'drug': 'Ramipril 5 mg'}]},
        ensure_ascii=False), encoding='utf-8')
    (root / 'notes' / 'broken.json').write_text('{"visits": [', encoding='utf-8')


class HindiDetectionTests(unittest.TestCase):
    def test_heading_is_not_a_name(self):
        from detector import detect_text
        self.assertFalse(detect_text('डिस्चार्ज सारांश').spans)

    def test_nukta_label_still_finds_name(self):
        from detector import detect_text
        spans = detect_text('मरीज़ का नाम: ज़ोरवान टकरेली   आयु: 30 वर्ष').spans
        people = [x.text for x in spans if x.entity_type == 'PERSON']
        self.assertEqual(people, ['ज़ोरवान टकरेली'])


class LetterheadTests(unittest.TestCase):
    def test_high_risk_letterhead_district_masked(self):
        p = Processor(b'k')
        p.observe('f', 'row:0', {'Patient Name': 'Zorvan Takreli', 'District': 'Tinypur', 'Age': '97', 'UHID': 'ZZH/26/000123'})
        p.observe('n', 'doc', 'Arogya Hospital, Tinypur\nPatient Name: Zorvan Takreli  Age: 97 Yrs/M\nUHID: ZZH/26/000123\n')
        p.finish()
        out, psn = p.clean('n', 'doc', 'Arogya Hospital, Tinypur\nPatient Name: Zorvan Takreli  Age: 97 Yrs/M\nUHID: ZZH/26/000123\n')
        self.assertIsNotNone(psn)
        self.assertNotIn('Tinypur', out)
        self.assertIn('85+', out)


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.input = base / 'input'
        build_dataset(cls.input)
        cls.out = {}
        for name, secret in [('a', b'secret-A'), ('a2', b'secret-A'), ('b', b'secret-B')]:
            out = base / name
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                report = run(cls.input, out, Processor(secret), secret)
            cls.out[name] = (out, report, stream.getvalue())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def everything(self, name):
        out, _, logs = self.out[name]
        blob = [logs]
        for f in out.rglob('*'):
            blob.append(f.name)
            if f.is_file():
                blob.append(f.read_text(encoding='utf-8'))
        text = '\n'.join(blob)
        for chunk in list(text.split()):
            try:
                text += base64.b64decode(chunk, validate=True).decode('utf-8', 'ignore')
            except Exception:
                pass
        return text

    def records(self, name):
        out = self.out[name][0]
        return [json.loads(l) for l in (out / 'records.jsonl').read_text().splitlines()]

    def test_no_canary_anywhere(self):
        text = self.everything('a')
        for needle in ('Zorvan', 'Takreli', 'ज़ोरवान', 'टकरेली', CANARY_PHONE, 'Tovan', 'Brindpur', '000123'):
            self.assertNotIn(needle, text, needle)

    def test_same_patient_one_pseudonym_across_scripts(self):
        recs = self.records('a')
        canary_files = [r['patient'] for r in recs if 'hindi_note' in r['file'] or 'bundle_1' in r['file'] or 'redacted_' in r['file']]
        reg = [r['patient'] for r in recs if r['file'].endswith('zz_hospital.csv')]
        self.assertTrue(reg[0])
        self.assertNotEqual(reg[0], reg[1])
        self.assertTrue(canary_files)
        self.assertEqual(set(canary_files), {reg[0]})

    def test_pseudonym_is_inside_record(self):
        out = self.out['a'][0]
        for r in self.records('a'):
            if r['patient']:
                self.assertIn(r['patient'], (out / r['file']).read_text(encoding='utf-8'))

    def test_deterministic_and_secret_dependent(self):
        a = sorted(p.relative_to(self.out['a'][0]) for p in self.out['a'][0].rglob('*') if p.is_file() and p.name != 'report.json')
        for rel in a:
            self.assertEqual((self.out['a'][0] / rel).read_bytes(), (self.out['a2'][0] / rel).read_bytes())
        pa = {r['patient'] for r in self.records('a') if r['patient']}
        pb = {r['patient'] for r in self.records('b') if r['patient']}
        self.assertFalse(pa & pb)

    def test_stay_length_kept_and_dates_shifted(self):
        out = self.out['a'][0]
        note = next(out.glob('sanitized/discharge/*.txt')).read_text(encoding='utf-8')
        adm = P.parse_numeric(note.split('Date of Admission: ')[1][:10])[0]
        dis = P.parse_numeric(note.split('Date of Discharge: ')[1][:10])[0]
        self.assertEqual((dis - adm).days, 9)
        self.assertNotEqual(adm, date(2026, 5, 15))
        bundle = json.loads((out / 'sanitized/fhir/bundle_1.json').read_text(encoding='utf-8'))
        period = bundle['entry'][1]['resource']['period']
        self.assertEqual((date.fromisoformat(period['end']) - date.fromisoformat(period['start'])).days, 9)
        self.assertEqual((date.fromisoformat(period['start']) - adm).days, 0)   # same patient, same shift

    def test_clinical_values_survive(self):
        out = self.out['a'][0]
        note = next(out.glob('sanitized/discharge/*.txt')).read_text(encoding='utf-8')
        for keep in ('Dr. Ramesh Srivastava', 'Paracetamol 650 mg 1-0-1 x 5 days', 'Temp 101.2 F', 'BP 150/90', 'Dengue fever (A97.9)'):
            self.assertIn(keep, note)
        hindi = (out / 'sanitized/notes/hindi_note.txt').read_text(encoding='utf-8')
        self.assertIn('Bukhar 102 F', hindi)
        self.assertIn('Dolo 650 BD x 5 days', hindi)

    def test_csv_shape_and_bands(self):
        out = self.out['a'][0]
        lines = (out / 'sanitized/registration/zz_hospital.csv').read_text(encoding='utf-8').splitlines()
        self.assertEqual(lines[0], 'UHID,Patient Name,Gender,Age,DOB,Relative Name,Village,District,PIN,Mobile,Reg Date')
        row = lines[1].split(',')
        lo, hi = map(int, row[3].split('-'))
        self.assertTrue(lo <= 47 <= hi)
        self.assertEqual(len(lines), 3)

    def test_fhir_references_resolve(self):
        out = self.out['a'][0]
        bundle = json.loads((out / 'sanitized/fhir/bundle_1.json').read_text(encoding='utf-8'))
        urls = {e['fullUrl'] for e in bundle['entry']}
        for e in bundle['entry']:
            ref = e['resource'].get('subject', {}).get('reference')
            if ref:
                self.assertIn(ref, urls)
        self.assertRegex(bundle['entry'][0]['resource']['birthDate'], r'^\d{4}-\d{2}-\d{2}$')

    def test_broken_file_quarantined(self):
        report = self.out['a'][1]
        self.assertEqual(report['counts']['files_quarantined'], 1)
        self.assertEqual(report['counts']['files_total'], 6)
        self.assertNotIn('broken', json.dumps(report))


if __name__ == '__main__':
    unittest.main()
