#!/usr/bin/env python3
"""Generate a hidden-style test dataset that the pipeline has never seen.

DEVELOPMENT ONLY. Everything is synthetic and invented here: new population,
new hospitals, new file layouts, labels, ID formats and date formats.

    python3 tools/make_hidden_dataset.py --out /path/kit_hidden --seed 7

Writes, in the same layout as the team kit (so test_attacker.py can score it):
    dev/input/...                 the files the pipeline receives
    dev/truth/truth.json          answer key (entities, preserve probes, dates, links)
    dev/attacker/registry.csv     voter-style population register
    dev/attacker/known_facts.jsonl
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import random
from datetime import date, timedelta
from pathlib import Path

# ----------------------------------------------------------------- vocabulary
MALE = {'hindu': [('Naveen', 'नवीन'), ('Pankaj', 'पंकज'), ('Deepak', 'दीपक'), ('Anuj', 'अनुज'), ('Gaurav', 'गौरव'),
                  ('Hemant', 'हेमंत'), ('Lalit', 'ललित'), ('Manish', 'मनीष'), ('Nitin', 'नितिन'), ('Prem', 'प्रेम'),
                  ('Raghav', 'राघव'), ('Satyam', 'सत्यम'), ('Tarun', 'तरुण'), ('Umesh', 'उमेश'), ('Vinod', 'विनोद'),
                  ('Yogesh', 'योगेश'), ('Bhagirath', 'भगीरथ'), ('Shivendra', 'शिवेंद्र'), ('Ramesh', 'रमेश')],
        'muslim': [('Ashfaq', 'अशफ़ाक़'), ('Imran', 'इमरान'), ('Irfan', 'इरफ़ान'), ('Javed', 'जावेद'), ('Nadeem', 'नदीम'),
                   ('Rizwan', 'रिज़वान'), ('Shakeel', 'शकील')],
        'sikh': [('Gurpreet', 'गुरप्रीत'), ('Harjeet', 'हरजीत'), ('Kuldeep', 'कुलदीप'), ('Jasvinder', 'जसविंदर')]}
FEMALE = {'hindu': [('Anita', 'अनीता'), ('Babita', 'बबीता'), ('Chanda', 'चंदा'), ('Durga', 'दुर्गा'), ('Hema', 'हेमा'),
                    ('Indu', 'इंदु'), ('Jyoti', 'ज्योति'), ('Kamla', 'कमला'), ('Lata', 'लता'), ('Madhu', 'मधु'),
                    ('Neelam', 'नीलम'), ('Rekha', 'रेखा'), ('Savita', 'सविता'), ('Sushma', 'सुषमा'), ('Urmila', 'उर्मिला'),
                    ('Vandana', 'वंदना'), ('Tejaswini', 'तेजस्विनी'), ('Dhruvika', 'ध्रुविका')],
          'muslim': [('Farzana', 'फ़रज़ाना'), ('Nasreen', 'नसरीन'), ('Rubina', 'रुबीना'), ('Shabnam', 'शबनम'), ('Tabassum', 'तबस्सुम'),
                     ('Zubeda', 'ज़ुबेदा')],
          'sikh': [('Harpreet', 'हरप्रीत'), ('Manjeet', 'मनजीत'), ('Simran', 'सिमरन')]}
SURNAME = {'hindu': [('Verma', 'वर्मा'), ('Shukla', 'शुक्ला'), ('Dubey', 'दुबे'), ('Tripathi', 'त्रिपाठी'), ('Saxena', 'सक्सेना'),
                     ('Kashyap', 'कश्यप'), ('Rawat', 'रावत'), ('Sonkar', 'सोनकर'), ('Pal', 'पाल'), ('Prajapati', 'प्रजापति'),
                     ('Gautam', 'गौतम'), ('Bharti', 'भारती'), ('Rathore', 'राठौर'), ('Awasthi', 'अवस्थी')],
           'muslim': [('Qureshi', 'क़ुरैशी'), ('Khan', 'ख़ान'), ('Mansuri', 'मंसूरी'), ('Rizvi', 'रिज़वी'), ('Farooqui', 'फ़ारूक़ी')],
           'sikh': [('Gill', 'गिल'), ('Sandhu', 'संधू'), ('Bajwa', 'बाजवा')]}
V_PRE = [('Bhawani', 'भवानी'), ('Ram', 'राम'), ('Sita', 'सीता'), ('Kesho', 'केशो'), ('Madho', 'माधो'), ('Hari', 'हरि'),
         ('Kunwar', 'कुँवर'), ('Lal', 'लाल'), ('Shiv', 'शिव'), ('Chand', 'चंद'), ('Bel', 'बेल'), ('Dhan', 'धन')]
V_SUF = [('pur', 'पुर'), ('ganj', 'गंज'), ('nagar', 'नगर'), ('garh', 'गढ़'), ('dih', 'डीह'), ('mau', 'मऊ'), ('khera', 'खेड़ा')]
DISTRICTS = [('Gonda', 'गोंडा', ['Colonelganj', 'Tarabganj'], '271'), ('Basti', 'बस्ती', ['Harraiya', 'Bhanpur'], '272'),
             ('Ayodhya', 'अयोध्या', ['Sohawal', 'Milkipur'], '224'), ('Shravasti', 'श्रावस्ती', ['Bhinga', 'Jamunaha'], '271'),
             ('Pratapgarh', 'प्रतापगढ़', ['Kunda', 'Patti'], '230'), ('Amethi', 'अमेठी', ['Gauriganj', 'Musafirkhana'], '227'),
             ('Kaushambi', 'कौशाम्बी', ['Manjhanpur', 'Sirathu'], '212'), ('Balrampur', 'बलरामपुर', ['Tulsipur', 'Utraula'], '271')]
MOHALLA = ['Shanti Nagar', 'Purani Bazar', 'Kazipura', 'Ganga Vihar', 'Tilak Colony', 'Station Road']
LANDMARK = ['near Shiv Mandir', 'opp. Gram Panchayat', 'behind Inter College', 'near Pani Tanki']
COMMON = [('Typhoid fever', 'A01.0', 'टाइफाइड बुखार'), ('Dengue fever', 'A97.9', 'डेंगू बुखार'), ('Malaria, unspecified', 'B54', 'मलेरिया'),
          ('Tuberculosis of lung', 'A15.0', 'फेफड़ों की टीबी'), ('Type 2 diabetes mellitus without complications', 'E11.9', 'मधुमेह'),
          ('Essential (primary) hypertension', 'I10', 'उच्च रक्तचाप'), ('Pneumonia, unspecified', 'J18.9', 'निमोनिया'),
          ('Anaemia, unspecified', 'D64.9', 'खून की कमी'), ('Urinary tract infection', 'N39.0', 'पेशाब में संक्रमण'),
          ('Infectious gastroenteritis and colitis, unspecified', 'A09', 'दस्त और उल्टी')]
RARE = [('Japanese encephalitis', 'A83.0', 'जापानी इंसेफेलाइटिस'), ('Scrub typhus', 'A75.3', 'स्क्रब टाइफस'),
        ('Toxic effect of snake venom', 'T63.0', 'सांप का ज़हर'), ('Guillain-Barre syndrome', 'G61.0', 'गुलियन बैरे सिंड्रोम'),
        ('Kawasaki disease', 'M30.3', 'कावासाकी रोग')]
MEDS = [('Paracetamol', '650 mg', '1-1-1'), ('Amlodipine', '5 mg', '0-0-1'), ('Metformin', '500 mg', '1-0-1'),
        ('Ceftriaxone', '1 g', 'BD'), ('Doxycycline', '100 mg', '1-0-1'), ('Pantoprazole', '40 mg', '1-0-0'),
        ('Levothyroxine', '50 mcg', '1-0-0'), ('Azithromycin', '500 mg', '1-0-0')]
DOCTORS = ['Dr. Ramesh Tripathi', 'Dr. Kamla Saxena', 'Dr. Imran Rizvi', 'Dr. Naveen Awasthi', 'Dr. Sushma Bharti']
MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
MONTHS_FULL = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
               'November', 'December']
GENERIC = {'kumar', 'kumari', 'devi', 'singh', 'kaur', 'bano', 'begum', 'khatoon', 'md', 'mohd', 'mohammad',
           'ji', 'sahab', 'didi', 'bhaiya'}
HOSPITALS = {
    'KMH': {'name': 'Kamla Memorial Hospital', 'city': 'Gonda', 'style': 'dot'},
    'SVH': {'name': 'Sarvodaya Hospital', 'city': 'Basti', 'style': 'slash'},
    'AGH': {'name': 'Aastha Global Hospital', 'city': 'Ayodhya', 'style': 'iso'},
    'CHB': {'name': 'CHC Bhinga', 'city': 'Shravasti', 'style': 'mon'},
}
DEVA_DIGITS = '०१२३४५६७८९'


def fmt(d: date, style: str) -> str:
    if style == 'dot':
        return d.strftime('%d.%m.%Y')
    if style == 'slash':
        return d.strftime('%d/%m/%Y')
    if style == 'iso':
        return d.isoformat()
    if style == 'mon':
        return f'{d.day:02d}-{MONTHS[d.month - 1]}-{d.year}'
    return f'{d.day} {MONTHS_FULL[d.month - 1]} {d.year}'


def tokens(name: str):
    return [t for t in name.casefold().replace('.', ' ').split() if t not in GENERIC and len(t) > 1]


# ----------------------------------------------------------------- truth helpers
class Unit:
    def __init__(self, loc, patient=None):
        self.loc, self.patient = loc, patient
        self.entities, self.preserve, self.dates = [], [], []
        self.strong = self.full_name = self.second_clue = self.first_plus_relative = False
        self.unique_combo = True

    def ent(self, typ, surface, script='latin', channel='content'):
        e = {'type': typ, 'surface': surface, 'script': script, 'channel': channel}
        if typ in ('PATIENT_NAME', 'RELATIVE_NAME', 'CANARY'):
            e['tokens'] = tokens(surface)
        self.entities.append(e)
        return surface

    def keep(self, kind, text):
        self.preserve.append({'text': text, 'kind': kind})
        return text

    def date(self, event, true, surface, anchor=None):
        self.dates.append({'true': true.isoformat(), 'event': event, 'anchor': anchor})
        return surface

    def as_dict(self):
        if not self.patient:
            link = 'none'
        elif self.strong or (self.full_name and self.second_clue) or (self.first_plus_relative and self.unique_combo):
            link = 'required'
        else:
            link = 'ambiguous'
        return {'loc': self.loc, 'patient': self.patient if self.patient else None, 'link': link,
                'entities': self.entities, 'preserve': self.preserve, 'dates': self.dates}


class Gen:
    def __init__(self, seed, n_patients):
        self.r = random.Random(seed)
        self.files = {}
        self.raw = {}
        self.population = []
        self.n_patients = n_patients
        self.uhid_seq = {k: 1000 + self.r.randint(0, 500) for k in HOSPITALS}
        self.canaries = []

    # ------------------------------------------------------------- population
    def village(self, district):
        a, b = self.r.choice(V_PRE), self.r.choice(V_SUF)
        suffix = self.r.choice(['', '', ' Kalan', ' Khurd'])
        deva_suffix = {' Kalan': ' कलां', ' Khurd': ' खुर्द', '': ''}[suffix]
        return a[0] + b[0] + suffix, a[1] + b[1] + deva_suffix

    def person(self, i, gender=None):
        r = self.r
        group = r.choices(['hindu', 'muslim', 'sikh'], [70, 22, 8])[0]
        gender = gender or r.choice('MF')
        given = r.choice((MALE if gender == 'M' else FEMALE)[group])
        sur = r.choice(SURNAME[group])
        age = min(99, max(1, int(r.gauss(42, 18))))
        dist = r.choice(DISTRICTS)
        vil = self.village(dist)
        if gender == 'F' and age >= 22 and r.random() < 0.7:
            rel, relg = 'W/o', r.choice(MALE[group])
        else:
            rel, relg = ('S/o' if gender == 'M' else 'D/o'), r.choice(MALE[group])
        dob = date(2026, 6, 1) - timedelta(days=age * 365 + r.randint(0, 364))
        p = {'rid': f'UPH{i:07d}', 'group': group, 'gender': gender, 'given': given, 'sur': sur, 'age': age,
             'dob': dob, 'rel': rel, 'relg': relg, 'house': f'H.No. {r.randint(1, 450)}', 'mohalla': r.choice(MOHALLA),
             'landmark': r.choice(LANDMARK), 'village': vil, 'tehsil': r.choice(dist[2]), 'district': dist,
             'pin': dist[3] + f'{r.randint(100, 999)}', 'phone': f'{r.choice("6789")}{r.randint(100000000, 999999999)}',
             'email': None, 'aadhaar': f'{r.randint(2000, 9999)}{r.randint(10000000, 99999999)}',
             'abha': f'{r.randint(10, 99)}{r.randint(100000000000, 999999999999)}', 'pan': None}
        if r.random() < 0.1:
            p['email'] = f'{given[0].lower()}{sur[0].lower()}{r.randint(10, 99)}@mailbox.example'
        if r.random() < 0.3:
            p['pan'] = ''.join(r.choice('ABCDEFGHJKLMNPRSTUVWXYZ') for _ in range(5)) + f'{r.randint(1000, 9999)}' + r.choice('ABCDEFHKLMNP')
        p['name'] = f"{given[0]} {sur[0]}"
        p['deva'] = f"{given[1]} {sur[1]}"
        p['relname'] = f"{relg[0]} {sur[0]}"
        p['reldeva'] = f"{relg[1]} {sur[1]}"
        return p

    def build_population(self):
        n = self.n_patients * 5
        self.population = [self.person(i) for i in range(n)]
        self.patients = self.r.sample(self.population, self.n_patients)
        for k, p in enumerate(self.patients):
            p['pt'] = f'HP{k:05d}'
        # homonyms: same full name, different person, village and age
        self.homonyms = []
        for a in self.r.sample(self.patients, 3):
            b = self.r.choice([x for x in self.patients if x is not a and x['gender'] == a['gender'] and x['group'] == a['group']
                               and abs(x['age'] - a['age']) > 8])
            b['given'], b['sur'] = a['given'], a['sur']
            b['name'], b['deva'] = a['name'], a['deva']
            self.homonyms.append([a['pt'], b['pt']])
        # re-identification traps
        old = self.patients[0]
        old['age'], old['dob'] = 97, date(1928, 3, 3)
        for p in self.patients:
            p['dx'] = self.r.choice(COMMON)
        for p in self.r.sample(self.patients[1:], 5):
            p['dx'] = self.r.choice(RARE)
        for p in self.patients:
            p['hospitals'] = self.r.sample(list(HOSPITALS), 2 if self.r.random() < 0.35 else 1)
            p['uhid'] = {}
            for h in p['hospitals']:
                p['uhid'][h] = self.new_uhid(h)
            stays = []
            for h in p['hospitals']:
                if self.r.random() < 0.65:
                    start = date(2026, 1, 5) + timedelta(days=self.r.randint(0, 300))
                    stays.append((h, start, start + timedelta(days=self.r.randint(2, 14))))
            p['stays'] = stays
            p['opd'] = [(h, date(2026, 1, 5) + timedelta(days=self.r.randint(0, 300))) for h in p['hospitals']
                        for _ in range(self.r.randint(0, 2))]

    def combo_unique(self, p):
        # DATASET.md rule: name + second clue links only if the combination is unique.
        key = (p['given'][0], p['relg'][0])
        return sum((q['given'][0], q['relg'][0]) == key for q in self.patients) == 1

    def new_uhid(self, h):
        self.uhid_seq[h] += self.r.randint(1, 9)
        n = self.uhid_seq[h]
        return {'KMH': f'KMH-26-{n:06d}', 'SVH': f'SVH/{n:05d}/26', 'AGH': f'AGH{n:07d}', 'CHB': f'CHB-{n:05d}'}[h]

    # ------------------------------------------------------------- writing
    def put(self, path, text, fmt_, units, encoding='utf-8', expect='sanitize', date_hint='dmy'):
        data = text.encode(encoding) if encoding != 'utf-16' else text.encode('utf-16')
        self.raw[path] = data
        self.files[path] = {'path': path, 'format': fmt_, 'encoding': encoding, 'expect': expect, 'date_hint': date_hint,
                            'sha256': hashlib.sha256(data).hexdigest(),
                            'units': {u.loc: u.as_dict() for u in units}}

    def phone_fmt(self, p, script='latin'):
        n = p['phone']
        style = self.r.choice(['+91 {} {}', '+91-{}{}', '0{}-{}', '{}{}', '({}) {}'])
        s = style.format(n[:5], n[5:])
        if script == 'deva':
            s = ''.join(DEVA_DIGITS[int(c)] if c.isdigit() else c for c in n)
        return s

    def table(self, header, rows, delim=','):
        out = io.StringIO()
        w = csv.writer(out, delimiter=delim, lineterminator='\n')
        w.writerow(header)
        for row in rows:
            w.writerow(row)
        return out.getvalue()

    # ------------------------------------------------------------- registration
    def registration(self):
        # KMH: new English labels, dd.mm.yyyy
        header = ['Regn No', 'Pt. Name', 'Sex', 'Yrs', 'Date Of Birth', 'Guardian (Relation)', 'Residential Address',
                  'Gram/Village', 'Block', 'Dist.', 'Postal Code', 'Contact No.', 'Aadhar', 'ABHA ID', 'Regd. On']
        rows, units = [], []
        for p in [p for p in self.patients if 'KMH' in p['hospitals']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            u.strong = u.full_name = u.second_clue = True
            reg = p['stays'][0][1] - timedelta(days=3) if p['stays'] else date(2025, 12, 1)
            rows.append([u.ent('MRN', p['uhid']['KMH']), u.ent('PATIENT_NAME', p['name']), p['gender'], str(p['age']),
                         u.ent('DOB', fmt(p['dob'], 'dot')), p['rel'] + ' ' + u.ent('RELATIVE_NAME', p['relname']),
                         u.ent('HOUSE', p['house']) + ', ' + u.ent('LOCALITY', 'Mohalla ' + p['mohalla']) + ', ' + u.ent('LANDMARK', p['landmark']),
                         u.ent('VILLAGE', p['village'][0]), p['tehsil'], u.keep('district', p['district'][0]),
                         u.ent('PIN', p['pin']), u.ent('PHONE', self.phone_fmt(p)),
                         u.ent('AADHAAR', f"{p['aadhaar'][:4]} {p['aadhaar'][4:8]} {p['aadhaar'][8:]}"),
                         u.ent('ABHA_NUMBER', f"{p['abha'][:2]}-{p['abha'][2:6]}-{p['abha'][6:10]}-{p['abha'][10:]}"),
                         u.date('registration', reg, fmt(reg, 'dot'))])
            units.append(u)
        self.put('registration/kmh_registration.csv', self.table(header, rows), 'csv', units)

        # SVH: Devanagari headers, UTF-16 TSV, mostly Devanagari names
        header = ['पंजीकरण सं.', 'नाम', 'लिंग', 'उम्र', 'जन्म तिथि', 'पिता/पति का नाम', 'पता', 'गाँव', 'जिला', 'पिन कोड', 'मोबाइल', 'आधार', 'पंजीकरण तिथि']
        rows, units = [], []
        for p in [p for p in self.patients if 'SVH' in p['hospitals']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            u.strong = u.full_name = u.second_clue = True
            deva = self.r.random() < 0.7
            script = 'deva' if deva else 'latin'
            reg = date(2025, 11, 20) + timedelta(days=self.r.randint(0, 40))
            rows.append([u.ent('MRN', p['uhid']['SVH']), u.ent('PATIENT_NAME', p['deva'] if deva else p['name'], script),
                         'पुरुष' if p['gender'] == 'M' else 'महिला', str(p['age']), u.ent('DOB', fmt(p['dob'], 'slash')),
                         ('पति ' if p['rel'] == 'W/o' else 'पिता ') + u.ent('RELATIVE_NAME', p['reldeva'] if deva else p['relname'], script),
                         u.ent('HOUSE', 'मकान नं. ' + p['house'][7:], 'deva') + ', ' + u.ent('LOCALITY', 'मोहल्ला ' + p['mohalla']),
                         u.ent('VILLAGE', p['village'][1] if deva else p['village'][0], script), u.keep('district', p['district'][1]),
                         u.ent('PIN', p['pin']), u.ent('PHONE', self.phone_fmt(p)),
                         u.ent('AADHAAR', f"{p['aadhaar'][:4]}-{p['aadhaar'][4:8]}-{p['aadhaar'][8:]}"),
                         u.date('registration', reg, fmt(reg, 'slash'))])
            units.append(u)
        self.put('registration/sarvodaya_panjikaran.tsv', self.table(header, rows, '\t'), 'tsv', units, 'utf-16')

        # AGH: nested JSON {"meta": {...}, "records": [...]} with an export path holding a name
        clerk = self.person(99999)
        records, units = [], []
        for p in [p for p in self.patients if 'AGH' in p['hospitals']]:
            u = Unit(f'/records/{len(records)}', p['pt'])
            u.strong = u.full_name = u.second_clue = True
            rec = {'person': {'fullName': u.ent('PATIENT_NAME', p['name']), 'gender': 'male' if p['gender'] == 'M' else 'female',
                              'dob': u.ent('DOB', p['dob'].isoformat()), 'age': p['age']},
                   'guardian': {'relation': p['rel'], 'name': u.ent('RELATIVE_NAME', p['relname'])},
                   'address': {'line': u.ent('HOUSE', p['house']) + ', ' + u.ent('LOCALITY', p['mohalla']),
                               'village': u.ent('VILLAGE', p['village'][0]), 'district': u.keep('district', p['district'][0]),
                               'pin': u.ent('PIN', p['pin'])},
                   'contacts': [{'type': 'mobile', 'value': u.ent('PHONE', p['phone'])}],
                   'ids': {'hospitalNo': u.ent('MRN', p['uhid']['AGH']), 'aadhaarNo': int(p['aadhaar'])}}
            u.ent('AADHAAR', p['aadhaar'])
            if p['email']:
                rec['contacts'].append({'type': 'email', 'value': u.ent('EMAIL', p['email'])})
            if p['pan']:
                rec['ids']['panNo'] = u.ent('PAN', p['pan'])
            records.append(rec)
            units.append(u)
        meta_unit = Unit('@file')
        meta = {'system': 'Aastha HIS v4', 'exported_from': 'D:/exports/' + meta_unit.ent('PATIENT_NAME', clerk['name'], channel='metadata') + '/agh_reg.json',
                'generated': '2026-10-30T10:00:00+05:30'}
        self.put('registration/aastha_export.json', json.dumps({'meta': meta, 'records': records}, ensure_ascii=False, indent=1),
                 'json', units + [meta_unit])

        # CHB: legacy cp1252 CSV, dd-Mon-yyyy, combined age/sex
        header = ['CHC_No', 'Patient Full Name', 'Age/Sex', 'Father-Husband', 'Village', 'Mobile', 'Date of Registration (dd-Mon-yyyy)']
        rows, units = [], []
        for p in [p for p in self.patients if 'CHB' in p['hospitals']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            u.strong = u.full_name = u.second_clue = True
            reg = date(2025, 12, 1) + timedelta(days=self.r.randint(0, 30))
            rows.append([u.ent('MRN', p['uhid']['CHB']), u.ent('PATIENT_NAME', p['name'].upper()), f"{p['age']}/{p['gender']}",
                         p['rel'] + ' ' + u.ent('RELATIVE_NAME', p['relname']), u.ent('VILLAGE', p['village'][0]),
                         u.ent('PHONE', self.phone_fmt(p)), u.date('registration', reg, fmt(reg, 'mon'))])
            units.append(u)
        self.put('registration/chc_bhinga_legacy.csv', self.table(header, rows), 'csv', units, 'cp1252', date_hint='mon')

    # ------------------------------------------------------------- discharge, notes
    def discharge(self):
        n = 0
        for p in self.patients:
            for h, start, end in p['stays']:
                n += 1
                style = HOSPITALS[h]['style']
                u = Unit('doc', p['pt'])
                u.strong = True
                dx = p['dx']
                doc = self.r.choice(DOCTORS)
                med = self.r.choice(MEDS)
                if h == 'SVH':
                    text = (f"{HOSPITALS[h]['name']}, {HOSPITALS[h]['city']}\nडिस्चार्ज सारांश\n\n"
                            f"रोगी का नाम: {u.ent('PATIENT_NAME', p['deva'], 'deva')}    आयु: {p['age']} वर्ष\n"
                            f"{'पति' if p['rel'] == 'W/o' else 'पिता'} का नाम: {u.ent('RELATIVE_NAME', p['reldeva'], 'deva')}\n"
                            f"पंजीकरण सं.: {u.ent('MRN', p['uhid'][h])}\n"
                            f"पता: ग्राम {u.ent('VILLAGE', p['village'][1], 'deva')}, जिला {u.keep('district', p['district'][1])} - {u.ent('PIN', p['pin'])}\n"
                            f"मोबाइल: {u.ent('PHONE', self.phone_fmt(p, 'deva'), 'deva')}\n"
                            f"भर्ती की तारीख: {u.date('admission', start, fmt(start, style), 'भर्ती की तारीख:')}\n"
                            f"छुट्टी की तारीख: {u.date('discharge', end, fmt(end, style), 'छुट्टी की तारीख:')}\n\n"
                            f"निदान: {u.keep('diagnosis', dx[2])} ({u.keep('diagnosis_code', dx[1])})\n"
                            f"{u.keep('vital', 'BP 132/84')} mmHg, {u.keep('lab', 'Haemoglobin 10.4 g/dL')}\n"
                            f"दवा: Tab {u.keep('medication', med[0] + ' ' + med[1])} {u.keep('frequency', med[2])} x 5 days\n"
                            f"{u.keep('doctor', doc)}\n")
                    name = f'discharge/svh_ds_{n:04d}.txt'
                else:
                    label = self.r.choice(['Name of Patient', "Patient's Name", 'Pt.', 'Name'])
                    rel_label = {'W/o': 'W/o', 'S/o': 'S/o', 'D/o': 'D/o'}[p['rel']]
                    dob_line = f"Date of Birth: {u.ent('DOB', fmt(p['dob'], style))}\n" if self.r.random() < 0.6 else ''
                    text = (f"{HOSPITALS[h]['name'].upper()}, {HOSPITALS[h]['city'].upper()}\nSUMMARY OF DISCHARGE\n\n"
                            f"{label}: {u.ent('PATIENT_NAME', p['name'])}   Age/Gender: {p['age']} Y/{p['gender']}\n"
                            f"{rel_label} {u.ent('RELATIVE_NAME', p['relname'])}\n"
                            f"IP No.: {u.ent('MRN', p['uhid'][h])}\n"
                            f"Residence: {u.ent('HOUSE', p['house'])}, Village {u.ent('VILLAGE', p['village'][0])}, Dist. {u.keep('district', p['district'][0])}, PIN {u.ent('PIN', p['pin'])}\n"
                            f"Contact: {u.ent('PHONE', self.phone_fmt(p))}\n{dob_line}"
                            f"Admitted On: {u.date('admission', start, fmt(start, style), 'Admitted On:')}\n"
                            f"Discharged On: {u.date('discharge', end, fmt(end, style), 'Discharged On:')}\n\n"
                            f"Final Diagnosis: {u.keep('diagnosis', dx[0])} ({u.keep('diagnosis_code', dx[1])})\n"
                            f"Complaints: {u.keep('complaint', 'C/O fever for 4 days')} with body ache.\n"
                            f"Vitals: {u.keep('vital', 'BP 128/82')}, {u.keep('vital', 'SpO2 96%')}, {u.keep('vital', 'Temp 100.4 F')}\n"
                            f"Investigations: {u.keep('lab', 'Haemoglobin 11.2 g/dL')}, {u.keep('lab', 'Platelet count 145000 /cumm')}\n"
                            f"Rx: Tab {u.keep('medication', med[0] + ' ' + med[1])} {u.keep('frequency', med[2])} x 5 days\n"
                            f"Treating consultant: {u.keep('doctor', doc)}\n"
                            f"{p['given'][0]} ki condition ab theek hai. Attendant {u.ent('RELATIVE_NAME', p['relg'][0], 'hinglish')} ko samjhaya.\n")
                    if self.r.random() < 0.5:
                        fname = f"{p['given'][0]}_{p['sur'][0]}"
                        u.ent('PATIENT_NAME', fname, channel='filename')
                        name = f"discharge/DS_{fname}_{p['uhid'][h].replace('/', '-')}.txt"
                    else:
                        name = f'discharge/{h.lower()}_summary_{n:04d}.txt'
                u.ent('PATIENT_NAME', p['given'][0], 'hinglish') if h != 'SVH' else None
                u.full_name = u.second_clue = True
                self.put(name, text, 'text', [u], date_hint='mon' if style == 'mon' else 'dmy')
                # Hinglish nursing note for some stays
                if self.r.random() < 0.4:
                    v = Unit('doc', p['pt'])
                    hon = self.r.choice(['ji', 'sahab', 'didi', 'bhaiya']) if p['gender'] == 'M' or True else 'ji'
                    with_id = self.r.random() < 0.6
                    v.strong = with_id
                    t = (f"NURSING NOTES - Ward {self.r.randint(1, 9)} ({v.keep('ward', 'General Medicine')})"
                         + (f" - {v.ent('MRN', p['uhid'][h])}" if with_id else '') + "\n\n"
                         f"{v.date('note', start, fmt(start, style))} 21:00 - {v.ent('PATIENT_NAME', p['given'][0] + ' ' + hon, 'hinglish')} ka "
                         f"{v.keep('vital', 'BP 140/90')}, pulse 98. Bukhar 102 F. {v.keep('medication', 'Paracetamol 650 mg')} diya.\n"
                         f"Subah 06:00 - patient ne raat theek se neend li. {v.keep('lab', 'RBS 162 mg/dL')}.\n"
                         f"Attendant ({p['rel']} {v.ent('RELATIVE_NAME', p['relg'][0], 'hinglish')}) ko diet samjhayi.\n")
                    v.first_plus_relative = True
                    v.unique_combo = self.combo_unique(p)
                    self.put(f'notes/nursing_{n:04d}.txt', t, 'text', [v])

    def fragmented(self):
        for k, p in enumerate([p for p in self.patients if p['rel'] == 'W/o' and p['stays']][:6]):
            u = Unit('doc', p['pt'])
            u.first_plus_relative = True
            u.unique_combo = self.combo_unique(p)
            h, start, end = p['stays'][0]
            t = (f"Discharge note\n\n{u.ent('PATIENT_NAME', p['given'][0])}, W/o {u.ent('RELATIVE_NAME', p['relg'][0])}, discharged in stable condition.\n"
                 f"Visit: {u.date('discharge', end, f'{end.day} {MONTHS_FULL[end.month - 1]}')}\n"
                 f"Treated for {u.keep('diagnosis', p['dx'][0])}. {u.keep('vital', 'BP 150/94')}. Continue {u.keep('medication', 'Amlodipine 5 mg')} {u.keep('frequency', '0-0-1')}.\n")
            self.put(f'discharge/short_note_{k:03d}.txt', t, 'text', [u])

    def prescriptions(self):
        k = 0
        for p in self.patients:
            for h, d in p['opd']:
                if h != 'SVH' or self.r.random() < 0.3:
                    continue
                k += 1
                u = Unit('doc', p['pt'])
                u.full_name = u.second_clue = True
                med = self.r.choice(MEDS)
                t = (f"{HOSPITALS[h]['name']} - ओपीडी पर्चा\n"
                     f"नाम: {u.ent('PATIENT_NAME', p['deva'], 'deva')}   आयु: {p['age']} वर्ष\n"
                     f"ग्राम: {u.ent('VILLAGE', p['village'][1], 'deva')}\n"
                     f"तारीख: {u.date('visit', d, fmt(d, 'slash'), 'तारीख:')}\n"
                     f"Rx\n1. Tab {u.keep('medication', med[0] + ' ' + med[1])} {u.keep('frequency', med[2])} x 5 days\n"
                     f"{u.keep('doctor', self.r.choice(DOCTORS))}\n")
                self.put(f'prescriptions/svh_rx_{k:04d}.txt', t, 'text', [u])

    # ------------------------------------------------------------- OPD JSON
    def opd(self):
        visits, units = [], []
        for p in self.patients:
            for h, d in p['opd']:
                if h != 'KMH':
                    continue
                u = Unit(f'/visits/{len(visits)}', p['pt'])
                u.strong = True
                med = self.r.choice(MEDS)
                visits.append({'regn_no': u.ent('MRN', p['uhid'][h]), 'visit_on': u.date('visit', d, fmt(d, 'dot')),
                               'consultant': u.keep('doctor', self.r.choice(DOCTORS)),
                               'chief_complaint': u.keep('complaint', 'C/O cough x 2 weeks'),
                               'vitals': {'bp': '124/80', 'pulse': 84, 'spo2': 97},
                               'dx': [{'code': u.keep('diagnosis_code', p['dx'][1]), 'display': u.keep('diagnosis', p['dx'][0])}],
                               'meds': [{'drug': u.keep('medication', med[0]), 'dose': med[1], 'freq': u.keep('frequency', med[2]), 'days': 5}],
                               'remarks': f"{u.ent('PATIENT_NAME', p['given'][0], 'hinglish')} ko 1 hafte baad bulaya.",
                               'pt': {'name': u.ent('PATIENT_NAME', p['name']), 'mob': u.ent('PHONE', p['phone'])}})
                units.append(u)
        # canary hidden in a JSON key
        canary = self.canary('Velmar Ostridge', 'key')
        cu = Unit('@file')
        cu.ent('CANARY', canary, channel='key')
        payload = {'export': 'KMH OPD', 'visits': visits}
        if visits:
            visits[0]['note for ' + canary] = 'call back'
        self.put('opd/kmh_opd_2026.json', json.dumps(payload, ensure_ascii=False, indent=1), 'json', units + [cu])
        # AGH: top-level list, camelCase keys, ISO dates
        visits, units = [], []
        for p in self.patients:
            for h, d in p['opd']:
                if h != 'AGH':
                    continue
                u = Unit(f'/{len(visits)}', p['pt'])
                u.strong = True
                visits.append({'hospitalNo': u.ent('MRN', p['uhid'][h]), 'visitDate': u.date('visit', d, d.isoformat()),
                               'patientName': u.ent('PATIENT_NAME', p['name']), 'contactNumber': u.ent('PHONE', '+91' + p['phone']),
                               'diagnosisText': u.keep('diagnosis', p['dx'][0]), 'icd10': u.keep('diagnosis_code', p['dx'][1]),
                               'treatingDoctor': u.keep('doctor', self.r.choice(DOCTORS))})
                units.append(u)
        self.put('opd/agh_opd_visits.json', json.dumps(visits, ensure_ascii=False, indent=1), 'json', units)

    # ------------------------------------------------------------- FHIR
    def fhir(self):
        k = 0
        for p in self.patients:
            for h, start, end in p['stays']:
                if h != 'AGH' or self.r.random() < 0.4:
                    continue
                k += 1
                u = Unit('doc', p['pt'])
                u.strong = True
                ids = {x: f'urn:uuid:{hashlib.md5((p["rid"] + x + str(start)).encode()).hexdigest()}' for x in ('pat', 'enc', 'con', 'doc', 'dr')}
                note = f"Discharge note for {p['name']}, mobile {p['phone']}. Diagnosis {p['dx'][0]}."
                u.ent('PATIENT_NAME', p['name'], channel='base64')
                attachment = base64.b64encode(note.encode()).decode()
                bundle = {'resourceType': 'Bundle', 'type': 'document', 'timestamp': end.isoformat() + 'T12:00:00+05:30', 'entry': [
                    {'fullUrl': ids['pat'], 'resource': {'resourceType': 'Patient', 'id': ids['pat'][9:],
                     'identifier': [{'system': 'https://aastha.example/uhid', 'value': u.ent('MRN', p['uhid'][h])}],
                     'name': [{'given': [u.ent('PATIENT_NAME', p['given'][0])], 'family': u.ent('PATIENT_NAME', p['sur'][0])}],
                     'gender': 'male' if p['gender'] == 'M' else 'female', 'birthDate': u.ent('DOB', p['dob'].isoformat()),
                     'telecom': [{'system': 'phone', 'value': u.ent('PHONE', p['phone'])}],
                     'address': [{'line': [u.ent('HOUSE', p['house'])], 'city': u.ent('VILLAGE', p['village'][0]),
                                  'district': u.keep('district', p['district'][0]), 'postalCode': u.ent('PIN', p['pin'])}],
                     'contact': [{'relationship': [{'text': p['rel']}], 'name': {'text': u.ent('RELATIVE_NAME', p['relname'])}}]}},
                    {'fullUrl': ids['dr'], 'resource': {'resourceType': 'Practitioner', 'id': ids['dr'][9:],
                     'name': [{'text': u.keep('doctor', self.r.choice(DOCTORS))}]}},
                    {'fullUrl': ids['enc'], 'resource': {'resourceType': 'Encounter', 'id': ids['enc'][9:], 'status': 'finished',
                     'subject': {'reference': ids['pat']}, 'period': {'start': u.date('admission', start, start.isoformat()),
                                                                     'end': u.date('discharge', end, end.isoformat())}}},
                    {'fullUrl': ids['con'], 'resource': {'resourceType': 'Condition', 'id': ids['con'][9:], 'subject': {'reference': ids['pat']},
                     'code': {'coding': [{'system': 'http://hl7.org/fhir/sid/icd-10', 'code': u.keep('diagnosis_code', p['dx'][1]),
                                          'display': u.keep('diagnosis', p['dx'][0])}], 'text': p['dx'][0]}}},
                    {'fullUrl': ids['doc'], 'resource': {'resourceType': 'DocumentReference', 'id': ids['doc'][9:], 'status': 'current',
                     'subject': {'reference': ids['pat'], 'display': u.ent('PATIENT_NAME', p['name'])},
                     'content': [{'attachment': {'contentType': 'text/plain', 'data': attachment}}]}}]}
                self.put(f'fhir/agh_bundle_{k:03d}.json', json.dumps(bundle, ensure_ascii=False, indent=1), 'fhir', [u])

    # ------------------------------------------------------------- lab, billing
    def lab_billing(self):
        canary = self.canary('Zephro Anaktal', 'header')
        header = ['sample_no', 'pt_name', 'age/sex', 'hosp_id', 'ref_by', 'investigation', 'result', 'units', 'normal_range',
                  'collected', 'verified by ' + canary]
        rows, units = [], []
        tests = [('Haemoglobin', '11.6', 'g/dL', '12.0-16.0'), ('Serum Creatinine', '1.4', 'mg/dL', '0.6-1.2'),
                 ('Random Blood Sugar', '182', 'mg/dL', '70-140')]
        for p in self.r.sample(self.patients, 40):
            h = p['hospitals'][0]
            d = (p['stays'][0][1] if p['stays'] else date(2026, 5, 10)) + timedelta(days=1)
            for t in tests:
                u = Unit(f'row:{len(rows)}', p['pt'])
                u.strong = True
                rows.append([f'LB{len(rows):06d}', u.ent('PATIENT_NAME', p['name']), f"{p['age']}/{p['gender']}", u.ent('MRN', p['uhid'][h]),
                             u.keep('doctor', self.r.choice(DOCTORS)), u.keep('lab_test', t[0]), t[1], t[2], u.keep('range', t[3]),
                             u.date('collected', d, fmt(d, 'dot')), 'ok'])
                units.append(u)
        cu = Unit('@header')
        cu.ent('CANARY', canary, channel='header')
        self.put('lab/pathcare_results.csv', self.table(header, rows), 'csv', units + [cu])
        header = ['claim_no', 'hospital_no', 'beneficiary', 'pmjay_card', 'pan', 'admit_dt', 'disch_dt', 'package', 'amount']
        rows, units = [], []
        for p in self.patients:
            for h, start, end in p['stays']:
                u = Unit(f'row:{len(rows)}', p['pt'])
                u.strong = True
                style = HOSPITALS[h]['style'] if HOSPITALS[h]['style'] != 'mon' else 'slash'
                rows.append([f'CL/26/{len(rows):05d}', u.ent('MRN', p['uhid'][h]), u.ent('PATIENT_NAME', p['name']),
                             u.ent('INSURANCE_ID', f'PMJAY-UP-{self.r.randint(1000000000, 9999999999)}'),
                             u.ent('PAN', p['pan']) if p['pan'] else '', u.date('admission', start, fmt(start, style)),
                             u.date('discharge', end, fmt(end, style)), u.keep('package', 'MG001A'), str(self.r.randint(5, 90) * 1000)])
                units.append(u)
        self.put('billing/state_claims.csv', self.table(header, rows), 'csv', units)

    # ------------------------------------------------------------- clean, misc, canaries
    def canary(self, name, where):
        self.canaries.append(name)
        return name

    def clean_and_misc(self):
        u = Unit('doc')
        t = ('Japanese Encephalitis prevention protocol\nVaccinate children 1-15 yrs. Dr. Ramesh Tripathi reviewed this protocol.\n'
             f"{u.keep('medication', 'Paracetamol 650 mg')} for fever. Report {u.keep('vital', 'SpO2 below 92%')}.\n")
        self.put('clean/je_protocol.txt', t, 'text', [u])
        rows, units = [], []
        for m in MEDS:
            v = Unit(f'row:{len(rows)}')
            rows.append([v.keep('medication', m[0]), v.keep('dose', m[1]), v.keep('frequency', m[2])])
            units.append(v)
        self.put('clean/formulary.csv', self.table(['drug', 'strength', 'frequency'], rows), 'csv', units)
        canary = self.canary('Qwilt Varunesh', 'filename')
        u = Unit('doc', None)
        u.ent('CANARY', canary, channel='filename')
        t = f"Referral letter\nPatient: {u.ent('CANARY', canary)}  Age: 51 Yrs/M\nMobile: 7000004321\nReferred to {u.keep('doctor', 'Dr. Kamla Saxena')}\n"
        self.put('misc/Referral_Qwilt_Varunesh.txt', t, 'text', [u])
        canary = self.canary('Ombrel Tasquith', 'base64')
        u = Unit('doc', None)
        u.ent('CANARY', canary, channel='base64')
        blob = base64.b64encode(f'Scanned consent of {canary}, phone 7000009876'.encode()).decode()
        self.put('misc/consent_scan.json', json.dumps({'document': 'consent', 'contentType': 'text/plain', 'data': blob}), 'json', [u])
        p = self.patients[1]
        self.put('misc/broken_export.json', '{"records": [{"name": "' + p['name'] + '", "mobile": "' + p['phone'] + '"', 'json',
                 [], expect='either')
        self.put('misc/old_system.xml', f'<patient><name>{p["name"]}</name></patient>', 'xml', [], expect='either')
        self.put('misc/empty.csv', '', 'csv', [], expect='either')
        self.put('misc/visits.jsonl', json.dumps({'name': p['name']}) + '\n', 'jsonl', [], expect='either')

    # ------------------------------------------------------------- attacker files
    def attacker(self, root: Path):
        (root / 'dev/attacker').mkdir(parents=True, exist_ok=True)
        with (root / 'dev/attacker/registry.csv').open('w', encoding='utf-8', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['rid', 'name', 'relation', 'relative_name', 'gender', 'age', 'house_no', 'mohalla', 'village', 'tehsil',
                        'district', 'pin', 'phone', 'email', 'aadhaar_last4'])
            for p in self.population:
                leak = self.r.random() < 0.6
                w.writerow([p['rid'], p['name'], p['rel'], p['relname'], p['gender'], p['age'], p['house'][7:], p['mohalla'],
                            p['village'][0], p['tehsil'], p['district'][0], p['pin'], p['phone'] if leak else '',
                            (p['email'] or '') if leak else '', p['aadhaar'][-4:] if leak else ''])
        facts = []
        for p in self.r.sample([p for p in self.patients if p['stays']], max(1, len(self.patients) * 3 // 10)):
            h, start, end = p['stays'][0]
            f = {'rid': p['rid'], 'visit_dates': [start.isoformat()], 'hospital': HOSPITALS[h]['name']}
            if self.r.random() < 0.5 or p['dx'] in RARE:
                f['condition_hint'] = p['dx'][0]
            if self.r.random() < 0.3:
                f['stay_days'] = (end - start).days
            facts.append(f)
        patient_rids = {p['rid'] for p in self.patients}
        for p in self.r.sample([x for x in self.population if x['rid'] not in patient_rids], 8):
            facts.append({'rid': p['rid'], 'visit_dates': ['2026-07-14'], 'hospital': HOSPITALS['KMH']['name']})
        self.r.shuffle(facts)
        (root / 'dev/attacker/known_facts.jsonl').write_text(''.join(json.dumps(f) + '\n' for f in facts), encoding='utf-8')

    def write(self, root: Path):
        for path, data in self.raw.items():
            f = root / 'dev/input' / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        truth = {'schema': 'raksha-truth/1', 'generator': 'team-0098 hidden-style v1', 'files': self.files,
                 'patients': {p['pt']: {'rid': p['rid']} for p in self.patients},
                 'traps': {'homonym_pairs': self.homonyms,
                           'reidentification': [self.patients[0]['pt']] + [p['pt'] for p in self.patients if p['dx'] in RARE],
                           'fragmented': [], 'language': [], 'meaning': []},
                 'canaries': self.canaries}
        (root / 'dev/truth').mkdir(parents=True, exist_ok=True)
        (root / 'dev/truth/truth.json').write_text(json.dumps(truth, ensure_ascii=False, default=str), encoding='utf-8')
        self.attacker(root)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--seed', type=int, default=7)
    ap.add_argument('--patients', type=int, default=120)
    a = ap.parse_args()
    g = Gen(a.seed, a.patients)
    g.build_population()
    g.registration()
    g.discharge()
    g.fragmented()
    g.prescriptions()
    g.opd()
    g.fhir()
    g.lab_billing()
    g.clean_and_misc()
    g.write(a.out)
    units = sum(len(f['units']) for f in g.files.values())
    print(f'{len(g.files)} files, {units} truth units, {len(g.patients)} patients, {len(g.population)} people in registry')


if __name__ == '__main__':
    main()
