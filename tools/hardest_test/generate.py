#!/usr/bin/env python3
"""Secret Wards HARDEST test generator (Track 3). Standard library only.

    python3 generate.py --out hardest_data --seed 2026 --patients 200

Creates, in the same layout as the official team kit:

    <out>/dev/input/                 the files your system receives (read-only on test day)
    <out>/dev/truth/truth.json       answer key: every PII mention, preserve probe, date, link
    <out>/dev/attacker/registry.csv  voter-roll style register of the whole population
    <out>/dev/attacker/known_facts.jsonl

Then run your system on <out>/dev/input and score it with score.py.

Everything is synthetic. Names and places are drawn from generic Indian
vocabularies; identifiers are random (Aadhaar numbers carry a valid Verhoeff
check digit so validators accept them). No real person is described.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import io
import json
import random
import urllib.parse
from datetime import date, timedelta
from pathlib import Path

REF = date(2026, 11, 20)
PARK, BELL, WILSON, KOCH = "Parkinson's disease", "Bell's palsy", "Wilson's disease", "Koch's (TB)"


# ------------------------------------------------------------------ vocab
M = {'hindu': [('Ramesh', 'रमेश'), ('Suresh', 'सुरेश'), ('Mahendra', 'महेंद्र'), ('Naveen', 'नवीन'), ('Pankaj', 'पंकज'),
               ('Deepak', 'दीपक'), ('Gaurav', 'गौरव'), ('Hemant', 'हेमंत'), ('Lalit', 'ललित'), ('Manish', 'मनीष'),
               ('Prem', 'प्रेम'), ('Raghav', 'राघव'), ('Satyam', 'सत्यम'), ('Umesh', 'उमेश'), ('Vinod', 'विनोद'),
               ('Bharat', 'भरत'), ('Raja', 'राजा'), ('Kiran', 'किरण'), ('Ram', 'राम'), ('Shivendra', 'शिवेंद्र')],
     'muslim': [('Mohammad Arif', 'मोहम्मद आरिफ़'), ('Imran', 'इमरान'), ('Irfan', 'इरफ़ान'), ('Javed', 'जावेद'),
                ('Nadeem', 'नदीम'), ('Rizwan', 'रिज़वान'), ('Shakeel', 'शकील'), ('Zubair', 'ज़ुबैर')],
     'sikh': [('Gurpreet', 'गुरप्रीत'), ('Harjeet', 'हरजीत'), ('Kuldeep', 'कुलदीप'), ('Jasvinder', 'जसविंदर')],
     'south': [('Karthik', 'कार्तिक'), ('Senthil', 'सेंथिल'), ('Murugan', 'मुरुगन'), ('Venkatesh', 'वेंकटेश')]}
F = {'hindu': [('Asha', 'आशा'), ('Pooja', 'पूजा'), ('Lakshmi', 'लक्ष्मी'), ('Ganga', 'गंगा'), ('Sita', 'सीता'),
               ('Anita', 'अनीता'), ('Babita', 'बबीता'), ('Durga', 'दुर्गा'), ('Kamla', 'कमला'), ('Rekha', 'रेखा'),
               ('Savita', 'सविता'), ('Sushma', 'सुषमा'), ('Urmila', 'उर्मिला'), ('Kiran', 'किरण'), ('Munni', 'मुन्नी')],
     'muslim': [('Farzana', 'फ़रज़ाना'), ('Nasreen', 'नसरीन'), ('Rubina', 'रुबीना'), ('Shabnam', 'शबनम'), ('Zainab', 'ज़ैनब')],
     'sikh': [('Harpreet', 'हरप्रीत'), ('Manjeet', 'मनजीत'), ('Simran', 'सिमरन')],
     'south': [('Lakshmi', 'लक्ष्मी'), ('Meenakshi', 'मीनाक्षी'), ('Kavitha', 'कविता')]}
SUR = {'hindu': [('Verma', 'वर्मा'), ('Shrivastava', 'श्रीवास्तव'), ('Tripathi', 'त्रिपाठी'), ('Chauhan', 'चौहान'),
                 ('Choudhary', 'चौधरी'), ('Kashyap', 'कश्यप'), ('Rawat', 'रावत'), ('Pal', 'पाल'), ('Gautam', 'गौतम'),
                 ('Bharti', 'भारती'), ('Yadav', 'यादव'), ('Mishra', 'मिश्रा'), ('Bell', 'बेल'), ('Parkash', 'परकाश')],
       'muslim': [('Qureshi', 'क़ुरैशी'), ('Khan', 'ख़ान'), ('Ansari', 'अंसारी'), ('Siddiqui', 'सिद्दीक़ी')],
       'sikh': [('Gill', 'गिल'), ('Sandhu', 'संधू')],
       'south': [('', '')]}
SPELLING = {'Shrivastava': ['Srivastava', 'Shrivastav', 'Srivastav'], 'Vinod': ['Binod'], 'Savita': ['Sabita'],
            'Babita': ['Vavita', 'Babeeta'], 'Anita': ['Aneeta'], 'Sushma': ['Sushama'], 'Deepak': ['Dipak'], 'Lakshmi': ['Laxmi', 'Lakshmee'],
            'Chauhan': ['Chouhan'], 'Choudhary': ['Chaudhari', 'Chaudhary'], 'Mohammad Arif': ['Md. Arif', 'Mohd Arif', 'Muhammad Arif'],
            'Kavitha': ['Kavita'], 'Pooja': ['Puja'], 'Qureshi': ['Kureshi'], 'Siddiqui': ['Siddiqi']}
NICK = {'Ramesh': 'Pappu', 'Suresh': 'Guddu', 'Munni': 'Munni', 'Pooja': 'Pinky', 'Rekha': 'Bittu'}
V_PRE = [('Bhawani', 'भवानी'), ('Ram', 'राम'), ('Sita', 'सीता'), ('Kesho', 'केशो'), ('Madho', 'माधो'), ('Hari', 'हरि'),
         ('Lal', 'लाल'), ('Shiv', 'शिव'), ('Chand', 'चंद'), ('Bel', 'बेल')]
V_SUF = [('pur', 'पुर'), ('ganj', 'गंज'), ('nagar', 'नगर'), ('garh', 'गढ़'), ('dih', 'डीह'), ('mau', 'मऊ'), ('khera', 'खेड़ा')]
DISTRICTS = [('Lucknow', 'लखनऊ', '226'), ('Barabanki', 'बाराबंकी', '225'), ('Sitapur', 'सीतापुर', '261'),
             ('Hardoi', 'हरदोई', '241'), ('Unnao', 'उन्नाव', '209'), ('Rae Bareli', 'रायबरेली', '229'),
             ('Gonda', 'गोंडा', '271'), ('Bahraich', 'बहराइच', '271')]
COMMON = [('Typhoid fever', 'A01.0', 'टाइफाइड बुखार'), ('Dengue fever', 'A97.9', 'डेंगू बुखार'),
          ('Tuberculosis of lung', 'A15.0', 'फेफड़ों की टीबी'), ('Type 2 diabetes mellitus without complications', 'E11.9', 'मधुमेह'),
          ('Essential (primary) hypertension', 'I10', 'उच्च रक्तचाप'), ('Pneumonia, unspecified', 'J18.9', 'निमोनिया'),
          ('Anaemia, unspecified', 'D64.9', 'खून की कमी'), ('Infectious gastroenteritis and colitis, unspecified', 'A09', 'दस्त और उल्टी')]
RARE = [('Japanese encephalitis', 'A83.0', 'जापानी इंसेफेलाइटिस'), ('Rabies, unspecified', 'A82.9', 'रेबीज़'),
        ('Visceral leishmaniasis (kala-azar)', 'B55.0', 'काला-अज़ार'), (PARK, 'G20', 'पार्किंसंस रोग'),
        (BELL, 'G51.0', 'बेल्स पाल्सी'), ('Guillain-Barre syndrome', 'G61.0', 'गुलियन बैरे सिंड्रोम')]
MEDS = [('Paracetamol', '650 mg', '1-1-1'), ('Dolo', '650', 'BD x 5 days'), ('Amlodipine', '5 mg', '0-0-1'),
        ('Ramipril', '5 mg', '1-0-0'), ('Metformin', '500 mg', '1-0-1'), ('Ceftriaxone', '1 g', 'IV BD'),
        ('Levothyroxine', '50 mcg', 'OD'), ('Pantoprazole', '40 mg', 'HS')]
HOSP = {'A': ('Sanjivani Multispeciality Hospital', 'Lucknow'), 'B': ('Jan Kalyan Charitable Hospital', 'Barabanki'),
        'C': ('Arogya Seva Sadan', 'Sitapur'), 'D': ('District Hospital Hardoi', 'Hardoi'), 'E': ('Sri Venkateswara Clinic', 'Lucknow')}
GENERIC = {'kumar', 'kumari', 'devi', 'singh', 'kaur', 'bano', 'begum', 'khatoon', 'md', 'mohd', 'mohammad', 'muhammad',
           'ji', 'sahab', 'didi', 'bhaiya', 'baby', 'of', 'late', 'shri', 'smt'}
HI_MONTHS = ['जनवरी', 'फ़रवरी', 'मार्च', 'अप्रैल', 'मई', 'जून', 'जुलाई', 'अगस्त', 'सितंबर', 'अक्टूबर', 'नवंबर', 'दिसंबर']
EN_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
DEVA = '०१२३४५६७८९'
HI_NUM = ['शून्य', 'एक', 'दो', 'तीन', 'चार', 'पाँच', 'छह', 'सात', 'आठ', 'नौ']
HINGLISH_NUM = ['zero', 'ek', 'do', 'teen', 'char', 'paanch', 'chhe', 'saat', 'aath', 'nau']
HOMO = {'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'i': 'і', 'A': 'А', 'E': 'Е', 'O': 'О', 'K': 'К', 'M': 'М'}

# ------------------------------------------------------------------ helpers
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def tokens(name):
    return [t for t in name.casefold().replace('.', ' ').replace('_', ' ').split() if t not in GENERIC and len(t) > 1]


def deva_digits(s):
    return ''.join(DEVA[int(c)] if c.isdigit() else c for c in s)


def fmt(d: date, style: str) -> str:
    return {'dmy': d.strftime('%d/%m/%Y'), 'mdy': d.strftime('%m/%d/%Y'), 'iso': d.isoformat(),
            'dot2': d.strftime('%d.%m.%y'), 'dash': d.strftime('%d-%m-%Y'),
            'mon': f'{d.day:02d}-{EN_MONTHS[d.month - 1]}-{d.year}',
            'ord': f"{d.day}{'th' if 10 <= d.day % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(d.day % 10, 'th')} {EN_MONTHS[d.month - 1]} '{str(d.year)[2:]}",
            'hindi': f'{deva_digits(str(d.day))} {HI_MONTHS[d.month - 1]} {deva_digits(str(d.year))}',
            'long': f'{d.day} {d.strftime("%B")} {d.year}'}[style]


# ------------------------------------------------------------------ truth
class Unit:
    def __init__(self, loc, patient=None, tags=()):
        self.loc, self.patient, self.tags = loc, patient, list(tags)
        self.entities, self.preserve, self.dates, self.fields = [], [], [], []
        self.link = 'none' if not patient else 'required'

    def ent(self, typ, surface, script='latin', channel='content', key=None, obf=None, person_role='patient'):
        e = {'type': typ, 'surface': surface, 'script': script, 'channel': channel, 'role': person_role}
        if typ in ('PATIENT_NAME', 'RELATIVE_NAME', 'CANARY', 'STAFF_NAME'):
            e['match'] = 'name'
            e['tokens'] = key or tokens(surface)
        elif typ in ('PHONE', 'AADHAAR', 'AADHAAR_VID', 'ABHA_NUMBER', 'MRN', 'INSURANCE_ID', 'PMJAY_ID'):
            e['match'] = 'digits'
            e['key'] = key or ''.join(c for c in surface if c.isdigit())
        elif typ == 'DOB':
            e['match'] = 'dob'
            e['key'] = key
        else:
            e['match'] = 'text'
            e['key'] = key or surface
        if obf:
            e['obfuscation'] = obf
        self.entities.append(e)
        return surface

    def keep(self, kind, text, trap=None):
        p = {'text': text, 'kind': kind}
        if trap:
            p['trap'] = trap
        self.preserve.append(p)
        return text

    def date(self, event, true, surface, anchor=None):
        self.dates.append({'true': true.isoformat(), 'event': event, 'anchor': anchor, 'surface': surface})
        return surface

    def field(self, kind, true):
        self.fields.append({'kind': kind, 'true': true})

    def as_dict(self):
        return {'loc': self.loc, 'patient': self.patient, 'link': self.link, 'tags': self.tags, 'entities': self.entities,
                'preserve': self.preserve, 'dates': self.dates, 'fields': self.fields}


# ------------------------------------------------------------------ generator
class Gen:
    def __init__(self, seed, n):
        self.r = random.Random(seed)
        self.n = n
        self.files, self.raw = {}, {}
        self.traps = {k: [] for k in ('homonym_pairs', 'twins', 'father_son_same_name', 'shared_phone_family',
                                       'married_name_change', 'cross_script', 'fragmented', 'reidentification',
                                       'meaning', 'newborn', 'spelling_variants')}
        self.canaries = []
        self.seq = 10000

    # ---- people
    def person(self, i, group=None, gender=None, age=None):
        r = self.r
        group = group or r.choices(['hindu', 'muslim', 'sikh', 'south'], [65, 20, 7, 8])[0]
        gender = gender or r.choice('MF')
        given = r.choice((M if gender == 'M' else F)[group])
        sur = r.choice(SUR[group])
        age = age if age is not None else min(98, max(1, int(r.gauss(44, 19))))
        dist = r.choice(DISTRICTS)
        a, b = r.choice(V_PRE), r.choice(V_SUF)
        suffix = r.choice(['', '', ' Kalan', ' Khurd'])
        village = (a[0] + b[0] + suffix, a[1] + b[1] + {' Kalan': ' कलां', ' Khurd': ' खुर्द', '': ''}[suffix])
        rel = 'W/o' if gender == 'F' and age >= 22 and r.random() < 0.7 else ('S/o' if gender == 'M' else 'D/o')
        relg = r.choice(M[group])
        dob = REF - timedelta(days=age * 365 + r.randint(0, 364))
        core = f'{r.randint(2, 9)}{r.randint(10 ** 9, 10 ** 10 - 1)}'
        p = {'rid': f'UPR{i:07d}', 'group': group, 'gender': gender, 'given': given, 'sur': sur, 'age': age, 'dob': dob,
             'rel': rel, 'relg': relg, 'house': r.randint(1, 499), 'village': village, 'district': dist,
             'pin': dist[2] + f'{r.randint(100, 999)}', 'phone': f'{r.choice("6789")}{r.randint(10 ** 8, 10 ** 9 - 1)}',
             'aadhaar': core + verhoeff_digit(core), 'abha': f'{r.randint(10, 99)}{r.randint(10 ** 11, 10 ** 12 - 1)}',
             'pan': ''.join(r.choice('ABCDEFGHJKLMNPRSTUVWXYZ') for _ in range(3)) + 'P' + ((sur[0] or given[0])[0].upper())
                    + f'{r.randint(1000, 9999)}' + r.choice('ABCDEFHKLMNP'),
             'epic': ''.join(r.choice('ABCDEFGHJKLMNPRSTUVWXYZ') for _ in range(3)) + f'{r.randint(10 ** 6, 10 ** 7 - 1)}',
             'email': None}
        if r.random() < 0.15:
            p['email'] = f'{given[0].split()[0].lower()}.{(sur[0] or "x").lower()}{r.randint(1, 99)}@mailbox.example'
        self.names(p)
        return p

    def names(self, p):
        g, s = p['given'], p['sur']
        if p['group'] == 'south':
            initial = self.r.choice('KRSMV')
            p['name'], p['deva'] = f'{initial}. {g[0]}', g[1]
        else:
            p['name'], p['deva'] = f'{g[0]} {s[0]}'.strip(), f'{g[1]} {s[1]}'.strip()
        p['relname'] = f"{p['relg'][0]} {s[0]}".strip()
        p['reldeva'] = f"{p['relg'][1]} {s[1]}".strip()

    def variant(self, p):
        """A realistic alternative spelling of the patient's name."""
        g, s = p['given'][0], p['sur'][0]
        g2 = self.r.choice(SPELLING.get(g, [g]))
        s2 = self.r.choice(SPELLING.get(s, [s])) if s else ''
        if p['group'] == 'south':
            return p['name']
        return f'{g2} {s2}'.strip()

    def build(self):
        r = self.r
        self.pop = [self.person(i) for i in range(self.n * 5)]
        self.patients = r.sample(self.pop, self.n)
        for k, p in enumerate(self.patients):
            p['pt'] = f'HT{k:05d}'
        P = self.patients
        # homonyms: same full name, different person
        for a in r.sample([p for p in P if p['group'] != 'south'], min(3, len([p for p in P if p['group'] != 'south']))):
            options = [x for x in P if x is not a and x['gender'] == a['gender'] and x['group'] == a['group'] and abs(x['age'] - a['age']) > 8]
            if not options:
                continue                      # small datasets: skip this trap
            b = r.choice(options)
            b['given'], b['sur'] = a['given'], a['sur']
            self.names(b)
            self.traps['homonym_pairs'].append([a['pt'], b['pt']])
        # twins: same DOB, parents, phone and village; different first names
        pool = [p for p in P if p['group'] == 'hindu']
        a, b = r.sample(pool, 2) if len(pool) >= 2 else r.sample(P, 2)
        b.update(dob=a['dob'], age=a['age'], sur=a['sur'], relg=a['relg'], rel=a['rel'] if a['rel'] != 'W/o' else 'S/o',
                 village=a['village'], district=a['district'], pin=a['pin'], phone=a['phone'], house=a['house'])
        a['rel'] = b['rel']
        self.names(a), self.names(b)
        self.traps['twins'].append([a['pt'], b['pt']])
        # father and son with the same name, same house and phone
        pool = [p for p in P if p['group'] == 'hindu' and p['gender'] == 'M']
        f, s = r.sample(pool if len(pool) >= 2 else P, 2)
        s.update(given=f['given'], sur=f['sur'], rel='S/o', relg=f['given'], village=f['village'], district=f['district'],
                 pin=f['pin'], phone=f['phone'], house=f['house'], age=max(1, f['age'] - 26))
        s['dob'] = REF - timedelta(days=s['age'] * 365 + 40)
        self.names(f), self.names(s)
        s['suffix'], f['suffix'] = 'Jr', 'Sr'
        self.traps['father_son_same_name'].append([f['pt'], s['pt']])
        # family sharing a phone (husband registered as patient too)
        pool = [p for p in P if p['group'] == 'muslim']
        w, h = r.sample(pool if len(pool) >= 2 else P, 2)
        h.update(phone=w['phone'], village=w['village'], district=w['district'], pin=w['pin'], sur=w['sur'])
        self.names(h), self.names(w)
        self.traps['shared_phone_family'].append([w['pt'], h['pt']])
        # married name change: maiden name at one hospital, married name at another
        wives = [p for p in P if p['gender'] == 'F' and p['group'] == 'hindu' and p['rel'] == 'W/o']
        mc = r.choice(wives) if wives else None
        if mc:
            mc['maiden'] = f"{mc['given'][0]} {r.choice(SUR['hindu'])[0]}"
            self.traps['married_name_change'].append(mc['pt'])
        # re-identification traps
        P[0]['age'], P[0]['dob'] = 102, date(1924, 2, 29)
        P[1]['age'], P[1]['dob'] = 0, REF - timedelta(days=12)
        P[1]['newborn'] = True
        P[2]['village'] = ('Chhotkapurwa', 'छोटकापुरवा')
        for x in P[:3]:
            self.traps['reidentification'].append(x['pt'])
        self.traps['newborn'].append(P[1]['pt'])
        for p in P:
            p['dx'] = r.choice(COMMON)
        for p in r.sample(P[3:], min(6, len(P) - 3)):
            p['dx'] = r.choice(RARE)
            self.traps['reidentification'].append(p['pt'])
        # hospitals and stays (some across a year end, a leap day)
        for p in P:
            p['hosp'] = r.sample(list(HOSP), 2 if r.random() < 0.4 else 1)
            p['uhid'] = {h: self.uhid(h) for h in p['hosp']}
            p['stays'] = []
            for h in p['hosp']:
                if r.random() < 0.7:
                    start = date(2025, 6, 1) + timedelta(days=r.randint(0, 520))
                    p['stays'].append((h, start, start + timedelta(days=r.randint(1, 16))))
        P[3]['stays'] = [(P[3]['hosp'][0], date(2025, 12, 27), date(2026, 1, 4))]
        P[4]['stays'] = [(P[4]['hosp'][0], date(2024, 2, 26), date(2024, 3, 2))]
        if self.traps['married_name_change']:
            mc['hosp'] = ['A', 'C']
            mc['uhid'] = {h: self.uhid(h) for h in mc['hosp']}
            st = date(2026, 3, 2)
            mc['stays'] = [('A', st, st + timedelta(days=5)), ('C', st + timedelta(days=60), st + timedelta(days=63))]
        for p in P:
            if p['given'][0] in SPELLING or p['sur'][0] in SPELLING:
                self.traps['spelling_variants'].append(p['pt'])
            if p['group'] != 'south' and len(p['hosp']) >= 1:
                self.traps['cross_script'].append(p['pt'])
        self.traps['cross_script'] = self.traps['cross_script'][:12]

    def uhid(self, h):
        self.seq += self.r.randint(1, 9)
        n = self.seq
        return {'A': f'SMH/25/{n:06d}', 'B': f'JKC-{n:07d}', 'C': f'UHID{n:06d}', 'D': f'DHH-IPD-{n:05d}', 'E': f'SVC{n}'}[h]

    def put(self, path, data, fmt_, units, expect='sanitize', date_hint='dmy', encoding='utf-8'):
        if isinstance(data, str):
            data = data.encode('utf-16') if encoding == 'utf-16' else data.encode(encoding, errors='replace')
        self.raw[path] = data
        self.files[path] = {'path': path, 'format': fmt_, 'encoding': encoding, 'expect': expect, 'date_hint': date_hint,
                            'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
                            'units': {u.loc: u.as_dict() for u in units}}

    @staticmethod
    def table(header, rows, delim=','):
        out = io.StringIO()
        w = csv.writer(out, delimiter=delim, lineterminator='\r\n')
        w.writerow(header)
        w.writerows(rows)
        return out.getvalue()

    # ---- obfuscation of one identifier surface
    def obf_phone(self, n):
        k = self.r.randrange(9)
        if k == 0:
            return f'+91 {n[:5]} {n[5:]}', None
        if k == 1:
            return f'091-{n[:3]}-{n[3:6]}-{n[6:]}', None
        if k == 2:
            return '\u200b'.join([n[:5], n[5:]]), 'zero_width'
        if k == 3:
            return deva_digits(n), 'devanagari_digits'
        if k == 4:
            return ''.join(chr(0xFF10 + int(c)) for c in n), 'fullwidth_digits'
        if k == 5:
            return ' '.join(n), 'spaced_digits'
        if k == 6:
            return ' '.join(HINGLISH_NUM[int(c)] for c in n), 'number_words_hinglish'
        if k == 7:
            return f'({n[:5]}) {n[5:]}', None
        return f'{n[:4]}.{n[4:7]}.{n[7:]}', None

    def obf_aadhaar(self, a):
        k = self.r.randrange(6)
        if k == 0:
            return f'{a[:4]} {a[4:8]} {a[8:]}', None
        if k == 1:
            return f'{a[:4]}-{a[4:8]}-{a[8:]}', None
        if k == 2:
            return deva_digits(f'{a[:4]} {a[4:8]} {a[8:]}'), 'devanagari_digits'
        if k == 3:
            return f'{a[:4]}\u00ad{a[4:8]}\u200c{a[8:]}', 'soft_hyphen_zwnj'
        if k == 4:
            return a, None
        return f'{a[:4]} {a[4:8]}\n{a[8:]}', 'line_break'

    def homoglyph(self, s):
        out = list(s)
        idx = [i for i, c in enumerate(out) if c in HOMO]
        for i in self.r.sample(idx, min(2, len(idx))):
            out[i] = HOMO[out[i]]
        return ''.join(out)

    # ---- files
    def registration(self):
        r = self.r
        # A: UTF-8 BOM CSV, every identifier type, obfuscated variants
        header = ['UHID', 'Patient Name', 'Gender', 'Age', 'DOB', 'Relation', 'Relative Name', 'Address', 'Village/Mohalla',
                  'Tehsil', 'District', 'PIN', 'Mobile', 'Aadhaar No', 'ABHA No', 'ABHA Address', 'PAN', 'Voter ID', 'Reg Date']
        rows, units = [], []
        for p in [p for p in self.patients if 'A' in p['hosp']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            name = p['name'] if r.random() > 0.15 else self.homoglyph(p['name'])
            ph, ph_o = self.obf_phone(p['phone'])
            aa, aa_o = self.obf_aadhaar(p['aadhaar'])
            age = '12 din' if p.get('newborn') else str(p['age'])
            abha_addr = f"{p['given'][0].split()[0].lower()}{p['house']}@abdm"
            reg = (p['stays'][0][1] if p['stays'] else date(2026, 3, 1)) - timedelta(days=2)
            rows.append([u.ent('MRN', p['uhid']['A']), u.ent('PATIENT_NAME', name, key=tokens(p['name']), obf='homoglyph' if name != p['name'] else None),
                         p['gender'], age, u.ent('DOB', fmt(p['dob'], 'dmy'), key=p['dob'].isoformat()), p['rel'],
                         u.ent('RELATIVE_NAME', p['relname'], person_role='relative'),
                         f"C/O {u.ent('RELATIVE_NAME', p['relname'], person_role='relative')}, {u.ent('HOUSE', 'H.No. %s' % p['house'])}, "
                         f"{u.ent('LOCALITY', 'Mohalla Purani Bazar')}, {u.ent('LANDMARK', 'near Hanuman Mandir')}",
                         u.ent('VILLAGE', p['village'][0]), 'Lalganj', u.keep('district', p['district'][0]),
                         u.ent('PIN', p['pin']), u.ent('PHONE', ph, key=p['phone'], obf=ph_o),
                         u.ent('AADHAAR', aa, key=p['aadhaar'], obf=aa_o),
                         u.ent('ABHA_NUMBER', f"{p['abha'][:2]}-{p['abha'][2:6]}-{p['abha'][6:10]}-{p['abha'][10:]}", key=p['abha']),
                         u.ent('ABHA_ADDRESS', abha_addr), u.ent('PAN', p['pan']), u.ent('VOTER_ID', p['epic']),
                         u.date('registration', reg, fmt(reg, 'dmy'))])
            u.field('age', p['age']), u.field('dob', p['dob'].isoformat())
            units.append(u)
        self.put('registration/sanjivani_registration.csv', '\ufeff' + self.table(header, rows), 'csv', units)
        # A duplicate copy with a PII-free name (same content, different file)
        self.put('registration/sanjivani_registration (copy).csv', self.raw['registration/sanjivani_registration.csv'], 'csv',
                 [Unit(**{'loc': k, 'patient': v['patient']}) for k, v in []] or units)

        # B: UTF-16 TSV, Devanagari headers, names and Hindi-month dates
        header = ['पंजीकरण सं.', 'नाम', 'लिंग', 'उम्र', 'जन्म तिथि', 'पिता/पति का नाम', 'पता', 'गाँव', 'जिला', 'पिन कोड', 'मोबाइल', 'आधार', 'पंजीकरण तिथि']
        rows, units = [], []
        for p in [p for p in self.patients if 'B' in p['hosp']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            deva = p['group'] != 'south' and r.random() < 0.8
            script = 'deva' if deva else 'latin'
            reg = date(2026, 1, 5) + timedelta(days=r.randint(0, 200))
            rows.append([u.ent('MRN', p['uhid']['B']), u.ent('PATIENT_NAME', p['deva'] if deva else p['name'], script),
                         'पुरुष' if p['gender'] == 'M' else 'महिला', deva_digits(str(p['age'])) if deva else str(p['age']),
                         u.ent('DOB', fmt(p['dob'], 'hindi'), 'deva', key=p['dob'].isoformat()),
                         ('पति ' if p['rel'] == 'W/o' else 'पिता ') + u.ent('RELATIVE_NAME', p['reldeva'] if deva else p['relname'], script, person_role='relative'),
                         u.ent('HOUSE', f"मकान नं. {deva_digits(str(p['house']))}", 'deva', key=f"मकान नं. {p['house']}"),
                         u.ent('VILLAGE', p['village'][1] if deva else p['village'][0], script), u.keep('district', p['district'][1]),
                         u.ent('PIN', deva_digits(p['pin']) if deva else p['pin'], key=p['pin']),
                         u.ent('PHONE', deva_digits(p['phone']), 'deva', key=p['phone'], obf='devanagari_digits'),
                         u.ent('AADHAAR', deva_digits(p['aadhaar']), 'deva', key=p['aadhaar'], obf='devanagari_digits'),
                         u.date('registration', reg, fmt(reg, 'hindi'))])
            units.append(u)
        self.put('registration/jan_kalyan_रोगी_सूची.tsv', self.table(header, rows, '\t'), 'tsv', units, encoding='utf-16', date_hint='hindi')

        # C: cp1252 legacy, MM/DD/YYYY (ambiguous days <= 12), split names, multi-line notes, maiden name
        header = ['PatientID', 'LastName', 'FirstName', 'Sex', 'DOB (MM/DD/YYYY)', 'Guardian', 'Street', 'City', 'District', 'Zip', 'Phone', 'Notes']
        rows, units = [], []
        for p in [p for p in self.patients if 'C' in p['hosp']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            first, last = (p['maiden'].split(' ', 1) if p.get('maiden') else (p['given'][0], p['sur'][0] or '-'))
            note = r.choice(['Pt allergic to sulfa drugs.\nOld card merged - verify identity.', 'Temp 101.2°F on arrival – sent to emergency.',
                             'Known case of HTN; on Ramipril 5 mg 1-0-0.', 'C/O fever x 3 days. H/O TB 5 yrs back.'])
            rows.append([u.ent('MRN', p['uhid']['C']), u.ent('PATIENT_NAME', last.upper()), u.ent('PATIENT_NAME', first.upper()),
                         p['gender'], u.ent('DOB', fmt(p['dob'], 'mdy'), key=p['dob'].isoformat()),
                         f"{p['rel'].upper()} {u.ent('RELATIVE_NAME', p['relname'].upper(), person_role='relative')}",
                         u.ent('HOUSE', f"H.No. {p['house']}"), u.ent('VILLAGE', p['village'][0]), u.keep('district', p['district'][0]),
                         u.ent('PIN', p['pin']), u.ent('PHONE', f"{p['phone'][:5]}-{p['phone'][5:]}", key=p['phone']),
                         u.keep('history', note.split('.')[0]) and note])
            if p.get('maiden'):
                u.tags.append('married_name_change')
            units.append(u)
        self.put('registration/arogya_legacy_export.csv', self.table(header, rows), 'csv', units, encoding='cp1252', date_hint='mdy')

        # D: nested JSON, Aadhaar stored as a JSON number under a misspelled key, PII in export metadata
        clerk = self.person(999999)
        recs, units = [], []
        for p in [p for p in self.patients if 'D' in p['hosp']]:
            u = Unit(f'/patients_list/{len(recs)}', p['pt'])
            rec = {'regn': u.ent('MRN', p['uhid']['D']),
                   'naam': {'first': u.ent('PATIENT_NAME', p['given'][0]), 'last': u.ent('PATIENT_NAME', p['sur'][0]) if p['sur'][0] else ''},
                   'umar': p['age'], 'ling': p['gender'], 'janm_tithi': u.ent('DOB', p['dob'].isoformat(), key=p['dob'].isoformat()),
                   'abhibhavak': {'rishta': p['rel'], 'naam': u.ent('RELATIVE_NAME', p['relname'], person_role='relative')},
                   'pata': {'gram': u.ent('VILLAGE', p['village'][0]), 'jila': u.keep('district', p['district'][0]), 'pin': int(p['pin'])},
                   'adhar_no': int(p['aadhaar']), 'mob': u.ent('PHONE', f"+91{p['phone']}", key=p['phone'])}
            u.ent('PIN', p['pin'])
            u.ent('AADHAAR', p['aadhaar'], obf='json_number')
            if p['email']:
                fw = self.r.random() < 0.5
                rec['email'] = u.ent('EMAIL', p['email'].replace('@', '\uff20') if fw else p['email'], key=p['email'], obf='fullwidth_at' if fw else None)
            recs.append(rec)
            units.append(u)
        meta = Unit('@file')
        payload = {'export_meta': {'system': 'eHospital v3', 'exported_by': meta.ent('STAFF_NAME', clerk['name'], channel='metadata', person_role='staff'),
                                   'source_path': f"C:/Users/{meta.ent('STAFF_NAME', clerk['given'][0], channel='metadata', person_role='staff')}/exports/dhh.json",
                                   'generated_at': '2026-11-19T18:00:00+05:30'},
                   'patients_list': recs}
        self.put('registration/dhh_patients.json', json.dumps(payload, ensure_ascii=False, indent=2), 'json', units + [meta])

        # E: South Indian initials-first names, single names, semicolon-free but quoted commas
        header = ['Card No', 'Name (Initial. Name)', 'Age / Sex', 'Father / Husband', 'Area', 'Phone No']
        rows, units = [], []
        for p in [p for p in self.patients if 'E' in p['hosp']]:
            u = Unit(f'row:{len(rows)}', p['pt'])
            rows.append([u.ent('MRN', p['uhid']['E']), u.ent('PATIENT_NAME', p['name']), f"{p['age']} / {p['gender']}",
                         u.ent('RELATIVE_NAME', p['relname'], person_role='relative'),
                         f"{u.ent('HOUSE', 'No. %s' % p['house'])}, {u.ent('LOCALITY', '2nd Cross, Gandhi Street')}, {u.keep('district', p['district'][0])}",
                         u.ent('PHONE', f"0{p['phone']}", key=p['phone'])])
            units.append(u)
        self.put('registration/sri_venkateswara_cards.csv', self.table(header, rows), 'csv', units)

    def discharge(self):
        r = self.r
        k = 0
        for p in self.patients:
            for h, start, end in p['stays']:
                k += 1
                u = Unit('doc', p['pt'])
                med = r.choice(MEDS)
                doc_given = p['relg'][0] if r.random() < 0.25 else r.choice(['Ramesh', 'Kavya', 'Imran', 'Sunita'])
                doctor = f'Dr. {doc_given} Shrivastava'
                if doc_given == p['relg'][0]:
                    u.tags.append('doctor_same_name_as_relative')
                style = r.choice(['dmy', 'dash', 'dot2', 'mon', 'ord', 'long', 'iso'])
                dx = p['dx']
                if h == 'B' and p['group'] != 'south':
                    text = (f"{HOSP[h][0]}, {HOSP[h][1]}\nडिस्चार्ज सारांश\n\n"
                            f"मरीज़ का नाम: {u.ent('PATIENT_NAME', p['deva'], 'deva')}    आयु: {deva_digits(str(p['age']))} वर्ष\n"
                            f"{'पति' if p['rel'] == 'W/o' else 'पिता'} का नाम: {u.ent('RELATIVE_NAME', p['reldeva'], 'deva', person_role='relative')}\n"
                            f"पंजीकरण सं.: {u.ent('MRN', p['uhid'][h])}\n"
                            f"पता: ग्राम {u.ent('VILLAGE', p['village'][1], 'deva')}, जिला {u.keep('district', p['district'][1])} - {u.ent('PIN', deva_digits(p['pin']), key=p['pin'])}\n"
                            f"मोबाइल: {u.ent('PHONE', deva_digits(p['phone']), 'deva', key=p['phone'], obf='devanagari_digits')}\n"
                            f"भर्ती की तारीख: {u.date('admission', start, fmt(start, 'hindi'), 'भर्ती की तारीख:')}\n"
                            f"छुट्टी की तारीख: {u.date('discharge', end, fmt(end, 'hindi'), 'छुट्टी की तारीख:')}\n\n"
                            f"निदान: {u.keep('diagnosis', dx[2])} ({u.keep('diagnosis_code', dx[1])})\n"
                            f"{u.keep('vital', 'BP 150/90')} mmHg, {u.keep('lab', 'Haemoglobin 9.6 g/dL')}\n"
                            f"दवा: Tab {u.keep('medication', med[0] + ' ' + med[1])} {u.keep('frequency', med[2])}\n"
                            f"{u.keep('doctor', doctor, 'doctor')}\n")
                else:
                    label = r.choice(['Patient Name', 'Name of Patient', "Patient's Name", 'Pt.', 'Naam', 'NAME'])
                    who = p['name'] if r.random() > 0.3 else self.variant(p)
                    if p.get('suffix'):
                        who = f"{who} {p['suffix']}"
                    if p.get('newborn'):
                        who = f"Baby of {p['relname'].split()[0]}"
                    nick = NICK.get(p['given'][0])
                    dob_line = f"DOB: {u.ent('DOB', fmt(p['dob'], style), key=p['dob'].isoformat())}\n" if r.random() < 0.6 else ''
                    age_s = '12 days' if p.get('newborn') else f"{p['age']} Yrs/{p['gender']}"
                    text = (f"{HOSP[h][0].upper()}, {HOSP[h][1].upper()}\nDISCHARGE SUMMARY\n\n"
                            f"{label}: {u.ent('PATIENT_NAME', who.upper() if label == 'NAME' else who, key=tokens(who))}"
                            + (f" (alias {u.ent('PATIENT_NAME', nick)})" if nick and r.random() < 0.5 else '')
                            + f"   Age/Sex: {age_s}\n"
                            f"{p['rel']} {u.ent('RELATIVE_NAME', ('Late ' if r.random() < 0.1 else '') + p['relname'], person_role='relative', key=tokens(p['relname']))}\n"
                            f"UHID: {u.ent('MRN', p['uhid'][h])}   IPD No: {u.ent('MRN', f'IP/{start.year % 100}/{r.randint(10000, 99999)}')}\n"
                            f"Address: {u.ent('HOUSE', 'Makan No. %s' % p['house'])}, Gram {u.ent('VILLAGE', p['village'][0])}, "
                            f"Distt. {u.keep('district', p['district'][0])} - {u.ent('PIN', p['pin'])}\n"
                            f"Mobile: {u.ent('PHONE', *self.obf_phone(p['phone'])[:1], key=p['phone'])}\n{dob_line}"
                            f"Consultant: {u.keep('doctor', doctor, 'doctor')} (MD Medicine)\n"
                            f"Ward/Bed: {u.keep('ward', 'Ward 7 (Medicine)', 'hospital-ward')} / Bed {r.randint(1, 30)}\n"
                            f"Date of Admission: {u.date('admission', start, fmt(start, style), 'Date of Admission:')}\n"
                            f"Date of Discharge: {u.date('discharge', end, fmt(end, style), 'Date of Discharge:')}\n\n"
                            f"Diagnosis: {u.keep('diagnosis', dx[0])} ({u.keep('diagnosis_code', dx[1])})\n"
                            f"Presenting complaints: {u.keep('complaint', 'C/O fever for 3 days', 'c/o-complaint')}, "
                            f"{u.keep('history', 'K/C/O DM2', 'k/c/o')}, {u.keep('history', 'H/O TB 9 yrs back', 'h/o')}.\n"
                            f"Course: {u.keep('vital', 'BP 126/86 mmHg')}, {u.keep('vital', 'SpO2 94%')}, {u.keep('vital', 'Temp 101.2 F')}. "
                            f"{u.keep('lab', 'Platelet count 150000 /cumm')}. {u.keep('lab', 'Serum Creatinine 2.0 mg/dL')}.\n"
                            f"{u.ent('PATIENT_NAME', p['given'][0].split()[-1], 'hinglish')} ji ki condition ab stable hai. "
                            f"{u.keep('context', 'ASHA worker', 'asha')} ko inform kiya.\n"
                            f"Medications: Tab {u.keep('medication', med[0] + ' ' + med[1])} {u.keep('frequency', med[2], '1-0-1')}; "
                            f"{u.keep('dose', 'Dolo 650 BD x 5 days', 'dose')}\n"
                            f"Attendant: {u.ent('RELATIVE_NAME', p['relg'][0], person_role='relative')} (C/O), Mob. {u.ent('PHONE', p['phone'])}\n")
                for d in u.dates:
                    pass
                u.field('age', p['age'])
                if r.random() < 0.35 and p['group'] != 'south':
                    fname = f"Discharge_Summary_{p['given'][0].replace(' ', '_')}_{p['sur'][0]}_{p['uhid'][h].replace('/', '-')}.txt"
                    u.ent('PATIENT_NAME', f"{p['given'][0].replace(' ', '_')}_{p['sur'][0]}", channel='filename', key=tokens(p['name']))
                elif r.random() < 0.15 and p['group'] != 'south':
                    fname = f"डिस्चार्ज_{p['deva'].replace(' ', '_')}.txt"
                    u.ent('PATIENT_NAME', p['deva'].replace(' ', '_'), 'deva', channel='filename', key=tokens(p['deva']))
                else:
                    fname = f'ds_{k:04d}.txt'
                self.put(f'discharge/{fname}', text, 'text', [u], date_hint=style)

    def notes(self):
        r = self.r
        k = 0
        for p in self.patients:
            for h, start, end in p['stays']:
                if r.random() > 0.45:
                    continue
                k += 1
                u = Unit('doc', p['pt'])
                hon = r.choice(['ji', 'sahab', 'didi', 'bhaiya', 'behenji', 'amma'])
                first = p['given'][0].split()[-1]
                ph, o = self.obf_phone(p['phone'])
                t = (f"NURSING NOTES - Ward 3, Bed {r.randint(1, 20)} - {u.ent('MRN', p['uhid'][h])}\n\n"
                     f"{u.date('note', start, fmt(start, 'dmy'))} 22:00 - {u.ent('PATIENT_NAME', first, 'hinglish')} {hon} ka "
                     f"{u.keep('vital', 'BP 117/82')}, pulse 106. Bukhar 103 F. {u.keep('medication', 'Paracetamol 650 mg')} diya.\n"
                     f"Subah 06:00 - patient ne raat theek se neend li. {u.keep('lab', 'RBS 145 mg/dL')}.\n"
                     f"Attendant ({p['rel']} {u.ent('RELATIVE_NAME', p['relg'][0], 'hinglish', person_role='relative')}) ka number "
                     f"{u.ent('PHONE', ph, 'hinglish', key=p['phone'], obf=o)} — unhe diet samjhayi.\n")
                self.put(f'notes/nursing_{k:04d}.txt', t, 'text', [u])
        # newborn twins: "B/O <mother> (Twin 1/2)", same DOB, same mother: never merge them
        mom = self.r.choice([p for p in self.pop if p['gender'] == 'F' and 20 <= p['age'] <= 35])
        born = date(2026, 10, 21)
        twins = []
        for t in (1, 2):
            baby = self.person(800000 + t, group=mom['group'], gender=self.r.choice('MF'), age=0)
            baby.update(pt=f'HTNB{t}', rid=f'UPRNB{t:05d}', dob=born, village=mom['village'], district=mom['district'],
                        pin=mom['pin'], phone=mom['phone'], hosp=['A'], uhid={'A': self.uhid('A')}, stays=[], dx=COMMON[0])
            self.patients.append(baby)
            self.pop.append(baby)
            twins.append(baby)
            u = Unit('doc', baby['pt'], ['newborn_twin'])
            u.link = 'ambiguous'
            t_txt = (f"NICU NOTE\nName: B/O {u.ent('RELATIVE_NAME', mom['name'], person_role='mother', key=tokens(mom['name']))} (Twin {t})\n"
                     f"UHID: {u.ent('MRN', baby['uhid']['A'])}  DOB: {u.ent('DOB', fmt(born, 'dmy'), key=born.isoformat())}  Wt {2.1 + t / 10:.1f} kg\n"
                     f"Born on Diwali ke din, 2 din NICU. {u.keep('vital', 'SpO2 95%')}. {u.keep('medication', 'Vitamin K 1 mg IM')} given.\n"
                     f"Mother's mobile: {u.ent('PHONE', mom['phone'], person_role='mother')}\n")
            self.put(f'notes/nicu_bo_twin_{t}.txt', t_txt, 'text', [u])
        self.traps['newborn'].append([b['pt'] for b in twins])
        # fragmented identity: first name + husband's first name + a date
        for j, p in enumerate([p for p in self.patients if p['rel'] == 'W/o' and p['stays']][:8]):
            u = Unit('doc', p['pt'], ['fragmented'])
            uniq = sum((q['given'], q['relg']) == (p['given'], p['relg']) for q in self.patients) == 1
            u.link = 'required' if uniq else 'ambiguous'
            self.traps['fragmented'].append(p['pt'])
            h, s, e = p['stays'][0]
            t = (f"Discharge note\n\n{u.ent('PATIENT_NAME', p['given'][0].split()[-1])}, W/o {u.ent('RELATIVE_NAME', p['relg'][0], person_role='relative')}, "
                 f"discharged in stable condition.\nVisit: {u.date('discharge', e, '%d %s' % (e.day, e.strftime('%B')))}\n"
                 f"Treated for {u.keep('diagnosis', p['dx'][0])}. {u.keep('vital', 'BP 168/92')}. Continue {u.keep('medication', 'Amlodipine 5 mg')} {u.keep('frequency', '0-0-1', '1-0-1')}.\n")
            self.put(f'discharge/note_{j:04d}.txt', t, 'text', [u])
        # WhatsApp forwards: sender is a relative, phone in Hindi number words, relative date
        for j, p in enumerate(r.sample(self.patients, 12)):
            u = Unit('doc', p['pt'])
            words = ' '.join(HI_NUM[int(c)] for c in p['phone'])
            sender = p['relg'][0]
            t = (f"[{r.randint(1, 28):02d}/{r.randint(1, 12):02d}/26, 8:{r.randint(10, 59)} pm] {u.ent('RELATIVE_NAME', sender + ' Bhaiya', person_role='relative', key=tokens(sender))}: <attachment: report.pdf>\n"
                 f"Forwarded\n*Pathkind Labs*\nReport of {u.ent('PATIENT_NAME', p['given'][0].split()[-1] + ' ji', 'hinglish', key=tokens(p['given'][0].split()[-1]))}  "
                 f"{p['age']} Y / {p['gender']}\n{u.keep('lab', 'Haemoglobin 7.6 g/dL')} | {u.keep('lab', 'HbA1c 7.5 %')}\n"
                 f"Dr ne bola {u.keep('dose', 'Dolo 650 BD x 5 days', 'dose')} lena hai 🙏 kal se shuru, 3 din pehle bukhar tha\n"
                 f"Koi problem ho to call karo {u.ent('PHONE', words, 'deva', key=p['phone'], obf='number_words_hindi')}\n")
            u.link = 'ambiguous'
            self.put(f'lab/whatsapp_forward_{j:04d}.txt', t, 'text', [u])

    def opd(self):
        r = self.r
        visits, units = [], []
        for p in self.patients:
            if 'A' not in p['hosp'] or r.random() < 0.3:
                continue
            u = Unit(f'/visits/{len(visits)}', p['pt'])
            d = date(2026, 1, 3) + timedelta(days=r.randint(0, 300))
            med = r.choice(MEDS)
            rel_first = p['relg'][0]
            visits.append({'visit_id': f'OPD/26/{len(visits):05d}', 'patient_ref': u.ent('MRN', p['uhid']['A']),
                           'visit_date': u.date('visit', d, fmt(d, 'dmy')), 'doctor': u.keep('doctor', f'Dr. {rel_first} Tripathi', 'doctor-vs-relative'),
                           'complaints': u.keep('complaint', 'C/O headache and giddiness x 3 days', 'c/o-complaint'),
                           'history': u.keep('history', "K/C/O Parkinson's disease", 'eponym'),
                           'vitals': {'bp': '123/76', 'pulse': 69, 'spo2': 89},
                           'diagnosis': [{'code': u.keep('diagnosis_code', p['dx'][1]), 'display': u.keep('diagnosis', p['dx'][0])}],
                           'rx': [{'drug': u.keep('medication', med[0]), 'strength': med[1], 'frequency': u.keep('frequency', med[2])}],
                           'notes': f"{u.ent('PATIENT_NAME', p['given'][0].split()[-1], 'hinglish')} ka BP {u.keep('vital', 'BP 123/76')}, "
                                    f"C/O {u.ent('RELATIVE_NAME', rel_first, person_role='relative')} (bhai) saath aaye.",
                           'callback_url': 'https://opd.example/callback?name=' + u.ent('PATIENT_NAME', urllib.parse.quote(urllib.parse.quote(p['name'])) if r.random() < 0.3 else urllib.parse.quote(p['name']), channel='percent', key=tokens(p['name']), obf='percent_encoding')
                                           + '&mobile=' + u.ent('PHONE', p['phone']),
                           'patient': {'name': u.ent('PATIENT_NAME', html.escape(p['name']).replace('a', '&#97;'), key=tokens(p['name']), obf='html_entities'),
                                       'age_sex': f"{p['age']}/{p['gender']}", 'mobile': u.ent('PHONE', '+91-' + p['phone'], key=p['phone'])}})
            units.append(u)
        cu = Unit('@file')
        canary = 'Velmorra Quistane'
        self.canaries.append(canary)
        cu.ent('CANARY', canary, channel='key')
        if visits:
            visits[0][f'remarks_for_{canary}'] = 'call back tomorrow'
        self.put('opd/sanjivani_opd_2026.json', json.dumps({'_export_meta': {'system': 'eHospital OPD'}, 'visits': visits}, ensure_ascii=False, indent=1), 'json', units + [cu])
        # same file shape but \u-escaped Devanagari names (ensure_ascii)
        visits, units = [], []
        for p in [p for p in self.patients if 'B' in p['hosp'] and p['group'] != 'south'][:40]:
            u = Unit(f'/visits/{len(visits)}', p['pt'])
            d = date(2026, 2, 1) + timedelta(days=r.randint(0, 250))
            visits.append({'reg_no': u.ent('MRN', p['uhid']['B']), 'tarikh': u.date('visit', d, d.isoformat()),
                           'rogi': u.ent('PATIENT_NAME', p['deva'], 'deva', channel='unicode_escape', obf='json_u_escape'),
                           'nidan': u.keep('diagnosis', p['dx'][2])})
            units.append(u)
        self.put('opd/jan_kalyan_opd_escaped.json', json.dumps({'visits': visits}, ensure_ascii=True), 'json', units)

    def fhir(self):
        r = self.r
        k = 0
        for p in self.patients:
            for h, start, end in p['stays']:
                if r.random() > 0.3:
                    continue
                k += 1
                u = Unit('doc', p['pt'])
                pid = hashlib.md5((p['rid'] + str(start)).encode()).hexdigest()
                ids = {x: f'urn:uuid:{pid[:8]}-{pid[8:12]}-4{pid[13:16]}-a{pid[17:20]}-{x}{pid[20:31]}' for x in 'pecdrn'}
                note = f"Patient {p['name']} (mob {p['phone']}) discharged. Diagnosis: {p['dx'][0]}."
                u.ent('PATIENT_NAME', p['name'], channel='base64', key=tokens(p['name']), obf='base64')
                u.ent('PHONE', p['phone'], channel='base64', obf='base64')
                narrative = f"<div xmlns=\"http://www.w3.org/1999/xhtml\">{p['name'][:3]}\u200b{p['name'][3:]}, {p['age']}y, Ph {p['phone']}</div>"
                u.ent('PATIENT_NAME', p['name'], channel='narrative', key=tokens(p['name']), obf='zero_width')
                datauri = 'data:text/plain;base64,' + base64.b64encode(f"Consent signed by {p['relname']}".encode()).decode()
                u.ent('RELATIVE_NAME', p['relname'], channel='base64', person_role='relative', obf='data_uri')
                bundle = {'resourceType': 'Bundle', 'id': pid, 'type': 'document', 'timestamp': end.isoformat() + 'T11:00:00+05:30',
                          'meta': {'source': '#' + u.ent('MRN', p['uhid'][h], channel='metadata'),
                                   'tag': [{'system': 'urn:ward', 'code': 'w7', 'display': 'Ward 7 bed of ' + u.ent('PATIENT_NAME', p['given'][0].split()[-1], channel='metadata')}]},
                          'entry': [
                    {'fullUrl': ids['p'], 'resource': {'resourceType': 'Patient', 'id': ids['p'][9:],
                     'text': {'status': 'generated', 'div': narrative},
                     'extension': [{'url': 'http://hl7.org/fhir/StructureDefinition/patient-mothersMaidenName',
                                    'valueString': u.ent('RELATIVE_NAME', f"{r.choice(F['hindu'])[0]} {r.choice(SUR['hindu'])[0]}", channel='extension', person_role='relative')}],
                     'identifier': [{'system': 'https://ndhm.gov.in/abha', 'value': u.ent('ABHA_NUMBER', f"{p['abha'][:2]}-{p['abha'][2:6]}-{p['abha'][6:10]}-{p['abha'][10:]}", key=p['abha'])},
                                    {'system': f"https://hospital.example/mrn/{u.ent('PATIENT_NAME', p['name'].lower().replace(' ', '-').replace('.', ''), channel='identifier_system', key=tokens(p['name']))}",
                                     'value': u.ent('MRN', p['uhid'][h])}],
                     'name': [{'use': 'official', 'text': u.ent('PATIENT_NAME', p['name']), 'given': [u.ent('PATIENT_NAME', p['given'][0])]}],
                     'gender': 'male' if p['gender'] == 'M' else 'female', 'birthDate': u.ent('DOB', p['dob'].isoformat(), key=p['dob'].isoformat()),
                     'telecom': [{'system': 'phone', 'value': u.ent('PHONE', p['phone'])}],
                     'address': [{'line': [u.ent('HOUSE', f"H.No. {p['house']}")], 'city': u.ent('VILLAGE', p['village'][0]),
                                  'district': u.keep('district', p['district'][0]), 'postalCode': u.ent('PIN', p['pin'])}],
                     'contact': [{'relationship': [{'text': p['rel']}], 'name': {'text': u.ent('RELATIVE_NAME', p['relname'], person_role='relative')}}]}},
                    {'fullUrl': ids['n'][:-3] + 'abc', 'resource': {'resourceType': 'Observation', 'id': ids['n'][9:-3] + 'abc', 'status': 'final',
                     'contained': [{'resourceType': 'RelatedPerson', 'id': 'rp1', 'patient': {'reference': ids['p']},
                                    'name': [{'text': u.ent('RELATIVE_NAME', p['relname'], channel='contained', person_role='relative')}],
                                    'telecom': [{'system': 'phone', 'value': u.ent('PHONE', '+91 ' + p['phone'], channel='contained', key=p['phone'])}]}],
                     'modifierExtension': [{'url': 'https://hospital.example/fhir/informant', 'valueString': u.ent('RELATIVE_NAME', p['relg'][0], channel='modifier_extension', person_role='relative')}],
                     'text': {'status': 'additional', 'div': '<div xmlns="http://www.w3.org/1999/xhtml">Informant ' + p['relname'] + ', village ' + u.ent('VILLAGE', p['village'][0], channel='narrative') + '</div>'},
                     'code': {'coding': [{'system': 'http://loinc.org', 'code': u.keep('code', '718-7'), 'display': 'Hemoglobin'}]},
                     'subject': {'reference': ids['p']}, 'performer': [{'reference': '#rp1'}],
                     'valueQuantity': {'value': 9.6, 'unit': 'g/dL'}}},
                    {'fullUrl': ids['r'], 'resource': {'resourceType': 'Practitioner', 'id': ids['r'][9:],
                     'name': [{'text': u.keep('doctor', f"Dr. {p['relg'][0]} Mishra", 'doctor-vs-relative')}]}},
                    {'fullUrl': ids['e'], 'resource': {'resourceType': 'Encounter', 'id': ids['e'][9:], 'status': 'finished',
                     'class': {'system': 'http://terminology.hl7.org/CodeSystem/v3-ActCode', 'code': 'IMP'},
                     'subject': {'reference': ids['p'], 'display': u.ent('PATIENT_NAME', p['name'])},
                     'period': {'start': u.date('admission', start, start.isoformat() + 'T10:30:00+05:30', '"start":'),
                                'end': u.date('discharge', end, end.isoformat() + 'T12:00:00+05:30', '"end":')}}},
                    {'fullUrl': ids['c'], 'resource': {'resourceType': 'Condition', 'id': ids['c'][9:], 'subject': {'reference': ids['p']},
                     'code': {'coding': [{'system': 'http://hl7.org/fhir/sid/icd-10', 'code': u.keep('diagnosis_code', p['dx'][1]),
                                          'display': u.keep('diagnosis', p['dx'][0])}], 'text': p['dx'][0]},
                     'note': [{'authorString': u.ent('RELATIVE_NAME', p['relname'], channel='annotation', person_role='relative'), 'text': 'informed'}]}},
                    {'fullUrl': ids['d'], 'resource': {'resourceType': 'DocumentReference', 'id': ids['d'][9:], 'status': 'current',
                     'subject': {'reference': ids['p']},
                     'content': [{'attachment': {'contentType': 'text/plain', 'title': 'Summary - ' + u.ent('PATIENT_NAME', p['name'], channel='attachment_title'),
                                                 'data': base64.b64encode(note.encode()).decode()}},
                                 {'attachment': {'contentType': 'text/plain', 'url': datauri}},
                                 {'attachment': {'contentType': 'application/gzip', 'title': 'archived note',
                                                 'data': base64.b64encode(__import__('gzip').compress(note.encode(), mtime=0)).decode()}}]}},
                    {'fullUrl': ids['n'], 'resource': {'resourceType': 'Communication', 'id': ids['n'][9:], 'status': 'completed',
                     'subject': {'reference': ids['p']},
                     'payload': [{'contentString': f"Call {u.ent('RELATIVE_NAME', p['relg'][0], person_role='relative')} on {u.ent('PHONE', p['phone'])}"}]}}]}
                self.put(f'fhir/bundle_{pid[:8]}.json', json.dumps(bundle, ensure_ascii=False, indent=1), 'fhir', [u])

    def lab_billing(self):
        r = self.r
        canary = 'Zephrine Oktaval'
        self.canaries.append(canary)
        header = ['sample_id', 'patient_name', 'age_sex', 'uhid', 'ref_doctor', 'test', 'result', 'unit', 'ref_range', 'collected_on',
                  f'verified_by {canary}']
        rows, units = [], []
        for p in r.sample(self.patients, min(60, len(self.patients))):
            h = p['hosp'][0]
            d = (p['stays'][0][1] if p['stays'] else date(2026, 4, 2)) + timedelta(days=1)
            for test, val, unit_, rng in [('Platelet Count', '226001', '/uL', '150000-410000'), ('Haemoglobin', '11.2', 'g/dL', '12.0-16.0'),
                                          ('Random Blood Sugar', '182', 'mg/dL', '70-140')]:
                u = Unit(f'row:{len(rows)}', p['pt'])
                rows.append([f'S{len(rows):08d}', u.ent('PATIENT_NAME', p['name']), f"{p['age']}/{p['gender']}", u.ent('MRN', p['uhid'][h]),
                             u.keep('doctor', 'Dr. Vandana Kulshrestha', 'doctor'), u.keep('lab_test', test),
                             u.keep('lab', val, 'pin-lookalike' if val == '226001' else None), unit_, u.keep('range', rng),
                             u.date('collected', d, fmt(d, 'dmy')), 'ok'])
                units.append(u)
        cu = Unit('@header')
        cu.ent('CANARY', canary, channel='header')
        self.put('lab/city_results.csv', self.table(header, rows), 'csv', units + [cu])
        header = ['bill_no', 'uhid', 'patient_name', 'pmjay_id', 'payer_pan', 'policy_no', 'esic_no', 'package_code', 'procedure',
                  'admission_date', 'discharge_date', 'amount_inr']
        rows, units = [], []
        for p in self.patients:
            for h, start, end in p['stays']:
                u = Unit(f'row:{len(rows)}', p['pt'])
                rows.append([f'BL/26/{len(rows):06d}', u.ent('MRN', p['uhid'][h]), u.ent('PATIENT_NAME', p['name'].upper()),
                             u.ent('PMJAY_ID', f'PMJAY-UP-{r.randint(10 ** 9, 10 ** 10 - 1)}'), u.ent('PAN', p['pan']),
                             u.ent('INSURANCE_ID', f'POL/33/{r.randint(10 ** 7, 10 ** 8 - 1)}'),
                             u.ent('INSURANCE_ID', f'{r.randint(10 ** 9, 10 ** 10 - 1)}') if r.random() < 0.3 else '',
                             u.keep('package', 'MG064A'),
                             ('=HYPERLINK("https://crm.example/' + u.ent('PATIENT_NAME', p['given'][0].split()[-1], channel='formula', key=tokens(p['given'][0].split()[-1])) + '","Haemodialysis session")')
                             if r.random() < 0.1 else u.keep('procedure', 'Haemodialysis session'),
                             u.date('admission', start, fmt(start, 'dmy')), u.date('discharge', end, fmt(end, 'dmy')),
                             u.keep('amount', str(r.choice([15000, 91000, 226001, 241001])), 'pin-lookalike')])
                units.append(u)
        self.put('billing/claims.csv', self.table(header, rows), 'csv', units)

    def clean_and_misc(self):
        r = self.r
        u = Unit('doc')
        t = ('Dengue management protocol (no patient data)\n'
             f"{u.keep('eponym', PARK, 'eponym')} and {u.keep('eponym', BELL, 'eponym')} are not names.\n"
             f"{u.keep('context', 'ASHA workers', 'asha')} visit Rampur and Sitapur blocks.\n"
             f"Give {u.keep('dose', 'Dolo 650 BD x 5 days', 'dose')}; {u.keep('frequency', '1-0-1', '1-0-1')}; Ward {u.keep('ward', 'Ward 12 (Paediatrics)', 'hospital-ward')}.\n"
             f"Reviewed by {u.keep('doctor', 'Dr. Asha Verma', 'doctor')} on 12/03/2026. Call 108 for ambulance. Sample code 718-7.\n"
             f"Look-alikes that are NOT identifiers: {u.keep('code', 'SNOMED CT 234567890127', 'aadhaar-lookalike')} (passes the Aadhaar Verhoeff check), "
             f"{u.keep('batch', 'Batch ABC1234567', 'voterid-lookalike')}, {u.keep('timestamp', 'log 20260315103045', 'abha-lookalike')}, "
             f"{u.keep('lab', 'Plt 1.5 lakh', 'lakh')}, {u.keep('amount', 'Rs 2,26,001', 'pin-lookalike')}, {u.keep('code', 'LOINC 2345-7')}, "
             f"{u.keep('medication', 'Augmentin 625 Duo')}, {u.keep('package', 'HBP SG039A')}, {u.keep('vital', 'BP 120/80')}.\n"
             f"Eponyms: {u.keep('eponym', WILSON, 'eponym')}, {u.keep('eponym', KOCH, 'eponym')}, {u.keep('eponym', 'Down syndrome', 'eponym')}.\n")
        self.put('clean/dengue_protocol.txt', t, 'text', [u])
        rows, units = [], []
        for m in MEDS:
            v = Unit(f'row:{len(rows)}')
            rows.append([v.keep('medication', m[0]), v.keep('dose', m[1]), v.keep('frequency', m[2])])
            units.append(v)
        self.put('clean/formulary.csv', self.table(['drug', 'strength', 'frequency'], rows), 'csv', units)
        # canaries in hard places
        c1 = 'Qorvantha Belisk'
        self.canaries.append(c1)
        u = Unit('doc')
        u.ent('CANARY', c1, channel='filename')
        u.ent('CANARY', self.homoglyph(c1), key=tokens(c1), obf='homoglyph')
        self.put(f'misc/Referral_{c1.replace(" ", "_")}.txt', f"Referral\nPatient: {self.homoglyph(c1)}  52 Yrs/M\nMob 7000001111\n", 'text', [u])
        c2 = 'Ombriel Tasquent'
        self.canaries.append(c2)
        u = Unit('doc')
        u.ent('CANARY', c2, channel='base64', obf='base64')
        self.put('misc/scanned_consent.json', json.dumps({'document': 'consent', 'contentType': 'text/plain',
                 'data': base64.b64encode(f'Consent of {c2}, phone 7000002222'.encode()).decode()}), 'json', [u])
        c3 = 'Lumeric Dravosh'
        self.canaries.append(c3)
        u = Unit('doc')
        u.ent('CANARY', c3, channel='folder', key=tokens(c3))
        self.put(f'misc/{c3.replace(" ", "_")}_files/notes.txt', 'Follow-up sheet. Dolo 650 BD x 5 days.\n', 'text', [u])
        c4 = 'Saverin Ekhollow'
        self.canaries.append(c4)
        u = Unit('doc')
        u.ent('CANARY', c4, obf='zero_width_split', key=tokens(c4))
        self.put('misc/helpdesk_ticket.txt', f"Ticket 4411: caller {c4[:4]}\u200d{c4[4:]} asked for report copy.\n", 'text', [u])
        # malformed / unsupported (must be quarantined, never copied)
        p = self.patients[5]
        pii = f'{p["name"]}, {p["phone"]}, {p["aadhaar"]}'
        self.put('misc/truncated_export.json', '{"patients": [{"name": "' + p['name'] + '", "mobile": "' + p['phone'] + '"', 'json', [], expect='quarantine')
        deep = {'k': 'v'}
        for _ in range(1500):
            deep = {'n': deep}
        deep_s = json.dumps(deep) if False else '{"n":' * 1500 + '{"name": "' + p['name'] + '"}' + '}' * 1500
        self.put('misc/deep_export.json', deep_s, 'json', [], expect='quarantine')
        self.put('misc/nan_values.json', '{"name": "' + p['name'] + '", "spo2": NaN}', 'json', [], expect='quarantine')
        self.put('misc/duplicate_keys.json', '{"name": "' + p['name'] + '", "name": "x"}', 'json', [], expect='quarantine')
        self.put('misc/corrupt_bytes_note.txt', b'Patient ' + p['name'].encode() + b' \xff\xfe\x00\xc3\x28 ' + p['phone'].encode(), 'text', [], expect='quarantine')
        self.put('misc/empty_export.csv', b'', 'csv', [], expect='quarantine')
        self.put('misc/hl7_cda_discharge.xml', f'<ClinicalDocument><patient><name>{p["name"]}</name><telecom value="tel:{p["phone"]}"/></patient></ClinicalDocument>', 'xml', [], expect='quarantine')
        self.put('misc/scanned_report.pdf', b'%PDF-1.4\n1 0 obj<<>>stream\n' + pii.encode() + b'\nendstream\n%%EOF', 'pdf', [], expect='quarantine')
        self.put('misc/photo_rx.jpg', b'\xff\xd8\xff\xe0\x00\x10JFIF' + pii.encode() + b'\xff\xd9', 'binary', [], expect='quarantine')
        self.put('misc/mislabeled_export.csv', json.dumps({'name': p['name'], 'mobile': p['phone']}), 'json-in-csv', [], expect='quarantine')
        self.put('misc/ragged_rows.csv', f'name,mobile\n{p["name"]},{p["phone"]},extra,cells\nx\n', 'csv', [], expect='quarantine')
        self.put('misc/visits.jsonl', json.dumps({'name': p['name']}) + '\n' + json.dumps({'name': p['name']}) + '\n', 'jsonl', [], expect='quarantine')
        self.put('misc/.patient_cache.json', json.dumps({'last_patient': p['name'], 'mobile': p['phone']}), 'json',
                 [self._cache_unit(p)], expect='either')

    def _cache_unit(self, p):
        u = Unit('doc', p['pt'])
        u.ent('PATIENT_NAME', p['name'])
        u.ent('PHONE', p['phone'])
        u.link = 'ambiguous'
        return u

    def attacker(self, root):
        d = root / 'dev/attacker'
        d.mkdir(parents=True, exist_ok=True)
        with (d / 'registry.csv').open('w', encoding='utf-8', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['rid', 'name', 'relation', 'relative_name', 'gender', 'age', 'house_no', 'village', 'district', 'pin',
                        'phone', 'email', 'aadhaar_last4'])
            for p in self.pop:
                leak = self.r.random() < 0.6
                w.writerow([p['rid'], p['name'], p['rel'], p['relname'], p['gender'], p['age'], p['house'], p['village'][0],
                            p['district'][0], p['pin'], p['phone'] if leak else '', (p['email'] or '') if leak else '',
                            p['aadhaar'][-4:] if leak else ''])
        facts = []
        for p in self.r.sample([p for p in self.patients if p['stays']], max(1, len(self.patients) * 3 // 10)):
            h, s, e = p['stays'][0]
            f = {'rid': p['rid'], 'visit_dates': [s.isoformat()], 'hospital': HOSP[h][0]}
            if self.r.random() < 0.5 or p['dx'] in RARE:
                f['condition_hint'] = p['dx'][0]
            if self.r.random() < 0.4:
                f['stay_days'] = (e - s).days
            facts.append(f)
        pr = {p['rid'] for p in self.patients}
        for p in self.r.sample([x for x in self.pop if x['rid'] not in pr], 10):
            facts.append({'rid': p['rid'], 'visit_dates': ['2026-07-14'], 'hospital': HOSP['A'][0], 'decoy': True})
        self.r.shuffle(facts)
        (d / 'known_facts.jsonl').write_text(''.join(json.dumps({k: v for k, v in f.items() if k != 'decoy'}) + '\n' for f in facts), encoding='utf-8')

    def write(self, root: Path):
        for path, data in self.raw.items():
            f = root / 'dev/input' / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        truth = {'schema': 'raksha-truth/1', 'generator': 'secret-wards-hardest-test/1.0', 'ref_date': REF.isoformat(),
                 'files': self.files, 'patients': {p['pt']: {'rid': p['rid']} for p in self.patients},
                 'traps': self.traps, 'canaries': self.canaries}
        (root / 'dev/truth').mkdir(parents=True, exist_ok=True)
        (root / 'dev/truth/truth.json').write_text(json.dumps(truth, ensure_ascii=False, default=str, indent=1), encoding='utf-8')
        self.attacker(root)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--seed', type=int, default=2026)
    ap.add_argument('--patients', type=int, default=200)
    a = ap.parse_args()
    if a.out.exists() and any(a.out.iterdir()):
        ap.error('--out must be a new or empty folder')
    if a.patients < 20:
        ap.error('--patients must be at least 20 (the traps need enough people)')
    g = Gen(a.seed, a.patients)
    g.build()
    g.registration()
    g.discharge()
    g.notes()
    g.opd()
    g.fhir()
    g.lab_billing()
    g.clean_and_misc()
    g.write(a.out)
    units = sum(len(f['units']) for f in g.files.values())
    ents = sum(len(u['entities']) for f in g.files.values() for u in f['units'].values())
    print(f'{len(g.files)} files, {units} records, {ents} PII mentions, {len(g.patients)} patients, '
          f'{len(g.pop)} people in registry, {len(g.canaries)} canaries -> {a.out}')


if __name__ == '__main__':
    main()
