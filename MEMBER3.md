# Member 3: linkage, pseudonyms, privacy layer and red-team

| File | Role |
|---|---|
| `linker.py` | Devanagari→Latin transliteration, name folding, Jaro-Winkler, blocking, scoring, conflict-safe clustering |
| `privacy.py` | HMAC pseudonyms, per-patient date shifts, age/DOB bands, PIN generalisation, risk levels |
| `team_processor.py` | The final `Processor(secret)` the runner loads: observe → finish → clean |
| `config/privacy.json` | Tunable privacy rules (band widths, shift range, k thresholds) |
| `test_member3.py` | Unit and end-to-end tests with planted fictional canaries |
| `test_attacker.py` | Development-only red-team harness against the practice kit (never imported at runtime) |
| `contract_check.py` | The kit's output-format rules plus stricter honesty checks (`CONTRACT OK`) |
| `docs/make_brief.py` | Regenerates `Project_Brief.pdf` (needs `reportlab`, dev only) |

## Linkage

Each record becomes evidence: labelled patient names (labels, name columns and FHIR
Patient outrank names in narrative), relatives (S/o, W/o, `pati ka naam`, FHIR contact),
UHID/IPD/Aadhaar/ABHA/PAN/email, phone, DOB, age with the record's latest event year,
gender, village tokens and ICD codes. Masked Aadhaar suffixes are ignored.

Names are transliterated (schwa-aware), honorifics dropped, variants folded
(Mohd/Md./Mohammad, Laxmi/Lakshmi, aa/a, ph/f, au/ou) and compared token-by-token
with Jaro-Winkler, independent of order. Generic particles (Kumar, Devi, Bano, Md.)
never identify anyone on their own.

Pairs are compared only inside blocks (shared identifier, phone or phonetic name key).
Weights: shared ID 10, phone 5, full name 5, partial name 3, relative 4, DOB 4,
village 2, compatible age 1; disagreeing national IDs −6, conflicting names cap the
score below the threshold of 7. Vetoes: gender, DOB, birth year (>2 years) and
conflicting full names. Clusters merge greedily by score, and a merge is refused when
the merged cluster would contain a conflict, so A~B and B~C never drags in a different C.
Records with only a first name and no second clue stay `patient: null`.

## Privacy layer

* Pseudonym: `PSN-` + 8 characters of HMAC-SHA256(secret, cluster evidence). It replaces
  the patient's name (including spelling variants found by the patient-aware sweep) and
  reference IDs inside the record, so the claim in records.jsonl is visible in the data.
* Dates: shifted by HMAC-derived ±20–200 days per patient (per record when unlinked), in
  the original layout (DMY, MDY, ISO, `15 May 2026`, timestamps). Month-first files are
  detected from unambiguous dates in the same file.
* Age: 10-year bands, 85+ top-coded; DOB becomes a birth-decade band (FHIR `birthDate`
  gets the shifted date so the bundle stays valid).
* Location: village/house/locality removed, district kept, PIN → 3-digit prefix.
* Adaptive generalisation: for each patient we estimate how many people in the
  attacker's voter registry share the released cell,
  `4 × patients(district) × share(gender) × share(age band)`, and widen until it is at
  least 5: first a 20-year band (PIN removed), then no district. At that level district
  names are also masked in letterheads ("Hospital, Barabanki").
* Rare diagnosis (ICD code held by < 3 patients): coarsest level. If only one patient has
  it, the disease *name* is replaced by its ICD-10 chapter ("rare condition (ICD-10 ch. I:
  infectious) (A82.9)"); the exact code stays for statistics.

Measured on practice data with `test_attacker.py` (district, gender, age band, PIN
prefix filters, the order the kit's ATTACKS.md documents):

| Policy | Profiles re-identified (≥ 0.5) | Records re-identified | Districts lost |
|---|---|---|---|
| Raw input | 10 / 48 | 11 / 746 | – |
| Fixed 5-year bands | 9 / 50 | – | 3 |
| Fixed 10-year bands | 5 / 50 | 4 / 746 | 3 |
| Adaptive (current) | **0 / 48** | **0 / 746** | 47 / 93 |

Targeted attack (ATTACKS.md A5: known visit date, hospital, condition, stay length,
global-shift recovery): 4 of 14 known people at ≥ 0.5 (raw input 2 of 14), 0 decoys
claimed, no global shift recoverable. The remaining hits come from exact stay lengths and
condition + demographics; removing every hospital name only moved the mean 0.24 → 0.23.

Kit self-check (`check_dev.py` rules, ported as `kit_selfcheck` in `test_attacker.py`):
0 of 3,230 personal-data pieces visible on the practice set and on the unseen-format copy,
0 of 4 canaries, 0 raw copies, 4,787 of 4,855 medical values kept (all 68 lost are the
deliberate privacy generalisations above).

Hidden-style test (`tools/make_hidden_dataset.py`, two seeds): 496 files, 270 new patients,
four hospital systems with formats never seen before (`Pt. Name`/`Contact No.` labels, UTF-16
TSV with Devanagari headers, `{"meta", "records"}` JSON, `dd-Mon-yyyy` and `dd.mm.yyyy`
dates, `AGH0001081` IDs, `(73036) 71330` phones, canaries in a header, a JSON key, a file
name and a base64 attachment). First run of the unchanged system: 92% of personal data
removed, linkage recall 65-68%, 2 of 4 canaries leaked. After the fixes in this repo:

| Measure | Hidden set A | Hidden set B |
|---|---|---|
| Personal data visible (kit self-check rules) | 0 / 3,808 | 0 / 4,445 |
| Canaries | 0 / 4 | 0 / 4 |
| Linkage precision / recall | 1.000 / 1.000 | 1.000 / 1.000 |
| Stay lengths exact after shifting | 112 / 112 | 134 / 134 |
| Voter-list attack: records / pooled profiles (raw) | 0 / 2 (198 / 60) | 0 / 0 (242 / 80) |
| Targeted attack (raw) | 18 / 36 (6) | 24 / 45 (12) |
| Medical values kept | 100% (2,563 / 2,563) | 100% (2,932 / 2,932) |

Fixes: separator-less hospital numbers, `{"meta", "records"}` JSON split per record,
`dd-Mon-yyyy` dates, Hindi `पिन कोड`/`गाँव` headers, bracketed phones, names written
into headers/keys, kinship honorifics (bhaiya, chacha ...), chat senders and attendants
never taken as the patient, weak notes linked only when exactly one patient fits,
ड़/ढ़ transliterated as r/rh, districts read from free-text addresses for the risk estimate,
ages like "16 Y/M", diagnosis phrases protected from name guessing, and a new ladder that
widens the age (10-year, 20-year, then "18+"/"0-17") instead of removing the district, so
every district and disease name survives. `max_level: 3` in `config/privacy.json` restores
district removal for the rarest patients (stricter privacy, about 1% fewer medical values).

Unseen-format check: a copy of the practice set with renamed CSV headers and JSON keys,
reworded note labels, `dd.mm.yyyy` dates and UPPERCASE names gives linkage 1.000 / 1.000,
zero identifier/village leaks, 23/23 intervals and a clean contract check.

## Reproduce

```sh
python3 -m unittest -q
RAKSHA_SECRET=practice python3 main.py --input KIT/dev/input --output out
python3 contract_check.py --input KIT/dev/input --output out
python3 test_attacker.py --kit KIT --output out
python3 test_attacker.py --kit KIT --scale 6
```

`test_attacker.py` prints aggregate counts only. Also fixed while integrating: JSON
deeper than 60 levels is quarantined (it used to crash the run on newer Pythons),
any `{"meta": ..., "<records>": [...]}` export gets per-record locators, and the
detector no longer reads temperatures such as `Bukhar 103 F` as "age 103, female",
Hindi labels with a nukta (मरीज़) no longer leave a stray `[PERSON]`, and Hindi headings
such as डिस्चार्ज सारांश are no longer guessed to be names.
