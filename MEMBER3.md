# Member 3: linkage, pseudonyms, privacy layer and red-team

| File | Role |
|---|---|
| `linker.py` | Devanagari→Latin transliteration, name folding, Jaro-Winkler, blocking, scoring, conflict-safe clustering |
| `privacy.py` | HMAC pseudonyms, per-patient date shifts, age/DOB bands, PIN generalisation, risk levels |
| `team_processor.py` | The final `Processor(secret)` the runner loads: observe → finish → clean |
| `config/privacy.json` | Tunable privacy rules (band widths, shift range, k thresholds) |
| `test_member3.py` | Unit and end-to-end tests with planted fictional canaries |
| `test_attacker.py` | Development-only red-team harness against the practice kit (never imported at runtime) |
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
* Rare diagnosis (ICD code held by < 3 patients): 20-year band, no district, no PIN.

Measured trade-off on practice data: 5-year bands left 9/50 profiles re-identifiable in
the registry attack; 10-year bands 4/50 (mean true-person probability 0.21 → 0.16).

## Reproduce

```sh
python3 -m unittest -q
RAKSHA_SECRET=practice python3 main.py --input KIT/dev/input --output out
python3 test_attacker.py --kit KIT --output out
python3 test_attacker.py --kit KIT --scale 6
```

`test_attacker.py` prints aggregate counts only. Also fixed while integrating: JSON
deeper than 60 levels is quarantined (it used to crash the run on newer Pythons),
any `{"meta": ..., "<records>": [...]}` export gets per-record locators, and the
detector no longer reads temperatures such as `Bukhar 103 F` as "age 103, female".
