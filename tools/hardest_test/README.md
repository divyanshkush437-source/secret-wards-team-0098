# Secret Wards — Hardest Test Kit (Track 3)

A synthetic, adversarial test set for Indian hospital-record de-identification
pipelines, with its own answer key and a stand-alone scorer. Python 3.9+,
standard library only. Everything is synthetic; no real person is described.

## Contents
| Path | What |
|---|---|
| `data/hardest_A/` | not committed; make it with the command below (391 files, 202 patients, 9,691 PII mentions, seed 2026) |
| `data/hardest_B/` | not committed (562 files, 302 patients, 13,751 PII mentions, seed 4242) |
| `generate.py` | make more sets: `python3 generate.py --out my_set --seed 7 --patients 400` |
| `score.py` | score your output against the answer key |
| `baselines.py` | copy-everything and delete-everything reference releases |
| `../../docs/RESEARCH_HARDEST_TESTS.md` | the research behind the traps |

Each set uses the official kit layout: `dev/input/` (give this to your system),
`dev/truth/truth.json` (answers), `dev/attacker/registry.csv`, `dev/attacker/known_facts.jsonl`.

## Use
The datasets are generated, not stored in the repo. From the repo root:
```sh
python3 tools/hardest_test/generate.py --out data/hardest_A --seed 2026 --patients 200
python3 tools/hardest_test/generate.py --out data/hardest_B --seed 4242 --patients 300
```
Then (paths relative to this folder):
```sh
RAKSHA_SECRET=s1 python3 main.py --input data/hardest_A/dev/input --output run1
RAKSHA_SECRET=s1 python3 main.py --input data/hardest_A/dev/input --output run2
RAKSHA_SECRET=s2 python3 main.py --input data/hardest_A/dev/input --output run3
python3 score.py --data data/hardest_A --output run1 --output2 run2 --output-other run3 --show 25 --json score.json
```
Never feed `dev/truth` or `dev/attacker` to your system.

## What is hard in here
- **Identifiers:** Verhoeff-valid Aadhaar written 6 ways (spaces, hyphens, Devanagari digits, soft hyphen + ZWNJ, line break, JSON number), ABHA number and ABHA address, PAN, voter ID, PMJAY, ESIC, policy numbers, 5 hospital ID styles; phones in 9 forms incl. zero-width, fullwidth, spaced and Hindi/Hinglish number words.
- **Look-alikes that must be kept:** SNOMED code passing the Aadhaar checksum, voter-ID-shaped batch numbers, ABHA-shaped timestamps, platelet counts and amounts equal to PIN codes, `Dolo 650`, `1-0-1`, LOINC/ICD/package codes, eponyms (Parkinson's, Bell's, Wilson's, Koch's), "ASHA worker", doctors who share a relative's first name, `C/O fever` vs `C/O <name>`, K/C/O, H/O.
- **Names:** Hindu/Muslim/Sikh/South-Indian initials-first names, spelling variants (Shrivastava/Srivastava, Lakshmi/Laxmi, v/b swaps), nicknames, names that are words (Asha, Kiran, Ganga), surnames Bell/Parkash, Devanagari, homoglyphs, `Baby of`, `Late`, Jr/Sr.
- **Hiding places:** file and folder names (incl. Devanagari), CSV headers, JSON keys, export metadata, FHIR narrative, extensions, modifierExtension, contained resources, identifier.system URLs, meta.tag, Annotation.authorString, Communication.payload, attachment titles, base64 / gzip+base64 / data URIs, percent (single and double), HTML entities, `\u` escapes, spreadsheet formula cells.
- **Linkage traps:** homonyms, twins, father and son with the same name, a family sharing one phone, married name change across hospitals, newborn twins `B/O` (never merge), cross-script, fragmented "Name, W/o Husband" notes (some genuinely ambiguous).
- **Dates:** DD/MM vs MM/DD, `dd.mm.yy`, `12th Mar '26`, `03-Mar-1928`, Hindi months with Devanagari digits, ISO timestamps, a stay across New Year, a 29 Feb DOB, festival-relative dates.
- **Re-identification:** a 102-year-old, a 12-day-old, a one-village patient, rare diseases, voter-roll and targeted known-facts attacks with decoys.
- **Robustness:** UTF-16, cp1252, BOM, truncated JSON, 1,500-deep JSON, NaN, duplicate keys, invalid UTF-8, empty file, XML/PDF/JPEG, JSON behind `.csv`, ragged CSV, `.jsonl`, hidden dotfile; 6 canaries.

## Calibration (hardest_A)
| Release | PII visible | Canaries | Approx. total |
|---|---|---|---|
| copy everything | 99.9% | 6/6 | −18.4 |
| delete everything | 0% | 0/6 | 31.5 |

Scale check: a 1,000-patient set (`--patients 1000`: 1,783 files, 46,345 PII mentions)
generates in under a second and scores in about 50 s using about 170 MB.

The total approximates the official weights in docs/SCORING.md; it is a practice
guide, not the official score. Leak matching is deliberately strict (homoglyph
fold, zero-width removal, Indic digits, number words, decoded hidden payloads).
