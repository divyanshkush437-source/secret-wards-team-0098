# Secret Wards — labelled training data (Track 3)

Synthetic, labelled NER data for training your own de-identification model
(CRF, classical ML or a small model you train yourself, which the Track 3 rules allow;
declare it in your README). Everything is synthetic.

Only the code is committed. Recreate the data from the repo root with
`python3 tools/training/make_training_data.py --out training_out` (train seeds 101-105,
dev 201, test 301); `train_other_generator.jsonl` comes from `tools/make_hidden_dataset.py`
seeds 11-13 exported the same way. Trained `*.model` files are not committed either.

| File | Content |
|---|---|
| `train.jsonl` / `train.conll` | 5,850 records, 47,805 personal-data spans, 28,116 keep spans (seeds 101-105) |
| `dev.jsonl` / `dev.conll` | 1,164 records (seed 201) |
| `test.jsonl` / `test.conll` | 1,229 records (seed 301) |
| `labels.json` | label list and counts per split |
| `make_training_data.py`, `generate.py` | regenerate or enlarge: `python3 make_training_data.py --out more --train-seeds 111 112 113` |

The hardest-test sets (seeds 2026 and 4242) are not included and the exporter refuses them,
so scores on the hardest test stay honest.

## Format
`*.jsonl`, one record per line:
```json
{"id": "train-101-registration/...#row:0", "source": "registration/...", "format": "csv", "script": ["latin"],
 "text": "UHID: SMH/25/010050\nPatient Name: Irfan Qureshi\n...",
 "spans": [{"start": 6, "end": 19, "label": "HOSPITAL_ID"}, {"start": 34, "end": 47, "label": "PATIENT"}],
 "keep":  [{"start": 210, "end": 217, "label": "KEEP_DISTRICT"}]}
```
Offsets are Python character offsets into `text` (end exclusive). CSV rows are rendered
`Header: value` per line; JSON/FHIR records as `dotted.path: value` per leaf (`\u` escapes
decoded); notes are the raw text. `keep` spans are values that must survive (doses,
frequencies, vitals, labs, diagnoses, ICD/LOINC/SNOMED codes, doctors, wards, eponyms,
PIN look-alike amounts) and make good negative examples.

`*.conll`: `TOKEN<TAB>BIO-label`, blank line between records.

PII labels: PATIENT, RELATIVE, PHONE, AADHAAR, ABHA, ABHA_ADDRESS, PAN,
VOTER_ID, HOSPITAL_ID, INSURANCE_ID, EMAIL, DOB, HOUSE, LOCALITY, LANDMARK, VILLAGE, PIN.
Spans include disguised forms exactly as written (Devanagari/fullwidth digits, zero-width
and soft-hyphen characters, homoglyphs, spaced digits, number words, HTML entities,
percent-encoding).

## Quick start (sklearn-crfsuite)
```python
import sklearn_crfsuite

def read_conll(path):
    sents, cur = [], []
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line:
            if cur: sents.append(cur); cur = []
        else:
            tok, tag = line.rsplit('\t', 1); cur.append((tok, tag))
    return sents

def feats(s, i):
    w = s[i][0]
    f = {'w': w.lower(), 'suf3': w[-3:], 'is_title': w.istitle(), 'is_upper': w.isupper(),
         'is_digit': w.isdigit(), 'len': len(w), 'deva': any('ऀ' <= c <= 'ॿ' for c in w),
         'shape': ''.join('d' if c.isdigit() else 'A' if c.isupper() else 'a' if c.isalpha() else c for c in w)[:8]}
    for k in (-2, -1, 1, 2):
        if 0 <= i + k < len(s): f[f'w{k}'] = s[i + k][0].lower()
    return f

train, dev = read_conll('train.conll'), read_conll('dev.conll')
X = [[feats(s, i) for i in range(len(s))] for s in train]; y = [[t for _, t in s] for s in train]
crf = sklearn_crfsuite.CRF(algorithm='lbfgs', c1=0.1, c2=0.1, max_iterations=100)
crf.fit(X, y)
```

## Caveats
This data comes from one generator, so a model can learn its templates. Combine a trained
model with rules and context, check it on the official practice set and the hardest test,
and expect lower accuracy on formats neither has seen.

## Trained models and measured accuracy
`train_crf.py` trains a CRF (`pip install python-crfsuite`). With `--rules <path to your
team repo>` it also feeds your rule detector's output to the model as features, which is
what makes it generalise. Use the same `--rules` path when you evaluate or run a model.

| Model | Trained on |
|---|---|
| `final_crf.model` | both generators + the full official practice data (use this one) |
| `crf_generators_only.model` | both generators only (no practice data) |

```sh
python3 train_crf.py --rules ../secret-wards-team-0098 --model final_crf.model --test test.jsonl
cat train.jsonl train_other_generator.jsonl > all.jsonl && python3 train_crf.py --rules ../secret-wards-team-0098 --train all.jsonl --model my.model
```
(`--train` takes one file; concatenate files first, e.g. `cat train.jsonl train_other_generator.jsonl > all.jsonl`.)

Measured entity-level F1 (exact span and label) on data each model never trained on:

| Evaluated on | rules-free CRF, one generator | + rule features, two generators | + practice data (2-fold, split by file) |
|---|---|---|---|
| test split (same generator) | 0.994 | 0.994 | - |
| hardest_A / hardest_B | 0.994 / 0.994 | 0.994 / 0.993 | - |
| other generator A / B | 0.735 / 0.737 | **0.988 / 0.985** | - |
| official practice data | 0.812 | 0.890 | **0.995 / 0.978** (held-out halves) |

Personal-data tokens caught on the held-out practice halves: 99.7% and 97.9%; clinical
"keep" values wrongly flagged: 0.00% and 0.07%. `final_crf.model` adds the whole practice
set, so it cannot be scored on it; the 2-fold numbers are its honest estimate. No model
is 100% on data from a new source: combine it with your rules, and check it on new data.
