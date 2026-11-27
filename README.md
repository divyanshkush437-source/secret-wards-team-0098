# Secret Wards — Team 0098

Offline, CPU-only, LLM-free privacy firewall for synthetic English, Hindi and Hinglish
hospital exports. No LLMs, pretrained transformers, model downloads or runtime network
calls are used. No machine-learning model is used at all: detection and linkage are
rules, gazetteer-free context patterns and classical string/phonetic matching written
during the event. The 2-page brief is [Project_Brief.pdf](Project_Brief.pdf).

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt   # required, during setup
.venv/bin/python -m unittest -q                      # 203 tests
.venv/bin/python contract_check.py --input INPUT --output OUTPUT   # official format rules + stricter checks
# RAKSHA_SECRET must already be set privately in your environment.
.venv/bin/python main.py --input /path/to/input --output /path/to/fresh_output
```

The normal command (also in raksha.toml) runs the full pipeline through
`team_processor.Processor`: Member 2 detection + Member 3 linkage and privacy layer.

- Member 1's ingestion and output runner: [MEMBER1.md](MEMBER1.md).
- Member 2's detector, run instructions and integration contract: [MEMBER2.md](MEMBER2.md).
- Member 3's linkage, pseudonyms, privacy layer and red-team results: [MEMBER3.md](MEMBER3.md).

## Final tuning pass

[Latest measured results](docs/final-tuning-2026-11-27/README.md): regression mean
96.72/100; fresh synthetic mean 97.06/100. Fixed an explicit patient-name leak in
clinical metadata. 203 tests and official submission checks pass. The 99–100
objective was not reached; privacy settings and scoring rules remain unchanged.
Earlier results below are historical.

## Library integration

Phone matching/normalization now uses `phonenumbers==9.0.44`. Devanagari character
conversion uses `indic-transliteration==2.3.83`, with a Hindi pronunciation adapter
that preserves existing name keys. `linker.py` retains clustering and its public API;
`detector/patterns.py` retains non-phone detection patterns. The optional phone fallback
and handwritten Devanagari alphabet tables have been removed.

[Before/after validation](docs/library-integration-2026-11-27.md): 735 cleaned files
and all linkage manifests are byte-identical on three benchmarks, with unchanged
scores. Additional tests cover international numbers, grouping and extensions.

## Latest privacy tuning and guideline audit

See [current results and method](docs/privacy-tuning-2026-11-27/README.md) and the
[guideline audit](docs/privacy-tuning-2026-11-27/GUIDELINES.md). **100% accuracy or privacy
is not established.** The new default (`max_level: 3`) removes district information only
for sparse patients after age widening; `max_level: 2` retains the previous geography policy.
Fixes cover compound guardian labels, conflicting family evidence, Unicode identity
extraction, and invalid FHIR encounters. Core remains rule-based, with no model training.
203 tests pass. Earlier headline scores below refer to earlier revisions and datasets.

## Historical practice results (official kit `dev/`, measured with `test_attacker.py`)

| Measure | Result |
|---|---|
| Files sanitized / quarantined | 193 / 7 (822 records, 775 linked) |
| Linkage precision / recall / F0.5 | 1.000 / 1.000 / 1.000; homonym pairs 2/2 kept apart; every trap patient 100% |
| Personal data visible (kit `check_dev.py` rules) | 0 / 3,230 across every type, script and hiding place; canaries 0 / 4; raw copies 0 |
| Clinical values kept | 4,855 / 4,855 (100%; also 100% on both hidden-style sets) |
| Admission/discharge intervals | 22 / 22 exact after per-patient shifting |
| Registry attack (district, gender, band, PIN prefix) | 0/746 records; 1/48 pooled profiles at ≥ 0.5 (raw input: 11 and 10) |
| Targeted attack (known visit date, hospital, condition, stay) | 6/14 known people (raw 2/14); global date shift not recoverable |
| Unseen-format copy (renamed columns, labels, dd.mm.yyyy dates) | linkage 1.000 / 1.000, 0 identifiers or villages leaked, contract OK |
| Two generated hidden-style sets (`tools/make_hidden_dataset.py`: 496 files, 270 new patients, 4 new hospital formats) | 0 / 8,253 personal-data pieces visible, 0 / 8 canaries, linkage 1.000 / 1.000, 246 / 246 stay lengths, 100% medical values, 0 voter-list record re-identifications (raw: 440) |
| Determinism | byte-identical with the same secret; 0 pseudonyms shared under another secret |
| Speed / memory | 4.7 s, 35 MB; 6× data (1,200 files) 45 s, 150 MB |

These are practice numbers, not a guarantee on hidden data. `config/privacy.json` sets
`max_level` 3 by default (sparse patients also lose their district). Set it to 2
for the previous district-preserving policy.

## Other modes

Use `--detector-only` to exercise the Member 2 adapter. Without that flag, the
runner selects `team_processor.Processor` if present, otherwise Member 1's interim
baseline. `--demo` is only for the two fictional sample rows in `examples/input`.

The detector-only mode masks identifiers and fine-grained locations but leaves
DOB, dates, age and gender unchanged and does not link patients. It is an
integration checkpoint, not an anonymized research release. Synthetic data only.

Core requires pinned `phonenumbers` and `indic-transliteration` packages installed
by setup. Runtime remains CPU-only and offline, with no model downloads. The
optional detector requirements add YAML editing and development tools.

## How the parts fit together

The runner reads each supported input twice in a stable order. Its first pass calls
`observe(file_id, loc, data)` so the processor can collect evidence in memory.
It then calls `finish()` once. The second pass calls `clean(file_id, loc, data)`
and writes processed values to a staging directory before publishing the report.
Original input locators are retained in records.jsonl. Every non-null patient ID
returned by the processor must also appear as a complete ID in that output record.

The detector uses bounded patterns for identifiers and dates plus multilingual
context rules for names and relatives. Structured clinical phrases protect against
weak name guesses. Date timestamps retain their time portion, while their calendar
date is exposed as a span for Member 3. Names, normalized identifiers and attributes
are sensitive intermediate data: never print or serialize them into reports.

The Member 3 processor links only when there is enough evidence, keeps every
clinical value, shifts each patient's dates by one secret offset and generalises
quasi-identifiers (see MEMBER3.md). Only aggregate counters should reach report.json. Failed imports and execution
errors produce fixed CLI messages, and malformed non-finite JSON numbers are
quarantined. Unsupported encoded attachments stop the run rather than being
published unchanged.

The synthetic practice scores are not a guarantee on unseen formats or patients.
The organisers' exact 2-CPU/4-GB sandbox was not reproduced locally.
[MEMBER3_READINESS.md](MEMBER3_READINESS.md) records the handoff audit that preceded
the Member 3 integration.
