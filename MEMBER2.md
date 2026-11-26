# Member 2: multilingual detection and integration

## Status

The detection engine is integrated with Member 1 through `member2_processor.Processor`.
Use the explicit `--detector-only` flag for integration runs. This is **not the final
privacy release**: DATE, DOB, AGE and GENDER remain unchanged and records are not
linked. Member 3 must supply the final `team_processor.Processor`. The existing
normal-run selection and Member 1 baseline are intentionally unchanged.

## Your role in plain language

You find the private information and return its position and type. Member 1 reads
and writes the files. Member 3 decides which records belong to one patient and
transforms identities and quasi-identifiers consistently.

For `Patient: Zorven Talrek; BP 150/90`, your detector identifies the name and leaves
the blood-pressure reading alone. You return an exact span; you do not invent a
patient linkage just because two names look similar.

## Run

Core code uses Python's standard library; Python 3.11+ is recommended. It also runs
on Python 3.9 using postponed annotations. No weights or network access are used.

```sh
python3 -m unittest -q
# Set RAKSHA_SECRET privately in your shell before running the pipeline.
python3 main.py --detector-only --input /absolute/path/to/toolkit/dev/input --output my_output_member2
python3 /absolute/path/to/toolkit/validate_output.py --input /absolute/path/to/toolkit/dev/input --output my_output_member2
python3 /absolute/path/to/toolkit/check_dev.py --output my_output_member2
```

Use a fresh output directory for each run. Do not print or commit the secret.
Optional packages in `detector_requirements.txt` must be installed before going
offline. `phonenumbers` adds possibility validation; the no-package fallback checks
bounded formats and digit lengths. PyYAML supports general YAML policy files; the
default policy is JSON syntax, which is valid YAML. The spaCy blank PhraseMatcher
helper is available for extensions, but the active core uses regex context rules.
Optional dependency paths were not installed or validated in this environment.

## Exact public contract

```python
from detector import EntitySpan, DetectionResult
from detector import detect_text, detect_record, detect_key_or_filename

result = detect_text('Patient: Zorven Talrek; Age: 47; BP 150/90')
# Pass result in memory to Member 3; do not print sensitive attributes.
assert result.age == 47
```

- `detect_text(text, field_hint='', policy_path=None)` returns DetectionResult.
- `detect_record(record, policy_path=None)` returns a dictionary of leaf results.
- `detect_key_or_filename(label)` returns EntitySpan objects for the original label.
- EntitySpan fields are start, end, entity_type, text, normalized, action, confidence.
- DetectionResult fields are spans, patient_names, relative_names, phones, ids,
  dates, dob, age, gender, locations and pincodes.

Offsets are half-open Python Unicode character offsets in the **original string**,
not UTF-8 bytes or JavaScript UTF-16 units. `text[s.start:s.end] == s.text`. Spans
are sorted and nonoverlapping. Apply replacements from right to left. AGE spans
cover digits only. Date values normalize to ISO dates; names are casefolded and
honorifics removed. Cross-script equivalence is Member 3's responsibility.

Flat record output keys match input keys. Nested records use escaped RFC 6901
pointers (for example `/name/0/given/0`); `~` and `/` become `~0` and `~1`.
Offsets index each leaf, or `str(number)` for numeric values. Keys themselves can
contain PII and must be inspected separately. Do not log result dictionaries.

| Entity | Default requested action for Member 3 |
|---|---|
| PERSON | PSEUDONYMIZE |
| RELATIVE, PHONE, EMAIL, ID_* | REDACT |
| DATE, DOB | DATE_SHIFT |
| AGE, LOCATION, PINCODE | GENERALIZE |
| GENDER | KEEP_META |

The adapter masks direct identifiers and fine-grained locations for testing. It
preserves observed district values, keeps numeric identifier replacements numeric,
and returns patient=None. These are integration defaults, not a replacement for
Member 3's privacy decisions. No k-anonymity, linkage or HMAC patient IDs are claimed.

## Member 1 adapter and Member 3 handoff

`observe(file_id, loc, data)` learns candidate names and clinical phrases from
current input in RAM. `finish()` compiles deterministic matching patterns.
`clean(file_id, loc, data)` returns `(cleaned_data, None)`. `entities` supplies
aggregate counts. `name_pattern` lets Member 1 protect recognized private paths.

Clinical phrases from structured clinical fields suppress weak name guesses;
explicit patient fields still detect names matching a doctor's name. Every field
is scanned for strongly formatted identifiers even if the label looks clinical.
Field hints cover English, Hindi and Hinglish variants and month-first DOB labels.
Text/plain base64 attachments are decoded, cleaned and re-encoded in memory.
Unsupported encoded content fails the run with a fixed error. Source-path metadata
is replaced in full. Keys use secret-keyed deterministic replacement names; a key
collision raises a fixed error instead of overwriting data. FHIR Patient versus
Practitioner name roles are respected and structural resource references are kept.
This is not a complete FHIR R4 validator.

Member 3 should call detector APIs on ORIGINAL text before applying transformations,
and use each detected span's action to choose the transformation. Do not link records
by a shared name alone. Keep date shifts consistent within a patient and embed the
same pseudonym in the actual output and records.jsonl. Supply `team_processor.py`
with Member 1's observe/finish/clean interface when ready. Do not use the detector-only
release for final submission.

## Security and limitations

Detection has no logging or writes. Dataclass reprs hide values, but attributes,
`asdict`, JSON serialization and tracebacks that capture locals can still disclose
PII. Keep evidence in RAM and reports aggregate-only. The adapter fails on invalid
attachments and oversized/nested inputs rather than publishing a partial release.
Member 1 owns per-file quarantine and final publication; a processor error stops
the entire run rather than dynamically quarantining one file.

Regex/context rules are heuristic. Unseen unlabelled names, new clinical vocabulary,
ambiguous C/O phrases, unusual encodings and metadata can cause misses or false
positives. Clinical field labels and the input-learned phrase vocabulary can also be
wrong in shifted columns. Do not treat an empty detection as a privacy certificate.
Name and clinical dictionaries come only from current input, never practice truth.

Dates default to day-first; an explicit `MM/DD` field label selects month-first.
Unlabelled month-first text remains ambiguous. Two-digit years 00–30 use 2000–2030;
31–99 use 1931–1999. Invalid dates are ignored. Government identifiers are shape
candidates, not proof of valid issuance. Masked Aadhaar values normalize with a
`MASKED:` prefix and must never be used as unique strong identifiers for linkage.

The public `detect_record` API does not infer all FHIR resource roles; the adapter
adds role-aware traversal. Member 3 should retain that contextual behavior. Full
FHIR profile validation, rare-value suppression, encryption-at-rest design and
attack-risk evaluation remain whole-team tasks. See VALIDATION_MEMBER2.md for
measured results and what they do not establish.
