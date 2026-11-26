# Member 3 handoff audit — 26 November 2026

**Ready for Member 3 integration after merging the readiness fixes. Not a final
privacy submission.** This audit started from merged main commit `0b923f9`.

## Findings and corrections

The original 114 tests passed. Seven new boundary tests failed and exposed gaps
that mattered to Member 3. Those failures were fixed, and additional regression
checks bring the total to **132 passing tests**.

| Finding | Correction |
|---|---|
| ISO timestamp dates were missed | Validate the timestamp, expose its date-only span and preserve the time/zone suffix |
| Adapter discarded MM/DD context | Preserve the original date-format hint until parsing |
| Public record detection could flag Practitioner names | Share contextual traversal with the integration adapter |
| Nested guardian names were classified as patients | Propagate relative roles through name containers |
| Attachments accepted unsupported MIME types | Require bounded UTF-8 text/plain base64; reject unsupported content safely |
| JSON NaN/Infinity could fail during output | Reject non-finite constants and overflowing floats while parsing; quarantine the file |
| Manifest IDs did not have to appear in exported records | Require a complete matching patient ID in the cleaned record, not just a prefix |

The CLI now also catches processor-import errors and uses a fixed message instead
of exposing an exception payload. Existing APIs and Member 1 output contracts are
retained. No final Member 3 processor or pretend linkage implementation was added.

## Verification

| Check | Result |
|---|---|
| Unit/integration tests | 132 passed on both locally available Python interpreters |
| Official format validator | CONTRACT OK |
| Practice input | 200 files; 193 sanitized; 7 quarantined; 674 records |
| Practice direct identifier categories | No visible names, relatives, phones, email, PAN, Aadhaar/ABHA, hospital or insurance identifiers |
| Practice location/PIN categories | No visible surfaces |
| Canary check | 0 of 4 surfaces found |
| Medical preservation | 4,855 of 4,855 measured values retained |
| Remaining practice leaks | 111 DOB surfaces, intentionally unchanged in detector-only mode |
| Network-blocked detector runs | Three complete runs with Python socket, connection and DNS calls blocked |
| Same secret, different Python hash seeds | Sanitized files and records.jsonl byte-identical |
| Different secret | Keyed metadata/path output changed; this does NOT demonstrate patient unlinkability or date shifting |
| Input integrity | Input tree digest unchanged |
| Secret exposure | No secret in stdout/stderr or output files |
| Run failures | Staging removed; no completion report published |
| Member 3 dispatch | Mock team_processor loaded through normal CLI selection |
| Member 3 writer contract | observe before finish before clean; CSV/text/grouped JSON IDs embedded and manifest locators correct |

The three detector-only runs took approximately 3.90–3.96 seconds each, with
reported peak RSS approximately 19.56–19.61 MB. The organizers' resource caps and
OS-level network namespace were not reproduced. Python socket blocking covers the
current pure-Python execution path, not arbitrary future native dependencies.

The official `check_submission.py --repo . --run` also passed its structural,
repeatability, secret and input-integrity checks. Its normal command currently
selects Member 1's baseline because team_processor.py is absent. Its generic
“READY TO SUBMIT” text is **not** evidence that linkage/privacy is implemented.
The README was expanded; the final project-brief PDF remains outstanding.

## What Member 3 should implement

Create `team_processor.py` with `Processor(secret: bytes)` and these methods:

1. `observe(file_id, loc, data)`: collect linkage evidence in memory from original
   records. The file token and locator can themselves be sensitive. Do not log them.
2. `finish()`: resolve clusters using sufficient evidence, without merging people
   solely because names match. Compile an optional `name_pattern` for the writer.
3. `clean(file_id, loc, data)`: return `(cleaned_data, patient_id_or_None)`. Linked
   records must contain that exact `PSN-...` ID. Envelope metadata at loc=None
   returns a cleaned dictionary and None. Preserve table headers consistently.

Expose aggregate `entities` and `generalized` counts. Reuse `detect_text` and
`detect_record` plus their exact Unicode offsets; shared contextual hints now
preserve patient/relative/doctor roles. Transform the original text from right to
left. Keep dates within a patient on the same shift so hospital stay lengths survive.
Age bands must contain the true age. Masked Aadhaar suffixes are not unique IDs.
FHIR references must continue to resolve. The current runner does not support row
suppression or changed locators without coordinated changes to the writer/manifest.

The detector-only adapter is a reference integration path, not the final privacy
layer. Do not run its redactions first and then try to link already-erased data.
The public detection API returns sensitive data and does not decode attachment
payloads; Member 3 must retain the adapter's bounded in-memory text/plain attachment
handling when cleaning or extracting linkage evidence from attachments.

## Remaining limits

Hidden-data accuracy, optional phonenumbers/PyYAML/spaCy paths, comprehensive FHIR
profile validation, full resource-capped execution, final patient/date behavior,
attack-risk reduction and encryption-at-rest design are not certified by these
checks. The doctor/clinical heuristics and shifted-column handling remain imperfect
for unseen input. Repeat all team tests and official checks after Member 3 merges.

Reproduce the core checks with `python3 -m unittest -q`, then follow MEMBER2.md to
run `--detector-only` and the official validators on synthetic practice data.
Use fresh output directories. Keep generated releases, secrets and toolkit truth
out of Git.
