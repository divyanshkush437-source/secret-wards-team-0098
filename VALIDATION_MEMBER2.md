# Member 2 validation — 26 November 2026

Validated against Member 1 main commit `04788dc` and public practice toolkit
commit `6c0a85aab458a0750ff7adfc70d1d173bab60ae6`.

| Check | Observed result |
|---|---|
| `python3 -m unittest -q` | 114 tests pass: 6 Member 1, 80 detector, 28 integration |
| Official `validate_output.py` | CONTRACT OK |
| Input accounting | 200 input files; 193 sanitized; 7 quarantined; 674 records |
| Names, relatives, phones, government/hospital/insurance IDs | 0 still visible in those practice-check categories |
| Fine-grained location and PIN categories | 0 still visible in the practice check |
| Canary surfaces | 0 of 4 found |
| Medical values preserved | 4,855 of 4,855 (100%) |
| Raw unsupported files copied | 0 |
| Remaining personal-data surfaces | 111 DOBs, intentionally unchanged in detector-only mode |
| Linkage | No records linked; Member 3 pending |
| Same-input/secret repeat | 193 sanitized files and records.jsonl byte-identical |

The local run took 3.8948 seconds with reported peak RSS 19.48 MB. These are local
measurements, not a test under the organizers' 2-CPU/4-GB sandbox. report.json timing
and resource fields naturally differ between runs and are excluded from byte
comparison, in line with the toolkit's determinism contract.

The supplied PDF's Track 3 requirements (pages 11–17) were checked against the
implementation boundaries. Runtime code does not read the toolkit, truth files or
attacker registry. The public practice checker uses truth externally; only its
aggregate results are recorded here. Names are learned from current input context;
there is no practice-patient name list in the source.

## Interpretation

These are practice results, not a guarantee for hidden data. The checker is an
approximate substring measure, not comprehensive semantic validation. Zero visible
direct identifiers on this practice set does not prove zero false negatives, and
100% preservation of measured values does not prove all unseen clinical text is safe.

The 114 regression tests add synthetic cases for shifted fields, exact offsets,
C/O versus K/C/O, clinical protection, doctor/patient role collisions, encoded
attachments, numeric types, deterministic keys, nested FHIR references, privacy-safe
reprs, silence and blocked sockets. Optional dependency paths were not installed.

The final submission still needs Member 3: patient linkage, HMAC pseudonyms,
consistent date/DOB shifting, age banding, risk-based generalization/suppression,
and evaluation against linkage attacks. The final 2-page project brief and full
FHIR validation remain team-level deliverables. Normal `raksha.toml` execution
still uses Member 1's baseline until `team_processor.py` is supplied; these results
apply specifically to `--detector-only`.

## Reproduction

See MEMBER2.md: run with --detector-only, run the official format checker, then
run the practice checker. Use fresh output directories. Repeat with the same secret
and compare sanitized/ plus records.jsonl. Do not check data, generated releases,
secrets, caches or toolkit truth into this repository.
