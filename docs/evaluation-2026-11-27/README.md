# Member 3 continuation: 27 November 2026

Started from `bbfeff0` (Member 3's latest pushed implementation). This is rule tuning
and validation, **not model training or fine-tuning**. No pretrained or learned model
was introduced. Runtime is standard-library Python with no network dependency.

## Changes

- Recognize yearless May dates, such as `Visit: 10 May`, so the existing patient-specific
  date shifter handles them. May was missing from the month list. Regression checks
  cover all twelve months and retention of a medication instruction.
- Roll back audit entity/generalization counters when an entire file is quarantined
  during cleaning. Failed work must not count as successful release processing.
- Added two regression tests; all **189 tests pass on Python 3.9 and 3.15**.

## Evaluation protocol

Generated new synthetic development data using seed **71127**, 80 requested patients,
and reserved seed **92831**, 120 requested patients, before tuning. The generator adds
trap identities, so actual patient counts can exceed the requested count. Used development
failures to make the changes, froze runtime changes, then evaluated the reserved set.
Truth and attacker data were used only by scorers, never supplied to the runtime.
These sets share the team's generator: this tests new identities and combinations,
not an independent external distribution or arbitrary real-world inputs.

| Measure | Development after fixes | Held-out set |
|---|---:|---:|
| Exported / quarantined files | 177 / 12 | 241 / 12 |
| Labelled identifier mentions still visible | 0 / 4,022 | 0 / 5,760 |
| Clinical preservation probes passed | 2,835 / 2,835 | 3,794 / 3,794 |
| Linkage precision / recall | 1.000 / 1.000 | 1.000 / 1.000 |
| Date intervals preserved | 98 / 98 | 157 / 157 |
| Date surface warnings | 1 / 683 | 0 / 923 |
| Planted canaries found | 0 | 0 / 6 |
| Approximate composite score | 95.80 / 100 | 98.08 / 100 |

The development date warnings fell from three to one. The remaining warning is a scorer
substring collision: original `4th May '26` occurs inside shifted `24th May '26` at a
different event. We did not change the scorer or adjust the reported score.
The development and held-out composite scores are not a before/after comparison:
privacy differs by dataset, and only the held-out score includes the cross-secret test.
The same development score rose from 95.7889 to 95.8006; this is a small targeted fix.

Held-out release checks: identical sanitized files/manifest with the same secret;
zero pseudonyms shared under another secret; no silent drops or malformed exported files;
all 12 malformed/unsupported cases handled by quarantine. All 772 claimed patient IDs
appear in their output records. Runtime was 9.32 seconds, peak RSS 31.98 MB on this machine.
Timing is machine-dependent. See the accompanying aggregate JSON files.

## Official practice kit

Official toolkit revision: `6c0a85aab458a0750ff7adfc70d1d173bab60ae6`.
`check_submission.py --repo . --run` passed: output contract, unchanged inputs,
same-secret determinism, changed outputs under another secret, and no secret in logs/output.
A separate practice run blocked Python socket operations and completed successfully:
193 files exported, seven quarantined, 822 records, `CONTRACT OK`.
Official `check_dev.py`: zero of 3,230 full-surface identifiers visible, zero of four
canaries, all 4,855 clinical probes preserved, linkage precision/recall 1.000.
The additional attacker harness reports 24/24 date intervals preserved.

## Remaining limitations

**98.08 is a practice composite score, not universal accuracy or the official hidden score.**
On held-out data the registry attack identified 2/773 records and 1/125 profiles;
the targeted attacker identified 7/36 known people (raw input: 19/36), with ten decoy claims.
Exact clinical conditions, stay lengths and demographics still convey identifying evidence.
Preserving those useful clinical facts prevents promising zero re-identification risk.

The stricter practice attacker also reports three patient-name token matches (versus
zero full-surface matches in the official self-check), six of fourteen targeted people,
and a positive global-shift-recovery heuristic. These are retained in the aggregate
report rather than hidden by the stronger headline metrics. Do not describe this as
fully anonymous, 100% private, or validated for every language, schema and input format.
The date-order fallback and yearless-date reference year remain assumptions on ambiguous
inputs. An observation-stage exception can stop the run; successful release is not
promised for arbitrary data. Unreadable/unsupported files are quarantined, not processed.

## Reproduce

From the repository root, use fresh output directories outside the input tree:

```sh
python3 -m unittest -q
python3 tools/hardest_test/generate.py --out /tmp/sw-dev --seed 71127 --patients 80
python3 tools/hardest_test/generate.py --out /tmp/sw-heldout --seed 92831 --patients 120
# Set RAKSHA_SECRET privately; keep it the same for both deterministic runs.
python3 main.py --input /tmp/sw-heldout/dev/input --output /tmp/sw-run-a
python3 main.py --input /tmp/sw-heldout/dev/input --output /tmp/sw-run-b
# Change RAKSHA_SECRET privately before the cross-secret run.
python3 main.py --input /tmp/sw-heldout/dev/input --output /tmp/sw-run-other
python3 tools/hardest_test/score.py --data /tmp/sw-heldout --output /tmp/sw-run-a --output2 /tmp/sw-run-b --output-other /tmp/sw-run-other --json /tmp/sw-score.json
python3 ../toolkit/check_submission.py --repo . --run
```

The checked-in results used public synthetic-only test keys `synthetic-final-key`
and `synthetic-other-key` (development: `synthetic-development-key`; official practice:
`synthetic-offline-test-key`). Never use these keys for sensitive data. Scores dependent
on date offsets can change with the key. These sets are now regression data: choose a
new reserved seed and preferably an independent generator for future final evaluation.
