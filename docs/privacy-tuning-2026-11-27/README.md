# Privacy tuning and guideline audit — 27 November 2026

**This project is not proven 100% accurate, 100% private, or universally compliant.**
The official submission checker passes; it checks packaging and execution, not perfect
anonymization. See [the requirement-by-requirement audit](GUIDELINES.md).

## What changed after a6917c5

1. Default `max_level` is 3: widen age first, then suppress district for sparse patients.
   Diagnoses and medications are preserved; geographic utility is intentionally reduced.
2. Recognize compound guardian labels, including `Father / Husband`, and redact the full
   relative name. Retain explicitly labelled relatives even when they share a patient's name.
3. Reject shared-phone/same-name merges with contradictory guardian names unless stronger
   shared-identifier evidence exists. This is deliberately conservative.
4. Preserve Unicode-normalized name spans as linkage evidence. The previous equality
   comparison accidentally discarded spans whose visible text changed during normalization.
5. Recognize names in `bed of ...` metadata while preserving ward/bed context.
6. Reject FHIR Encounter inputs missing required status/class. The synthetic generator
   was missing class; corrected the generator, not the scoring rules.
7. HMAC-remap FHIR IDs, full URLs and references together. UUID-like segments such as
   `021f` were incorrectly interpreted as ages and changed to `18+`, invalidating IDs.
8. Updated the two-page A4 project brief; all PDF text is at least 10 pt.

**196 unit tests pass on Python 3.9 and 3.15.** Official `check_submission.py --run`
passes the output contract, repeat determinism, changed-key output, no secret in logs/output,
and input preservation. Independent FHIR R4 model checks pass on all **106/106 output
bundles** in the final three runs. This checks the installed FHIR resource models, not
all FHIRPath invariants, terminology bindings or deployment-specific profiles.

## Final measured results

| Seed | Practice composite /100 | Weighted leak matches / mentions | Link precision / recall | Clinical probes kept | Date intervals kept | Targeted people identified |
|---|---:|---:|---:|---:|---:|---:|
| 2117101 | 96.65 | 1 / 6041 | 100.000% / 100.000% | 3906 / 3920 | 157 / 157 | 7 / 36 |
| 2117102 | 94.21 | 5 / 5845 | 100.000% / 99.646% | 3674 / 3689 | 149 / 149 | 13 / 36 |
| 2117103 | 97.28 | 0 / 5638 | 100.000% / 100.000% | 3608 / 3620 | 146 / 146 | 7 / 36 |

Mean composite: **96.05/100**. Each dataset requests 120 patients;
the generator adds trap identities. Every run handled all 12 malformed/unsupported cases,
with no silent drops, raw copies or canary leaks. The only lost preservation probes are
district values. Simulated targeted attacks still succeeded. Fractional leak counts in
some earlier runs are token-weighted matches, not fractions of people.

Do not compare this mean directly with the earlier 98.08 headline: datasets and keys differ,
and these final runs omit the cross-secret score component (the official checker separately
tests changed keys). Identical scoring settings were used within each policy comparison.

## Development selection and candid comparisons

On seed 71127 (80 requested patients), holding data/key/scorer fixed:

| Candidate | Approx. total | Targeted hits | Lost clinical probes |
|---|---:|---:|---:|
| Previous district-preserving policy | 95.8006 | 10/24 | 0 |
| Sparse-district suppression | 96.7885 | 5/24 | 31 district values |
| Wider date offsets (365 days) | 95.1944 | 10/24 | 0 |
| Higher age-band risk threshold | 95.8331 | 10/24 | 0 |

Rejected wider shifts; selected sparse-district suppression. On two then-reserved seeds,
policy alone improved 95.02→95.72 and 96.32→97.49. On the **original** seed92831,
policy alone reduced the score 98.08→97.84 despite reducing targeted hits 7→5.
That regression is retained in `original-final.json`; the new policy is a privacy/utility
trade-off, not an improvement on every input. Set `max_level` back to 2 if retaining all
district information is the chosen policy.

The two reserved sets then exposed guardian and Unicode linkage bugs and became development
regressions. Seeds1117101–1117104 were another validation round and exposed metadata/FHIR
issues. Seeds2117101–2117103 were newly generated after those fixes, then rerun after fixing
the observed invalid-ID issue. They are now regression data, not untouched final-test data.
Their scores above are for the final code. All rounds use the team's generator, so they do
not establish generalization to an independent real-world distribution. No real patient
records were used. Aggregate JSON from unsuccessful candidates and intermediate rounds is
retained; no scorer thresholds or formulas were edited.

## Reproduction

Generate fresh datasets outside the repository/input tree:

```sh
python3 -m unittest -q
python3 tools/hardest_test/generate.py --out /tmp/sw-check-data --seed 2117101 --patients 120
# Set RAKSHA_SECRET privately before running. Use a fresh output directory.
python3 main.py --input /tmp/sw-check-data/dev/input --output /tmp/sw-check-output
python3 contract_check.py --input /tmp/sw-check-data/dev/input --output /tmp/sw-check-output
python3 tools/hardest_test/score.py --data /tmp/sw-check-data --output /tmp/sw-check-output --json /tmp/sw-check-score.json
python3 ../toolkit/check_submission.py --repo . --run
```

The public synthetic test key for final runs was `synthetic-release-audit-key`;
for development71127 it was `synthetic-development-key`, and for672903/81942 it was
`synthetic-validation-key`. Do not use these public test keys for sensitive data.
Earlier original-set comparison used `synthetic-final-key` and `synthetic-other-key`.
Model validation used development-only `fhir.resources==6.5.0` / `pydantic==1.10.27`;
PDF generation used development-only reportlab4.5.1. Neither is a core runtime dependency.

## Remaining work / limits

Residual name/location matches and missed links remain in the scorecards, as does successful
re-identification from retained clinical facts. These are not hidden by the passing test
suite. Full R4 profile validation is not implemented at runtime. Encrypted raw-data storage
is not implemented by this read-only pipeline; it needs an encrypted deployment volume.
Registered team member names and the official event/deadline window still need moderator
confirmation. These limitations prevent claiming all guidelines are certified or any-input
accuracy is 100%. The sealed official evaluator is the authority for the competition score.
