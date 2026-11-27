# Final tuning pass — 27 November 2026

Baseline commit: 7af15ac. This is rule-based tuning, not model training.
The 99–100 target was **not reached**. Scoring formulas, evaluation options,
linking thresholds and deployed privacy configuration are unchanged.

## Accepted fix

Explicit high-confidence patient/relative context in a clinical metadata field
must not be shielded by learning that entire field as a clinical phrase.
For example, `Ward 7 bed of Zorven` keeps the ward information but removes the
patient name. Actual clinical expressions and doctor contexts remain protected.
No benchmark names, answer keys or seeds are used by runtime code.

All 203 unit tests pass. The official submission checker passes the output
contract, same-secret determinism, different-secret changes, secret protection
and input immutability. The change is limited to metadata redaction.

## Measured results

First three rows are existing regression data. Last three are fresh seeds first
run after the fix; no further tuning was done using those results. All request
120 synthetic patients and add trap cases. These are team-generated data, not
independent real-world validation or official hidden scores.

| Seed | Practice /100 | Link precision | Link recall | Weighted leaks | Clinical probes kept | Targeted identities recovered |
|---|---:|---:|---:|---:|---:|---:|
| 2117101 | 96.651545 | 100.0000% | 100.0000% | 1 | 3906 / 3920 | 7 / 36 |
| 2117102 | 96.218098 | 100.0000% | 99.6455% | 0 | 3674 / 3689 | 13 / 36 |
| 2117103 | 97.282944 | 100.0000% | 100.0000% | 0 | 3608 / 3620 | 7 / 36 |
| 3117101 | 96.271425 | 99.6867% | 100.0000% | 0 | 3960 / 3980 | 8 / 36 |
| 3117102 | 97.852288 | 100.0000% | 100.0000% | 0 | 3725 / 3742 | 6 / 36 |
| 3117103 | 97.066171 | 100.0000% | 100.0000% | 1 | 3998 / 4026 | 11 / 36 |

Regression mean: **96.7175/100**, previously 96.0494. Fresh-set mean: **97.0633/100**.

Seed 2117102 improved 94.213570 → 96.218098 and weighted name leaks fell
5 → 0. Other regression scores, linkage metrics and clinical preservation stayed
unchanged. All measured admission/discharge intervals were preserved; no planted
canaries leaked. Remaining missed/false links, location matches and successful
simulated attacks are disclosed above. Lower leaks and recovered identities are better.

## Rejected policy experiments

On development seed 2117102, increasing k_registry from 5 to 20 yielded
97.567185; increasing it to 50 yielded 97.579360. Both reduced targeted recovered
identities from 13/36 to 3/36 but clinical-preservation probes dropped from
3674/3689 to 3450/3689: 224 additional district values were suppressed.
These candidates were not adopted; the existing privacy settings and level of
geographic detail were retained. Candidate results are saved, not hidden.

## Reproduction and conditions

Use `.venv/bin/python tools/hardest_test/generate.py --out DATA --seed SEED --patients 120`,
then run main.py on DATA/dev/input with RAKSHA_SECRET set to the public synthetic
key `synthetic-release-audit-key`, then score with
`tools/hardest_test/score.py --data DATA --output OUTPUT --json SCORE.json`.
Never use this test key for sensitive records. No --output-other component was
added to inflate comparison scores; changed-key behavior is checked separately.

Runtime remains CPU-only, offline, rules-based and free of LLM/pretrained model
weights. The previous guideline audit and its unresolved deployment/FHIR/eligibility
limitations still apply; passing the checker is not full guideline certification.
