# Guideline audit — 27 November 2026

Audited the supplied Yugaantar DevForge problem statement (Track 3, pages 11–17)
and [official toolkit](https://github.com/Reinforce-SST/Secret-Wards-ToolKit), commit
`6c0a85aab458a0750ff7adfc70d1d173bab60ae6`: PROBLEM_STATEMENT, SPEC, FAQ,
SANDBOX, SCORING and PROJECT_BRIEF. This is an engineering audit, not an organizer
certification or a guarantee of 100% on hidden data.

| Requirement | Evidence / status |
|---|---|
| No LLM, generative model or pretrained transformer | Runtime source/import audit: rules and classical string matching only. Training tools are development-only; no model is loaded. |
| Offline, CPU-only | No network client in runtime; `urllib.parse` only decodes strings. Fresh runs completed with Python socket operations blocked. Core uses the standard library and a single process. |
| 2 CPUs, 4 GB, 15 minutes | Tested cases comfortably below memory/time limits. Mac tests do not reproduce the organizer's full Linux namespace/cgroup sandbox or establish worst-case scaling. |
| Synthetic data only | Tests use organizer practice data or the team's synthetic generators. No real patient records added. |
| No hardcoded patient identities | Generic label, Unicode and relationship rules; runtime does not read test truth, attacker files, seeds or benchmark outputs. Examples in tests/comments are not runtime identity tables. |
| `raksha.toml`, setup/run entrypoint | Present and exercised by official `check_submission.py --run`. |
| Expected output tree, UTF-8 and locators | Official and stricter contract checks pass on tested inputs; same-format exports and SHA-256 report entries. |
| Keyed pseudonyms and shifts | HMAC-SHA256 from environment key. Official tests verify deterministic sanitized files/manifest, changed outputs for another key, no key in output/logs. |
| Input immutability and quarantine | Official test confirms unchanged input; unsupported/malformed cases are reported, not copied raw. New guard rejects Encounter resources missing status/class. Resource IDs and references are transformed together to prevent demographic detection from corrupting them. |
| FHIR R4 validity | Official practice inputs pass independent `fhir.resources==6.5.0` model validation. Older synthetic generator omitted Encounter.class; generator fixed and missing fields quarantined. Minimal runtime guards are not a complete R4 profile/invariant validator. See final schema audit for current generated inputs/outputs. |
| Clinical integrity | Diagnoses, medicines, doses and intervals retained on measured sets; sparse-patient district suppression deliberately reduces geographic utility. Generalization is a disclosed trade-off, not 100% preservation. |
| Patient identity consistency | Regression fixes cover compound guardian labels, conflicting family evidence and Unicode look-alikes. Final measured precision/recall are in README; arbitrary homonyms cannot be guaranteed. |
| Zero identifier/canary leaks | This is an objective, not certified globally. Separate token, canary and simulated attack results are retained in the scorecards. |
| Privacy against linkage attacks | Residual successful attacks remain. No claim of fully anonymous output. |
| Encryption at rest / security design | Raw input and intermediate evidence stay in RAM after reading; no new raw copies are persisted. The pipeline does NOT encrypt the organizer's read-only input or provide an encrypted archive feature. Encrypted source volumes, backups, swap and access controls are deployment responsibilities, not implemented/certified here. |
| Two-page brief, A4, >=10 pt | Updated PDF rendered and inspected; two A4 pages, minimum text size 10 pt. Architecture, approach, USP, trade-off, security and limitations covered. |
| Public repo created during event | Earliest git commit is 26 November 2026. Exact official event window and the team's registered member list are not available here; ownership/event eligibility must be confirmed by the team. Brief lists member roles, not verified registered names. |
| Deadline and submission | A pushed branch is not submission or a merge into main. Organizer deadline/frozen commit must be confirmed by moderator. |

## Security boundary

The competition supplies read-only synthetic files. Encrypting or modifying those inputs
inside the run would violate the immutable-input contract. A deployment should keep
original files on encrypted storage, mount them read-only for processing, restrict output
access and keep release keys outside the data. This deployment design is not evidence
that such infrastructure is already enabled. Temporary output contains processed values;
a missed identifier in those values remains a privacy failure, so temporary output must
not be described as provably free of PII. Runtime error messages do not include source
records. An observation-stage exception can still stop a run; failures are not universal
successful-processing guarantees.

## Limits of these checks

The local practice scorer differs from the sealed official evaluator, including some
privacy weights and the set of FHIR invariants checked. Its composite is not “accuracy”.
No score is rounded to 100 and no scoring rule was changed to improve a result.
