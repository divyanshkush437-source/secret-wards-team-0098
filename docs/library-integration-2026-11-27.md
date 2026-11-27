# Library integration — 27 November 2026

Baseline: `b5b3084`. Installed `phonenumbers==9.0.44` and
`indic-transliteration==2.3.83` in the project `.venv`; both are required setup
dependencies in requirements.txt. No runtime downloads or ML models were introduced.

## Replacement scope

- Removed the optional import/fallback and handwritten `PHONE` pattern from
  detector/patterns.py. `detector/phone_numbers.py` uses PhoneNumberMatcher, parse,
  possibility validation and E.164 normalization. Region defaults to India.
- Added international numbers, varied digit grouping and extension coverage.
  Extensions are redacted with the contact but excluded from the underlying phone
  identity key. Rejected short local-only candidates and embedded word/ID substrings;
  existing clinical-context protection still applies.
- Removed the handwritten Devanagari alphabet tables and implementation from linker.py.
  transliteration.py obtains its character inventory and transliteration from the
  installed library. A Roman-spelling/Hindi schwa adapter preserves existing linkage
  keys; it also handles four candra vowels the pinned ITRANS converter does not render
  consistently. This is an explicit compatibility layer, not a claim of replacing
  every linguistic rule with a library call.
- Retained linker.py's clustering and public functions, and patterns.py's dates,
  identifiers and other patterns. Deleting those modules would break callers.

## Validation

**201 tests pass** (196 existing, five new behavioral tests with subcases).
Package dependency check passes. Official `check_submission.py --run` passes output
contract, same-secret determinism, different-secret changes, input preservation and
no secret in logs/output. Runtime also completed with socket operations disabled.

Using the same input bytes and `synthetic-release-audit-key` as the baseline:

| Seed | Before /100 | After /100 | Link precision / recall | Cleaned files |
|---|---:|---:|---|---:|
| 2117101 | 96.651545 | 96.651545 | 1.000 / 1.000 (unchanged) | 252 |
| 2117102 | 94.213570 | 94.213570 | 1.000 / 0.996455 (unchanged) | 244 |
| 2117103 | 97.282944 | 97.282944 | 1.000 / 1.000 (unchanged) | 239 |

All **735 sanitized files** and all three records.jsonl manifests are byte-identical
to baseline. Therefore pseudonyms, links, date shifts and clinical values are unchanged
on these datasets. Report timing/resource values are expected to differ. Alphabet/context
comparisons against the baseline transliterator also produced no spelling differences
for its previously supported characters. New tests verify that Latin/Hindi records
with different supported phone formats still link to the same patient.

The scores are local practice composites, not universal accuracy or official hidden
scores. The residual privacy/detection/linkage limitations in the previous audit still
apply. Neither library guarantees finding every possible spelling or phone format.

## Run

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest -q
# Set RAKSHA_SECRET privately; use fresh output folders.
.venv/bin/python main.py --input INPUT --output OUTPUT
# Let the official checker find the installed runtime dependencies:
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python ../toolkit/check_submission.py --repo . --run
```

Upstream documentation:
[python-phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) and
[indic-transliteration](https://github.com/indic-transliteration/indic_transliteration_py).
The synthetic benchmark key above is public test data; never use it for sensitive records.
