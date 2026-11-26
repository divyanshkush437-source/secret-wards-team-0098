# Secret Wards — Team 0098

Offline detection and privacy pipeline for synthetic English, Hindi and Hinglish
hospital exports. No LLMs, pretrained transformers, model downloads or runtime
network calls are used by the current code.

- Member 1's ingestion and output runner: [MEMBER1.md](MEMBER1.md).
- Member 2's detector, run instructions and integration contract: [MEMBER2.md](MEMBER2.md).
- Measured checks and remaining work: [VALIDATION_MEMBER2.md](VALIDATION_MEMBER2.md).

```sh
python3 -m unittest -q
# RAKSHA_SECRET must already be set privately in your environment.
python3 main.py --detector-only --input /path/to/synthetic/input --output my_output_member2
```

Use `--detector-only` to exercise the Member 2 adapter. Without that flag, the
runner selects `team_processor.Processor` if present, otherwise Member 1's interim
baseline. `--demo` is only for the two fictional sample rows in `examples/input`.
The normal submission command in raksha.toml is unchanged; the final Member 3
processor and privacy layer still need integration before submission.

The detector-only mode masks identifiers and fine-grained locations but leaves
DOB, dates, age and gender unchanged and does not link patients. It is an
integration checkpoint, not an anonymized research release. Synthetic data only.

Core execution needs only the Python standard library. The optional detector
requirements add phone validation, YAML editing and development tools; they are
not automatically installed or required by the submission entry point.

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

The final Member 3 processor must preserve clinical information, link only when
there is enough evidence, and consistently transform dates and quasi-identifiers.
Only aggregate counters should reach report.json. Failed imports and execution
errors produce fixed CLI messages, and malformed non-finite JSON numbers are
quarantined. Unsupported encoded attachments stop the run rather than being
published unchanged.

The synthetic practice scores are not a guarantee on unseen formats or patients.
The full 2-CPU/4-GB sandbox and final re-identification risk have not been verified.
The two-page project brief will need the completed Member 3 design and results.
See [MEMBER3_READINESS.md](MEMBER3_READINESS.md) for the latest boundary tests,
network-blocked practice runs, and the exact remaining integration responsibilities.
