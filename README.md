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
