# Member 1 walkthrough

Run the commands below from this branch on your Mac. Python 3.9+ on macOS or Linux is sufficient.

1. Open Terminal in the repository directory. Run `git switch member-1-file-handler` after fetching the branch.
2. Run `export RAKSHA_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"`. This makes a temporary secret for your shell. Reuse it to reproduce opaque paths.
3. Run `python3 -m unittest -v test_member1`.
4. Run `python3 main.py --demo --input examples/input --output my_output`. Choose a fresh destination for each run.
5. Inspect `my_output/report.json`, `my_output/records.jsonl` and the generated CSV in `my_output/sanitized/`. Expect one cleaned CSV, two row entries, one quarantined malformed JSON and no fictional names. The medicine survives.
6. Connect the team processor as described below. Remove the demo flag and use the organizer's dev input. Compare the report fields, file path convention, record locations and TOML keys with the official contract. Run `python3 validate_output.py --input dev/input --output my_output_team` after producing my_output_team. Record real time and memory on the full dataset.

## Team handoff

Members 2 and 3 implement a shared adapter in team_processor.py exposing Processor(secret). The secret is bytes. The runner calls the following methods.

* observe(file_id, loc, data) once per record before any outputs are written. Member 2 extracts identifying evidence. Member 3 indexes evidence for cross-file linking. Keep the minimum evidence in memory.
* finish() once after the first pass. Member 3 resolves groups.
* clean(file_id, loc, data) on the second pass returns (cleaned_data, patient_id_or_None). Member 2 cleans values and sensitive keys, including CSV headers. Member 3 applies privacy transformations and supplies a PSN identifier for confident matches. Both passes use the same file_id and loc. Return a dictionary with consistent keys for each table row, a string for notes, and JSON-compatible data for JSON/FHIR.

file_id is an opaque relative output path. Folder depth is preserved. Each file report links its input content digest to its output path. Locations use zero-based row numbers, JSON pointers (empty string for the root) or doc for text. When header renaming is needed across a table, agree on a consistent mapping before returning cleaned rows.

## Scope to verify with the official starter

The sample processor accepts only the two bundled fictional row values. Normal mode requires the team adapter. FHIR input is JSON and the runner does not validate clinical schemas. Simple collection bundles are split by entry. Other bundles and envelopes are passed whole to the adapter so metadata is included. Adapt the record boundaries to the official dataset. Header-only CSVs are quarantined. Ordinary files are hashed even if parsing fails. Unreadable files and symlinks have a null digest. All files must stay unchanged during a run. Peak memory depends on the largest file and the linker's index. Confirm both contest limits on the official practice set.
