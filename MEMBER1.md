# Member 1 · official practice run

Use the Secret Wards toolkit from https://github.com/Reinforce-SST/Secret-Wards-ToolKit. The commands below assume it was unzipped into Downloads on your Mac. Run them from the team repository on the member-1-file-handler branch.

```sh
git pull --ff-only
export RAKSHA_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
kit="$HOME/Downloads/Secret-Wards-ToolKit-main"
python3 -m unittest -v test_member1
python3 main.py --input "$kit/dev/input" --output my_output_official
python3 "$kit/validate_output.py" --input "$kit/dev/input" --output my_output_official
python3 "$kit/check_dev.py" --output my_output_official
python3 "$kit/check_submission.py" --repo . --run
```

Choose an empty or new output directory for each release. The two-row practice exercise remains available with `--demo --input examples/input`. Only use the integration baseline with synthetic data. The official format checker tests structure. The separate practice self-check measures leaks, medical utility and patient linkage.

## Team handoff

Member 1 reads input twice in sorted order. Normal runs use team_processor.Processor(secret) when installed or baseline_processor.Processor otherwise. Members 2 and 3 supply team_processor.py. Import failures inside it stop execution.

* observe(file_id, loc, data) receives each record before linkage. file_id is an internal path token, loc is the original record locator, and data is parsed text, JSON, or a table row. For a grouped JSON document loc=None denotes envelope metadata. Never log file_id or data.
* finish() resolves matches across files. An optional compiled name_pattern lets the writer recognize private path components.
* clean(file_id, loc, data) returns (cleaned_data, patient_id_or_None). Clean both keys and values. Apply the same header transformation across table rows. For linked records embed the same ID in the exported data. Envelope metadata should return a dictionary and None.
* Supply an entities counter for removed identifiers and a generalized count for transformed records. FHIR bundles use doc as their locator and require consistent references. Suppression and changed output locators need coordinated support before enabling them.

The writer uses UTF-8, reports input SHA-256 hashes and the output mapping, and uses keyed tokens for suspicious path components. Temporary output contains only processed values. Keep raw data and cross-file evidence in memory. Unreadable inputs, header-only tables and malformed or unsupported inputs have limitations; the reader quarantines these when possible. The interim processor is a simple structured-field and regex baseline. It lacks comprehensive multilingual detection, patient linkage and date shifting. The team still owns these features and the final README/PDF.
