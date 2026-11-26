"""Member 1's offline two-pass file runner. Python 3.9+, Linux/macOS."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import tempfile
import time

from io_handler import parse
from security import safe_path


def snapshot(path):
    if path.resolve() != path or not path.is_file():
        raise ValueError("invalid input")
    raw = path.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest()


def run(root, output, processor, secret):
    root = root.resolve()
    output = output.resolve()
    if not root.is_dir() or (output.exists() and (not output.is_dir() or any(output.iterdir()))) or root == output or root in output.parents:
        raise ValueError("use independent input and fresh output")
    start = time.monotonic()
    entries = []
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        entry = {"input_sha256": None, "status": "quarantined", "output": None, "reason": "unsupported_or_malformed"}
        entries.append(entry)
        try:
            raw, digest = snapshot(path)
            entry["input_sha256"] = digest
            doc = parse(raw, path.suffix.lower())
        except (ValueError, OSError, csv.Error, RecursionError):
            continue
        name = safe_path(path.relative_to(root), secret)
        if doc.envelope:
            processor.observe(name, None, doc.envelope)
        for loc, data in doc.records:
            processor.observe(name, loc, data)
        files.append((entry, path, name))
    processor.finish()
    processed = linked = 0
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        stage = Path(temporary) / "ready"
        clean = stage / "sanitized"
        clean.mkdir(parents=True)
        with (stage / "records.jsonl").open("w", encoding="utf-8") as manifest:
            for entry, path, name in files:
                raw, digest = snapshot(path)
                if digest != entry["input_sha256"]:
                    raise ValueError("input changed")
                try:
                    written = export_one(doc_bytes=raw, path=path, root=root, name=name, secret=secret,
                                         processor=processor, clean=clean, manifest=manifest)
                except ValueError as exc:
                    if str(exc) in FATAL:
                        raise
                    written = None
                except (TypeError, KeyError, RecursionError, UnicodeError):
                    written = None
                if written is None:
                    entry["reason"] = "processing_error"      # quarantined, never half-exported
                    continue
                exported, rows = written
                del entry["reason"]
                entry.update(status="sanitized", output=exported)
                processed += len(rows)
                linked += sum(r["patient"] is not None for r in rows)
            failed = sum(e.get("reason") == "processing_error" for e in entries)
            if files and failed == len(files):
                # Every parseable file failed: the processor is broken, not the data.
                raise ValueError("processing failed for every file")
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        sanitized = sum(e["status"] == "sanitized" for e in entries)
        entities = dict(getattr(processor, "entities", {}))
        counts = {"files_total": len(entries), "files_sanitized": sanitized,
                  "files_quarantined": len(entries) - sanitized, "records_processed": processed,
                  "identifiers_detected": sum(entities.values()), "records_linked": linked,
                  "records_generalized": getattr(processor, "generalized", 0),
                  "records_suppressed": 0, "records_quarantined": 0}
        report = {"schema": "raksha-report/1", "files": entries, "counts": counts,
                  "entities": entities, "timing": {"seconds": round(time.monotonic() - start, 4)},
                  "resources": {"peak_rss_mb": round(rss / (1048576 if sys.platform == "darwin" else 1024), 2)}}
        (stage / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        # Publish the completion report last.
        for filename in ("sanitized", "records.jsonl", "report.json"):
            (stage / filename).rename(output / filename)
    return report


# Processor-contract violations are bugs, not bad data: they still stop the run.
FATAL = {"input changed", "invalid patient identifier", "patient identifier missing from output record"}


def export_one(doc_bytes, path, root, name, secret, processor, clean, manifest):
    """Clean one file completely in memory, then write it. Returns (exported, rows)."""
    doc = parse(doc_bytes, path.suffix.lower())
    rel = safe_path(path.relative_to(root), secret, getattr(processor, "name_pattern", None))
    exported = "sanitized/" + rel
    if doc.envelope:
        doc.envelope, _ = processor.clean(name, None, doc.envelope)
    values = []
    rows = []
    for loc, data in doc.records:
        value, patient = processor.clean(name, loc, data)
        if patient is not None and not re.fullmatch(r"PSN-[A-Z0-9]+", patient):
            raise ValueError("invalid patient identifier")
        if patient is not None:
            rendered_value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, allow_nan=False)
            if not re.search(r'(?<![A-Za-z0-9-])' + re.escape(patient) + r'(?![A-Za-z0-9-])', rendered_value):
                raise ValueError("patient identifier missing from output record")
        values.append(value)
        rows.append({"file": exported, "loc": loc, "patient": patient})
    text = doc.render(values)               # render fully before touching the disk
    destination = clean / rel
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="") as handle:
        handle.write(text)
    for row in rows:
        manifest.write(json.dumps(row) + "\n")
    return exported, rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--detector-only", action="store_true", help="Member 2 integration run; no linkage or date shifting")
    args = parser.parse_args()
    secret = os.environ.get("RAKSHA_SECRET", "").encode()
    if not secret:
        parser.exit(2, "Set RAKSHA_SECRET before running.\n")
    if args.demo and args.detector_only:
        parser.exit(2, "Choose only one processor mode.\n")
    try:
        if args.detector_only:
            from member2_processor import Processor
        elif args.demo:
            from demo_processor import DemoProcessor as Processor
        else:
            try:
                from team_processor import Processor
            except ModuleNotFoundError as exc:
                if exc.name != "team_processor":
                    parser.exit(2, "Missing team processor dependency.\n")
                from baseline_processor import Processor
        result = run(args.input.resolve(), args.output.resolve(), Processor(secret), secret)
    except Exception:
        parser.exit(1, "Run stopped. Check input, output destination and processor setup.\n")
    print("Sanitized {files_sanitized} files, quarantined {files_quarantined}, wrote {records_processed} records.".format(**result["counts"]))


if __name__ == "__main__":
    main()
