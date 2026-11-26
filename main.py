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
    if not root.is_dir() or output.exists() or root == output or root in output.parents:
        raise ValueError("use independent input and fresh output")
    start = time.monotonic()
    entries = []
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        entry = {"sha256": None, "status": "quarantined", "records": 0}
        entries.append(entry)
        try:
            raw, digest = snapshot(path)
            entry["sha256"] = digest
            doc = parse(raw, path.suffix.lower())
        except (ValueError, OSError, csv.Error, RecursionError):
            continue
        name = safe_path(path.relative_to(root), secret)
        for loc, data in doc.records:
            processor.observe(name, loc, data)
        files.append((entry, path, name))
    processor.finish()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        stage = Path(temporary) / "ready"
        clean = stage / "sanitized"
        clean.mkdir(parents=True)
        with (stage / "records.jsonl").open("w", encoding="utf-8") as manifest:
            for entry, path, name in files:
                raw, digest = snapshot(path)
                if digest != entry["sha256"]:
                    raise ValueError("input changed")
                doc = parse(raw, path.suffix.lower())
                values = []
                rows = []
                for loc, data in doc.records:
                    value, patient = processor.clean(name, loc, data)
                    if patient is not None and not re.fullmatch(r"PSN-[A-Z0-9]+", patient):
                        raise ValueError("invalid patient identifier")
                    values.append(value)
                    rows.append({"file": name, "loc": loc, "patient": patient})
                destination = clean / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("x", encoding="utf-8", newline="") as handle:
                    handle.write(doc.render(values))
                for row in rows:
                    manifest.write(json.dumps(row) + "\n")
                entry.update(status="sanitized", file=name, records=len(rows))
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report = {"files": entries, "input_files": len(entries), "sanitized": len(files),
                  "quarantined": len(entries) - len(files),
                  "records": sum(e["records"] for e in entries),
                  "elapsed_seconds": round(time.monotonic() - start, 6),
                  "peak_ram_bytes": rss if sys.platform == "darwin" else rss * 1024}
        (stage / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if output.exists():
            raise ValueError("destination already exists")
        stage.rename(output)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    secret = os.environ.get("RAKSHA_SECRET", "").encode()
    if not secret:
        parser.exit(2, "Set RAKSHA_SECRET before running.\n")
    if args.demo:
        from demo_processor import DemoProcessor as Processor
    else:
        try:
            from team_processor import Processor
        except ImportError:
            parser.exit(2, "Team processor unavailable. Use --demo for the fictional example.\n")
    try:
        result = run(args.input.resolve(), args.output.resolve(), Processor(secret), secret)
    except Exception:
        parser.exit(1, "Run stopped. Check input, output destination and processor setup.\n")
    print("Sanitized {sanitized} files, quarantined {quarantined}, wrote {records} records.".format(**result))


if __name__ == "__main__":
    main()
