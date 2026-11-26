#!/usr/bin/env python3
"""Output-contract check (same rules as the team kit's validate_output.py, docs/SPEC.md).

    python3 contract_check.py --input INPUT --output OUTPUT

Prints CONTRACT OK or the problems. Also adds stricter checks the official
format checker does not make: every JSON output parses, every claimed
pseudonym appears inside its exported record, report counts match the files.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

STATUSES = {"sanitized", "quarantined", "suppressed"}
COUNTS = ["files_total", "files_sanitized", "files_quarantined", "records_processed", "identifiers_detected",
          "records_linked", "records_generalized", "records_suppressed", "records_quarantined"]


def _files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for n in sorted(fn):
            yield Path(dp) / n


def check(inp: Path, out: Path):
    errors, warns = [], []
    shas = {}
    for p in _files(inp):
        shas.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), []).append(p.relative_to(inp).as_posix())
    san = out / "sanitized"
    if not san.is_dir():
        errors.append("missing output/sanitized/")
    exported = {p.relative_to(san).as_posix() for p in _files(san)} if san.is_dir() else set()
    report = None
    try:
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors.append("missing output/report.json")
    except ValueError as exc:
        errors.append(f"report.json is not valid JSON: {exc}")
    declared = {}
    if isinstance(report, dict):
        for ent in report.get("files") or []:
            sha = str(ent.get("input_sha256", "")).lower()
            if sha not in shas:
                warns.append("report.files entry whose input_sha256 matches no input file")
                continue
            if ent.get("status") not in STATUSES:
                errors.append(f"report.files status must be one of {sorted(STATUSES)}")
            declared.setdefault(sha, []).append(ent)
            o = ent.get("output")
            if ent.get("status") == "sanitized":
                if not o:
                    errors.append("a sanitized entry has no output path")
                elif str(o).replace("sanitized/", "", 1) not in exported:
                    errors.append(f"declared output does not exist: {o}")
        counts = report.get("counts") or {}
        missing = [k for k in COUNTS if not isinstance(counts.get(k), (int, float))]
        if missing:
            warns.append(f"report.counts missing: {', '.join(missing)}")
        if not isinstance((report.get("timing") or {}).get("seconds"), (int, float)):
            warns.append("report.timing.seconds missing")
        if not isinstance((report.get("resources") or {}).get("peak_rss_mb"), (int, float)):
            warns.append("report.resources.peak_rss_mb missing")
        # Stricter: honesty of counts.
        entries = report.get("files") or []
        if counts.get("files_total") != sum(len(v) for v in shas.values()):
            errors.append("files_total does not equal the number of input files")
        if counts.get("files_sanitized") != sum(e.get("status") == "sanitized" for e in entries):
            errors.append("files_sanitized does not match report.files")
        if counts.get("files_sanitized") != len(exported):
            errors.append("files_sanitized does not match the files in sanitized/")
    silent = sum(1 for sha, paths in shas.items() for path in paths if path not in exported and sha not in declared)
    if silent:
        errors.append(f"{silent} input files are neither exported (same path) nor declared in report.files")
    bad = 0
    for rel in exported:
        data = (san / rel).read_bytes()
        try:
            text = (data[3:] if data.startswith(b"\xef\xbb\xbf") else data).decode("utf-8")
        except UnicodeDecodeError:
            bad += 1
            continue
        if rel.endswith(".json"):
            try:
                json.loads(text)
            except ValueError:
                errors.append(f"sanitized JSON does not parse: {rel}")
    if bad:
        errors.append(f"{bad} sanitized files are not UTF-8")
    rj = out / "records.jsonl"
    if not rj.exists():
        warns.append("missing records.jsonl: identity resolution cannot be credited")
    else:
        linked = 0
        lines = rj.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                errors.append(f"records.jsonl line {i} is not JSON")
                break
            if not isinstance(r, dict) or "file" not in r or "loc" not in r or "patient" not in r:
                errors.append(f"records.jsonl line {i} needs file, loc, patient")
                break
            f = str(r["file"]).replace("sanitized/", "", 1)
            if f not in exported:
                errors.append(f"records.jsonl line {i} points to a file that was not exported: {r['file']}")
                break
            if r["patient"]:
                linked += 1
                body = (san / f).read_text(encoding="utf-8")
                if not re.search(r"(?<![A-Za-z0-9-])" + re.escape(r["patient"]) + r"(?![A-Za-z0-9-])", body):
                    errors.append(f"records.jsonl line {i}: pseudonym not present in exported file")
                    break
        if isinstance(report, dict):
            counts = report.get("counts") or {}
            if counts.get("records_processed") != len([l for l in lines if l.strip()]):
                errors.append("records_processed does not match records.jsonl")
            if counts.get("records_linked") != linked:
                errors.append("records_linked does not match records.jsonl")
    return errors, warns


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    errors, warns = check(Path(a.input), Path(a.output))
    for w in warns:
        print("WARN ", w)
    for e in errors:
        print("ERROR", e)
    print("CONTRACT OK" if not errors else "CONTRACT PROBLEMS FOUND")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
