import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from demo_processor import DemoProcessor
from io_handler import parse
from main import run


class MemberOneTests(unittest.TestCase):
    def test_sample_run(self):
        root = Path(__file__).resolve().parent / "examples/input"
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "result"
            result = run(root, out, DemoProcessor(b"test"), b"test")
            self.assertEqual((result["sanitized"], result["quarantined"], result["records"]), (1, 1, 2))
            self.assertEqual({f["sha256"] for f in result["files"]},
                             {hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()})
            records = [json.loads(line) for line in (out / "records.jsonl").read_text().splitlines()]
            self.assertEqual([r["loc"] for r in records], ["row:0", "row:1"])
            cleaned = out / "sanitized" / records[0]["file"]
            self.assertEqual(cleaned.read_text().count("Dolo 650"), 2)
            for path in out.rglob("*"):
                if path.is_file():
                    self.assertNotIn(b"Demo Canary", path.read_bytes())
            with self.assertRaises(ValueError):
                run(root, out, DemoProcessor(b"test"), b"test")

    def test_text_and_tables(self):
        for suffix, separator in [(".tsv", "\t"), (".csv", ",")]:
            doc = parse(("id" + separator + "note\n1" + separator + '"café\nward"').encode("latin1"), suffix)
            result = doc.render([doc.records[0][1]])
            self.assertEqual(list(csv.reader(io.StringIO(result), delimiter=separator))[1], ["1", "café\nward"])
        doc = parse("नमस्ते".encode(), ".txt")
        self.assertEqual(doc.records, [("doc", "नमस्ते")])

    def test_json_layouts(self):
        for data, loc in [([1], "/0"), ({"visits": [1]}, "/visits/0"),
                          ({"resourceType": "Patient"}, ""),
                          ({"resourceType": "Bundle", "type": "collection",
                            "entry": [{"resource": {"resourceType": "Patient"}}]}, "/entry/0")]:
            doc = parse(json.dumps(data).encode(), ".json")
            self.assertEqual(doc.records[0][0], loc)
            self.assertEqual(json.loads(doc.render([v for _, v in doc.records])), data)

    def test_bad_input(self):
        for raw, suffix in [(b"oops", ".json"), (b'{"a":1,"a":2}', ".json"),
                            (b"a,a\n1,2", ".csv"), (b"abcdef", ".bin")]:
            with self.assertRaises(ValueError):
                parse(raw, suffix)

    def test_processor_failure_does_not_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "input"
            root.mkdir()
            (root / "private.txt").write_text("unknown")
            out = Path(folder) / "output"
            with self.assertRaises(ValueError):
                run(root, out, DemoProcessor(b"test"), b"test")
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
