"""Parse supported records and rebuild files using only cleaned data."""
import csv
import io
import json
from dataclasses import dataclass


def unique_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate key")
    return result


@dataclass
class Document:
    layout: str
    records: list
    delimiter: str = ","
    envelope: object = None
    group: str = ""

    def render(self, values):
        if self.layout == "table":
            stream = io.StringIO(newline="")
            fields = list(values[0])
            writer = csv.DictWriter(stream, fields, delimiter=self.delimiter)
            writer.writeheader()
            for row in values:
                if set(row) != set(fields):
                    raise ValueError("inconsistent cleaned headers")
                writer.writerow(row)
            return stream.getvalue()
        if self.layout == "text":
            if not isinstance(values[0], str):
                raise ValueError("expected text")
            return values[0]
        if self.layout == "group":
            data = dict(self.envelope)
            data[self.group] = values
        elif self.layout == "list":
            data = values
        else:
            data = values[0]
        return json.dumps(data, ensure_ascii=False, allow_nan=False) + "\n"


def parse(raw, suffix):
    if not raw.strip():
        raise ValueError("empty file")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        body = raw.decode("utf-16")
    else:
        try:
            body = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            body = raw.decode("cp1252")
    if "\0" in body:
        raise ValueError("binary input")
    if suffix in {".csv", ".tsv"}:
        delimiter = "," if suffix == ".csv" else "\t"
        reader = csv.reader(io.StringIO(body, newline=""), delimiter=delimiter, strict=True)
        fields = next(reader, [])
        if not all(fields) or len(set(fields)) != len(fields):
            raise ValueError("invalid headers")
        records = []
        for index, row in enumerate(reader):
            if len(row) != len(fields):
                raise ValueError("invalid row")
            records.append((f"row:{index}", dict(zip(fields, row))))
        if not records:
            raise ValueError("empty table")
        return Document("table", records, delimiter)
    if suffix == ".txt":
        return Document("text", [("doc", body)])
    if suffix != ".json":
        raise ValueError("unsupported format")
    data = json.loads(body, object_pairs_hook=unique_keys)
    if isinstance(data, list):
        return Document("list", [(f"/{i}", v) for i, v in enumerate(data)])
    if isinstance(data, dict):
        for key in ("visits", "patients"):
            if data.get("resourceType") != "Bundle" and isinstance(data.get(key), list):
                envelope = {k: v for k, v in data.items() if k != key}
                rows = [(f"/{key}/{i}", v) for i, v in enumerate(data[key])]
                return Document("group", rows, envelope=envelope, group=key)
    return Document("json", [("doc", data)])
