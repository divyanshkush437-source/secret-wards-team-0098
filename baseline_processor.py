"""Interim rules for integration testing. Replace with the team's full processor."""
from collections import Counter
import hashlib
import hmac
import re

PRIVATE_FIELDS = set("patientname firstname lastname guardian guardianname fathername mothername address street phone mobile email aadhaar abha uhid mrn patientid policyno payerpan pmjayid relativename village village mohalla villagemohalla tehsil pin zip dob aadharno aadhaarno abhano guardianname".split())
NAME_FIELDS = set("patientname firstname lastname guardian guardianname fathername mothername relativename".split())
PATTERNS = {
    "EMAIL": re.compile(r"[\w.+-]+@[\w.-]+\.[\w]+"),
    "PHONE": re.compile(r"(?<!\d)(?:\+?91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)"),
    "AADHAAR": re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"),
    "MRN": re.compile(r"(?i)(?<![a-z0-9])(?:[a-z]{2,8}-(?:[a-z]{2,5}-)?(?:\d{2,4}-)?\d{5,}|(?:uhid|mrn|adm)\d{5,})(?![a-z0-9])"),
    "PAN": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
}


def field(key):
    return "".join(c for c in key.casefold() if c.isalnum())


class Processor:
    def __init__(self, secret):
        self.secret = secret
        self.names = set()
        self.entities = Counter()
        self.name_pattern = None

    def observe(self, file_id, loc, data):
        if isinstance(data, list):
            for value in data:
                self.observe(file_id, loc, value)
        elif isinstance(data, dict):
            for key, value in data.items():
                if field(key) in NAME_FIELDS and isinstance(value, str) and len(value.strip()) >= 3:
                    self.names.add(value.strip())
                self.observe(file_id, loc, value)

    def finish(self):
        if self.names:
            terms = sorted(self.names, key=lambda s: (-len(s), s))
            self.name_pattern = re.compile(r"(?<![^\W_])(?:" + "|".join(re.escape(t).replace(r"\ ", "[ _-]+") for t in terms) + r")(?![^\W_])", re.I)

    def text(self, value):
        for kind, pattern in PATTERNS.items():
            value, count = pattern.subn("[" + kind + "]", value)
            if count:
                self.entities[kind] += count
        if self.name_pattern:
            value, count = self.name_pattern.subn("[PATIENT_NAME]", value)
            if count:
                self.entities["PATIENT_NAME"] += count
        return value

    def value(self, data):
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, list):
            return [self.value(item) for item in data]
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                safe = self.text(key)
                if safe != key:
                    token = hmac.new(self.secret, key.encode(), hashlib.sha256).hexdigest()[:16]
                    safe = "field_" + token
                while safe in result:
                    safe += "_"
                if field(key) in PRIVATE_FIELDS and isinstance(value, str) and value:
                    result[safe] = "[REDACTED]"
                    self.entities["PRIVATE_FIELD"] += 1
                elif key == "data" and "contentType" in data and isinstance(value, str):
                    # Omit optional FHIR Attachment.data from the research release.
                    self.entities["ATTACHMENT"] += 1
                else:
                    result[safe] = self.value(value)
            return result
        return data

    def clean(self, file_id, loc, data):
        return self.value(data), None
