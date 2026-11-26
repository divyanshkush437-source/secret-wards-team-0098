"""Preserve ordinary paths and replace components carrying identifying clues."""
import hashlib
import hmac
import re
from pathlib import Path


def safe_path(relative, secret, name_pattern=None):
    parts = []
    for i, component in enumerate(relative.parts):
        risky = (re.search(r"(?i:(?:^|[_ -])(?:[a-z]{2,8}-(?:[a-z]{2,5}-)?(?:\d{2,4}-)?\d{5,}|(?:uhid|mrn|adm)\d{5,}))|\d{9}|@|[^\x00-\x7f]|[A-Z][a-z]+[ _-][A-Z][a-z]+", component)
                 or (name_pattern and name_pattern.search(component)))
        if risky:
            prefix = "/".join(relative.parts[:i + 1])
            component = "redacted_" + hmac.new(secret, prefix.encode(), hashlib.sha256).hexdigest()[:24]
            if i == len(relative.parts) - 1:
                component += relative.suffix.lower()
        parts.append(component)
    return Path(*parts).as_posix()
