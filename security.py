"""Opaque identifiers for file and folder names."""
import hashlib
import hmac


def safe_path(relative, secret):
    parts = []
    for index, _ in enumerate(relative.parts, start=1):
        prefix = "/".join(relative.parts[:index])
        token = hmac.new(secret, prefix.encode("utf-8", "surrogateescape"),
                         hashlib.sha256).hexdigest()[:24]
        parts.append(token)
    return "/".join(parts) + relative.suffix.lower()
