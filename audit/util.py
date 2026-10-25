"""Small shared helpers: token extraction, time handling, JSON-safe values."""
import re
from datetime import datetime, timezone

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
REF_RE = re.compile(r"\buser_\d+\b")
NULLS = {"", "null", "none", "nan", "n/a"}


def parse_ts(s):
    """Parse an ISO-8601 'Z' timestamp into an aware datetime (None if bad)."""
    if not s:
        return None
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def is_null(v):
    return v is None or (isinstance(v, str) and v.strip().lower() in NULLS)


def tokens(value):
    """Identifier tokens (lower-cased emails, hashes, user refs) found in any value."""
    out = set()
    if is_null(value):
        return out
    if isinstance(value, (dict, list, tuple)):
        for item in (value.values() if isinstance(value, dict) else value):
            out |= tokens(item)
        return out
    s = str(value)
    out |= {e.lower() for e in EMAIL_RE.findall(s)}
    out |= {h.lower() for h in HASH_RE.findall(s)}
    out |= set(REF_RE.findall(s))
    return out


def has_direct_identifier(value):
    """True if a value carries an email address (a direct identifier)."""
    return bool(EMAIL_RE.search(str(value))) if not is_null(value) else False
