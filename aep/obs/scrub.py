"""NO-PHI guard. Everything bound for Langfuse (or a local log) passes through scrub().

Two layers:
  - key-based: values under identifying keys (patient_id, mrn, dob, name, ...)
    are replaced wholesale with a salted hash token, whatever their type.
  - text-based: free text is scanned for canaries, SSNs, MRNs, patient ids,
    emails, phones and DOBs; each hit is replaced with a hash token.

Tokens look like `<patient_id:3f9a0c1b2e>`. The same input maps to the same token
within a salt, so traces can still be grouped by patient without revealing who.
Set OBS_SCRUB_SALT for tokens that are stable across processes; otherwise a
random per-process salt is used (short numeric ids can't be brute-forced back).
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os
import re
import threading
from typing import Any, Iterable, TypeVar

T = TypeVar("T")

_SALT = (os.environ.get("OBS_SCRUB_SALT") or "").encode() or os.urandom(16)

# Keys whose values are identifiers/PHI regardless of what the value looks like.
_SENSITIVE_KEY = re.compile(
    r"patient|mrn|ssn|social_security|dob|date_of_birth|birth_?date|"
    r"first_?name|last_?name|full_?name|given_?name|family_?name|"
    r"address|phone|email|insurance|member_?id|canary",
    re.IGNORECASE,
)

# (label, pattern). Order matters: canaries first so they're never partially eaten.
# Patterns with a capture group replace only the group, keeping the context prefix.
_TEXT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("canary", re.compile(r"\b(?:[A-Z0-9]+[-_])*CANARY[-_][A-Za-z0-9_-]+", re.IGNORECASE)),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("mrn", re.compile(r"\bMRN\b[\s:#=-]*([A-Za-z0-9-]{3,})", re.IGNORECASE)),
    ("patient_id", re.compile(
        r"\b(?:patient[_ -]?id|pid)\b[\"']?\s*[:=#]?\s*[\"']?([A-Za-z0-9_-]+)", re.IGNORECASE)),
    ("patient_id", re.compile(r"\bpatient\s*#?\s*(\d+)\b", re.IGNORECASE)),
    ("patient_id", re.compile(r"/patients?/([A-Za-z0-9_-]+)", re.IGNORECASE)),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)")),
    ("dob", re.compile(
        r"\b(?:dob|d\.o\.b\.|date of birth|born(?: on)?)\b[\s:=-]*"
        r"(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{2,4})",
        re.IGNORECASE,
    )),
]

_canaries: set[str] = {c.strip() for c in os.environ.get("OBS_CANARIES", "").split(",") if c.strip()}
_canary_lock = threading.Lock()
_canary_re: re.Pattern | None = None


def register_canaries(canaries: Iterable[str]) -> None:
    """Add literal canary strings (e.g. from AttackCase.oracle_config['canary'])
    that must never leave the process, even if they don't look like a canary."""
    global _canary_re
    with _canary_lock:
        _canaries.update(str(c) for c in canaries if str(c))
        _canary_re = None


def _literal_canary_re() -> re.Pattern | None:
    global _canary_re
    with _canary_lock:
        if _canary_re is None and _canaries:
            alts = sorted(_canaries, key=len, reverse=True)
            _canary_re = re.compile("|".join(re.escape(c) for c in alts))
        return _canary_re


def hash_token(value: Any, label: str = "phi") -> str:
    digest = hmac.new(_SALT, str(value).encode(), hashlib.sha256).hexdigest()[:10]
    return f"<{label}:{digest}>"


def _sub(label: str, pattern: re.Pattern, text: str) -> str:
    def repl(m: re.Match) -> str:
        if pattern.groups:
            start, end = m.span(1)
            return m.string[m.start():start] + hash_token(m.group(1), label) + m.string[end:m.end()]
        return hash_token(m.group(0), label)
    return pattern.sub(repl, text)


def scrub_text(text: str) -> str:
    literal = _literal_canary_re()
    if literal is not None:
        text = _sub("canary", literal, text)
    for label, pattern in _TEXT_PATTERNS:
        text = _sub(label, pattern, text)
    return text


def _key_label(key: str) -> str:
    return re.sub(r"\W+", "_", key.lower()).strip("_") or "phi"


def _hash_all(value: Any, label: str) -> Any:
    """Replace every leaf under a sensitive key; keep the container shape."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return {k: _hash_all(v, label) for k, v in value.items()}
    if isinstance(value, tuple):
        return tuple(_hash_all(v, label) for v in value)
    if isinstance(value, (list, set)):
        return [_hash_all(v, label) for v in value]
    return hash_token(value, label)


def scrub(obj: T) -> T:
    """Return a PHI-free copy of obj with the same shape.

    str -> str, dict -> dict, list/tuple -> list/tuple; numbers/bools/None pass
    through. Pydantic models and dataclasses are converted to (scrubbed) dicts;
    any other object is scrubbed via its str(), so nothing unscanned escapes.
    """
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return scrub_text(obj)  # type: ignore[return-value]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = scrub_text(k) if isinstance(k, str) else k
            if isinstance(k, str) and _SENSITIVE_KEY.search(k):
                out[key] = _hash_all(v, _key_label(k))
            else:
                out[key] = scrub(v)
        return out  # type: ignore[return-value]
    if isinstance(obj, (list, tuple)):
        return type(obj)(scrub(v) for v in obj)  # type: ignore[return-value]
    if isinstance(obj, set):
        return [scrub(v) for v in obj]  # type: ignore[return-value]
    if hasattr(obj, "model_dump"):
        return scrub(obj.model_dump(mode="json"))
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return scrub(dataclasses.asdict(obj))
    if isinstance(obj, bytes):
        return f"<bytes:{len(obj)}>"  # type: ignore[return-value]
    return scrub_text(str(obj))  # type: ignore[return-value]


def langfuse_mask(*, data: Any, **_: Any) -> Any:
    """Langfuse `mask=` hook — a second line of defence inside the SDK."""
    return scrub(data)
