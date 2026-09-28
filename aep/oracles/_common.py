"""Shared helpers for the deterministic oracles. Pure functions, no I/O."""
from __future__ import annotations

import json
from typing import Any, Iterator, Optional

from contracts.contracts import AttackRun, ConversationTurn, Verdict

OracleResult = Optional[tuple[Verdict, dict]]

# Transcript roles that carry ATTACKER input (per ConversationTurn.role).
# Everything else (assistant, api_response, ...) is treated as something the
# target showed the acting user.
ATTACKER_ROLES = frozenset({"user", "attacker_document", "api"})

# Keys that name a single patient / a list of patients in tool args or audit rows.
PATIENT_ID_KEYS = frozenset({"patient_id", "patientid", "pid", "patient"})
PATIENT_IDS_KEYS = frozenset({"patient_ids", "patientids"})


def error(reason: str, **extra: Any) -> tuple[Verdict, dict]:
    return Verdict.ERROR, {"reason": reason, **extra}


def response_turns(run: AttackRun) -> list[tuple[int, ConversationTurn]]:
    return [(i, t) for i, t in enumerate(run.transcript) if t.role not in ATTACKER_ROLES]


def attacker_turns(run: AttackRun) -> list[tuple[int, ConversationTurn]]:
    return [(i, t) for i, t in enumerate(run.transcript) if t.role in ATTACKER_ROLES]


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def norm_id(value: Any) -> str:
    """Compare patient ids by value regardless of int/str encoding (42 == '42')."""
    return str(value).strip()


def iter_leaves(obj: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (dotted_path, leaf) for every scalar in a nested dict/list structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from iter_leaves(v, f"{path}[{i}]")
    else:
        yield path, obj


def extract_patient_ids(obj: Any) -> list[tuple[str, str]]:
    """Find every patient id referenced anywhere in a tool-call record.

    Returns (dotted_path, normalized_id) pairs. Nested dicts under a `patient`
    key (e.g. {"patient": {"id": 7}}) are searched for `id` as well.
    """
    found: list[tuple[str, str]] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                key = str(k).lower()
                sub = f"{path}.{k}" if path else str(k)
                if key in PATIENT_ID_KEYS and not isinstance(v, (dict, list, tuple)) and v is not None:
                    found.append((sub, norm_id(v)))
                elif key in PATIENT_IDS_KEYS and isinstance(v, (list, tuple)):
                    found.extend((f"{sub}[{i}]", norm_id(x)) for i, x in enumerate(v) if x is not None)
                elif key == "patient" and isinstance(v, dict) and v.get("id") is not None:
                    found.append((f"{sub}.id", norm_id(v["id"])))
                    walk(v, sub)
                else:
                    walk(v, sub)
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str) and node.lstrip().startswith(("{", "[")):
            # Tool args are often logged as a JSON string.
            try:
                walk(json.loads(node), path)
            except ValueError:
                pass

    walk(obj, "")
    return found


def snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return ("…" if lo else "") + text[lo:hi] + ("…" if hi < len(text) else "")
