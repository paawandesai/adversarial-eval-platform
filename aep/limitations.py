"""Documented target limitations: seed cases that can't reach a verdict on the current test host.

A case is tagged in its seed JSON under ``oracle_config.known_limitation``:

    "known_limitation": {"expected": "inconclusive", "reason": "...", "ref": "THREAT_MODEL.md section 7"}

The case stays in the suite and its oracle and verdict logic are unchanged. Reporting surfaces
(scripts/run_campaign_seeds.py, the dashboard, the regression gate) label its ERROR verdicts as an
expected skip instead of a platform error. Remove the tag once the limitation is lifted.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

KEY = "known_limitation"


def expected_inconclusive(case: Any) -> Optional[str]:
    """The documented reason this case is expected to be inconclusive, or None."""
    tag = (getattr(case, "oracle_config", None) or {}).get(KEY)
    if not isinstance(tag, dict) or tag.get("expected") != "inconclusive":
        return None
    reason = str(tag.get("reason") or "documented limitation")
    return f"{reason} ({tag['ref']})" if tag.get("ref") else reason


def expected_map(cases: Iterable[Any]) -> dict[str, str]:
    """case_id -> reason, for every tagged case."""
    return {c.case_id: r for c in cases if (r := expected_inconclusive(c)) is not None}
