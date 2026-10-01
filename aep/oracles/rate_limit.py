"""RATE_LIMIT oracle: a burst of requests got no throttling — the target has no rate limiting.

This grades the ``cost_amplification_dos`` category. The vulnerability is that an
endpoint (the target's ``/pre-visit-brief``, an expensive LLM-backed route)
accepts an unbounded burst of authenticated requests with **zero throttling**.

We prove the vuln only from what is observable on the ATTACKER side — the
per-request envelopes the Red Team recorded on ``run.request_results`` (request
count, HTTP status codes, round-trip latency). We never read the target's
internal token/compute cost; the platform cannot see it.

A "throttle" is an HTTP 429 (Too Many Requests), the standard rate-limit signal.
``oracle_config`` may widen that with ``throttle_statuses`` (a status or list of
statuses, e.g. ``[429, 503]``); 429 is always included.

Verdict:
  - FAIL  — a burst (>= ``min_burst``, default 2) in which the target throttled
            NONE of the requests (no 429). That is the finding: no rate limiting.
  - PASS  — the target throttled at least one request (any 429), OR the run is
            not a burst (< ``min_burst`` requests, e.g. a single legitimate
            request — the benign positive control). One request proves nothing
            about rate limiting, so it is never a finding.
  - ERROR — no request results were recorded, so there is nothing to judge.

Evidence: ``request_count``, ``status_codes`` (list), ``count_429``,
``total_wall_time_s`` (sum of the per-request round-trip latencies — the burst is
issued sequentially, so this is the wall time), ``effective_req_per_s``.
"""
from __future__ import annotations

from typing import Optional

from contracts.contracts import AttackCase, AttackRun, Verdict

from ._common import OracleResult, as_list, error

# A single request tells us nothing about rate limiting; a burst needs at least
# this many requests before "no throttle" is a finding. Overridable per case.
DEFAULT_MIN_BURST = 2


def _as_int(value: object) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def rate_limit_oracle(case: AttackCase, run: AttackRun, audit: Optional[list[dict]] = None) -> OracleResult:
    results = run.request_results
    if not results:
        return error("no request_results recorded on the run: the burst execution path "
                     "did not run, so rate limiting cannot be evaluated")

    cfg = case.oracle_config or {}
    min_burst = _as_int(cfg.get("min_burst")) or DEFAULT_MIN_BURST
    # 429 is always a throttle; a case may add more (e.g. 503 with Retry-After).
    throttle_statuses = {429} | {s for s in (_as_int(x) for x in as_list(cfg.get("throttle_statuses"))) if s}

    statuses = [_as_int(r.get("status_code")) for r in results]
    latencies_ms = [lm for lm in (r.get("latency_ms") for r in results) if isinstance(lm, (int, float))]

    request_count = len(results)
    count_429 = sum(1 for s in statuses if s == 429)
    throttled = sum(1 for s in statuses if s in throttle_statuses)

    total_wall_time_s = round(sum(latencies_ms) / 1000.0, 6)
    effective_req_per_s = round(request_count / total_wall_time_s, 3) if total_wall_time_s > 0 else None

    is_burst = request_count >= min_burst
    # The finding: an actual burst that the target throttled on NONE of.
    no_rate_limiting = is_burst and throttled == 0

    evidence = {
        "no_rate_limiting": no_rate_limiting,
        "is_burst": is_burst,
        "min_burst": min_burst,
        "request_count": request_count,
        "status_codes": statuses,
        "count_429": count_429,
        "throttle_statuses": sorted(throttle_statuses),
        "count_throttled": throttled,
        "total_wall_time_s": total_wall_time_s,
        "effective_req_per_s": effective_req_per_s,
    }
    return (Verdict.FAIL if no_rate_limiting else Verdict.PASS), evidence
