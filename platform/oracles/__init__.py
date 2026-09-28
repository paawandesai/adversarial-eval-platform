"""Deterministic verdict oracles — the core of the Judge.

Each oracle is a pure function (case, run, audit) -> (Verdict, evidence) | None
conforming to contracts.interfaces.Oracle. They decide attack success from
EVIDENCE (response text, audit rows, traces, counters, HTTP status), never from
model opinion. `None` means the oracle does not apply (its config is absent).

`audit` is the grey-box record list the Judge fetched for the run's
correlation_id: tool-call rows for TOOL_CALL_AUDIT, log/trace records for
LOG_SCAN. Other oracles ignore it.
"""
from __future__ import annotations

from typing import Optional

from contracts.contracts import AttackCase, AttackRun, JudgeVerdict, OracleType, Verdict
from contracts.interfaces import Oracle

from .canary import canary_oracle
from .http_assert import http_assert_oracle
from .log_scan import DEFAULT_PHI_PATTERNS, log_scan_oracle
from .token_counter import token_counter_oracle
from .tool_call_audit import tool_call_audit_oracle

ORACLES: dict[OracleType, Oracle] = {
    OracleType.CANARY: canary_oracle,
    OracleType.TOOL_CALL_AUDIT: tool_call_audit_oracle,
    OracleType.LOG_SCAN: log_scan_oracle,
    OracleType.TOKEN_COUNTER: token_counter_oracle,
    OracleType.HTTP_ASSERT: http_assert_oracle,
}


def judge_deterministic(case: AttackCase, run: AttackRun,
                        audit: Optional[list[dict]] = None) -> Optional[JudgeVerdict]:
    """Dispatch on case.oracle. None only for LLM_JUDGE (the semantic judge's job).

    A deterministic case whose oracle can't reach a verdict (missing config,
    oracle crash) yields ERROR rather than None, so it is never silently
    handed to the LLM judge.
    """
    if case.oracle == OracleType.LLM_JUDGE:
        return None

    oracle = ORACLES.get(case.oracle)
    if oracle is None:
        verdict, evidence = Verdict.ERROR, {"reason": f"no deterministic oracle registered for {case.oracle.value}"}
    else:
        try:
            result = oracle(case, run, audit)
        except Exception as exc:  # an oracle bug must not take down the judge loop
            result = Verdict.ERROR, {"reason": "oracle raised", "error": f"{type(exc).__name__}: {exc}"}
        if result is None:
            result = Verdict.ERROR, {"reason": "oracle_config missing the keys this oracle needs",
                                     "oracle_config": case.oracle_config}
        verdict, evidence = result

    return JudgeVerdict(
        run_id=run.run_id,
        case_id=case.case_id,
        correlation_id=run.correlation_id,
        verdict=verdict,
        oracle_used=case.oracle,
        oracle_evidence=evidence,
    )


__all__ = [
    "ORACLES",
    "DEFAULT_PHI_PATTERNS",
    "judge_deterministic",
    "canary_oracle",
    "tool_call_audit_oracle",
    "log_scan_oracle",
    "token_counter_oracle",
    "http_assert_oracle",
]
