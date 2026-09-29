"""Alert definitions over the store. Read-only: only ``list_runs()``, ``list_verdicts()`` and ``list_cases()``
are called.

    from aep.alerts import evaluate
    results = evaluate(store)                    # thresholds and window from env
    [r.key for r in results if r.firing]

Three alerts, each over the runs started inside the window (default: the last 24 h):

  p95_latency          p95 of end-to-end run latency (sum of AttackRun.latency_ms_by_step, the dashboard's
                       "Latency p95") above ALERT_P95_LATENCY_MS. Runs with no recorded steps are left out.
  error_rate           share of judged runs whose verdicts are all ERROR (the run could not be evaluated; the
                       dashboard's "error" bucket) above ALERT_ERROR_RATE. Runs with no verdict yet are left out,
                       and so are ERRORs on cases tagged expected-inconclusive (aep/limitations.py): those are
                       documented skips, the dashboard's "skipped", not platform errors.
  target_failure_rate  share of runs with at least one target or tool failure above ALERT_TARGET_FAILURE_RATE.
                       A failure is an HTTP 408, 429 or 5xx from the target in the transcript, or an observed tool
                       call reporting an error (outcome/status error|failed|failure|timeout, an error_type, or a
                       status_code of 408, 429 or 5xx). Other 4xx are the target refusing, which is a defence.

An alert with fewer than ALERT_MIN_SAMPLES (default 5) runs in its denominator is ``insufficient_data``, never
firing. ALERT_WINDOW_HOURS sets the window; 0 means all runs in the store. On-call actions: docs/ALERTS.md.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional

from aep.limitations import expected_map
from contracts.contracts import AttackRun, JudgeVerdict, Verdict

FIRING, OK, INSUFFICIENT = "firing", "ok", "insufficient_data"
RUNBOOK = "docs/ALERTS.md"
EXAMPLE_LIMIT = 5

FAILURE_STATUSES = frozenset({408, 429})  # plus every 5xx
FAILURE_OUTCOMES = frozenset({"error", "failed", "failure", "timeout", "timed_out"})
# The three shapes the Red Team writes a target response into an assistant turn (aep/agents/red_team.py).
_STATUS_RES = (
    re.compile(r'"status_code":\s*(\d{3})'),       # _describe_response: {"body": ..., "status_code": 503}
    re.compile(r"^\[(?:upload )?status=(\d{3})"),  # _reply_text / _describe_upload fallbacks
)


@dataclass(frozen=True)
class AlertDef:
    key: str
    title: str
    env: str
    default: float
    unit: str  # "ms" or "ratio"
    measures: str

    @property
    def runbook(self) -> str:
        return f"{RUNBOOK}#{self.key}"


DEFINITIONS: tuple[AlertDef, ...] = (
    AlertDef("p95_latency", "Run latency p95", "ALERT_P95_LATENCY_MS", 60_000.0, "ms",
             "p95 of end-to-end run latency (sum of latency_ms_by_step)"),
    AlertDef("error_rate", "Evaluation error rate", "ALERT_ERROR_RATE", 0.10, "ratio",
             "judged runs whose verdicts are all ERROR / judged runs"),
    AlertDef("target_failure_rate", "Tool/target failure rate", "ALERT_TARGET_FAILURE_RATE", 0.05, "ratio",
             "runs with a target 408/429/5xx or a failed tool call / runs"),
)
BY_KEY = {d.key: d for d in DEFINITIONS}


@dataclass(frozen=True)
class Settings:
    thresholds: Mapping[str, float]
    window_hours: float = 24.0  # 0 = every run in the store
    min_samples: int = 5


@dataclass
class AlertResult:
    key: str
    title: str
    state: str
    value: Optional[float]
    threshold: float
    unit: str
    samples: int
    detail: str
    runbook: str
    breakdown: dict[str, Any] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)  # correlation ids, for the Langfuse trace

    @property
    def firing(self) -> bool:
        return self.state == FIRING

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _number(env: Mapping[str, str], key: str, default: float, *, minimum: float = 0.0,
            maximum: Optional[float] = None) -> float:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{key}={raw!r} is not a number") from None
    if value < minimum or (maximum is not None and value > maximum):
        bound = f"between {minimum:g} and {maximum:g}" if maximum is not None else f">= {minimum:g}"
        raise ValueError(f"{key}={raw!r} must be {bound}")
    return value


def settings_from_env(env: Optional[Mapping[str, str]] = None, **overrides: Optional[float]) -> Settings:
    """Thresholds from ALERT_* env, then any non-None override (keyed by alert key, window_hours,
    min_samples). A malformed value raises ValueError naming the variable: a silently defaulted
    threshold is worse than a loud one."""
    env = os.environ if env is None else env
    thresholds = {d.key: _number(env, d.env, d.default, maximum=1.0 if d.unit == "ratio" else None)
                  for d in DEFINITIONS}
    window = _number(env, "ALERT_WINDOW_HOURS", 24.0)
    min_samples = int(_number(env, "ALERT_MIN_SAMPLES", 5, minimum=1))
    for key, value in overrides.items():
        if value is None:
            continue
        if key in thresholds:
            if value < 0 or (BY_KEY[key].unit == "ratio" and value > 1):
                raise ValueError(f"{key} threshold {value:g} out of range")
            thresholds[key] = float(value)
        elif key == "window_hours":
            window = float(value)
        elif key == "min_samples":
            min_samples = max(1, int(value))
        else:
            raise TypeError(f"unknown override {key!r}")
    return Settings(thresholds=thresholds, window_hours=window, min_samples=min_samples)


# --------------------------------------------------------------------------- #
# Signals
# --------------------------------------------------------------------------- #
def percentile(values: Iterable[float], q: float) -> Optional[float]:
    """Linear-interpolated percentile (numpy's default), q in [0, 100]. None for no values."""
    xs = sorted(values)
    if not xs:
        return None
    pos = (len(xs) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def _is_failure_status(status: Any) -> bool:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return code in FAILURE_STATUSES or code >= 500


def target_failures(run: AttackRun) -> list[str]:
    """Why this run counts as a tool/target failure; empty when it doesn't."""
    reasons: list[str] = []
    for turn in run.transcript:
        if turn.role != "assistant":
            continue
        for pattern in _STATUS_RES:
            m = pattern.search(turn.content)
            if m and _is_failure_status(m.group(1)):
                reasons.append(f"target HTTP {m.group(1)}")
                break
    for call in run.tool_calls_observed:
        if not isinstance(call, dict):
            continue
        tool = call.get("tool") or call.get("name") or "tool"
        outcome = str(call.get("outcome") or call.get("status") or "").lower()
        if outcome in FAILURE_OUTCOMES:
            reasons.append(f"{tool} {outcome}")
        elif call.get("error_type"):
            reasons.append(f"{tool} {call['error_type']}")
        elif _is_failure_status(call.get("status_code")):
            reasons.append(f"{tool} HTTP {call['status_code']}")
    return reasons


def _error_reason(v: JudgeVerdict) -> str:
    ev = v.oracle_evidence or {}
    reason = str(ev.get("reason") or ev.get("error") or "no reason recorded")
    return f"{v.oracle_used.value}: {reason}"


def _in_window(runs: list[AttackRun], settings: Settings, now: datetime) -> list[AttackRun]:
    if not settings.window_hours:
        return runs
    since = now - timedelta(hours=settings.window_hours)
    return [r for r in runs if _aware(r.started_at) >= since]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _top(counter: Counter, n: int = 5) -> dict[str, int]:
    return dict(counter.most_common(n))


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def _result(d: AlertDef, settings: Settings, value: Optional[float], samples: int, detail: str,
            breakdown: dict[str, Any], examples: list[str]) -> AlertResult:
    threshold = settings.thresholds[d.key]
    if samples < settings.min_samples or value is None:
        state = INSUFFICIENT
        detail = f"{samples} of {settings.min_samples} samples needed" + (f"; {detail}" if detail else "")
    else:
        state = FIRING if value > threshold else OK
    return AlertResult(key=d.key, title=d.title, state=state, value=value, threshold=threshold, unit=d.unit,
                       samples=samples, detail=detail, runbook=d.runbook, breakdown=breakdown,
                       examples=examples[:EXAMPLE_LIMIT])


def _p95_latency(runs: list[AttackRun], settings: Settings) -> AlertResult:
    timed = [r for r in runs if r.latency_ms_by_step]
    totals = {r.correlation_id: sum(r.latency_ms_by_step.values()) for r in timed}
    by_step: dict[str, list[float]] = defaultdict(list)
    for r in timed:
        for step, ms in r.latency_ms_by_step.items():
            by_step[step].append(ms)
    step_p95 = {s: round(percentile(v, 95) or 0.0, 1) for s, v in by_step.items()}
    value = percentile(totals.values(), 95)
    threshold = settings.thresholds["p95_latency"]
    slow = sorted((c for c, t in totals.items() if t > threshold), key=lambda c: -totals[c])
    detail = f"{len(slow)} of {len(timed)} runs over {threshold:g} ms" if timed else "no runs with latency"
    return _result(BY_KEY["p95_latency"], settings, value, len(timed), detail,
                   {"p95_ms_by_step": dict(sorted(step_p95.items(), key=lambda kv: -kv[1]))}, slow)


def _error_rate(runs: list[AttackRun], verdicts: list[JudgeVerdict], settings: Settings,
                expected: Mapping[str, str]) -> AlertResult:
    by_run: dict[str, list[JudgeVerdict]] = defaultdict(list)
    for v in verdicts:
        by_run[v.run_id].append(v)
    judged = [r for r in runs if by_run.get(r.run_id)]
    all_error = {r.run_id for r in judged if all(v.verdict == Verdict.ERROR for v in by_run[r.run_id])}
    skips = [r for r in judged if r.run_id in all_error and r.case_id in expected]
    judged = [r for r in judged if not (r.run_id in all_error and r.case_id in expected)]
    errored = [r for r in judged if r.run_id in all_error]
    reasons = Counter(_error_reason(v) for r in errored for v in by_run[r.run_id])
    value = len(errored) / len(judged) if judged else None
    unjudged = len(runs) - len(judged) - len(skips)
    detail = f"{len(errored)} of {len(judged)} judged runs errored"
    if unjudged:
        detail += f"; {unjudged} not judged yet"
    if skips:
        detail += f"; {len(skips)} expected skips (documented limitation) excluded"
    return _result(BY_KEY["error_rate"], settings, value, len(judged), detail,
                   {"reasons": _top(reasons)}, [r.correlation_id for r in errored])


def _target_failure_rate(runs: list[AttackRun], settings: Settings) -> AlertResult:
    failing = {r.correlation_id: target_failures(r) for r in runs}
    failing = {c: why for c, why in failing.items() if why}
    kinds = Counter(reason for why in failing.values() for reason in set(why))
    value = len(failing) / len(runs) if runs else None
    return _result(BY_KEY["target_failure_rate"], settings, value, len(runs),
                   f"{len(failing)} of {len(runs)} runs hit a target or tool failure",
                   {"failures": _top(kinds)}, list(failing))


def evaluate(store: Any, settings: Optional[Settings] = None, *, now: Optional[datetime] = None
             ) -> list[AlertResult]:
    """Every alert in DEFINITIONS order. Calls only store.list_runs(), list_verdicts() and list_cases()."""
    settings = settings or settings_from_env()
    now = now or datetime.now(timezone.utc)
    runs = _in_window(store.list_runs(), settings, now)
    ids = {r.run_id for r in runs}
    verdicts = [v for v in store.list_verdicts() if v.run_id in ids]
    return [
        _p95_latency(runs, settings),
        _error_rate(runs, verdicts, settings, expected_map(store.list_cases())),
        _target_failure_rate(runs, settings),
    ]


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #
def format_value(value: Optional[float], unit: str) -> str:
    if value is None:
        return "—"
    return f"{value:.0f} ms" if unit == "ms" else f"{value:.1%}"


def format_text(results: list[AlertResult], settings: Settings) -> str:
    window = f"last {settings.window_hours:g} h" if settings.window_hours else "all runs"
    lines = [f"alerts over {window} (min {settings.min_samples} samples)"]
    for r in results:
        lines.append(f"  [{r.state.upper():17}] {r.key:20} {format_value(r.value, r.unit):>9} "
                     f"(threshold {format_value(r.threshold, r.unit)})  {r.detail}")
        for name, items in r.breakdown.items():
            if items:
                lines.append(f"      {name}: {json.dumps(items)}")
        if r.firing:
            if r.examples:
                lines.append(f"      examples: {', '.join(r.examples)}")
            lines.append(f"      runbook: {r.runbook}")
    return "\n".join(lines)
