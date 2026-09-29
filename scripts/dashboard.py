"""Read-only platform dashboard over the SQLite store.

    python3 scripts/dashboard.py                          # seeds.db -> dashboard.html
    python3 scripts/dashboard.py --db seeds.db --out /tmp/aep.html
    python3 scripts/dashboard.py --serve --port 8765      # re-reads the store on every request
    python3 scripts/dashboard.py --serve --watch          # + auto-refresh live as a campaign writes

When serving, /health and /ready answer as in aep/health.py (liveness, and dependency readiness with a 503).

The store is opened with ``SqliteStore.open_readonly`` (SQLite ``mode=ro``), so nothing here can write to it.
The page is one self-contained HTML file: inline CSS and JS, no external requests.

Langfuse links (env)
--------------------
    LANGFUSE_HOST           e.g. https://langfuse.example.com
    LANGFUSE_PROJECT_PATH   path between host and /traces, e.g. /project/cm1abc2def   (wins if set)
    LANGFUSE_PROJECT_ID     shorthand for LANGFUSE_PROJECT_PATH=/project/<id>
Without a host and a project, rows show the correlation_id without a link. The trace id is derived from the
correlation_id exactly as aep.obs.tracing does it (Langfuse ``create_trace_id(seed=correlation_id)``).

Aggregation functions take plain model lists (or a Store-shaped object) so they are testable with a fake.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import os
import pathlib
import sys
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, Mapping, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from aep.agents.documentation import REVIEW_SEVERITIES  # noqa: E402
from aep import health  # noqa: E402
from aep.agents.judge import needs_human_review  # noqa: E402
from aep.limitations import expected_map  # noqa: E402
from aep.store.sqlite_store import _WORST_RANK, SqliteStore  # noqa: E402
from contracts.contracts import (  # noqa: E402
    AttackCase, AttackCategory, AttackRun, JudgeVerdict, OracleType, Severity, Verdict, VulnerabilityReport,
)

# Run outcome buckets, plus "unjudged" where it applies. "skipped" is an ERROR on a case whose seed documents it
# as expected-inconclusive (aep.limitations): shown apart so it doesn't read as a platform error.
OUTCOMES = ("pass", "partial", "fail", "error", "skipped")
SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
FEED_LIMIT = 100


# --------------------------------------------------------------------------- #
# Small helpers
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


def langfuse_trace_id(correlation_id: str) -> str:
    """Same derivation as Langfuse.create_trace_id(seed=...), which aep.obs.tracing uses per correlation_id."""
    return hashlib.sha256(correlation_id.encode("utf-8")).digest()[:16].hex()


def langfuse_trace_url(correlation_id: Optional[str], env: Mapping[str, str]) -> Optional[str]:
    host = (env.get("LANGFUSE_HOST") or "").rstrip("/")
    path = env.get("LANGFUSE_PROJECT_PATH") or (
        f"/project/{env['LANGFUSE_PROJECT_ID']}" if env.get("LANGFUSE_PROJECT_ID") else "")
    if not (correlation_id and host and path):
        return None
    return f"{host}/{path.strip('/')}/traces/{langfuse_trace_id(correlation_id)}"


def worst_by_run(verdicts: Iterable[JudgeVerdict]) -> dict[str, Verdict]:
    """run_id -> worst verdict across its oracles (fail > partial > pass > error), as SqliteStore.coverage()."""
    out: dict[str, Verdict] = {}
    for v in verdicts:
        cur = out.get(v.run_id)
        if cur is None or _WORST_RANK[v.verdict] > _WORST_RANK[cur]:
            out[v.run_id] = v.verdict
    return out


def outcome(verdict: str, case_id: str, expected: Mapping[str, str]) -> str:
    """The displayed bucket for a verdict value: ERROR on a documented-limitation case is "skipped"."""
    return "skipped" if verdict == Verdict.ERROR.value and case_id in expected else verdict


def _short(text: str, limit: int = 140) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# --------------------------------------------------------------------------- #
# Aggregations
# --------------------------------------------------------------------------- #
def header_stats(runs: list[AttackRun], verdicts: list[JudgeVerdict],
                 reports: list[VulnerabilityReport], expected: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    """Verdict counts are per verdict row. Latency is end-to-end per run (sum of its steps); runs with no
    recorded steps are left out of the percentiles rather than counted as 0 ms."""
    expected = expected or {}
    counts = Counter(outcome(v.verdict.value, v.case_id, expected) for v in verdicts)
    totals = [sum(r.latency_ms_by_step.values()) for r in runs if r.latency_ms_by_step]
    return {
        "runs": len(runs),
        "verdicts": len(verdicts),
        **{k: counts.get(k, 0) for k in OUTCOMES},
        "findings": len(reports),
        "cost_usd": sum(r.cost_usd for r in runs),
        "latency_p50_ms": percentile(totals, 50),
        "latency_p95_ms": percentile(totals, 95),
        "latency_samples": len(totals),
    }


def coverage_matrix(coverage: Mapping[str, Mapping[str, Any]], cases: list[AttackCase],
                    runs: list[AttackRun], verdicts: list[JudgeVerdict]) -> list[dict[str, Any]]:
    """One row per AttackCategory (enum order), zero-coverage ones included and flagged ``gap``.

    runs/pass/fail/partial/cost_usd come from store.coverage(). It has no error bucket, so ``error`` (runs whose
    only verdicts are ERROR), ``skipped`` (those runs on expected-inconclusive cases) and ``unjudged`` (the
    rest) are derived here with the same worst-verdict rule.
    """
    case_by_id = {c.case_id: c for c in cases}
    expected = expected_map(cases)
    worst = worst_by_run(verdicts)
    errors: Counter = Counter()
    skipped: Counter = Counter()
    for r in runs:
        case = case_by_id.get(r.case_id)
        if case is not None and worst.get(r.run_id) == Verdict.ERROR:
            (skipped if case.case_id in expected else errors)[case.category.value] += 1
    n_cases = Counter(c.category.value for c in cases)
    n_regression = Counter(c.category.value for c in cases if c.in_regression_suite)

    categories = [c.value for c in AttackCategory]
    categories += sorted(set(coverage) - set(categories))  # anything the store knows that the enum doesn't
    rows = []
    for cat in categories:
        cov = coverage.get(cat, {})
        count = int(cov.get("count", 0))
        row = {
            "category": cat,
            "cases": n_cases.get(cat, 0),
            "in_regression": n_regression.get(cat, 0),
            "runs": count,
            "pass": int(cov.get("pass", 0)),
            "fail": int(cov.get("fail", 0)),
            "partial": int(cov.get("partial", 0)),
            "error": errors.get(cat, 0),
            "skipped": skipped.get(cat, 0),
            "cost_usd": float(cov.get("cost_usd", 0.0)),
        }
        row["unjudged"] = max(count - row["pass"] - row["fail"] - row["partial"] - row["error"] - row["skipped"], 0)
        row["gap"] = count == 0
        rows.append(row)
    return rows


def evidence_summary(v: JudgeVerdict) -> str:
    """One line a human can scan: what the oracle actually saw."""
    ev = v.oracle_evidence or {}
    parts: list[str] = []
    if needs_human_review(v):
        parts.append(f"needs human review (proposed {ev.get('proposed_verdict', '?')})")

    if v.oracle_used == OracleType.CANARY and "canary_hit" in ev:
        if ev.get("canary_hit"):
            hits = ev.get("hits") or []
            parts.append(f"canary hit: {ev.get('match')}" + (f" ({_plural(len(hits), 'hit')})" if len(hits) > 1 else ""))
        else:
            parts.append(f"no canary in {_plural(int(ev.get('responses_checked', 0)), 'response')}")
    elif v.oracle_used in (OracleType.TOOL_CALL_AUDIT, OracleType.HTTP_ASSERT) and "violations" in ev:
        violations = ev.get("violations") or []
        if violations:
            first = violations[0]
            detail = first.get("reason") or first.get("assertion") or first.get("tool") or ""
            parts.append(f"{_plural(len(violations), 'violation')}" + (f": {detail}" if detail else ""))
        elif v.oracle_used == OracleType.TOOL_CALL_AUDIT:
            parts.append(f"no violations in {_plural(int(ev.get('tool_calls_checked', 0)), 'tool call')}")
        else:
            parts.append(f"no violations, statuses {ev.get('statuses', [])}")
    elif v.oracle_used == OracleType.LOG_SCAN and "phi_in_logs" in ev:
        hits = ev.get("hits") or []
        parts.append(f"PHI in logs: {', '.join(sorted({h.get('rule', '?') for h in hits}))}" if hits
                     else f"no PHI in {_plural(int(ev.get('records_scanned', 0)), 'record')}")
    elif v.oracle_used == OracleType.TOKEN_COUNTER and "budget_exceeded" in ev:
        parts.append(f"budget exceeded: {ev.get('exceeded')}" if ev.get("budget_exceeded")
                     else f"within budget ({ev.get('tokens_total', 0)} tokens)")
    elif v.oracle_used == OracleType.LLM_JUDGE and v.judge_rationale:
        conf = f" [{v.judge_confidence:.2f}]" if v.judge_confidence is not None else ""
        parts.append(f"{v.judge_rationale}{conf}")

    if ev.get("reason") or ev.get("error"):
        parts.append(" — ".join(str(ev[k]) for k in ("reason", "error") if ev.get(k)))
    audit = ev.get("audit")
    if isinstance(audit, dict) and audit.get("status") not in (None, "ok", "not_needed"):
        parts.append(f"audit: {audit['status']}")
    if not parts:  # unknown shape: first few scalar fields
        scalars = [f"{k}={val}" for k, val in ev.items() if isinstance(val, (str, int, float, bool))][:3]
        parts.append(", ".join(scalars) or "no evidence recorded")
    return _short(" · ".join(parts))


def verdict_feed(verdicts: list[JudgeVerdict], env: Mapping[str, str],
                 limit: int = FEED_LIMIT, expected: Optional[Mapping[str, str]] = None) -> list[dict[str, Any]]:
    """Most recent first (evaluated_at), capped at ``limit``. A skipped row's evidence leads with the
    documented reason."""
    expected = expected or {}
    recent = sorted(verdicts, key=lambda v: v.evaluated_at, reverse=True)[:limit]
    rows = []
    for v in recent:
        shown = outcome(v.verdict.value, v.case_id, expected)
        evidence = evidence_summary(v)
        if shown == "skipped":
            evidence = _short(f"expected-inconclusive: {expected[v.case_id]} · {evidence}")
        rows.append({
            "evaluated_at": v.evaluated_at,
            "verdict": shown,
            "oracle_used": v.oracle_used.value,
            "case_id": v.case_id,
            "run_id": v.run_id,
            "correlation_id": v.correlation_id,
            "needs_human_review": needs_human_review(v),
            "evidence": evidence,
            "trace_url": langfuse_trace_url(v.correlation_id, env),
        })
    return rows


def load_reviews(store: Any) -> dict[str, bool]:
    """vuln_id -> pending_human_review from Documentation's ``report_reviews`` sidecar table, read-only.

    Read directly rather than through SqliteReviewLedger, whose constructor runs CREATE TABLE.
    """
    conn = getattr(store, "_conn", None)
    if conn is None:
        return {}
    try:
        rows = conn.execute("SELECT vuln_id, pending_human_review FROM report_reviews").fetchall()
    except Exception:  # table absent: nothing has been documented yet
        return {}
    return {r[0]: bool(r[1]) for r in rows}


def _finding_correlation(report: VulnerabilityReport, runs_by_case: Mapping[str, list[AttackRun]],
                         verdicts_by_run: Mapping[str, list[JudgeVerdict]]) -> Optional[str]:
    """Reports carry no correlation_id, so link the repro case's most recent failing run (else its latest run)."""
    runs = runs_by_case.get(report.repro_case_id, [])
    failing = [v for r in runs for v in verdicts_by_run.get(r.run_id, []) if v.verdict == Verdict.FAIL]
    if failing:
        return max(failing, key=lambda v: v.evaluated_at).correlation_id
    return max(runs, key=lambda r: r.started_at).correlation_id if runs else None


def findings_table(reports: list[VulnerabilityReport], runs: list[AttackRun], verdicts: list[JudgeVerdict],
                   reviews: Mapping[str, bool], env: Mapping[str, str]) -> list[dict[str, Any]]:
    """Critical first, then newest. ``pending_human_review`` follows Documentation.is_pending_review: the
    ledger's answer if there is one, else fail closed for critical/high."""
    runs_by_case: dict[str, list[AttackRun]] = defaultdict(list)
    for r in runs:
        runs_by_case[r.case_id].append(r)
    verdicts_by_run: dict[str, list[JudgeVerdict]] = defaultdict(list)
    for v in verdicts:
        verdicts_by_run[v.run_id].append(v)

    ordered = sorted(reports, key=lambda r: r.created_at, reverse=True)
    ordered.sort(key=lambda r: SEVERITY_ORDER.get(r.severity, 99))  # stable: newest first within a severity
    rows = []
    for r in ordered:
        corr = _finding_correlation(r, runs_by_case, verdicts_by_run)
        rows.append({
            "vuln_id": r.vuln_id,
            "severity": r.severity.value,
            "category": r.category.value,
            "owasp": [o.value for o in r.owasp.classic] + [o.value for o in r.owasp.llm],
            "title": r.title,
            "status": r.status.value,
            "pending_human_review": reviews[r.vuln_id] if r.vuln_id in reviews
            else r.severity in REVIEW_SEVERITIES,
            "repro_case_id": r.repro_case_id,
            "first_seen_version": r.first_seen_version,
            "last_seen_version": r.last_seen_version,
            "correlation_id": corr,
            "trace_url": langfuse_trace_url(corr, env),
        })
    return rows


def version_breakdown(runs: list[AttackRun], verdicts: list[JudgeVerdict],
                      expected: Optional[Mapping[str, str]] = None) -> list[dict[str, Any]]:
    """Run outcomes per target_version, oldest version first (by its earliest run).

    ``regressions`` / ``fixes`` compare each version with the one before it, over cases run at both:
    a case whose worst verdict went PASS -> FAIL regressed; FAIL -> PASS is a fix.
    """
    expected = expected or {}
    worst = worst_by_run(verdicts)
    by_version: dict[str, list[AttackRun]] = defaultdict(list)
    for r in runs:
        by_version[r.target_version].append(r)
    order = sorted(by_version, key=lambda ver: min(r.started_at for r in by_version[ver]))

    rows, prev_cases = [], None
    for ver in order:
        vruns = by_version[ver]
        mix = Counter(outcome(worst[r.run_id].value, r.case_id, expected) if r.run_id in worst else "unjudged"
                      for r in vruns)
        case_worst: dict[str, Verdict] = {}
        for r in vruns:
            w = worst.get(r.run_id)
            if w is not None and (r.case_id not in case_worst or _WORST_RANK[w] > _WORST_RANK[case_worst[r.case_id]]):
                case_worst[r.case_id] = w
        row = {
            "target_version": ver,
            "runs": len(vruns),
            "cases": len({r.case_id for r in vruns}),
            **{k: mix.get(k, 0) for k in (*OUTCOMES, "unjudged")},
            "cost_usd": sum(r.cost_usd for r in vruns),
            "first_run": min(r.started_at for r in vruns),
            "regressions": None, "fixes": None,
        }
        if prev_cases is not None:
            shared = set(prev_cases) & set(case_worst)
            row["regressions"] = sum(prev_cases[c] == Verdict.PASS and case_worst[c] == Verdict.FAIL for c in shared)
            row["fixes"] = sum(prev_cases[c] == Verdict.FAIL and case_worst[c] == Verdict.PASS for c in shared)
        judged = row["pass"] + row["fail"] + row["partial"]
        row["fail_rate"] = row["fail"] / judged if judged else None
        rows.append(row)
        prev_cases = case_worst
    return rows


def build(store: Any, env: Optional[Mapping[str, str]] = None, reviews: Optional[Mapping[str, bool]] = None,
          source: str = "", notice: str = "") -> dict[str, Any]:
    """Everything the page shows. Reads only: list_* and coverage()."""
    env = os.environ if env is None else env
    cases, runs = store.list_cases(), store.list_runs()
    verdicts, reports = store.list_verdicts(), store.list_reports()
    reviews = load_reviews(store) if reviews is None else reviews
    expected = expected_map(cases)
    return {
        "generated_at": datetime.now(timezone.utc),
        "source": source,
        "notice": notice,
        "langfuse_linked": langfuse_trace_url("x", env) is not None,
        "stats": header_stats(runs, verdicts, reports, expected),
        "coverage": coverage_matrix(store.coverage(), cases, runs, verdicts),
        "feed": verdict_feed(verdicts, env, expected=expected),
        "feed_total": len(verdicts),
        "findings": findings_table(reports, runs, verdicts, reviews, env),
        "versions": version_breakdown(runs, verdicts, expected),
    }


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_CSS = """
:root{color-scheme:light;--bg:#f4f4f2;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#8a8984;
--line:#e3e2dd;--row:#f7f7f5;--good:#0ca30c;--warn:#fab219;--serious:#ec835a;--crit:#d03b3b;--neutral:#9b9a94;
--unjudged:#d6d5cf;--link:#2a78d6;--gapbg:#fdf3f0}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#111110;--surface:#1a1a19;
--ink:#fff;--ink2:#c3c2b7;--muted:#8f8e86;--line:#2e2e2c;--row:#20201f;--neutral:#8f8e86;--unjudged:#3a3a37;
--link:#6aa7ef;--gapbg:#2a1d19}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#111110;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#8f8e86;
--line:#2e2e2c;--row:#20201f;--neutral:#8f8e86;--unjudged:#3a3a37;--link:#6aa7ef;--gapbg:#2a1d19}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",
Roboto,Helvetica,Arial,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:8px;margin-bottom:16px}
h1{font-size:20px;margin:0}h2{font-size:15px;margin:0 0 4px}
.sub{color:var(--ink2);font-size:12px;overflow-wrap:anywhere}
section{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:16px;margin-top:16px}
.sechead{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:8px;margin-bottom:12px}
.notice{overflow-wrap:anywhere;background:var(--gapbg);border:1px solid var(--serious);border-radius:8px;padding:10px 14px;margin-top:12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:14px}
.tile .k{color:var(--ink2);font-size:12px}.tile .v{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}
.tile .d{color:var(--ink2);font-size:12px;margin-top:4px;display:flex;flex-wrap:wrap;gap:4px 10px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal;min-width:240px}
th{font-size:12px;color:var(--ink2);font-weight:600;cursor:pointer;user-select:none;position:sticky;top:0;
background:var(--surface)}
th[data-dir="asc"]::after{content:" ▲"}th[data-dir="desc"]::after{content:" ▼"}
td.n,th.n{text-align:right}
tbody tr:hover{background:var(--row)}
tr.gap td{background:var(--gapbg)}tr.gap td.cat{font-weight:600}
.zero{color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.chip{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--ink)}
.chip::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--c,var(--neutral))}
.c-pass{--c:var(--good)}.c-fail{--c:var(--crit)}.c-partial{--c:var(--warn)}.c-error{--c:var(--neutral)}
.c-skipped{--c:var(--unjudged)}
.c-critical{--c:var(--crit)}.c-high{--c:var(--serious)}.c-medium{--c:var(--warn)}.c-low,.c-info{--c:var(--neutral)}
.c-gap{--c:var(--serious)}
.flag{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:1px 6px;color:var(--ink2)}
.flag.on{border-color:var(--serious);color:var(--ink)}
.bar{display:flex;gap:2px;width:160px;height:10px}
.bar span{display:block;height:100%;min-width:3px}
.bar span:first-child{border-radius:4px 0 0 4px}.bar span:last-child{border-radius:0 4px 4px 0}
.bar span:only-child{border-radius:4px}
.bar .empty{flex:1;background:var(--unjudged);opacity:.5;border-radius:4px}
.s-pass{background:var(--good)}.s-partial{background:var(--warn)}.s-fail{background:var(--crit)}
.s-error{background:var(--neutral)}.s-unjudged{background:var(--unjudged)}
.s-skipped{background:repeating-linear-gradient(45deg,var(--neutral) 0 2px,var(--unjudged) 2px 5px)}
.legend{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:12px;color:var(--ink2)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
select{font:inherit;font-size:12px;padding:3px 6px;border-radius:6px;border:1px solid var(--line);
background:var(--surface);color:var(--ink)}
.empty-state{color:var(--ink2);padding:18px 4px}
"""

_JS = """
document.querySelectorAll('table.sortable').forEach(function(t){
  t.querySelectorAll('th').forEach(function(th,i){
    th.addEventListener('click',function(){
      var dir=th.dataset.dir==='asc'?'desc':'asc';
      t.querySelectorAll('th').forEach(function(o){delete o.dataset.dir});th.dataset.dir=dir;
      var body=t.tBodies[0],rows=Array.prototype.slice.call(body.rows);
      rows.sort(function(a,b){
        var x=a.cells[i].dataset.sort!==undefined?a.cells[i].dataset.sort:a.cells[i].textContent.trim();
        var y=b.cells[i].dataset.sort!==undefined?b.cells[i].dataset.sort:b.cells[i].textContent.trim();
        var nx=parseFloat(x),ny=parseFloat(y),c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);
        return dir==='asc'?c:-c;
      });
      rows.forEach(function(r){body.appendChild(r)});
    });
  });
});
var f=document.getElementById('feed-filter');
if(f){f.addEventListener('change',function(){
  document.querySelectorAll('#feed tbody tr').forEach(function(r){
    r.style.display=(f.value===''||r.dataset.verdict===f.value)?'':'none';
  });
});}
"""

_OUTCOME_LABELS = {"pass": "pass — defended", "partial": "partial", "fail": "fail — attack succeeded",
                   "error": "error", "skipped": "skipped — expected (documented limitation)",
                   "unjudged": "unjudged"}


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _num(n: Any) -> str:
    return f'<td class="n{" zero" if not n else ""}">{_e(n)}</td>'


def _ts(dt: Optional[datetime]) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ") if dt else ""


def _ms(v: Optional[float]) -> str:
    if v is None:
        return "—"
    return f"{v / 1000:.2f} s" if v >= 1000 else f"{v:.0f} ms"


def _chip(kind: str, label: Optional[str] = None) -> str:
    return f'<span class="chip c-{_e(kind)}">{_e(label or kind)}</span>'


def _trace(url: Optional[str], corr: Optional[str]) -> str:
    if not corr:
        return '<span class="zero">—</span>'
    if url:
        return f'<a class="mono" href="{_e(url)}" target="_blank" rel="noopener" title="{_e(corr)}">trace ↗</a>'
    return (f'<span class="mono zero" title="{_e(corr)} (set LANGFUSE_HOST and LANGFUSE_PROJECT_ID to link)">'
            f'{_e(corr[:8])}…</span>')


def _bar(row: Mapping[str, int]) -> str:
    keys = (*OUTCOMES, "unjudged")
    total = sum(row.get(k, 0) for k in keys)
    if not total:
        return '<div class="bar" title="no runs"><span class="empty"></span></div>'
    segs = "".join(
        f'<span class="s-{k}" style="flex:{row[k]}" title="{_e(_OUTCOME_LABELS[k])}: {row[k]} of {total}"></span>'
        for k in keys if row.get(k))
    return f'<div class="bar" role="img" aria-label="{_e(", ".join(f"{k} {row[k]}" for k in keys if row.get(k)))}">{segs}</div>'


def _legend() -> str:
    return '<div class="legend">' + "".join(
        f'<span><i class="s-{k}"></i>{_e(_OUTCOME_LABELS[k])}</span>' for k in (*OUTCOMES, "unjudged")) + "</div>"


def _tiles(s: Mapping[str, Any]) -> str:
    breakdown = "".join(_chip(k, f"{k} {s[k]}") for k in OUTCOMES)
    tiles = [
        ("Runs", s["runs"], ""),
        ("Verdicts", s["verdicts"], breakdown),
        ("Findings", s["findings"], ""),
        ("Cost", f"${s['cost_usd']:.4f}", "sum of AttackRun.cost_usd"),
        ("Latency p50", _ms(s["latency_p50_ms"]), f"per run, {_plural(s['latency_samples'], 'sample')}"),
        ("Latency p95", _ms(s["latency_p95_ms"]), "summed across steps"),
    ]
    return '<div class="tiles">' + "".join(
        f'<div class="tile"><div class="k">{_e(k)}</div><div class="v">{_e(v)}</div>'
        f'<div class="d">{d}</div></div>' for k, v, d in tiles) + "</div>"


def _coverage(rows: list[dict[str, Any]]) -> str:
    gaps = sum(r["gap"] for r in rows)
    body = "".join(
        f'<tr class="{"gap" if r["gap"] else ""}"><td class="cat mono">{_e(r["category"])}'
        f'{" " + _chip("gap", "no runs") if r["gap"] else ""}</td>'
        + _num(r["cases"]) + _num(r["in_regression"]) + _num(r["runs"])
        + "".join(_num(r[k]) for k in (*OUTCOMES, "unjudged"))
        + f'<td class="n" data-sort="{r["cost_usd"]}">${r["cost_usd"]:.4f}</td><td>{_bar(r)}</td></tr>'
        for r in rows)
    return (
        f'<section><div class="sechead"><div><h2>Coverage by attack category</h2>'
        f'<div class="sub">{len(rows) - gaps} of {len(rows)} categories exercised · {gaps} with no runs. '
        f'Run outcome = worst verdict across its oracles.</div></div>{_legend()}</div>'
        '<div class="scroll"><table class="sortable"><thead><tr><th>Category</th><th class="n">Cases</th>'
        '<th class="n">In regression</th><th class="n">Runs</th><th class="n">Pass</th><th class="n">Partial</th>'
        '<th class="n">Fail</th><th class="n">Error</th><th class="n">Skipped</th><th class="n">Unjudged</th><th class="n">Cost</th>'
        f'<th>Outcome mix</th></tr></thead><tbody>{body}</tbody></table></div></section>')


def _feed(rows: list[dict[str, Any]], total: int) -> str:
    if not rows:
        return ('<section><h2>Verdict feed</h2><div class="empty-state">No verdicts yet. Run '
                '<span class="mono">python3 scripts/run_campaign_seeds.py</span> to judge the seed cases.</div></section>')
    review_flag = ' <span class="flag on">review</span>'
    body = "".join(
        f'<tr data-verdict="{_e(r["verdict"])}"><td class="mono">{_e(_ts(r["evaluated_at"]))}</td>'
        f'<td>{_chip(r["verdict"])}{review_flag if r["needs_human_review"] else ""}</td>'
        f'<td class="mono">{_e(r["oracle_used"])}</td><td class="mono">{_e(r["case_id"])}</td>'
        f'<td class="wrap">{_e(r["evidence"])}</td><td>{_trace(r["trace_url"], r["correlation_id"])}</td></tr>'
        for r in rows)
    options = "".join(f'<option value="{k}">{k}</option>' for k in OUTCOMES)
    shown = f"latest {len(rows)} of {total}" if total > len(rows) else f"{total} verdicts"
    return (
        f'<section><div class="sechead"><div><h2>Verdict feed</h2><div class="sub">{shown}, newest first</div></div>'
        f'<label class="sub">Show <select id="feed-filter"><option value="">all</option>{options}</select></label></div>'
        '<div class="scroll"><table id="feed" class="sortable"><thead><tr><th>Evaluated</th><th>Verdict</th>'
        '<th>Oracle</th><th>Case</th><th>Evidence</th><th>Trace</th></tr></thead>'
        f'<tbody>{body}</tbody></table></div></section>')


def _findings(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<section><h2>Findings</h2><div class="empty-state">No vulnerability reports yet.</div></section>'
    pending = sum(r["pending_human_review"] for r in rows)
    body = "".join(
        f'<tr><td class="mono">{_e(r["vuln_id"])}</td>'
        f'<td data-sort="{SEVERITY_ORDER.get(Severity(r["severity"]), 9)}">{_chip(r["severity"])}</td>'
        f'<td class="mono">{_e(r["category"])}</td><td class="mono">{"<br>".join(_e(o) for o in r["owasp"]) or "—"}</td>'
        f'<td class="wrap">{_e(r["title"])}</td><td>{_e(r["status"])}</td>'
        f'<td><span class="flag{" on" if r["pending_human_review"] else ""}">'
        f'{"pending" if r["pending_human_review"] else "approved"}</span></td>'
        f'<td class="mono">{_e(r["last_seen_version"] or "—")}</td><td>{_trace(r["trace_url"], r["correlation_id"])}</td></tr>'
        for r in rows)
    return (
        f'<section><div class="sechead"><div><h2>Findings</h2><div class="sub">{len(rows)} reports · {pending} pending '
        'human review · critical first. Trace = most recent failing run of the repro case.</div></div></div>'
        '<div class="scroll"><table class="sortable"><thead><tr><th>Vuln</th><th>Severity</th><th>Category</th>'
        '<th>OWASP</th><th>Title</th><th>Status</th><th>Review</th><th>Last seen</th><th>Trace</th></tr></thead>'
        f'<tbody>{body}</tbody></table></div></section>')


def _versions(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<section><h2>Target versions</h2><div class="empty-state">No runs yet.</div></section>'
    def delta(n: Optional[int]) -> str:
        return '<td class="n zero">—</td>' if n is None else _num(n)

    def rate(r: Mapping[str, Any]) -> str:
        if r["fail_rate"] is None:
            return '<td class="n zero" data-sort="-1">—</td>'
        return f'<td class="n" data-sort="{r["fail_rate"]}">{r["fail_rate"] * 100:.0f}%</td>'

    body = "".join(
        f'<tr><td class="mono">{_e(r["target_version"])}</td><td class="mono">{_e(_ts(r["first_run"]))}</td>'
        + _num(r["cases"]) + _num(r["runs"]) + "".join(_num(r[k]) for k in (*OUTCOMES, "unjudged"))
        + rate(r) + delta(r["regressions"]) + delta(r["fixes"]) + f"<td>{_bar(r)}</td></tr>"
        for r in rows)
    return (
        '<section><div class="sechead"><div><h2>Target versions</h2><div class="sub">Oldest first. Fail rate = fail / '
        '(pass + partial + fail). Regressions and fixes compare each case with the previous version '
        f'(pass → fail, fail → pass).</div></div>{_legend()}</div>'
        '<div class="scroll"><table class="sortable"><thead><tr><th>Version</th><th>First run</th><th class="n">Cases</th>'
        '<th class="n">Runs</th><th class="n">Pass</th><th class="n">Partial</th><th class="n">Fail</th>'
        '<th class="n">Error</th><th class="n">Skipped</th><th class="n">Unjudged</th><th class="n">Fail rate</th><th class="n">Regressions</th>'
        f'<th class="n">Fixes</th><th>Outcome mix</th></tr></thead><tbody>{body}</tbody></table></div></section>')


def _signature(stats: Mapping[str, Any], findings: int) -> str:
    """A compact string that changes iff a shown aggregate changed — the /watch poll's diff key."""
    return json.dumps({"stats": stats, "findings": findings}, sort_keys=True, default=str)


def _watch_js(signature: str, interval_s: float) -> str:
    """Poll /data every interval; reload only when the aggregate signature changes (no idle flashing).

    Read-only: it fetches JSON aggregates and reloads the page — it never posts and never triggers
    an attack. A failed/locked read is ignored and the next tick retries."""
    ms = max(1000, int(interval_s * 1000))
    return (
        "(function(){var sig=" + json.dumps(signature) + ";var ms=" + str(ms) + ";"
        "function tick(){fetch('data',{cache:'no-store'})"
        ".then(function(r){return r.ok?r.json():null;})"
        ".then(function(d){if(d&&d.signature&&d.signature!==sig){location.reload();return;}"
        "setTimeout(tick,ms);}).catch(function(){setTimeout(tick,ms);});}"
        "setTimeout(tick,ms);})();"
    )


def render_html(data: Mapping[str, Any], watch: bool = False, interval_s: float = 3.0) -> str:
    notice = f'<div class="notice">{_e(data["notice"])}</div>' if data.get("notice") else ""
    link_note = "" if data["langfuse_linked"] else " · Langfuse links off (set LANGFUSE_HOST + LANGFUSE_PROJECT_ID)"
    live = (f'<span style="color:var(--good);font-size:12px"> · ● live (every {_e(str(int(interval_s)))}s)</span>'
            if watch else "")
    watch_js = ""
    if watch:
        sig = _signature(data["stats"], data["stats"].get("findings", 0))
        watch_js = f"<script>{_watch_js(sig, interval_s)}</script>"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>AEP Dashboard</title><style>{_CSS}</style></head><body><main>'
        '<header><h1>Adversarial eval platform</h1>'
        f'<div class="sub">{_e(data["source"])} · generated {_e(_ts(data["generated_at"]))} · read-only{_e(link_note)}{live}</div>'
        f'</header>{notice}{_tiles(data["stats"])}{_coverage(data["coverage"])}{_findings(data["findings"])}'
        f'{_feed(data["feed"], data["feed_total"])}{_versions(data["versions"])}'
        f'</main><script>{_JS}</script>{watch_js}</body></html>')


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def generate(db: str, watch: bool = False, interval_s: float = 3.0) -> str:
    """Render the page for ``db``. A missing file renders an empty dashboard instead of creating one."""
    if not pathlib.Path(db).exists():
        with SqliteStore(":memory:") as empty:
            return render_html(build(empty, source=db, notice=f"No database at {db}: showing an empty store."),
                               watch=watch, interval_s=interval_s)
    with SqliteStore.open_readonly(db) as store:
        return render_html(build(store, source=db), watch=watch, interval_s=interval_s)


def _aggregates(store: Any, db: str, notice: str = "") -> dict[str, Any]:
    runs, verdicts, reports = store.list_runs(), store.list_verdicts(), store.list_reports()
    stats = header_stats(runs, verdicts, reports, expected_map(store.list_cases()))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": db,
        "notice": notice,
        "stats": stats,
        "coverage": coverage_matrix(store.coverage(), store.list_cases(), runs, verdicts),
        "findings": len(reports),
        "signature": _signature(stats, len(reports)),
    }


def aggregates(db: str) -> dict[str, Any]:
    """Current JSON-safe aggregates for the ``/data`` poll. Read-only, and never raises.

    A missing file returns an empty-store payload. A transient read failure — the campaign writes
    while the dashboard reads — returns the last-shape payload with an ``error`` note, still HTTP 200
    so the poller keeps ticking rather than seeing a 500 and stopping."""
    try:
        if not pathlib.Path(db).exists():
            with SqliteStore(":memory:") as empty:
                return _aggregates(empty, db, notice=f"No database at {db}.")
        with SqliteStore.open_readonly(db) as store:
            return _aggregates(store, db)
    except Exception as exc:  # locked/mid-write/corrupt read: degrade, don't 500
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": db,
            "error": f"{type(exc).__name__}: {exc}",
            "stats": {}, "coverage": [], "findings": 0, "signature": "",
        }


def make_handler(db: str, watch: bool = False, interval_s: float = 3.0) -> type[BaseHTTPRequestHandler]:
    """The read-only GET handler: ``/`` (page), ``/data`` (JSON aggregates for --watch), ``/health``,
    ``/ready``. There is no POST and no attack-triggering route — the dashboard only observes."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            probe = health.handle(self.path)
            if probe is not None:
                health.write_json(self, *probe)
                return
            route = self.path.split("?")[0].rstrip("/") or "/"
            if route == "/data":  # read-only JSON aggregates for the --watch poll
                health.write_json(self, 200, aggregates(db))
                return
            if route not in ("/", "/index.html"):
                self.send_error(404)
                return
            try:
                body, status = generate(db, watch=watch, interval_s=interval_s).encode("utf-8"), 200
            except Exception as exc:  # show the failure instead of dropping the connection
                body, status = f"dashboard error: {type(exc).__name__}: {exc}".encode("utf-8"), 500
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8" if status == 200 else "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"[dashboard] {fmt % args}\n")

    return Handler


def serve(db: str, host: str, port: int, watch: bool = False, interval_s: float = 3.0) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(db, watch=watch, interval_s=interval_s))
    mode = f"  (--watch: auto-refresh every {int(interval_s)}s)" if watch else ""
    print(f"serving {db} at http://{host}:{port}/  (Ctrl-C to stop){mode}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", default="seeds.db", help="SQLite store path (default: seeds.db)")
    p.add_argument("--out", default="dashboard.html", help="HTML output path (default: dashboard.html)")
    p.add_argument("--serve", action="store_true", help="serve over HTTP instead of writing a file")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--watch", action="store_true",
                   help="with --serve: auto-refresh the page from the store on an interval (live campaign view)")
    p.add_argument("--interval", type=float, default=3.0,
                   help="--watch poll interval in seconds (default: 3)")
    args = p.parse_args(argv)
    if args.serve:
        serve(args.db, args.host, args.port, watch=args.watch, interval_s=args.interval)
        return 0
    if args.watch:
        print("--watch has no effect without --serve (a static file cannot auto-refresh)", file=sys.stderr)
    out = pathlib.Path(args.out)
    out.write_text(generate(args.db), encoding="utf-8")
    print(f"wrote {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
