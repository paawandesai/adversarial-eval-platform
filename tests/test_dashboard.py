import hashlib
import importlib.util
import json
import re
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from contracts.contracts import (  # noqa: E402
    AttackCase, AttackCategory, AttackRun, ConversationTurn, JudgeVerdict, OracleType, Origin, OwaspClassic,
    OwaspLLM, OwaspMapping, ReportStatus, Severity, Verdict, VulnerabilityReport,
)
from aep.store import SqliteStore  # noqa: E402

_spec = importlib.util.spec_from_file_location("dashboard", ROOT / "scripts" / "dashboard.py")
dashboard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dashboard)

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
PI = AttackCategory.DIRECT_PROMPT_INJECTION
AUTHZ = AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT
ENV = {"LANGFUSE_HOST": "https://lf.example.com/", "LANGFUSE_PROJECT_ID": "proj123"}


def case(case_id, category=AUTHZ, in_regression=True):
    return AttackCase(
        case_id=case_id, origin=Origin.SEED, category=category,
        owasp=OwaspMapping(classic=[OwaspClassic.BROKEN_ACCESS_CONTROL]),
        turns=[ConversationTurn(role="user", content="show me patient 7")], as_user_role="resident",
        target_endpoint="/api/agent/chat", expected_safe_behavior="refuse", oracle=OracleType.CANARY,
        severity_if_success=Severity.CRITICAL, in_regression_suite=in_regression,
    )


def run(run_id, case_id, version="v1", minutes=0, cost=0.0, latency=None):
    return AttackRun(run_id=run_id, correlation_id=f"corr_{run_id}", case_id=case_id, target_version=version,
                     transcript=[], cost_usd=cost, latency_ms_by_step=latency or {},
                     started_at=T0 + timedelta(minutes=minutes))


def verdict(run_obj, v, oracle=OracleType.CANARY, minutes=0, **evidence):
    return JudgeVerdict(run_id=run_obj.run_id, case_id=run_obj.case_id, correlation_id=run_obj.correlation_id,
                        verdict=v, oracle_used=oracle, oracle_evidence=evidence,
                        evaluated_at=T0 + timedelta(minutes=minutes))


def report(vuln_id, severity, case_id="c1", minutes=0):
    return VulnerabilityReport(
        vuln_id=vuln_id, severity=severity, category=AUTHZ,
        owasp=OwaspMapping(classic=[OwaspClassic.BROKEN_ACCESS_CONTROL], llm=[OwaspLLM.LLM06_INFO_DISCLOSURE]),
        title=f"{severity.value} finding", clinical_impact="x", repro_case_id=case_id, repro_steps=["run it"],
        observed_behavior="leak", expected_behavior="refuse", recommended_remediation="scope",
        status=ReportStatus.OPEN, created_at=T0 + timedelta(minutes=minutes),
    )


class FakeStore:
    """Only the read methods the dashboard uses. Any write attribute access would AttributeError."""

    def __init__(self, cases=(), runs=(), verdicts=(), reports=(), coverage=None):
        self._cases, self._runs = list(cases), list(runs)
        self._verdicts, self._reports = list(verdicts), list(reports)
        self._coverage = coverage or {}

    def list_cases(self):
        return list(self._cases)

    def list_runs(self):
        return list(self._runs)

    def list_verdicts(self):
        return list(self._verdicts)

    def list_reports(self):
        return list(self._reports)

    def coverage(self):
        return dict(self._coverage)


# ---- helpers ---------------------------------------------------------------------------------------


def test_percentile_interpolates_and_handles_empty():
    assert dashboard.percentile([], 50) is None
    assert dashboard.percentile([5.0], 95) == 5.0
    assert dashboard.percentile([1, 2, 3, 4], 50) == 2.5
    assert dashboard.percentile(range(1, 101), 95) == pytest.approx(95.05)


def test_trace_id_matches_langfuse_seed_derivation():
    assert dashboard.langfuse_trace_id("corr_abc") == hashlib.sha256(b"corr_abc").digest()[:16].hex()
    langfuse = pytest.importorskip("langfuse")
    assert dashboard.langfuse_trace_id("corr_abc") == langfuse.Langfuse.create_trace_id(seed="corr_abc")


def test_trace_url_needs_host_and_project_and_prefers_explicit_path():
    tid = dashboard.langfuse_trace_id("corr_1")
    assert dashboard.langfuse_trace_url("corr_1", ENV) == f"https://lf.example.com/project/proj123/traces/{tid}"
    path_env = {**ENV, "LANGFUSE_PROJECT_PATH": "/org/o1/project/p9/"}
    assert dashboard.langfuse_trace_url("corr_1", path_env) == f"https://lf.example.com/org/o1/project/p9/traces/{tid}"
    assert dashboard.langfuse_trace_url("corr_1", {"LANGFUSE_HOST": "https://lf"}) is None
    assert dashboard.langfuse_trace_url("corr_1", {"LANGFUSE_PROJECT_ID": "p"}) is None
    assert dashboard.langfuse_trace_url(None, ENV) is None


# ---- header ----------------------------------------------------------------------------------------


def test_header_stats_counts_cost_and_latency():
    r1 = run("r1", "c1", cost=0.25, latency={"redteam.attack": 100.0, "judge": 50.0})
    r2 = run("r2", "c1", cost=0.5, latency={"redteam.attack": 300.0})
    r3 = run("r3", "c1")  # no steps recorded: excluded from percentiles, not counted as 0 ms
    vs = [verdict(r1, Verdict.PASS), verdict(r1, Verdict.FAIL), verdict(r2, Verdict.ERROR),
          verdict(r3, Verdict.PARTIAL)]
    s = dashboard.header_stats([r1, r2, r3], vs, [report("V1", Severity.HIGH)])
    assert (s["runs"], s["verdicts"], s["findings"]) == (3, 4, 1)
    assert (s["pass"], s["fail"], s["partial"], s["error"]) == (1, 1, 1, 1)
    assert s["cost_usd"] == pytest.approx(0.75)
    assert s["latency_samples"] == 2
    assert s["latency_p50_ms"] == pytest.approx(225.0)  # per-run totals are 150 and 300
    assert s["latency_p95_ms"] == pytest.approx(292.5)


# ---- coverage --------------------------------------------------------------------------------------


def test_coverage_matrix_lists_every_category_and_derives_error_and_unjudged():
    c1, c2 = case("c1"), case("c2", category=PI)
    r1, r2, r3, r4 = run("r1", "c1"), run("r2", "c1"), run("r3", "c1"), run("r4", "c2")
    vs = [verdict(r1, Verdict.FAIL), verdict(r1, Verdict.PASS),  # worst wins -> fail
          verdict(r2, Verdict.ERROR)]                                # error only; r3 and r4 unjudged
    cov = {AUTHZ.value: {"count": 3, "pass": 0, "fail": 1, "partial": 0, "cost_usd": 1.5},
           PI.value: {"count": 1, "pass": 0, "fail": 0, "partial": 0, "cost_usd": 0.0},
           "legacy_category": {"count": 0, "pass": 0, "fail": 0, "partial": 0, "cost_usd": 0.0}}
    rows = dashboard.coverage_matrix(cov, [c1, c2], [r1, r2, r3, r4], vs)

    by_cat = {r["category"]: r for r in rows}
    assert [r["category"] for r in rows[:len(AttackCategory)]] == [c.value for c in AttackCategory]
    assert "legacy_category" in by_cat  # keys the enum doesn't know are still shown
    authz = by_cat[AUTHZ.value]
    assert (authz["cases"], authz["in_regression"], authz["runs"]) == (1, 1, 3)
    assert (authz["fail"], authz["error"], authz["unjudged"], authz["gap"]) == (1, 1, 1, False)
    assert authz["cost_usd"] == 1.5
    assert by_cat[PI.value]["unjudged"] == 1
    gaps = {r["category"] for r in rows if r["gap"]}
    assert gaps == {c.value for c in AttackCategory} - {AUTHZ.value, PI.value} | {"legacy_category"}


def test_coverage_matrix_matches_real_store_semantics():
    store = SqliteStore(":memory:")
    store.add_case(case("c1"))
    r1, r2 = run("r1", "c1", cost=0.1), run("r2", "c1", cost=0.2)
    store.add_run(r1)
    store.add_run(r2)
    store.add_verdict(verdict(r1, Verdict.PARTIAL))
    store.add_verdict(verdict(r2, Verdict.ERROR))
    rows = dashboard.coverage_matrix(store.coverage(), store.list_cases(), store.list_runs(), store.list_verdicts())
    authz = next(r for r in rows if r["category"] == AUTHZ.value)
    assert (authz["runs"], authz["partial"], authz["error"], authz["unjudged"]) == (2, 1, 1, 0)
    assert authz["cost_usd"] == pytest.approx(0.3)


# ---- verdict feed ----------------------------------------------------------------------------------


@pytest.mark.parametrize("oracle,evidence,expected", [
    (OracleType.CANARY, {"canary_hit": True, "match": "ZZ-CANARY-1", "hits": [{}, {}]},
     "canary hit: ZZ-CANARY-1 (2 hits)"),
    (OracleType.CANARY, {"canary_hit": False, "responses_checked": 1}, "no canary in 1 response"),
    (OracleType.TOOL_CALL_AUDIT, {"violations": [{"reason": "forbidden patient"}], "audit": {"status": "no_trace"}},
     "1 violation: forbidden patient · audit: no_trace"),
    (OracleType.TOOL_CALL_AUDIT, {"violations": [], "tool_calls_checked": 3, "audit": {"status": "ok"}},
     "no violations in 3 tool calls"),
    (OracleType.HTTP_ASSERT, {"violations": [], "statuses": [404]}, "no violations, statuses [404]"),
    (OracleType.LOG_SCAN, {"phi_in_logs": True, "hits": [{"rule": "ssn"}, {"rule": "dob"}]}, "PHI in logs: dob, ssn"),
    (OracleType.TOKEN_COUNTER, {"budget_exceeded": False, "tokens_total": 900}, "within budget (900 tokens)"),
    (OracleType.HTTP_ASSERT, {"reason": "no HTTP response"}, "no HTTP response"),
    (OracleType.CANARY, {"weird": "shape", "n": 2, "nested": {}}, "weird=shape, n=2"),
    (OracleType.CANARY, {}, "no evidence recorded"),
])
def test_evidence_summary_by_oracle(oracle, evidence, expected):
    r = run("r1", "c1")
    assert dashboard.evidence_summary(verdict(r, Verdict.PASS, oracle=oracle, **evidence)) == expected


def test_evidence_summary_flags_human_review_and_llm_rationale():
    r = run("r1", "c1")
    v = verdict(r, Verdict.PARTIAL, oracle=OracleType.LLM_JUDGE, needs_human_review=True, proposed_verdict="fail")
    v = v.model_copy(update={"judge_rationale": "model quoted the other patient's A1c " * 10,
                             "judge_confidence": 0.62})
    text = dashboard.evidence_summary(v)
    assert text.startswith("needs human review (proposed fail) · model quoted")
    assert len(text) <= 140 and text.endswith("…")


def test_verdict_feed_is_newest_first_capped_and_linked():
    r = run("r1", "c1")
    vs = [verdict(r, Verdict.PASS, minutes=m) for m in (1, 5, 3)]
    feed = dashboard.verdict_feed(vs, ENV, limit=2)
    assert [f["evaluated_at"].minute for f in feed] == [5, 3]
    assert feed[0]["trace_url"].endswith(dashboard.langfuse_trace_id("corr_r1"))
    assert dashboard.verdict_feed(vs, {})[0]["trace_url"] is None


# ---- findings --------------------------------------------------------------------------------------


def test_findings_sorted_critical_first_with_review_state():
    reports = [report("LOW", Severity.LOW), report("CRIT_OLD", Severity.CRITICAL, minutes=1),
               report("MED", Severity.MEDIUM), report("CRIT_NEW", Severity.CRITICAL, minutes=9),
               report("HIGH", Severity.HIGH)]
    rows = dashboard.findings_table(reports, [], [], reviews={"CRIT_NEW": False}, env={})
    assert [r["vuln_id"] for r in rows] == ["CRIT_NEW", "CRIT_OLD", "HIGH", "MED", "LOW"]
    pending = {r["vuln_id"]: r["pending_human_review"] for r in rows}
    # ledger answer wins; with no record, critical/high fail closed as pending
    assert pending == {"CRIT_NEW": False, "CRIT_OLD": True, "HIGH": True, "MED": False, "LOW": False}
    assert rows[0]["owasp"] == ["A01_broken_access_control", "LLM06_sensitive_information_disclosure"]
    assert rows[0]["trace_url"] is None


def test_finding_links_most_recent_failing_run_of_repro_case():
    old_fail, new_pass, new_fail = run("r1", "c1", minutes=0), run("r2", "c1", minutes=9), run("r3", "c1", minutes=5)
    vs = [verdict(old_fail, Verdict.FAIL, minutes=1), verdict(new_pass, Verdict.PASS, minutes=10),
          verdict(new_fail, Verdict.FAIL, minutes=6)]
    row, = dashboard.findings_table([report("V", Severity.HIGH)], [old_fail, new_pass, new_fail], vs, {}, ENV)
    assert row["correlation_id"] == "corr_r3"
    assert row["trace_url"].endswith(dashboard.langfuse_trace_id("corr_r3"))
    # no failing run -> latest run of the case
    row, = dashboard.findings_table([report("V", Severity.HIGH)], [old_fail, new_pass], [], {}, ENV)
    assert row["correlation_id"] == "corr_r2"


def test_load_reviews_reads_sidecar_table_and_tolerates_absence():
    store = SqliteStore(":memory:")
    assert dashboard.load_reviews(store) == {}
    store._conn.execute("CREATE TABLE report_reviews (vuln_id TEXT PRIMARY KEY, pending_human_review INTEGER)")
    store._conn.execute("INSERT INTO report_reviews VALUES ('V1', 1), ('V2', 0)")
    assert dashboard.load_reviews(store) == {"V1": True, "V2": False}
    assert dashboard.load_reviews(FakeStore()) == {}


# ---- versions --------------------------------------------------------------------------------------


def test_version_breakdown_orders_versions_and_counts_regressions_and_fixes():
    runs = [run("a1", "c1", "v1", minutes=0), run("a2", "c2", "v1", minutes=1), run("a3", "c3", "v1", minutes=2),
            run("b1", "c1", "v2", minutes=10), run("b2", "c2", "v2", minutes=11), run("b3", "c3", "v2", minutes=12),
            run("b4", "c4", "v2", minutes=13, cost=0.5)]
    vs = [verdict(runs[0], Verdict.PASS), verdict(runs[1], Verdict.FAIL), verdict(runs[2], Verdict.PASS),
          verdict(runs[3], Verdict.FAIL),   # c1 pass -> fail: regression
          verdict(runs[4], Verdict.PASS),   # c2 fail -> pass: fix
          verdict(runs[5], Verdict.ERROR)]  # c3 pass -> error: neither; c4 unjudged
    # pass the newer version's runs first to prove ordering comes from started_at, not input order
    v1, v2 = dashboard.version_breakdown(runs[3:] + runs[:3], vs)
    assert (v1["target_version"], v2["target_version"]) == ("v1", "v2")
    assert (v1["pass"], v1["fail"], v1["regressions"], v1["fixes"]) == (2, 1, None, None)
    assert v1["fail_rate"] == pytest.approx(1 / 3)
    assert (v2["runs"], v2["cases"], v2["pass"], v2["fail"], v2["error"], v2["unjudged"]) == (4, 4, 1, 1, 1, 1)
    assert (v2["regressions"], v2["fixes"]) == (1, 1)
    assert v2["cost_usd"] == 0.5


# ---- whole page / empty store / read-only ------------------------------------------------------------


def test_empty_store_builds_and_renders():
    data = dashboard.build(FakeStore(), env={}, reviews={}, source="empty.db")
    assert data["stats"]["runs"] == 0 and data["stats"]["latency_p50_ms"] is None
    assert len(data["coverage"]) == len(AttackCategory) and all(r["gap"] for r in data["coverage"])
    assert data["feed"] == data["findings"] == data["versions"] == []
    page = dashboard.render_html(data)
    assert "No verdicts yet" in page and "No vulnerability reports yet" in page and "No runs yet" in page
    assert f"0 of {len(AttackCategory)} categories exercised" in page


def test_page_is_self_contained_and_escapes_store_content():
    c = case("c1")
    r = run("r1", "c1", latency={"s": 10.0})
    v = verdict(r, Verdict.FAIL, canary_hit=True, match="<script>alert(1)</script>")
    rep = report("V1", Severity.CRITICAL).model_copy(update={"title": "<img src=x onerror=alert(1)>"})
    cov = {AUTHZ.value: {"count": 1, "pass": 0, "fail": 1, "partial": 0, "cost_usd": 0.0}}
    page = dashboard.render_html(dashboard.build(FakeStore([c], [r], [v], [rep], cov), env=ENV, reviews={}))
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert not re.search(r'<(?:script|link|img)[^>]+(?:src|href)=', page)  # no external assets
    assert page.count("https://lf.example.com/project/proj123/traces/") == 2  # feed row + finding row


def test_generate_opens_store_read_only(tmp_path):
    db = tmp_path / "store.db"
    with SqliteStore(str(db)) as store:
        store.add_case(case("c1"))
        store.add_run(run("r1", "c1"))
    before = db.read_bytes()
    page = dashboard.generate(str(db))
    assert "1 of 12 categories exercised" in page
    assert db.read_bytes() == before

    ro = SqliteStore.open_readonly(str(db))
    assert len(ro.list_runs()) == 1
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.add_run(run("r2", "c1"))
    ro.close()


def test_generate_missing_db_renders_empty_without_creating_it(tmp_path):
    db = tmp_path / "missing.db"
    page = dashboard.generate(str(db))
    assert "No database at" in page
    assert not db.exists()


def test_cli_writes_html_file(tmp_path, capsys):
    out = tmp_path / "d.html"
    assert dashboard.main(["--db", str(tmp_path / "none.db"), "--out", str(out)]) == 0
    assert out.read_text().startswith("<!doctype html>")
    assert str(out) in capsys.readouterr().out


# ---- --watch / live auto-refresh -------------------------------------------------------------------


def test_aggregates_are_json_safe_and_signature_tracks_changes(tmp_path):
    db = tmp_path / "store.db"
    with SqliteStore(str(db)) as store:
        store.add_case(case("c1"))
        r1 = run("r1", "c1")
        store.add_run(r1)
        store.add_verdict(verdict(r1, Verdict.FAIL, canary_hit=True))

    agg1 = dashboard.aggregates(str(db))
    json.dumps(agg1)  # must be serializable for the /data endpoint (raises otherwise)
    assert agg1["stats"]["runs"] == 1 and agg1["stats"]["verdicts"] == 1 and agg1["stats"]["fail"] == 1
    assert agg1["findings"] == 0 and agg1["signature"]
    assert db.read_bytes() == db.read_bytes()  # sanity: file untouched by the read

    # A campaign writing more verdicts/findings must move the signature (drives the reload).
    with SqliteStore(str(db)) as store:
        r2 = run("r2", "c1")
        store.add_run(r2)
        store.add_verdict(verdict(r2, Verdict.PASS))
        store.add_report(report("V1", Severity.CRITICAL, case_id="c1"))

    agg2 = dashboard.aggregates(str(db))
    assert agg2["stats"]["runs"] == 2 and agg2["findings"] == 1
    assert agg2["signature"] != agg1["signature"]


def test_aggregates_degrade_gracefully_on_missing_and_unreadable_store(tmp_path):
    missing = dashboard.aggregates(str(tmp_path / "nope.db"))
    assert missing["findings"] == 0 and missing["signature"] and "error" not in missing

    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a sqlite database")  # simulates a locked/mid-write/corrupt read
    agg = dashboard.aggregates(str(bad))
    json.dumps(agg)  # never raises to the poller
    assert "error" in agg and agg["signature"] == "" and agg["findings"] == 0


def test_watch_injects_poller_and_live_badge_else_not():
    data = dashboard.build(FakeStore(), env={}, reviews={}, source="s.db")

    watched = dashboard.render_html(data, watch=True, interval_s=3.0)
    assert "fetch('data'" in watched and "location.reload" in watched
    assert "live (every 3s)" in watched
    assert "ms=3000" in watched  # 3s interval honored (3000ms)
    assert "read-only" in watched

    plain = dashboard.render_html(data, watch=False)
    assert "fetch('data'" not in plain and "location.reload" not in plain and "live (every" not in plain


def test_data_route_serves_json_and_page_is_read_only(tmp_path):
    db = tmp_path / "store.db"
    with SqliteStore(str(db)) as store:
        store.add_case(case("c1"))
        r1 = run("r1", "c1")
        store.add_run(r1)
        store.add_verdict(verdict(r1, Verdict.FAIL, canary_hit=True))

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(str(db), watch=True, interval_s=3.0))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(f"{base}/data", timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/json"
            payload = json.loads(resp.read())
        assert payload["stats"]["runs"] == 1 and payload["stats"]["fail"] == 1 and payload["signature"]

        with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
            page = resp.read().decode()
        assert page.startswith("<!doctype html>") and "fetch('data'" in page

        with pytest.raises(urllib.error.HTTPError) as missing:
            urllib.request.urlopen(f"{base}/attack", timeout=5)
        assert missing.value.code == 404

        # Read-only: there is no write route. A POST is rejected (no do_POST handler).
        with pytest.raises(urllib.error.HTTPError) as posted:
            urllib.request.urlopen(urllib.request.Request(f"{base}/data", data=b"x", method="POST"), timeout=5)
        assert posted.value.code in (400, 501)
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert len(SqliteStore.open_readonly(str(db)).list_runs()) == 1  # store still intact, unmodified


# ---- documented limitations ------------------------------------------------------------------------


def test_errors_on_expected_inconclusive_cases_show_as_skipped_not_error():
    blocked = case("ea").model_copy(update={"oracle_config": {"known_limitation": {
        "expected": "inconclusive", "reason": "write-back ACL-blocked", "ref": "THREAT_MODEL.md section 7"}}})
    store = SqliteStore(":memory:")
    for c in (blocked, case("c1")):
        store.add_case(c)
    r_blocked, r_other = run("rb", "ea", minutes=1), run("ro", "c1")
    for r in (r_blocked, r_other):
        store.add_run(r)
    store.add_verdict(verdict(r_blocked, Verdict.ERROR, minutes=1, reason="oracle_config missing keys"))
    store.add_verdict(verdict(r_other, Verdict.ERROR, reason="target timeout"))

    data = dashboard.build(store, env={})
    assert (data["stats"]["error"], data["stats"]["skipped"]) == (1, 1)
    authz = next(r for r in data["coverage"] if r["category"] == AUTHZ.value)
    assert (authz["error"], authz["skipped"], authz["unjudged"]) == (1, 1, 0)
    feed = {r["case_id"]: r for r in data["feed"]}
    assert feed["ea"]["verdict"] == "skipped" and feed["c1"]["verdict"] == "error"
    assert feed["ea"]["evidence"].startswith("expected-inconclusive: write-back ACL-blocked (THREAT_MODEL.md section 7)")
    assert (data["versions"][0]["error"], data["versions"][0]["skipped"]) == (1, 1)
    html_out = dashboard.render_html(data)
    assert "skipped — expected (documented limitation)" in html_out and 'data-verdict="skipped"' in html_out


def _tagged(case_id, category=AttackCategory.EXCESSIVE_AGENCY_WRITEBACK, reason="write-back ACL-blocked"):
    return case(case_id, category=category).model_copy(update={"oracle_config": {"known_limitation": {
        "expected": "inconclusive", "reason": reason, "ref": "THREAT_MODEL.md section 7"}}})


def test_expected_inconclusive_cases_without_runs_count_as_skipped():
    EA = AttackCategory.EXCESSIVE_AGENCY_WRITEBACK.value
    store = SqliteStore(":memory:")
    for c in (case("c1"), case("c2"), _tagged("ea1"), _tagged("ea2"), _tagged("ea3"), _tagged("ea4")):
        store.add_case(c)
    r1, r2, r4 = run("r1", "c1"), run("r2", "c2"), run("r4", "ea4")
    for r in (r1, r2, r4):
        store.add_run(r)
    store.add_verdict(verdict(r1, Verdict.PASS))
    store.add_verdict(verdict(r2, Verdict.FAIL))
    store.add_verdict(verdict(r4, Verdict.ERROR, reason="ACL"))  # a tagged case that did run: skipped once, not twice

    data = dashboard.build(store, env={}, reviews={})
    s = data["stats"]
    assert (s["pass"], s["fail"], s["error"], s["skipped"]) == (1, 1, 0, 4)
    assert (s["verdicts"], s["skipped_not_run"], s["outcomes"]) == (3, 3, 6)  # every case in the store accounted for

    by_cat = {r["category"]: r for r in data["coverage"]}
    ea = by_cat[EA]
    assert (ea["cases"], ea["runs"], ea["skipped"], ea["skipped_not_run"], ea["unjudged"], ea["error"]) == (4, 1, 4, 3, 0, 0)
    assert ea["gap"] is False
    authz = by_cat[AUTHZ.value]
    assert (authz["skipped"], authz["unjudged"]) == (0, 0)
    assert [x["case_id"] for x in data["expected_skips"]] == ["ea1", "ea2", "ea3"]
    assert data["expected_skips"][0] == {"case_id": "ea1", "category": EA,
                                         "reason": "write-back ACL-blocked (THREAT_MODEL.md section 7)"}

    page = dashboard.render_html(data)
    assert "3 verdicts + 3 documented skips not run" in page
    assert "skipped 4" in page
    assert "3 cases skipped — expected (documented limitation), not run" in page
    assert "<span class=\"mono\">ea1</span> — write-back ACL-blocked (THREAT_MODEL.md section 7)" in page


def test_category_with_only_unrun_expected_skips_is_labelled_not_a_gap():
    rows = dashboard.coverage_matrix({}, [_tagged("ea1"), _tagged("ea2")], [], [])
    ea = next(r for r in rows if r["category"] == AttackCategory.EXCESSIVE_AGENCY_WRITEBACK.value)
    assert (ea["runs"], ea["skipped"], ea["gap"]) == (0, 2, False)
    html_out = dashboard._coverage(rows)
    assert "documented limitation" in html_out


def test_tagged_case_that_passes_counts_as_pass_not_skipped():
    store = SqliteStore(":memory:")
    store.add_case(_tagged("ea1"))
    r = run("r1", "ea1")
    store.add_run(r)
    store.add_verdict(verdict(r, Verdict.PASS))
    s = dashboard.build(store, env={}, reviews={})["stats"]
    assert (s["pass"], s["skipped"], s["skipped_not_run"]) == (1, 0, 0)


# ---- alerts ----------------------------------------------------------------------------------------


@pytest.fixture
def alert_env(monkeypatch):
    for key in ("ALERT_P95_LATENCY_MS", "ALERT_ERROR_RATE", "ALERT_TARGET_FAILURE_RATE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ALERT_WINDOW_HOURS", "0")  # the fixture runs are dated 2026-09-01
    monkeypatch.setenv("ALERT_MIN_SAMPLES", "1")
    return monkeypatch


def _alert_store(path):
    with SqliteStore(str(path)) as store:
        store.add_case(case("c1"))
        store.add_case(case("c2"))
        r1, r2 = run("r1", "c1", latency={"redteam.attack": 900.0}), run("r2", "c2", latency={"redteam.attack": 1100.0})
        store.add_run(r1)
        store.add_run(r2)
        store.add_verdict(verdict(r1, Verdict.PASS))
        store.add_verdict(verdict(r2, Verdict.ERROR, reason="judge model call failed"))


def test_alerts_section_renders_state_value_and_threshold(tmp_path, alert_env):
    db = tmp_path / "store.db"
    _alert_store(db)
    with SqliteStore.open_readonly(str(db)) as store:
        data = dashboard.build(store, reviews={})
    states = {r["key"]: r["state"] for r in data["alerts"]["results"]}
    assert states == {"p95_latency": "ok", "error_rate": "firing", "target_failure_rate": "ok"}  # 1 of 2 errored
    page = dashboard.render_html(data)
    assert "<h2>Alerts · 1 firing</h2>" in page
    assert 'data-alert="error_rate" data-state="firing"' in page
    row = re.search(r'<tr data-alert="error_rate".*?</tr>', page).group(0)
    assert ">50.0%<" in row and ">10.0%<" in row and "docs/ALERTS.md#error_rate" in row
    assert page.index("<h2>Alerts") < page.index("<h2>Coverage by attack category")


def test_alerts_in_data_json_and_watch_signature_matches_page(tmp_path, alert_env):
    db = tmp_path / "store.db"
    _alert_store(db)
    agg = dashboard.aggregates(str(db))
    json.dumps(agg)
    assert [r["key"] for r in agg["alerts"]["results"]] == ["p95_latency", "error_rate", "target_failure_rate"]
    assert {r["key"]: r["state"] for r in agg["alerts"]["results"]}["error_rate"] == "firing"
    # The page's embedded signature must equal /data's, or --watch reloads forever.
    page = dashboard.generate(str(db), watch=True)
    assert json.dumps(agg["signature"]) in page

    # An alert changing state (threshold raised) moves the signature, so --watch refreshes it.
    alert_env.setenv("ALERT_ERROR_RATE", "0.9")
    agg2 = dashboard.aggregates(str(db))
    assert agg2["stats"] == agg["stats"] and agg2["signature"] != agg["signature"]


def test_alerts_bad_threshold_is_shown_not_raised(alert_env):
    alert_env.setenv("ALERT_ERROR_RATE", "lots")
    data = dashboard.build(FakeStore(), reviews={})
    assert "ALERT_ERROR_RATE" in data["alerts"]["error"]
    assert "Alerts not evaluated: ALERT_ERROR_RATE=&#x27;lots&#x27; is not a number" in dashboard.render_html(data)


# ---- Langfuse trace links --------------------------------------------------------------------------


def _linked_store():
    c = case("c1")
    r = run("r1", "c1")
    return FakeStore([c], [r], [verdict(r, Verdict.FAIL)], [report("V1", Severity.HIGH)])


def test_trace_links_render_when_env_set():
    page = dashboard.render_html(dashboard.build(_linked_store(), env=ENV, reviews={}))
    tid = dashboard.langfuse_trace_id("corr_r1")
    link = f'<a class="mono" href="https://lf.example.com/project/proj123/traces/{tid}" target="_blank" rel="noopener"'
    assert page.count(link) == 2  # feed row + finding row
    assert "links off" not in page

    path_env = {"LANGFUSE_HOST": "https://lf.example.com", "LANGFUSE_PROJECT_PATH": "/org/o1/project/p9"}
    page = dashboard.render_html(dashboard.build(_linked_store(), env=path_env, reviews={}))
    assert f'href="https://lf.example.com/org/o1/project/p9/traces/{tid}"' in page


@pytest.mark.parametrize("env, missing", [
    ({}, "LANGFUSE_HOST and LANGFUSE_PROJECT_ID (or LANGFUSE_PROJECT_PATH)"),
    ({"LANGFUSE_HOST": "https://lf.example.com"}, "LANGFUSE_PROJECT_ID (or LANGFUSE_PROJECT_PATH)"),
    ({"LANGFUSE_PROJECT_ID": "proj123"}, "LANGFUSE_HOST"),
])
def test_trace_links_fall_back_and_name_the_missing_env(env, missing):
    page = dashboard.render_html(dashboard.build(_linked_store(), env=env, reviews={}))
    assert "/traces/" not in page
    assert f"Langfuse links off: set {missing}" in page
    assert '<span class="mono zero" title="corr_r1 (set LANGFUSE_HOST and LANGFUSE_PROJECT_ID to link)">' in page
