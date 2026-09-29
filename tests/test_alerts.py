"""Alert definitions (aep/alerts.py) and the CLI (scripts/alerts.py), over a fake store."""
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aep import alerts  # noqa: E402
from aep.store import SqliteStore  # noqa: E402
from contracts.contracts import AttackRun, ConversationTurn, JudgeVerdict, OracleType, Verdict  # noqa: E402

_spec = importlib.util.spec_from_file_location("alerts_cli", ROOT / "scripts" / "alerts.py")
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)

NOW = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)


class FakeStore:
    """The two read methods alerts may call. Anything else, a write included, raises AttributeError."""

    def __init__(self, runs=(), verdicts=()):
        self._runs, self._verdicts = list(runs), list(verdicts)
        self.calls = []

    def list_runs(self):
        self.calls.append("list_runs")
        return list(self._runs)

    def list_verdicts(self):
        self.calls.append("list_verdicts")
        return list(self._verdicts)


def run(i, latency=None, hours_ago=1.0, replies=(), tool_calls=()):
    return AttackRun(
        run_id=f"run_{i}", correlation_id=f"corr_{i}", case_id=f"case_{i}", target_version="v1",
        transcript=[t for text in replies for t in (ConversationTurn(role="user", content="hi"),
                                                     ConversationTurn(role="assistant", content=text))],
        tool_calls_observed=list(tool_calls),
        latency_ms_by_step={"redteam.attack": latency} if latency is not None else {},
        started_at=NOW - timedelta(hours=hours_ago),
    )


def verdict(r, v, oracle=OracleType.CANARY, **evidence):
    return JudgeVerdict(run_id=r.run_id, case_id=r.case_id, correlation_id=r.correlation_id,
                        verdict=v, oracle_used=oracle, oracle_evidence=evidence)


def settings(**overrides):
    return alerts.settings_from_env({}, **overrides)


def by_key(results):
    return {r.key: r for r in results}


def evaluate(runs=(), verdicts=(), **overrides):
    return by_key(alerts.evaluate(FakeStore(runs, verdicts), settings(**overrides), now=NOW))


# --------------------------------------------------------------------------- #
# Definitions and configuration
# --------------------------------------------------------------------------- #
def test_three_definitions_each_with_a_runbook_section():
    doc = (ROOT / "docs" / "ALERTS.md").read_text()
    headings = set(re.findall(r"^## (\S+)$", doc, flags=re.M))
    assert [d.key for d in alerts.DEFINITIONS] == ["p95_latency", "error_rate", "target_failure_rate"]
    for d in alerts.DEFINITIONS:
        assert d.key in headings, f"docs/ALERTS.md has no '## {d.key}' section"
        assert d.runbook == f"docs/ALERTS.md#{d.key}"
        assert d.env in doc


def test_defaults():
    s = alerts.settings_from_env({})
    assert s.thresholds == {"p95_latency": 60000.0, "error_rate": 0.10, "target_failure_rate": 0.05}
    assert (s.window_hours, s.min_samples) == (24.0, 5)


def test_env_then_override_precedence():
    env = {"ALERT_P95_LATENCY_MS": "5000", "ALERT_ERROR_RATE": "0.3", "ALERT_TARGET_FAILURE_RATE": "0.2",
           "ALERT_WINDOW_HOURS": "6", "ALERT_MIN_SAMPLES": "2"}
    s = alerts.settings_from_env(env, error_rate=0.5, p95_latency=None)
    assert s.thresholds == {"p95_latency": 5000.0, "error_rate": 0.5, "target_failure_rate": 0.2}
    assert (s.window_hours, s.min_samples) == (6.0, 2)


@pytest.mark.parametrize("env, match", [
    ({"ALERT_ERROR_RATE": "ten percent"}, "ALERT_ERROR_RATE.*not a number"),
    ({"ALERT_TARGET_FAILURE_RATE": "5"}, "ALERT_TARGET_FAILURE_RATE.*between 0 and 1"),
    ({"ALERT_P95_LATENCY_MS": "-1"}, "ALERT_P95_LATENCY_MS"),
    ({"ALERT_MIN_SAMPLES": "0"}, "ALERT_MIN_SAMPLES"),
])
def test_bad_config_raises_naming_the_variable(env, match):
    with pytest.raises(ValueError, match=match):
        alerts.settings_from_env(env)


def test_bad_override_raises():
    with pytest.raises(ValueError):
        alerts.settings_from_env({}, error_rate=1.5)


# --------------------------------------------------------------------------- #
# Read-only
# --------------------------------------------------------------------------- #
def test_evaluate_only_calls_the_two_read_methods():
    store = FakeStore([run(1, 100)], [])
    alerts.evaluate(store, settings(), now=NOW)
    assert sorted(set(store.calls)) == ["list_runs", "list_verdicts"]


# --------------------------------------------------------------------------- #
# p95_latency
# --------------------------------------------------------------------------- #
def test_p95_latency_fires_above_threshold():
    runs = [run(i, 1_000) for i in range(9)] + [run(9, 120_000)]
    a = evaluate(runs, p95_latency=30_000)["p95_latency"]
    assert a.state == alerts.FIRING and a.value > 30_000 and a.samples == 10
    assert a.examples == ["corr_9"]
    assert a.breakdown["p95_ms_by_step"] == {"redteam.attack": pytest.approx(a.value, abs=0.1)}
    assert a.detail == "1 of 10 runs over 30000 ms"


def test_p95_latency_ok_below_threshold_and_skips_runs_without_steps():
    runs = [run(i, 2_000) for i in range(5)] + [run(9)]
    a = evaluate(runs)["p95_latency"]
    assert a.state == alerts.OK and a.value == 2_000 and a.samples == 5 and a.examples == []


def test_p95_latency_sums_steps_end_to_end():
    r = run(1)
    r.latency_ms_by_step = {"redteam.attack": 40_000, "judge": 30_000}
    a = evaluate([r], min_samples=1)["p95_latency"]
    assert a.value == 70_000 and a.state == alerts.FIRING


# --------------------------------------------------------------------------- #
# error_rate
# --------------------------------------------------------------------------- #
def test_error_rate_counts_runs_whose_verdicts_are_all_error():
    runs = [run(i) for i in range(10)]
    verdicts = [verdict(runs[i], Verdict.PASS) for i in range(8)]
    verdicts += [verdict(runs[8], Verdict.ERROR, OracleType.LLM_JUDGE, reason="judge model call failed"),
                 verdict(runs[9], Verdict.ERROR, OracleType.HTTP_ASSERT, reason="oracle raised")]
    # One oracle erroring beside a real verdict leaves the run evaluated.
    verdicts.append(verdict(runs[0], Verdict.ERROR, reason="oracle raised"))
    a = evaluate(runs, verdicts)["error_rate"]
    assert a.state == alerts.FIRING and a.value == pytest.approx(0.2) and a.samples == 10
    assert a.breakdown["reasons"] == {"llm_judge: judge model call failed": 1, "http_assert: oracle raised": 1}
    assert a.examples == ["corr_8", "corr_9"]


def test_error_rate_leaves_unjudged_runs_out():
    runs = [run(i) for i in range(8)]
    verdicts = [verdict(r, Verdict.FAIL) for r in runs[:6]]
    a = evaluate(runs, verdicts)["error_rate"]
    assert a.state == alerts.OK and a.value == 0.0 and a.samples == 6
    assert a.detail == "0 of 6 judged runs errored; 2 not judged yet"


def test_error_rate_at_threshold_is_not_firing():
    runs = [run(i) for i in range(10)]
    verdicts = [verdict(r, Verdict.ERROR if i == 0 else Verdict.PASS) for i, r in enumerate(runs)]
    assert evaluate(runs, verdicts)["error_rate"].state == alerts.OK  # 10% is not above 10%


# --------------------------------------------------------------------------- #
# target_failure_rate
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("reply, failing", [
    ('{"body": {"error": "Internal"}, "status_code": 503}', True),   # brief: _describe_response
    ("[status=500]", True),                                          # chat with no text: _reply_text
    ("[upload status=502 document_id=None extraction=None]", True),  # _describe_upload
    ("[status=429]", True),
    ('{"body": null, "status_code": 408}', True),
    ("[upload status=415 document_id=None extraction=None]", False),  # a refusal is a defence
    ('{"body": {"error": "Forbidden"}, "status_code": 403}', False),
    ("I can't share another patient's record. Status 500 is not relevant here.", False),
])
def test_target_failure_from_transcript(reply, failing):
    assert bool(alerts.target_failures(run(1, replies=[reply]))) is failing


@pytest.mark.parametrize("call, failing", [
    ({"tool": "fhir_read", "outcome": "timeout"}, True),
    ({"tool": "lab_writeback", "status": "failed"}, True),
    ({"tool": "llm", "error_type": "RateLimitError"}, True),
    ({"tool": "vision", "status_code": 502}, True),
    ({"tool": "fhir_read", "outcome": "success", "status_code": 200}, False),
    ({"tool": "fhir_read", "status_code": 404}, False),
])
def test_target_failure_from_tool_calls(call, failing):
    assert bool(alerts.target_failures(run(1, tool_calls=[call]))) is failing


def test_target_failure_rate_fires_with_breakdown():
    runs = [run(i, replies=["ok"]) for i in range(8)]
    runs.append(run(8, replies=["[status=503]", "[status=503]"]))
    runs.append(run(9, tool_calls=[{"tool": "fhir_read", "outcome": "timeout"}]))
    a = evaluate(runs)["target_failure_rate"]
    assert a.state == alerts.FIRING and a.value == pytest.approx(0.2)
    assert a.breakdown["failures"] == {"target HTTP 503": 1, "fhir_read timeout": 1}
    assert a.examples == ["corr_8", "corr_9"]


# --------------------------------------------------------------------------- #
# Window and sample floor
# --------------------------------------------------------------------------- #
def test_window_excludes_old_runs_and_zero_means_all():
    runs = [run(i, 100_000, hours_ago=48) for i in range(5)] + [run(9, 1_000, hours_ago=1)]
    assert evaluate(runs)["p95_latency"].samples == 1
    a = evaluate(runs, window_hours=0)["p95_latency"]
    assert a.samples == 6 and a.state == alerts.FIRING


def test_window_filters_verdicts_with_their_runs():
    old, new = run(1, hours_ago=48), run(2, hours_ago=1)
    a = evaluate([old, new], [verdict(old, Verdict.ERROR), verdict(new, Verdict.PASS)], min_samples=1)["error_rate"]
    assert a.samples == 1 and a.value == 0.0


def test_too_few_samples_is_insufficient_data_even_when_over_threshold():
    runs = [run(i, 500_000, replies=["[status=500]"]) for i in range(3)]
    results = evaluate(runs, [verdict(r, Verdict.ERROR) for r in runs])
    assert {r.state for r in results.values()} == {alerts.INSUFFICIENT}
    assert not any(r.firing for r in results.values())
    assert results["p95_latency"].detail.startswith("3 of 5 samples needed")


def test_empty_store():
    results = evaluate()
    assert all(r.state == alerts.INSUFFICIENT and r.value is None for r in results.values())


def test_naive_timestamps_are_treated_as_utc():
    r = run(1, 100)
    r.started_at = (NOW - timedelta(hours=1)).replace(tzinfo=None)
    assert evaluate([r], min_samples=1)["p95_latency"].samples == 1


def test_format_text_shows_runbook_only_when_firing():
    runs = [run(i, 1_000) for i in range(5)]
    s = settings(p95_latency=500)
    text = alerts.format_text(alerts.evaluate(FakeStore(runs), s, now=NOW), s)
    assert "[FIRING" in text and "runbook: docs/ALERTS.md#p95_latency" in text
    assert "docs/ALERTS.md#error_rate" not in text


# --------------------------------------------------------------------------- #
# CLI over a real SQLite file
# --------------------------------------------------------------------------- #
@pytest.fixture
def db(tmp_path, monkeypatch):
    for key in ("ALERT_P95_LATENCY_MS", "ALERT_ERROR_RATE", "ALERT_TARGET_FAILURE_RATE",
                "ALERT_WINDOW_HOURS", "ALERT_MIN_SAMPLES"):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "aep.db"
    with SqliteStore(str(path)) as store:
        for i in range(6):
            r = run(i, 1_000 + i, replies=["[status=503]" if i == 0 else "fine"])
            store.add_run(r)
            store.add_verdict(verdict(r, Verdict.PASS))
    return path


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_cli_exit_codes_and_json(db, capsys):
    before = _sha(db)
    # 1 of 6 runs hit a 503: 16.7% > 5% default.
    assert cli.main(["--db", str(db), "--all", "--json"]) == cli.EXIT_FIRING
    out = json.loads(capsys.readouterr().out)
    states = {a["key"]: a["state"] for a in out["alerts"]}
    assert states == {"p95_latency": "ok", "error_rate": "ok", "target_failure_rate": "firing"}
    assert cli.main(["--db", str(db), "--all", "--target-failure-rate", "0.5"]) == cli.EXIT_OK
    assert "[OK" in capsys.readouterr().out
    assert _sha(db) == before  # read-only


def test_cli_config_and_missing_db_errors(db, tmp_path, monkeypatch, capsys):
    assert cli.main(["--db", str(tmp_path / "nope.db")]) == cli.EXIT_ERROR
    assert "no database" in capsys.readouterr().err
    assert not (tmp_path / "nope.db").exists()
    monkeypatch.setenv("ALERT_ERROR_RATE", "lots")
    assert cli.main(["--db", str(db)]) == cli.EXIT_ERROR
    assert "ALERT_ERROR_RATE" in capsys.readouterr().err
