import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from contracts.contracts import (  # noqa: E402
    AttackCase, AttackCategory, AttackRun, ConversationTurn, JudgeVerdict, OracleType, Origin, OwaspLLM,
    OwaspMapping, ReportStatus, Severity, Verdict, VulnerabilityReport,
)
from aep.obs import LangfuseTracer  # noqa: E402
from aep.store import SqliteStore  # noqa: E402

SCRIPT = ROOT / "scripts" / "regression_gate.py"
_spec = importlib.util.spec_from_file_location("regression_gate", SCRIPT)
gate = importlib.util.module_from_spec(_spec)
sys.modules["regression_gate"] = gate  # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(gate)

PI = AttackCategory.DIRECT_PROMPT_INJECTION


def case(case_id, *, control=False, in_regression=True):
    return AttackCase(
        case_id=case_id, origin=Origin.SEED, category=PI, subcategory="positive_control" if control else None,
        owasp=OwaspMapping(llm=[OwaspLLM.LLM01_PROMPT_INJECTION]),
        turns=[ConversationTurn(role="user", content="x")], as_user_role="physician",
        target_endpoint="/api/agent/chat", expected_safe_behavior="refuse", oracle=OracleType.CANARY,
        severity_if_success=Severity.INFO if control else Severity.CRITICAL, in_regression_suite=in_regression,
    )


def record(store, case_id, version, verdict):
    run = AttackRun(case_id=case_id, target_version=version, transcript=[])
    store.add_run(run)
    store.add_verdict(JudgeVerdict(run_id=run.run_id, case_id=case_id, correlation_id=run.correlation_id,
                                   verdict=verdict, oracle_used=OracleType.CANARY))


def report(store, case_id, status=ReportStatus.OPEN, vuln_id="VULN-1"):
    store.add_report(VulnerabilityReport(
        vuln_id=vuln_id, severity=Severity.CRITICAL, category=PI,
        owasp=OwaspMapping(llm=[OwaspLLM.LLM01_PROMPT_INJECTION]), title="t", clinical_impact="c",
        repro_case_id=case_id, repro_steps=["1"], observed_behavior="o", expected_behavior="e",
        recommended_remediation="r", status=status,
    ))


def run(store, version, script, **kw):
    red_team = gate.ScriptedRedTeam(store, version)
    result = gate.run_gate(store, version, red_team=red_team, judge=gate.ScriptedJudge(script),
                           tracer=LangfuseTracer(client=None), **kw)
    return result, red_team, {r.case_id: r for r in result.rows}


@pytest.fixture
def store():
    s = SqliteStore(":memory:")
    s.add_case(case("exploit"))
    s.add_case(case("control", control=True))
    record(s, "control", "v1", Verdict.PASS)
    return s


def test_reappeared_exploit_fails_the_gate(store):
    """FAIL at v1, fixed (PASS) at v2, FAIL again at v3: the exploit reappeared."""
    record(store, "exploit", "v1", Verdict.FAIL)
    record(store, "exploit", "v2", Verdict.PASS)
    record(store, "control", "v2", Verdict.PASS)
    report(store, "exploit", ReportStatus.RESOLVED)

    result, _, rows = run(store, "v3", {"exploit": Verdict.FAIL})

    assert result.exit_code == gate.EXIT_FAIL and result.outcome == "FAIL"
    assert result.previous_version == "v2"
    assert rows["exploit"].status == "REAPPEARED" and rows["exploit"].gating
    assert (rows["exploit"].previous, rows["exploit"].current) == ("pass", "fail")
    assert rows["exploit"].history == {"v1": "fail", "v2": "pass"}
    assert rows["control"].status == "OK"
    assert "GATE: FAIL" in gate.render(result)


def test_claimed_fix_still_fail_fails_the_gate(store):
    record(store, "exploit", "v1", Verdict.FAIL)
    report(store, "exploit", ReportStatus.RESOLVED)
    result, _, rows = run(store, "v2", {"exploit": Verdict.FAIL})
    assert result.exit_code == gate.EXIT_FAIL
    assert rows["exploit"].status == "STILL_VULNERABLE" and "status=resolved" in rows["exploit"].claim


@pytest.mark.parametrize("claim", [{"claimed": ["exploit"]}, {"claimed": ["VULN-1"]}, {"all_claimed": True}])
def test_fix_can_be_claimed_from_the_command_line(store, claim):
    record(store, "exploit", "v1", Verdict.FAIL)
    report(store, "exploit")  # OPEN: no claim in the store
    result, _, rows = run(store, "v2", {"exploit": Verdict.FAIL}, **claim)
    assert result.exit_code == gate.EXIT_FAIL and rows["exploit"].status == "STILL_VULNERABLE"


def test_unclaimed_open_exploit_is_reported_but_does_not_block(store):
    record(store, "exploit", "v1", Verdict.FAIL)
    report(store, "exploit")
    result, _, rows = run(store, "v2", {"exploit": Verdict.FAIL})
    assert result.exit_code == gate.EXIT_PASS
    assert rows["exploit"].status == "KNOWN_OPEN" and not rows["exploit"].gating


def test_positive_control_flipping_to_fail_is_breakage(store):
    record(store, "exploit", "v1", Verdict.FAIL)
    result, _, rows = run(store, "v2", {"exploit": Verdict.PASS, "control": Verdict.FAIL})
    assert result.exit_code == gate.EXIT_FAIL
    assert rows["control"].status == "BREAKAGE" and rows["exploit"].status == "FIXED"


def test_validated_fix_passes_and_only_gated_cases_are_replayed(store):
    record(store, "exploit", "v1", Verdict.FAIL)
    store.add_case(case("never-failed"))
    record(store, "never-failed", "v1", Verdict.PASS)
    store.add_case(case("exploratory", in_regression=False))
    record(store, "exploratory", "v1", Verdict.FAIL)
    report(store, "exploit", ReportStatus.RESOLVED)

    result, red_team, rows = run(store, "v2", {"exploit": Verdict.PASS})

    assert result.exit_code == gate.EXIT_PASS
    assert sorted(red_team.replayed) == ["control", "exploit"]
    assert set(rows) == {"control", "exploit"} and rows["exploit"].status == "FIXED"


def test_same_version_recheck_uses_only_the_new_verdicts(store):
    """Re-gating the build that was fixed: an older FAIL at the same version must not mask the new PASS."""
    record(store, "exploit", "v1", Verdict.FAIL)
    report(store, "exploit", ReportStatus.RESOLVED)
    result, _, rows = run(store, "v1", {"exploit": Verdict.PASS})
    assert result.previous_version == "v1"
    assert rows["exploit"].current == "pass" and result.exit_code == gate.EXIT_PASS


def test_errored_gated_case_is_inconclusive_unless_allowed(store):
    record(store, "exploit", "v1", Verdict.FAIL)
    result, _, rows = run(store, "v2", {"exploit": Verdict.ERROR})
    assert result.exit_code == gate.EXIT_INCONCLUSIVE and rows["exploit"].status == "INCONCLUSIVE"
    assert run(store, "v3", {"exploit": Verdict.ERROR}, allow_errors=True)[0].exit_code == gate.EXIT_PASS


def test_empty_suite_is_inconclusive():
    result, _, _ = run(SqliteStore(":memory:"), "v1", {})
    assert result.exit_code == gate.EXIT_INCONCLUSIVE and "no confirmed exploits" in result.reason


@pytest.mark.parametrize("scenario,code", [("reappeared", 1), ("still-vulnerable", 1), ("breakage", 1),
                                           ("clean", 0)])
def test_script_exit_code(tmp_path, scenario, code):
    """The CI contract: the process itself exits nonzero when a reappeared exploit is simulated."""
    out = tmp_path / "gate.json"
    proc = subprocess.run([sys.executable, str(SCRIPT), "--demo", scenario, "--report", str(out)],
                          capture_output=True, text=True, cwd=tmp_path, timeout=60)
    assert proc.returncode == code, proc.stdout + proc.stderr
    assert f"GATE: {'FAIL' if code else 'PASS'}" in proc.stdout
    assert json.loads(out.read_text())["exit_code"] == code


def test_missing_store_is_inconclusive(tmp_path):
    assert gate.main(["--db", str(tmp_path / "nope.db"), "--target-version", "v1"]) == gate.EXIT_INCONCLUSIVE


# --------------------------------------------------------------------------- documented limitations

BLOCKED = {"expected": "inconclusive", "reason": "write-back ACL-blocked", "ref": "THREAT_MODEL.md section 7"}


def blocked_control(case_id):
    c = case(case_id, control=True)
    return c.model_copy(update={"oracle_config": {"positive_control": True, "known_limitation": BLOCKED}})


@pytest.fixture
def live_like(store):
    """The live store's shape: a known-open exploit, a runnable control, two blocked controls that ERROR."""
    record(store, "exploit", "v1", Verdict.FAIL)
    for cid in ("ea-06", "ipi-06"):
        store.add_case(blocked_control(cid))
        record(store, cid, "v1", Verdict.ERROR)
    return store


def test_blocked_controls_are_expected_skip_and_gate_passes(live_like):
    result, red_team, rows = run(live_like, "v1", {"exploit": Verdict.FAIL, "control": Verdict.PASS})

    assert result.exit_code == gate.EXIT_PASS and result.outcome == "PASS"
    assert sorted(red_team.replayed) == ["control", "exploit"]  # blocked controls are not replayed
    assert rows["ea-06"].status == rows["ipi-06"].status == "EXPECTED_SKIP"
    assert not rows["ea-06"].gating and "ACL-blocked" in rows["ea-06"].limitation
    assert rows["exploit"].status == "KNOWN_OPEN" and rows["control"].status == "OK"
    assert "2 expected-inconclusive" in result.reason
    text = gate.render(result)
    checked, _, listed = text.partition("expected-inconclusive (documented limitation)")
    assert "ea-06" not in checked and "ea-06" in listed and "GATE: PASS" in listed


def test_untagged_erroring_control_is_still_inconclusive(live_like):
    live_like.add_case(case("other-control", control=True))
    result, _, rows = run(live_like, "v1", {"exploit": Verdict.FAIL, "other-control": Verdict.ERROR})
    assert result.exit_code == gate.EXIT_INCONCLUSIVE and rows["other-control"].status == "INCONCLUSIVE"


def test_real_failures_still_fail_alongside_blocked_controls(live_like):
    record(live_like, "exploit", "v1", Verdict.PASS)  # worst at v1 stays FAIL: no reappearance
    report(live_like, "exploit", ReportStatus.RESOLVED)
    result, _, rows = run(live_like, "v2", {"exploit": Verdict.FAIL, "control": Verdict.FAIL})
    assert result.exit_code == gate.EXIT_FAIL
    assert rows["exploit"].status == "STILL_VULNERABLE" and rows["control"].status == "BREAKAGE"


def test_run_blocked_replays_them_and_a_fail_is_real_breakage(live_like):
    result, red_team, rows = run(live_like, "v2", {"ea-06": Verdict.FAIL, "ipi-06": Verdict.ERROR},
                                 run_blocked=True)
    assert "ea-06" in red_team.replayed and "ipi-06" in red_team.replayed
    assert rows["ea-06"].status == "BREAKAGE" and rows["ipi-06"].status == "EXPECTED_SKIP"
    assert result.exit_code == gate.EXIT_FAIL


def test_only_blocked_cases_is_inconclusive():
    s = SqliteStore(":memory:")
    s.add_case(blocked_control("ea-06"))
    result, red_team, _ = run(s, "v1", {})
    assert red_team.replayed == [] and result.exit_code == gate.EXIT_INCONCLUSIVE


def test_seed_tags_cover_only_the_documented_blocked_cases():
    """ea-* (write-back ACL-blocked) and ipi-02/05/06 (ingestion pending); never authz, never the ipi cases that
    reach a verdict."""
    from aep.limitations import expected_map
    seeds = [AttackCase.model_validate_json(p.read_text()) for p in (ROOT / "evals" / "seeds").glob("*/*.json")]
    tagged = {"-".join(cid.split("-")[:3]) for cid in expected_map(seeds)}
    assert tagged == {f"seed-ea-0{i}" for i in range(1, 7)} | {"seed-ipi-02", "seed-ipi-05", "seed-ipi-06"}
