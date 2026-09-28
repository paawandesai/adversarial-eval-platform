import asyncio
import re
import sys
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from contracts.contracts import (  # noqa: E402
    AttackCase, AttackCategory, AttackRun, ConversationTurn, JudgeVerdict, OracleType, Origin, OwaspLLM,
    OwaspMapping, ReportStatus, Severity, Verdict, VulnerabilityReport, WorkItem,
)
from aep.agents.orchestrator import (  # noqa: E402
    Orchestrator, PlannedWork, PolicyConfig, summarize_regression,
)
from aep.obs import LangfuseTracer  # noqa: E402
from aep.store import SqliteStore  # noqa: E402

PI = AttackCategory.DIRECT_PROMPT_INJECTION
AUTHZ = AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT
IPI = AttackCategory.INDIRECT_PROMPT_INJECTION
RULE_PREFIX = re.compile(r"^R[1-5] [a-z_]+: ")
_WORST = {Verdict.ERROR: 0, Verdict.PASS: 1, Verdict.PARTIAL: 2, Verdict.FAIL: 3}


# --------------------------------------------------------------------------- fakes


class FakeStore:
    """In-memory Store with the SqliteStore query surface the orchestrator uses."""

    def __init__(self):
        self.cases, self.runs, self.verdicts, self.reports, self.work_items = {}, {}, [], {}, []

    def add_case(self, case):
        self.cases[case.case_id] = case

    def get_case(self, case_id):
        return self.cases[case_id]

    def list_cases(self, category=None, in_regression=None, severity=None):
        cat = getattr(category, "value", category)
        return [c for c in self.cases.values()
                if (cat is None or c.category.value == cat)
                and (in_regression is None or c.in_regression_suite == in_regression)]

    def add_run(self, run):
        self.runs[run.run_id] = run

    def get_run(self, run_id):
        return self.runs[run_id]

    def list_runs(self, case_id=None, target_version=None, correlation_id=None):
        return [r for r in self.runs.values()
                if (case_id is None or r.case_id == case_id)
                and (target_version is None or r.target_version == target_version)]

    def add_verdict(self, verdict):
        self.verdicts.append(verdict)

    def list_verdicts(self, case_id=None, verdict=None, run_id=None, correlation_id=None, target_version=None):
        return [v for v in self.verdicts
                if (case_id is None or v.case_id == case_id) and (verdict is None or v.verdict == verdict)
                and (run_id is None or v.run_id == run_id)]

    def add_report(self, report):
        self.reports[report.vuln_id] = report

    def list_reports(self, **_):
        return list(self.reports.values())

    def add_work_item(self, item):
        self.work_items.append(item)

    def _worst(self, run_id) -> Optional[Verdict]:
        vs = [v.verdict for v in self.verdicts if v.run_id == run_id]
        return max(vs, key=_WORST.get) if vs else None

    def regression_results(self, target_version, category=None, severity=None):
        out = {}
        for c in self.list_cases(in_regression=True):
            worst = [self._worst(r.run_id) for r in self.list_runs(case_id=c.case_id, target_version=target_version)]
            worst = [w for w in worst if w is not None]
            out[c.case_id] = max(worst, key=_WORST.get) if worst else None
        return out

    def coverage(self):
        out = {cat.value: {"count": 0, "pass": 0, "fail": 0, "partial": 0, "cost_usd": 0.0}
               for cat in AttackCategory}
        for r in self.runs.values():
            bucket = out[self.cases[r.case_id].category.value]
            bucket["count"] += 1
            bucket["cost_usd"] += r.cost_usd
            worst = self._worst(r.run_id)
            if worst in (Verdict.PASS, Verdict.FAIL, Verdict.PARTIAL):
                bucket[worst.value] += 1
        return out


class FakeRedTeam:
    """Writes one run per work item / replay, like the real Red Team would."""

    def __init__(self, store, version="v1", tokens=1_000, cost=0.01):
        self.store, self.version, self.tokens, self.cost = store, version, tokens, cost
        self.executed: list[WorkItem] = []
        self.replayed: list[str] = []
        self.calls: list[str] = []

    def _run(self, case_id):
        run = AttackRun(case_id=case_id, target_version=self.version,
                        transcript=[ConversationTurn(role="user", content="x")],
                        tokens_prompt=self.tokens // 2, tokens_completion=self.tokens - self.tokens // 2,
                        cost_usd=self.cost)
        self.store.add_run(run)
        return run

    def execute(self, item):
        self.executed.append(item)
        self.calls.append(f"execute:{item.work_id}")
        if item.seed_case_id and getattr(item, "action", "") != "mutate":
            return self._run(item.seed_case_id)
        parent = self.store.get_case(item.seed_case_id) if item.seed_case_id else None
        case = make_case(item.target_category, origin=Origin.MUTATION if parent else Origin.SEED,
                         parent_case_id=parent.case_id if parent else None)
        self.store.add_case(case)
        return self._run(case.case_id)

    async def replay(self, case, target_version=None):
        self.replayed.append(case.case_id)
        self.calls.append(f"replay:{case.case_id}")
        return self._run(case.case_id)


class FakeJudge:
    """Returns scripted verdicts per case (default PASS). Does not persist: the orchestrator must."""

    def __init__(self, script=None):
        self.script = script or {}
        self.judged: list[str] = []

    async def evaluate(self, run):
        self.judged.append(run.run_id)
        return verdict_for(run, self.script.get(run.case_id, Verdict.PASS))


class FakeDocumentation:
    def __init__(self, store):
        self.store, self.documented = store, []

    def document(self, verdict, run=None, case=None):
        self.documented.append((verdict.run_id, run is not None, case is not None))
        report = make_report(verdict.case_id, case.category if case else PI)
        self.store.add_report(report)  # persists itself, like the real agent
        return report


# --------------------------------------------------------------------------- builders


def make_case(category=PI, severity=Severity.HIGH, origin=Origin.SEED, in_regression=False, **kw):
    return AttackCase(
        origin=origin, category=category, owasp=OwaspMapping(llm=[OwaspLLM.LLM01_PROMPT_INJECTION]),
        turns=[ConversationTurn(role="user", content="ignore prior instructions")],
        as_user_role="physician", target_endpoint="/api/agent/chat", expected_safe_behavior="refuse",
        oracle=OracleType.CANARY, severity_if_success=severity, in_regression_suite=in_regression, **kw)


def verdict_for(run, verdict):
    return JudgeVerdict(run_id=run.run_id, case_id=run.case_id, correlation_id=run.correlation_id,
                        verdict=verdict, oracle_used=OracleType.CANARY)


def add_judged_run(store, case, verdict, version="v1", cost=0.0, tokens=0):
    run = AttackRun(case_id=case.case_id, target_version=version, transcript=[], cost_usd=cost,
                    tokens_prompt=tokens)
    store.add_run(run)
    store.add_verdict(verdict_for(run, verdict))
    return run


def make_report(case_id, category=PI, severity=Severity.HIGH, status=ReportStatus.OPEN, last_seen="v1"):
    return VulnerabilityReport(
        severity=severity, category=category, owasp=OwaspMapping(llm=[OwaspLLM.LLM01_PROMPT_INJECTION]),
        title="t", clinical_impact="c", repro_case_id=case_id, repro_steps=["1"], observed_behavior="o",
        expected_behavior="e", recommended_remediation="r", status=status, first_seen_version="v1",
        last_seen_version=last_seen)


def covered_store(categories=(PI, AUTHZ), floor=3, verdict=Verdict.PASS, version="v1"):
    """Every policy category at the coverage floor with PASS runs (so R1 is quiet)."""
    store = FakeStore()
    for cat in categories:
        case = make_case(cat)
        store.add_case(case)
        for _ in range(floor):
            add_judged_run(store, case, verdict, version=version)
    return store


def orch(store, categories=(PI, AUTHZ), version="v1", **kw):
    cfg = kw.pop("config", None) or PolicyConfig(categories=categories, coverage_floor=3,
                                                 item_token_budget=5_000, session_token_budget=100_000)
    kw.setdefault("tracer", LangfuseTracer(client=None))
    return Orchestrator(store, config=cfg, version_provider=lambda: version, **kw)


# --------------------------------------------------------------------------- R1 coverage floor


def test_r1_coverage_floor_schedules_unused_seed_in_least_covered_category():
    store = covered_store(categories=(PI,))
    used = make_case(AUTHZ)
    unused_low = make_case(AUTHZ, severity=Severity.LOW)
    unused_crit = make_case(AUTHZ, severity=Severity.CRITICAL)
    for c in (used, unused_low, unused_crit):
        store.add_case(c)
    add_judged_run(store, used, Verdict.PASS)

    item = orch(store).next_work_item()

    assert isinstance(item, PlannedWork) and item.rule == "R1"
    assert item.target_category == AUTHZ
    assert item.seed_case_id == unused_crit.case_id  # unused, highest severity first
    assert item.reason.startswith("R1 coverage_floor: ")
    assert "1 run(s)" in item.reason and unused_crit.case_id in item.reason
    assert store.work_items == [item]  # persisted for audit


def test_r1_generates_fresh_when_no_unused_seed_and_counts_scheduled_items():
    store = covered_store(categories=(PI,))
    o = orch(store)
    items = [o.next_work_item() for _ in range(4)]
    # AUTHZ has no seeds: three fresh-generation items fill the floor, then R1 goes quiet.
    assert [i.rule for i in items[:3]] == ["R1"] * 3
    assert all(i.seed_case_id is None and i.action == "generate" for i in items[:3])
    assert "scheduled" in items[2].reason
    assert items[3] is None


# --------------------------------------------------------------------------- R2 partial mutation


def test_r2_mutates_most_promising_partial_once():
    store = covered_store()
    low = make_case(PI, severity=Severity.LOW)
    crit = make_case(AUTHZ, severity=Severity.CRITICAL)
    broke = make_case(PI, severity=Severity.CRITICAL)
    for c in (low, crit, broke):
        store.add_case(c)
    add_judged_run(store, low, Verdict.PARTIAL)
    crit_run = add_judged_run(store, crit, Verdict.PARTIAL)
    add_judged_run(store, broke, Verdict.PARTIAL)
    add_judged_run(store, broke, Verdict.FAIL)  # already broke through: nothing to escalate

    o = orch(store)
    first, second, third = o.next_work_item(), o.next_work_item(), o.next_work_item()

    assert first.rule == "R2" and first.action == "mutate"
    assert first.seed_case_id == crit.case_id and first.parent_run_id == crit_run.run_id
    assert first.reason.startswith("R2 partial_mutation: ") and crit_run.run_id in first.reason
    assert second.rule == "R2" and second.seed_case_id == low.case_id
    assert third is None


def test_r2_skips_partial_that_already_has_a_mutation_child():
    store = covered_store()
    parent = make_case(PI)
    store.add_case(parent)
    add_judged_run(store, parent, Verdict.PARTIAL)
    store.add_case(make_case(PI, origin=Origin.MUTATION, parent_case_id=parent.case_id))
    assert orch(store).next_work_item() is None


def test_r1_takes_precedence_over_r2():
    store = covered_store(categories=(PI,))
    partial = make_case(PI)
    store.add_case(partial)
    add_judged_run(store, partial, Verdict.PARTIAL)
    item = orch(store).next_work_item()  # AUTHZ has no runs
    assert item.rule == "R1" and item.target_category == AUTHZ


# --------------------------------------------------------------------------- R3 new version


def test_new_version_triggers_regression_before_exploration():
    store = covered_store(categories=(PI,))  # AUTHZ below floor -> R1 would fire
    reg = make_case(PI, in_regression=True)
    store.add_case(reg)
    add_judged_run(store, reg, Verdict.PASS, version="v1")
    o = orch(store, version="v2")
    assert o.last_seen_version == "v1"  # derived from the Store's latest run

    item = o.next_work_item()
    assert item.rule == "R3" and item.action == "regression"
    assert item.reason.startswith("R3 new_target_version: ")
    assert "'v1' -> 'v2'" in item.reason
    assert item.target_version == "v2" and item.previous_version == "v1"
    assert item.regression_case_ids == [reg.case_id]
    assert o.next_work_item().rule == "R3"  # keeps gating until the regression actually runs

    o._replay = FakeRedTeam(store, version="v2").replay
    o._judge = FakeJudge().evaluate
    o.run_regression("v2")
    assert o.last_seen_version == "v2"
    assert o.next_work_item().rule == "R1"  # exploration resumes only now


def test_first_version_is_baseline_not_a_trigger():
    store = FakeStore()
    store.add_case(make_case(PI, in_regression=True))
    o = orch(store, categories=(PI,))
    item = o.next_work_item()
    assert item.rule == "R1"
    assert o.last_seen_version == "v1"
    assert any("baseline" in t for t in o.decisions[-1]["trail"])


def test_campaign_runs_regression_before_any_exploration_on_new_version():
    store = covered_store(categories=(PI,))
    reg = make_case(PI, in_regression=True)
    store.add_case(reg)
    add_judged_run(store, reg, Verdict.PASS, version="v1")
    rt = FakeRedTeam(store, version="v2")
    o = orch(store, version="v2", red_team=rt, judge=FakeJudge(), documentation=FakeDocumentation(store))

    result = o.run_campaign(max_items=2)

    assert [i.rule for i in result.items] == ["R3", "R1"]
    assert rt.calls[0] == f"replay:{reg.case_id}" and rt.calls[1].startswith("execute:")
    assert [o_.status for o_ in result.regressions] == ["unchanged"]


# --------------------------------------------------------------------------- R4 re-verify


def test_r4_reverifies_high_open_finding_not_retested_on_current_version():
    store = covered_store(version="v2")
    retested, stale, low, closed = (make_case(PI) for _ in range(4))
    for c in (retested, stale, low, closed):
        store.add_case(c)
    add_judged_run(store, retested, Verdict.FAIL, version="v2")
    store.add_report(make_report(retested.case_id, severity=Severity.CRITICAL))
    store.add_report(make_report(low.case_id, severity=Severity.LOW))
    store.add_report(make_report(closed.case_id, status=ReportStatus.RESOLVED))
    stale_report = make_report(stale.case_id, category=AUTHZ, severity=Severity.HIGH)
    store.add_report(stale_report)

    o = orch(store, version="v2", last_seen_version="v2")
    item = o.next_work_item()

    assert item.rule == "R4" and item.action == "reverify"
    assert item.seed_case_id == stale.case_id and item.vuln_id == stale_report.vuln_id
    assert item.target_category == AUTHZ
    assert item.reason.startswith("R4 reverify_open_finding: ") and "'v2'" in item.reason
    assert o.next_work_item() is None  # emitted once per version


def test_r2_takes_precedence_over_r4():
    store = covered_store()
    partial, finding = make_case(PI), make_case(PI)
    store.add_case(partial)
    store.add_case(finding)
    add_judged_run(store, partial, Verdict.PARTIAL)
    store.add_report(make_report(finding.case_id, severity=Severity.CRITICAL))
    o = orch(store, version="v2", last_seen_version="v2")
    assert [o.next_work_item().rule, o.next_work_item().rule] == ["R2", "R4"]


# --------------------------------------------------------------------------- R5 cost guard + token budget


def test_r5_cost_guard_deprioritizes_expensive_category():
    store = covered_store()
    for case in [c for c in store.cases.values() if c.category == PI]:
        for run in store.list_runs(case_id=case.case_id):
            store.runs[run.run_id] = run.model_copy(update={"cost_usd": 5.0})  # $15, 0 findings
    pi_partial = make_case(PI, severity=Severity.CRITICAL)
    authz_partial = make_case(AUTHZ, severity=Severity.LOW)
    store.add_case(pi_partial)
    store.add_case(authz_partial)
    add_judged_run(store, pi_partial, Verdict.PARTIAL)
    add_judged_run(store, authz_partial, Verdict.PARTIAL)

    o = orch(store)
    item = o.next_work_item()
    # PI's partial is more severe, but PI is over the cost-per-finding threshold.
    assert item.rule == "R2" and item.seed_case_id == authz_partial.case_id
    trail = o.decisions[-1]["trail"]
    assert any(t.startswith("R5 cost_guard: direct_prompt_injection") and "deprioritized" in t for t in trail)

    assert o.next_work_item() is None  # only cost-guarded work left -> halt
    assert "cost-guarded: direct_prompt_injection" in o.decisions[-1]["reason"]


def test_r5_cost_guard_divides_by_findings():
    store = covered_store(categories=(PI,), verdict=Verdict.FAIL)  # one failing case = 1 finding, 3 runs
    for run in list(store.runs.values()):
        store.runs[run.run_id] = run.model_copy(update={"cost_usd": 1.0})  # $3 for 1 finding
    partial = make_case(PI)
    store.add_case(partial)
    add_judged_run(store, partial, Verdict.PARTIAL)
    cfg = PolicyConfig(categories=(PI,), max_cost_per_finding_usd=5.0)
    assert orch(store, categories=(PI,), config=cfg).next_work_item().rule == "R2"


def test_next_work_item_returns_none_when_budget_spent():
    store = FakeStore()
    cfg = PolicyConfig(categories=(PI,), item_token_budget=5_000, session_token_budget=8_000,
                       min_item_tokens=1_000)
    o = orch(store, categories=(PI,), config=cfg)
    a, b, c = o.next_work_item(), o.next_work_item(), o.next_work_item()
    assert a.token_budget == 5_000 and b.token_budget == 3_000  # capped by what's left
    assert c is None
    assert o.decisions[-1]["reason"].startswith("R5 token_budget: ")


def test_token_budget_halts_campaign():
    store = FakeStore()
    rt = FakeRedTeam(store, tokens=4_000)
    cfg = PolicyConfig(categories=(PI, AUTHZ, IPI), coverage_floor=10, item_token_budget=5_000,
                       min_item_tokens=1_000)
    o = orch(store, categories=(PI, AUTHZ, IPI), config=cfg, red_team=rt, judge=FakeJudge())

    result = o.run_campaign(max_items=100, token_budget=10_000)

    # 4k actually used per item: 0 -> 4k -> 8k; 2k left still allows a (2k-capped) item -> 12k; halt.
    assert len(rt.executed) == 3
    assert [i.token_budget for i in result.items] == [5_000, 5_000, 2_000]
    assert result.stop_reason.startswith("R5 token_budget: ")
    assert result.tokens_used == 12_000
    assert o.budget_remaining < 0


def test_failed_red_team_is_charged_and_does_not_loop():
    class Broken(FakeRedTeam):
        def execute(self, item):
            self.executed.append(item)
            raise RuntimeError("target unreachable")

    store = FakeStore()
    rt = Broken(store)
    o = orch(store, categories=(PI,), red_team=rt, judge=FakeJudge())
    result = o.run_campaign(max_items=50, token_budget=1_000_000)
    assert len(rt.executed) == 3  # floor of 3 attempts, then R1 stops re-emitting
    assert result.tokens_used == 3 * 5_000  # full reservation charged per failure
    assert result.stop_reason.startswith("no rule fired")
    errors = [r for r in o.audit_log if r["event"] == "handoff" and "error" in r]
    assert len(errors) == 3 and "target unreachable" in errors[0]["error"]


# --------------------------------------------------------------------------- campaign handoffs


def test_campaign_handoffs_are_explicit_logged_and_persisted_once():
    store = FakeStore()
    seed = make_case(PI)
    store.add_case(seed)
    rt = FakeRedTeam(store)
    judge = FakeJudge(script={seed.case_id: Verdict.FAIL})
    doc = FakeDocumentation(store)
    tracer = LangfuseTracer(client=None)
    o = orch(store, categories=(PI,), red_team=rt, judge=judge, documentation=doc, tracer=tracer)

    result = o.run_campaign(max_items=3, token_budget=1_000_000)

    assert all(RULE_PREFIX.match(i.reason) for i in result.items)
    assert result.items[0].seed_case_id == seed.case_id and result.items[0].action == "replay_seed"
    assert rt.replayed == [seed.case_id]  # an unused seed is replayed as-is
    assert len(result.runs) == 3 and len(result.verdicts) == 3
    assert len(doc.documented) == 1 and doc.documented[0][1:] == (True, True)  # got run + case
    assert len(store.verdicts) == 3  # judge didn't persist; orchestrator did, exactly once
    assert len(store.reports) == 1  # documentation persisted; orchestrator didn't duplicate

    handoffs = [r["agent"] for r in o.audit_log if r["event"] == "handoff"]
    assert handoffs[:3] == ["redteam.replay", "judge", "documentation"]
    steps = [rec["step"] for rec in tracer.records]
    assert "orchestrator.decide" in steps
    assert {"orchestrator.handoff.redteam.replay", "orchestrator.handoff.judge",
            "orchestrator.handoff.documentation", "orchestrator.handoff.redteam.execute"} <= set(steps)
    judge_span = next(rec for rec in tracer.records if rec["step"] == "orchestrator.handoff.judge")
    assert judge_span["correlation_id"] == result.runs[0].correlation_id  # threads with the run
    assert [e["event"] for e in o.audit_log][0] == "campaign.start"
    assert o.audit_log[-1]["event"] == "campaign.stop"


def test_plain_callables_are_accepted_as_agents():
    store = FakeStore()
    rt = FakeRedTeam(store)
    o = orch(store, categories=(PI,), red_team=rt.execute, judge=lambda run: verdict_for(run, Verdict.PASS))
    result = o.run_campaign(max_items=1)
    assert len(result.runs) == 1 and len(store.verdicts) == 1


def test_async_version_provider_in_campaign():
    store = FakeStore()
    rt = FakeRedTeam(store)

    async def version():
        return "v9"

    o = Orchestrator(store, red_team=rt, judge=FakeJudge(), version_provider=version,
                     config=PolicyConfig(categories=(PI,)), tracer=LangfuseTracer(client=None))
    asyncio.run(o.arun_campaign(max_items=1))
    assert o.last_seen_version == "v9"
    assert o.next_work_item() is not None  # sync path runs the async provider too


# --------------------------------------------------------------------------- run_regression


def _regression_store(store):
    exploit = make_case(PI, in_regression=True, severity=Severity.CRITICAL)
    fixed = make_case(AUTHZ, in_regression=True)
    steady = make_case(PI, in_regression=True)
    for c in (exploit, fixed, steady):
        store.add_case(c)
    add_judged_run(store, exploit, Verdict.PASS, version="v1")
    add_judged_run(store, fixed, Verdict.FAIL, version="v1")
    add_judged_run(store, steady, Verdict.PASS, version="v1")
    judge = FakeJudge(script={exploit.case_id: Verdict.FAIL, fixed.case_id: Verdict.PASS})
    return exploit, fixed, steady, judge


@pytest.mark.parametrize("store_factory", [FakeStore, SqliteStore], ids=["fake", "sqlite"])
def test_run_regression_flags_reappeared_exploit_and_cross_category(store_factory):
    store = store_factory()
    exploit, fixed, steady, judge = _regression_store(store)
    rt = FakeRedTeam(store, version="v2")
    o = orch(store, version="v2", red_team=rt, judge=judge)

    outcomes = {x.case_id: x for x in o.run_regression("v2")}

    assert sorted(rt.replayed) == sorted([exploit.case_id, fixed.case_id, steady.case_id])
    assert outcomes[exploit.case_id].status == "reappeared"
    assert (outcomes[exploit.case_id].previous, outcomes[exploit.case_id].current) == (Verdict.PASS, Verdict.FAIL)
    assert outcomes[exploit.case_id].cross_category  # fix landed in AUTHZ, PI broke
    assert outcomes[fixed.case_id].status == "fixed" and not outcomes[fixed.case_id].cross_category
    assert outcomes[steady.case_id].status == "unchanged"

    gate = summarize_regression(outcomes.values())
    assert gate["passed"] is False
    assert gate["reappeared"] == [exploit.case_id] and gate["cross_category"] == [exploit.case_id]
    assert gate["fixed"] == [fixed.case_id]
    assert o.last_seen_version == "v2"
    done = [r for r in o.audit_log if r["event"] == "regression.done"][0]
    assert done["reappeared"] == [exploit.case_id] and done["previous_version"] == "v1"


def test_run_regression_same_category_regression_is_not_cross_category():
    store = FakeStore()
    exploit = make_case(PI, in_regression=True)
    store.add_case(exploit)
    add_judged_run(store, exploit, Verdict.PASS, version="v1")
    o = orch(store, version="v2", red_team=FakeRedTeam(store, version="v2"),
             judge=FakeJudge(script={exploit.case_id: Verdict.FAIL}))
    [outcome] = o.run_regression("v2")
    assert outcome.status == "reappeared" and not outcome.cross_category


def test_run_regression_reports_errors_without_aborting_suite():
    store = FakeStore()
    ok, bad = make_case(PI, in_regression=True), make_case(PI, in_regression=True)
    store.add_case(ok)
    store.add_case(bad)
    rt = FakeRedTeam(store, version="v2")
    real_replay = rt.replay

    async def flaky(case, target_version=None):
        if case.case_id == bad.case_id:
            raise TimeoutError("target timeout")
        return await real_replay(case, target_version)

    rt.replay = flaky
    o = orch(store, version="v2", red_team=rt, judge=FakeJudge(), last_seen_version="v1")
    outcomes = {x.case_id: x for x in o.run_regression("v2")}
    assert outcomes[ok.case_id].status == "new"
    assert outcomes[bad.case_id].status == "error" and "target timeout" in outcomes[bad.case_id].note
    assert summarize_regression(outcomes.values())["errors"] == [bad.case_id]


def test_run_regression_falls_back_to_execute_when_red_team_has_no_replay():
    store = FakeStore()
    case = make_case(PI, in_regression=True)
    store.add_case(case)
    rt = FakeRedTeam(store, version="v2")
    o = orch(store, version="v2", red_team=rt.execute, judge=FakeJudge())
    o.run_regression("v2", previous_version="v1")
    assert [i.seed_case_id for i in rt.executed] == [case.case_id]
    assert rt.executed[0].reason.startswith("R3 new_target_version: ")
