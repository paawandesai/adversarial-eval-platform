"""Orchestrator: deterministic policy that decides what the Red Team attacks next.

No LLM is involved. Every decision comes from a fixed rule table over the Store, and each WorkItem's
``reason`` starts with the rule that fired (``"R2 partial_mutation: ..."``), so an auditor can replay
any decision from the Store's state.

Policy (see ``Orchestrator.next_work_item``)
-------------------------------------------
    R5 token_budget         session token budget exhausted -> emit nothing (campaign halts)
    R3 new_target_version   target /version differs from the last one seen -> regression trigger
    R1 coverage_floor       replay every seed not yet run this session, then fill categories that are
                            still under ``coverage_floor`` runs with generate-fresh work
    R2 partial_mutation     a PARTIAL verdict nobody has mutated yet -> mutate from that case
    R4 reverify_open_finding  a high-severity OPEN finding not re-tested on this version -> replay it
    R5 cost_guard           a category's cost per new finding is over the threshold -> R1/R2 skip it

Rules are numbered as in the design spec. They are *evaluated* in the order above: R3 runs before R1
because on a new target version the regression suite must be replayed before any new exploration.
R4 is exempt from the cost guard, since re-verifying a known high-severity finding is bounded work.

R1 schedules seeds before any generate-fresh work, across all categories. Seeds are cheap and
deterministic, and they are what the campaign is judged against. Generating fresh cases costs LLM
calls and only makes sense once the seeds are exhausted. Hand-authored seeds (``Origin.SEED``) are
replayed once per session, because they are the baseline every campaign re-checks. Other unmutated
cases are replayed only if the Store has never run them. Seed replays reserve ``seed_token_budget``,
not ``item_token_budget``, so planned LLM work can't lock up the session budget before a seed runs.

Agents are injected, not imported, so this module has no dependency on the Red Team / Judge /
Documentation packages and can be tested with fakes. Each dependency may be an object with one of the
method names below, or a plain callable. Sync and async implementations are both accepted.

    red_team.execute(item: WorkItem)                 -> AttackRun | list[AttackRun]  (or run_work_item)
    red_team.replay(case: AttackCase[, target_version=...]) -> AttackRun | list[AttackRun]
    judge.judge(run: AttackRun)                      -> JudgeVerdict | list[JudgeVerdict]
    documentation.document(verdict[, run=..., case=...]) -> VulnerabilityReport | None
    version_provider()                               -> str | None   (e.g. TargetClient.target_version)

Sync agents are called on a worker thread. That keeps them off the campaign's event loop, so an
agent that calls ``asyncio.run`` itself (as ``RedTeam.run_work_item`` does) still works.

Runs, verdicts and reports returned by the agents are written to the Store if the agent did not
already write them, so either persistence convention works without duplicates.

Every decision and every agent handoff is traced through ``aep.obs`` (steps ``orchestrator.decide`` and
``orchestrator.handoff.<agent>``) and appended to ``Orchestrator.audit_log``.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional
from uuid import uuid4

from pydantic import Field

from aep.obs import get_tracer
from contracts.contracts import (
    AttackCase, AttackCategory, AttackRun, JudgeVerdict, Origin, ReportStatus, Severity, Verdict,
    VulnerabilityReport, WorkItem,
)

log = logging.getLogger("aep.orchestrator")

SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3,
                 Severity.CRITICAL: 4}
# Worst verdict wins when several oracles judge one run (same order as the Store).
VERDICT_RANK = {Verdict.ERROR: 0, Verdict.PASS: 1, Verdict.PARTIAL: 2, Verdict.FAIL: 3}
OPEN_STATUSES = (ReportStatus.OPEN, ReportStatus.REGRESSED)

RULES = {
    "R1": "coverage_floor",
    "R2": "partial_mutation",
    "R3": "new_target_version",
    "R4": "reverify_open_finding",
    "R5": "cost_guard",
}
R5_BUDGET = "R5 token_budget"


def _rule(rule_id: str) -> str:
    return f"{rule_id} {RULES[rule_id]}"


@dataclass(frozen=True)
class PolicyConfig:
    coverage_floor: int = 3                 # runs per category before it counts as covered
    item_token_budget: int = 20_000         # per-WorkItem hard cap handed to the Red Team (LLM work)
    seed_token_budget: int = 2_000          # reservation for replay_seed/reverify: no generation spend
    session_token_budget: int = 200_000     # per-session cap; emission stops when it is spent
    min_item_tokens: int = 1_000            # don't emit an item with less budget than this
    max_cost_per_finding_usd: float = 2.0   # R5 threshold
    cost_guard_min_runs: int = 3            # R5 only judges categories with at least this many runs
    reverify_min_severity: Severity = Severity.HIGH
    categories: Optional[tuple] = None      # restrict the policy to these AttackCategory values


class PlannedWork(WorkItem):
    """A WorkItem with the structured audit fields behind its ``reason``.

    Still a WorkItem, so the Red Team and the Store accept it as-is (the Store keeps the extra fields
    in the JSON body).
    """
    rule: str = Field(description="rule id that fired, e.g. 'R2'")
    action: str = Field(description="replay_seed | generate | mutate | reverify | regression")
    target_version: Optional[str] = None
    previous_version: Optional[str] = None
    parent_run_id: Optional[str] = None
    vuln_id: Optional[str] = None
    regression_case_ids: list[str] = Field(default_factory=list)


@dataclass
class RegressionOutcome:
    """One regression-suite case compared across two target versions."""
    case_id: str
    category: str
    severity: str
    previous: Optional[Verdict]
    current: Optional[Verdict]
    status: str            # reappeared | worsened | fixed | improved | unchanged | new | error
    cross_category: bool = False
    run_ids: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def is_regression(self) -> bool:
        return self.status in ("reappeared", "worsened")


@dataclass
class CampaignResult:
    session_id: str
    items: list[WorkItem] = field(default_factory=list)
    runs: list[AttackRun] = field(default_factory=list)
    verdicts: list[JudgeVerdict] = field(default_factory=list)
    reports: list[VulnerabilityReport] = field(default_factory=list)
    regressions: list[RegressionOutcome] = field(default_factory=list)
    stop_reason: str = ""
    tokens_used: int = 0


def summarize_regression(outcomes: Iterable[RegressionOutcome]) -> dict:
    """What the CI gate needs: did anything regress, and what."""
    outcomes = list(outcomes)
    return {
        "passed": not any(o.is_regression for o in outcomes),
        "reappeared": [o.case_id for o in outcomes if o.status == "reappeared"],
        "worsened": [o.case_id for o in outcomes if o.status == "worsened"],
        "cross_category": [o.case_id for o in outcomes if o.cross_category],
        "fixed": [o.case_id for o in outcomes if o.status == "fixed"],
        "errors": [o.case_id for o in outcomes if o.status == "error"],
    }


class Orchestrator:
    def __init__(self, store: Any, *, red_team: Any = None, judge: Any = None, documentation: Any = None,
                 version_provider: Optional[Callable[[], Any]] = None, config: Optional[PolicyConfig] = None,
                 tracer: Any = None, last_seen_version: Optional[str] = None,
                 session_id: Optional[str] = None) -> None:
        self.store = store
        self.config = config or PolicyConfig()
        self.session_id = session_id or f"orch_{uuid4().hex[:12]}"
        self._tracer = tracer
        self._execute = _bind(red_team, ("execute", "run", "run_work_item"), "red_team")
        self._replay = _bind(red_team, ("replay", "run_case", "execute_case"), "red_team", allow_call=False)
        self._judge = _bind(judge, ("judge", "evaluate"), "judge")
        self._document = _bind(documentation, ("document", "write_report", "report"), "documentation")
        self._version_provider = version_provider

        self._last_seen_version = last_seen_version or self._latest_run_version()
        self._current_version: Optional[str] = None

        self._budget_total = self.config.session_token_budget
        self._tokens_used = 0
        self._reserved: dict[str, int] = {}          # work_id -> tokens reserved at emission

        self._coverage_pending: Counter = Counter()  # category -> R1 items emitted, no run seen yet
        self._used_seeds: set[str] = set()
        self._mutated_cases: set[str] = set()
        self._reverified: set[tuple[str, str]] = set()  # (vuln_id, version)

        self.audit_log: list[dict] = []
        self.decisions: list[dict] = []

    # ---- budget ----------------------------------------------------------------------------------

    @property
    def tokens_used(self) -> int:
        return self._tokens_used

    @property
    def budget_remaining(self) -> int:
        return self._budget_total - self._tokens_used - sum(self._reserved.values())

    def reset_budget(self, token_budget: int) -> None:
        """Start a fresh per-session token budget."""
        self._budget_total = token_budget
        self._tokens_used = 0
        self._reserved.clear()

    def complete(self, item: WorkItem, runs: Iterable[AttackRun] = (), *, failed: bool = False) -> None:
        """Release an item's reservation and charge what it actually used.

        A failed dispatch is charged its full reservation, since the Red Team may have spent tokens
        it could not report.
        """
        runs = list(runs)
        reserved = self._reserved.pop(item.work_id, 0)
        self._tokens_used += reserved if failed else sum(_run_tokens(r) for r in runs)
        if isinstance(item, PlannedWork) and item.rule == "R1" and runs:
            # The run now shows up in coverage(), so stop counting it as pending. A failed attempt stays
            # pending, which keeps R1 from re-emitting the same gap forever.
            self._coverage_pending[item.target_category.value] -= 1

    # ---- version ---------------------------------------------------------------------------------

    @property
    def last_seen_version(self) -> Optional[str]:
        return self._last_seen_version

    def observe_version(self, version: Optional[str]) -> None:
        if version:
            self._current_version = version

    def _latest_run_version(self) -> Optional[str]:
        list_runs = getattr(self.store, "list_runs", None)
        runs = list_runs() if list_runs else []
        return runs[-1].target_version if runs else None

    def _poll_version_sync(self) -> Optional[str]:
        if self._version_provider is None:
            return None
        result = self._version_provider()
        if inspect.isawaitable(result):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(_await(result))
            _close(result)
            log.warning("orchestrator: async version_provider inside a running loop; use arun_campaign")
            return None
        return result

    async def _poll_version_async(self) -> Optional[str]:
        if self._version_provider is None:
            return None
        return await _maybe_await(self._version_provider())

    # ---- policy ----------------------------------------------------------------------------------

    def next_work_item(self, target_version: Optional[str] = None) -> Optional[WorkItem]:
        """Apply the policy once. Returns the next WorkItem, or None when there is no work or budget.

        ``target_version`` is the target's current /version; if omitted, ``version_provider`` is polled.
        """
        return self._next(target_version if target_version is not None else self._poll_version_sync())

    def _next(self, version: Optional[str]) -> Optional[WorkItem]:
        self.observe_version(version)
        trail: list[str] = []
        with self._trace(self.session_id, "orchestrator.decide", target_version=self._current_version) as span:
            item = self._decide(self._current_version, trail)
            if item is not None:
                self._reserve(item)
                persist = getattr(self.store, "add_work_item", None)
                if persist is not None:
                    persist(item)
            decision = {
                "event": "decision",
                "session_id": self.session_id,
                "rule": item.rule if isinstance(item, PlannedWork) else None,
                "work_id": item.work_id if item else None,
                "reason": item.reason if item else trail[-1],
                "target_version": self._current_version,
                "trail": trail,
            }
            span.set_output(decision)
        self.decisions.append(decision)
        self.audit_log.append(decision)
        log.info("orchestrator.decide %s", decision["reason"])
        return item

    def _decide(self, version: Optional[str], trail: list[str]) -> Optional[PlannedWork]:
        remaining = self.budget_remaining
        if remaining < self.config.min_item_tokens:
            trail.append(f"{R5_BUDGET}: session budget exhausted ({self._tokens_used} used + "
                         f"{sum(self._reserved.values())} reserved of {self._budget_total}; "
                         f"{remaining} left < min_item_tokens {self.config.min_item_tokens}); halting")
            return None

        item = self._rule3_new_version(version, remaining, trail)
        if item is not None:
            return item

        cases = _CaseCache(self.store)
        coverage = self.store.coverage()
        guarded = self._rule5_cost_guard(coverage, cases, trail)
        budget = min(self.config.item_token_budget, remaining)

        for rule in (self._rule1_coverage_floor, self._rule2_partial_mutation):
            item = rule(coverage, guarded, cases, budget, version, trail)
            if item is not None:
                return item
        item = self._rule4_reverify(budget, version, trail)
        if item is not None:
            return item

        halted = f"; cost-guarded: {', '.join(sorted(guarded))}" if guarded else ""
        trail.append(f"no rule fired: coverage met, no unmutated PARTIALs, no un-retested high-severity "
                     f"open findings{halted}")
        return None

    def _categories(self) -> list[str]:
        cats = self.config.categories or tuple(AttackCategory)
        return [AttackCategory(c).value for c in cats]

    def _rule3_new_version(self, version: Optional[str], remaining: int,
                           trail: list[str]) -> Optional[PlannedWork]:
        r = _rule("R3")
        if version is None:
            trail.append(f"{r}: skipped, target version unknown")
            return None
        prev = self._last_seen_version
        if prev is None:
            self._last_seen_version = version
            trail.append(f"{r}: first version seen ({version!r}); recorded as baseline, nothing to compare")
            return None
        if version == prev:
            trail.append(f"{r}: target version unchanged ({version!r})")
            return None
        suite = self.store.list_cases(in_regression=True)
        if not suite:
            self._last_seen_version = version
            trail.append(f"{r}: version changed {prev!r} -> {version!r} but regression suite is empty; "
                         f"acknowledged")
            return None
        suite.sort(key=lambda c: -SEVERITY_RANK[c.severity_if_success])
        return PlannedWork(
            rule="R3", action="regression",
            target_category=suite[0].category, seed_case_id=None, token_budget=remaining,
            target_version=version, previous_version=prev,
            regression_case_ids=[c.case_id for c in suite],
            reason=(f"{r}: target /version changed {prev!r} -> {version!r}; replaying {len(suite)} "
                    f"regression-suite case(s) before any new exploration"),
        )

    def _rule5_cost_guard(self, coverage: dict, cases: "_CaseCache", trail: list[str]) -> dict[str, str]:
        """Categories whose cost per new finding is over the threshold -> why. R1 and R2 skip them."""
        r = _rule("R5")
        findings: Counter = Counter()
        for case_id in {v.case_id for v in self.store.list_verdicts(verdict=Verdict.FAIL)}:
            case = cases.get(case_id)
            if case is not None:
                findings[case.category.value] += 1
        guarded = {}
        for cat in self._categories():
            c = coverage.get(cat) or {}
            runs, cost = c.get("count", 0), float(c.get("cost_usd", 0.0))
            if runs < self.config.cost_guard_min_runs:
                continue
            per_finding = cost / max(findings[cat], 1)
            if per_finding > self.config.max_cost_per_finding_usd:
                why = (f"{r}: {cat} spent ${cost:.2f} over {runs} runs for {findings[cat]} finding(s) = "
                       f"${per_finding:.2f}/finding > ${self.config.max_cost_per_finding_usd:.2f}; "
                       f"deprioritized")
                guarded[cat] = why
                trail.append(why)
        return guarded

    def _rule1_coverage_floor(self, coverage: dict, guarded: dict, cases: "_CaseCache", budget: int,
                              version: Optional[str], trail: list[str]) -> Optional[PlannedWork]:
        r = _rule("R1")
        floor = self.config.coverage_floor
        tallies = []
        for order, cat in enumerate(self._categories()):
            runs = (coverage.get(cat) or {}).get("count", 0)
            pending = max(self._coverage_pending[cat], 0)
            tallies.append((runs + pending, order, cat, runs, pending))
        tallies.sort()

        def status(cat: str, runs: int, pending: int) -> str:
            scheduled = f" + {pending} scheduled" if pending else ""
            below = "<" if runs + pending < floor else ">="
            return f"{r}: {cat} has {runs} run(s){scheduled} {below} coverage floor {floor}; "

        def emit(cat: str, action: str, seed: Optional[AttackCase], token_budget: int,
                 reason: str) -> PlannedWork:
            self._coverage_pending[cat] += 1
            return PlannedWork(rule="R1", action=action, target_category=AttackCategory(cat),
                               seed_case_id=seed.case_id if seed else None, token_budget=token_budget,
                               target_version=version, reason=reason)

        def replay(cat: str, runs: int, pending: int, seed: AttackCase, why: str) -> PlannedWork:
            self._used_seeds.add(seed.case_id)
            seed_budget = min(self.config.seed_token_budget, self.budget_remaining)
            return emit(cat, "replay_seed", seed, seed_budget,
                        status(cat, runs, pending) + f"running unused seed {seed.case_id!r}{why}")

        # Pass 1: a hand-authored seed not yet run this session, in any category, beats generating
        # fresh. Least-covered category first.
        for _, _, cat, runs, pending in tallies:
            if cat in guarded:
                continue
            seed = self._unused_seed(cat, hand_authored=True)
            if seed is not None:
                return replay(cat, runs, pending, seed, " (seeds run before any generate-fresh work)")

        # Pass 2: every seed has run; fill categories still under the floor, with a never-run case
        # if the Store has one, else generated work.
        gaps = [t for t in tallies if t[0] < floor]
        if not gaps:
            trail.append(f"{r}: every seed ran this session and every category has >= {floor} runs")
            return None
        for _, _, cat, runs, pending in gaps:
            if cat in guarded:
                trail.append(f"{r}: {cat} below floor but cost-guarded (R5); skipped")
                continue
            seed = self._unused_seed(cat, hand_authored=False)
            if seed is not None:
                return replay(cat, runs, pending, seed, "")
            return emit(cat, "generate", None, budget, status(cat, runs, pending) +
                        "no unused seed in any category, Red Team to generate fresh")
        return None

    def _unused_seed(self, category: str, *, hand_authored: bool) -> Optional[AttackCase]:
        """Highest-severity replayable case in ``category``.

        hand_authored=True: ``Origin.SEED`` cases not yet run this session. False: any unmutated case
        the Store has never run.
        """
        if hand_authored:
            keep = lambda c: c.origin == Origin.SEED  # noqa: E731
        else:
            keep = lambda c: c.origin != Origin.MUTATION and not self.store.list_runs(case_id=c.case_id)  # noqa: E731
        seeds = [c for c in self.store.list_cases(category=category)
                 if c.case_id not in self._used_seeds and keep(c)]
        seeds.sort(key=lambda c: -SEVERITY_RANK[c.severity_if_success])  # stable: store order breaks ties
        return seeds[0] if seeds else None

    def _rule2_partial_mutation(self, coverage: dict, guarded: dict, cases: "_CaseCache", budget: int,
                                version: Optional[str], trail: list[str]) -> Optional[PlannedWork]:
        r = _rule("R2")
        partials = self.store.list_verdicts(verdict=Verdict.PARTIAL)
        if not partials:
            trail.append(f"{r}: no PARTIAL verdicts")
            return None
        failed = {v.case_id for v in self.store.list_verdicts(verdict=Verdict.FAIL)}
        best = None
        for recency, v in enumerate(partials):
            case = cases.get(v.case_id)
            if case is None or v.case_id in self._mutated_cases:
                continue
            cat = case.category.value
            if cat in guarded:
                trail.append(f"{r}: PARTIAL on {v.case_id!r} skipped, {cat} cost-guarded (R5)")
                continue
            if v.case_id in failed:
                continue  # already broke through; nothing to escalate
            if any(c.parent_case_id == v.case_id for c in self.store.list_cases(category=cat)):
                continue  # already mutated in an earlier session
            key = (SEVERITY_RANK[case.severity_if_success], recency)
            if best is None or key > best[0]:
                best = (key, v, case)
        if best is None:
            trail.append(f"{r}: every PARTIAL is already mutated, broke through, or cost-guarded")
            return None
        _, v, case = best
        self._mutated_cases.add(case.case_id)
        return PlannedWork(
            rule="R2", action="mutate", target_category=case.category, seed_case_id=case.case_id,
            token_budget=budget, target_version=version, parent_run_id=v.run_id,
            reason=(f"{r}: run {v.run_id!r} of case {case.case_id!r} ({case.category.value}, "
                    f"{case.severity_if_success.value} if successful) was judged PARTIAL by "
                    f"{v.oracle_used.value}; mutating it is the likeliest break-through"),
        )

    def _rule4_reverify(self, budget: int, version: Optional[str], trail: list[str]) -> Optional[PlannedWork]:
        r = _rule("R4")
        if version is None:
            trail.append(f"{r}: skipped, target version unknown")
            return None
        min_rank = SEVERITY_RANK[self.config.reverify_min_severity]
        reports = [rep for rep in self.store.list_reports()
                   if rep.status in OPEN_STATUSES and SEVERITY_RANK[rep.severity] >= min_rank]
        reports.sort(key=lambda rep: -SEVERITY_RANK[rep.severity])
        for rep in reports:
            if (rep.vuln_id, version) in self._reverified:
                continue
            if self.store.list_runs(case_id=rep.repro_case_id, target_version=version):
                continue
            self._reverified.add((rep.vuln_id, version))
            return PlannedWork(
                rule="R4", action="reverify", target_category=rep.category, seed_case_id=rep.repro_case_id,
                token_budget=min(budget, self.config.seed_token_budget), target_version=version,
                vuln_id=rep.vuln_id,
                reason=(f"{r}: {rep.severity.value} finding {rep.vuln_id!r} is {rep.status.value} and its repro "
                        f"case {rep.repro_case_id!r} has not been re-tested on version {version!r} "
                        f"(last seen {rep.last_seen_version or 'unknown'!r})"),
            )
        trail.append(f"{r}: no {self.config.reverify_min_severity.value}+ open finding needs re-testing "
                     f"on {version!r}")
        return None

    def _reserve(self, item: WorkItem) -> None:
        if not (isinstance(item, PlannedWork) and item.action == "regression"):
            self._reserved[item.work_id] = item.token_budget

    # ---- regression ------------------------------------------------------------------------------

    def run_regression(self, target_version: str, previous_version: Optional[str] = None
                       ) -> list[RegressionOutcome]:
        """Replay the regression suite against ``target_version`` and compare with the prior version."""
        return _run_sync(self.arun_regression(target_version, previous_version))

    async def arun_regression(self, target_version: str, previous_version: Optional[str] = None
                              ) -> list[RegressionOutcome]:
        cid = f"regr_{uuid4().hex[:12]}"
        prev = previous_version or self._prior_version(target_version)
        before = self.store.regression_results(prev) if prev else {}
        suite = self.store.list_cases(in_regression=True)
        self._audit({"event": "regression.start", "correlation_id": cid, "target_version": target_version,
                     "previous_version": prev, "cases": [c.case_id for c in suite]})

        run_ids: dict[str, list[str]] = {}
        errors: dict[str, str] = {}
        for case in suite:
            try:
                runs = await self._replay_case(case, target_version, cid)
                run_ids[case.case_id] = [r.run_id for r in runs]
                for run in runs:
                    self._tokens_used += _run_tokens(run)
                    if run.target_version != target_version:
                        log.warning("orchestrator: replay of %s ran against %r, expected %r",
                                    case.case_id, run.target_version, target_version)
                    await self._judge_run(run, case, document=False)
            except Exception as exc:  # one broken case must not hide the rest of the suite
                errors[case.case_id] = f"{type(exc).__name__}: {exc}"

        after = self.store.regression_results(target_version)
        outcomes = []
        for case in suite:
            prior, current = before.get(case.case_id), after.get(case.case_id)
            outcomes.append(RegressionOutcome(
                case_id=case.case_id, category=case.category.value, severity=case.severity_if_success.value,
                previous=prior, current=current, status=_classify(prior, current, case.case_id in errors),
                run_ids=run_ids.get(case.case_id, []), note=errors.get(case.case_id, ""),
            ))

        # Cross-category: a fix landed in one category and something regressed in another.
        fixed_in = {o.category for o in outcomes if o.status == "fixed"}
        for o in outcomes:
            if o.is_regression and fixed_in and o.category not in fixed_in:
                o.cross_category = True
                o.note = (o.note + "; " if o.note else "") + f"regressed while fixes landed in {sorted(fixed_in)}"

        summary = summarize_regression(outcomes)
        self._audit({"event": "regression.done", "correlation_id": cid, "target_version": target_version,
                     "previous_version": prev, **summary})
        for o in outcomes:
            if o.is_regression:
                log.warning("orchestrator: REGRESSION %s %s: %s -> %s%s", o.status, o.case_id,
                            _v(o.previous), _v(o.current), " (cross-category)" if o.cross_category else "")
        self._last_seen_version = target_version
        return outcomes

    def _prior_version(self, target_version: str) -> Optional[str]:
        if self._last_seen_version and self._last_seen_version != target_version:
            return self._last_seen_version
        list_runs = getattr(self.store, "list_runs", None)
        for run in reversed(list_runs() if list_runs else []):
            if run.target_version != target_version:
                return run.target_version
        return None

    async def _replay_case(self, case: AttackCase, target_version: str, cid: str) -> list[AttackRun]:
        self._used_seeds.add(case.case_id)  # replayed this session; R1 needn't run it again
        if self._replay is not None:
            fn, agent = self._replay, "redteam.replay"
            call = lambda: _call_flex(fn, case, target_version=target_version)  # noqa: E731
        else:
            item = PlannedWork(rule="R3", action="regression", target_category=case.category,
                               seed_case_id=case.case_id, token_budget=self.config.item_token_budget,
                               target_version=target_version,
                               reason=f"{_rule('R3')}: regression replay of {case.case_id!r}")
            fn, agent = self._require(self._execute, "red_team"), "redteam.execute"
            call = lambda: fn(item)  # noqa: E731
        runs = _as_list(await self._handoff(agent, call, correlation_id=cid, case_id=case.case_id,
                                            target_version=target_version))
        for run in runs:
            self._ensure_run(run)
        return runs

    # ---- campaign --------------------------------------------------------------------------------

    def run_campaign(self, max_items: int, token_budget: Optional[int] = None) -> CampaignResult:
        """Pull work until max_items, 'no more work', or the token budget runs out."""
        return _run_sync(self.arun_campaign(max_items, token_budget))

    async def arun_campaign(self, max_items: int, token_budget: Optional[int] = None) -> CampaignResult:
        if token_budget is not None:
            self.reset_budget(token_budget)
        result = CampaignResult(session_id=self.session_id)
        self._audit({"event": "campaign.start", "correlation_id": self.session_id, "max_items": max_items,
                     "token_budget": self._budget_total})
        for _ in range(max_items):
            item = self._next(await self._poll_version_async())
            if item is None:
                result.stop_reason = self.decisions[-1]["reason"]
                break
            result.items.append(item)
            if isinstance(item, PlannedWork) and item.action == "regression":
                result.regressions.extend(await self.arun_regression(item.target_version, item.previous_version))
                continue
            await self._dispatch(item, result)
        else:
            result.stop_reason = f"max_items {max_items} reached"
        result.tokens_used = self._tokens_used
        self._audit({"event": "campaign.stop", "correlation_id": self.session_id,
                     "stop_reason": result.stop_reason, "items": len(result.items),
                     "tokens_used": result.tokens_used})
        return result

    async def _dispatch(self, item: WorkItem, result: CampaignResult) -> None:
        """WorkItem -> Red Team -> Judge -> (FAIL) Documentation, each handoff traced."""
        action = getattr(item, "action", None)
        try:
            if action in ("replay_seed", "reverify") and self._replay is not None and item.seed_case_id:
                case = self.store.get_case(item.seed_case_id)
                fn = self._replay
                runs = _as_list(await self._handoff(
                    "redteam.replay", lambda: _call_flex(fn, case, target_version=self._current_version),
                    correlation_id=self.session_id, work_id=item.work_id, case_id=case.case_id))
            else:
                fn = self._require(self._execute, "red_team")
                runs = _as_list(await self._handoff("redteam.execute", lambda: fn(item),
                                                    correlation_id=self.session_id, work_id=item.work_id,
                                                    category=item.target_category.value))
        except Exception:
            self.complete(item, failed=True)
            return
        for run in runs:
            self._ensure_run(run)
        self.complete(item, runs)
        result.runs.extend(runs)
        for run in runs:
            try:
                verdicts, reports = await self._judge_run(run, None, document=True)
            except Exception:
                continue  # already logged by _handoff; keep the campaign going
            result.verdicts.extend(verdicts)
            result.reports.extend(reports)

    async def _judge_run(self, run: AttackRun, case: Optional[AttackCase], *, document: bool
                         ) -> tuple[list[JudgeVerdict], list[VulnerabilityReport]]:
        judge = self._require(self._judge, "judge")
        verdicts = _as_list(await self._handoff("judge", lambda: judge(run), correlation_id=run.correlation_id,
                                                run_id=run.run_id, case_id=run.case_id))
        for v in verdicts:
            self._ensure_verdict(v)
        reports: list[VulnerabilityReport] = []
        if not document or self._document is None:
            return verdicts, reports
        for v in verdicts:
            if v.verdict != Verdict.FAIL:
                continue
            case = case or _safe_get_case(self.store, run.case_id)
            doc = self._document
            try:
                out = await self._handoff("documentation", lambda: _call_flex(doc, v, run=run, case=case),
                                          correlation_id=run.correlation_id, run_id=run.run_id,
                                          case_id=run.case_id)
            except Exception:
                continue
            for rep in _as_list(out):
                self._ensure_report(rep)
                reports.append(rep)
        return verdicts, reports

    # ---- handoffs, persistence, tracing ---------------------------------------------------------

    async def _handoff(self, agent: str, call: Callable[[], Any], *, correlation_id: str, **meta: Any) -> Any:
        record = {"event": "handoff", "agent": agent, "correlation_id": correlation_id,
                  "session_id": self.session_id, **meta}
        with self._trace(correlation_id, f"orchestrator.handoff.{agent}", **meta) as span:
            try:
                # Sync agents run off the event loop (they may call asyncio.run themselves).
                # An async agent's call() just builds a coroutine, which is awaited here.
                out = await _maybe_await(await asyncio.to_thread(call))
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
                self._audit(record)
                log.exception("orchestrator: handoff to %s failed", agent)
                raise
            record["output"] = _describe(out)
            span.set_output(record["output"])
        self._audit(record)
        return out

    def _audit(self, record: dict) -> None:
        self.audit_log.append(record)
        log.info("orchestrator.%s %s", record["event"], {k: v for k, v in record.items() if k != "event"})

    def _trace(self, correlation_id: str, step: str, **meta: Any):
        return (self._tracer or get_tracer()).trace(correlation_id, step, **meta)

    @staticmethod
    def _require(fn: Optional[Callable], role: str) -> Callable:
        if fn is None:
            raise RuntimeError(f"orchestrator: no {role} injected")
        return fn

    def _ensure_run(self, run: AttackRun) -> None:
        try:
            self.store.get_run(run.run_id)
        except KeyError:
            self.store.add_run(run)

    def _ensure_verdict(self, verdict: JudgeVerdict) -> None:
        existing = [v for v in self.store.list_verdicts(case_id=verdict.case_id) if v.run_id == verdict.run_id]
        if not any(v.oracle_used == verdict.oracle_used and v.verdict == verdict.verdict for v in existing):
            self.store.add_verdict(verdict)

    def _ensure_report(self, report: VulnerabilityReport) -> None:
        if not any(r.vuln_id == report.vuln_id for r in self.store.list_reports()):
            self.store.add_report(report)


# ---- helpers ---------------------------------------------------------------------------------------


class _CaseCache:
    """get_case memoized for one decision; None for cases the Store doesn't know."""

    def __init__(self, store: Any) -> None:
        self._store = store
        self._cache: dict[str, Optional[AttackCase]] = {}

    def get(self, case_id: str) -> Optional[AttackCase]:
        if case_id not in self._cache:
            self._cache[case_id] = _safe_get_case(self._store, case_id)
        return self._cache[case_id]


def _safe_get_case(store: Any, case_id: str) -> Optional[AttackCase]:
    try:
        return store.get_case(case_id)
    except KeyError:
        return None


def _classify(previous: Optional[Verdict], current: Optional[Verdict], errored: bool) -> str:
    if errored or current is None or current == Verdict.ERROR:
        return "error"
    if previous is None or previous == Verdict.ERROR:
        return "new"
    if current == previous:
        return "unchanged"
    if previous == Verdict.PASS and current == Verdict.FAIL:
        return "reappeared"
    if VERDICT_RANK[current] > VERDICT_RANK[previous]:
        return "worsened"
    return "fixed" if current == Verdict.PASS else "improved"


def _run_tokens(run: AttackRun) -> int:
    return int(run.tokens_prompt or 0) + int(run.tokens_completion or 0)


def _v(verdict: Optional[Verdict]) -> Optional[str]:
    return verdict.value if verdict is not None else None


def _bind(obj: Any, names: tuple, role: str, *, allow_call: bool = True) -> Optional[Callable]:
    if obj is None:
        return None
    for name in names:
        fn = getattr(obj, name, None)
        if callable(fn):
            return fn
    if allow_call and callable(obj):
        return obj
    if not allow_call:
        return None
    raise TypeError(f"{role} must be callable or define one of {names}")


def _call_flex(fn: Callable, *args: Any, **kwargs: Any) -> Any:
    """Call fn with the keyword arguments it accepts (so agents can take fewer context args)."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return fn(*args)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params):
        return fn(*args, **kwargs)
    names = {p.name for p in params}
    return fn(*args, **{k: v for k, v in kwargs.items() if k in names})


def _as_list(out: Any) -> list:
    if out is None:
        return []
    if isinstance(out, (list, tuple)):
        return list(out)
    return [out]


def _describe(out: Any) -> Any:
    """Ids only: handoff records must stay small and PHI-free."""
    items = _as_list(out)
    desc = []
    for x in items:
        if isinstance(x, AttackRun):
            desc.append({"run_id": x.run_id, "case_id": x.case_id, "target_version": x.target_version,
                         "tokens": _run_tokens(x)})
        elif isinstance(x, JudgeVerdict):
            desc.append({"run_id": x.run_id, "verdict": x.verdict.value, "oracle": x.oracle_used.value})
        elif isinstance(x, VulnerabilityReport):
            desc.append({"vuln_id": x.vuln_id, "severity": x.severity.value})
        else:
            desc.append(type(x).__name__)
    return desc


async def _maybe_await(x: Any) -> Any:
    return await x if inspect.isawaitable(x) else x


async def _await(x: Any) -> Any:
    return await x


def _close(x: Any) -> None:
    close = getattr(x, "close", None)
    if close is not None:
        close()


def _run_sync(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    coro.close()
    raise RuntimeError("called from inside a running event loop; await the arun_* variant instead")
