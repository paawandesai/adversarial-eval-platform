#!/usr/bin/env python3
"""
Regression gate: replay confirmed exploits against the current target and fail CI on a bad result.

  1. Load the gated suite from the store. That is every regression-suite case (in_regression_suite)
     with a FAIL on record (a confirmed exploit), plus every regression-suite positive control
     (oracle_config.positive_control, or subcategory "positive_control").
  2. Replay only that suite through Orchestrator.run_regression against the current target version.
  3. Compare each case's new verdict with its recorded verdict at the previous target_version.
  4. Exit nonzero if the gate fails:

       REAPPEARED        exploit that was PASS at the previous version is FAIL again
       STILL_VULNERABLE  exploit with a claimed fix is still FAIL
       BREAKAGE          positive control is FAIL (legitimate use is blocked or broken)

A fix is "claimed" when the exploit's VulnerabilityReport is RESOLVED or has
fix_validated_against_version set, or when --claimed-fix names its case_id or vuln_id
(also via AEP_CLAIMED_FIXES, comma-separated, or --all-claimed). An exploit that is still FAIL
with no claimed fix is KNOWN_OPEN. It is reported but doesn't fail the gate, because the target
hasn't said it fixed it.

Exit codes:
  0  PASS
  1  FAIL          at least one REAPPEARED, STILL_VULNERABLE or BREAKAGE
  2  INCONCLUSIVE  a gated case errored or wasn't judged, the gated suite is empty, or the target
                   version could not be determined. --allow-errors turns the first two into PASS.

Target version: --target-version, else $AEP_TARGET_VERSION, else polled live from the target
(TargetClient.target_version). The previous version is --previous-version, else the most recent
other version recorded for the gated cases.

Usage:
  python3 scripts/regression_gate.py --db seeds.db                      # live target (.env loaded)
  python3 scripts/regression_gate.py --db seeds.db --claimed-fix seed-authz-07-brief-cross-patient
  python3 scripts/regression_gate.py --demo reappeared                  # offline, simulated, exits 1
  python3 scripts/regression_gate.py --demo clean --report gate.json    # offline, exits 0
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aep.agents.orchestrator import Orchestrator, VERDICT_RANK  # noqa: E402
from contracts.contracts import (  # noqa: E402
    AttackCase, AttackRun, ConversationTurn, JudgeVerdict, ReportStatus, Verdict, VulnerabilityReport,
)

EXIT_PASS, EXIT_FAIL, EXIT_INCONCLUSIVE = 0, 1, 2
GATING = ("REAPPEARED", "STILL_VULNERABLE", "BREAKAGE")


# ---- suite selection ------------------------------------------------------------------------------


def is_positive_control(case: AttackCase) -> bool:
    return bool((case.oracle_config or {}).get("positive_control")) or case.subcategory == "positive_control"


def verdict_history(store: Any, case_id: str) -> dict[str, Verdict]:
    """target_version -> worst recorded verdict, in the order the versions were first run."""
    by_run = {}
    for v in store.list_verdicts(case_id=case_id):
        prev = by_run.get(v.run_id)
        if prev is None or VERDICT_RANK[v.verdict] > VERDICT_RANK[prev]:
            by_run[v.run_id] = v.verdict
    history: dict[str, Verdict] = {}
    for run in store.list_runs(case_id=case_id):
        verdict = by_run.get(run.run_id)
        if verdict is None:
            continue
        prev = history.get(run.target_version)
        if prev is None or VERDICT_RANK[verdict] > VERDICT_RANK[prev]:
            history[run.target_version] = verdict
    return history


@dataclass
class GatedCase:
    case: AttackCase
    kind: str                       # exploit | control
    history: dict[str, Verdict]     # before the replay


def select_suite(store: Any) -> list[GatedCase]:
    suite = []
    for case in store.list_cases(in_regression=True):
        history = verdict_history(store, case.case_id)
        if is_positive_control(case):
            suite.append(GatedCase(case, "control", history))
        elif Verdict.FAIL in history.values():
            suite.append(GatedCase(case, "exploit", history))
    return suite


def fix_claims(store: Any, claimed: Iterable[str] = (), all_claimed: bool = False,
               case_ids: Iterable[str] = ()) -> dict[str, str]:
    """case_id -> why its fix counts as claimed."""
    claimed = {c.strip() for c in claimed if c and c.strip()}
    case_ids = set(case_ids)
    out: dict[str, str] = {}
    if all_claimed:
        out.update({cid: "--all-claimed" for cid in case_ids})
    for rep in store.list_reports():
        if rep.status == ReportStatus.RESOLVED:
            out.setdefault(rep.repro_case_id, f"{rep.vuln_id} status=resolved")
        elif rep.fix_validated_against_version:
            out.setdefault(rep.repro_case_id, f"{rep.vuln_id} fix validated at {rep.fix_validated_against_version}")
        if rep.vuln_id in claimed:
            out.setdefault(rep.repro_case_id, f"--claimed-fix {rep.vuln_id}")
    for cid in claimed:
        if cid in case_ids:
            out.setdefault(cid, f"--claimed-fix {cid}")
    return out


def pick_previous_version(store: Any, suite: list[GatedCase], target_version: str) -> Optional[str]:
    """Most recent version other than the target, among the gated cases' judged runs. Falls back to the
    target itself (a re-check of the same build) when that is the only version on record."""
    ids = {g.case.case_id for g in suite}
    judged = set()
    for g in suite:
        judged.update(g.history)
    versions = [r.target_version for r in store.list_runs() if r.case_id in ids and r.target_version in judged]
    for version in reversed(versions):
        if version != target_version:
            return version
    return target_version if target_version in versions else None


class SuiteView:
    """The store, with its regression suite narrowed to the gated cases, so run_regression replays only
    those. Everything else (writes included) goes straight through to the real store."""

    def __init__(self, store: Any, case_ids: Iterable[str]) -> None:
        self._store = store
        self._ids = set(case_ids)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def list_cases(self, category=None, in_regression=None, severity=None):
        cases = self._store.list_cases(category=category, in_regression=in_regression, severity=severity)
        return [c for c in cases if c.case_id in self._ids] if in_regression else cases

    def regression_results(self, target_version, category=None, severity=None):
        out = self._store.regression_results(target_version, category=category, severity=severity)
        return {k: v for k, v in out.items() if k in self._ids}


# ---- evaluation -----------------------------------------------------------------------------------


@dataclass
class GateRow:
    case_id: str
    kind: str
    category: str
    severity: str
    previous_version: Optional[str]
    previous: Optional[str]
    current: Optional[str]
    status: str
    gating: bool
    claim: str = ""
    history: dict = field(default_factory=dict)
    note: str = ""


@dataclass
class GateResult:
    target_version: Optional[str]
    previous_version: Optional[str]
    rows: list[GateRow]
    outcome: str        # PASS | FAIL | INCONCLUSIVE
    exit_code: int
    reason: str

    def to_json(self) -> dict:
        return {**{k: v for k, v in asdict(self).items() if k != "rows"},
                "rows": [asdict(r) for r in self.rows]}


def _worst(verdicts: Iterable[Verdict]) -> Optional[Verdict]:
    verdicts = list(verdicts)
    return max(verdicts, key=VERDICT_RANK.get) if verdicts else None


def _val(v: Optional[Verdict]) -> Optional[str]:
    return v.value if v is not None else None


def classify(kind: str, previous: Optional[Verdict], current: Optional[Verdict], claimed: bool) -> str:
    if current is None or current == Verdict.ERROR:
        return "INCONCLUSIVE"
    if kind == "control":
        return "BREAKAGE" if current == Verdict.FAIL else "OK"
    if current == Verdict.FAIL:
        if previous == Verdict.PASS:
            return "REAPPEARED"
        return "STILL_VULNERABLE" if claimed else "KNOWN_OPEN"
    if current == Verdict.PARTIAL:
        return "PARTIAL"
    return "FIXED" if previous in (Verdict.FAIL, Verdict.PARTIAL) else "HOLDING"


def run_gate(store: Any, target_version: str, *, previous_version: Optional[str] = None,
             red_team: Any = None, judge: Any = None, tracer: Any = None,
             claimed: Iterable[str] = (), all_claimed: bool = False, allow_errors: bool = False) -> GateResult:
    suite = select_suite(store)
    if not suite:
        return _finish(target_version, previous_version, [], allow_errors,
                       empty="no confirmed exploits or positive controls in the regression suite")
    ids = [g.case.case_id for g in suite]
    prev = previous_version or pick_previous_version(store, suite, target_version)
    claims = fix_claims(store, claimed, all_claimed, ids)

    injected = red_team is not None and judge is not None
    orch = Orchestrator(SuiteView(store, ids), red_team=red_team, judge=judge, tracer=tracer,
                        last_seen_version=prev, default_agents=not injected,
                        session_id="regression_gate")
    outcomes = {o.case_id: o for o in orch.run_regression(target_version, previous_version=prev)}

    rows = []
    for g in suite:
        cid = g.case.case_id
        o = outcomes.get(cid)
        # Only this replay's verdicts count as current: older runs at the same version must not mask it.
        current = _worst(v.verdict for rid in (o.run_ids if o else []) for v in store.list_verdicts(run_id=rid))
        if current is None and o is not None and o.run_ids:
            current = o.current
        note = o.note if o else "not replayed"
        if prev in g.history:
            previous, prev_label = g.history[prev], prev
        elif g.history:  # never run at the chosen previous version: compare with its latest record
            prev_label = list(g.history)[-1]
            previous = g.history[prev_label]
        else:
            previous, prev_label = None, None
        status = classify(g.kind, previous, current, cid in claims)
        rows.append(GateRow(
            case_id=cid, kind=g.kind, category=g.case.category.value,
            severity=g.case.severity_if_success.value, previous_version=prev_label,
            previous=_val(previous), current=_val(current), status=status, gating=status in GATING,
            claim=claims.get(cid, ""), history={k: v.value for k, v in g.history.items()}, note=note,
        ))
    return _finish(target_version, prev, rows, allow_errors)


def _finish(target_version, prev, rows, allow_errors, empty: str = "") -> GateResult:
    failing = [r for r in rows if r.gating]
    unknown = [r for r in rows if r.status == "INCONCLUSIVE"]
    if failing:
        outcome, code = "FAIL", EXIT_FAIL
        reason = "; ".join(f"{r.status} {r.case_id}" for r in failing)
    elif (unknown or empty) and not allow_errors:
        outcome, code = "INCONCLUSIVE", EXIT_INCONCLUSIVE
        reason = empty or f"{len(unknown)} gated case(s) errored or were not judged: " + \
            ", ".join(r.case_id for r in unknown)
    else:
        outcome, code = "PASS", EXIT_PASS
        reason = empty or "no reappeared exploit, no unfixed claimed fix, no positive-control breakage"
        if unknown:
            reason += f" ({len(unknown)} inconclusive, allowed)"
    return GateResult(target_version, prev, rows, outcome, code, reason)


# ---- output ---------------------------------------------------------------------------------------


def render(result: GateResult) -> str:
    lines = [
        "=" * 96,
        f"REGRESSION GATE  target={result.target_version}  previous={result.previous_version}",
        "=" * 96,
    ]
    if result.rows:
        lines.append(f"{'':2}{'STATUS':17}{'KIND':8}{'PREV':9}{'NOW':9}{'SEV':9}CASE")
        for r in result.rows:
            mark = "✗" if r.gating else ("?" if r.status == "INCONCLUSIVE" else "✓")
            prev = f"{r.previous or '-'}"
            lines.append(f"{mark:2}{r.status:17}{r.kind:8}{prev:9}{(r.current or '-'):9}{r.severity:9}{r.case_id}")
            detail = []
            if r.claim:
                detail.append(f"fix claimed: {r.claim}")
            if r.history:
                detail.append("history: " + " → ".join(f"{k}:{v}" for k, v in r.history.items()))
            if r.note:
                detail.append(r.note)
            for d in detail:
                lines.append(f"{'':27}{d}")
    counts: dict[str, int] = {}
    for r in result.rows:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines += [
        "-" * 96,
        "counts: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"),
        f"GATE: {result.outcome}  (exit {result.exit_code})  {result.reason}",
    ]
    return "\n".join(lines)


# ---- target version -------------------------------------------------------------------------------


def live_target_version() -> Optional[str]:
    from aep.target.client import TargetClient

    async def poll() -> Optional[str]:
        async with TargetClient() as client:
            return await client.target_version()

    return asyncio.run(poll())


# ---- offline demo ---------------------------------------------------------------------------------
# Simulated replays over real seed cases, so the gate can be shown (and CI-smoke-tested) without the
# live target. Nothing here is written to seeds.db.

DEMO_EXPLOIT = ROOT / "evals/seeds/authz_bypass_cross_patient/authz_07_brief_cross_patient.json"
DEMO_CONTROL = ROOT / "evals/seeds/authz_bypass_cross_patient/authz_06_benign_positive_control.json"

# scenario -> (recorded history per case, replay verdict per case, report status for the exploit)
DEMO_SCENARIOS = {
    "reappeared": ({"exploit": [("0.3.0", Verdict.FAIL), ("0.3.1", Verdict.PASS)],
                    "control": [("0.3.0", Verdict.PASS), ("0.3.1", Verdict.PASS)]},
                   {"exploit": Verdict.FAIL, "control": Verdict.PASS}, ReportStatus.RESOLVED, "0.3.2"),
    "still-vulnerable": ({"exploit": [("0.3.0", Verdict.FAIL)], "control": [("0.3.0", Verdict.PASS)]},
                         {"exploit": Verdict.FAIL, "control": Verdict.PASS}, ReportStatus.RESOLVED, "0.3.1"),
    "breakage": ({"exploit": [("0.3.0", Verdict.FAIL)], "control": [("0.3.0", Verdict.PASS)]},
                 {"exploit": Verdict.PASS, "control": Verdict.FAIL}, ReportStatus.RESOLVED, "0.3.1"),
    "clean": ({"exploit": [("0.3.0", Verdict.FAIL)], "control": [("0.3.0", Verdict.PASS)]},
              {"exploit": Verdict.PASS, "control": Verdict.PASS}, ReportStatus.RESOLVED, "0.3.1"),
}


class ScriptedRedTeam:
    """Replays a case by recording a simulated run at the requested version."""

    def __init__(self, store: Any, version: str) -> None:
        self.store, self.version = store, version
        self.replayed: list[str] = []

    def replay(self, case: AttackCase, target_version: Optional[str] = None) -> AttackRun:
        self.replayed.append(case.case_id)
        run = AttackRun(case_id=case.case_id, target_version=target_version or self.version,
                        transcript=[ConversationTurn(role="user", content="[simulated replay]")],
                        redteam_model="scripted")
        self.store.add_run(run)
        return run

    def execute(self, item: Any) -> AttackRun:
        return self.replay(self.store.get_case(item.seed_case_id), getattr(item, "target_version", None))


class ScriptedJudge:
    """Returns a scripted verdict per case_id (default PASS)."""

    def __init__(self, script: dict[str, Verdict]) -> None:
        self.script = script

    def judge(self, run: AttackRun) -> JudgeVerdict:
        return JudgeVerdict(run_id=run.run_id, case_id=run.case_id, correlation_id=run.correlation_id,
                            verdict=self.script.get(run.case_id, Verdict.PASS), oracle_used="http_assert",
                            oracle_evidence={"simulated": True})


def build_demo(scenario: str) -> tuple[Any, str, ScriptedRedTeam, ScriptedJudge]:
    from aep.store import SqliteStore

    history, replay, report_status, target = DEMO_SCENARIOS[scenario]
    store = SqliteStore(":memory:")
    cases = {"exploit": AttackCase.model_validate_json(DEMO_EXPLOIT.read_text()),
             "control": AttackCase.model_validate_json(DEMO_CONTROL.read_text())}
    for role, case in cases.items():
        case = case.model_copy(update={"in_regression_suite": True})
        cases[role] = case
        store.add_case(case)
        for version, verdict in history[role]:
            run = AttackRun(case_id=case.case_id, target_version=version, transcript=[], redteam_model="scripted")
            store.add_run(run)
            store.add_verdict(JudgeVerdict(run_id=run.run_id, case_id=case.case_id,
                                           correlation_id=run.correlation_id, verdict=verdict,
                                           oracle_used=case.oracle))
    ex = cases["exploit"]
    store.add_report(VulnerabilityReport(
        vuln_id="VULN-DEMO-1", severity=ex.severity_if_success, category=ex.category, owasp=ex.owasp,
        title="Pre-visit brief returns another patient's chart (demo)", clinical_impact="cross-patient PHI",
        repro_case_id=ex.case_id, repro_steps=[f"replay {ex.case_id}"], observed_behavior="200 + other chart",
        expected_behavior="403", recommended_remediation="scope brief reads to the caller's panel",
        status=report_status, first_seen_version="0.3.0", last_seen_version=history["exploit"][-1][0],
    ))
    judge = ScriptedJudge({cases[role].case_id: v for role, v in replay.items()})
    return store, target, ScriptedRedTeam(store, target), judge


# ---- CLI ------------------------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=os.environ.get("AEP_DB", "seeds.db"), help="SQLite store (default seeds.db)")
    ap.add_argument("--target-version", default=os.environ.get("AEP_TARGET_VERSION"),
                    help="current target version (default: $AEP_TARGET_VERSION, else polled live)")
    ap.add_argument("--previous-version", help="version to compare against (default: latest other on record)")
    ap.add_argument("--claimed-fix", action="append", default=[], metavar="CASE_OR_VULN_ID",
                    help="treat this exploit's fix as claimed (repeatable)")
    ap.add_argument("--all-claimed", action="store_true", help="treat every confirmed exploit as claimed fixed")
    ap.add_argument("--allow-errors", action="store_true", help="errored/unjudged gated cases don't block")
    ap.add_argument("--report", metavar="PATH", help="also write the gate result as JSON")
    ap.add_argument("--demo", choices=sorted(DEMO_SCENARIOS), help="offline simulated scenario (no target)")
    args = ap.parse_args(argv)

    claimed = list(args.claimed_fix) + os.environ.get("AEP_CLAIMED_FIXES", "").split(",")
    red_team = judge = tracer = None
    if args.demo:
        from aep.obs import LangfuseTracer
        store, target_version, red_team, judge = build_demo(args.demo)
        tracer = LangfuseTracer(client=None)
        print(f"[demo] scenario={args.demo}: simulated replays, nothing is sent to the target")
    else:
        from aep.store import SqliteStore
        if not Path(args.db).exists():
            print(f"GATE: INCONCLUSIVE  store {args.db!r} not found (run scripts/load_seeds.py and a campaign)")
            return EXIT_INCONCLUSIVE
        store = SqliteStore(args.db)
        target_version = args.target_version
        if not target_version:
            try:
                target_version = live_target_version()
            except Exception as exc:
                print(f"GATE: INCONCLUSIVE  could not read the target version: {type(exc).__name__}: {exc}")
                return EXIT_INCONCLUSIVE
        if not target_version:
            print("GATE: INCONCLUSIVE  target reported no version; pass --target-version")
            return EXIT_INCONCLUSIVE

    result = run_gate(store, target_version, previous_version=args.previous_version, red_team=red_team,
                      judge=judge, tracer=tracer, claimed=claimed, all_claimed=args.all_claimed,
                      allow_errors=args.allow_errors)
    print(render(result))
    if args.report:
        Path(args.report).write_text(json.dumps(result.to_json(), indent=2))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
