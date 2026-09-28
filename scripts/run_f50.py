import sys, pathlib, asyncio
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from aep.store.sqlite_store import SqliteStore
from aep.agents.red_team import RedTeam
from aep.agents.judge import Judge
from contracts.contracts import WorkItem, AttackCategory

store = SqliteStore("seeds.db")
cases = store.list_cases(category=AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT.value)

# prefer a canary-oracle case (cleanest deterministic proof); else fall back to the first
seed = next((c for c in cases if str(c.oracle).lower().endswith("canary")), cases[0])
print(f"seed: {seed.case_id}  as_user={seed.as_user_role}  oracle={seed.oracle}")

work = WorkItem(
    target_category=AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT,
    seed_case_id=seed.case_id,
    token_budget=50_000,
    reason="manual F-50 single-case reproduction",
)

rt = RedTeam(store=store)
run = rt.run_work_item(work)          # sync; runs against the LIVE target, writes AttackRun
print(f"run: {run.run_id}  corr={run.correlation_id}  target_version={run.target_version}")

judge = Judge(store=store)
verdict = asyncio.run(judge.evaluate(run))   # only the Judge is async
print(f"\nVERDICT: {verdict.verdict}  oracle={verdict.oracle_used}")
print(f"EVIDENCE: {verdict.oracle_evidence}")
