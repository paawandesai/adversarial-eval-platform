import sys, pathlib, asyncio
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aep.store.sqlite_store import SqliteStore
from aep.agents.red_team import RedTeam
from aep.agents.judge import Judge
from aep.agents.documentation import Documentation
from contracts.contracts import WorkItem, AttackCategory

s = SqliteStore("seeds.db")
rt, judge, doc = RedTeam(store=s), Judge(store=s), Documentation(store=s)

for case in s.list_cases():
    try:
        work = WorkItem(target_category=AttackCategory(case.category),
                        seed_case_id=case.case_id, token_budget=50000,
                        reason=f"campaign: {case.case_id}")
        run = rt.run_work_item(work)
        v = asyncio.run(judge.evaluate(run))
        rep = doc.document(v)
        tag = f"REPORT {rep.vuln_id}" if rep else ""
        print(f"{v.verdict.value:8} {v.oracle_used.value:18} {case.case_id}  {tag}")
    except Exception as e:
        print(f"{'error':8} {type(e).__name__:18} {case.case_id}: {str(e)[:70]}")

print("\n--- reports ---")
for r in s.list_reports():
    print(r.severity.value, r.category.value, "|", r.title)
