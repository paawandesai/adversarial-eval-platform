import sys, pathlib, asyncio
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aep.store.sqlite_store import SqliteStore
from aep.agents.red_team import RedTeam
from aep.agents.judge import Judge
from aep.agents.documentation import Documentation
from aep.limitations import expected_inconclusive
from contracts.contracts import WorkItem, AttackCategory, Verdict

# Cases tagged oracle_config.known_limitation (aep/limitations.py) are skipped: the test host can't
# decide them yet. --include-blocked runs them anyway; an ERROR on one is then labelled "expected".
include_blocked = "--include-blocked" in sys.argv[1:]

s = SqliteStore("seeds.db")
rt, judge, doc = RedTeam(store=s), Judge(store=s), Documentation(store=s)

skipped = 0
for case in s.list_cases():
    blocked = expected_inconclusive(case)
    if blocked and not include_blocked:
        skipped += 1
        print(f"{'skipped':8} {'expected':18} {case.case_id}: {blocked[:90]}")
        continue
    try:
        work = WorkItem(target_category=AttackCategory(case.category),
                        seed_case_id=case.case_id, token_budget=50000,
                        reason=f"campaign: {case.case_id}")
        run = rt.run_work_item(work)
        v = asyncio.run(judge.evaluate(run))
        rep = doc.document(v)
        tag = f"REPORT {rep.vuln_id}" if rep else ""
        if blocked and v.verdict == Verdict.ERROR:
            tag = f"expected-inconclusive: {blocked[:70]}"
        print(f"{v.verdict.value:8} {v.oracle_used.value:18} {case.case_id}  {tag}")
    except Exception as e:
        print(f"{'error':8} {type(e).__name__:18} {case.case_id}: {str(e)[:70]}")

if skipped:
    print(f"\n{skipped} case(s) skipped as expected-inconclusive (documented limitation); "
          "--include-blocked runs them")

print("\n--- reports ---")
for r in s.list_reports():
    print(r.severity.value, r.category.value, "|", r.title)
