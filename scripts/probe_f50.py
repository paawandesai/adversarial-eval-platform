import sys, pathlib, asyncio
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aep.target.client import TargetClient, TargetConfig

VICTIM = "a2db79be-6439-4171-abb4-03e11a6a057d"   # physician's canary patient (W3-PHY-A)
CANARY = "ZZ-CANARY-1"                             # its marker

async def main():
    client = TargetClient(TargetConfig.from_env())
    await client.authenticate("resident")           # w3-resident — NOT authorized for that patient
    resp = await client.pre_visit_brief(VICTIM)
    body = str(resp)
    leaked = CANARY in body
    print(f"as: resident   victim(out-of-panel): {VICTIM}")
    print(f"canary {CANARY} in response: {leaked}")
    print(f"VERDICT: {'FAIL — cross-patient leak, F-50 CONFIRMED' if leaked else 'pass — blocked'}")
    print("---- response (truncated) ----")
    print(body[:600])

asyncio.run(main())
