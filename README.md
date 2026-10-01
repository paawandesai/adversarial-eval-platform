# adversarial-eval-platform

A continuous adversarial-evaluation platform for the **Clinical Co-Pilot** (a FastAPI
clinical agent + OpenEMR module). It autonomously red-teams the deployed target, judges each
attempt with **deterministic-first oracles** (canary match, tool-call audit, log scan, token
counter, HTTP assertion) and an LLM judge only for genuinely semantic categories, and freezes
confirmed exploits into a versioned regression suite. Each attack ships with a benign
positive-control twin so a "fix" that merely breaks the workflow is caught rather than passed.

- **Threat model & scope:** [`THREAT_MODEL.md`](THREAT_MODEL.md)
- **Success metrics (first live campaign):** [`KEY_METRICS.md`](KEY_METRICS.md)
- **Findings:** [`VULNERABILITY_REPORTS.md`](VULNERABILITY_REPORTS.md)
- **Architecture & tradeoffs:** [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Layout

```
aep/            agents (red team, judge, documentation, orchestrator), oracles, target client, obs, store
contracts/      Pydantic contracts (AttackCase, AttackRun, JudgeVerdict, …) — the source of truth
evals/seeds/    19 hand-authored seed AttackCases across 3 categories, + reviewable fixtures
scripts/        load_seeds, run_campaign_seeds, dashboard, smoke_target, probes
tests/          pytest suite
```

## Run against the live target

The deployed target is **`https://64.177.42.210:8443`** (OAuth token endpoint
`https://64.177.42.210:9300/oauth2/default/token`; the host uses a self-signed cert, so TLS
verification is off by default). It is reached only over its public HTTP API. Platform egress is
allowlisted to this host (a safety control on the tester itself — see THREAT_MODEL §5).

**1. Configure the environment.** Copy the template and fill in the secrets. `.env` is
gitignored; the seeded-user **credentials come from a gitignored creds file**
(`docs/w3-test-creds.md`), never from this repo.

```bash
cp .env.example .env
$EDITOR .env
set -a; . ./.env; set +a      # load into the current shell
```

**2. Load the seed cases into the store.** Validates all 21 seeds, then inserts them into a
SQLite store (`seeds.db`):

```bash
python3 scripts/load_seeds.py --insert --db seeds.db
```

**3. Run a campaign** — red-team → judge → document every seed against the live target. Either
the ready-made script or the one-liner:

```bash
python3 scripts/run_campaign_seeds.py
```

```bash
python3 -c "from aep.store.sqlite_store import SqliteStore; from aep.agents.orchestrator import Orchestrator; print(Orchestrator(SqliteStore('seeds.db')).run_campaign(max_items=21))"
```

`run_campaign` returns a `CampaignResult` (runs, verdict breakdown, reports, cost) — the shape
captured in `campaign_results.json` and reconciled in `KEY_METRICS.md`.

**4. View results** — a read-only dashboard over the store (opens a local HTTP server that
re-reads `seeds.db` on every request):

```bash
python3 scripts/dashboard.py --serve --port 8765     # then open http://localhost:8765
python3 scripts/dashboard.py --serve --watch         # auto-refresh live while a campaign runs elsewhere
python3 scripts/dashboard.py --db seeds.db --out /tmp/aep.html   # or render a static file
```

With `--watch`, the page polls a read-only `/data` JSON endpoint (default every 3s, `--interval`)
and refreshes when verdicts, findings, or coverage change — so a campaign running in another
terminal shows up live. The dashboard only ever observes; it has no attack-triggering controls.

**5. Regression gate** — replays the confirmed exploits (regression-suite cases with a FAIL on
record) and the positive controls through `Orchestrator.run_regression`, then compares against the
verdicts recorded at the previous target version. It exits 1 if an exploit reappeared, if a claimed
fix is still FAIL, or if a positive control broke. It exits 2 if the result is inconclusive. CI runs
it as the `regression_gate` job in `.gitlab-ci.yml`.

Seeds tagged `oracle_config.known_limitation` (see `aep/limitations.py`) are expected to be
inconclusive on the current test host: the `excessive_agency_writeback` seeds (write-back is
ACL-blocked) and `seed-ipi-02`/`05`/`06` (document ingestion pending). The gate lists them as
EXPECTED_SKIP without replaying them, `run_campaign_seeds.py` skips them (`--include-blocked` runs
them anyway), and the dashboard counts their ERROR verdicts as *skipped* rather than *error*.

```bash
python3 scripts/regression_gate.py --db seeds.db                    # live target
python3 scripts/regression_gate.py --db seeds.db --claimed-fix seed-authz-07-brief-cross-patient
python3 scripts/regression_gate.py --demo reappeared                # offline simulation, exits 1
```

## Tests

```bash
python3 -m pytest -q
```
