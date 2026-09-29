# Alerts and on-call runbook

Three alerts are computed over the store: latency, evaluation errors, and tool or target failures.
They are defined in `aep/alerts.py` and evaluated by `scripts/alerts.py`. Evaluation is read-only:
the store is opened with `SqliteStore.open_readonly` (SQLite `mode=ro`), and only `list_runs()`,
`list_verdicts()` and `list_cases()` are called. The dashboard shows the same alerts near the top
of the page, and its `/data` JSON includes them.

```sh
python3 scripts/alerts.py                    # seeds.db, last 24 h, thresholds from ALERT_* env
python3 scripts/alerts.py --db campaign.db --all --json
```

| Exit code | Meaning |
|---|---|
| 0 | Nothing is firing. `insufficient_data` does not count as firing. |
| 1 | At least one alert is firing. Page on this. |
| 2 | A threshold is malformed, or there is no store at `--db`. |

To page from cron, run it every 15 minutes and alert on a non-zero exit:

```cron
*/15 * * * *  cd /path/to/adversarial-eval-platform && python3 scripts/alerts.py --db campaign.db || notify-oncall
```

## Configuration

A CLI flag overrides the matching environment variable, and the environment variable overrides the default.

| Alert | Env | Flag | Default | Fires when |
|---|---|---|---|---|
| `p95_latency` | `ALERT_P95_LATENCY_MS` | `--p95-ms` | `60000` | p95 of end-to-end run latency is above this (ms) |
| `error_rate` | `ALERT_ERROR_RATE` | `--error-rate` | `0.10` | the share of judged runs that could not be evaluated is above this |
| `target_failure_rate` | `ALERT_TARGET_FAILURE_RATE` | `--target-failure-rate` | `0.05` | the share of runs with a target or tool failure is above this |
| window | `ALERT_WINDOW_HOURS` | `--window-hours`, `--all` | `24` | Only runs started in the last N hours count. `0` or `--all` counts every run. |
| sample floor | `ALERT_MIN_SAMPLES` | `--min-samples` | `5` | With fewer runs in the denominator, the alert is `insufficient_data` |

A threshold that isn't a number, or a rate outside 0–1, makes the script exit with code 2 and name the
variable. It never falls back to the default, because a threshold that is silently wrong is worse than one that fails loudly.

Each alert is in one of three states: `firing`, `ok` or `insufficient_data`. The output also includes:

- **breakdown:** what is driving the number.
- **examples:** up to 5 correlation ids. Paste one into the dashboard's trace link or Langfuse. The trace
  id is `sha256(correlation_id)[:16].hex()`.

Before you start on any alert, check dependency health. Run `python3 -m aep.health`, then
`curl -s localhost:8766/ready`. The dashboard server also answers `/ready`.

---

## p95_latency

**What it measures.** The p95 of each run's total latency, which is the sum of
`AttackRun.latency_ms_by_step`. This is the same number as the dashboard's "Latency p95" tile. Runs with
no recorded steps are left out. The breakdown gives the p95 for each step (`p95_ms_by_step`).

**Why 60 s.** Recent campaigns run at a p95 of about 8 s. The target client allows 90 s per request
(`TARGET_TIMEOUT_SECONDS`), so a run near 60 s is one slow turn away from a timeout. Past that point, slow
runs turn into errors.

**Impact.** Results are still valid. The risk is that runs start hitting the timeout, which moves the
problem to `error_rate` and `target_failure_rate`. Campaigns also cost more wall-clock time. This is not a
page-worthy outage on its own unless the other two alerts are also firing.

**On-call action.**
1. Read `p95_ms_by_step` to find the slow step. `redteam.attack` covers both the target calls and the Red
   Team model's generation.
2. Check `/ready`. If `target` reports `degraded`, or its `latency_ms` is in seconds, the target is slow.
   Tell the target owner and lower campaign concurrency until it recovers.
3. If the target is fast, open the Langfuse trace for the slowest correlation ids in `examples`. Time
   spent in the Red Team model call usually means router retries: 429s or 5xx from the provider back off
   exponentially (`ROUTER_MAX_RETRIES`, `ROUTER_BACKOFF_BASE_S`). Check the provider's status. If it stays
   slow, point `REDTEAM_MODEL` at the fallback.
4. **Resolved** when the next window's p95 is back under the threshold. If campaigns have legitimately
   grown (more turns per case), raise `ALERT_P95_LATENCY_MS` and record why.

## error_rate

**What it measures.** The share of judged runs whose verdicts are all `ERROR`. A run is ERROR when it
could not be evaluated. This is the dashboard's "error" bucket. Runs with no verdict yet are left out of
the denominator, and the detail line reports how many there are. So are ERRORs on cases tagged
`oracle_config.known_limitation` (see `aep/limitations.py`). Those are documented skips, which the
dashboard shows as "skipped" rather than as platform errors. The breakdown counts the oracle and the
evidence `reason` of each ERROR verdict.

**Why 10%.** Every errored run is an attack case with no verdict, so coverage shrinks without any warning.
The regression gate also treats an errored gated case as INCONCLUSIVE (exit code 2), so a high error rate
blocks CI too.

**On-call action.** Triage by the top entry in `breakdown.reasons`:

| Reason | Cause | Action |
|---|---|---|
| `oracle_config missing the keys this oracle needs` | A case's `oracle_config` is incomplete. This is a data bug, not an outage. | Fix the case under `evals/seeds/` (see `evals/seeds/README.md`), then reload with `scripts/load_seeds.py`. File it; no page needed. |
| `judge model call failed` | The judge's model provider failed. | Check the `llm:*` checks in `/ready`. Typical causes: an Ollama model that isn't pulled (`ollama pull <model>`), a rejected key, or DeepSeek billing that isn't funded (HTTP 402). Fix it and re-judge. |
| `no HTTP response (JSON with status/status_code) in transcript` | `http_assert` found no target response to check. Either the target failed mid-run, or the case's route doesn't match the oracle. | Check `target_failure_rate` and `/ready` → `target`. If both are fine, it is a case bug: fix the case's route or oracle. |
| `oracle raised` | A bug in an oracle. The evidence carries the exception. | Open an issue with the correlation id and the error. |
| `no deterministic oracle registered for …` | A case names an oracle that doesn't exist. | Fix the case's `oracle`. |

After the fix, re-run the affected cases with `scripts/run_campaign_seeds.py`, or with the regression gate
for gated cases. **Resolved** when the rate over the next window is under the threshold.

## target_failure_rate

**What it measures.** The share of runs with at least one tool or target failure. A run counts as a failure when either of these is true:
- **Target response:** a target response in the transcript is HTTP **408, 429 or 5xx**.
- **Observed tool call:** a tool call in `tool_calls_observed` reports an error. That means an
  `outcome`/`status` of `error`, `failed`, `failure` or `timeout`, a non-empty `error_type`, or a
  `status_code` of 408, 429 or 5xx.

Other 4xx codes (401, 403, 404, 409, 413, 415, 422) are **not** failures. They are the target refusing a
request, which is the defence the platform exists to test. The breakdown counts the failure kinds, for
example `target HTTP 503` or `fhir_read timeout`.

**Why 5%.** A healthy target should almost never return 5xx or throttle. Findings from runs that hit
failures are unreliable: a refusal and a crash look the same to some oracles.

**On-call action.**
1. Check `/ready` → `target`. If the target is down or `not_ready`, it is an outage. **Pause campaigns**,
   because runs during an outage produce ERRORs, not findings. Then tell the target owner.
2. Read `breakdown.failures`:
   - **`target HTTP 429`:** the target is rate-limiting the platform. Lower campaign concurrency, or space
     the runs out.
   - **`target HTTP 5xx`:** if it only happens on certain cases, open the example traces. A 500 that a
     specific payload triggers is itself a potential **finding** (robustness or denial of service). Hand the
     correlation id to the Documentation flow rather than dismissing it as noise. If 5xx hits every case, it is a target outage (step 1).
   - **Tool failures** (`fhir_read …`, `lab_writeback …`, `llm …`): a dependency of the target, such as
     OpenEMR/FHIR or the target's own LLM, is failing. The target's Langfuse trace (the judge's
     `AUDIT_LANGFUSE_*` project) shows the `tool_call_event` with its `error_type` and `status_code`.
3. **Resolved** when `/ready` → `target` is `ok` and the next window's rate is under the threshold.
   Re-run whatever ran during the incident.

**Blind spot.** A transport failure is a failure with no HTTP response at all: a connection, TLS or
timeout error. It raises `TargetTransportError` and aborts the run before the run is stored, so this alert
can't see it. The symptoms are `/ready` showing the target down, `handoff … error` records in the
orchestrator audit log, and fewer runs in the window than the campaign planned. `/ready` is the
authoritative check for reachability.

---

## Changing an alert

Thresholds, the window and the sample floor are all set through env or flags, so tuning them needs no code
change. To add or redefine an alert, edit `DEFINITIONS` and `evaluate()` in `aep/alerts.py`, add its
section here with a matching heading (the `runbook` field links to `docs/ALERTS.md#<key>`), and cover it in
`tests/test_alerts.py`.
