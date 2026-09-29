# Performance Baseline — Adversarial Evaluation Platform

Load / stress baseline for the platform's target-facing execution path, produced by
`scripts/load_test.py`. This is a **template**: the mock-mode column establishes the platform's
own async overhead (no network), and the **live** rows are left blank to be filled in from a
measured run against the deployed target.

> **How this is measured.** One "attack execution" = one simulated clinician session:
> authenticate → pre-visit brief → `--turns` conversation turns (read-only; nothing is written to
> a chart). The driver runs many executions concurrently per level and records latency
> percentiles, throughput, error rate, and the platform process's CPU and peak RSS.

## How to run

```bash
# MOCK target (default) — in-process, ZERO real traffic. Safe to run anytime, including overnight.
python3 scripts/load_test.py -c 10,50,100 -n 200 --json baseline_mock.json

# LIVE target — real traffic to the deployed host. Off by default; prints a warning. Attended only.
python3 scripts/load_test.py --live -c 10,50,100 -n 200 --json baseline_live.json
```

Key flags: `-c/--concurrency` (levels), `-n/--requests` (executions per level), `--turns`
(conversation turns per execution), `--max-turns` (hard cap, default 60), `--mock-latency-ms`
(simulated per-request latency in mock mode), `--live` (off by default).

## Environment

Fill in when recording a baseline:

- Date / commit: `____`
- Host (platform runner): `____` (CPU cores, RAM)
- Target: `https://64.177.42.210:8443` (mock: in-process `MockLatencyTransport`)
- Driver settings: requests/level `____`, turns/execution `____`, mock latency `____ ms`
- Python: `____`

## Results — MOCK (platform async overhead, no network)

*Establishes the platform's own ceiling: latency here is driver + client overhead plus the
simulated `--mock-latency-ms`, not the target.*

| Concurrency | Requests | Throughput (exec/s) | p50 ms | p95 ms | p99 ms | Error rate | CPU % | Peak RSS MiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | | | | | | | | |
| 50 | | | | | | | | |
| 100 | | | | | | | | |

## Results — LIVE (deployed target)

*Real end-to-end: includes OAuth token minting and the target's LLM-backed brief/conversation
latency. Expect much higher p95/p99 than mock. Record errors (timeouts, 5xx, auth) explicitly.*

| Concurrency | Requests | Throughput (exec/s) | p50 ms | p95 ms | p99 ms | Error rate | CPU % | Peak RSS MiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | | | | | | | | |
| 50 | | | | | | | | |
| 100 | | | | | | | | |

## Observations & thresholds

Fill in after a run:

- **Throughput saturation point:** the concurrency level past which throughput stops rising
  (executions queue rather than complete faster) — `____`.
- **Latency knee:** the level where p95/p99 begins climbing steeply — `____`.
- **Error onset:** the level (if any) where the error rate leaves 0% and the dominant error class
  (timeout / 5xx / auth / rate-limit) — `____`.
- **Resource ceiling:** peak RSS and CPU% at the top level; whether the platform process, not the
  target, is the bottleneck — `____`.
- **Recommended operating concurrency** for continuous/overnight campaigns against the live
  target — `____`.

> Notes: CPU% is process CPU time over wall time and can exceed 100% across cores. Peak RSS is the
> process maximum (`ru_maxrss`) observed during the run. For finer per-interval sampling, install
> `psutil`; the driver falls back to stdlib `resource` when it is absent.
