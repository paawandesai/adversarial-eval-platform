"""Load / stress test driver for the adversarial platform's target-facing path.

    python3 scripts/load_test.py                       # MOCK target (default) — no real traffic
    python3 scripts/load_test.py -c 10,50,100 -n 200   # concurrency levels, requests per level
    python3 scripts/load_test.py --json out.json       # also write raw results
    python3 scripts/load_test.py --live                # DANGER: hits the real deployed target

Each "attack execution" is one simulated clinician session: authenticate, pull a pre-visit
brief, then send `--turns` conversation turns (capped at `--max-turns`). The driver runs many
such executions concurrently at each `--concurrency` level and reports, per level:
p50/p95/p99 latency, throughput (exec/s), error rate, and the platform process's CPU and peak
memory during the level.

SAFETY: the target is **mocked by default** (an in-process async transport with a small
simulated latency), so running this overnight sends **zero** real traffic. `--live` is off by
default; when set it prints a warning and drives the real deployed target via env config.
Nothing here writes to a chart — executions only read (brief + conversation).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import resource
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aep.target.client import CORRELATION_ID_HEADER, TargetClient, TargetConfig  # noqa: E402

ClientFactory = Callable[[], TargetClient]


# --------------------------------------------------------------------------- #
# Statistics
# --------------------------------------------------------------------------- #
def percentile(values: list[float], q: float) -> Optional[float]:
    """Linear-interpolated q-th percentile (0–100) of ``values``; None if empty."""
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    rank = (q / 100.0) * (len(ordered) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


# --------------------------------------------------------------------------- #
# Process resource usage (stdlib only — no psutil dependency)
# --------------------------------------------------------------------------- #
def _maxrss_mb() -> float:
    """Peak resident set size of this process, in MiB. ru_maxrss is bytes on macOS, KiB on Linux."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024


def _cpu_seconds() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


# --------------------------------------------------------------------------- #
# Mock target — an in-process async transport, so no real traffic is sent
# --------------------------------------------------------------------------- #
class MockLatencyTransport(httpx.AsyncBaseTransport):
    """Answers the token endpoint and the read routes after a fixed simulated latency.

    Async (unlike httpx.MockTransport) so many concurrent executions actually overlap in the
    event loop, which is what makes the concurrency levels meaningful."""

    def __init__(self, latency_ms: float = 2.0) -> None:
        self._delay = max(0.0, latency_ms) / 1000.0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._delay:
            await asyncio.sleep(self._delay)
        path = request.url.path
        cid = request.headers.get(CORRELATION_ID_HEADER)
        echo = {CORRELATION_ID_HEADER: cid} if cid else {}
        if path.endswith("/token"):
            return httpx.Response(200, json={
                "access_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsb2FkIn0.sig",
                "token_type": "Bearer", "expires_in": 3600, "scope": "openid user/Patient.read",
            })
        if path == "/openapi.json":
            return httpx.Response(200, json={"info": {"version": "mock-load"}})
        if path == "/pre-visit-brief":
            return httpx.Response(200, headers=echo, json={"brief": "Pre-visit brief (mock).", "session_id": "s"})
        if path == "/pre-visit-brief/conversation":
            return httpx.Response(200, headers=echo, json={"answer": "ok", "session_id": "s"})
        if path == "/w2/ask":
            return httpx.Response(200, headers=echo, json={"message": "ok"})
        return httpx.Response(404, json={"detail": "not found"})


def mock_config() -> TargetConfig:
    return TargetConfig(
        base_url="https://mock.local",
        token_url="https://mock.local/oauth2/default/token",
        client_id="mock", client_secret="mock",
        default_patient_id="00000000-0000-0000-0000-000000000000",
        chat_route="conversation",
    )


def mock_client_factory(latency_ms: float = 2.0, config: Optional[TargetConfig] = None) -> ClientFactory:
    cfg = config or mock_config()
    transport = MockLatencyTransport(latency_ms)  # stateless; safe to share across executions
    return lambda: TargetClient(cfg, transport=transport)


def live_client_factory(config: Optional[TargetConfig] = None) -> ClientFactory:
    cfg = config or TargetConfig.from_env()
    return lambda: TargetClient(cfg)


# --------------------------------------------------------------------------- #
# One execution and one level
# --------------------------------------------------------------------------- #
@dataclass
class ExecResult:
    latency_ms: float
    ok: bool
    error: Optional[str] = None


async def execute_once(factory: ClientFactory, role: str, patient_id: Optional[str], turns: int) -> ExecResult:
    """One simulated clinician session: authenticate, brief, then `turns` conversation turns."""
    t0 = time.perf_counter()
    client = factory()
    statuses: list[int] = []
    try:
        await client.authenticate(role)
        pid = patient_id or client.patient_id
        brief = await client.pre_visit_brief(pid)
        statuses.append(int(brief.get("status_code", 0)))
        conv_id = brief.get("conversation_id")
        for i in range(turns):
            resp = await client.chat(
                [{"role": "user", "content": f"load turn {i}", "patient_id": pid}],
                conversation_id=conv_id, patient_id=pid, route="conversation",
            )
            conv_id = resp.get("conversation_id") or conv_id
            statuses.append(int(resp.get("status_code", 0)))
    except Exception as exc:  # noqa: BLE001 — any failure is a failed execution, recorded not raised
        return ExecResult((time.perf_counter() - t0) * 1000.0, False, f"{type(exc).__name__}: {exc}")
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass
    latency = (time.perf_counter() - t0) * 1000.0
    bad = [s for s in statuses if s >= 400 or s == 0]
    return ExecResult(latency, not bad, None if not bad else f"http_status={bad[0]}")


@dataclass
class LevelResult:
    concurrency: int
    requests: int
    completed: int
    errors: int
    error_rate: float
    throughput_rps: float
    wall_s: float
    p50_ms: Optional[float]
    p95_ms: Optional[float]
    p99_ms: Optional[float]
    mean_ms: Optional[float]
    max_ms: Optional[float]
    cpu_seconds: float
    cpu_percent: float
    peak_rss_mb: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def run_level(concurrency: int, requests: int, factory: ClientFactory, *,
                    role: str = "physician", patient_id: Optional[str] = None,
                    turns: int = 2, max_turns: int = 60) -> LevelResult:
    """Run ``requests`` executions with at most ``concurrency`` in flight; record the metrics."""
    turns = max(0, min(turns, max_turns))
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one() -> ExecResult:
        async with sem:
            return await execute_once(factory, role, patient_id, turns)

    cpu0, wall0 = _cpu_seconds(), time.perf_counter()
    results = await asyncio.gather(*(one() for _ in range(requests)))
    wall = max(time.perf_counter() - wall0, 1e-9)
    cpu = _cpu_seconds() - cpu0

    latencies = [r.latency_ms for r in results if r.ok]
    errors = sum(1 for r in results if not r.ok)
    completed = len(results) - errors
    return LevelResult(
        concurrency=concurrency,
        requests=requests,
        completed=completed,
        errors=errors,
        error_rate=errors / requests if requests else 0.0,
        throughput_rps=completed / wall,
        wall_s=wall,
        p50_ms=percentile(latencies, 50),
        p95_ms=percentile(latencies, 95),
        p99_ms=percentile(latencies, 99),
        mean_ms=statistics.fmean(latencies) if latencies else None,
        max_ms=max(latencies) if latencies else None,
        cpu_seconds=cpu,
        cpu_percent=100.0 * cpu / wall,
        peak_rss_mb=_maxrss_mb(),
    )


async def run_suite(levels: list[int], requests: int, factory: ClientFactory, **kw: Any) -> list[LevelResult]:
    out: list[LevelResult] = []
    for c in levels:
        out.append(await run_level(c, requests, factory, **kw))
    return out


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _fmt(v: Optional[float], nd: int = 1) -> str:
    return "—" if v is None else f"{v:.{nd}f}"


def render_table(results: list[LevelResult], *, live: bool) -> str:
    head = (
        f"| Concurrency | Requests | Throughput (exec/s) | p50 ms | p95 ms | p99 ms | "
        f"Error rate | CPU % | Peak RSS MiB |\n"
        f"| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n"
    )
    rows = "".join(
        f"| {r.concurrency} | {r.requests} | {_fmt(r.throughput_rps, 1)} | {_fmt(r.p50_ms)} | "
        f"{_fmt(r.p95_ms)} | {_fmt(r.p99_ms)} | {r.error_rate * 100:.1f}% | "
        f"{_fmt(r.cpu_percent, 0)} | {_fmt(r.peak_rss_mb, 1)} |\n"
        for r in results
    )
    return f"Mode: {'LIVE (real target)' if live else 'MOCK (in-process, no real traffic)'}\n\n" + head + rows


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
_LIVE_WARNING = (
    "\n"
    "  ****************************************************************\n"
    "  * --live: sending REAL load to the deployed target:          *\n"
    "  *   {url:<56}*\n"
    "  * This is real traffic. Do NOT run this unattended/overnight. *\n"
    "  ****************************************************************\n"
)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("-c", "--concurrency", default="10,50,100",
                   help="comma-separated concurrency levels (default: 10,50,100)")
    p.add_argument("-n", "--requests", type=int, default=100,
                   help="executions per concurrency level (default: 100)")
    p.add_argument("--turns", type=int, default=2, help="conversation turns per execution (default: 2)")
    p.add_argument("--max-turns", type=int, default=60, help="hard cap on turns per execution (default: 60)")
    p.add_argument("--mock-latency-ms", type=float, default=2.0,
                   help="simulated per-request latency for the mock target (default: 2.0)")
    p.add_argument("--role", default="physician", help="seeded role to authenticate as (default: physician)")
    p.add_argument("--json", dest="json_out", default=None, help="also write raw results to this JSON path")
    p.add_argument("--live", action="store_true",
                   help="DANGER: drive the REAL deployed target instead of the mock (default: off)")
    args = p.parse_args(argv)

    try:
        levels = [int(x) for x in args.concurrency.split(",") if x.strip()]
    except ValueError:
        print("--concurrency must be comma-separated integers, e.g. 10,50,100", file=sys.stderr)
        return 2
    if not levels:
        print("--concurrency produced no levels", file=sys.stderr)
        return 2

    if args.live:
        cfg = TargetConfig.from_env()
        print(_LIVE_WARNING.format(url=cfg.base_url), file=sys.stderr)
        factory = live_client_factory(cfg)
        patient_id = cfg.default_patient_id
    else:
        factory = mock_client_factory(args.mock_latency_ms)
        patient_id = mock_config().default_patient_id

    results = asyncio.run(run_suite(
        levels, args.requests, factory,
        role=args.role, patient_id=patient_id, turns=args.turns, max_turns=args.max_turns,
    ))

    print(render_table(results, live=args.live))
    if args.json_out:
        payload = {
            "mode": "live" if args.live else "mock",
            "requests_per_level": args.requests,
            "turns": min(args.turns, args.max_turns),
            "levels": [r.to_dict() for r in results],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
