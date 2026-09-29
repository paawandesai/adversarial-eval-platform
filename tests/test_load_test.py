"""Tests for scripts/load_test.py — mock target only, no live calls."""
import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aep.target.client import CORRELATION_ID_HEADER, TargetClient  # noqa: E402

_spec = importlib.util.spec_from_file_location("load_test", ROOT / "scripts" / "load_test.py")
load_test = importlib.util.module_from_spec(_spec)
sys.modules["load_test"] = load_test  # so @dataclass can resolve annotations under `from __future__`
_spec.loader.exec_module(load_test)


def run(coro):
    return asyncio.run(coro)


# ---- percentile ------------------------------------------------------------------------------------


def test_percentile_edges_and_interpolation():
    assert load_test.percentile([], 50) is None
    assert load_test.percentile([7.0], 99) == 7.0
    assert load_test.percentile([1, 2, 3, 4], 50) == 2.5
    assert load_test.percentile(list(range(1, 101)), 99) == pytest.approx(99.01)


# ---- one level against the mock --------------------------------------------------------------------


def test_run_level_mock_has_no_errors_and_ordered_percentiles():
    factory = load_test.mock_client_factory(latency_ms=1.0)
    r = run(load_test.run_level(10, 30, factory, turns=2, max_turns=60))
    assert r.concurrency == 10 and r.requests == 30
    assert r.completed == 30 and r.errors == 0 and r.error_rate == 0.0
    assert r.throughput_rps > 0 and r.wall_s > 0
    assert r.p50_ms is not None and r.p95_ms is not None and r.p99_ms is not None
    assert r.p50_ms <= r.p95_ms <= r.p99_ms <= r.max_ms
    assert r.peak_rss_mb > 0 and r.cpu_seconds >= 0
    json.dumps(r.to_dict())  # serialisable for --json


def test_run_suite_one_result_per_level():
    factory = load_test.mock_client_factory(latency_ms=0.0)
    results = run(load_test.run_suite([1, 5], 10, factory, turns=1))
    assert [r.concurrency for r in results] == [1, 5]
    assert all(r.completed == 10 for r in results)


# ---- error accounting ------------------------------------------------------------------------------


class _BriefFails(httpx.AsyncBaseTransport):
    """Token succeeds; the brief returns 500 — so every execution is a failure."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t", "token_type": "Bearer",
                                             "expires_in": 3600, "scope": "openid"})
        return httpx.Response(500, json={"detail": "boom"})


def test_error_rate_counts_http_failures():
    cfg = load_test.mock_config()
    factory = lambda: TargetClient(cfg, transport=_BriefFails())  # noqa: E731
    r = run(load_test.run_level(5, 10, factory, turns=1))
    assert r.errors == 10 and r.completed == 0 and r.error_rate == 1.0
    assert r.p50_ms is None  # no successful latencies to summarise


# ---- max-turns cap ---------------------------------------------------------------------------------


class _Counting(load_test.MockLatencyTransport):
    def __init__(self):
        super().__init__(latency_ms=0.0)
        self.by_path: dict[str, int] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.by_path[request.url.path] = self.by_path.get(request.url.path, 0) + 1
        return await super().handle_async_request(request)


def test_max_turns_caps_conversation_turns():
    transport = _Counting()
    cfg = load_test.mock_config()
    factory = lambda: TargetClient(cfg, transport=transport)  # noqa: E731
    # One execution, ask for 100 turns but cap at 3 -> exactly 3 conversation calls.
    run(load_test.run_level(1, 1, factory, turns=100, max_turns=3))
    assert transport.by_path.get("/pre-visit-brief/conversation") == 3
    assert transport.by_path.get("/pre-visit-brief") == 1  # one brief per execution


# ---- execute_once ----------------------------------------------------------------------------------


def test_execute_once_ok_on_mock():
    factory = load_test.mock_client_factory(latency_ms=0.0)
    res = run(load_test.execute_once(factory, "physician",
                                     "00000000-0000-0000-0000-000000000000", turns=2))
    assert res.ok and res.error is None and res.latency_ms >= 0


# ---- CLI: mock is the default, no live traffic -----------------------------------------------------


def test_main_defaults_to_mock_and_writes_json(tmp_path, capsys):
    out = tmp_path / "r.json"
    rc = load_test.main(["-c", "5,10", "-n", "12", "--turns", "1", "--json", str(out)])
    assert rc == 0
    printed = capsys.readouterr()
    assert "MOCK (in-process, no real traffic)" in printed.out
    assert "LIVE" not in printed.out and "DANGER" not in printed.out  # not live, no warning
    payload = json.loads(out.read_text())
    assert payload["mode"] == "mock"
    assert [lvl["concurrency"] for lvl in payload["levels"]] == [5, 10]
    assert all(lvl["error_rate"] == 0.0 for lvl in payload["levels"])


def test_live_flag_is_off_by_default_and_factory_uses_env(monkeypatch):
    # --live is opt-in: the default table renders MOCK.
    factory = load_test.mock_client_factory()
    assert isinstance(factory(), TargetClient)
    # live_client_factory reads env config but does not make a call on construction.
    monkeypatch.setenv("TARGET_BASE_URL", "https://example.invalid:8443")
    live = load_test.live_client_factory()
    client = live()
    assert client.config.base_url == "https://example.invalid:8443"
    run(client.aclose())


def test_render_table_labels_mode():
    factory = load_test.mock_client_factory(latency_ms=0.0)
    results = run(load_test.run_suite([2], 4, factory, turns=1))
    assert "MOCK" in load_test.render_table(results, live=False)
    assert "LIVE (real target)" in load_test.render_table(results, live=True)
