"""/health and /ready. Every dependency sits behind an httpx.MockTransport: no network, no real keys."""
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aep import health  # noqa: E402

TARGET = "https://target.test:8443"
LANGFUSE = "https://lf.test"
DEEPSEEK = "https://ds.test"
OLLAMA = "http://ollama.test:11434"

# All three agents on DeepSeek, as in production; redteam has no fallback here unless a test adds one.
ENV = {
    "TARGET_BASE_URL": TARGET,
    "LANGFUSE_HOST": LANGFUSE, "LANGFUSE_PUBLIC_KEY": "pk", "LANGFUSE_SECRET_KEY": "sk",
    "REDTEAM_MODEL": "deepseek:deepseek-chat", "REDTEAM_FALLBACK_MODEL": "deepseek:deepseek-chat",
    "JUDGE_MODEL": "deepseek:deepseek-chat", "DOCUMENTATION_MODEL": "deepseek:deepseek-chat",
    "DEEPSEEK_API_KEY": "ds-key", "DEEPSEEK_BASE_URL": DEEPSEEK,
    "ANTHROPIC_API_KEY": "sk-ant-test", "OLLAMA_HOST": OLLAMA,
}

ANTHROPIC_MODELS = {"data": [{"type": "model", "id": "claude-opus-5-5", "display_name": "Claude Opus 5.5",
                              "created_at": "2026-01-01T00:00:00Z"}],
                    "has_more": False, "first_id": "claude-opus-5-5", "last_id": "claude-opus-5-5"}


class Deps:
    """Routes requests by host to per-dependency behaviours; records what was called."""

    def __init__(self, **overrides):
        self.calls = []
        self.behaviour = {
            "target.test": lambda req: httpx.Response(200, json={"status": "ready", "checks": {}}),
            "lf.test": lambda req: httpx.Response(200, json={"status": "OK", "version": "3"}),
            "ds.test": lambda req: (httpx.Response(200, json={"object": "list", "data": []})
                                    if req.headers.get("authorization") == "Bearer ds-key"
                                    else httpx.Response(401, json={"error": "bad key"})),
            "api.anthropic.com": lambda req: (httpx.Response(200, json=ANTHROPIC_MODELS)
                                              if req.headers.get("x-api-key") == "sk-ant-test"
                                              else httpx.Response(401, json={"type": "error", "error": {
                                                  "type": "authentication_error", "message": "bad key"}})),
            "ollama.test": lambda req: httpx.Response(200, json={"models": [{"name": "llama3.1:latest"}]}),
        }
        self.behaviour.update(overrides)

    def __call__(self, request):
        self.calls.append(str(request.url))
        return self.behaviour[request.url.host](request)

    @property
    def transport(self):
        return httpx.MockTransport(self)


def unreachable(request):
    raise httpx.ConnectError("connection refused", request=request)


def ready(env=ENV, deps=None, timeout=1.0):
    deps = deps or Deps()
    return (*health.readiness(env, transport=deps.transport, timeout=timeout), deps)


# --------------------------------------------------------------------------- #
# /health
# --------------------------------------------------------------------------- #
def test_health_is_alive_without_touching_dependencies():
    called = []
    status, body = health.handle("/health", ready=lambda: called.append(1))
    assert status == 200 and body["status"] == "alive" and body["uptime_s"] >= 0
    assert called == []


def test_handle_ignores_other_paths_and_tolerates_query_and_slash():
    assert health.handle("/") is None
    assert health.handle("/metrics") is None
    assert health.handle("/health/?x=1")[0] == 200


# --------------------------------------------------------------------------- #
# /ready
# --------------------------------------------------------------------------- #
def test_all_reachable_is_ready():
    status, body, deps = ready()
    assert status == 200 and body["status"] == "ready"
    assert set(body["checks"]) == {"target", "langfuse", "llm:deepseek"}
    assert all(c["status"] == "ok" for c in body["checks"].values())
    assert body["checks"]["llm:deepseek"]["used_by"] == ["redteam", "redteam (fallback)", "judge", "documentation"]
    assert f"{TARGET}/ready" in deps.calls
    assert f"{LANGFUSE}/api/public/health" in deps.calls
    assert f"{DEEPSEEK}/models" in deps.calls
    assert all(isinstance(c["latency_ms"], float) for c in body["checks"].values())


def test_target_unreachable_is_503_with_per_dependency_body():
    status, body, _ = ready(deps=Deps(**{"target.test": unreachable}))
    assert status == 503 and body["status"] == "not_ready"
    target = body["checks"]["target"]
    assert target["status"] == "down" and target["required"] is True
    assert "ConnectError" in target["detail"]
    assert body["checks"]["langfuse"]["status"] == "ok"
    assert body["checks"]["llm:deepseek"]["status"] == "ok"


def test_target_not_ready_503_is_down():
    deps = Deps(**{"target.test": lambda req: httpx.Response(503, json={"status": "not_ready", "checks": {}})})
    status, body, _ = ready(deps=deps)
    assert status == 503
    assert body["checks"]["target"]["detail"].endswith("-> 503 (not_ready)")


def test_target_without_ready_route_falls_back_to_health():
    deps = Deps(**{"target.test": lambda req: httpx.Response(404) if req.url.path == "/ready"
                   else httpx.Response(200, json={"status": "alive"})})
    status, body, deps = ready(deps=deps)
    assert status == 200
    target_calls = [c for c in deps.calls if "target.test" in c]
    assert target_calls == [f"{TARGET}/ready", f"{TARGET}/health"]
    assert body["checks"]["target"]["detail"] == f"GET {TARGET}/health -> 200 (alive)"


def test_langfuse_down_fails_readiness():
    status, body, _ = ready(deps=Deps(**{"lf.test": lambda req: httpx.Response(503)}))
    assert status == 503
    lf = body["checks"]["langfuse"]
    assert lf["status"] == "down" and lf["required"] is True and lf["detail"].endswith("-> 503")


def test_langfuse_unset_is_not_configured_and_not_required():
    env = {k: v for k, v in ENV.items() if not k.startswith("LANGFUSE_")}
    status, body, deps = ready(env=env)
    assert status == 200
    assert body["checks"]["langfuse"]["status"] == "not_configured"
    assert body["checks"]["langfuse"]["required"] is False
    assert not any("lf.test" in c for c in deps.calls)


def test_langfuse_host_without_keys_is_down():
    env = {**ENV, "LANGFUSE_SECRET_KEY": ""}
    status, body, deps = ready(env=env)
    assert status == 503
    assert "LANGFUSE_SECRET_KEY not set" in body["checks"]["langfuse"]["detail"]
    assert not any("lf.test" in c for c in deps.calls)


def test_deepseek_bad_key_is_down():
    status, body, _ = ready(env={**ENV, "DEEPSEEK_API_KEY": "wrong"})
    assert status == 503
    ds = body["checks"]["llm:deepseek"]
    assert ds["status"] == "down" and ds["required"] is True and "credentials rejected" in ds["detail"]


def test_deepseek_missing_key_is_down_without_a_call():
    env = {k: v for k, v in ENV.items() if k != "DEEPSEEK_API_KEY"}
    status, body, deps = ready(env=env)
    assert status == 503 and body["checks"]["llm:deepseek"]["detail"] == "DEEPSEEK_API_KEY not set"
    assert not any("ds.test" in c for c in deps.calls)


def test_anthropic_checked_through_the_sdk_when_routed():
    env = {**ENV, "REDTEAM_MODEL": "anthropic:claude-opus-5-5"}
    status, body, deps = ready(env=env)
    assert status == 200
    assert body["checks"]["llm:anthropic"]["status"] == "ok"
    assert body["checks"]["llm:anthropic"]["used_by"] == ["redteam"]
    assert any(c.startswith("https://api.anthropic.com/v1/models") for c in deps.calls)


def test_anthropic_bad_key_with_live_fallback_is_down_but_not_required():
    env = {**ENV, "REDTEAM_MODEL": "anthropic:claude-opus-5-5", "ANTHROPIC_API_KEY": "wrong"}
    status, body, _ = ready(env=env)
    anth = body["checks"]["llm:anthropic"]
    assert anth["status"] == "down" and "credentials rejected" in anth["detail"]
    assert anth["required"] is False  # redteam falls back to deepseek, which is up
    assert status == 200


def test_anthropic_down_and_fallback_down_fails_readiness():
    env = {**ENV, "REDTEAM_MODEL": "anthropic:claude-opus-5-5", "REDTEAM_FALLBACK_MODEL": "ollama:qwen2.5-coder:14b"}
    status, body, _ = ready(env=env, deps=Deps(**{"api.anthropic.com": unreachable, "ollama.test": unreachable}))
    assert status == 503
    assert body["checks"]["llm:anthropic"]["required"] is True
    assert body["checks"]["llm:ollama"]["required"] is True
    assert body["checks"]["llm:deepseek"]["status"] == "ok"


def test_ollama_model_not_pulled_is_down():
    env = {**ENV, "DOCUMENTATION_MODEL": "ollama:qwen2.5-coder:14b"}
    status, body, _ = ready(env=env)
    assert status == 503
    assert "not pulled: qwen2.5-coder:14b" in body["checks"]["llm:ollama"]["detail"]


def test_ollama_untagged_name_matches_latest():
    status, body, _ = ready(env={**ENV, "DOCUMENTATION_MODEL": "ollama:llama3.1"})
    assert status == 200 and body["checks"]["llm:ollama"]["status"] == "ok"


def test_judge_on_claude_is_a_routing_failure():
    status, body, _ = ready(env={**ENV, "JUDGE_MODEL": "anthropic:claude-opus-5-5"})
    assert status == 503
    assert body["checks"]["llm_routing"]["status"] == "down"
    assert "independent" in body["checks"]["llm_routing"]["detail"]


def test_a_hung_dependency_is_bounded_by_the_timeout():
    release = threading.Event()

    def hang(request):
        release.wait(10)
        return httpx.Response(200, json={"status": "ready"})

    try:
        t0 = time.monotonic()
        status, body, _ = ready(deps=Deps(**{"target.test": hang}), timeout=0.2)
        elapsed = time.monotonic() - t0
    finally:
        release.set()
    assert elapsed < 1.5
    assert status == 503
    assert body["checks"]["target"] == {"status": "down", "required": True, "detail": "timed out after 0.4s"}
    assert body["checks"]["langfuse"]["status"] == "ok"


def test_a_crashing_check_reports_instead_of_raising(monkeypatch):
    def boom(client, env):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(health, "check_langfuse", boom)
    status, body, _ = ready()
    assert status == 503 and body["checks"]["langfuse"]["detail"] == "check failed: RuntimeError: kaboom"


def test_timeout_from_env():
    deps = Deps()
    status, _ = health.readiness({**ENV, "READY_TIMEOUT_S": "0.5"}, transport=deps.transport)
    assert status == 200


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #
@pytest.fixture
def server():
    state = {"result": (200, {"status": "ready", "checks": {}})}
    httpd = health.make_server("127.0.0.1", 0, ready=lambda: state["result"])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", state
    httpd.shutdown()
    httpd.server_close()


def test_server_routes(server):
    base, state = server
    r = httpx.get(f"{base}/health")
    assert r.status_code == 200 and r.json()["status"] == "alive"
    assert r.headers["content-type"] == "application/json"
    assert httpx.get(f"{base}/ready").status_code == 200
    state["result"] = (503, {"status": "not_ready", "checks": {"target": {"status": "down"}}})
    r = httpx.get(f"{base}/ready")
    assert r.status_code == 503 and r.json()["checks"]["target"]["status"] == "down"
    assert httpx.get(f"{base}/nope").status_code == 404
