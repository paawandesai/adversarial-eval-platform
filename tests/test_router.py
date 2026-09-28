"""Model router: provider request/response shapes, cost capture, retries, per-agent routing.

Every provider sits behind an httpx.MockTransport. No network, no real keys.
"""
import json
import os
import sys

import httpx
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from aep.models import router as r  # noqa: E402
from aep.models.router import (  # noqa: E402
    ConfigError, JudgeIndependenceError, LLMResult, ProviderError, Router, parse_model,
)

MESSAGES = [{"role": "system", "content": "be terse"}, {"role": "user", "content": "hi"}]
KEYS = {"ANTHROPIC_API_KEY": "test-anthropic", "DEEPSEEK_API_KEY": "test-deepseek"}


# --------------------------------------------------------------------------- #
# Fake provider backends
# --------------------------------------------------------------------------- #
def anthropic_ok(text="hello from claude", model="claude-opus-5-5", stop_reason="end_turn"):
    return httpx.Response(200, json={
        "id": "msg_1", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": text}], "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 1000, "output_tokens": 200},
    })


def deepseek_ok(text="hello from deepseek"):
    return httpx.Response(200, json={
        "id": "c1", "object": "chat.completion", "model": "deepseek-chat",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 500, "completion_tokens": 100, "total_tokens": 600},
    })


def ollama_ok(text="hello from ollama"):
    return httpx.Response(200, json={
        "model": "qwen2.5-coder:14b", "message": {"role": "assistant", "content": text},
        "done": True, "prompt_eval_count": 40, "eval_count": 12,
    })


OK = {"api.anthropic.com": anthropic_ok, "api.deepseek.com": deepseek_ok, "localhost": ollama_ok}


class Backend:
    """Routes by host. `script[host]` is a list of responses/exceptions served in order."""

    def __init__(self, **script):
        self.script = {h.replace("_", "."): list(v) for h, v in script.items()}
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queue = self.script.get(request.url.host)
        item = queue.pop(0) if queue else OK[request.url.host]()
        if isinstance(item, Exception):
            raise item
        return httpx.Response(item.status_code, headers=item.headers, content=item.content)  # fresh copy

    def bodies(self, host):
        return [json.loads(q.content) for q in self.requests if q.url.host == host]


def make(env=None, **script):
    backend = Backend(**script)
    sleeps = []
    router = Router(env={**KEYS, **(env or {})} if env is not False else {},
                    http=httpx.Client(transport=httpx.MockTransport(backend)),
                    sleep=sleeps.append, rand=lambda: 1.0)
    return router, backend, sleeps


# --------------------------------------------------------------------------- #
# Model strings
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("spec,expected", [
    ("ollama:qwen2.5-coder:14b", ("ollama", "qwen2.5-coder:14b")),
    ("deepseek:deepseek-chat", ("deepseek", "deepseek-chat")),
    ("anthropic:claude-opus-5-5", ("anthropic", "claude-opus-5-5")),
    ("claude-opus-5-5", ("anthropic", "claude-opus-5-5")),
    ("deepseek-chat", ("deepseek", "deepseek-chat")),
    ("qwen2.5-coder:14b", ("ollama", "qwen2.5-coder:14b")),
])
def test_parse_model(spec, expected):
    assert parse_model(spec) == expected


def test_parse_model_rejects_empty():
    with pytest.raises(ConfigError):
        parse_model("")
    with pytest.raises(ConfigError):
        parse_model("deepseek:")


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #
def test_anthropic_request_shape_and_cost():
    router, backend, _ = make()
    res = router.complete("anthropic:claude-opus-5-5", MESSAGES, temperature=1.0, max_tokens=512)

    assert isinstance(res, LLMResult)
    assert (res.text, res.provider, res.model) == ("hello from claude", "anthropic", "claude-opus-5-5")
    assert (res.tokens_prompt, res.tokens_completion) == (1000, 200)
    assert res.cost_usd == pytest.approx((1000 * 4.0 + 200 * 20.0) / 1e6)
    assert res.latency_ms >= 0

    req = backend.requests[0]
    assert req.url.path == "/v1/messages"
    assert req.headers["x-api-key"] == "test-anthropic"
    assert "anthropic-version" in req.headers
    body = json.loads(req.content)
    assert body["system"] == "be terse"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert body["max_tokens"] == 512
    assert "temperature" not in body  # Opus 5.5 rejects sampling params


def test_anthropic_keeps_temperature_where_supported():
    router, backend, _ = make()
    router.complete("claude-haiku-4-5", MESSAGES, temperature=0.2)
    body = backend.bodies("api.anthropic.com")[0]
    assert body["temperature"] == 0.2
    assert body["max_tokens"] == r.DEFAULT_ANTHROPIC_MAX_TOKENS


def test_anthropic_refusal_is_an_error_not_text():
    router, _, sleeps = make(api_anthropic_com=[anthropic_ok(text="", stop_reason="refusal")])
    with pytest.raises(ProviderError, match="refused"):
        router.complete("claude-opus-5-5", MESSAGES)
    assert sleeps == []  # not retried


def test_deepseek_request_shape_and_cost():
    router, backend, _ = make()
    res = router.complete("deepseek:deepseek-chat", MESSAGES, temperature=0.0, max_tokens=900)

    assert (res.text, res.provider, res.model) == ("hello from deepseek", "deepseek", "deepseek-chat")
    assert (res.tokens_prompt, res.tokens_completion) == (500, 100)
    assert res.cost_usd == pytest.approx((500 * 0.28 + 100 * 0.42) / 1e6)

    req = backend.requests[0]
    assert str(req.url) == "https://api.deepseek.com/chat/completions"
    assert req.headers["authorization"] == "Bearer test-deepseek"
    body = json.loads(req.content)
    assert body == {"model": "deepseek-chat", "messages": MESSAGES, "stream": False,
                    "temperature": 0.0, "max_tokens": 900}


def test_deepseek_base_url_from_env():
    router, backend, _ = make({"DEEPSEEK_BASE_URL": "https://api.deepseek.com/v1/"})
    router.complete("deepseek-chat", MESSAGES)
    assert str(backend.requests[0].url) == "https://api.deepseek.com/v1/chat/completions"


def test_ollama_request_shape_and_free():
    router, backend, _ = make()
    res = router.complete("ollama:qwen2.5-coder:14b", MESSAGES, temperature=0.7, max_tokens=256)

    assert (res.provider, res.model, res.cost_usd) == ("ollama", "qwen2.5-coder:14b", 0.0)
    assert (res.tokens_prompt, res.tokens_completion) == (40, 12)
    req = backend.requests[0]
    assert str(req.url) == "http://localhost:11434/api/chat"
    assert "authorization" not in req.headers
    body = json.loads(req.content)
    assert body["stream"] is False and body["model"] == "qwen2.5-coder:14b"
    assert body["options"] == {"temperature": 0.7, "num_predict": 256}


def test_missing_key_is_config_error_without_http():
    router, backend, _ = make(env=False)
    with pytest.raises(ConfigError, match="DEEPSEEK_API_KEY"):
        router.complete("deepseek-chat", MESSAGES)
    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        router.complete("claude-opus-5-5", MESSAGES)
    assert backend.requests == []


def test_price_override_and_unknown_model(caplog):
    router, _, _ = make({"ROUTER_PRICES": json.dumps({"deepseek:deepseek-chat": [1.0, 2.0]})})
    res = router.complete("deepseek-chat", MESSAGES)
    assert res.cost_usd == pytest.approx((500 * 1.0 + 100 * 2.0) / 1e6)

    assert r.price_per_mtok("anthropic", "claude-something-new", {}) == (10.0, 50.0)  # errs high
    assert r.price_per_mtok("ollama", "anything", {}) == (0.0, 0.0)


# --------------------------------------------------------------------------- #
# Retries
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host,spec,fail", [
    ("api_anthropic_com", "claude-opus-5-5", httpx.Response(529, json={"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})),
    ("api_deepseek_com", "deepseek-chat", httpx.Response(503, text="busy")),
    ("localhost", "ollama:qwen2.5-coder:14b", httpx.ConnectError("refused")),
])
def test_transient_failures_retry_with_backoff(host, spec, fail):
    router, backend, sleeps = make(**{host: [fail, fail]})
    res = router.complete(spec, MESSAGES)
    assert res.text.startswith("hello")
    assert len(backend.requests) == 3
    assert sleeps == [0.5, 1.0]  # base 0.5s, doubling (jitter pinned to 1.0)


def test_retry_after_header_is_honoured():
    router, _, sleeps = make(api_deepseek_com=[httpx.Response(429, headers={"retry-after": "7"}, text="slow down")])
    router.complete("deepseek-chat", MESSAGES)
    assert sleeps == [7.0]


def test_client_errors_are_not_retried():
    router, backend, sleeps = make(api_deepseek_com=[httpx.Response(400, text="bad request")])
    with pytest.raises(ProviderError) as exc:
        router.complete("deepseek-chat", MESSAGES)
    assert exc.value.status == 400 and not exc.value.retryable
    assert len(backend.requests) == 1 and sleeps == []


def test_retries_give_up_after_max():
    router, backend, sleeps = make({"ROUTER_MAX_RETRIES": "2"}, api_deepseek_com=[httpx.Response(500, text="x")] * 5)
    with pytest.raises(ProviderError, match="HTTP 500"):
        router.complete("deepseek-chat", MESSAGES)
    assert len(backend.requests) == 3 and len(sleeps) == 2


# --------------------------------------------------------------------------- #
# Per-agent routing
# --------------------------------------------------------------------------- #
def test_agent_defaults():
    router, _, _ = make()
    assert router.resolve_agent("red_team") == (("anthropic", "claude-opus-5-5"), ("ollama", "qwen2.5-coder:14b"))
    assert router.resolve_agent("judge") == (("deepseek", "deepseek-chat"), None)
    assert router.resolve_agent("documentation") == (("deepseek", "deepseek-chat"), None)
    assert router.resolve_agent("redteam") == router.resolve_agent("red-team")


def test_agent_env_overrides():
    router, backend, _ = make({"DOCUMENTATION_MODEL": "ollama:llama3.1:8b", "REDTEAM_MODEL": "anthropic:claude-sonnet-5-5"})
    res = router.for_agent("documentation", MESSAGES)
    assert (res.provider, res.model) == ("ollama", "qwen2.5-coder:14b")  # served-by comes from the response
    assert backend.bodies("localhost")[0]["model"] == "llama3.1:8b"
    assert router.resolve_agent("red_team")[0] == ("anthropic", "claude-sonnet-5-5")


@pytest.mark.parametrize("env", [
    {"JUDGE_MODEL": "anthropic:claude-opus-5-5"},
    {"JUDGE_MODEL": "claude-fable-5-1"},
    {"JUDGE_MODEL": "ollama:claude-distill:7b"},
    {"JUDGE_FALLBACK_MODEL": "anthropic:claude-haiku-4-5"},
])
def test_judge_rejects_claude_before_any_call(env):
    router, backend, _ = make(env)
    with pytest.raises(JudgeIndependenceError):
        router.for_agent("judge", MESSAGES)
    assert backend.requests == []


def test_judge_routes_to_deepseek():
    router, backend, _ = make()
    res = router.for_agent("judge", MESSAGES, temperature=0.0, max_tokens=900)
    assert res.provider == "deepseek"
    assert [q.url.host for q in backend.requests] == ["api.deepseek.com"]


def test_red_team_uses_anthropic_when_keyed():
    router, backend, _ = make()
    res = router.for_agent("red_team", MESSAGES)
    assert res.provider == "anthropic"
    assert [q.url.host for q in backend.requests] == ["api.anthropic.com"]


def test_red_team_falls_back_to_ollama_without_key():
    router, backend, _ = make({"ANTHROPIC_API_KEY": ""})
    res = router.for_agent("red_team", MESSAGES)
    assert (res.provider, res.model, res.cost_usd) == ("ollama", "qwen2.5-coder:14b", 0.0)
    assert [q.url.host for q in backend.requests] == ["localhost"]


def test_red_team_falls_back_after_primary_exhausts_retries():
    router, backend, sleeps = make({"ROUTER_MAX_RETRIES": "1"}, api_anthropic_com=[httpx.Response(500, json={})] * 2)
    res = router.for_agent("red_team", MESSAGES)
    assert res.provider == "ollama"
    assert [q.url.host for q in backend.requests] == ["api.anthropic.com"] * 2 + ["localhost"]


def test_red_team_falls_back_on_refusal():
    router, _, _ = make(api_anthropic_com=[anthropic_ok(text="", stop_reason="refusal")])
    assert router.for_agent("red_team", MESSAGES).provider == "ollama"


def test_no_fallback_surfaces_the_error():
    router, _, _ = make({"DEEPSEEK_API_KEY": ""})
    with pytest.raises(ConfigError, match="DEEPSEEK_API_KEY"):
        router.for_agent("documentation", MESSAGES)


def test_unknown_agent_needs_env():
    router, _, _ = make()
    with pytest.raises(ConfigError, match="TRIAGE_MODEL"):
        router.for_agent("triage", MESSAGES)
    router, _, _ = make({"TRIAGE_MODEL": "deepseek-chat"})
    assert router.for_agent("triage", MESSAGES).provider == "deepseek"


# --------------------------------------------------------------------------- #
# Module-level API, and the agents/obs that consume it
# --------------------------------------------------------------------------- #
@pytest.fixture
def shared_router():
    router, backend, _ = make()
    r.set_router(router)
    yield backend
    r.set_router(None)


def test_module_functions_use_shared_router(shared_router):
    assert r.complete("deepseek-chat", MESSAGES).provider == "deepseek"
    assert r.for_agent("judge", MESSAGES).provider == "deepseek"
    assert len(shared_router.requests) == 2


def test_judge_default_router_is_this_module():
    from aep.agents import llm_judge
    assert llm_judge.default_router() is r


def test_record_llm_reads_llmresult_fields(monkeypatch, shared_router):
    for k in ("LANGFUSE_HOST", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    from aep.obs import LangfuseTracer
    tracer = LangfuseTracer()
    with tracer.trace("corr_router", "judge.llm") as span:
        span.record_llm(r.complete("deepseek-chat", MESSAGES))
    s = tracer.summary("corr_router")
    assert (s["tokens_prompt"], s["tokens_completion"]) == (500, 100)
    assert s["cost_usd"] == pytest.approx((500 * 0.28 + 100 * 0.42) / 1e6)
