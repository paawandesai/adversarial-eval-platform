"""Model router: one call shape over Ollama, DeepSeek and Anthropic.

    from aep.models import router
    r = router.complete("deepseek:deepseek-chat", messages, temperature=0.0, max_tokens=900)
    r = router.for_agent("documentation", messages)      # model picked from env, see AGENT_ROUTES
    r.text, r.tokens_prompt, r.tokens_completion, r.cost_usd, r.latency_ms, r.provider, r.model

Model strings are "provider:model" (provider = ollama | deepseek | anthropic). The
prefix may be left off: claude/fable/opus/sonnet/haiku/mythos names go to anthropic,
deepseek-* to deepseek, anything else to ollama. Only the first colon splits, so
"ollama:qwen2.5-coder:14b" is model "qwen2.5-coder:14b".

Per-agent routing (for_agent) reads env at call time:
  red_team       REDTEAM_MODEL        default anthropic:claude-opus-5-5
                 REDTEAM_FALLBACK_MODEL default ollama:qwen2.5-coder:14b
  judge          JUDGE_MODEL          default deepseek:deepseek-chat
  documentation  DOCUMENTATION_MODEL  default deepseek:deepseek-chat
Any agent also honours <AGENT>_FALLBACK_MODEL. The fallback serves when the primary's
provider has no credentials, or the primary fails after retries (or refuses). The
result's provider/model always name what actually served. for_agent("judge") raises
JudgeIndependenceError for any Claude-family primary or fallback, before any call: the
judge must stay independent of the Claude Red Team.

Credentials and endpoints come only from env: ANTHROPIC_API_KEY, DEEPSEEK_API_KEY,
DEEPSEEK_BASE_URL (default https://api.deepseek.com), OLLAMA_HOST (default
http://localhost:11434). Tuning: ROUTER_MAX_RETRIES (3), ROUTER_BACKOFF_BASE_S (0.5),
ROUTER_TIMEOUT_S (120), ROUTER_PRICES (JSON {"provider:model": [in, out]} USD per 1M
tokens, overrides PRICES).

Retries: connection errors, 408, 409, 429 and 5xx are retried with exponential backoff
plus jitter (Retry-After is honoured when larger). Other 4xx and missing credentials
fail at once. Every result carries tokens and cost; Ollama is always free. latency_ms is
wall-clock for the whole call, retries and fallback included.
"""
from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

import httpx

log = logging.getLogger("aep.models.router")

PROVIDERS = ("ollama", "deepseek", "anthropic")
_CLAUDE_MARKERS = ("claude", "anthropic", "fable", "mythos", "opus", "sonnet", "haiku")

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_ANTHROPIC_MAX_TOKENS = 16000
RETRYABLE_STATUS = frozenset({408, 409, 429})
MAX_BACKOFF_S = 30.0

# USD per 1M tokens (input, output), matched by longest model-name prefix.
# Anthropic: first-party list prices, cached 2026-09-25. DeepSeek: cache-miss list
# price; re-check against their pricing page, or override with ROUTER_PRICES.
PRICES: dict[str, dict[str, tuple[float, float]]] = {
    "anthropic": {
        "claude-fable-5": (10.0, 50.0),
        "claude-mythos-5": (10.0, 50.0),
        "claude-opus-5-5": (4.0, 20.0),
        "claude-opus-5": (5.0, 25.0),
        "claude-opus-4": (5.0, 25.0),
        "claude-sonnet-5": (2.0, 10.0),
        "claude-sonnet-4": (3.0, 15.0),
        "claude-haiku-4": (1.0, 5.0),
    },
    "deepseek": {
        "deepseek-chat": (0.28, 0.42),
        "deepseek-reasoner": (0.28, 0.42),
    },
}
# An unpriced paid model is charged at the provider's highest rate, so budgets err high.
_UNKNOWN_PRICE = {p: max(t.values(), key=sum) for p, t in PRICES.items()}

# Claude models that still accept temperature/top_p/top_k. Newer ones return a 400.
_SAMPLING_OK = ("claude-haiku-4", "claude-sonnet-4", "claude-opus-4-6", "claude-opus-4-5",
                "claude-opus-4-1", "claude-opus-4-0", "claude-3")
_SAMPLING_KEYS = ("temperature", "top_p", "top_k")


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LLMResult:
    text: str
    tokens_prompt: int
    tokens_completion: int
    cost_usd: float
    latency_ms: float
    provider: str
    model: str


class RouterError(RuntimeError):
    """Base for every error the router raises."""


class ConfigError(RouterError):
    """Bad model string, unknown agent, or missing credentials. Never retried."""


class JudgeIndependenceError(ConfigError, ValueError):
    """A Claude-family model was routed to the judge."""


class ProviderError(RouterError):
    def __init__(self, provider: str, message: str, *, status: Optional[int] = None,
                 retryable: bool = False, retry_after: Optional[float] = None) -> None:
        super().__init__(f"{provider}: {message}")
        self.provider, self.status, self.retryable, self.retry_after = provider, status, retryable, retry_after


@dataclass(frozen=True)
class Route:
    env: str
    default: Optional[str] = None
    fallback: Optional[str] = None
    independent_of_claude: bool = False

    @property
    def fallback_env(self) -> str:
        return self.env.replace("_MODEL", "_FALLBACK_MODEL")


AGENT_ROUTES: dict[str, Route] = {
    "redteam": Route("REDTEAM_MODEL", "anthropic:claude-opus-5-5", fallback="ollama:qwen2.5-coder:14b"),
    "judge": Route("JUDGE_MODEL", "deepseek:deepseek-chat", independent_of_claude=True),
    "documentation": Route("DOCUMENTATION_MODEL", "deepseek:deepseek-chat"),
}


def _agent_key(agent: str) -> str:
    return agent.lower().replace("_", "").replace("-", "")


# --------------------------------------------------------------------------- #
# Model strings, pricing
# --------------------------------------------------------------------------- #
def parse_model(model_str: str) -> tuple[str, str]:
    """"provider:model" -> (provider, model); infers the provider when there is no prefix."""
    spec = (model_str or "").strip()
    if not spec:
        raise ConfigError("empty model string")
    head, sep, tail = spec.partition(":")
    if sep and head.lower() in PROVIDERS:
        if not tail:
            raise ConfigError(f"no model after provider in {model_str!r}")
        return head.lower(), tail
    low = spec.lower()
    if any(m in low for m in _CLAUDE_MARKERS):
        return "anthropic", spec
    if low.startswith("deepseek"):
        return "deepseek", spec
    return "ollama", spec


def is_claude_family(provider: str, model: str) -> bool:
    return provider == "anthropic" or any(m in model.lower() for m in _CLAUDE_MARKERS)


def price_per_mtok(provider: str, model: str, env: Mapping[str, str]) -> tuple[float, float]:
    if provider == "ollama":
        return (0.0, 0.0)
    override = env.get("ROUTER_PRICES")
    if override:
        try:
            table = json.loads(override)
            hit = table.get(f"{provider}:{model}")
            if hit is not None:
                return float(hit[0]), float(hit[1])
        except (ValueError, TypeError, IndexError, AttributeError):
            log.warning("router: ignoring malformed ROUTER_PRICES")
    known = PRICES.get(provider, {})
    matches = [p for p in known if model.startswith(p)]
    if matches:
        return known[max(matches, key=len)]
    log.warning("router: no price for %s:%s; charging the provider's highest rate", provider, model)
    return _UNKNOWN_PRICE.get(provider, (0.0, 0.0))


# --------------------------------------------------------------------------- #
# Providers. Each returns (text, tokens_prompt, tokens_completion, served_model).
# --------------------------------------------------------------------------- #
def _status_error(provider: str, status: int, body: str, retry_after: Optional[str]) -> ProviderError:
    try:
        wait = float(retry_after) if retry_after is not None else None
    except ValueError:
        wait = None
    retryable = status in RETRYABLE_STATUS or status >= 500
    return ProviderError(provider, f"HTTP {status}: {body[:300]}", status=status,
                         retryable=retryable, retry_after=wait)


def _post_json(provider: str, http: httpx.Client, url: str, body: dict, headers: dict,
               timeout: float) -> dict:
    try:
        resp = http.post(url, json=body, headers=headers, timeout=timeout)
    except httpx.TransportError as exc:  # connect, read, timeout
        raise ProviderError(provider, f"{type(exc).__name__}: {exc}", retryable=True) from exc
    if resp.status_code >= 400:
        raise _status_error(provider, resp.status_code, resp.text, resp.headers.get("retry-after"))
    try:
        return resp.json()
    except ValueError as exc:
        raise ProviderError(provider, "response is not JSON", retryable=True) from exc


def _call_ollama(http: httpx.Client, env: Mapping[str, str], model: str, messages: list[dict],
                 kw: dict, timeout: float) -> tuple[str, int, int, str]:
    options = {k: kw.pop(k) for k in ("temperature", "top_p", "top_k", "seed") if k in kw}
    if "max_tokens" in kw:
        options["num_predict"] = kw.pop("max_tokens")
    if "stop" in kw:
        options["stop"] = kw.pop("stop")
    body = {"model": model, "messages": messages, "stream": False, **kw}
    if options:
        body["options"] = {**body.get("options", {}), **options}
    host = env.get("OLLAMA_HOST") or DEFAULT_OLLAMA_HOST
    data = _post_json("ollama", http, f"{host.rstrip('/')}/api/chat", body, {}, timeout)
    text = (data.get("message") or {}).get("content") or ""
    return text, int(data.get("prompt_eval_count") or 0), int(data.get("eval_count") or 0), data.get("model") or model


def _call_deepseek(http: httpx.Client, env: Mapping[str, str], model: str, messages: list[dict],
                   kw: dict, timeout: float) -> tuple[str, int, int, str]:
    key = env.get("DEEPSEEK_API_KEY")
    if not key:
        raise ConfigError("DEEPSEEK_API_KEY is not set")
    base = env.get("DEEPSEEK_BASE_URL") or DEFAULT_DEEPSEEK_BASE_URL
    body = {"model": model, "messages": messages, "stream": False, **kw}
    data = _post_json("deepseek", http, f"{base.rstrip('/')}/chat/completions", body,
                      {"Authorization": f"Bearer {key}"}, timeout)
    choices = data.get("choices") or []
    if not choices:
        raise ProviderError("deepseek", "response has no choices", retryable=True)
    text = (choices[0].get("message") or {}).get("content") or ""
    usage = data.get("usage") or {}
    return (text, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
            data.get("model") or model)


def _call_anthropic(http: httpx.Client, env: Mapping[str, str], model: str, messages: list[dict],
                    kw: dict, timeout: float) -> tuple[str, int, int, str]:
    import anthropic

    key = env.get("ANTHROPIC_API_KEY")
    if not key:
        raise ConfigError("ANTHROPIC_API_KEY is not set")
    # Leading system messages become the top-level system prompt.
    system = []
    while messages and messages[0].get("role") == "system":
        system.append(str(messages[0].get("content") or ""))
        messages = messages[1:]
    if "system" in kw:
        system.insert(0, str(kw.pop("system")))
    params: dict[str, Any] = {"model": model, "messages": messages,
                              "max_tokens": kw.pop("max_tokens", DEFAULT_ANTHROPIC_MAX_TOKENS)}
    if system:
        params["system"] = "\n\n".join(system)
    if "stop" in kw:
        stop = kw.pop("stop")
        params["stop_sequences"] = [stop] if isinstance(stop, str) else list(stop)
    for k in _SAMPLING_KEYS:
        if k in kw:
            value = kw.pop(k)
            if model.startswith(_SAMPLING_OK):
                params[k] = value
            else:
                log.debug("router: %s does not accept %s; dropped", model, k)
    if kw:
        params["extra_body"] = kw

    # The router owns retries, so the SDK's are off.
    client = anthropic.Anthropic(api_key=key, http_client=http, max_retries=0, timeout=timeout)
    try:
        resp = client.messages.create(**params)
    except anthropic.APIStatusError as exc:
        raise _status_error("anthropic", exc.status_code, str(exc.message),
                            exc.response.headers.get("retry-after")) from exc
    except anthropic.APIConnectionError as exc:  # includes APITimeoutError
        raise ProviderError("anthropic", f"{type(exc).__name__}: {exc}", retryable=True) from exc
    if resp.stop_reason == "refusal":
        category = getattr(getattr(resp, "stop_details", None), "category", None)
        raise ProviderError("anthropic", f"model refused (category={category})")
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    u = resp.usage
    prompt = (u.input_tokens or 0) + (getattr(u, "cache_read_input_tokens", None) or 0) \
        + (getattr(u, "cache_creation_input_tokens", None) or 0)
    return text, int(prompt), int(u.output_tokens or 0), resp.model or model


_PROVIDER_CALLS: dict[str, Callable[..., tuple[str, int, int, str]]] = {
    "ollama": _call_ollama,
    "deepseek": _call_deepseek,
    "anthropic": _call_anthropic,
}
_KEY_ENV = {"deepseek": "DEEPSEEK_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}


# --------------------------------------------------------------------------- #
# Router
# --------------------------------------------------------------------------- #
class Router:
    """Holds the HTTP client and settings. The module-level functions use a shared default."""

    def __init__(self, *, env: Optional[Mapping[str, str]] = None, http: Optional[httpx.Client] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 rand: Callable[[], float] = random.random) -> None:
        self._env = env
        self._http = http
        self._sleep, self._rand = sleep, rand
        self._lock = threading.Lock()

    @property
    def env(self) -> Mapping[str, str]:
        return os.environ if self._env is None else self._env

    def _client(self) -> httpx.Client:
        with self._lock:
            if self._http is None:
                self._http = httpx.Client()
            return self._http

    def _int(self, key: str, default: int) -> int:
        try:
            return int(self.env.get(key, default))
        except ValueError:
            return default

    def _float(self, key: str, default: float) -> float:
        try:
            return float(self.env.get(key, default))
        except ValueError:
            return default

    # ---- public -------------------------------------------------------------------------------

    def complete(self, model_str: str, messages: list[dict], **kw: Any) -> LLMResult:
        t0 = time.perf_counter()
        provider, model = parse_model(model_str)
        return self._finish(t0, provider, *self._call_with_retry(provider, model, messages, kw))

    def for_agent(self, agent: str, messages: list[dict], **kw: Any) -> LLMResult:
        t0 = time.perf_counter()
        primary, fallback = self.resolve_agent(agent)
        chain = [primary] + ([fallback] if fallback and fallback != primary else [])
        last: Optional[RouterError] = None
        for i, (provider, model) in enumerate(chain):
            key_env = _KEY_ENV.get(provider)
            if key_env and not self.env.get(key_env) and i + 1 < len(chain):
                log.info("router: %s has no %s; using fallback for %s", provider, key_env, agent)
                continue
            try:
                return self._finish(t0, provider, *self._call_with_retry(provider, model, messages, dict(kw)))
            except RouterError as exc:
                last = exc
                if i + 1 < len(chain):
                    log.warning("router: %s:%s failed for %s (%s); trying fallback", provider, model, agent, exc)
        assert last is not None
        raise last

    def resolve_agent(self, agent: str) -> tuple[tuple[str, str], Optional[tuple[str, str]]]:
        """(primary, fallback) for an agent, from env with defaults. Enforces judge independence."""
        key = _agent_key(agent)
        route = AGENT_ROUTES.get(key) or Route(f"{key.upper()}_MODEL")
        primary_str = self.env.get(route.env) or route.default
        if not primary_str:
            raise ConfigError(f"no model for agent {agent!r}: set {route.env}")
        fallback_str = self.env.get(route.fallback_env) or route.fallback
        primary = parse_model(primary_str)
        fallback = parse_model(fallback_str) if fallback_str else None
        if route.independent_of_claude:
            for p, m in filter(None, (primary, fallback)):
                if is_claude_family(p, m):
                    raise JudgeIndependenceError(
                        f"{agent} may not use Claude-family model {p}:{m}; "
                        "it must stay independent of the Claude Red Team")
        return primary, fallback

    # ---- internals ----------------------------------------------------------------------------

    def _call_with_retry(self, provider: str, model: str, messages: list[dict],
                         kw: dict) -> tuple[str, int, int, str]:
        call = _PROVIDER_CALLS[provider]
        retries = max(0, self._int("ROUTER_MAX_RETRIES", 3))
        base = self._float("ROUTER_BACKOFF_BASE_S", 0.5)
        timeout = self._float("ROUTER_TIMEOUT_S", 120.0)
        attempt = 0
        while True:
            try:
                return call(self._client(), self.env, model, list(messages), dict(kw), timeout)
            except ProviderError as exc:
                if not exc.retryable or attempt >= retries:
                    raise
                delay = min(MAX_BACKOFF_S, base * (2 ** attempt)) * (0.5 + self._rand() / 2)
                if exc.retry_after is not None:
                    delay = max(delay, min(MAX_BACKOFF_S, exc.retry_after))
                attempt += 1
                log.warning("router: %s:%s attempt %d failed (%s); retrying in %.2fs",
                            provider, model, attempt, exc, delay)
                self._sleep(delay)

    def _finish(self, t0: float, provider: str, text: str, tokens_prompt: int, tokens_completion: int,
                served_model: str) -> LLMResult:
        price_in, price_out = price_per_mtok(provider, served_model, self.env)
        cost = (tokens_prompt * price_in + tokens_completion * price_out) / 1_000_000
        return LLMResult(text=text, tokens_prompt=tokens_prompt, tokens_completion=tokens_completion,
                         cost_usd=cost, latency_ms=(time.perf_counter() - t0) * 1000.0,
                         provider=provider, model=served_model)


# --------------------------------------------------------------------------- #
# Module-level API (what the agents import)
# --------------------------------------------------------------------------- #
_default: Optional[Router] = None
_default_lock = threading.Lock()


def get_router() -> Router:
    global _default
    with _default_lock:
        if _default is None:
            _default = Router()
        return _default


def set_router(router: Optional[Router]) -> None:
    """Replace the shared router (tests, or a custom http client). None resets to lazy default."""
    global _default
    with _default_lock:
        _default = router


def complete(model_str: str, messages: list[dict], **kw: Any) -> LLMResult:
    return get_router().complete(model_str, messages, **kw)


def for_agent(agent: str, messages: list[dict], **kw: Any) -> LLMResult:
    return get_router().for_agent(agent, messages, **kw)


def resolve_agent(agent: str) -> tuple[tuple[str, str], Optional[tuple[str, str]]]:
    return get_router().resolve_agent(agent)


__all__ = [
    "AGENT_ROUTES", "PRICES", "ConfigError", "JudgeIndependenceError", "LLMResult", "ProviderError",
    "Route", "Router", "RouterError", "complete", "for_agent", "get_router", "is_claude_family",
    "parse_model", "price_per_mtok", "resolve_agent", "set_router",
]
