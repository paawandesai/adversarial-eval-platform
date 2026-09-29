"""Platform liveness and readiness endpoints.

    python3 -m aep.health                        # serves on 127.0.0.1:8766
    python3 -m aep.health --host 0.0.0.0 --port 8080
    python3 scripts/dashboard.py --serve         # the dashboard server answers both routes too

GET /health   200 {"status": "alive", "uptime_s": ...} while the process can answer at all. No dependency
              is touched, so a slow provider never fails liveness.
GET /ready    200 {"status": "ready", "checks": {...}} when every required dependency answered;
              503 {"status": "not_ready", "checks": {...}} otherwise. Same body shape as the target's /ready.

Each check is {"status": "ok" | "down" | "not_configured", "required": bool, "detail": str, "latency_ms": ...}:

  target        GET {TARGET_BASE_URL}/ready (falls back to /health on a 404). A 503 "not_ready" from the target
                is down: campaigns against it would only produce errors. TLS as TargetClient does it
                (TARGET_CA_BUNDLE, else unverified). Always required.
  langfuse      GET {LANGFUSE_HOST}/api/public/health. Without LANGFUSE_HOST it is not_configured and not
                required, since aep.obs.tracing then logs locally by design. With a host but no key pair it is
                down: traces would be dropped silently.
  llm:<provider> one per provider some agent routes to (router.resolve_agent, primaries and fallbacks).
                deepseek  GET {DEEPSEEK_BASE_URL}/models with the key (free; a 401 means a bad key).
                anthropic models.list(limit=1) through the SDK (free; checks the key the same way).
                ollama    GET {OLLAMA_HOST}/api/tags, and every routed model must be pulled.
                A provider is required when some agent would have no working model without it, so a down
                primary with a live fallback reports down but does not fail readiness.
  llm_routing   only present when resolving the routes fails (bad model string, a Claude model on the judge).

Checks run concurrently and each is bounded by READY_TIMEOUT_S (default 3). The whole /ready answer is
bounded by twice that: a check still running then is reported down as timed out.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Optional, Union

import httpx

from aep.models.router import (
    AGENT_ROUTES, DEFAULT_DEEPSEEK_BASE_URL, DEFAULT_OLLAMA_HOST, ConfigError, Router,
)
from aep.target.client import DEFAULT_BASE_URL as DEFAULT_TARGET_BASE_URL

DEFAULT_TIMEOUT_S = 3.0
OK, DOWN, NOT_CONFIGURED = "ok", "down", "not_configured"
_STARTED = time.monotonic()


@dataclass
class Check:
    status: str
    required: bool = True
    detail: str = ""
    latency_ms: Optional[float] = None
    used_by: Optional[list[str]] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class _Probe:
    """One check to run: fn(client, env) -> Check. ``verify`` is the TLS setting its client needs."""
    fn: Callable[[httpx.Client, Mapping[str, str]], Check]
    verify: Union[bool, str] = True


def _timed(fn: Callable[[], Check]) -> Check:
    t0 = time.perf_counter()
    check = fn()
    if check.latency_ms is None and check.status != NOT_CONFIGURED:
        check.latency_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    return check


def _err(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _bad_status(url: str, resp: httpx.Response) -> str:
    if resp.status_code in (401, 403):
        return f"GET {url} -> {resp.status_code}: credentials rejected"
    return f"GET {url} -> {resp.status_code}"


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check_target(client: httpx.Client, env: Mapping[str, str]) -> Check:
    base = (env.get("TARGET_BASE_URL") or DEFAULT_TARGET_BASE_URL).rstrip("/")
    url = f"{base}/ready"
    try:
        resp = client.get(url)
        if resp.status_code == 404:
            url = f"{base}/health"
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return Check(DOWN, detail=f"GET {url}: {_err(exc)}")
    try:
        reported = (resp.json() or {}).get("status")
    except ValueError:
        reported = None
    suffix = f" ({reported})" if reported else ""
    if resp.status_code == 200:
        return Check(OK, detail=f"GET {url} -> 200{suffix}")
    return Check(DOWN, detail=_bad_status(url, resp) + suffix)


def check_langfuse(client: httpx.Client, env: Mapping[str, str]) -> Check:
    host = (env.get("LANGFUSE_HOST") or "").rstrip("/")
    if not host:
        return Check(NOT_CONFIGURED, required=False, detail="LANGFUSE_HOST not set; tracing logs locally")
    missing = [k for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY") if not env.get(k)]
    if missing:
        return Check(DOWN, detail=f"{' and '.join(missing)} not set; traces would be dropped")
    url = f"{host}/api/public/health"
    try:
        resp = client.get(url)
    except httpx.HTTPError as exc:
        return Check(DOWN, detail=f"GET {url}: {_err(exc)}")
    if resp.status_code == 200:
        return Check(OK, detail=f"GET {url} -> 200")
    return Check(DOWN, detail=_bad_status(url, resp))


def check_deepseek(client: httpx.Client, env: Mapping[str, str]) -> Check:
    key = env.get("DEEPSEEK_API_KEY")
    if not key:
        return Check(DOWN, detail="DEEPSEEK_API_KEY not set")
    url = f"{(env.get('DEEPSEEK_BASE_URL') or DEFAULT_DEEPSEEK_BASE_URL).rstrip('/')}/models"
    try:
        resp = client.get(url, headers={"Authorization": f"Bearer {key}"})
    except httpx.HTTPError as exc:
        return Check(DOWN, detail=f"GET {url}: {_err(exc)}")
    if resp.status_code == 200:
        return Check(OK, detail=f"GET {url} -> 200")
    return Check(DOWN, detail=_bad_status(url, resp))


def check_anthropic(client: httpx.Client, env: Mapping[str, str]) -> Check:
    import anthropic

    key = env.get("ANTHROPIC_API_KEY")
    if not key:
        return Check(DOWN, detail="ANTHROPIC_API_KEY not set")
    # Same construction as the router's calls, so ANTHROPIC_BASE_URL is honoured identically.
    sdk = anthropic.Anthropic(api_key=key, http_client=client, max_retries=0)
    try:
        sdk.models.list(limit=1)
    except anthropic.AuthenticationError as exc:
        return Check(DOWN, detail=f"models.list -> {exc.status_code}: credentials rejected")
    except anthropic.APIStatusError as exc:
        return Check(DOWN, detail=f"models.list -> {exc.status_code}")
    except anthropic.APIConnectionError as exc:  # includes APITimeoutError
        return Check(DOWN, detail=f"models.list: {_err(exc)}")
    return Check(OK, detail="models.list -> 200")


def check_ollama(client: httpx.Client, env: Mapping[str, str], models: list[str]) -> Check:
    url = f"{(env.get('OLLAMA_HOST') or DEFAULT_OLLAMA_HOST).rstrip('/')}/api/tags"
    try:
        resp = client.get(url)
    except httpx.HTTPError as exc:
        return Check(DOWN, detail=f"GET {url}: {_err(exc)}")
    if resp.status_code != 200:
        return Check(DOWN, detail=_bad_status(url, resp))
    try:
        pulled = {m.get("name") for m in resp.json().get("models") or []}
    except (ValueError, AttributeError):
        return Check(DOWN, detail=f"GET {url} -> 200 with an unreadable body")
    # An untagged name means ":latest" to Ollama.
    missing = [m for m in models if m not in pulled and f"{m}:latest" not in pulled]
    if missing:
        return Check(DOWN, detail=f"GET {url} -> 200, but not pulled: {', '.join(sorted(missing))}")
    return Check(OK, detail=f"GET {url} -> 200")


# --------------------------------------------------------------------------- #
# Readiness
# --------------------------------------------------------------------------- #
def _llm_routes(env: Mapping[str, str]) -> tuple[dict[str, set[str]], dict[str, list[str]], list[str]]:
    """(agent -> check names in its chain, check name -> agents using it, ollama models routed to).
    Raises ConfigError when a route does not resolve."""
    router = Router(env=env)
    chains: dict[str, set[str]] = {}
    used_by: dict[str, list[str]] = {}
    ollama_models: list[str] = []
    for agent in AGENT_ROUTES:
        primary, fallback = router.resolve_agent(agent)
        chains[agent] = set()
        for (provider, model), label in [(primary, agent)] + ([(fallback, f"{agent} (fallback)")] if fallback else []):
            name = f"llm:{provider}"
            chains[agent].add(name)
            if label not in used_by.setdefault(name, []):
                used_by[name].append(label)
            if provider == "ollama" and model not in ollama_models:
                ollama_models.append(model)
    return chains, used_by, ollama_models


def readiness(env: Optional[Mapping[str, str]] = None, *,
              transport: Optional[httpx.BaseTransport] = None,
              timeout: Optional[float] = None) -> tuple[int, dict[str, Any]]:
    """Run every check concurrently; (HTTP status, body). ``transport`` is for tests (httpx.MockTransport)."""
    env = os.environ if env is None else env
    if timeout is None:
        try:
            timeout = float(env.get("READY_TIMEOUT_S", DEFAULT_TIMEOUT_S))
        except ValueError:
            timeout = DEFAULT_TIMEOUT_S

    probes: dict[str, _Probe] = {
        "target": _Probe(check_target, verify=env.get("TARGET_CA_BUNDLE") or False),
        "langfuse": _Probe(check_langfuse),
    }
    routing_error: Optional[Check] = None
    try:
        chains, used_by, ollama_models = _llm_routes(env)
    except ConfigError as exc:
        chains, used_by, ollama_models = {}, {}, []
        routing_error = Check(DOWN, detail=str(exc))
    llm_fns: dict[str, Callable[[httpx.Client, Mapping[str, str]], Check]] = {
        "llm:deepseek": check_deepseek,
        "llm:anthropic": check_anthropic,
        "llm:ollama": lambda c, e: check_ollama(c, e, ollama_models),
    }
    probes.update({name: _Probe(llm_fns[name]) for name in used_by})

    def run(probe: _Probe) -> Check:
        try:
            with httpx.Client(timeout=timeout, verify=probe.verify, transport=transport) as client:
                return _timed(lambda: probe.fn(client, env))
        except Exception as exc:  # a check must report, never take /ready down with it
            return Check(DOWN, detail=f"check failed: {_err(exc)}")

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="ready")
    futures = {name: pool.submit(run, probe) for name, probe in probes.items()}
    concurrent.futures.wait(futures.values(), timeout=timeout * 2)
    pool.shutdown(wait=False)  # a hung check is abandoned, not waited on

    checks: dict[str, Check] = {}
    for name, fut in futures.items():
        checks[name] = fut.result() if fut.done() else Check(DOWN, detail=f"timed out after {timeout * 2:g}s")
        if name in used_by:
            checks[name].used_by = used_by[name]
    checks["langfuse"].required = checks["langfuse"].status != NOT_CONFIGURED

    # An LLM provider is required when some agent would be left with no working model without it.
    for name in used_by:
        checks[name].required = any(
            name in chain and not any(checks[other].status == OK for other in chain - {name})
            for chain in chains.values())
    if routing_error is not None:
        checks["llm_routing"] = routing_error

    ready = all(c.status == OK for c in checks.values() if c.required)
    body = {"status": "ready" if ready else "not_ready", "checks": {k: c.to_dict() for k, c in checks.items()}}
    return (200 if ready else 503), body


def liveness() -> tuple[int, dict[str, Any]]:
    return 200, {"status": "alive", "uptime_s": round(time.monotonic() - _STARTED, 1)}


def handle(path: str, *, ready: Callable[[], tuple[int, dict[str, Any]]] = readiness
           ) -> Optional[tuple[int, dict[str, Any]]]:
    """(status, JSON body) for /health and /ready, None for any other path. Shared with the dashboard server."""
    route = path.split("?")[0].rstrip("/") or "/"
    if route == "/health":
        return liveness()
    if route == "/ready":
        return ready()
    return None


def write_json(handler: BaseHTTPRequestHandler, status: int, body: Mapping[str, Any]) -> None:
    data = json.dumps(body, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
def make_server(host: str, port: int, *, ready: Callable[[], tuple[int, dict[str, Any]]] = readiness
                ) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            result = handle(self.path, ready=ready)
            if result is None:
                self.send_error(404)
                return
            write_json(self, *result)

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"[health] {fmt % args}\n")

    return ThreadingHTTPServer((host, port), Handler)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8766)
    args = p.parse_args(argv)
    httpd = make_server(args.host, args.port)
    print(f"health at http://{args.host}:{args.port}/health and /ready  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
