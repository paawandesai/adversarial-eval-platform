"""Tracer (contracts.interfaces.Tracer) backed by self-hosted Langfuse.

    tracer = get_tracer()
    with tracer.trace(run.correlation_id, "redteam.generate") as span:
        result = router.complete(...)
        span.record_llm(result)                       # tokens + cost from LLMResult
        span.tool_call("target.chat", args={...}, result=resp)

    @traced("judge.evaluate")                         # correlation_id from args
    async def evaluate(run: AttackRun): ...

    tracer.summary(run.correlation_id)  # -> latency_ms_by_step, tokens_*, cost_usd

Every span for one agent invocation lands in one Langfuse trace whose id is
derived from the correlation_id; nested trace() calls become child spans.

Config (env): LANGFUSE_HOST, LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY.
If any is missing, the SDK isn't installed, or Langfuse errors, the tracer
degrades to local logging (logger "aep.obs") and never raises into the
caller. All payloads go through scrub() before they reach Langfuse or the log.
Prompt/completion text is only sent when OBS_CAPTURE_CONTENT=1 (still scrubbed),
since free text can carry PHI no regex will catch.
"""
from __future__ import annotations

import contextvars
import functools
import inspect
import json
import logging
import os
import threading
import time
from collections import OrderedDict, deque
from typing import Any, Callable, Optional
from uuid import uuid4

from aep.obs.scrub import langfuse_mask, scrub

log = logging.getLogger("aep.obs")

_current: contextvars.ContextVar[Optional["Span"]] = contextvars.ContextVar("obs_span", default=None)

# LLMResult (aep.models.router) names first; the rest are aliases for other result shapes.
_INPUT_KEYS = ("tokens_prompt", "input_tokens", "prompt_tokens", "tokens_in")
_OUTPUT_KEYS = ("tokens_completion", "output_tokens", "completion_tokens", "tokens_out")
_COST_KEYS = ("cost_usd", "cost", "total_cost")


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _first(obj: Any, keys: tuple[str, ...]) -> Any:
    for source in (obj, _get(obj, "usage")):
        if source is None:
            continue
        for k in keys:
            v = _get(source, k)
            if v is not None:
                return v
    return None


def _capture_content() -> bool:
    return os.environ.get("OBS_CAPTURE_CONTENT", "").lower() in ("1", "true", "yes")


class Span:
    """Handle yielded by trace(). All methods are safe to call; none raise."""

    def __init__(self, tracer: "LangfuseTracer", correlation_id: str, step: str,
                 parent: Optional["Span"], metadata: dict):
        self.tracer = tracer
        self.correlation_id = correlation_id
        self.step = step
        self.parent = parent
        self.metadata = dict(metadata)
        self.latency_ms: Optional[float] = None
        self.tokens_prompt = 0
        self.tokens_completion = 0
        self.cost_usd = 0.0
        self.llm_calls: list[dict] = []
        self.tool_calls: list[dict] = []
        self.output: Any = None
        self.error: Optional[str] = None
        self._t0 = 0.0
        self._lf = None  # Langfuse span, when the backend is live

    def record_llm(self, result: Any = None, *, model: Optional[str] = None,
                   input_tokens: Optional[int] = None, output_tokens: Optional[int] = None,
                   cost_usd: Optional[float] = None, prompt: Any = None,
                   completion: Any = None) -> None:
        """Attach token counts and cost. `result` is the router's LLMResult (object
        or dict; usage may be flat or under `.usage`). Explicit kwargs win."""
        try:
            call = {
                "model": model or (_get(result, "model") if result is not None else None),
                "input_tokens": int(input_tokens if input_tokens is not None else _first(result, _INPUT_KEYS) or 0),
                "output_tokens": int(output_tokens if output_tokens is not None else _first(result, _OUTPUT_KEYS) or 0),
                "cost_usd": float(cost_usd if cost_usd is not None else _first(result, _COST_KEYS) or 0.0),
            }
            latency = _get(result, "latency_ms") if result is not None else None
            if latency is not None:
                call["latency_ms"] = float(latency)
            if _capture_content():
                call["prompt"] = prompt if prompt is not None else _get(result, "prompt") if result is not None else None
                call["completion"] = completion if completion is not None else (
                    _get(result, "text") if result is not None else None)
            self.tokens_prompt += call["input_tokens"]
            self.tokens_completion += call["output_tokens"]
            self.cost_usd += call["cost_usd"]
            self.llm_calls.append(call)
            self.tracer._emit_generation(self, call)
        except Exception:  # observability must never break the caller
            log.warning("obs: record_llm failed", exc_info=True)

    def tool_call(self, name: str, args: Any = None, result: Any = None, *,
                  error: Optional[str] = None, latency_ms: Optional[float] = None) -> None:
        """Record a tool-call event (name, args, result) under this span."""
        try:
            event = {"name": name, "args": args, "result": result, "error": error, "latency_ms": latency_ms}
            self.tool_calls.append(event)
            self.tracer._emit_event(self, event)
        except Exception:
            log.warning("obs: tool_call failed", exc_info=True)

    def set_metadata(self, **kwargs: Any) -> None:
        self.metadata.update(kwargs)

    def set_output(self, output: Any) -> None:
        self.output = output

    def to_record(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "step": self.step,
            "parent_step": self.parent.step if self.parent else None,
            "latency_ms": self.latency_ms,
            "tokens_prompt": self.tokens_prompt,
            "tokens_completion": self.tokens_completion,
            "cost_usd": self.cost_usd,
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "metadata": self.metadata,
            "error": self.error,
        }


class _TraceContext:
    """Sync and async context manager returned by LangfuseTracer.trace()."""

    def __init__(self, tracer: "LangfuseTracer", correlation_id: str, step: str, metadata: dict):
        parent = _current.get()
        if parent is not None and parent.correlation_id != correlation_id:
            parent = None  # never nest across invocations
        self.span = Span(tracer, correlation_id, step, parent, metadata)
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> Span:
        self._token = _current.set(self.span)
        self.span.tracer._start(self.span)
        self.span._t0 = time.perf_counter()
        return self.span

    def __exit__(self, exc_type, exc, tb) -> bool:
        span = self.span
        span.latency_ms = (time.perf_counter() - span._t0) * 1000.0
        if exc_type is not None:
            span.error = f"{exc_type.__name__}: {exc}"
        if self._token is not None:
            _current.reset(self._token)
        span.tracer._finish(span)
        return False  # re-raise caller exceptions untouched

    async def __aenter__(self) -> Span:
        return self.__enter__()

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return self.__exit__(exc_type, exc, tb)


class LangfuseTracer:
    """Conforms to contracts.interfaces.Tracer."""

    def __init__(self, *, host: Optional[str] = None, public_key: Optional[str] = None,
                 secret_key: Optional[str] = None, client: Any = None,
                 max_records: int = 2000, max_summaries: int = 1024):
        self.records: deque[dict] = deque(maxlen=max_records)  # scrubbed, newest last
        self._summaries: OrderedDict[str, dict] = OrderedDict()
        self._max_summaries = max_summaries
        self._lock = threading.Lock()
        self._client = client if client is not None else self._connect(
            host or os.environ.get("LANGFUSE_HOST"),
            public_key or os.environ.get("LANGFUSE_PUBLIC_KEY"),
            secret_key or os.environ.get("LANGFUSE_SECRET_KEY"),
        )

    @staticmethod
    def _connect(host: Optional[str], public_key: Optional[str], secret_key: Optional[str]) -> Any:
        if not (host and public_key and secret_key):
            log.info("obs: Langfuse env not set (LANGFUSE_HOST/PUBLIC_KEY/SECRET_KEY); logging locally")
            return None
        try:
            from langfuse import Langfuse
            return Langfuse(public_key=public_key, secret_key=secret_key, host=host, mask=langfuse_mask)
        except Exception:
            log.warning("obs: Langfuse unavailable; logging locally", exc_info=True)
            return None

    @property
    def enabled(self) -> bool:
        """True when spans are being shipped to Langfuse."""
        return self._client is not None

    # -- public API ---------------------------------------------------------

    def trace(self, correlation_id: str, step: str, **metadata: Any) -> _TraceContext:
        return _TraceContext(self, str(correlation_id), step, metadata)

    def traced(self, step: Optional[str] = None, *, correlation_id_arg: str = "correlation_id") -> Callable:
        """Decorator for sync or async functions; see module-level traced()."""
        return _traced(lambda: self, step, correlation_id_arg)

    def summary(self, correlation_id: str) -> dict:
        """Aggregates for one invocation, shaped like the AttackRun observability fields."""
        with self._lock:
            s = self._summaries.get(correlation_id)
            return json.loads(json.dumps(s)) if s else {
                "latency_ms_by_step": {}, "tokens_prompt": 0, "tokens_completion": 0, "cost_usd": 0.0,
            }

    def flush(self) -> None:
        if self._client is not None:
            try:
                self._client.flush()
            except Exception:
                log.warning("obs: Langfuse flush failed", exc_info=True)

    def shutdown(self) -> None:
        if self._client is not None:
            try:
                self._client.shutdown()
            except Exception:
                log.warning("obs: Langfuse shutdown failed", exc_info=True)

    # -- backend ------------------------------------------------------------

    def _trace_context(self, span: Span, parent_lf: Any = None) -> dict:
        ctx = {"trace_id": self._client.create_trace_id(seed=span.correlation_id)}
        if parent_lf is not None:
            ctx["parent_span_id"] = parent_lf.id
        return ctx

    def _backend(self, what: str, fn: Callable[[], Any]) -> Any:
        if self._client is None:
            return None
        try:
            return fn()
        except Exception:
            log.warning("obs: Langfuse %s failed; continuing locally", what, exc_info=True)
            return None

    def _start(self, span: Span) -> None:
        def start():
            parent_lf = span.parent._lf if span.parent else None
            lf = self._client.start_span(
                trace_context=self._trace_context(span, parent_lf),
                name=scrub(span.step),
                metadata=scrub({"correlation_id": span.correlation_id, **span.metadata}),
            )
            if span.parent is None:
                lf.update_trace(name=scrub(span.step), session_id=scrub(span.correlation_id),
                                metadata=scrub({"correlation_id": span.correlation_id}))
            return lf
        span._lf = self._backend("start_span", start)

    def _emit_generation(self, span: Span, call: dict) -> None:
        def emit():
            clean = scrub(call)
            gen = self._client.start_generation(
                trace_context=self._trace_context(span, span._lf),
                name=scrub(f"{span.step}.llm"),
                model=clean.get("model"),
                input=clean.get("prompt"),
                output=clean.get("completion"),
                usage_details={"input": clean["input_tokens"], "output": clean["output_tokens"]},
                cost_details={"total": clean["cost_usd"]},
                metadata={"latency_ms": clean.get("latency_ms")},
            )
            gen.end()
        self._backend("generation", emit)

    def _emit_event(self, span: Span, event: dict) -> None:
        def emit():
            clean = scrub(event)
            self._client.create_event(
                trace_context=self._trace_context(span, span._lf),
                name=f"tool:{clean['name']}",
                input=clean["args"],
                output=clean["result"],
                metadata={"latency_ms": clean["latency_ms"]},
                level="ERROR" if clean["error"] else None,
                status_message=clean["error"],
            )
        self._backend("event", emit)

    def _finish(self, span: Span) -> None:
        record = scrub(span.to_record())
        with self._lock:
            self.records.append(record)
            s = self._summaries.setdefault(span.correlation_id, {
                "latency_ms_by_step": {}, "tokens_prompt": 0, "tokens_completion": 0, "cost_usd": 0.0,
            })
            self._summaries.move_to_end(span.correlation_id)
            by_step = s["latency_ms_by_step"]
            by_step[span.step] = by_step.get(span.step, 0.0) + span.latency_ms
            s["tokens_prompt"] += span.tokens_prompt
            s["tokens_completion"] += span.tokens_completion
            s["cost_usd"] += span.cost_usd
            while len(self._summaries) > self._max_summaries:
                self._summaries.popitem(last=False)

        log.log(logging.DEBUG if self.enabled else logging.INFO, "obs.span %s", json.dumps(record, default=str))

        def end():
            span._lf.update(
                output=scrub(span.output),
                metadata=scrub({"latency_ms": span.latency_ms, **span.metadata}),
                level="ERROR" if span.error else None,
                status_message=scrub(span.error),
            )
            span._lf.end()
        if span._lf is not None:
            self._backend("end_span", end)


_default: Optional[LangfuseTracer] = None
_default_lock = threading.Lock()


def get_tracer() -> LangfuseTracer:
    """Process-wide tracer, built lazily from env on first use."""
    global _default
    with _default_lock:
        if _default is None:
            _default = LangfuseTracer()
        return _default


def set_tracer(tracer: Optional[LangfuseTracer]) -> None:
    """Swap the process-wide tracer (tests, or wiring a custom client)."""
    global _default
    with _default_lock:
        _default = tracer


def trace(correlation_id: str, step: str, **metadata: Any) -> _TraceContext:
    return get_tracer().trace(correlation_id, step, **metadata)


def traced(step: Optional[str] = None, *, correlation_id_arg: str = "correlation_id") -> Callable:
    """Decorator for sync or async functions, using the process-wide tracer
    (resolved per call, so set_tracer() after import still takes effect).

    The correlation id is taken from the `correlation_id_arg` parameter, else any
    argument with a `.correlation_id` (e.g. an AttackRun), else the enclosing
    span, else a fresh id."""
    return _traced(get_tracer, step, correlation_id_arg)


def _traced(get: Callable[[], LangfuseTracer], step: Optional[str], correlation_id_arg: str) -> Callable:
    def decorate(fn: Callable) -> Callable:
        name = step or f"{fn.__module__}.{fn.__qualname__}"
        sig = inspect.signature(fn)

        def cid_for(args: tuple, kwargs: dict) -> str:
            try:
                bound = sig.bind_partial(*args, **kwargs).arguments
            except TypeError:
                bound = dict(kwargs)
            if bound.get(correlation_id_arg):
                return str(bound[correlation_id_arg])
            for v in bound.values():
                cid = getattr(v, "correlation_id", None)
                if isinstance(cid, str) and cid:
                    return cid
            parent = _current.get()
            return parent.correlation_id if parent else f"corr_{uuid4().hex[:12]}"

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                with get().trace(cid_for(args, kwargs), name):
                    return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with get().trace(cid_for(args, kwargs), name):
                return fn(*args, **kwargs)
        return wrapper
    return decorate
