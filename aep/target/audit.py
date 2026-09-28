# JUDGE-ONLY. The Red Team must never import this — it is a trust-boundary violation.
"""
AuditReader — the judge's grey-box, read-only view of what the target did
for one request: its tool calls and its event trace, keyed by the
correlation_id TargetClient sent (contracts/target_api.md §7).

Where the record lives. The target has no audit HTTP route. Every event it
logs is also exported to its self-hosted Langfuse, one trace per
correlation_id, with the trace id derived deterministically:

    trace_id = sha256(correlation_id).digest()[:16].hex()

(the Langfuse SDK's `create_trace_id(seed=...)`, which the target uses). So
the reader never needs the target's cooperation to find a request's trace,
only Langfuse's public read API: `GET /api/public/traces/{trace_id}`, which
returns the trace with its observations embedded. Each observation is one
target event; its `name` is the event type (`tool_call_event`,
`retrieval_event`, `authorization_check_event`, `llm_usage_event`, ...) and
its `metadata` is the event's fields.

What it does NOT hold: prompts, completions, answer text or chart values —
the target exports identifiers, counts and outcomes only. A judge that needs
the answer text reads it from the AttackRun transcript, not from here.

Separate credential. This reader authenticates to Langfuse with its own key
pair (AUDIT_LANGFUSE_*), never the target OAuth client TargetClient uses,
and this module is kept apart from target.client so the Red Team's import
graph never reaches it.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import httpx

from contracts.interfaces import AuditReaderProtocol

DEFAULT_AUDIT_HOST = "https://64-177-51-119.sslip.io"

# Target events that record the target acting on something outside itself.
TOOL_EVENT_TYPES = frozenset(
    {
        "tool_call_event",  # one per external call: FHIR read, LLM, vision, retriever, write-back
        "retrieval_event",  # one per FHIR resource type read, with counts
        "evidence_retrieval_event",  # W2 guideline-corpus search (/w2/ask)
        "authorization_check_event",  # requested vs held scope, and the outcome
        "llm_usage_event",  # model + token counts (a Langfuse GENERATION)
    }
)


class AuditUnavailable(RuntimeError):
    """The audit backend could not be read (not configured, unreachable, 401/403, 5xx)."""


def trace_id_for(correlation_id: str) -> str:
    """The Langfuse trace id the target files a request's events under."""
    return hashlib.sha256(correlation_id.encode("utf-8")).digest()[:16].hex()


@dataclass(frozen=True)
class AuditConfig:
    host: str = DEFAULT_AUDIT_HOST
    public_key: Optional[str] = None
    secret_key: Optional[str] = field(default=None, repr=False)
    # Langfuse has a Let's Encrypt certificate, so verification stays on.
    verify: Union[bool, str] = True
    timeout_seconds: float = 20.0
    # Langfuse ingests asynchronously: a trace can be 404 for a few seconds
    # after the target answered. Poll this long before concluding "no trace".
    ingest_wait_seconds: float = 15.0
    poll_interval_seconds: float = 1.0

    @classmethod
    def from_env(cls) -> "AuditConfig":
        env = os.environ.get
        # TODO(audit-credential): Langfuse project API keys are not scoped —
        # any key pair can also write. This reader only ever issues GETs, but
        # the key it is given should be a dedicated pair for the judge,
        # rotated independently of the target's own export keys, and never
        # present in the Red Team's environment.
        return cls(
            host=env("AUDIT_LANGFUSE_HOST", DEFAULT_AUDIT_HOST).rstrip("/"),
            public_key=env("AUDIT_LANGFUSE_PUBLIC_KEY"),
            secret_key=env("AUDIT_LANGFUSE_SECRET_KEY"),
            timeout_seconds=float(env("AUDIT_TIMEOUT_SECONDS", "20")),
            ingest_wait_seconds=float(env("AUDIT_INGEST_WAIT_SECONDS", "15")),
        )


def _observation_record(obs: dict) -> dict:
    metadata = obs.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {"raw": metadata}
    return {
        "event_type": metadata.get("event_type") or obs.get("name"),
        "tool": metadata.get("tool"),
        "target": metadata.get("target"),
        "outcome": metadata.get("outcome"),
        "status_code": metadata.get("status_code"),
        "latency_ms": metadata.get("latency_ms"),
        "resource_type": metadata.get("resource_type"),
        "model": obs.get("model"),
        "usage": obs.get("usageDetails") or obs.get("usage"),
        "level": obs.get("level"),
        "status_message": obs.get("statusMessage"),
        "start_time": obs.get("startTime"),
        "observation_id": obs.get("id"),
        "metadata": metadata,
    }


class AuditReader(AuditReaderProtocol):
    """Read-only. Every method is a GET against the audit backend."""

    def __init__(
        self,
        config: Optional[AuditConfig] = None,
        *,
        http: Optional[httpx.AsyncClient] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.config = config or AuditConfig.from_env()
        if not self.config.public_key or not self.config.secret_key:
            raise AuditUnavailable(
                "audit backend not configured: set AUDIT_LANGFUSE_PUBLIC_KEY and "
                "AUDIT_LANGFUSE_SECRET_KEY"
            )
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(
            verify=self.config.verify,
            timeout=self.config.timeout_seconds,
            transport=transport,
        )
        self._auth = httpx.BasicAuth(self.config.public_key, self.config.secret_key)

    def __repr__(self) -> str:  # never the keys
        return f"AuditReader(host={self.config.host!r})"

    async def __aenter__(self) -> "AuditReader":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def _get_trace(self, correlation_id: str) -> Optional[dict]:
        """The raw Langfuse trace, or None if none arrived within ingest_wait_seconds."""
        url = f"{self.config.host}/api/public/traces/{trace_id_for(correlation_id)}"
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.ingest_wait_seconds
        while True:
            try:
                response = await self._http.get(url, auth=self._auth)
            except httpx.TransportError as exc:
                raise AuditUnavailable(f"audit backend unreachable ({type(exc).__name__})") from exc
            if response.status_code == 200:
                return response.json()
            if response.status_code != 404:
                raise AuditUnavailable(f"audit backend answered HTTP {response.status_code}")
            if loop.time() >= deadline:
                return None
            await asyncio.sleep(self.config.poll_interval_seconds)

    async def tool_calls(self, correlation_id: str) -> list[dict]:
        """
        The target's external actions for this request, oldest first. Empty
        when there is no trace — which the judge must read as "no evidence",
        not as "no tool calls" (a request that 401s before any work emits
        only its http_request_event).
        """
        trace = await self._get_trace(correlation_id)
        if trace is None:
            return []
        records = [
            _observation_record(obs)
            for obs in trace.get("observations") or []
            if isinstance(obs, dict)
        ]
        calls = [r for r in records if r["event_type"] in TOOL_EVENT_TYPES]
        return sorted(calls, key=lambda r: r["start_time"] or "")

    async def response_trace(self, correlation_id: str) -> dict:
        """
        The whole request as the target recorded it: every event, the trace's
        tags (use_case, retrieved:<ResourceType>, route, ...) and scores
        (verification_passed, out_of_scope_request_rejected, ...).
        `found` is False when no trace arrived within the ingest wait.
        """
        trace = await self._get_trace(correlation_id)
        if trace is None:
            return {
                "correlation_id": correlation_id,
                "trace_id": trace_id_for(correlation_id),
                "found": False,
                "events": [],
                "scores": [],
                "tags": [],
            }
        events = sorted(
            (_observation_record(o) for o in trace.get("observations") or [] if isinstance(o, dict)),
            key=lambda r: r["start_time"] or "",
        )
        return {
            "correlation_id": correlation_id,
            "trace_id": trace.get("id") or trace_id_for(correlation_id),
            "found": True,
            "name": trace.get("name"),
            "session_id": trace.get("sessionId"),
            "tags": trace.get("tags") or [],
            "scores": [
                {k: s.get(k) for k in ("name", "value", "dataType", "observationId")}
                for s in trace.get("scores") or []
                if isinstance(s, dict)
            ],
            "latency": trace.get("latency"),
            "events": events,
        }
