"""
TargetClient — the attacker's view of the Clinical Co-Pilot: its public HTTP
API, reached the way a clinician's browser or the OpenEMR module reaches it.
Endpoint contracts are transcribed in contracts/target_api.md; nothing here
is imported from the target's source.

What the client guarantees, and the rest of the platform leans on:

- **One correlation id per call, minted here.** Every request carries
  `X-Correlation-ID`; the target binds it to every log line, tool call and
  Langfuse trace for that request, and echoes it back. The judge's
  AuditReader (target/audit.py) finds the grey-box record by exactly this id.
  Minted ids are bare UUID4s because `POST /w2/ask` validates its echoed
  correlation_id as a UUID and 500s on anything else (target_api.md §6).
- **HTTP outcomes are data, not exceptions.** A 401/403/404/409/413/415/422/
  429/5xx is often the thing an attack is probing, so every call returns an
  envelope dict (status_code, body, correlation_id, latency_ms, ...) and
  never raises for a status. Only a transport failure (connect error,
  timeout) raises, as TargetTransportError, still carrying the correlation
  id so the judge can look for a partial trace.
- **Async and shareable.** One httpx.AsyncClient can be passed to many
  TargetClient instances (one per simulated user, each with its own token)
  for the 10/50/100-user load test; a client that creates its own
  AsyncClient closes it, one that was handed one does not.
- **The bearer token never leaves the Authorization header** — it is not in
  any envelope, exception message or repr.
"""

from __future__ import annotations

import asyncio
import mimetypes
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import httpx

from contracts.interfaces import TargetClientProtocol

# Seeded OpenEMR users the platform attacks as (AttackCase.as_user_role).
ROLES: tuple[str, ...] = ("physician", "nurse", "resident")

CORRELATION_ID_HEADER = "X-Correlation-ID"

DEFAULT_BASE_URL = "https://64.177.42.210:8443"
DEFAULT_TOKEN_URL = "https://64.177.42.210:9300/oauth2/default/token"

# Everything any exposed route reads: the brief's four resource types, the
# conversation's lab/visit rules (Observation, Encounter), and the upload
# guard's REQUIRED_SCOPES (Patient, MedicationRequest, AllergyIntolerance).
# Same set as the target's scripts/smoke_test_fhir.py. A scope-abuse case
# narrows this with TargetClient(scope=...), never by editing the default.
DEFAULT_SCOPE = (
    "openid "
    "user/Patient.read "
    "user/Condition.read "
    "user/MedicationRequest.read "
    "user/AllergyIntolerance.read "
    "user/Encounter.read "
    "user/Observation.read"
)

# Refresh this long before the token's stated expiry (OpenEMR: 3600 s).
_TOKEN_SKEW_SECONDS = 60.0

CHAT_ROUTES = {
    # The multi-turn follow-up conversation (Week 1 Use Case 3).
    "conversation": "/pre-visit-brief/conversation",
    # The Week 2 supervisor turn; the only chat route that takes document_ids.
    "w2_ask": "/w2/ask",
}


class TargetAuthError(RuntimeError):
    """The OAuth token endpoint refused to mint a token."""

    def __init__(self, role: str, status_code: Optional[int], detail: str) -> None:
        super().__init__(f"authentication as {role!r} failed (HTTP {status_code}): {detail}")
        self.role = role
        self.status_code = status_code
        self.detail = detail


class TargetTransportError(RuntimeError):
    """No HTTP response at all: connect failure, TLS failure or timeout."""

    def __init__(self, endpoint: str, correlation_id: str, cause: Exception) -> None:
        super().__init__(f"{endpoint} failed without a response ({type(cause).__name__})")
        self.endpoint = endpoint
        self.correlation_id = correlation_id
        self.cause = cause


def new_correlation_id() -> str:
    """A bare UUID4: accepted by every target route, including /w2/ask."""
    return str(uuid.uuid4())


def _tls_verify() -> Union[bool, str]:
    # TODO(tls): trust the agent's Caddy local CA instead of skipping
    # verification. The target's operator exports that root
    # (agent/docs/deployment.md in the target repo); once it is in hand, set
    # TARGET_CA_BUNDLE=/path/to/caddy-root.crt and this verifies against it.
    # OpenEMR on :9300 is self-signed too, so the same applies to TOKEN_URL.
    bundle = os.environ.get("TARGET_CA_BUNDLE")
    return bundle if bundle else False


@dataclass(frozen=True)
class TargetConfig:
    base_url: str = DEFAULT_BASE_URL
    token_url: str = DEFAULT_TOKEN_URL
    client_id: Optional[str] = None
    client_secret: Optional[str] = field(default=None, repr=False)
    scope: str = DEFAULT_SCOPE
    verify: Union[bool, str] = False
    # The brief and a conversation turn each make an LLM call; 90 s is above
    # the target's own observed p99 with room for a loaded host.
    timeout_seconds: float = 90.0
    default_patient_id: Optional[str] = None
    chat_route: str = "conversation"

    @classmethod
    def from_env(cls) -> "TargetConfig":
        env = os.environ.get
        return cls(
            base_url=env("TARGET_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            token_url=env("TARGET_TOKEN_URL", DEFAULT_TOKEN_URL),
            # FHIR_CLIENT_* are the names the target's own scripts use for the
            # same password-grant client; accepted so one export serves both.
            client_id=env("TARGET_OAUTH_CLIENT_ID") or env("FHIR_CLIENT_ID"),
            client_secret=env("TARGET_OAUTH_CLIENT_SECRET") or env("FHIR_CLIENT_SECRET"),
            scope=env("TARGET_OAUTH_SCOPE", DEFAULT_SCOPE),
            verify=_tls_verify(),
            timeout_seconds=float(env("TARGET_TIMEOUT_SECONDS", "90")),
            default_patient_id=env("TARGET_PATIENT_ID"),
            chat_route=env("TARGET_CHAT_ROUTE", "conversation"),
        )

    def credentials_for(self, role: str) -> tuple[str, str]:
        """
        (username, password) for a seeded user. Overridable per role with
        TARGET_<ROLE>_USERNAME / TARGET_<ROLE>_PASSWORD.

        TODO(seed-users): only `physician` / `physician` is documented as
        seeded on the deployed target (username-as-password demo accounts).
        `nurse` and `resident` follow the same convention by default but are
        unconfirmed — if they do not exist, authenticate() raises
        TargetAuthError with OpenEMR's `invalid_grant`, and the accounts must
        be seeded (with the intended ACLs) on the target.
        """
        key = role.upper()
        username = os.environ.get(f"TARGET_{key}_USERNAME", role)
        password = os.environ.get(f"TARGET_{key}_PASSWORD", username)
        return username, password


def _message_text(content: Any) -> str:
    """A chat message's text: a plain string, or Anthropic-style text blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.get("text", "") if isinstance(block, dict) else str(block) for block in content
        )
    raise TypeError(f"unsupported message content type: {type(content).__name__}")


def _parse_body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {"raw": response.text}


class TargetClient(TargetClientProtocol):
    """
    One simulated clinician session against the target. Not safe to share
    across roles — create one per (user, role); share the AsyncClient instead.
    """

    def __init__(
        self,
        config: Optional[TargetConfig] = None,
        *,
        http: Optional[httpx.AsyncClient] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        patient_id: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> None:
        self.config = config or TargetConfig.from_env()
        self.patient_id = patient_id or self.config.default_patient_id
        self.scope = scope or self.config.scope
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(
            verify=self.config.verify,
            timeout=self.config.timeout_seconds,
            transport=transport,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=100),
        )
        self.role: Optional[str] = None
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        # Created on first use: on Python 3.9 a Lock binds to the event loop
        # current at construction, which may not be the one it is used on.
        self._token_lock: Optional[asyncio.Lock] = None
        self.granted_scope = ""
        self.last_correlation_id: Optional[str] = None

    def __repr__(self) -> str:  # never the token
        return f"TargetClient(base_url={self.config.base_url!r}, role={self.role!r})"

    async def __aenter__(self) -> "TargetClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # ------------------------------------------------------------------ auth

    async def authenticate(self, role: str) -> None:
        """
        Mint an access token for a seeded user via OpenEMR's OAuth2 token
        endpoint, **password grant** (target_api.md §2).

        Not client_credentials: the deployed OpenEMR advertises only
        authorization_code, password and refresh_token, and every route
        requires a token bound to a real clinician (`sub`), which
        client_credentials cannot carry. OpenEMR also requires the
        non-standard `user_role=users` form field for a staff login.
        """
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, got {role!r}")
        if not self.config.client_id or not self.config.client_secret:
            raise TargetAuthError(
                role,
                None,
                "no OAuth client configured: set TARGET_OAUTH_CLIENT_ID and "
                "TARGET_OAUTH_CLIENT_SECRET (a password-grant-enabled OpenEMR client)",
            )
        username, password = self.config.credentials_for(role)
        try:
            response = await self._http.post(
                self.config.token_url,
                data={
                    "grant_type": "password",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "username": username,
                    "password": password,
                    "user_role": "users",
                    "scope": self.scope,
                },
            )
        except httpx.TransportError as exc:
            raise TargetAuthError(role, None, f"token endpoint unreachable ({type(exc).__name__})") from exc

        body = _parse_body(response)
        token = body.get("access_token") if isinstance(body, dict) else None
        if response.status_code != 200 or not token:
            # OAuth error bodies are {error, error_description, hint}: safe to
            # surface; the request's password and secret are never echoed.
            detail = (
                f"{body.get('error')}: {body.get('error_description') or body.get('hint') or ''}"
                if isinstance(body, dict) and "error" in body
                else "no access_token in response"
            )
            raise TargetAuthError(role, response.status_code, detail.strip())

        self.role = role
        self._token = token
        expires_in = float(body.get("expires_in") or 3600)
        self._token_expires_at = time.monotonic() + expires_in
        # OpenEMR's `scope` field can understate the JWT's scopes (target
        # finding F-09): recorded for evidence, never used to decide anything.
        self.granted_scope = body.get("scope", "")

    async def _bearer(self) -> str:
        if self._token is None or self.role is None:
            raise RuntimeError("call authenticate(role) before calling the target")
        if time.monotonic() >= self._token_expires_at - _TOKEN_SKEW_SECONDS:
            if self._token_lock is None:
                self._token_lock = asyncio.Lock()
            async with self._token_lock:
                if time.monotonic() >= self._token_expires_at - _TOKEN_SKEW_SECONDS:
                    await self.authenticate(self.role)
        assert self._token is not None
        return self._token

    # ------------------------------------------------------------- transport

    async def _call(
        self,
        method: str,
        path: str,
        *,
        correlation_id: Optional[str] = None,
        authenticated: bool = True,
        **kwargs: Any,
    ) -> dict:
        correlation_id = correlation_id or new_correlation_id()
        self.last_correlation_id = correlation_id
        endpoint = f"{method} {path}"
        headers = dict(kwargs.pop("headers", None) or {})
        headers[CORRELATION_ID_HEADER] = correlation_id
        if authenticated:
            headers["Authorization"] = f"Bearer {await self._bearer()}"

        started = time.perf_counter()
        try:
            response = await self._http.request(
                method, f"{self.config.base_url}{path}", headers=headers, **kwargs
            )
        except httpx.TransportError as exc:
            raise TargetTransportError(endpoint, correlation_id, exc) from exc
        latency_ms = round((time.perf_counter() - started) * 1000, 3)

        body = _parse_body(response)
        # The target echoes the id it actually used; it substitutes a fresh
        # UUID for an inbound value that is not identifier-shaped. The echoed
        # one is what the audit trail is keyed by.
        echoed = response.headers.get(CORRELATION_ID_HEADER)
        if not echoed and isinstance(body, dict):
            echoed = body.get("correlation_id")
        return {
            "endpoint": endpoint,
            "status_code": response.status_code,
            "ok": response.is_success,
            "correlation_id": echoed or correlation_id,
            "correlation_id_sent": correlation_id,
            "latency_ms": latency_ms,
            "role": self.role,
            "body": body,
        }

    # ------------------------------------------------------------- endpoints

    async def chat(
        self,
        messages: list[dict],
        conversation_id: Optional[str] = None,
        *,
        patient_id: Optional[str] = None,
        document_ids: Optional[list[str]] = None,
        route: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> dict:
        """
        Send one conversation turn: the LAST `role == "user"` message.

        The target keeps conversation state server-side (keyed by the token's
        `sub` and the session) and its request schema has no history field,
        so earlier messages are not replayed — a multi-turn attack sends each
        turn in its own chat() call with the same conversation_id.

        conversation_id is the target's session_id; omit it to start a new
        conversation, then reuse the returned envelope's `conversation_id`.
        patient_id comes from the kwarg, else the message's `patient_id`,
        else the client's default. document_ids (kwarg or message field)
        route the turn to /w2/ask, the only chat route that takes them.
        """
        user_turns = [m for m in messages if m.get("role") == "user"]
        if not user_turns:
            raise ValueError("chat() needs at least one message with role 'user'")
        last = user_turns[-1]
        question = _message_text(last.get("content", ""))
        patient_id = patient_id or last.get("patient_id") or self.patient_id
        if not patient_id:
            raise ValueError("no patient_id: pass one, set it on the message, or on the client")
        if document_ids is None:
            document_ids = last.get("document_ids")
        route = route or ("w2_ask" if document_ids else self.config.chat_route)
        if route not in CHAT_ROUTES:
            raise ValueError(f"route must be one of {sorted(CHAT_ROUTES)}, got {route!r}")

        session_id = conversation_id or str(uuid.uuid4())
        payload: dict[str, Any] = {
            "patient_id": patient_id,
            "session_id": session_id,
            "question": question,
        }
        if route == "w2_ask":
            payload["document_ids"] = list(document_ids or [])

        result = await self._call(
            "POST", CHAT_ROUTES[route], json=payload, correlation_id=correlation_id
        )
        body = result["body"] if isinstance(result["body"], dict) else {}
        result.update(
            conversation_id=session_id,
            patient_id=patient_id,
            text=body.get("answer") if route == "conversation" else body.get("message"),
        )
        return result

    async def end_conversation(
        self, patient_id: str, conversation_id: str, *, correlation_id: Optional[str] = None
    ) -> dict:
        """Discard the server-side conversation state now rather than at its TTL."""
        return await self._call(
            "POST",
            "/pre-visit-brief/conversation/end",
            json={"patient_id": patient_id, "session_id": conversation_id},
            correlation_id=correlation_id,
        )

    async def upload(
        self,
        patient_id: str,
        file_path: str,
        doc_type: str,
        *,
        content_type: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> dict:
        """
        POST /documents?kind=<doc_type>&patient_id=<id> with the raw file as
        the body (not multipart). doc_type is passed through unvalidated —
        the target accepts lab_pdf | intake_form and 422s anything else,
        which is itself something a case may probe. Extraction runs in the
        background; poll extraction_status() with the returned document_id.
        """
        path = Path(file_path)
        data = await asyncio.to_thread(path.read_bytes)
        if content_type is None:
            guessed = mimetypes.guess_type(path.name)[0]
            content_type = guessed or "application/octet-stream"
        result = await self._call(
            "POST",
            "/documents",
            params={"kind": doc_type, "patient_id": patient_id},
            content=data,
            headers={"Content-Type": content_type},
            correlation_id=correlation_id,
        )
        body = result["body"] if isinstance(result["body"], dict) else {}
        result.update(
            patient_id=patient_id,
            document_id=body.get("document_id"),
            extraction_status=body.get("status"),
        )
        return result

    async def extraction_status(
        self, patient_id: str, document_id: str, *, correlation_id: Optional[str] = None
    ) -> dict:
        """GET /documents/{document_id}/extraction for the chart it was uploaded to."""
        result = await self._call(
            "GET",
            f"/documents/{document_id}/extraction",
            params={"patient_id": patient_id},
            correlation_id=correlation_id,
        )
        body = result["body"] if isinstance(result["body"], dict) else {}
        result.update(document_id=document_id, extraction_status=body.get("status"))
        return result

    async def pre_visit_brief(
        self,
        patient_id: str,
        *,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> dict:
        """POST /pre-visit-brief. The returned session_id can seed chat()'s conversation_id."""
        payload: dict[str, Any] = {"patient_id": patient_id}
        if session_id is not None:
            payload["session_id"] = session_id
        result = await self._call(
            "POST", "/pre-visit-brief", json=payload, correlation_id=correlation_id
        )
        body = result["body"] if isinstance(result["body"], dict) else {}
        result.update(
            patient_id=patient_id,
            text=body.get("brief"),
            conversation_id=body.get("session_id"),
        )
        return result

    async def health(self) -> dict:
        """GET /health — liveness, unauthenticated."""
        return await self._call("GET", "/health", authenticated=False)

    async def target_version(self) -> Optional[str]:
        """
        The target's published API version (openapi.json `info.version`).

        TODO(target-version): AttackRun.target_version wants a commit SHA,
        and the target exposes none (no /version route; /health returns only
        {"status": "alive"}). Until it does, regression anchors on this
        semver plus the deploy date recorded out of band.
        """
        result = await self._call("GET", "/openapi.json", authenticated=False)
        body = result["body"]
        if result["ok"] and isinstance(body, dict):
            return (body.get("info") or {}).get("version")
        return None
