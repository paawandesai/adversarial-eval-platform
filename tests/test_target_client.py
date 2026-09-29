"""
Unit tests for aep/target — httpx.MockTransport only, no live calls.

Async code is driven with asyncio.run() so the suite needs nothing beyond
pytest and httpx.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from aep.target.audit import AuditConfig, AuditReader, AuditUnavailable, trace_id_for  # noqa: E402
from aep.target.client import (  # noqa: E402
    CORRELATION_ID_HEADER,
    TargetAuthError,
    TargetClient,
    TargetConfig,
    TargetTransportError,
)

BASE = "https://target.test"
TOKEN_URL = "https://emr.test/oauth2/default/token"
PATIENT = "a2c0e096-23d5-4cf9-ad5b-4895597363a7"
TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEifQ.sig"


# Env the client reads (TargetConfig.from_env, credentials_for) or the audit reader might. Cleared for every
# test so the suite passes the same whether or not a real .env is sourced into the shell.
AMBIENT_ENV_PREFIXES = ("TARGET_", "FHIR_CLIENT_", "AUDIT_LANGFUSE_")


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    import os
    for name in list(os.environ):
        if name.startswith(AMBIENT_ENV_PREFIXES):
            monkeypatch.delenv(name)


def config(**overrides) -> TargetConfig:
    values = dict(
        base_url=BASE,
        token_url=TOKEN_URL,
        client_id="cid",
        client_secret="csecret",
        default_patient_id=PATIENT,
    )
    values.update(overrides)
    return TargetConfig(**values)


class FakeTarget:
    """Records every request; answers the token endpoint and the agent routes."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.token_calls = 0
        self.expires_in = 3600
        self.routes: dict[tuple[str, str], object] = {}

    def on(self, method: str, path: str, handler) -> None:
        self.routes[(method, path)] = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) == TOKEN_URL:
            self.token_calls += 1
            return httpx.Response(
                200,
                json={
                    "access_token": TOKEN,
                    "token_type": "Bearer",
                    "expires_in": self.expires_in,
                    "scope": "openid user/Patient.read",
                },
            )
        handler = self.routes.get((request.method, request.url.path))
        if handler is None:
            return httpx.Response(404, json={"detail": "Not Found"})
        return handler(request)

    def agent_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if str(r.url) != TOKEN_URL]


def echo(status: int, body_fn):
    """A handler that echoes the inbound correlation id, as the target does."""

    def handler(request: httpx.Request) -> httpx.Response:
        cid = request.headers[CORRELATION_ID_HEADER]
        return httpx.Response(
            status, json=body_fn(request, cid), headers={CORRELATION_ID_HEADER: cid}
        )

    return handler


def run(coro):
    return asyncio.run(coro)


async def authed_client(fake: FakeTarget, role: str = "physician", **cfg) -> TargetClient:
    client = TargetClient(config(**cfg), transport=httpx.MockTransport(fake))
    await client.authenticate(role)
    return client


# --------------------------------------------------------------------- auth


def test_authenticate_uses_openemr_password_grant():
    fake = FakeTarget()

    async def go():
        client = await authed_client(fake, "nurse")
        await client.aclose()
        return client

    client = run(go())
    form = parse_qs(fake.requests[0].content.decode())
    assert form["grant_type"] == ["password"]
    assert form["user_role"] == ["users"]
    assert form["username"] == ["nurse"]
    assert form["client_id"] == ["cid"]
    assert "user/Observation.read" in form["scope"][0]
    assert client.role == "nurse"
    assert TOKEN not in repr(client)


def test_role_credentials_can_be_overridden(monkeypatch):
    monkeypatch.setenv("TARGET_RESIDENT_USERNAME", "dr_res")
    monkeypatch.setenv("TARGET_RESIDENT_PASSWORD", "pw")
    assert config().credentials_for("resident") == ("dr_res", "pw")
    assert config().credentials_for("physician") == ("physician", "physician")


def test_authenticate_rejects_unknown_role():
    with pytest.raises(ValueError):
        run(TargetClient(config(), transport=httpx.MockTransport(FakeTarget())).authenticate("admin"))


def test_authenticate_failure_surfaces_oauth_error_without_secrets():
    def refuse(request):
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "bad credentials"}
        )

    client = TargetClient(config(), transport=httpx.MockTransport(refuse))
    with pytest.raises(TargetAuthError) as info:
        run(client.authenticate("physician"))
    assert info.value.status_code == 400
    assert "invalid_grant" in str(info.value)
    assert "csecret" not in str(info.value)


def test_authenticate_without_client_config_fails_clearly():
    client = TargetClient(
        config(client_id=None, client_secret=None), transport=httpx.MockTransport(FakeTarget())
    )
    with pytest.raises(TargetAuthError, match="TARGET_OAUTH_CLIENT_ID"):
        run(client.authenticate("physician"))


def test_calls_before_authenticate_are_refused():
    client = TargetClient(config(), transport=httpx.MockTransport(FakeTarget()))
    with pytest.raises(RuntimeError, match="authenticate"):
        run(client.pre_visit_brief(PATIENT))


def test_expired_token_is_refreshed_before_the_call():
    fake = FakeTarget()
    fake.expires_in = 1  # inside the refresh skew: stale at once
    fake.on("POST", "/pre-visit-brief", echo(200, lambda r, c: {"brief": "ok", "session_id": "s"}))

    async def go():
        client = await authed_client(fake)
        await client.pre_visit_brief(PATIENT)
        await client.aclose()

    run(go())
    assert fake.token_calls == 2


# ------------------------------------------------------------ correlation


def test_every_call_mints_a_uuid_correlation_id_and_sends_it():
    fake = FakeTarget()
    fake.on("POST", "/pre-visit-brief", echo(200, lambda r, c: {"brief": "b", "session_id": "s"}))

    async def go():
        client = await authed_client(fake)
        a = await client.pre_visit_brief(PATIENT)
        b = await client.pre_visit_brief(PATIENT)
        await client.aclose()
        return a, b

    a, b = run(go())
    sent = [r.headers[CORRELATION_ID_HEADER] for r in fake.agent_requests()]
    assert [a["correlation_id"], b["correlation_id"]] == sent
    assert len(set(sent)) == 2
    for cid in sent:
        assert str(uuid.UUID(cid)) == cid  # /w2/ask 500s on a non-UUID id


def test_caller_supplied_correlation_id_is_propagated():
    fake = FakeTarget()
    fake.on("POST", "/pre-visit-brief", echo(200, lambda r, c: {"brief": "b", "session_id": "s"}))

    async def go():
        client = await authed_client(fake)
        result = await client.pre_visit_brief(PATIENT, correlation_id="run-corr-1")
        await client.aclose()
        return result

    result = run(go())
    assert fake.agent_requests()[0].headers[CORRELATION_ID_HEADER] == "run-corr-1"
    assert result["correlation_id"] == "run-corr-1"


def test_envelope_reports_the_id_the_target_actually_used():
    fake = FakeTarget()

    def replaced(request):  # the target swaps a non-identifier id for a fresh UUID
        return httpx.Response(
            200, json={"brief": "b", "session_id": "s"}, headers={CORRELATION_ID_HEADER: "server-id"}
        )

    fake.on("POST", "/pre-visit-brief", replaced)

    async def go():
        client = await authed_client(fake)
        result = await client.pre_visit_brief(PATIENT, correlation_id="x")
        await client.aclose()
        return result

    result = run(go())
    assert result["correlation_id"] == "server-id"
    assert result["correlation_id_sent"] == "x"


# -------------------------------------------------------------- endpoints


def test_pre_visit_brief_request_and_envelope():
    fake = FakeTarget()
    fake.on(
        "POST",
        "/pre-visit-brief",
        echo(200, lambda r, c: {"brief": "BRIEF", "session_id": "sess-1234", "correlation_id": c}),
    )

    async def go():
        client = await authed_client(fake)
        result = await client.pre_visit_brief(PATIENT, session_id="sess-1234")
        await client.aclose()
        return result

    result = run(go())
    request = fake.agent_requests()[0]
    assert request.url == httpx.URL(f"{BASE}/pre-visit-brief")
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(request.content) == {"patient_id": PATIENT, "session_id": "sess-1234"}
    assert result["status_code"] == 200 and result["ok"]
    assert result["text"] == "BRIEF"
    assert result["conversation_id"] == "sess-1234"
    assert result["role"] == "physician"
    assert TOKEN not in json.dumps(result)


def test_chat_sends_only_the_last_user_turn_and_keeps_the_session():
    fake = FakeTarget()
    fake.on(
        "POST",
        "/pre-visit-brief/conversation",
        echo(200, lambda r, c: {"answer": "ANS", "turn_status": "answered", "correlation_id": c}),
    )
    messages = [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "reply"},
        {"role": "user", "content": [{"type": "text", "text": "second"}]},
    ]

    async def go():
        client = await authed_client(fake)
        first = await client.chat(messages)
        second = await client.chat(
            [{"role": "user", "content": "third"}], conversation_id=first["conversation_id"]
        )
        await client.aclose()
        return first, second

    first, second = run(go())
    bodies = [json.loads(r.content) for r in fake.agent_requests()]
    assert bodies[0] == {
        "patient_id": PATIENT,
        "session_id": first["conversation_id"],
        "question": "second",
    }
    assert bodies[1]["session_id"] == first["conversation_id"]
    assert second["conversation_id"] == first["conversation_id"]
    assert first["text"] == "ANS"


def test_chat_with_documents_routes_to_w2_ask():
    fake = FakeTarget()
    fake.on("POST", "/w2/ask", echo(200, lambda r, c: {"status": "answered", "message": "MSG"}))

    async def go():
        client = await authed_client(fake)
        result = await client.chat(
            [{"role": "user", "content": "what does the lab say?"}],
            conversation_id="sess-abcdef",
            document_ids=["doc1"],
        )
        await client.aclose()
        return result

    result = run(go())
    request = fake.agent_requests()[0]
    assert request.url.path == "/w2/ask"
    assert json.loads(request.content)["document_ids"] == ["doc1"]
    assert result["text"] == "MSG"


def test_chat_requires_a_user_message_and_a_patient():
    client = TargetClient(config(default_patient_id=None), transport=httpx.MockTransport(FakeTarget()))
    with pytest.raises(ValueError, match="user"):
        run(client.chat([{"role": "assistant", "content": "x"}]))
    with pytest.raises(ValueError, match="patient_id"):
        run(client.chat([{"role": "user", "content": "x"}]))


def test_upload_sends_raw_bytes_with_query_params(tmp_path):
    pdf = tmp_path / "lab.pdf"
    pdf.write_bytes(b"%PDF-1.4 sample")
    fake = FakeTarget()
    fake.on(
        "POST",
        "/documents",
        echo(200, lambda r, c: {"document_id": "d1", "kind": "lab_pdf", "status": "pending"}),
    )

    async def go():
        client = await authed_client(fake)
        result = await client.upload(PATIENT, str(pdf), "lab_pdf")
        await client.aclose()
        return result

    result = run(go())
    request = fake.agent_requests()[0]
    assert request.content == b"%PDF-1.4 sample"
    assert request.headers["Content-Type"] == "application/pdf"
    assert dict(request.url.params) == {"kind": "lab_pdf", "patient_id": PATIENT}
    assert result["document_id"] == "d1"
    assert result["extraction_status"] == "pending"


def test_extraction_status_polls_the_document():
    fake = FakeTarget()
    fake.on(
        "GET",
        "/documents/d1/extraction",
        echo(200, lambda r, c: {"document_id": "d1", "status": "complete"}),
    )

    async def go():
        client = await authed_client(fake)
        result = await client.extraction_status(PATIENT, "d1")
        await client.aclose()
        return result

    result = run(go())
    assert dict(fake.agent_requests()[0].url.params) == {"patient_id": PATIENT}
    assert result["extraction_status"] == "complete"


def test_error_statuses_are_returned_not_raised():
    fake = FakeTarget()
    fake.on(
        "POST",
        "/pre-visit-brief",
        echo(
            404,
            lambda r, c: {"error": "patient_not_found", "message": "m", "correlation_id": c},
        ),
    )

    async def go():
        client = await authed_client(fake)
        result = await client.pre_visit_brief(PATIENT)
        await client.aclose()
        return result

    result = run(go())
    assert result["status_code"] == 404
    assert result["ok"] is False
    assert result["body"]["error"] == "patient_not_found"


def test_non_json_body_is_kept_raw():
    fake = FakeTarget()
    fake.on("POST", "/pre-visit-brief", lambda r: httpx.Response(502, text="Bad Gateway"))

    async def go():
        client = await authed_client(fake)
        result = await client.pre_visit_brief(PATIENT)
        await client.aclose()
        return result

    assert run(go())["body"] == {"raw": "Bad Gateway"}


def test_transport_failure_raises_with_correlation_id():
    fake = FakeTarget()

    def boom(request):
        raise httpx.ConnectError("refused", request=request)

    fake.on("POST", "/pre-visit-brief", boom)

    async def go():
        client = await authed_client(fake)
        try:
            await client.pre_visit_brief(PATIENT, correlation_id="corr-lost")
        finally:
            await client.aclose()

    with pytest.raises(TargetTransportError) as info:
        run(go())
    assert info.value.correlation_id == "corr-lost"
    assert info.value.endpoint == "POST /pre-visit-brief"


def test_concurrent_users_share_one_http_client():
    fake = FakeTarget()
    fake.on("POST", "/pre-visit-brief", echo(200, lambda r, c: {"brief": "b", "session_id": "s"}))

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake)) as http:
            clients = [TargetClient(config(), http=http) for _ in range(50)]
            await asyncio.gather(*(c.authenticate("physician") for c in clients))
            results = await asyncio.gather(*(c.pre_visit_brief(PATIENT) for c in clients))
            for c in clients:
                await c.aclose()  # must not close the shared client
            assert not http.is_closed
            return results

    results = run(go())
    assert len({r["correlation_id"] for r in results}) == 50
    assert all(r["status_code"] == 200 for r in results)


# ------------------------------------------------------------ AuditReader


def audit_config(**overrides) -> AuditConfig:
    values = dict(
        host="https://audit.test",
        public_key="pk",
        secret_key="sk",
        ingest_wait_seconds=0.05,
        poll_interval_seconds=0.01,
    )
    values.update(overrides)
    return AuditConfig(**values)


TRACE = {
    "id": "t",
    "name": "pre_visit_brief",
    "sessionId": "hmac",
    "tags": ["use_case:pre_visit_brief", "retrieved:Condition"],
    "scores": [{"name": "verification_passed", "value": 1.0, "dataType": "BOOLEAN", "extra": 1}],
    "observations": [
        {
            "id": "o2",
            "name": "tool_call_event",
            "startTime": "2026-09-28T10:00:02Z",
            "metadata": {"event_type": "tool_call_event", "tool": "llm", "outcome": "ok"},
        },
        {
            "id": "o1",
            "name": "tool_call_event",
            "startTime": "2026-09-28T10:00:01Z",
            "metadata": {
                "event_type": "tool_call_event",
                "tool": "fhir_read",
                "target": "Condition",
                "outcome": "ok",
                "status_code": 200,
            },
        },
        {
            "id": "o3",
            "name": "http_request_event",
            "startTime": "2026-09-28T10:00:03Z",
            "metadata": {"event_type": "http_request_event", "status_code": 200},
        },
    ],
}


def test_trace_id_matches_langfuse_seeded_id():
    assert trace_id_for("abc") == hashlib.sha256(b"abc").digest()[:16].hex()
    assert len(trace_id_for("abc")) == 32


def test_tool_calls_reads_the_correlated_trace_and_filters():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=TRACE)

    async def go():
        async with AuditReader(audit_config(), transport=httpx.MockTransport(handler)) as reader:
            return await reader.tool_calls("corr-1")

    calls = run(go())
    assert seen[0].method == "GET"
    assert seen[0].url.path == f"/api/public/traces/{trace_id_for('corr-1')}"
    assert seen[0].headers["Authorization"] == httpx.BasicAuth("pk", "sk")._auth_header
    assert [c["observation_id"] for c in calls] == ["o1", "o2"]  # oldest first, no http event
    assert calls[0]["tool"] == "fhir_read" and calls[0]["target"] == "Condition"


def test_response_trace_includes_all_events_tags_and_scores():
    async def go():
        reader = AuditReader(
            audit_config(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json=TRACE))
        )
        try:
            return await reader.response_trace("corr-1")
        finally:
            await reader.aclose()

    trace = run(go())
    assert trace["found"] is True
    assert len(trace["events"]) == 3
    assert "retrieved:Condition" in trace["tags"]
    assert trace["scores"] == [
        {"name": "verification_passed", "value": 1.0, "dataType": "BOOLEAN", "observationId": None}
    ]


def test_audit_waits_for_ingestion_then_reads():
    responses = [httpx.Response(404), httpx.Response(404), httpx.Response(200, json=TRACE)]

    async def go():
        reader = AuditReader(
            audit_config(ingest_wait_seconds=5),
            transport=httpx.MockTransport(lambda r: responses.pop(0)),
        )
        try:
            return await reader.tool_calls("corr-1")
        finally:
            await reader.aclose()

    assert len(run(go())) == 2
    assert responses == []


def test_audit_missing_trace_is_empty_not_an_error():
    async def go():
        reader = AuditReader(
            audit_config(), transport=httpx.MockTransport(lambda r: httpx.Response(404))
        )
        try:
            return await reader.tool_calls("c"), await reader.response_trace("c")
        finally:
            await reader.aclose()

    calls, trace = run(go())
    assert calls == []
    assert trace["found"] is False and trace["trace_id"] == trace_id_for("c")


def test_audit_auth_failure_raises():
    async def go():
        reader = AuditReader(
            audit_config(), transport=httpx.MockTransport(lambda r: httpx.Response(401))
        )
        try:
            await reader.tool_calls("c")
        finally:
            await reader.aclose()

    with pytest.raises(AuditUnavailable, match="401"):
        run(go())


def test_audit_requires_its_own_credential():
    with pytest.raises(AuditUnavailable):
        AuditReader(audit_config(public_key=None))
    assert "sk" not in repr(AuditReader(audit_config()))


# --------------------------------------------------------- trust boundary


def test_target_client_import_graph_never_reaches_audit():
    """The Red Team imports aep.target / aep.target.client; neither may pull in aep.target.audit."""
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import aep.target, aep.target.client; "
        "assert 'aep.target.audit' not in sys.modules, 'aep.target.audit leaked'"
    )
    subprocess.run(
        [sys.executable, "-c", code, str(REPO)], check=True
    )


def test_audit_module_carries_the_judge_only_banner():
    first = (REPO / "aep" / "target" / "audit.py").read_text().splitlines()[0]
    assert "JUDGE-ONLY" in first and "Red Team must never import this" in first
