# Target API contract — Clinical Co-Pilot

The public HTTP surface of the system under test, transcribed from reading the
target's W1/W2 repository (`agent/app/models/api.py`, `agent/app/api/*.py`,
`agent/app/middleware/correlation.py`, `agent/deploy/Caddyfile`,
`agent/scripts/smoke_test_fhir.py`) at `main@f0040f8`, 2026-09-28. No target
source is vendored here; this file is the only copy of the contract this repo
holds. Implemented by `platform/target/client.py` (attacker view) and
`platform/target/audit.py` (judge-only view).

Anything marked **UNVERIFIED** was read from source and has not been observed
against the live deployment yet. `scripts/smoke_target.py` is the check.

---

## 1. Hosts

| What | URL | TLS |
|---|---|---|
| Agent API (Caddy → FastAPI) | `https://64.177.42.210:8443` | Caddy local CA (`tls internal`), not publicly trusted. Client runs `verify=False` until `TARGET_CA_BUNDLE` points at the exported root. |
| OpenEMR (OAuth2 + FHIR) | `https://64.177.42.210:9300` | Self-signed. |
| Langfuse (target's trace export) | `https://64-177-51-119.sslip.io` | Let's Encrypt, verified. |

Caddy proxies only these path prefixes to the agent: `/pre-visit-brief*`,
`/documents*`, `/w2/ask*`, `/health*`, `/ready*`, `/docs*`, `/openapi.json`.
Everything else is the static UI. Request-body caps at the proxy: **16 KB**
for everything except `/documents*`, which is **25 MiB**.

## 2. Authentication

Every agent route except `/health`, `/ready`, `/docs`, `/openapi.json` takes
the clinician's own OpenEMR access token:

```
Authorization: Bearer <JWT>
```

The agent holds no credential of its own and forwards the token to OpenEMR's
FHIR API unchanged; OpenEMR decides what it may read.

**Getting a token — OAuth2 password grant, not client credentials.** The
deployed OpenEMR advertises `grant_types_supported: [authorization_code,
password, refresh_token]` — no `client_credentials`. Every route also needs a
token bound to a real user (its `sub` becomes part of the session key), which
client credentials cannot carry.

```
POST https://64.177.42.210:9300/oauth2/default/token
Content-Type: application/x-www-form-urlencoded

grant_type=password
client_id=<password-grant-enabled client>
client_secret=<secret>
username=<openemr user>
password=<password>
user_role=users            # OpenEMR-specific, REQUIRED for staff logins ("patient" = portal)
scope=openid user/Patient.read user/Condition.read user/MedicationRequest.read
      user/AllergyIntolerance.read user/Encounter.read user/Observation.read
```

→ `200 {access_token, token_type: "Bearer", expires_in: 3600, scope, id_token?}`
→ `4xx {error, error_description, hint?}` (e.g. `invalid_grant`, `invalid_client`)

Notes:
- The client must be provisioned by an operator: clients registered through
  `/oauth2/default/registration` are created disabled and authorization-code
  only; `grant_types` must be edited to include `password` in the database.
  The chart-embed client the OpenEMR module uses is authorization-code only
  and cannot be used here.
- The response's `scope` field can understate what the JWT actually carries
  (target finding F-09). Treat it as evidence only.
- Token lifetime is 1 h; the client refreshes 60 s before expiry by re-running
  the grant.
- **Seeded users:** `physician`/`physician` is documented. `nurse` and
  `resident` are assumed to follow the same username-as-password pattern —
  **UNVERIFIED**; override with `TARGET_<ROLE>_USERNAME` / `_PASSWORD`.

**How the agent reads the token** (before any FHIR call): it must be a
three-part JWT whose payload has a `sub` matching `^[A-Za-z0-9._-]{1,128}$`.
The signature is *not* checked by the agent — the first FHIR read under the
token is what proves it. `/documents` additionally reads `aud` (client id) and
`scopes` from the unverified payload (§8).

## 3. Cross-cutting behaviour

**Correlation id.** Request header `X-Correlation-ID`. If it matches
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` the agent adopts it; otherwise it
silently substitutes a fresh UUID4. The id actually used is echoed in the
`X-Correlation-ID` response header and in every body's `correlation_id`. It
is bound to every log line, tool-call event and Langfuse trace for the
request (§7).

> `/w2/ask` is stricter: its response and routing records require the id to
> be a UUID (`8-4-4-4-12` hex). A header that passes the middleware's rule but
> is not a UUID (e.g. `corr-123`) should fail response validation → **500
> internal_error**. **UNVERIFIED** live. TargetClient therefore always mints
> bare UUID4s.

**Strict request bodies.** Every JSON body forbids unknown fields and does no
type coercion; a mismatch is `422 invalid_request`. Messages list field
locations and rule names only, never submitted values.

**Error body** (all non-2xx the agent itself produces):

```json
{"error": "<ErrorCode>", "message": "<safe fixed text>", "correlation_id": "<id>"}
```

`ErrorCode` ∈ `missing_bearer_token`, `malformed_bearer_token`,
`fhir_token_rejected`, `invalid_request`, `patient_not_found`,
`fhir_unavailable`, `brief_generation_failed`, `follow_up_generation_failed`,
`internal_error`, `insufficient_scope`, `rate_limited`, `extraction_capacity`.
401s carry `WWW-Authenticate: Bearer` (`error="invalid_token"` for a
malformed or rejected token). A body Caddy rejects (over the size cap) or a
502 from Caddy itself is not in this shape — the client keeps non-JSON bodies
as `{"raw": "<text>"}`.

**Identifiers.**
- `patient_id`: FHIR Patient id, lowercase UUID only
  (`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).
  Known-good patient on the current host: `a2c36e54-af42-4c38-b86e-ade616ed5494`.
- `session_id`: `^[A-Za-z0-9-]{8,64}$`.
- `patient_session_key` = `<token sub>:<patient_id>:<session_id>`, computed
  server-side; the caller cannot supply it.

## 4. `POST /pre-visit-brief`

Request:
```json
{"patient_id": "<uuid>", "session_id": "<optional; generated if omitted>"}
```

200 response:
```json
{
  "brief": "physician-facing text",
  "patient_id": "...", "session_id": "...", "patient_session_key": "...",
  "correlation_id": "...",
  "verification": {"claims": 0, "verified": 0, "unverified": 0},
  "claims": [{"resource_type": "Condition|MedicationRequest|AllergyIntolerance|...",
              "source_id": "...", "field": "...", "value": "str|number|null",
              "verified": true, "unverified_reason": null}],
  "sections": [{"resource_type": "...", "retrieved": 0, "in_brief": 0}],
  "timing": {"retrieve_seconds": 0.0, "draft_seconds": 0.0, "verify_seconds": 0.0,
             "render_seconds": 0.0, "total_seconds": 0.0}
}
```

Errors: 401 `missing_bearer_token` / `malformed_bearer_token` (no FHIR call
made) · 401 `fhir_token_rejected` (OpenEMR said 401 — expired, revoked *or*
missing scope, indistinguishable) · 404 `patient_not_found` · 422 · 502
`fhir_unavailable` · 502 `brief_generation_failed` (LLM failed; no partial
brief) · 500 `internal_error`.

Scopes the brief needs: `user/Patient.read`, `user/Condition.read`,
`user/MedicationRequest.read`, `user/AllergyIntolerance.read`.

## 5. Multi-turn chat — `POST /pre-visit-brief/conversation`

The Week 1 follow-up conversation. **The request carries no history**: state
is kept server-side as the verified claims of earlier turns, keyed by
(token `sub`, `session_id`) and bound to one patient. A turn naming a
different patient in the same session discards the stored conversation first
(`transition: reset_patient_changed`). Idle state expires (`reset_expired`).
Every turn re-reads the chart under the caller's token.

Request:
```json
{"patient_id": "<uuid>", "session_id": "<required>", "question": "1..500 chars, not blank"}
```

200 response (a refusal is a 200, not an error):
```json
{
  "answer": "text; failed claims marked UNVERIFIED",
  "turn_status": "answered|partially_answered|not_in_record|refused_out_of_scope|refused_unverifiable",
  "refusals": ["vitals|clinical_notes|procedures|immunizations|imaging|family_social_history|scheduling|demographics_billing|other_patients|trend_or_comparison|clinical_judgment|change_detection"],
  "gaps": ["lab_results|visit_history|other_chart_data|not_stated_in_record|interpretation|unresolved_reference"],
  "question": "...", "patient_id": "...", "session_id": "...",
  "patient_session_key": "...", "correlation_id": "...",
  "conversation": {"turn": 1, "transition": "started|continued|reset_patient_changed|reset_expired",
                   "context_turns": 0, "context_claims": 0, "state_saved": true,
                   "expires_in_seconds": 0},
  "retrieval": [{"resource_type": "...", "rule": "base_set|question_rule|context_carry",
                 "retrieved": 0, "considered": 0}],
  "verification": {"claims": 0, "verified": 0, "unverified": 0},
  "claims": [{"...ClaimOutcome fields (§4)...": "", "text": "rendered line"}],
  "sections": [...], "timing": {...}
}
```

Refusals are decided by rule before retrieval; no model call is made for them.
Errors: as §4, with `follow_up_generation_failed` instead of
`brief_generation_failed`. A failed turn stores nothing. Lab/visit questions
additionally need `user/Observation.read`, `user/Encounter.read`.

`POST /pre-visit-brief/conversation/end` — `{"patient_id", "session_id"}` →
`{"ended": bool, "session_id", "correlation_id"}`. Does a Patient read first
to prove the token before touching state.

(Also present, single-turn: `POST /pre-visit-brief/follow-up` with the same
request shape; not proxied through a separate Caddy rule but covered by
`/pre-visit-brief*`.)

## 6. Week 2 chat — `POST /w2/ask`

Supervisor turn over the chart, uploaded documents and a guideline corpus.
Shares its session with §5 (one session, one open chart). The only chat route
that can reference uploaded documents.

Request:
```json
{"patient_id": "<uuid>", "session_id": "<8-64>", "question": "1..500",
 "document_ids": ["<id from POST /documents>", "... at most 4"]}
```

200 response — every clinical outcome, including refusals and failed tools:
```json
{
  "status": "answered|partially_answered|not_in_record|refused",
  "reason_code": "<RoutingReasonCode, e.g. chart_only_question, guideline_question, out_of_scope_resource, unverifiable_judgment, document_still_processing, document_not_found, document_identity_mismatch, extraction_failed, ...>",
  "message": "clinician-facing text",
  "answer_view": {...} | null,
  "unverified": [...], "critical_values": [...], "discrepancies": [...],
  "limitations": [...], "gaps": [...],
  "routing": [{"route": "...", "reason_code": "...", "correlation_id": "<uuid>", ...}],
  "handoffs": [...],
  "conversation": {"turn": 1, "transition": "...", "context_turns": 0, "state_saved": true},
  "patient_session_key": "...", "correlation_id": "<uuid>",
  "node_ms": {"<node>": 0}, "total_ms": 0
}
```

HTTP errors only for non-clinical failures: 401 (three codes as §4), 404
`patient_not_found`, 422, 502 `fhir_unavailable`, 500 `internal_error`.

## 7. Audit trail (judge-only)

There is **no audit HTTP route on the agent.** The grey-box record is the
target's Langfuse export:

- One trace per correlation id, `trace_id = sha256(correlation_id)[:16].hex()`
  (Langfuse SDK `create_trace_id(seed=...)`).
- Each target event is one root observation: `name` = event type,
  `metadata` = the event's fields plus `event_type`, `correlation_id`,
  `use_case`, `patient_session_key` (HMAC'd — the session id, not the raw key).
- Event types of interest: `tool_call_event` (`tool` ∈ `fhir_read|llm|vision|
  guideline_retriever|lab_writeback`, `target`, `outcome`, `latency_ms`,
  `attempts`, `retries`, `error_type`, `status_code`), `retrieval_event`,
  `evidence_retrieval_event` (W2 guideline search),
  `authorization_check_event` (requested vs held scope, outcome; an accepted
  out-of-scope request is logged at level ERROR), `llm_usage_event` (a
  GENERATION with model + token counts), `claim_verified_event`,
  `http_request_event`.
- Trace tags: `use_case:<v>`, `retrieved:<ResourceType>`, `tool:<t>`,
  `route:<template>`, `pipeline:<p>`. Scores: `verification_passed`,
  `unverified_claim_disclosed`, `out_of_scope_request_rejected`,
  `response_latency_seconds`.
- **Never** exported: prompts, completions, answer text, chart values, the
  question. Answer text comes from the attacker-side transcript.
- Read API: `GET /api/public/traces/{trace_id}` with HTTP Basic
  (`public_key:secret_key`), which embeds `observations` and `scores`.
  Ingestion is asynchronous — expect 404 for a few seconds after the response.
- Requests rejected before a turn starts (401, 422) produce only an
  `http_request_event`.

## 8. Document upload — `POST /documents`

```
POST /documents?kind=<lab_pdf|intake_form>&patient_id=<uuid>
Authorization: Bearer <JWT>
Content-Type: application/pdf          (application/x-pdf also accepted)
<raw PDF bytes — NOT multipart>
```

Check order, all before the body is read:
1. Token shape (401), then its unverified `scopes` claim must contain
   `user/Patient.read`, `user/MedicationRequest.read`,
   `user/AllergyIntolerance.read` (403 `insufficient_scope`), then OpenEMR
   must accept it for a Patient read of `patient_id` (401 / 404 / 502).
2. Sliding-window rate limits per OAuth client (`aud`), per user (`sub`), per
   patient → 429 `rate_limited` + `Retry-After`. Counted once step 1 passes.
3. `Content-Type` (415) and declared `Content-Length` > 25 MiB (413).
4. A free extraction slot, else 503 `extraction_capacity` + `Retry-After`
   (no queue).

Then the body: empty → 400; > 25 MiB → 413; not starting `%PDF-` or
unreadable → 415. Error bodies for 400/409/413/415 and the extraction 404 use
`error: invalid_request`.

200 response:
```json
{"document_id": "<SHA3-512-derived id>", "kind": "lab_pdf|intake_form",
 "status": "pending|in_progress|complete|failed", "byte_length": 0,
 "correlation_id": "...", "identity_check": "mismatch|confirmed|not_confirmed|null",
 "write_back": {...} | null}
```

- Extraction runs in the background from upload time; the response returns
  immediately (usually `pending`).
- `document_id` is content-addressed: the same bytes to the same patient is a
  duplicate (200, current status, no new work); the same bytes to a
  **different** patient is **409**.
- **Side effect:** a completed `lab_pdf` whose identity check confirms the
  patient has its located, coded rows **written back into the chart** under
  the uploader's token, without review. `intake_form` is never written back.
  Smoke and non-write-back cases should upload `intake_form`.
- Filename is never logged or stored.

`GET /documents/{document_id}/extraction?patient_id=<uuid>` → same auth as
step 1 (not rate-limited) →
`{document_id, kind, status, extraction_id, failure_reason, correlation_id,
identity_check, write_back}`. Unknown id and another patient's id are the
same **404**.

## 9. Unauthenticated routes

| Route | Response |
|---|---|
| `GET /health` | `{"status": "alive"}` |
| `GET /ready` | `{"status": "ready|degraded|not_ready", "checks": {name: {status, required, detail}}}`; 503 when `not_ready` |
| `GET /openapi.json` | FastAPI schema; `info.version` is the API version (`0.3.0` at time of writing) |

There is **no `/version` route** and no commit SHA exposed.
`AttackRun.target_version` currently records `openapi.json` `info.version`
(TODO in `TargetClient.target_version`).
