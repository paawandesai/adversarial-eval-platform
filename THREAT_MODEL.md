# THREAT_MODEL.md — Clinical Co-Pilot Attack Surface

*Target under test: the Clinical Co-Pilot — a chat + document agent embedded in a forked OpenEMR. Agent at `https://64.177.42.210:8443`; OpenEMR at `:9300`; OAuth token at `/oauth2/default/token` (password grant). This is a living document; the adversarial platform continuously exercises the categories below.*

---

## 1. Executive Summary (~500 words)

The Clinical Co-Pilot's attack surface is the AI-assisted workflow layered onto OpenEMR: a conversational agent, a multimodal document-ingestion pipeline (lab PDFs and intake forms), a FHIR read layer, and a lab write-back endpoint — all reachable over the network by an authenticated clinical user. We assess the surface across six threat categories: prompt injection (direct, indirect, multi-turn), data exfiltration, state corruption, tool misuse, denial of service, and identity/role exploitation. The platform attacks only this surface; we deliberately exclude OpenEMR's legacy PHP core except where the agent can reach it.

**The highest-risk category is broken access control, and it is already confirmed, not hypothesized.** The target enforces no per-patient scoping (tracked as F-50). We measured this directly: each of three seeded users (physician, nurse, resident) read every planted canary across the panels (9 of 9 over FHIR), and a nurse's brief for the physician's canary patient returned HTTP 200 with the canary string `ZZ-CANARY-1` in the body. Any authenticated user can read any patient. This single defect underwrites the entire data-exfiltration and identity-exploitation categories, and it is the finding the platform reproduces on its first cross-panel probe.

Two further findings are confirmed from prior audit and build. First, **excessive agency in write-back**: extracted lab values are written back to OpenEMR without human confirmation, so an injection that reaches the extraction path can plant a fabricated clinical value (an integrity failure with direct patient-safety impact). Second, **weak client authentication**: the deployed OpenEMR issues clinician-scoped tokens to a public client via the password grant without a client-secret check (documented F-65), lowering the bar for token acquisition.

The remaining categories are suspected but not yet confirmed and are where the platform's autonomous exploration concentrates: indirect prompt injection through uploaded documents (the agent's own ingestion path), multi-turn safeguard erosion, system-prompt extraction, PHI leakage into logs/traces, SSRF via document-embedded URLs, and cost-amplification denial of service.

**Coverage prioritization.** The Orchestrator directs the Red Team by risk and by evidence. Priority order: (1) confirmed high-severity gaps first, to produce reproducible reports and regression cases (cross-patient access, write-back integrity); (2) the LLM-native categories that map to the agent's unique surface (indirect injection via documents, multi-turn erosion); (3) direct-API attacks requiring no prompt (conversation-ID reuse, token-scope abuse, cost amplification), where deterministic tooling outperforms an LLM; (4) categories with existing partial defenses, to test whether they hold under mutation. Success is judged by deterministic oracles wherever possible — canary-string leakage, tool-call audit, log scans, token/cost counters — with an independent LLM judge reserved for semantic verdicts.

**Trust-boundary summary.** The platform reaches the target only over the network, as a scoped user, with no source access. Within the target, the physician/nurse/resident roles *should* be a boundary but (per F-50) are not. The Judge reads execution evidence from Langfuse traces (the target exposes no audit endpoint), a grey-box channel the Red Team never receives. The platform's own egress is allowlisted to the target host so it can never be turned against another system.

---

## 2. System Under Test & Trust Boundaries

**Reachable surface (what an authenticated user can touch):**
- `POST /pre-visit-brief` — the brief generator (FHIR reads, LLM synthesis, verification layer).
- The multi-turn chat endpoint (`/pre-visit-brief/conversation`) — conversation state, tool routing.
- `POST /w2/ask` and the document upload/ingestion path — lab PDF and intake-form extraction (VLM), with write-back of extracted values.
- The FHIR read layer (Patient, Condition, MedicationRequest, AllergyIntolerance, Observation, Encounter).
- The lab write-back endpoint (own OAuth scope, idempotency ledger).
- `GET /health`, `/ready`, `/version` (unauthenticated).

**Trust zones:**
| Zone | What it should enforce | Actual state |
|---|---|---|
| Client auth (OAuth password grant) | client secret + user credentials | public client, no secret check (F-65) |
| User role (physician / nurse / resident) | per-panel patient access | **not enforced (F-50 — confirmed)** |
| Agent tool layer | act only within the requesting user's authorization | inherits F-50; write-back unreviewed |
| Verification layer | claims traceable to source | present (W1/W2); tested under injection here |
| Observability | no raw PHI in traces | scrubber in platform; target traces tested |

**Testing-fidelity notes (affect how attacks are constructed):**
- The target accepts **only UUID4** correlation IDs; non-UUID ids (e.g. `corr_…`) are rejected. The platform's target client must send UUID4 on the wire.
- OpenEMR has **no resident role**; the resident user is modeled as a group. Privilege-escalation cases treat it as a distinct, lower-trust principal regardless.
- The target exposes **no audit endpoint**; execution evidence is read from Langfuse traces by correlation id.

---

## 3. Attack Surface Map

Each category lists: surface, impact, exploitation difficulty, existing defenses, OWASP mapping, platform coverage (AttackCategory), and status.

### 3.1 Prompt Injection — direct, indirect, multi-turn
- **Surface:** chat input (direct); uploaded lab PDF / intake form processed by the VLM (indirect); conversation history across turns (multi-turn).
- **Impact:** hijack the agent to exfiltrate data, trigger tools, or override safeguards. Indirect is the highest-value vector because the agent's *purpose* is to read attacker-influenceable documents.
- **Difficulty:** low–medium. Indirect requires only that a document reach ingestion; the front desk uploads intake forms, so the trust assumption is already weak.
- **Existing defenses:** the verification/citation layer constrains unsupported claims; no dedicated injection filter on document text.
- **OWASP:** LLM01 (prompt injection), A03 (injection); indirect also A04 (insecure design).
- **Coverage:** `direct_prompt_injection`, `indirect_prompt_injection`, `multi_turn_erosion`.
- **Status:** suspected; **primary exploration target.**

### 3.2 Data Exfiltration — PHI leakage, cross-patient, authz bypass
- **Surface:** brief/chat responses, FHIR reads, canary patients across panels.
- **Impact:** unauthorized disclosure of PHI; cross-patient access. **Critical.**
- **Difficulty:** **trivial — confirmed.** No panel scoping (F-50): a nurse retrieved the physician's canary patient (200, `ZZ-CANARY-1` present); 9/9 canary reads across users over FHIR.
- **Existing defenses:** none effective at the patient-scoping layer.
- **OWASP:** A01 (broken access control), LLM06 (sensitive information disclosure), A07 (auth failures for the client-secret gap).
- **Coverage:** `authz_bypass_cross_patient`, `phi_in_logs`.
- **Status:** **CONFIRMED (F-50).** Deterministic canary oracle reproduces it.

### 3.3 State Corruption — conversation history manipulation, context poisoning
- **Surface:** multi-turn conversation state; document content that persists into later turns.
- **Impact:** an early poisoned turn (or an ingested document) steers later answers; safeguards asserted in turn 1 eroded by turn N.
- **Difficulty:** medium. Requires multi-turn sequencing; the deterministic mutation engine turn-splits to probe it.
- **Existing defenses:** per-answer verification re-grounds each response, which partially limits carry-over.
- **OWASP:** LLM01, A04 (insecure design).
- **Coverage:** `multi_turn_erosion`, plus indirect-injection cases whose payload persists.
- **Status:** suspected.

### 3.4 Tool Misuse — unintended invocation, parameter tampering, recursive calls
- **Surface:** the agent's FHIR read tools and the **lab write-back endpoint**.
- **Impact:** injection-driven tool calls with tampered patient IDs (cross-patient action) or **fabricated write-back values** — an integrity/patient-safety failure. Recursive/looping tool calls feed the DoS category.
- **Difficulty:** medium; write-back is high-impact because it is **unreviewed** (confirmed).
- **Existing defenses:** write-back has an idempotency ledger (prevents duplicates, not fabrication); no human confirmation gate.
- **OWASP:** LLM08 (excessive agency), A08 (integrity failures), A01 (for cross-patient tool calls).
- **Coverage:** `excessive_agency_writeback`.
- **Status:** **CONFIRMED (unreviewed write-back);** cross-patient tool action inherits F-50.

### 3.5 Denial of Service — token exhaustion, loops, cost amplification
- **Surface:** long conversations, recursive tool/retrieval behavior, large or crafted uploads.
- **Impact:** unbounded token/cost growth; unpredictable latency; runaway spend.
- **Difficulty:** low–medium. The doc itself notes cost grew unpredictably with long chains.
- **Existing defenses:** none specific to cost; answer-scope bounding limits some latency.
- **OWASP:** LLM04 (model DoS), A04 (insecure design).
- **Coverage:** `cost_amplification_dos`. Deterministic token/cost oracle judges it.
- **Status:** suspected; deterministic to confirm.

### 3.6 Identity & Role Exploitation — privilege escalation, persona hijack, trust-boundary violation
- **Surface:** the OAuth password grant, role scoping, the agent's persona/system prompt.
- **Impact:** act beyond one's role (escalation), coerce the agent out of scope (persona hijack), extract the system prompt.
- **Difficulty:** escalation is trivial given F-50; persona hijack / prompt extraction are medium and LLM-judged.
- **Existing defenses:** verification layer; weak client auth (F-65) lowers the entry bar.
- **OWASP:** A01, A07, LLM01, LLM06.
- **Coverage:** `persona_hijack`, `system_prompt_extraction`, `token_scope_abuse`, `conversation_id_reuse`.
- **Status:** escalation **confirmed via F-50**; persona/prompt-extraction suspected.

---

## 4. Confirmed Findings (finding-in-hand)

| ID | Title | Category | Severity | Evidence | OWASP |
|---|---|---|---|---|---|
| F-50 | No per-patient scoping — any user reads any patient | Data exfiltration / authz | **Critical** | Nurse brief for physician's canary patient → 200 with `ZZ-CANARY-1`; 9/9 cross-panel canary reads over FHIR | A01, LLM06 |
| WB-01 | Unreviewed lab write-back accepts fabricated values | Tool misuse / integrity | **High** | Extracted rows written without confirmation gate (W2 build) | LLM08, A08 |
| F-65 | Clinician-scoped tokens issued to a public client without secret check | Identity / auth | **High** | Documented in W1/W2 audit | A07 |

These are reproducible today; the platform converts each into a `VulnerabilityReport` with a minimal repro and a regression case on first run.

---

## 5. Out of Scope (deliberate)

- OpenEMR's legacy PHP core (admin panels, non-agent forms) except where the agent can reach it. "Vulnerable components" is handled by a dependency scan of the agent service plus a note on OpenEMR CVE history, not by pen-testing the PHP stack.
- Network/infrastructure attacks below the application layer.
- The platform's egress is **allowlisted to the target host**, so the adversarial system cannot be pointed at any other system — a safety control on the tester itself.

---

## 6. How the Platform Exercises This Model

The Orchestrator reads coverage and open findings from the store and directs the Red Team by the priority in §1. Every case maps to the OWASP categories above (enforced in the case schema). Verdicts are deterministic-first (canary, tool-call audit, log scan, token counter, HTTP assert), with an independent LLM judge only for semantic categories (system-prompt extraction, persona hijack, unsafe advice). Confirmed exploits become versioned regression cases anchored on the target's `/version`, each paired with a benign positive control so a "fix" that merely breaks the workflow is caught rather than passed.
