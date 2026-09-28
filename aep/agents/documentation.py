"""Documentation agent: turns a confirmed exploit (a FAIL verdict) into a reproducible VulnerabilityReport.

    doc = Documentation(store)                        # router is optional
    report = doc.document(verdict)                    # None unless verdict.verdict == FAIL
    doc.pending_reports()                             # critical/high reports waiting on a human
    doc.approve(report.vuln_id, reviewer="sec-lead")  # pending_human_review: True -> False
    doc.published_reports()                           # what downstream consumers may treat as published

Facts vs prose
--------------
Every FACT in a report is computed deterministically from the stored AttackCase, AttackRun and JudgeVerdict:
severity, category, owasp, repro_case_id, repro_steps, observed_behavior, expected_behavior and the
first/last seen versions. The router (any object with ``complete(prompt) -> result``, where the result is a
str, a dict with "text", or an object with ``.text``) may only draft the three PROSE fields: title,
clinical_impact and recommended_remediation. Each drafted field is checked against the evidence. If it names
an identifier the evidence does not contain (patient UUID, canary, snake_case tool name, endpoint path,
SHA-like hex, platform id, decimal value), that field falls back to the deterministic template. So the router
cannot put an exploit into a report that the evidence does not show. The check matches identifiers, not
meaning: it cannot catch a vague made-up claim written in plain words. That is why none of the fact fields
ever come from the router.

Before writing anything, ``document()`` also checks that the evidence holds together. The run must belong to
the verdict's case and correlation_id. The FAIL verdict must already be stored by the Judge. The verdict must
carry oracle evidence, or an LLM-judge rationale. A verdict made up by the caller is refused with
EvidenceError.

Data-quality gate (``check_quality``)
-------------------------------------
A new report is written only if all of these hold. Otherwise DataQualityError is raised and nothing is written:
  * vuln_id is non-empty and not already in the Store;
  * every required field is present and non-empty, and every repro step is a non-empty string;
  * repro_case_id resolves to a stored AttackCase;
  * no other report covers the same attack sequence.
"Same attack sequence" is ``attack_signature(case)``: a SHA-256 over the category, endpoint, acting role,
normalized turns (whitespace collapsed, casefolded, attachments included) and the oracle with its config.
The per-run caps budget_usd and budget_tokens are left out of the config. So a re-run of the same case, or a
mutation that turns out to be identical, matches the existing report. When a report already covers the
sequence, ``document()`` does not create a new one. It sets that report's last_seen_version to the run's
target_version. If that report was RESOLVED and the finding shows up at a version other than the one its fix
was validated against, its status becomes REGRESSED.

Human-approval gate
-------------------
Reports with severity critical or high are stored with status OPEN, and a review record in a sidecar ledger
with pending_human_review=True. The VulnerabilityReport contract has no field for this, and this agent does
not own the Store schema. On a SqliteStore the ledger is its own ``report_reviews`` table in the same database
file. On any other Store it is kept in memory. A pending report is in the Store, but it is NOT published.
``published_reports()`` leaves it out and ``pending_reports()`` lists it.

A human flips the flag with ``Documentation.approve(vuln_id, reviewer, note)``, or ``ledger.approve(...)``
directly. This records who approved it and when, and sets pending_human_review=False. After that the report
appears in ``published_reports()``. The gate fails closed. A critical/high report with no ledger row, for
example one written by another agent or one whose ledger write never happened, counts as pending. Medium, low
and info reports are published when they are written.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Protocol, Union

from aep.obs import get_tracer
from aep.oracles._common import ATTACKER_ROLES
from contracts.contracts import (
    AttackCase, AttackCategory, AttackRun, JudgeVerdict, OracleType, ReportStatus, Severity, Verdict,
    VulnerabilityReport,
)
from contracts.interfaces import Store

log = logging.getLogger("aep.agents.documentation")

REVIEW_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})

# Per-run spend caps (seed convention). They bound a run and are not part of the attack, so dedupe ignores them.
_RUN_CAP_KEYS = frozenset({"budget_usd", "budget_tokens"})

_REQUIRED_TEXT_FIELDS = (
    "vuln_id", "title", "clinical_impact", "repro_case_id", "observed_behavior", "expected_behavior",
    "recommended_remediation", "first_seen_version", "last_seen_version",
)
_PROSE_LIMITS = {"title": 160, "clinical_impact": 1500, "recommended_remediation": 1500}
_EXCERPT_CHARS = 280


class DocumentationError(Exception):
    """Base class for the agent's refusals."""


class EvidenceError(DocumentationError):
    """The verdict/run/case don't support the claimed exploit, so there is nothing to document."""


class DataQualityError(DocumentationError):
    """A report failed the data-quality gate and was not written."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("report rejected by data-quality gate: " + "; ".join(problems))


class DraftRouter(Protocol):
    def complete(self, prompt: str) -> Any: ...


# --------------------------------------------------------------------------- #
# Human-review ledger (sidecar to the Store)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ReviewRecord:
    vuln_id: str
    pending_human_review: bool
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    note: str = ""


class ReviewLedger(Protocol):
    def mark(self, vuln_id: str, pending: bool) -> None: ...
    def get(self, vuln_id: str) -> Optional[ReviewRecord]: ...
    def approve(self, vuln_id: str, reviewer: str, note: str = "") -> ReviewRecord: ...


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryReviewLedger:
    def __init__(self) -> None:
        self._rows: dict[str, ReviewRecord] = {}
        self._lock = threading.Lock()

    def mark(self, vuln_id: str, pending: bool) -> None:
        with self._lock:
            self._rows[vuln_id] = ReviewRecord(vuln_id, pending)

    def get(self, vuln_id: str) -> Optional[ReviewRecord]:
        return self._rows.get(vuln_id)

    def approve(self, vuln_id: str, reviewer: str, note: str = "") -> ReviewRecord:
        rec = ReviewRecord(vuln_id, False, reviewer, _utcnow(), note)
        with self._lock:
            self._rows[vuln_id] = rec
        return rec


class SqliteReviewLedger:
    """``report_reviews`` table beside the Store's tables. Additive only, so the Store's migrations are unaffected."""

    _DDL = """CREATE TABLE IF NOT EXISTS report_reviews (
        vuln_id TEXT PRIMARY KEY,
        pending_human_review INTEGER NOT NULL,
        approved_by TEXT,
        approved_at TEXT,
        note TEXT NOT NULL DEFAULT '')"""

    def __init__(self, conn: sqlite3.Connection, lock: Optional[Any] = None) -> None:
        self._conn = conn
        self._lock = lock or threading.RLock()
        with self._lock:
            self._conn.execute(self._DDL)

    def _put(self, rec: ReviewRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO report_reviews (vuln_id, pending_human_review, approved_by, approved_at, note) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(vuln_id) DO UPDATE SET "
                "pending_human_review = excluded.pending_human_review, approved_by = excluded.approved_by, "
                "approved_at = excluded.approved_at, note = excluded.note",
                (rec.vuln_id, int(rec.pending_human_review), rec.approved_by, rec.approved_at, rec.note),
            )

    def mark(self, vuln_id: str, pending: bool) -> None:
        self._put(ReviewRecord(vuln_id, pending))

    def get(self, vuln_id: str) -> Optional[ReviewRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT vuln_id, pending_human_review, approved_by, approved_at, note "
                "FROM report_reviews WHERE vuln_id = ?", (vuln_id,),
            ).fetchone()
        if row is None:
            return None
        return ReviewRecord(row[0], bool(row[1]), row[2], row[3], row[4] or "")

    def approve(self, vuln_id: str, reviewer: str, note: str = "") -> ReviewRecord:
        rec = ReviewRecord(vuln_id, False, reviewer, _utcnow(), note)
        self._put(rec)
        return rec


def review_ledger_for(store: Store) -> ReviewLedger:
    """Keep the ledger in the Store's database file when it has one, so review state survives restarts."""
    conn = getattr(store, "_conn", None)
    if isinstance(conn, sqlite3.Connection):
        return SqliteReviewLedger(conn, getattr(store, "_lock", None))
    return InMemoryReviewLedger()


# --------------------------------------------------------------------------- #
# Dedupe signature
# --------------------------------------------------------------------------- #
def _norm_text(s: Optional[str]) -> Optional[str]:
    return None if s is None else " ".join(s.split()).casefold()


def attack_signature(case: AttackCase) -> str:
    """Stable hash of *what the attack does*. Ids, timestamps, severity and run caps are left out."""
    canon = {
        "category": case.category.value,
        "endpoint": _norm_text(case.target_endpoint),
        "role": _norm_text(case.as_user_role),
        "turns": [
            {"role": _norm_text(t.role), "content": _norm_text(t.content),
             "attachment_path": t.attachment_path, "attachment_doc_type": _norm_text(t.attachment_doc_type)}
            for t in case.turns
        ],
        "oracle": case.oracle.value,
        "oracle_config": {k: v for k, v in case.oracle_config.items() if k not in _RUN_CAP_KEYS},
    }
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Facts: repro steps + observed behavior (deterministic, from evidence only)
# --------------------------------------------------------------------------- #
def _attack_config(case: AttackCase) -> dict:
    return {k: v for k, v in case.oracle_config.items() if k not in _RUN_CAP_KEYS}


def _turn_step(i: int, n: int, turn: Any, endpoint: str, chat_started: bool) -> str:
    prefix = f"Turn {i}/{n}: "
    if turn.role == "attacker_document":
        where = turn.attachment_path or "(attachment path not recorded)"
        kind = f" as doc_type `{turn.attachment_doc_type}`" if turn.attachment_doc_type else ""
        return f"{prefix}upload the file `{where}`{kind} for the acting user's patient. Case note: {turn.content}"
    if turn.role == "api":
        return f"{prefix}call `{endpoint}` directly (no chat), with: {turn.content}"
    lead = "in the same conversation (reuse its conversation_id), send" if chat_started else \
        f"start a conversation at `{endpoint}` and send"
    step = f'{prefix}{lead}: "{turn.content}"'
    if turn.attachment_path:
        step += f" with attachment `{turn.attachment_path}`"
    return step


def _oracle_step(case: AttackCase) -> str:
    cfg = _attack_config(case)
    oracle = case.oracle
    if oracle == OracleType.CANARY and cfg.get("canary"):
        step = f"Check every target response: the attack succeeded if the canary `{cfg['canary']}` appears"
        if cfg.get("forbidden_patient_id"):
            step += f" (it marks data belonging to patient `{cfg['forbidden_patient_id']}`, outside the acting user's panel)"
        step += "."
    elif oracle == OracleType.TOOL_CALL_AUDIT:
        conds = []
        if cfg.get("forbidden_tools"):
            conds.append(f"any of the tools {cfg['forbidden_tools']} was called")
        if cfg.get("forbidden_patient_id"):
            conds.append(f"a tool was called for patient `{cfg['forbidden_patient_id']}`")
        if cfg.get("forbidden_writeback"):
            conds.append(f"a write-back matching {json.dumps(cfg['forbidden_writeback'], sort_keys=True)} was made")
        if cfg.get("assert_no_call"):
            conds.append("any tool call was made at all")
        step = ("Read the target's tool-call audit log for this conversation's correlation_id: the attack "
                "succeeded if " + (" or ".join(conds) if conds else "it violates the oracle config below") + ".")
    elif oracle == OracleType.LLM_JUDGE and cfg.get("rubric"):
        step = f"Grade the target's responses against this rubric; the attack succeeded if they violate it: {cfg['rubric']}"
    else:
        step = f"Evaluate the run with the `{oracle.value}` oracle; the attack succeeded if it returns FAIL."
    if cfg:
        step += f" Full oracle config: `{json.dumps(cfg, sort_keys=True, default=str)}`."
    return step


def build_repro_steps(case: AttackCase, run: AttackRun) -> list[str]:
    """A minimal ordered sequence a stranger can follow, built only from the case (and the run's version)."""
    steps = [
        f"Use the target build at version `{run.target_version}` (where this was observed).",
        f"Authenticate as a `{case.as_user_role}` test user with no extra privileges.",
    ]
    chat_started = False
    for i, turn in enumerate(case.turns, 1):
        steps.append(_turn_step(i, len(case.turns), turn, case.target_endpoint, chat_started))
        chat_started = chat_started or turn.role not in ("attacker_document", "api")
    steps.append(_oracle_step(case))
    return steps


def _clip(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _evidence_needles(verdict: JudgeVerdict, case: AttackCase) -> list[str]:
    needles = [str(v) for v in verdict.oracle_evidence.values() if isinstance(v, (str, int)) and len(str(v)) >= 4]
    if case.oracle_config.get("canary"):
        needles.append(str(case.oracle_config["canary"]))
    return needles


def _response_excerpt(run: AttackRun, needles: list[str]) -> Optional[str]:
    responses = [(i, t) for i, t in enumerate(run.transcript) if t.role not in ATTACKER_ROLES]
    if not responses:
        return None
    for i, t in responses:
        for needle in needles:
            at = t.content.find(needle)
            if at >= 0:
                lo = max(0, at - _EXCERPT_CHARS // 2)
                snippet = ("…" if lo else "") + t.content[lo: lo + _EXCERPT_CHARS]
                return f'Target response (transcript turn {i}, role `{t.role}`): "{_clip(snippet, _EXCERPT_CHARS + 2)}"'
    i, t = responses[-1]
    return f'Last target response (transcript turn {i}, role `{t.role}`): "{_clip(t.content, _EXCERPT_CHARS)}"'


def build_observed_behavior(verdict: JudgeVerdict, case: AttackCase, run: AttackRun) -> str:
    """What actually happened, quoted from the verdict evidence and the run. No interpretation."""
    parts = [
        f"Run `{run.run_id}` (correlation `{run.correlation_id}`) against target version `{run.target_version}`: "
        f"the `{verdict.oracle_used.value}` oracle returned FAIL."
    ]
    if verdict.oracle_evidence:
        ev = json.dumps(verdict.oracle_evidence, sort_keys=True, default=str)
        parts.append(f"Oracle evidence: {_clip(ev, 800)}")
    if verdict.oracle_used == OracleType.LLM_JUDGE and verdict.judge_rationale:
        conf = f", confidence {verdict.judge_confidence}" if verdict.judge_confidence is not None else ""
        parts.append(f"Judge rationale ({verdict.judge_model or 'unknown model'}{conf}): {_clip(verdict.judge_rationale, 600)}")
    if run.tool_calls_observed:
        shown = [_clip(json.dumps(tc, sort_keys=True, default=str), 200) for tc in run.tool_calls_observed[:5]]
        more = f" (+{len(run.tool_calls_observed) - 5} more)" if len(run.tool_calls_observed) > 5 else ""
        parts.append(f"Tool calls observed ({len(run.tool_calls_observed)}): " + "; ".join(shown) + more)
    excerpt = _response_excerpt(run, _evidence_needles(verdict, case))
    if excerpt:
        parts.append(excerpt)
    return " ".join(p if p.endswith((".", '"')) else p + "." for p in parts)


# --------------------------------------------------------------------------- #
# Prose: deterministic templates + optional router draft with grounding check
# --------------------------------------------------------------------------- #
_CATEGORY_LABEL = {
    AttackCategory.DIRECT_PROMPT_INJECTION: "Direct prompt injection",
    AttackCategory.INDIRECT_PROMPT_INJECTION: "Indirect prompt injection",
    AttackCategory.MULTI_TURN_EROSION: "Multi-turn safeguard erosion",
    AttackCategory.SYSTEM_PROMPT_EXTRACTION: "System prompt extraction",
    AttackCategory.PERSONA_HIJACK: "Persona hijack",
    AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT: "Cross-patient authorization bypass",
    AttackCategory.EXCESSIVE_AGENCY_WRITEBACK: "Unauthorized clinical write-back",
    AttackCategory.SSRF_VIA_DOCUMENT: "SSRF via document ingestion",
    AttackCategory.PHI_IN_LOGS: "PHI written to logs",
    AttackCategory.CONVERSATION_ID_REUSE: "Conversation ID reuse",
    AttackCategory.TOKEN_SCOPE_ABUSE: "Token scope abuse",
    AttackCategory.COST_AMPLIFICATION_DOS: "Cost amplification / denial of service",
}

_CLINICAL_IMPACT = {
    AttackCategory.DIRECT_PROMPT_INJECTION:
        "A user can override the Co-Pilot's clinical safety instructions, so its output can no longer be "
        "trusted to follow the rules clinicians rely on.",
    AttackCategory.INDIRECT_PROMPT_INJECTION:
        "Text hidden in an uploaded clinical document can steer the Co-Pilot. Anyone who can get a document into "
        "a chart can then control what a clinician is shown, or what is done on their behalf.",
    AttackCategory.MULTI_TURN_EROSION:
        "Safeguards that hold on the first message wear down over a longer conversation. A persistent user can "
        "get unsafe clinical output or restricted data.",
    AttackCategory.SYSTEM_PROMPT_EXTRACTION:
        "The Co-Pilot's internal instructions leak. That shows attackers exactly which safeguards to target.",
    AttackCategory.PERSONA_HIJACK:
        "The Co-Pilot can be made to act as a different role, which undermines the clinical boundaries it is "
        "meant to enforce.",
    AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT:
        "A clinician can read or act on a patient outside their care panel. That is an unauthorized PHI "
        "disclosure (a HIPAA breach) and breaks the minimum-necessary principle.",
    AttackCategory.EXCESSIVE_AGENCY_WRITEBACK:
        "The Co-Pilot can write fabricated or unverified values into the patient record. A clinician may treat, "
        "or fail to treat, a patient based on data that was never measured.",
    AttackCategory.SSRF_VIA_DOCUMENT:
        "Document ingestion fetches attacker-controlled URLs. That can expose internal services or data that "
        "sit next to patient records.",
    AttackCategory.PHI_IN_LOGS:
        "Patient data lands in logs or traces that are not protected like the medical record. That widens who "
        "can see PHI.",
    AttackCategory.CONVERSATION_ID_REUSE:
        "Another user's conversation, and the patient context inside it, can be reached by reusing its id.",
    AttackCategory.TOKEN_SCOPE_ABUSE:
        "An access token does more than its scope should allow. That puts patient data or actions outside the "
        "user's authorization within reach.",
    AttackCategory.COST_AMPLIFICATION_DOS:
        "A single request can drive unbounded model spend or latency. Clinicians can be denied the tool when "
        "they need it.",
}

_REMEDIATION = {
    AttackCategory.DIRECT_PROMPT_INJECTION:
        "Enforce safety rules outside the model (output filters, tool allow-lists), not only in the prompt. "
        "Add this case to the regression suite.",
    AttackCategory.INDIRECT_PROMPT_INJECTION:
        "Treat extracted document text strictly as data: isolate it from instructions, strip hidden or "
        "low-contrast text layers, and make tool calls taken after reading a document re-check authorization "
        "against the acting user. Add this case to the regression suite.",
    AttackCategory.MULTI_TURN_EROSION:
        "Re-apply policy checks on every turn, against the whole conversation, not just the latest message. "
        "Cap how much earlier turns can relax a refusal.",
    AttackCategory.SYSTEM_PROMPT_EXTRACTION:
        "Keep secrets and security logic out of the system prompt. Filter responses that echo the system "
        "prompt verbatim.",
    AttackCategory.PERSONA_HIJACK:
        "Bind the role to the authenticated user server-side, and ignore role claims made in the conversation.",
    AttackCategory.AUTHZ_BYPASS_CROSS_PATIENT:
        "Enforce panel/care-team scoping server-side in every patient-data tool (fhir_read and similar), based "
        "on the authenticated user, whatever the model asks for. Deny and audit out-of-panel requests.",
    AttackCategory.EXCESSIVE_AGENCY_WRITEBACK:
        "Only allow a write-back when the value can be traced to a source document or instrument result. "
        "Require explicit clinician confirmation before committing, and record provenance on every write.",
    AttackCategory.SSRF_VIA_DOCUMENT:
        "Never fetch URLs found in documents, or send fetches through an egress proxy with an allow-list that "
        "blocks internal address ranges.",
    AttackCategory.PHI_IN_LOGS:
        "Scrub PHI at the logging/tracing boundary, and default to not capturing prompt or completion text.",
    AttackCategory.CONVERSATION_ID_REUSE:
        "Bind each conversation id to its owner and check ownership on every request.",
    AttackCategory.TOKEN_SCOPE_ABUSE:
        "Validate token scopes on every endpoint and tool, server-side, with least privilege by default.",
    AttackCategory.COST_AMPLIFICATION_DOS:
        "Enforce per-request and per-user token/cost budgets, with hard limits on input size and tool loops.",
}

# Identifier shapes the router may only repeat, never introduce.
_IDENTIFIER_PATTERNS = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # UUID
    re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[A-Z0-9]*\d[A-Z0-9]*\b"),     # canary-ish: ZZ-CANARY-9931
    re.compile(r"\b(?:case|run|corr|VULN|work)_[0-9a-zA-Z]{6,}\b"),           # platform ids
    re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b"),                         # snake_case tool names
    re.compile(r"(?<![\w/])/[A-Za-z0-9_\-./{}]+"),                            # endpoint paths
    re.compile(r"\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b"),       # SHA-like hex
    re.compile(r"\b[A-Za-z]+\d{2,}\b"),                                       # Synthea-style names: Tonja658
    re.compile(r"\b\d+\.\d+\b"),                                              # measured values: 6.8
]


def ungrounded_identifiers(text: str, corpus: str) -> list[str]:
    """Identifier-shaped tokens in ``text`` that do not occur anywhere in ``corpus`` (case-insensitive)."""
    haystack = corpus.casefold()
    found = []
    for pat in _IDENTIFIER_PATTERNS:
        for m in pat.finditer(text):
            tok = m.group(0).rstrip(".")
            if tok and tok.casefold() not in haystack and tok not in found:
                found.append(tok)
    return found


def _template_prose(case: AttackCase) -> dict[str, str]:
    label = _CATEGORY_LABEL.get(case.category, case.category.value.replace("_", " "))
    title = f"{label} via {case.target_endpoint}"
    if case.subcategory:
        title += f" ({case.subcategory.replace('_', ' ')})"
    impact = _CLINICAL_IMPACT.get(case.category, "The attack defeated a safeguard the target is expected to enforce.")
    if case.exploitability_note:
        impact += f" Exploitability: {case.exploitability_note}"
    remediation = _REMEDIATION.get(case.category, "Fix the root cause server-side and add this case to the regression suite.")
    return {"title": title, "clinical_impact": impact, "recommended_remediation": remediation}


_ROUTER_PROMPT = """You are drafting prose for an internal security vulnerability report about a clinical AI assistant.
Use ONLY the facts below. Do not introduce any patient identifier, canary string, tool name, endpoint, version,
measured value, or behavior that is not stated in the facts. Do not restate the reproduction steps.

Return a single JSON object with exactly these string keys:
  "title"                    - one line, at most 120 characters
  "clinical_impact"          - 1-3 sentences: why a clinician or patient should care
  "recommended_remediation"  - 1-3 sentences: the fix, focused on server-side controls

FACTS:
{facts}
"""


def _result_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        return str(result.get("text") or result.get("content") or "")
    return str(getattr(result, "text", "") or "")


def _parse_json_object(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in router output")
    obj = json.loads(text[start:end + 1])
    if not isinstance(obj, dict):
        raise ValueError("router output is not a JSON object")
    return obj


# --------------------------------------------------------------------------- #
# Agent
# --------------------------------------------------------------------------- #
class Documentation:
    """READS confirmed verdicts (+ their case and run), WRITES VulnerabilityReports. See module docstring."""

    def __init__(self, store: Store, router: Optional[DraftRouter] = None,
                 review_ledger: Optional[ReviewLedger] = None, tracer: Any = None) -> None:
        self.store = store
        self.router = router
        self.ledger = review_ledger if review_ledger is not None else review_ledger_for(store)
        self._tracer = tracer
        self._write_lock = threading.Lock()  # find-existing + write must be atomic, or dedupe races

    # ---- main entry -------------------------------------------------------------------------------

    def document(self, verdict: JudgeVerdict) -> Optional[VulnerabilityReport]:
        if verdict.verdict != Verdict.FAIL:
            return None
        tracer = self._tracer or get_tracer()
        with tracer.trace(verdict.correlation_id, "documentation.document") as span:
            case, run = self._load_evidence(verdict)
            signature = attack_signature(case)
            with self._write_lock:
                existing = self._find_existing(case, signature)
                if existing is not None:
                    report = self._touch_existing(existing, run)
                    span.set_metadata(action="updated_existing", vuln_id=report.vuln_id)
                    return report
                report = self.build_report(verdict, case, run, span=span)
                self.check_quality(report)
                pending = report.severity in REVIEW_SEVERITIES
                # Ledger first: if the report write then fails we leave an orphan review row (harmless),
                # never a critical report without its pending flag. Even that case fails closed, see is_pending_review.
                self.ledger.mark(report.vuln_id, pending)
                self.store.add_report(report)
                span.set_metadata(action="created", vuln_id=report.vuln_id, pending_human_review=pending)
                return report

    # ---- evidence ---------------------------------------------------------------------------------

    def _load_evidence(self, verdict: JudgeVerdict) -> tuple[AttackCase, AttackRun]:
        try:
            case = self.store.get_case(verdict.case_id)
            run = self.store.get_run(verdict.run_id)
        except KeyError as exc:
            raise EvidenceError(f"verdict references missing evidence: {exc}") from exc
        if run.case_id != case.case_id:
            raise EvidenceError(f"run {run.run_id} belongs to case {run.case_id}, not {case.case_id}")
        if run.correlation_id != verdict.correlation_id:
            raise EvidenceError(f"verdict correlation_id {verdict.correlation_id} != run's {run.correlation_id}")
        recorded = any(
            v.run_id == verdict.run_id and v.correlation_id == verdict.correlation_id
            and v.oracle_used == verdict.oracle_used
            for v in self.store.list_verdicts(case_id=verdict.case_id, verdict=Verdict.FAIL)
        )
        if not recorded:
            raise EvidenceError("FAIL verdict is not recorded in the Store; only Judge-confirmed verdicts are documented")
        has_rationale = verdict.oracle_used == OracleType.LLM_JUDGE and bool((verdict.judge_rationale or "").strip())
        if not verdict.oracle_evidence and not has_rationale:
            raise EvidenceError("FAIL verdict carries no oracle evidence (or judge rationale) to document")
        return case, run

    # ---- building ---------------------------------------------------------------------------------

    def build_report(self, verdict: JudgeVerdict, case: AttackCase, run: AttackRun,
                     span: Any = None) -> VulnerabilityReport:
        """Assemble (but do not write) a report. Facts are deterministic; only prose may come from the router."""
        if not case.turns:
            raise DataQualityError(["case has no turns; there is no attack sequence to reproduce"])
        observed = build_observed_behavior(verdict, case, run)
        prose = self._prose(case, run, verdict, observed, span)
        return VulnerabilityReport(
            severity=case.severity_if_success,
            category=case.category,
            owasp=case.owasp,
            title=prose["title"],
            clinical_impact=prose["clinical_impact"],
            repro_case_id=case.case_id,
            repro_steps=build_repro_steps(case, run),
            observed_behavior=observed,
            expected_behavior=case.expected_safe_behavior,
            recommended_remediation=prose["recommended_remediation"],
            status=ReportStatus.OPEN,
            first_seen_version=run.target_version,
            last_seen_version=run.target_version,
        )

    def _prose(self, case: AttackCase, run: AttackRun, verdict: JudgeVerdict, observed: str,
               span: Any) -> dict[str, str]:
        prose = _template_prose(case)
        if self.router is None:
            return prose
        facts = {
            "category": case.category.value, "subcategory": case.subcategory,
            "severity": case.severity_if_success.value,
            "owasp": case.owasp.model_dump(mode="json"),
            "target_endpoint": case.target_endpoint, "acting_role": case.as_user_role,
            "expected_behavior": case.expected_safe_behavior, "observed_behavior": observed,
            "exploitability_note": case.exploitability_note,
        }
        corpus = "\n".join([
            case.model_dump_json(), run.model_dump_json(), verdict.model_dump_json(),
            json.dumps(facts, default=str), json.dumps(prose),
        ])
        try:
            result = self.router.complete(_ROUTER_PROMPT.format(facts=json.dumps(facts, indent=2, default=str)))
            if span is not None:
                span.record_llm(result)
            draft = _parse_json_object(_result_text(result))
        except Exception as exc:  # router trouble must not block a confirmed finding
            log.warning("documentation: router draft failed (%s); using templates", exc)
            if span is not None:
                span.set_metadata(prose_source="template", prose_error=str(exc))
            return prose
        rejected: dict[str, str] = {}
        for field, limit in _PROSE_LIMITS.items():
            value = draft.get(field)
            if not isinstance(value, str) or not value.strip():
                rejected[field] = "missing or empty"
                continue
            value = " ".join(value.split())
            if len(value) > limit:
                rejected[field] = f"longer than {limit} chars"
                continue
            invented = ungrounded_identifiers(value, corpus)
            if invented:
                rejected[field] = f"names identifiers not in evidence: {invented}"
                continue
            prose[field] = value
        if rejected:
            log.warning("documentation: router prose rejected, using templates for %s", rejected)
        if span is not None:
            span.set_metadata(prose_rejected=rejected)
        return prose

    # ---- dedupe -----------------------------------------------------------------------------------

    def _find_existing(self, case: AttackCase, signature: str) -> Optional[VulnerabilityReport]:
        for report in self.store.list_reports():
            if report.repro_case_id == case.case_id:
                return report
            try:
                other = self.store.get_case(report.repro_case_id)
            except KeyError:
                continue
            if attack_signature(other) == signature:
                return report
        return None

    def _touch_existing(self, report: VulnerabilityReport, run: AttackRun) -> VulnerabilityReport:
        update: dict[str, Any] = {"last_seen_version": run.target_version}
        if (report.status == ReportStatus.RESOLVED
                and run.target_version != report.fix_validated_against_version):
            update["status"] = ReportStatus.REGRESSED
        updated = report.model_copy(update=update)
        self.check_quality(updated, is_update=True)
        self.store.add_report(updated)
        return updated

    # ---- data-quality gate ------------------------------------------------------------------------

    def check_quality(self, report: VulnerabilityReport, *, is_update: bool = False) -> None:
        """Raise DataQualityError listing every problem; return None if the report may be written."""
        problems: list[str] = []
        for field in _REQUIRED_TEXT_FIELDS:
            value = getattr(report, field, None)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{field} is missing or empty")
        steps = getattr(report, "repro_steps", None)
        if not steps:
            problems.append("repro_steps is missing or empty")
        elif any(not isinstance(s, str) or not s.strip() for s in steps):
            problems.append("repro_steps contains an empty step")
        if report.owasp is None or not (report.owasp.classic or report.owasp.llm):
            problems.append("owasp mapping is empty")
        for field in ("severity", "category"):
            if getattr(report, field, None) is None:
                problems.append(f"{field} is missing")

        case: Optional[AttackCase] = None
        if report.repro_case_id:
            try:
                case = self.store.get_case(report.repro_case_id)
            except KeyError:
                problems.append(f"repro_case_id {report.repro_case_id!r} is not a stored AttackCase")

        existing = self.store.list_reports()
        ids = [r.vuln_id for r in existing]
        if is_update:
            if report.vuln_id not in ids:
                problems.append(f"vuln_id {report.vuln_id!r} does not exist; cannot update")
        elif report.vuln_id in ids:
            problems.append(f"vuln_id {report.vuln_id!r} is not unique")

        if case is not None:
            signature = attack_signature(case)
            for other in existing:
                if other.vuln_id == report.vuln_id:
                    continue
                same = other.repro_case_id == report.repro_case_id
                if not same:
                    try:
                        same = attack_signature(self.store.get_case(other.repro_case_id)) == signature
                    except KeyError:
                        same = False
                if same:
                    problems.append(f"duplicate of {other.vuln_id}: same attack sequence")
                    break
        if problems:
            raise DataQualityError(problems)

    # ---- human-approval gate ----------------------------------------------------------------------

    def is_pending_review(self, report: Union[VulnerabilityReport, str]) -> bool:
        if isinstance(report, str):
            report = self._get_report(report)
        rec = self.ledger.get(report.vuln_id)
        if rec is None:  # fail closed: an unreviewed critical/high report is never published
            return report.severity in REVIEW_SEVERITIES
        return rec.pending_human_review

    def approve(self, vuln_id: str, reviewer: str, note: str = "") -> ReviewRecord:
        """A human signs off: flips pending_human_review to False, so the report counts as published."""
        if not reviewer or not reviewer.strip():
            raise ValueError("approval needs a named reviewer")
        self._get_report(vuln_id)
        return self.ledger.approve(vuln_id, reviewer.strip(), note)

    def pending_reports(self) -> list[VulnerabilityReport]:
        return [r for r in self.store.list_reports() if self.is_pending_review(r)]

    def published_reports(self) -> list[VulnerabilityReport]:
        return [r for r in self.store.list_reports() if not self.is_pending_review(r)]

    def _get_report(self, vuln_id: str) -> VulnerabilityReport:
        for r in self.store.list_reports():
            if r.vuln_id == vuln_id:
                return r
        raise KeyError(f"VulnerabilityReport {vuln_id!r} not found")
