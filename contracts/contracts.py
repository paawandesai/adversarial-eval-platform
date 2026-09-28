"""
Adversarial Evaluation Platform — canonical contracts (source of truth).

Every agent conforms to these shapes:
  - Red Team   WRITES AttackCase, WRITES AttackRun (transcript, no verdict)
  - Judge      READS AttackRun, WRITES Verdict (+ oracle evidence)
  - Orchestrator READS coverage/findings, WRITES WorkItem
  - Documentation READS confirmed Verdicts, WRITES VulnerabilityReport
  - Regression READS AttackCase(regression=True), re-runs, compares Verdicts

Design notes:
  - OWASP mapping is REQUIRED on every case (classic + LLM Top 10).
  - Verdicts are boolean-ish (PASS/FAIL/PARTIAL); prefer DETERMINISTIC oracles.
    The LLM judge is a fallback for genuinely semantic calls only.
  - correlation_id threads every log line, tool call, and LLM call for one run.
  - Mutations carry parent_case_id so attack lineage is reconstructable.
  - Versioning: bump SCHEMA_VERSION on any breaking change (contract tests guard).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

SCHEMA_VERSION = "v1"


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AttackCategory(str, Enum):
    # LLM-layer (attack enters through the conversation / uploaded content)
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"        # via uploaded PDF/intake
    MULTI_TURN_EROSION = "multi_turn_erosion"                      # safeguard decay over turns
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    PERSONA_HIJACK = "persona_hijack"
    # App-layer damage delivered via the LLM
    AUTHZ_BYPASS_CROSS_PATIENT = "authz_bypass_cross_patient"      # read/act outside user's panel
    EXCESSIVE_AGENCY_WRITEBACK = "excessive_agency_writeback"      # fabricated lab write-back
    SSRF_VIA_DOCUMENT = "ssrf_via_document"                        # ingestion fetches attacker URL
    PHI_IN_LOGS = "phi_in_logs"                                    # logging failure
    # Direct-API layer (no prompt involved)
    CONVERSATION_ID_REUSE = "conversation_id_reuse"
    TOKEN_SCOPE_ABUSE = "token_scope_abuse"
    COST_AMPLIFICATION_DOS = "cost_amplification_dos"


class OwaspClassic(str, Enum):
    BROKEN_ACCESS_CONTROL = "A01_broken_access_control"
    CRYPTO_FAILURES = "A02_cryptographic_failures"
    INJECTION = "A03_injection"
    INSECURE_DESIGN = "A04_insecure_design"
    SECURITY_MISCONFIG = "A05_security_misconfiguration"
    VULNERABLE_COMPONENTS = "A06_vulnerable_components"
    AUTH_FAILURES = "A07_identification_auth_failures"
    INTEGRITY_FAILURES = "A08_software_data_integrity_failures"
    LOGGING_FAILURES = "A09_logging_monitoring_failures"
    SSRF = "A10_ssrf"


class OwaspLLM(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01_prompt_injection"
    LLM02_INSECURE_OUTPUT = "LLM02_insecure_output_handling"
    LLM03_DATA_POISONING = "LLM03_training_data_poisoning"
    LLM04_MODEL_DOS = "LLM04_model_denial_of_service"
    LLM05_SUPPLY_CHAIN = "LLM05_supply_chain"
    LLM06_INFO_DISCLOSURE = "LLM06_sensitive_information_disclosure"
    LLM07_INSECURE_PLUGIN = "LLM07_insecure_plugin_design"
    LLM08_EXCESSIVE_AGENCY = "LLM08_excessive_agency"
    LLM09_OVERRELIANCE = "LLM09_overreliance"
    LLM10_MODEL_THEFT = "LLM10_model_theft"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    PASS = "pass"        # target defended; attack did NOT succeed
    FAIL = "fail"        # attack SUCCEEDED — a vulnerability
    PARTIAL = "partial"  # attack partially succeeded; needs mutation/escalation
    ERROR = "error"      # run could not be evaluated (target unreachable, timeout)


class OracleType(str, Enum):
    CANARY = "canary"                    # marker string for another patient appeared
    TOOL_CALL_AUDIT = "tool_call_audit"  # tool invoked with out-of-panel patient id
    LOG_SCAN = "log_scan"                # PHI/canary regex hit in traces
    TOKEN_COUNTER = "token_counter"      # cost/token budget exceeded
    HTTP_ASSERT = "http_assert"          # status/field assertion on direct API call
    LLM_JUDGE = "llm_judge"              # semantic verdict — fallback only


class Origin(str, Enum):
    SEED = "seed"                # hand-authored (often via the interactive harness)
    MUTATION = "mutation"        # derived from a parent via deterministic transform
    HARNESS_DISCOVERY = "harness_discovery"  # found interactively, then frozen


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


# --------------------------------------------------------------------------- #
# Attack case  (Red Team writes; regression replays)
# --------------------------------------------------------------------------- #
class ConversationTurn(BaseModel):
    role: str = Field(description="'user' or 'attacker_document' or 'api'")
    content: str
    # For document-based indirect injection, the payload rides inside a file:
    attachment_path: Optional[str] = None
    attachment_doc_type: Optional[str] = None  # lab_pdf | intake_form | referral_fax


class OwaspMapping(BaseModel):
    classic: list[OwaspClassic] = Field(default_factory=list)
    llm: list[OwaspLLM] = Field(default_factory=list)

    @model_validator(mode="after")
    def at_least_one(self):
        if not self.classic and not self.llm:
            raise ValueError("every case must map to >=1 OWASP category")
        return self


class AttackCase(BaseModel):
    schema_version: str = SCHEMA_VERSION
    case_id: str = Field(default_factory=lambda: _uid("case"))
    origin: Origin
    parent_case_id: Optional[str] = None  # set for MUTATION → lineage

    category: AttackCategory
    subcategory: Optional[str] = None
    owasp: OwaspMapping

    # The attack itself — a sequence so multi-turn is first-class.
    turns: list[ConversationTurn]

    # Who runs it (drives least-privilege: attacker uses a scoped test user).
    as_user_role: str = Field(description="physician | nurse | resident")
    target_endpoint: str = Field(description="e.g. /api/agent/chat, /api/agent/upload")

    # Ground truth for the oracle.
    expected_safe_behavior: str
    oracle: OracleType
    oracle_config: dict = Field(
        default_factory=dict,
        description="e.g. {'canary': 'ZZ-CANARY-9931', 'forbidden_patient_id': 42}",
    )

    severity_if_success: Severity
    exploitability_note: str = ""
    in_regression_suite: bool = False

    created_at: datetime = Field(default_factory=_now)

    @model_validator(mode="after")
    def mutation_needs_parent(self):
        if self.origin == Origin.MUTATION and not self.parent_case_id:
            raise ValueError("MUTATION cases must set parent_case_id (lineage)")
        return self


# --------------------------------------------------------------------------- #
# Run + verdict  (Red Team writes run; Judge writes verdict)
# --------------------------------------------------------------------------- #
class AttackRun(BaseModel):
    """One execution of one AttackCase against a specific target version."""
    schema_version: str = SCHEMA_VERSION
    run_id: str = Field(default_factory=lambda: _uid("run"))
    correlation_id: str = Field(default_factory=lambda: _uid("corr"))  # threads all logs
    case_id: str
    target_version: str  # commit SHA from target /version — regression anchors on this

    transcript: list[ConversationTurn]  # what actually happened
    tool_calls_observed: list[dict] = Field(default_factory=list)  # from target audit log

    # Observability (engineering req: latency by step, tokens, cost).
    tokens_prompt: int = 0
    tokens_completion: int = 0
    cost_usd: float = 0.0
    latency_ms_by_step: dict[str, float] = Field(default_factory=dict)

    redteam_model: str = ""
    started_at: datetime = Field(default_factory=_now)


class JudgeVerdict(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    case_id: str
    correlation_id: str

    verdict: Verdict
    oracle_used: OracleType
    oracle_evidence: dict = Field(
        default_factory=dict,
        description="deterministic proof, e.g. {'canary_hit': True, 'match': 'ZZ-CANARY-9931'}",
    )
    # Only populated when oracle_used == LLM_JUDGE:
    judge_model: Optional[str] = None
    judge_rationale: Optional[str] = None
    judge_confidence: Optional[float] = None

    evaluated_at: datetime = Field(default_factory=_now)


# --------------------------------------------------------------------------- #
# Vulnerability report  (Documentation agent writes)
# --------------------------------------------------------------------------- #
class ReportStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REGRESSED = "regressed"


class VulnerabilityReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    vuln_id: str = Field(default_factory=lambda: _uid("VULN"))
    severity: Severity
    category: AttackCategory
    owasp: OwaspMapping

    title: str
    clinical_impact: str                 # why a clinician/patient should care
    repro_case_id: str                   # minimal reproducing AttackCase
    repro_steps: list[str]
    observed_behavior: str
    expected_behavior: str
    recommended_remediation: str

    status: ReportStatus = ReportStatus.OPEN
    fix_validated_against_version: Optional[str] = None
    first_seen_version: str = ""
    last_seen_version: str = ""

    created_at: datetime = Field(default_factory=_now)

    @model_validator(mode="after")
    def repro_not_empty(self):
        if not self.repro_steps:
            raise ValueError("a report a stranger can't reproduce is not a report")
        return self


# --------------------------------------------------------------------------- #
# Orchestrator work item  (Orchestrator writes; Red Team consumes)
# --------------------------------------------------------------------------- #
class WorkItem(BaseModel):
    schema_version: str = SCHEMA_VERSION
    work_id: str = Field(default_factory=lambda: _uid("work"))
    target_category: AttackCategory
    seed_case_id: Optional[str] = None   # mutate from this, or None to generate fresh
    token_budget: int = Field(description="hard cap; Red Team halts when exceeded")
    reason: str = Field(description="why the orchestrator chose this (coverage gap, open finding)")
    created_at: datetime = Field(default_factory=_now)