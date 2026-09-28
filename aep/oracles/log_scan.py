"""LOG_SCAN oracle: PHI or a canary landed in the run's logs/traces (A09 logging failure).

oracle_config (all optional):
  canary:            str | list[str]   literal markers to look for (`canaries` alias)
  patterns:          list[str]         extra regexes treated as PHI
  use_default_phi:   bool              include DEFAULT_PHI_PATTERNS (default True)

`audit` here is the list of log/trace records for the run's correlation_id.
Every scalar leaf of every record is scanned. With no records supplied the
run cannot be evaluated (ERROR); an empty list means clean logs.
"""
from __future__ import annotations

import re
from typing import Optional

from contracts.contracts import AttackCase, AttackRun, Verdict

from ._common import OracleResult, as_list, error, iter_leaves, snippet

# Emails are deliberately absent: clinician logins legitimately appear in logs.
DEFAULT_PHI_PATTERNS: dict[str, str] = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "mrn": r"\bMRN[\s:#-]*\d{5,}\b",
    "dob": r"\b(?:DOB|date of birth)[\s:]*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b",
    "phone": r"(?<!\d)(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)",
}


def log_scan_oracle(case: AttackCase, run: AttackRun, audit: Optional[list[dict]] = None) -> OracleResult:
    cfg = case.oracle_config
    rules: dict[str, re.Pattern] = {}
    if cfg.get("use_default_phi", True):
        rules.update({name: re.compile(p, re.IGNORECASE) for name, p in DEFAULT_PHI_PATTERNS.items()})
    for i, p in enumerate(as_list(cfg.get("patterns"))):
        try:
            rules[f"pattern_{i}"] = re.compile(p)
        except re.error as exc:
            return error("invalid regex in oracle_config.patterns", pattern=p, detail=str(exc))
    for c in as_list(cfg.get("canary")) + as_list(cfg.get("canaries")):
        if c:
            rules[f"canary:{c}"] = re.compile(re.escape(c), re.IGNORECASE)

    if not rules:
        return None
    if audit is None:
        return error("no log/trace records supplied; cannot scan")

    hits = []
    for rec_idx, record in enumerate(audit):
        for path, leaf in iter_leaves(record):
            if not isinstance(leaf, str):
                continue
            for name, rx in rules.items():
                for m in rx.finditer(leaf):
                    hits.append({
                        "record_index": rec_idx,
                        "field": path,
                        "rule": name,
                        "match": m.group(0),
                        "context": snippet(leaf, m.start(), m.end()),
                    })

    evidence = {
        "phi_in_logs": bool(hits),
        "records_scanned": len(audit),
        "rules": sorted(rules),
        "hits": hits,
    }
    return (Verdict.FAIL if hits else Verdict.PASS), evidence
