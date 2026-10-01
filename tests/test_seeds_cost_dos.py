"""The cost_amplification_dos seed cases validate against the AttackCase schema.

Runs the real ``scripts/load_seeds.py`` (the command the author validates with)
in a clean subprocess and asserts the whole suite still passes AND the new
category is present with its attack case + benign positive-control twin.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SEEDS_DIR = REPO / "evals" / "seeds" / "cost_amplification_dos"


def test_cost_dos_seeds_exist():
    files = sorted(p.name for p in SEEDS_DIR.glob("*.json"))
    assert files == [
        "dos_01_brief_burst_no_rate_limit.json",
        "dos_02_benign_positive_control.json",
    ]


def test_load_seeds_validates_the_whole_suite_including_cost_dos():
    proc = subprocess.run(
        [sys.executable, "scripts/load_seeds.py", "--json"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"

    summary = json.loads(proc.stdout)
    by_cat = summary["by_category"]
    assert "cost_amplification_dos" in by_cat
    cat = by_cat["cost_amplification_dos"]
    assert cat["count"] == 2
    assert cat["positive_control"] == 1  # the benign twin
    assert "seed-dos-01-brief-burst-no-rate-limit" in summary["case_ids"]
    assert "seed-dos-02-benign-positive-control" in summary["case_ids"]


def test_cost_dos_cases_parse_as_attackcases_with_rate_limit_oracle():
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from contracts.contracts import AttackCase, AttackCategory, OracleType, Severity

    attack = AttackCase.model_validate(
        json.loads((SEEDS_DIR / "dos_01_brief_burst_no_rate_limit.json").read_text())
    )
    assert attack.category == AttackCategory.COST_AMPLIFICATION_DOS
    assert attack.oracle == OracleType.RATE_LIMIT
    assert attack.target_endpoint == "/pre-visit-brief"
    assert attack.oracle_config["burst"] == 20
    assert attack.severity_if_success == Severity.HIGH

    benign = AttackCase.model_validate(
        json.loads((SEEDS_DIR / "dos_02_benign_positive_control.json").read_text())
    )
    assert benign.oracle == OracleType.RATE_LIMIT
    assert benign.oracle_config["positive_control"] is True
    assert benign.oracle_config["burst"] == 1
    assert benign.severity_if_success == Severity.INFO
