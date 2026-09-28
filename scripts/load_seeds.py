#!/usr/bin/env python3
"""Load, validate, and (optionally) store the seed AttackCases.

Every ``evals/seeds/<category>/*.json`` file is exactly one ``AttackCase`` record.
This script loads them all, validates each against the canonical Pydantic model in
``contracts.contracts``, and enforces a few suite-level invariants that the model
itself does not (OWASP classic+LLM both present, unique case ids, dir/category
match, each required category has a benign positive-control twin).

It FAILS LOUDLY: any invalid case, bad JSON, or violated invariant makes the whole
run exit non-zero after reporting *every* problem found (not just the first).

Usage
-----
    python scripts/load_seeds.py                 # validate only (exit 1 on any error)
    python scripts/load_seeds.py --seeds-dir DIR # non-default location
    python scripts/load_seeds.py --json          # machine-readable summary
    python scripts/load_seeds.py --insert --db seeds.db   # also insert into SqliteStore

``--insert`` imports the SqliteStore (contracts.interfaces.Store implementation)
lazily; if that agent's code is not present in this checkout, it explains and
exits non-zero rather than pretending to have stored anything.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from pydantic import ValidationError

    from contracts.contracts import AttackCase
except ModuleNotFoundError as exc:  # pragma: no cover - environment guard
    sys.stderr.write(
        f"FATAL: cannot import contracts/pydantic ({exc}). "
        f"Run from the repo root with dependencies installed.\n"
    )
    raise SystemExit(2)

# The three categories this seed set is required to cover, each needing >=1
# benign positive-control twin.
REQUIRED_CATEGORIES = (
    "indirect_prompt_injection",
    "authz_bypass_cross_patient",
    "excessive_agency_writeback",
)

RESET, RED, GREEN, YEL, DIM = "\033[0m", "\033[31m", "\033[32m", "\033[33m", "\033[2m"


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


class SeedError(Exception):
    """A single validation / invariant failure, tied to a file."""

    def __init__(self, path: Path, message: str):
        self.path = path
        self.message = message
        super().__init__(message)


def _iter_case_files(seeds_dir: Path):
    """Yield every seed JSON file, skipping the fixtures directory."""
    for path in sorted(seeds_dir.rglob("*.json")):
        if "fixtures" in path.relative_to(seeds_dir).parts:
            continue
        yield path


def _is_positive_control(case: AttackCase) -> bool:
    return bool(case.oracle_config.get("positive_control")) or case.subcategory == "positive_control"


def load_cases(seeds_dir: Path) -> tuple[list[tuple[Path, AttackCase]], list[SeedError]]:
    """Return (valid cases, errors). Never raises for per-case problems."""
    cases: list[tuple[Path, AttackCase]] = []
    errors: list[SeedError] = []
    seen_ids: dict[str, Path] = {}

    files = list(_iter_case_files(seeds_dir))
    if not files:
        errors.append(SeedError(seeds_dir, "no seed JSON files found"))
        return cases, errors

    for path in files:
        # 1) JSON parse
        try:
            raw = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            errors.append(SeedError(path, f"invalid JSON: {exc}"))
            continue
        if not isinstance(raw, dict):
            errors.append(SeedError(path, "top-level JSON must be a single object (one AttackCase)"))
            continue

        # 2) schema validation against the canonical model
        try:
            case = AttackCase.model_validate(raw)
        except ValidationError as exc:
            errors.append(SeedError(path, f"AttackCase validation failed:\n{exc}"))
            continue

        # 3) suite-level invariants the model does not enforce
        dir_category = path.parent.name
        if case.category.value != dir_category:
            errors.append(SeedError(
                path, f"category '{case.category.value}' does not match directory '{dir_category}'"))
        if not case.owasp.classic:
            errors.append(SeedError(path, "OWASP mapping must include >=1 classic category"))
        if not case.owasp.llm:
            errors.append(SeedError(path, "OWASP mapping must include >=1 LLM Top-10 category"))
        if case.origin.value != "seed":
            errors.append(SeedError(path, f"seed files must have origin 'seed', got '{case.origin.value}'"))
        if not case.turns:
            errors.append(SeedError(path, "case has no turns"))
        if case.case_id in seen_ids:
            errors.append(SeedError(
                path, f"duplicate case_id '{case.case_id}' (also in {seen_ids[case.case_id].name})"))
        else:
            seen_ids[case.case_id] = path

        cases.append((path, case))

    # 4) coverage invariants across the whole set
    by_cat: dict[str, list[AttackCase]] = {}
    for _, case in cases:
        by_cat.setdefault(case.category.value, []).append(case)
    for cat in REQUIRED_CATEGORIES:
        found = by_cat.get(cat, [])
        if not found:
            errors.append(SeedError(seeds_dir, f"required category '{cat}' has no cases"))
            continue
        if not any(_is_positive_control(c) for c in found):
            errors.append(SeedError(
                seeds_dir, f"category '{cat}' is missing a benign positive-control twin"))

    return cases, errors


def print_summary(cases: list[tuple[Path, AttackCase]]) -> None:
    by_cat: dict[str, list[AttackCase]] = {}
    for _, case in cases:
        by_cat.setdefault(case.category.value, []).append(case)

    print(f"\n{_c('Seed coverage', YEL)}")
    print(f"  {'category':<32}{'cases':>6}{'regr':>6}{'pos-ctl':>8}")
    for cat in sorted(by_cat):
        group = by_cat[cat]
        regr = sum(1 for c in group if c.in_regression_suite)
        pos = sum(1 for c in group if _is_positive_control(c))
        print(f"  {cat:<32}{len(group):>6}{regr:>6}{pos:>8}")
    total = len(cases)
    regr = sum(1 for _, c in cases if c.in_regression_suite)
    pos = sum(1 for _, c in cases if _is_positive_control(c))
    print(f"  {'-'*52}")
    print(f"  {'TOTAL':<32}{total:>6}{regr:>6}{pos:>8}")

    sev: dict[str, int] = {}
    for _, c in cases:
        sev[c.severity_if_success.value] = sev.get(c.severity_if_success.value, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    sev_line = "  ".join(f"{k}={sev.get(k, 0)}" for k in order)
    print(f"\n  severity_if_success:  {sev_line}")


def summary_dict(cases: list[tuple[Path, AttackCase]]) -> dict:
    by_cat: dict[str, dict] = {}
    for _, case in cases:
        e = by_cat.setdefault(case.category.value, {"count": 0, "regression": 0, "positive_control": 0})
        e["count"] += 1
        e["regression"] += int(case.in_regression_suite)
        e["positive_control"] += int(_is_positive_control(case))
    return {
        "total": len(cases),
        "by_category": by_cat,
        "case_ids": [c.case_id for _, c in cases],
    }


def insert_into_store(cases: list[tuple[Path, AttackCase]], db_path: str) -> int:
    """Insert every valid case into a SqliteStore. Returns count inserted."""
    # The store lives under <repo>/platform/store; `platform` cannot be imported
    # as a package (stdlib clash), so put that dir on sys.path and import `store`.
    platform_dir = REPO_ROOT / "platform"
    if str(platform_dir) not in sys.path:
        sys.path.insert(0, str(platform_dir))
    try:
        from store import SqliteStore  # type: ignore
    except ModuleNotFoundError as exc:
        sys.stderr.write(
            f"{_c('--insert failed', RED)}: SqliteStore not available in this checkout ({exc}).\n"
            f"  The store lands on branch feat/store; merge it in before using --insert.\n"
        )
        raise SystemExit(3)

    store = SqliteStore(db_path)
    n = 0
    for _, case in cases:
        store.add_case(case)
        n += 1
    if hasattr(store, "close"):
        store.close()
    return n


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds-dir", default=str(REPO_ROOT / "evals" / "seeds"),
                    help="directory holding <category>/*.json (default: evals/seeds)")
    ap.add_argument("--insert", action="store_true", help="insert validated cases into a SqliteStore")
    ap.add_argument("--db", default="seeds.db", help="SqliteStore path for --insert (default: seeds.db)")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable JSON summary")
    args = ap.parse_args(argv)

    seeds_dir = Path(args.seeds_dir).resolve()
    cases, errors = load_cases(seeds_dir)

    if errors:
        sys.stderr.write(_c(f"\n{len(errors)} problem(s) found — FAILING:\n", RED))
        for err in errors:
            try:
                rel = err.path.relative_to(REPO_ROOT)
            except ValueError:
                rel = err.path
            sys.stderr.write(f"\n{_c('✗', RED)} {rel}\n    {err.message}\n")
        sys.stderr.write(_c(f"\n{len(cases)} case(s) parsed; refusing to proceed.\n", RED))
        return 1

    if args.json:
        print(json.dumps(summary_dict(cases), indent=2))
    else:
        print(_c(f"✓ all {len(cases)} seed cases valid", GREEN))
        print_summary(cases)

    if args.insert:
        n = insert_into_store(cases, args.db)
        print(_c(f"\n✓ inserted {n} case(s) into {args.db}", GREEN))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
