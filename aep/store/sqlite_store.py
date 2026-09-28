"""SqliteStore — SQLite persistence for the red-team platform (implements contracts.interfaces.Store).

Layout
------
Each contract model is stored whole as JSON in a ``body`` column. That column is the source of truth and
round-trips through Pydantic. A few denormalized columns sit next to it for the hot query paths:

    cases:      category, in_regression, severity           (severity = severity_if_success)
    runs:       case_id, target_version, correlation_id, cost_usd
    verdicts:   run_id, case_id, correlation_id, verdict
    reports:    repro_case_id, category, severity, status, first_seen_version, last_seen_version
    work_items: target_category, seed_case_id

Hot columns are always derived from ``body`` on write (see ``_ROW``), so they can be rebuilt from it.

Schema versioning / migrations
------------------------------
``meta`` holds two rows. ``schema_version`` is this database layout (an int, owned here).
``contract_schema_version`` is ``contracts.SCHEMA_VERSION``, recorded when the database was last opened.
On open, ``_migrate`` applies each ``MIGRATIONS`` entry above the stored ``schema_version``, in order and in
one transaction, then records the new version.

To add a field without losing data (e.g. ``AttackRun.redteam_model`` as a queryable column):
  1. In contracts, give the new field a default (``foo: Optional[str] = None``). Old JSON bodies still
     validate, and new writes carry it automatically. If nothing needs to query it, stop here: no table
     change is needed.
  2. To make it queryable, append a migration that only adds things:
         MIGRATIONS[2] = [
             "ALTER TABLE runs ADD COLUMN redteam_model TEXT",
             "UPDATE runs SET redteam_model = json_extract(body, '$.redteam_model')",
             "CREATE INDEX IF NOT EXISTS ix_runs_redteam_model ON runs(redteam_model)",
         ]
     and add the column to that table's ``_ROW`` function.
  ``ADD COLUMN`` leaves existing rows alone, and the backfill reads the JSON body, so nothing is lost.
  Never drop or rename a column in place. Add the new one, backfill it, and stop reading the old one.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from enum import Enum
from typing import Any, Callable, Iterable, Optional, Type, TypeVar, Union

from pydantic import BaseModel

from contracts.contracts import (
    SCHEMA_VERSION as CONTRACT_SCHEMA_VERSION,
    AttackCase, AttackCategory, AttackRun, JudgeVerdict, ReportStatus, Severity, Verdict,
    VulnerabilityReport, WorkItem,
)

_BASE_SCHEMA = [
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        in_regression INTEGER NOT NULL DEFAULT 0,
        severity TEXT NOT NULL,
        body TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_cases_category ON cases(category, in_regression)",
    "CREATE INDEX IF NOT EXISTS ix_cases_regression ON cases(in_regression, severity)",
    """CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        target_version TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        cost_usd REAL NOT NULL DEFAULT 0,
        body TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_runs_case ON runs(case_id, target_version)",
    "CREATE INDEX IF NOT EXISTS ix_runs_version ON runs(target_version)",
    "CREATE INDEX IF NOT EXISTS ix_runs_corr ON runs(correlation_id)",
    """CREATE TABLE IF NOT EXISTS verdicts (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        verdict TEXT NOT NULL,
        body TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_verdicts_run ON verdicts(run_id)",
    "CREATE INDEX IF NOT EXISTS ix_verdicts_case ON verdicts(case_id, verdict)",
    "CREATE INDEX IF NOT EXISTS ix_verdicts_corr ON verdicts(correlation_id)",
    """CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        repro_case_id TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        first_seen_version TEXT,
        last_seen_version TEXT,
        body TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_reports_sev ON reports(severity, category)",
    "CREATE INDEX IF NOT EXISTS ix_reports_last_seen ON reports(last_seen_version)",
    """CREATE TABLE IF NOT EXISTS work_items (
        id TEXT PRIMARY KEY,
        target_category TEXT NOT NULL,
        seed_case_id TEXT,
        body TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_work_items_category ON work_items(target_category)",
]

# version -> SQL statements that move the layout from version-1 to version. Only add things; see the module
# docstring. _BASE_SCHEMA is version 1.
MIGRATIONS: dict[int, list[str]] = {}
SCHEMA_VERSION = max(MIGRATIONS, default=1)


def _v(value: Any) -> Any:
    """Enum -> its value; bool -> int; everything else unchanged. The form hot columns are stored in."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bool):
        return int(value)
    return value


# Model -> hot-column values (every table also has ``id`` and ``body``).
_ROW: dict[str, Callable[[Any], dict[str, Any]]] = {
    "cases": lambda c: {
        "id": c.case_id, "category": _v(c.category), "in_regression": _v(c.in_regression_suite),
        "severity": _v(c.severity_if_success),
    },
    "runs": lambda r: {
        "id": r.run_id, "case_id": r.case_id, "target_version": r.target_version,
        "correlation_id": r.correlation_id, "cost_usd": r.cost_usd,
    },
    # JudgeVerdict has no id of its own, so each add is a new row with a minted id.
    "verdicts": lambda v: {
        "id": uuid.uuid4().hex, "run_id": v.run_id, "case_id": v.case_id,
        "correlation_id": v.correlation_id, "verdict": _v(v.verdict),
    },
    "reports": lambda r: {
        "id": r.vuln_id, "repro_case_id": r.repro_case_id, "category": _v(r.category),
        "severity": _v(r.severity), "status": _v(r.status),
        "first_seen_version": r.first_seen_version or None, "last_seen_version": r.last_seen_version or None,
    },
    "work_items": lambda w: {
        "id": w.work_id, "target_category": _v(w.target_category), "seed_case_id": w.seed_case_id,
    },
}

_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3,
                  Severity.CRITICAL: 4}
_SEVERITY_RANK_SQL = "CASE severity " + " ".join(
    f"WHEN '{s.value}' THEN {n}" for s, n in _SEVERITY_RANK.items()) + " END"

# A run judged by several oracles counts as its worst verdict: fail > partial > pass > error.
_WORST_RANK = {Verdict.ERROR: 1, Verdict.PASS: 2, Verdict.PARTIAL: 3, Verdict.FAIL: 4}
_WORST_RANK_SQL = "CASE v.verdict " + " ".join(
    f"WHEN '{s.value}' THEN {n}" for s, n in _WORST_RANK.items()) + " END"
_RANK_TO_VERDICT = {n: s for s, n in _WORST_RANK.items()}

M = TypeVar("M", bound=BaseModel)
SeverityLike = Union[Severity, str]


class SqliteStore:
    """Store over a single SQLite file (or ``":memory:"``). One connection, safe to share across threads."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._migrate()

    # ---- lifecycle -------------------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SqliteStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def meta(self, key: str) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    @property
    def schema_version(self) -> int:
        return int(self.meta("schema_version") or 0)

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def _migrate(self) -> None:
        with self._lock, _Transaction(self._conn):
            for stmt in _BASE_SCHEMA:
                self._conn.execute(stmt)
            current = self.schema_version or 1  # a fresh database has just been created at version 1
            for version in sorted(v for v in MIGRATIONS if v > current):
                for stmt in MIGRATIONS[version]:
                    self._conn.execute(stmt)
                current = version
            self._set_meta("schema_version", str(current))
            self._set_meta("contract_schema_version", CONTRACT_SCHEMA_VERSION)

    # ---- generic helpers -------------------------------------------------------------------------

    def _upsert(self, table: str, model: BaseModel) -> None:
        row = _ROW[table](model)
        row["body"] = model.model_dump_json()
        cols = list(row)
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
            f"ON CONFLICT(id) DO UPDATE SET {', '.join(f'{c} = excluded.{c}' for c in cols if c != 'id')}"
        )
        with self._lock, _Transaction(self._conn):
            self._conn.execute(sql, [row[c] for c in cols])

    def _get(self, table: str, model_cls: Type[M], id_: str) -> M:
        with self._lock:
            row = self._conn.execute(f"SELECT body FROM {table} WHERE id = ?", (id_,)).fetchone()
        if row is None:
            raise KeyError(f"{model_cls.__name__} {id_!r} not found")
        return model_cls.model_validate_json(row["body"])

    def _select(self, model_cls: Type[M], sql: str, params: Iterable[Any] = ()) -> list[M]:
        with self._lock:
            rows = self._conn.execute(sql, list(params)).fetchall()
        return [model_cls.model_validate_json(r["body"]) for r in rows]

    @staticmethod
    def _where(filters: dict[str, Any]) -> tuple[str, list[Any]]:
        """Equality filters, skipping None. Keys are column names (optionally ``alias.column``)."""
        pairs = [(col, _v(val)) for col, val in filters.items() if val is not None]
        if not pairs:
            return "", []
        return " WHERE " + " AND ".join(f"{col} = ?" for col, _ in pairs), [val for _, val in pairs]

    # ---- cases -----------------------------------------------------------------------------------

    def add_case(self, case: AttackCase) -> None:
        """Insert, or replace by case_id (e.g. to promote a case into the regression suite)."""
        self._upsert("cases", case)

    def get_case(self, case_id: str) -> AttackCase:
        return self._get("cases", AttackCase, case_id)

    def list_cases(self, category: Optional[str] = None, in_regression: Optional[bool] = None,
                   severity: Optional[SeverityLike] = None) -> list[AttackCase]:
        where, params = self._where(
            {"category": category, "in_regression": in_regression, "severity": severity}
        )
        return self._select(AttackCase, f"SELECT body FROM cases{where} ORDER BY rowid", params)

    # ---- runs ------------------------------------------------------------------------------------

    def add_run(self, run: AttackRun) -> None:
        self._upsert("runs", run)

    def get_run(self, run_id: str) -> AttackRun:
        return self._get("runs", AttackRun, run_id)

    def list_runs(self, case_id: Optional[str] = None, target_version: Optional[str] = None,
                  correlation_id: Optional[str] = None) -> list[AttackRun]:
        where, params = self._where(
            {"case_id": case_id, "target_version": target_version, "correlation_id": correlation_id}
        )
        return self._select(AttackRun, f"SELECT body FROM runs{where} ORDER BY rowid", params)

    # ---- verdicts --------------------------------------------------------------------------------

    def add_verdict(self, verdict: JudgeVerdict) -> None:
        """Always appends: verdicts have no id, and several oracles may judge the same run."""
        self._upsert("verdicts", verdict)

    def list_verdicts(self, case_id: Optional[str] = None, verdict: Optional[Verdict] = None,
                      run_id: Optional[str] = None, correlation_id: Optional[str] = None,
                      target_version: Optional[str] = None) -> list[JudgeVerdict]:
        where, params = self._where({
            "v.case_id": case_id, "v.verdict": verdict, "v.run_id": run_id,
            "v.correlation_id": correlation_id, "r.target_version": target_version,
        })
        sql = f"SELECT v.body FROM verdicts v LEFT JOIN runs r ON r.id = v.run_id{where} ORDER BY v.rowid"
        return self._select(JudgeVerdict, sql, params)

    # ---- regression ------------------------------------------------------------------------------

    def regression_results(self, target_version: str, category: Optional[str] = None,
                           severity: Optional[SeverityLike] = None) -> dict[str, Optional[Verdict]]:
        """Regression-suite cases -> worst verdict across their runs at ``target_version``.

        None means the case has not been run (or not judged) at that version yet. Compare two versions'
        results to spot regressions (PASS -> FAIL) and fixes (FAIL -> PASS).
        """
        where, params = self._where(
            {"c.in_regression": True, "c.category": category, "c.severity": severity}
        )
        sql = f"""
            SELECT c.id AS case_id, MAX({_WORST_RANK_SQL}) AS worst
            FROM cases c
            LEFT JOIN runs r ON r.case_id = c.id AND r.target_version = ?
            LEFT JOIN verdicts v ON v.run_id = r.id
            {where}
            GROUP BY c.id
            ORDER BY c.rowid
        """
        with self._lock:
            rows = self._conn.execute(sql, [target_version, *params]).fetchall()
        return {r["case_id"]: _RANK_TO_VERDICT.get(r["worst"]) for r in rows}

    # ---- reports ---------------------------------------------------------------------------------

    def add_report(self, report: VulnerabilityReport) -> None:
        """Insert, or replace by vuln_id (status changes, last_seen_version bumps)."""
        self._upsert("reports", report)

    def get_report(self, vuln_id: str) -> VulnerabilityReport:
        return self._get("reports", VulnerabilityReport, vuln_id)

    def list_reports(self, severity: Optional[SeverityLike] = None, category: Optional[str] = None,
                     status: Optional[ReportStatus] = None, first_seen_version: Optional[str] = None,
                     last_seen_version: Optional[str] = None,
                     min_severity: Optional[SeverityLike] = None) -> list[VulnerabilityReport]:
        """Filter reports. ``min_severity`` uses the order info < low < medium < high < critical, so "high"
        also returns critical ones."""
        where, params = self._where({
            "severity": severity, "category": category, "status": status,
            "first_seen_version": first_seen_version, "last_seen_version": last_seen_version,
        })
        if min_severity is not None:
            where += (" AND " if where else " WHERE ") + f"{_SEVERITY_RANK_SQL} >= ?"
            params.append(_SEVERITY_RANK[Severity(min_severity)])
        return self._select(VulnerabilityReport, f"SELECT body FROM reports{where} ORDER BY rowid", params)

    # ---- work items ------------------------------------------------------------------------------

    def add_work_item(self, item: WorkItem) -> None:
        self._upsert("work_items", item)

    def get_work_item(self, work_id: str) -> WorkItem:
        return self._get("work_items", WorkItem, work_id)

    def list_work_items(self, target_category: Optional[str] = None) -> list[WorkItem]:
        where, params = self._where({"target_category": target_category})
        return self._select(WorkItem, f"SELECT body FROM work_items{where} ORDER BY rowid", params)

    # ---- aggregates ------------------------------------------------------------------------------

    def coverage(self) -> dict:
        """``{category: {count, pass, fail, partial, cost_usd}}`` for every AttackCategory.

        count         number of runs of cases in that category. Categories with no runs are included with
                      zeros so the orchestrator can see the gaps.
        pass/fail/partial
                      runs whose *worst* verdict (fail > partial > pass > error) is that bucket. Runs that are
                      unjudged or only ERROR count toward ``count`` alone.
        cost_usd      total AttackRun.cost_usd for those runs.
        """
        sql = f"""
            WITH per_run AS (
                SELECT r.id, r.case_id, r.cost_usd, MAX({_WORST_RANK_SQL}) AS worst
                FROM runs r LEFT JOIN verdicts v ON v.run_id = r.id
                GROUP BY r.id
            )
            SELECT c.category AS category,
                   COUNT(p.id) AS count,
                   COALESCE(SUM(p.worst = {_WORST_RANK[Verdict.PASS]}), 0) AS pass,
                   COALESCE(SUM(p.worst = {_WORST_RANK[Verdict.FAIL]}), 0) AS fail,
                   COALESCE(SUM(p.worst = {_WORST_RANK[Verdict.PARTIAL]}), 0) AS partial,
                   COALESCE(SUM(p.cost_usd), 0.0) AS cost_usd
            FROM per_run p JOIN cases c ON c.id = p.case_id
            GROUP BY c.category
        """
        out = {cat.value: {"count": 0, "pass": 0, "fail": 0, "partial": 0, "cost_usd": 0.0}
               for cat in AttackCategory}
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        for r in rows:
            out[r["category"]] = {
                "count": r["count"], "pass": r["pass"], "fail": r["fail"], "partial": r["partial"],
                "cost_usd": float(r["cost_usd"]),
            }
        return out


class _Transaction:
    """BEGIN IMMEDIATE / COMMIT / ROLLBACK around a block (the connection is in autocommit mode)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._owner = False

    def __enter__(self) -> None:
        if not self._conn.in_transaction:
            self._conn.execute("BEGIN IMMEDIATE")
            self._owner = True

    def __exit__(self, exc_type: Any, *exc: Any) -> None:
        if self._owner:
            self._conn.execute("ROLLBACK" if exc_type else "COMMIT")
