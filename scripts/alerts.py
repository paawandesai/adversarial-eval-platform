#!/usr/bin/env python3
"""Evaluate the platform alerts over the store (read-only). Definitions: aep/alerts.py; on-call: docs/ALERTS.md.

    python3 scripts/alerts.py                              # seeds.db, last 24 h, thresholds from ALERT_* env
    python3 scripts/alerts.py --db campaign.db --all       # every run in the store
    python3 scripts/alerts.py --p95-ms 30000 --error-rate 0.2 --target-failure-rate 0.1 --json

Exit codes (so cron or CI can page on it):
  0  nothing firing (insufficient_data counts as not firing)
  1  at least one alert firing
  2  bad configuration, or no store at --db

The store is opened with SqliteStore.open_readonly (SQLite mode=ro); nothing here can write to it.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from aep.alerts import evaluate, format_text, settings_from_env  # noqa: E402
from aep.store.sqlite_store import SqliteStore  # noqa: E402

EXIT_OK, EXIT_FIRING, EXIT_ERROR = 0, 1, 2


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", default="seeds.db", help="SQLite store path (default: seeds.db)")
    p.add_argument("--p95-ms", type=float, help="p95 run latency threshold in ms (ALERT_P95_LATENCY_MS)")
    p.add_argument("--error-rate", type=float, help="error-rate threshold, 0-1 (ALERT_ERROR_RATE)")
    p.add_argument("--target-failure-rate", type=float,
                   help="tool/target failure-rate threshold, 0-1 (ALERT_TARGET_FAILURE_RATE)")
    p.add_argument("--window-hours", type=float, help="look-back window (ALERT_WINDOW_HOURS, default 24)")
    p.add_argument("--all", action="store_true", help="every run in the store, no window")
    p.add_argument("--min-samples", type=int, help="fewer runs than this is insufficient_data (ALERT_MIN_SAMPLES)")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = p.parse_args(argv)

    try:
        settings = settings_from_env(
            p95_latency=args.p95_ms, error_rate=args.error_rate, target_failure_rate=args.target_failure_rate,
            window_hours=0.0 if args.all else args.window_hours, min_samples=args.min_samples)
    except ValueError as exc:
        print(f"alerts: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not pathlib.Path(args.db).exists():
        print(f"alerts: no database at {args.db}", file=sys.stderr)
        return EXIT_ERROR

    with SqliteStore.open_readonly(args.db) as store:
        results = evaluate(store, settings)
    if args.json:
        print(json.dumps({"window_hours": settings.window_hours, "min_samples": settings.min_samples,
                          "alerts": [r.to_dict() for r in results]}, indent=2))
    else:
        print(format_text(results, settings))
    return EXIT_FIRING if any(r.firing for r in results) else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
