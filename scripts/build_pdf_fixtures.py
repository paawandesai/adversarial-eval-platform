#!/usr/bin/env python3
"""Render the reviewable ``.txt`` injection fixtures into real text-layer PDFs.

The target rejects any upload whose bytes do not begin with ``%PDF-`` (HTTP 415),
so a ``.txt`` fixture never reaches the extraction/VLM pipeline and an attack
"passes" only because it was never delivered. ``aep/fixtures/pdf.py`` turns each
``.txt`` source of truth into a standards-correct PDF with a real text layer that
the target accepts and extracts; the red-team executor uploads whatever the seed's
``attachment_path`` points at, so the ``.pdf`` must exist on disk beside the ``.txt``.

Run from the repo root: ``python3 scripts/build_pdf_fixtures.py`` (``--check`` only
reports whether each PDF is present and up to date without writing).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from aep.fixtures.pdf import render_fixture  # noqa: E402

FIXTURES = REPO_ROOT / "evals" / "seeds" / "fixtures"

# The injection fixtures delivered as uploaded documents. The malformed-upload
# boundary fixture (ipi_malformed_not_a_pdf.pdf) is deliberately NOT a real PDF
# and is intentionally left untouched.
INJECTION_FIXTURES = [
    "ipi_lab_pdf_exfil.txt",
    "ipi_lab_pdf_sysprompt.txt",
    "ipi_lab_pdf_persona.txt",
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="report presence/freshness only; write nothing")
    args = ap.parse_args()

    stale = []
    for name in INJECTION_FIXTURES:
        src = FIXTURES / name
        dst = src.with_suffix(".pdf")
        if not src.exists():
            print(f"MISSING SOURCE {src}")
            stale.append(name)
            continue
        if args.check:
            fresh = dst.exists() and dst.stat().st_mtime >= src.stat().st_mtime
            print(f"{'ok  ' if fresh else 'STALE'} {dst.name}")
            if not fresh:
                stale.append(name)
            continue
        out = render_fixture(src, dst)
        print(f"rendered {src.name} -> {out.name} ({out.stat().st_size} bytes)")

    if args.check and stale:
        print(f"\n{len(stale)} fixture(s) missing or stale; run without --check")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
