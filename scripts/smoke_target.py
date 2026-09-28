#!/usr/bin/env python3
"""
Go/no-go smoke test against the LIVE Clinical Co-Pilot.

  1. authenticate as physician (OpenEMR password grant)
  2. one chat turn            POST /pre-visit-brief/conversation
  3. upload one sample doc    POST /documents  (+ one extraction status read)
  4. pre-visit brief          POST /pre-visit-brief

Exit 0 only if every step returns 2xx. Each step prints its status, latency
and correlation_id, so a failure can be looked up in the target's trace.

Required env:
  TARGET_OAUTH_CLIENT_ID, TARGET_OAUTH_CLIENT_SECRET   (or FHIR_CLIENT_ID / _SECRET)
Optional env:
  TARGET_BASE_URL   default https://64.177.42.210:8443
  TARGET_TOKEN_URL  default https://64.177.42.210:9300/oauth2/default/token
  TARGET_PATIENT_ID default below (seeded demo patient on the current host)
  TARGET_CA_BUNDLE  verify TLS against the agent's CA (else verification is off)

The sample document is a one-page PDF generated here, uploaded as
`intake_form` by default: the target writes a lab_pdf's extracted rows back
into the chart (its D54), and never an intake form's, so the smoke test
leaves the chart unchanged. Its bytes depend only on the patient id, so a
re-run is a duplicate upload (200, no new extraction) rather than new work.

Usage:
  python3 scripts/smoke_target.py [--patient UUID] [--doc PATH --doc-type lab_pdf]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# See platform/target/__init__.py for why `platform/` itself is the import root.
sys.path[:0] = [str(REPO), str(REPO / "platform")]

from target.client import (  # noqa: E402
    TargetAuthError,
    TargetClient,
    TargetConfig,
    TargetTransportError,
)

# Phil Belford on the deployed host (target repo agent/load-test/README.md).
DEFAULT_PATIENT_ID = "a2c36e54-af42-4c38-b86e-ade616ed5494"


def sample_pdf(text: str) -> bytes:
    """A minimal valid one-page PDF showing `text` (no dependencies)."""
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 72 720 Td ({safe}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


def excerpt(value: object, limit: int = 300) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[:limit] + f"... [{len(text)} chars]"


def report(step: str, result: dict, detail: object) -> bool:
    mark = "PASS" if result["ok"] else "FAIL"
    print(
        f"[{mark}] {step}: HTTP {result['status_code']} in {result['latency_ms']:.0f} ms "
        f"correlation_id={result['correlation_id']}"
    )
    print(f"       {excerpt(detail)}")
    return bool(result["ok"])


async def main(args: argparse.Namespace) -> int:
    config = TargetConfig.from_env()
    print(f"target {config.base_url}  patient {args.patient}  tls_verify={config.verify!r}")
    passed: list[bool] = []

    async with TargetClient(config, patient_id=args.patient) as client:
        try:
            await client.authenticate("physician")
        except TargetAuthError as exc:
            print(f"[FAIL] authenticate(physician): {exc}")
            return 1
        print(f"[PASS] authenticate(physician): granted scope {client.granted_scope!r}")

        try:
            chat = await client.chat(
                [{"role": "user", "content": "What active medications is this patient on?"}]
            )
            body = chat["body"] if isinstance(chat["body"], dict) else {}
            passed.append(
                report(
                    "chat",
                    chat,
                    {"turn_status": body.get("turn_status"), "answer": chat["text"]}
                    if chat["ok"]
                    else chat["body"],
                )
            )

            if args.doc:
                doc_path = Path(args.doc)
            else:
                doc_path = Path(tempfile.gettempdir()) / f"smoke-{args.patient}.pdf"
                doc_path.write_bytes(
                    sample_pdf(f"Adversarial platform smoke test document {args.patient}")
                )
            upload = await client.upload(args.patient, str(doc_path), args.doc_type)
            passed.append(report(f"upload ({args.doc_type})", upload, upload["body"]))
            if upload["ok"] and upload.get("document_id"):
                status = await client.extraction_status(args.patient, upload["document_id"])
                report("extraction status (informational)", status, status["body"])

            brief = await client.pre_visit_brief(args.patient)
            passed.append(
                report(
                    "pre_visit_brief",
                    brief,
                    {"verification": brief["body"].get("verification"), "brief": brief["text"]}
                    if brief["ok"]
                    else brief["body"],
                )
            )
        except TargetTransportError as exc:
            print(f"[FAIL] {exc.endpoint}: no response ({exc.cause!r}) correlation_id={exc.correlation_id}")
            return 1

    verdict = "GO" if all(passed) and len(passed) == 3 else "NO-GO"
    print(f"\n{verdict}: {sum(passed)}/3 endpoint checks passed")
    return 0 if verdict == "GO" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--patient", default=os.environ.get("TARGET_PATIENT_ID", DEFAULT_PATIENT_ID))
    parser.add_argument("--doc", help="PDF to upload instead of the generated sample")
    parser.add_argument("--doc-type", default="intake_form", choices=["intake_form", "lab_pdf"])
    sys.exit(asyncio.run(main(parser.parse_args())))
