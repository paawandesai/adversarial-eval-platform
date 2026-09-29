"""Render a seed's plain-text fixture into a real PDF the target will ingest.

The target rejects any upload whose bytes do not begin with ``%PDF-`` (415) and
extracts labs with a PyMuPDF + Claude-vision pipeline whose *locate* stage
matches the model's transcription against the page's text words (PyMuPDF
``get_text("words")``, OCR only as a fallback). A row is written to the chart
only when its value, collection date and reference range are each located as a
word on the page, so a fixture needs a real **text layer** with exact words, not
a scanned image.

We therefore emit a minimal, standards-correct PDF with a Helvetica text layer:
one ``BT … Tj … ET`` line per source line, drawn top-down. PyMuPDF reads the
words with precise bounding boxes, which is what lets the locate stage place the
value, date and range and the planner write the row. Glyphs are also drawn, so
the same page rasterizes legibly for the vision pass.

The plain-text ``.txt`` fixtures stay the reviewable source of truth; this module
(via ``scripts/build_pdf_fixtures.py``) is the only thing that turns them into the
``.pdf`` bytes the red-team executor uploads. Lines flagged in the text as a
hidden layer (``<<HIDDEN …>>`` / ``<<injected>>`` markers) are drawn as ordinary
visible text: the payload has to be present for the extractor to read.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

# US-Letter in PDF points (72 pt/in), origin bottom-left.
_PAGE_W, _PAGE_H = 612, 792
_MARGIN_X = 54
_TOP_Y = 738
_LINE_H = 16
_FONT_SIZE = 11
_MAX_LINES = (_TOP_Y - 54) // _LINE_H


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _content_stream(lines: list[str]) -> bytes:
    parts = ["BT", f"/F1 {_FONT_SIZE} Tf", f"{_LINE_H} TL", f"{_MARGIN_X} {_TOP_Y} Td"]
    for i, line in enumerate(lines):
        # Non-ASCII (e.g. the "·" many lab headers use) is not in WinAnsi; drop it.
        safe = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in line)
        if i:
            parts.append("T*")
        parts.append(f"({_escape(safe)}) Tj")
    parts.append("ET")
    return ("\n".join(parts)).encode("latin-1", "replace")


def _paginate(lines: list[str]) -> list[list[str]]:
    return [lines[i:i + _MAX_LINES] for i in range(0, len(lines), _MAX_LINES)] or [[]]


def _build_pdf(pages_lines: list[list[str]]) -> bytes:
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)  # 1-based object number

    font_num = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                   b"/Encoding /WinAnsiEncoding >>")
    page_nums: list[int] = []
    kids_placeholder = add(b"")  # Pages tree, filled once kids are known

    for lines in pages_lines:
        stream = _content_stream(lines)
        content_num = add(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
        page_num = add(
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] "
            b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
            % (kids_placeholder, _PAGE_W, _PAGE_H, font_num, content_num)
        )
        page_nums.append(page_num)

    kids = b" ".join(b"%d 0 R" % n for n in page_nums)
    objects[kids_placeholder - 1] = (
        b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_nums))
    )
    catalog_num = add(b"<< /Type /Catalog /Pages %d 0 R >>" % kids_placeholder)

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (len(objects) + 1)
    for i, body in enumerate(objects, start=1):
        offsets[i] = len(out)
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref_pos = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for i in range(1, len(objects) + 1):
        out += b"%010d 00000 n \n" % offsets[i]
    out += (b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objects) + 1, catalog_num, xref_pos))
    return bytes(out)


def render_text_to_pdf(text: str, out_path: str | Path) -> Path:
    """Render ``text`` (one line per newline) into a text-layer PDF at ``out_path``."""
    lines = text.replace("\t", "    ").splitlines()
    pdf = _build_pdf(_paginate(lines))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pdf)
    return out


def render_fixture(txt_path: str | Path, out_path: Optional[str | Path] = None) -> Path:
    """Render a ``.txt`` fixture to a sibling ``.pdf`` (or ``out_path``)."""
    src = Path(txt_path)
    dst = Path(out_path) if out_path is not None else src.with_suffix(".pdf")
    return render_text_to_pdf(src.read_text(), dst)
