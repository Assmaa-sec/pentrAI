"""Lay out a printable assessment from stored report text and recorded detections."""

from __future__ import annotations

import html
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from io import BytesIO


_PAGE_WIDTH = 595.28
_PAGE_HEIGHT = 841.89
_MARGIN = 50
_CONTENT_WIDTH = _PAGE_WIDTH - 2 * _MARGIN
_BODY_TOP = 84
_BODY_BOTTOM = 774

_NAVY = "101F32"
_PANEL = "1A3449"
_TEAL = "006F69"
_BRIGHT_TEAL = "65D5CB"
_INK = "22364A"
_MUTED = "536A7D"
_COVER_MUTED = "BCD0DE"
_SURFACE = "F1F6F7"
_RULE = "D7E2E8"
_WHITE = "FFFFFF"

_REGULAR = "Helvetica"
_BOLD = "Helvetica-Bold"
_MONO = "Courier"
_FONTS = (_REGULAR, _BOLD, _MONO)

# Upper bounds in thousandths of an em for the two Helvetica weights.
_GLYPH_WIDTH = {
    glyph: width
    for width, glyphs in (
        (350, b" !'(),-./:;I[\\]fijlt|"),
        (500, b'"*r\x60{}'),
        (625, b"#$+0123456789<=>?_abcdeghknopqsuvxyz"),
        (825, b"ABCDEFGHJKLNOPQRSTUVXYZ^w~"),
    )
    for glyph in glyphs
}

_SEVERITY_COLORS = {
    "critical": ("861A42", "F8E7ED"),
    "high": ("9B301B", "FAEBE5"),
    "medium": ("805000", "FFF3D9"),
    "low": ("245583", "EAF2FA"),
    "info": (_MUTED, _SURFACE),
}
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+)")
_FENCE = re.compile(r"^(\x60{3,}|~{3,})[^\x60~]*$")
_STATIC_ESCAPE = re.compile(r"\\([\\\x60*_{}\[\]()#+.!|>~-])")
_STATIC_TITLE = "PentrAI source assessment"
_FIELDS = {
    "Scope", "Posture", "Source", "Manifest", "Scanner version", "Outcome", "Severity",
    "CWE", "Location", "Description", "Notes", "Evidence", "Observed result", "HexStrike tool calls",
}
_DIGEST_FIELDS = {"Evidence SHA-256", "Scanner output SHA-256"}


@dataclass(frozen=True)
class _Type:
    font: str
    size: int
    leading: int
    color: str


_BODY = _Type(_REGULAR, 11, 16, _INK)
_PAGE_TITLE = _Type(_BOLD, 26, 32, _NAVY)
_SECTION = _Type(_BOLD, 18, 24, _NAVY)
_SUBHEADING = _Type(_BOLD, 13, 18, _NAVY)
_PREVIEW_TITLE = _Type(_BOLD, 11, 15, _INK)
_LABEL = _Type(_BOLD, 9, 12, _TEAL)
_FOOTER = _Type(_REGULAR, 9, 12, _MUTED)
_CODE = _Type(_MONO, 10, 15, _WHITE)


def _encode(value: str) -> bytes:
    return "".join(char if char.isprintable() else " " for char in value).encode("cp1252", "replace")


def _advance(glyph: int, font: str) -> int:
    return 600 if font == _MONO else _GLYPH_WIDTH.get(glyph, 1040)


def _wrap(text: str, width: float, style: _Type) -> list[bytes]:
    encoded = _encode(text)
    if not encoded:
        return [b""]
    limit = width * 1000 / style.size
    if style.font == _MONO:
        columns = int(limit // 600)
        return [encoded[index:index + columns] for index in range(0, len(encoded), columns)]

    lines = []
    start = 0
    while start < len(encoded):
        end, last_space, used = start, start, 0
        while end < len(encoded):
            glyph = encoded[end]
            used += _advance(glyph, style.font)
            if used > limit and end > start:
                break
            if glyph == 32:
                last_space = end
            end += 1
        if end < len(encoded) and last_space > start and encoded[end] != 32:
            end = last_space
        lines.append(encoded[start:end].rstrip())
        start = end
        while start < len(encoded) and encoded[start] == 32:
            start += 1
    return lines


def _rgb(color: str) -> str:
    return " ".join(f"{int(color[index:index + 2], 16) / 255:.4f}" for index in (0, 2, 4))


def _text(page: list[bytes], x: float, y: float, value: str | bytes, style: _Type, *, right=False) -> None:
    encoded = _encode(value) if isinstance(value, str) else value
    if right:
        x -= sum(_advance(glyph, style.font) for glyph in encoded) * style.size / 1000
    literal = encoded.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    baseline = _PAGE_HEIGHT - y - style.size
    page.append(
        f"BT /{style.font} {style.size} Tf {_rgb(style.color)} rg {x:.2f} {baseline:.2f} Td (".encode("ascii")
        + literal + b") Tj ET"
    )


def _box(page: list[bytes], x: float, y: float, width: float, height: float, color: str, radius=0) -> None:
    top = _PAGE_HEIGHT - y
    bottom = top - height
    fill = _rgb(color)
    if not radius:
        page.append(f"{fill} rg {x:.2f} {bottom:.2f} {width:.2f} {height:.2f} re f".encode("ascii"))
        return

    right = x + width
    corner = radius * 0.552285
    path = (
        f"{x + radius:.2f} {bottom:.2f} m {right - radius:.2f} {bottom:.2f} l "
        f"{right-radius+corner:.2f} {bottom:.2f} {right:.2f} {bottom+radius-corner:.2f} "
        f"{right:.2f} {bottom+radius:.2f} c {right:.2f} {top-radius:.2f} l "
        f"{right:.2f} {top-radius+corner:.2f} {right-radius+corner:.2f} {top:.2f} "
        f"{right-radius:.2f} {top:.2f} c {x+radius:.2f} {top:.2f} l "
        f"{x+radius-corner:.2f} {top:.2f} {x:.2f} {top-radius+corner:.2f} "
        f"{x:.2f} {top-radius:.2f} c {x:.2f} {bottom+radius:.2f} l "
        f"{x:.2f} {bottom+radius-corner:.2f} {x+radius-corner:.2f} {bottom:.2f} "
        f"{x+radius:.2f} {bottom:.2f} c h"
    )
    page.append(f"{fill} rg {path} f".encode("ascii"))


def _severity_badge(page: list[bytes], x: float, y: float, severity: str | None) -> None:
    label = severity or "Unspecified"
    if label not in _SEVERITY_COLORS:
        label = "Unspecified"
    ink, surface = _SEVERITY_COLORS.get(label, (_MUTED, "E4EDF1"))
    _box(page, x, y, 76, 20, surface, radius=10)
    _text(page, x + 10, y + 4, label.upper(), replace(_LABEL, color=ink))


def _cover(is_static: bool, assessment_id: str, report_date: date | None, total: int | None) -> list[bytes]:
    page: list[bytes] = []
    _box(page, 0, 0, _PAGE_WIDTH, _PAGE_HEIGHT, _NAVY)
    _box(page, 0, 0, _PAGE_WIDTH, 9, _BRIGHT_TEAL)
    _box(page, _MARGIN, 74, 52, 52, _BRIGHT_TEAL, radius=10)
    _text(page, _MARGIN + 16, 81, "P", _Type(_BOLD, 31, 38, _NAVY))
    _text(page, _MARGIN + 69, 84, "PentrAI", _Type(_BOLD, 25, 32, _WHITE))
    _text(page, _MARGIN, 195, "SOURCE CODE REVIEW" if is_static else "SECURITY REVIEW",
          replace(_LABEL, color=_BRIGHT_TEAL))
    title = _Type(_BOLD, 40, 45, _WHITE)
    _text(page, _MARGIN, 263, "Security assessment", title)
    _text(page, _MARGIN, 308, "report", title)

    label = replace(_LABEL, color=_COVER_MUTED)
    if assessment_id:
        _box(page, _MARGIN, 432, _CONTENT_WIDTH, 84, _PANEL, radius=10)
        _text(page, _MARGIN + 20, 451, "ASSESSMENT ID", label)
        _text(page, _MARGIN + 20, 473, assessment_id, _Type(_MONO, 14, 20, _WHITE))
    if report_date is not None:
        _text(page, _MARGIN, 568, "REPORT DATE", label)
        _text(page, _MARGIN, 591, report_date.isoformat(), _Type(_REGULAR, 12, 16, _WHITE))
    if total is not None:
        x = _MARGIN + 200 if report_date is not None else _MARGIN
        _text(page, x, 568, "DETECTED FINDINGS", label)
        _text(page, x, 585, str(total), _Type(_BOLD, 21, 26, _WHITE))
    _box(page, _MARGIN, 730, _CONTENT_WIDTH, 1.5, _BRIGHT_TEAL)
    return page


class _Layout:
    def __init__(self, cover: list[bytes]):
        self.pages = [cover]
        self.new_page()

    @property
    def page(self) -> list[bytes]:
        return self.pages[-1]

    def new_page(self) -> None:
        self.pages.append([])
        self.y = _BODY_TOP
        _box(self.page, 0, 0, _PAGE_WIDTH, 8, _NAVY)
        _text(self.page, _MARGIN, 25, "PentrAI", _Type(_BOLD, 17, 22, _NAVY))
        _text(self.page, _PAGE_WIDTH - _MARGIN, 29, "SECURITY REVIEW", _LABEL, right=True)
        _box(self.page, _MARGIN, 58, _CONTENT_WIDTH, 0.75, _RULE)

    def reserve(self, height: float) -> None:
        if self.y + height > _BODY_BOTTOM and self.y > _BODY_TOP:
            self.new_page()

    def lines(self, lines: list[bytes], style: _Type, *, indent=0, gap=0) -> None:
        for line in lines:
            self.reserve(style.leading)
            _text(self.page, _MARGIN + indent, self.y, line, style)
            self.y += style.leading
        self.y += gap

    def heading(self, value: str, style: _Type, *, before=0, after=10) -> None:
        lines = _wrap(value, _CONTENT_WIDTH, style)
        self.reserve(before + len(lines) * style.leading + after + 2 * _BODY.leading + 4)
        self.y += before
        self.lines(lines, style, gap=after)

    def paragraph(self, value: str, *, bullet=False) -> None:
        indent = 14 if bullet else 0
        lines = _wrap(value, _CONTENT_WIDTH - indent, _BODY)
        self.reserve(min(2, len(lines)) * _BODY.leading)
        if bullet:
            _text(self.page, _MARGIN, self.y, "•", replace(_BODY, color=_TEAL))
        self.lines(lines, _BODY, indent=indent, gap=3)

    def field(self, name: str, value: str) -> None:
        indent = 116
        if name == "Severity" and value in _SEVERITY_COLORS:
            self.reserve(20)
            _text(self.page, _MARGIN, self.y + 4, name.upper(), _LABEL)
            _severity_badge(self.page, _MARGIN + indent, self.y, value)
            self.y += 23
            return
        lines = _wrap(value, _CONTENT_WIDTH - indent, _BODY)
        self.reserve(min(2, len(lines)) * _BODY.leading)
        _text(self.page, _MARGIN, self.y + 2, name.upper(), _LABEL)
        self.lines(lines, _BODY, indent=indent, gap=3)

    def summary(self, counts: Mapping[str | None, int]) -> None:
        total = sum(counts.values())
        severities = [(name.title(), counts.get(name, 0), colors[0])
                      for name, colors in _SEVERITY_COLORS.items() if counts.get(name, 0)]
        unspecified = total - sum(count for _, count, _ in severities)
        if unspecified:
            severities.append(("Unspecified", unspecified, _MUTED))
        self.reserve(96)
        _box(self.page, _MARGIN, self.y, _CONTENT_WIDTH, 76, _SURFACE, radius=9)
        _text(self.page, _MARGIN + 16, self.y + 8, str(total), _Type(_BOLD, 28, 34, _NAVY))
        _text(self.page, _MARGIN + 16, self.y + 50, "DETECTED FINDINGS", _LABEL)
        if severities:
            start = _MARGIN + 160
            step = min(126, (_CONTENT_WIDTH - 172) / len(severities))
            _box(self.page, start - 16, self.y + 16, 0.75, 44, _RULE)
            for index, (label, count, ink) in enumerate(severities):
                x = start + index * step
                _text(self.page, x, self.y + 13, str(count), _Type(_BOLD, 22, 26, ink))
                _text(self.page, x, self.y + 50, label, replace(_LABEL, color=ink))
        self.y += 96

    def findings_preview(self, detections: Sequence[tuple[str, str | None]]) -> None:
        priority = {severity: rank for rank, severity in enumerate(_SEVERITY_COLORS)}
        preview = sorted(detections, key=lambda finding: priority.get(finding[1] or "", len(priority)))[:4]
        self.reserve(124)
        self.heading("Findings at a glance", _SECTION, before=12)
        for title, severity in preview:
            indent = 106
            title = " ".join(title.split())
            if len(title) > 115:
                title = title[:114].rstrip() + "…"
            lines = _wrap(title, _CONTENT_WIDTH - indent - 14, _PREVIEW_TITLE)
            height = max(40, len(lines) * _PREVIEW_TITLE.leading + 18)
            self.reserve(height)
            _box(self.page, _MARGIN, self.y, _CONTENT_WIDTH, height, _SURFACE, radius=8)
            _severity_badge(self.page, _MARGIN + 12, self.y + (height - 20) / 2, severity)
            y = self.y + (height - len(lines) * _PREVIEW_TITLE.leading) / 2
            for index, line in enumerate(lines):
                _text(self.page, _MARGIN + indent, y + index * _PREVIEW_TITLE.leading, line, _PREVIEW_TITLE)
            self.y += height + 6
        if len(detections) > len(preview):
            self.lines([_encode(f"Showing {len(preview)} of {len(detections)} detections")], _FOOTER)

    def evidence(self, label: str, values: list[str]) -> None:
        lines = [line for value in values for line in _wrap(value, _CONTENT_WIDTH - 32, _CODE)]
        index = 0
        while index < len(lines):
            self.reserve(42 + min(len(lines) - index, 2) * _CODE.leading)
            slots = int((_BODY_BOTTOM - self.y - 42) // _CODE.leading)
            chunk = lines[index:index + slots]
            height = 42 + len(chunk) * _CODE.leading
            _box(self.page, _MARGIN, self.y, _CONTENT_WIDTH, height, _PANEL, radius=8)
            _text(self.page, _MARGIN + 16, self.y + 10, label.upper(), replace(_LABEL, color=_BRIGHT_TEAL))
            for offset, line in enumerate(chunk):
                _text(self.page, _MARGIN + 16, self.y + 28 + offset * _CODE.leading, line, _CODE)
            index += len(chunk)
            self.y += height + 10

    def footers(self, assessment_id: str) -> None:
        for number, page in enumerate(self.pages[1:], 2):
            _box(page, _MARGIN, 793, _CONTENT_WIDTH, 0.75, _RULE)
            if assessment_id:
                _text(page, _MARGIN, 803, assessment_id, _FOOTER)
            _text(page, _PAGE_WIDTH - _MARGIN, 803, f"{number} / {len(self.pages)}", _FOOTER, right=True)


def _display(text: str, is_static: bool) -> str:
    if is_static:
        text = _STATIC_ESCAPE.sub(r"\1", text)
    return html.unescape(text)


def _report_body(layout: _Layout, lines: list[str], *, is_static: bool, is_runner: bool) -> None:
    fence = ""
    code: list[str] = []
    for raw in lines:
        line = raw.strip()
        if fence:
            if len(line) >= len(fence) and line == fence[0] * len(line):
                layout.evidence("Code excerpt", code)
                code = []
                fence = ""
            else:
                code.append((html.unescape(raw) if is_runner else raw).expandtabs(4))
            continue
        opening = _FENCE.fullmatch(line)
        if opening:
            fence = opening[1]
            continue
        if not line:
            layout.y += 4
            continue
        heading = _HEADING.fullmatch(line)
        if heading:
            depth = len(heading[1])
            value = _display(heading[2], is_static)
            layout.heading(value, _SECTION if depth <= 2 else _SUBHEADING, before=10)
            continue
        name, separator, value = line.partition(": ")
        if separator and name in _DIGEST_FIELDS:
            layout.evidence(name, _display(value, is_static).split(", "))
        elif separator and name in _FIELDS:
            layout.field(name, _display(value, is_static))
        else:
            bullet = line.startswith(("- ", "* ", "+ "))
            layout.paragraph(_display(line[2:] if bullet else line, is_static), bullet=bullet)
    if fence:
        layout.evidence("Code excerpt", code)


def _report_sections(lines: list[str], *, is_static: bool, is_runner: bool) -> tuple[list[str], list[str]]:
    for index, line in enumerate(lines):
        if is_runner and line.startswith("## "):
            return lines[:index], lines[index:]
        if is_static and line == "## Detected findings":
            details = lines[index + 1:]
            if any(line.startswith("### ") for line in details):
                return lines[:index], details
            break
    return lines, []


def _pdf_bytes(pages: list[list[bytes]]) -> bytes:
    first_page = 4 + len(_FONTS)
    page_ids = range(first_page, first_page + 2 * len(pages), 2)
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    fonts = " ".join(f"/{font} {index} 0 R" for index, font in enumerate(_FONTS, 4))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /Lang (en) >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii"),
        b"<< /Title (PentrAI Security Assessment Report) /Creator (PentrAI) >>",
    ]
    objects.extend(
        f"<< /Type /Font /Subtype /Type1 /BaseFont /{font} /Encoding /WinAnsiEncoding >>".encode("ascii")
        for font in _FONTS
    )
    for page_id, page in zip(page_ids, pages, strict=True):
        content = b"\n".join(page) + b"\n"
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_WIDTH} {_PAGE_HEIGHT}] "
            f"/Resources << /Font << {fonts} >> >> /Contents {page_id + 1} 0 R >>".encode("ascii")
        )
        objects.append(f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"endstream")

    buffer = BytesIO()
    buffer.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(buffer.tell())
        buffer.write(f"{index} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
    xref = buffer.tell()
    buffer.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    buffer.write(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R /Info 3 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return buffer.getvalue()


def render_pdf(
    markdown: str,
    *,
    assessment_id: str = "",
    report_date: date | None = None,
    detections: Sequence[tuple[str, str | None]] | None = None,
) -> bytes:
    """Export stored Markdown as inert text with report-specific typography."""
    lines = markdown.strip().splitlines()
    title = ""
    if lines and lines[0].startswith("# "):
        title = lines.pop(0)[2:].strip()
    is_static = title == _STATIC_TITLE
    is_runner = title == "PentrAI assessment" and any(line.startswith("HexStrike tool calls: ") for line in lines)
    total = len(detections) if detections is not None else None
    layout = _Layout(_cover(is_static, assessment_id, report_date, total))
    heading = "Assessment overview" if not title or is_static or is_runner else _display(title, is_static)
    layout.heading(heading, _PAGE_TITLE, after=16)
    if detections is not None:
        layout.summary(Counter(severity for _, severity in detections))
    overview, details = _report_sections(lines, is_static=is_static, is_runner=is_runner)
    _report_body(layout, overview, is_static=is_static, is_runner=is_runner)
    if details:
        if detections:
            layout.findings_preview(detections)
        layout.new_page()
        layout.heading("Detected findings" if is_static else "Finding details", _PAGE_TITLE)
        _report_body(layout, details, is_static=is_static, is_runner=is_runner)
    if not lines and not title:
        layout.paragraph("No report text was recorded.")
    layout.footers(assessment_id)
    return _pdf_bytes(layout.pages)
