"""Dependency-free PDF and DOCX export from persisted plain-text reports."""

from __future__ import annotations

import html
import textwrap
import zipfile
from io import BytesIO

from .report_pdf import render_pdf as render_pdf


def _visible_lines(markdown: str) -> list[str]:
    lines: list[str] = []
    for raw in markdown.splitlines():
        clean = "".join(char if char.isprintable() else " " for char in raw)
        lines.extend(textwrap.wrap(clean, width=95, break_long_words=True, replace_whitespace=False) or [""])
    return lines


def render_docx(markdown: str) -> bytes:
    """Build a minimal OOXML document with escaped text and no active content."""
    paragraphs = []
    for line in _visible_lines(markdown):
        safe = html.escape("".join(char if ord(char) >= 32 else " " for char in line), quote=False)
        paragraphs.append(f'<w:p><w:r><w:t xml:space="preserve">{safe}</w:t></w:r></w:p>')
    body = "".join(paragraphs)
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f'<w:body>{body}<w:sectPr/></w:body></w:document>')
    types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
             '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
             '<Default Extension="xml" ContentType="application/xml"/>'
             '<Override PartName="/word/document.xml" '
             'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
             '</Types>')
    relationships = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                     '<Relationship Id="rId1" '
                     'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                     'Target="word/document.xml"/></Relationships>')
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()
