"""Dependency-free PDF and DOCX export from persisted plain-text reports."""

from __future__ import annotations

import html
import textwrap
import zipfile
from io import BytesIO


def _visible_lines(markdown: str) -> list[str]:
    lines: list[str] = []
    for raw in markdown.splitlines():
        clean = "".join(char if char.isprintable() else " " for char in raw)
        lines.extend(textwrap.wrap(clean, width=95, break_long_words=True, replace_whitespace=False) or [""])
    return lines


def render_pdf(markdown: str) -> bytes:
    """Render a conservative text-only PDF with no embedded source markup."""
    visible = _visible_lines(markdown)
    pages = [visible[index:index + 52] for index in range(0, len(visible), 52)] or [[]]
    page_ids = [4 + index * 2 for index in range(len(pages))]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        ("<< /Type /Pages /Kids [" + " ".join(f"{number} 0 R" for number in page_ids)
         + f"] /Count {len(pages)} >>").encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for index, lines in enumerate(pages):
        page_id = page_ids[index]
        stream = [b"BT /F1 9 Tf 45 798 Td 13 TL"]
        for line in lines:
            safe = line.encode("latin-1", errors="replace").decode("latin-1")
            safe = safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            stream.append(f"({safe}) Tj T*".encode("latin-1"))
        stream.append(b"ET")
        content = b"\n".join(stream) + b"\n"
        objects.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                        f"/Resources << /Font << /F1 3 0 R >> >> /Contents {page_id + 1} 0 R >>").encode("ascii"))
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
    buffer.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return buffer.getvalue()


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
