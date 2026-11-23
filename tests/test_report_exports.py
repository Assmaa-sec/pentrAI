from __future__ import annotations

import re
import unittest
from datetime import date

from control_plane.report_exports import render_pdf


def _page_streams(pdf: bytes) -> list[bytes]:
    return re.findall(rb"\nstream\n(.*?)\nendstream\n", pdf, re.DOTALL)


class ReportPdfTests(unittest.TestCase):
    def test_preview_uses_recorded_detections_and_details_preserve_evidence(self):
        digest = "a" * 64
        markdown = (
            "# PentrAI assessment\n\n"
            "The findings require validation within the assessed scope.\n\n"
            "HexStrike tool calls: 3.\n\n"
            "## Review the dependency lockfile\n\n"
            "Severity: medium\n\n"
            f"Evidence SHA-256: {digest}\n"
        )
        cover, overview, details = _page_streams(render_pdf(
            markdown, assessment_id="example-assessment", report_date=date(2026, 11, 23),
            detections=[("Review the dependency lockfile", "medium")],
        ))
        self.assertIn(b"(2026-11-23)", cover)
        self.assertIn(b"(Findings at a glance)", overview)
        self.assertIn(b"(Review the dependency lockfile)", overview)
        self.assertIn(b"(Medium)", overview)
        self.assertIn(b"(The findings require validation within the assessed scope.)", overview)
        self.assertIn(b"(Finding details)", details)
        self.assertIn(digest.encode("ascii"), details)
        self.assertIn(b"(3 / 3)", details)

    def test_zero_detections_keep_coverage_and_escaped_scope_visible(self):
        markdown = (
            "# PentrAI source assessment\n\n"
            r"Scope: Sample\-archive\.zip &amp; notes" + "\n\n"
            "## Coverage and limitations\n\n"
            "Only supported manifests were examined.\n\n"
            "## Detected findings\n\n"
            "No findings were detected within the stated coverage.\n"
        )
        cover, overview = _page_streams(render_pdf(markdown, detections=[]))
        self.assertIn(b"(0)", cover)
        self.assertIn(b"(Sample-archive.zip & notes)", overview)
        self.assertIn(b"(Coverage and limitations)", overview)
        self.assertIn(b"(No findings were detected within the stated coverage.)", overview)

    def test_legacy_text_and_long_code_blocks_survive_pagination(self):
        fence = "\x60" * 3
        code_lines = [f"    note-{index:03d}" for index in range(100)]
        markdown = "\n".join([
            "# Older assessment",
            "",
            r"Recorded (notes)\draft &lt;example&gt;",
            fence,
            *code_lines,
            fence,
            "",
            "End of report.",
        ])
        pdf = render_pdf(markdown)
        pages = _page_streams(pdf)
        self.assertGreater(len(pages), 3)
        self.assertIn(rb"(Recorded \(notes\)\\draft <example>)", pages[1])
        for line in code_lines:
            self.assertEqual(1, pdf.count(f"({line})".encode("ascii")))
        self.assertIn(b"(End of report.)", pages[-1])
        self.assertIn(f"({len(pages)} / {len(pages)})".encode("ascii"), pages[-1])


if __name__ == "__main__":
    unittest.main()
