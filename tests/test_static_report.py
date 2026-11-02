from __future__ import annotations

import unittest


class StaticReportTests(unittest.TestCase):
    def test_untrusted_package_and_advisory_cannot_inject_html_or_claim_confirmation(self):
        from static_worker.report import render_static_report
        from static_worker.sca import DetectedFinding

        finding = DetectedFinding(
            state="detected",
            source="sca",
            dependency="evil<script>alert(1)</script>@1",
            advisory_id="CVE-2024-0001",
            source_manifest="requirements.txt",
            scanner_version="2.0",
            database_version="2026-10-03",
            scanner_output_sha256="a" * 64,
        )
        report = render_static_report([finding], scope="internal app", unresolved=("unparsed manifest",))
        self.assertNotIn("<script>", report)
        self.assertIn("detected", report.lower())
        self.assertIn("not live validated", report.lower())
        self.assertIn("unparsed manifest", report)
        self.assertNotIn("completely secure", report.lower())


if __name__ == "__main__":
    unittest.main()
