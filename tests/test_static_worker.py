from __future__ import annotations

import unittest
import uuid
import zipfile
from pathlib import Path


class FakeScanner:
    scanner_version = "2.0.0"
    database_version = "2026-10-03"

    def scan(self, sbom):
        return {"results": [{"packages": [{
            "package": {"name": "Flask", "version": "2.0.3", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "GHSA-test", "aliases": ["CVE-2024-0001"]}],
        }]}]}


class StaticWorkerTests(unittest.TestCase):
    def test_authorized_archive_produces_detected_report(self):
        from static_worker.worker import StaticJob, run_static_job

        root = Path(".tmp") / f"job-{uuid.uuid4().hex}"
        root.mkdir(parents=True)
        archive_path = root / "source.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("requirements.txt", "Flask==2.0.3\n")
        result = run_static_job(
            StaticJob(archive_path=archive_path, workspace=root, authorized=True, scope="internal fixture"),
            FakeScanner(),
        )
        self.assertEqual("detected", result.findings[0].state)
        self.assertIn("CVE\\-2024\\-0001", result.report_markdown)
        self.assertIn("not live validated", result.report_markdown)
        (root / "source" / "requirements.txt").unlink()
        (root / "source").rmdir()
        archive_path.unlink()
        root.rmdir()

    def test_unauthorized_job_never_extracts(self):
        from static_worker.worker import StaticJob, run_static_job

        root = Path(".tmp") / f"job-{uuid.uuid4().hex}"
        root.mkdir(parents=True)
        with self.assertRaisesRegex(PermissionError, "authorization"):
            run_static_job(
                StaticJob(archive_path=root / "missing.zip", workspace=root, authorized=False, scope=""),
                FakeScanner(),
            )
        self.assertFalse((root / "source").exists())
        root.rmdir()


if __name__ == "__main__":
    unittest.main()
