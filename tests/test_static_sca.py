from __future__ import annotations

import unittest
import uuid
import zipfile
from pathlib import Path


class StaticScaTests(unittest.TestCase):
    def setUp(self):
        from static_worker.intake import IntakeLimits, extract_archive, inspect_archive

        self.root = Path(".tmp") / f"sca-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True)
        self.archive = self.root / "source.zip"
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("requirements.txt", "Flask==2.0.3\n# comment\nrequests>=2\n")
        self.inventory = inspect_archive(self.archive, IntakeLimits())
        self.source = extract_archive(self.archive, self.root, IntakeLimits())

    def tearDown(self):
        (self.source / "requirements.txt").unlink()
        self.source.rmdir()
        self.archive.unlink()
        self.root.rmdir()

    def test_sbom_includes_only_exact_pins_and_records_partial_coverage(self):
        from static_worker.sbom import build_sbom

        sbom = build_sbom(self.source, self.inventory)
        self.assertEqual("CycloneDX", sbom.document["bomFormat"])
        self.assertEqual("pkg:pypi/flask@2.0.3", sbom.document["components"][0]["purl"])
        self.assertIn("requests>=2", sbom.unresolved)

    def test_osv_result_stays_detected_with_provenance(self):
        from static_worker.sbom import build_sbom
        from static_worker.sca import normalize_osv_results

        sbom = build_sbom(self.source, self.inventory)
        scanner_output = {
            "results": [{"source": {"type": "lockfile", "path": "requirements.txt"}, "packages": [
                {"package": {"name": "Flask", "version": "2.0.3", "ecosystem": "PyPI"},
                 "vulnerabilities": [{"id": "GHSA-test", "aliases": ["CVE-2024-0001"]}]}
            ]}]
        }
        findings = normalize_osv_results(scanner_output, sbom, scanner_version="2.0.0", database_version="2026-10-03")
        self.assertEqual(1, len(findings))
        self.assertEqual("detected", findings[0].state)
        self.assertEqual("CVE-2024-0001", findings[0].advisory_id)
        self.assertEqual("Flask@2.0.3", findings[0].dependency)
        self.assertEqual("2.0.0", findings[0].scanner_version)


if __name__ == "__main__":
    unittest.main()
