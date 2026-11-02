from __future__ import annotations

import hashlib
import unittest
import uuid
import zipfile
from pathlib import Path


SCANNER_SHA256 = "e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6"
DB_SHA256 = "8df9bbfa70f951082f9e00b8871a6ca628c4a8c58f3128594050033636429f50"


class OfflineOSVAdapterTests(unittest.TestCase):
    def test_refuses_unverified_binary(self):
        from static_worker.osv import OfflineOSVScanner

        binary = Path(".tmp") / f"fake-osv-{uuid.uuid4().hex}.exe"
        binary.write_bytes(b"untrusted")
        try:
            with self.assertRaisesRegex(ValueError, "scanner binary digest"):
                OfflineOSVScanner(binary, "0" * 64, Path(".tmp/osvdb"), DB_SHA256, Path(".tmp"))
        finally:
            binary.unlink()

    @unittest.skipUnless(
        Path(".tmp/osv-scanner.exe").exists() and Path(".tmp/osvdb/osv-scalibr/PyPI/all.zip").exists(),
        "pinned offline OSV fixture assets are not installed",
    )
    def test_guinea_pig_positive_corpus_offline(self):
        from static_worker.osv import OfflineOSVScanner
        from static_worker.worker import StaticJob, run_static_job

        workspace = Path(".tmp") / f"osv-job-{uuid.uuid4().hex}"
        workspace.mkdir(parents=True)
        archive = workspace / "source.zip"
        requirements = Path("guinea_pig/target/requirements.txt").read_bytes()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("requirements.txt", requirements)
        scanner = OfflineOSVScanner(
            Path(".tmp/osv-scanner.exe"), SCANNER_SHA256,
            Path(".tmp/osvdb"), DB_SHA256, workspace,
        )
        result = run_static_job(StaticJob(archive, workspace, True, "owned guinea-pig fixture"), scanner)
        self.assertGreaterEqual(len(result.findings), 4)
        self.assertTrue(all(finding.state == "detected" for finding in result.findings))
        self.assertTrue(all(finding.database_version == f"sha256:{DB_SHA256}" for finding in result.findings))
        (workspace / "source" / "requirements.txt").unlink()
        (workspace / "source").rmdir()
        (workspace / "osv-scanner.json").unlink()
        (workspace / "osv-results.json").unlink()
        archive.unlink()
        workspace.rmdir()


if __name__ == "__main__":
    unittest.main()
