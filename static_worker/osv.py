"""Pinned, offline OSV-Scanner adapter for normalized dependency inventory."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from .sbom import SbomArtifact


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class OfflineOSVScanner:
    """Scan a PentrAI-generated lockfile with a verified binary and database.

    This adapter still requires an isolated, egress-denied worker at deployment.
    The `--offline` flag is a second layer, not a substitute for network policy.
    """

    scanner_version = "2.6.0"

    def __init__(
        self,
        binary: Path,
        expected_binary_sha256: str,
        database_root: Path,
        expected_database_sha256: str,
        workspace: Path,
    ) -> None:
        self.binary = binary.resolve(strict=True)
        if _sha256(self.binary) != expected_binary_sha256.lower():
            raise ValueError("scanner binary digest mismatch")
        self.database_root = database_root.resolve(strict=True)
        database = self.database_root / "osv-scalibr" / "PyPI" / "all.zip"
        if not database.is_file() or _sha256(database) != expected_database_sha256.lower():
            raise ValueError("scanner database digest mismatch")
        self.database_version = f"sha256:{expected_database_sha256.lower()}"
        self.workspace = workspace.resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("scanner workspace must be a directory")

    def scan(self, sbom: SbomArtifact) -> dict:
        input_path = self.workspace / "osv-scanner.json"
        output_path = self.workspace / "osv-results.json"
        packages = [
            {"package": {"name": component["name"], "version": component["version"], "ecosystem": "PyPI"}}
            for component in sbom.document["components"]
        ]
        input_path.write_text(json.dumps({"results": [{"packages": packages}]}), encoding="utf-8")
        output_path.unlink(missing_ok=True)
        environment = os.environ.copy()
        environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(self.database_root)
        environment["GOMEMLIMIT"] = "1GiB"
        process = subprocess.run(
            [
                str(self.binary), "scan", "source", "--offline", "--no-resolve",
                "--lockfile", f"osv-scanner:{input_path}", "--format=json",
                "--output-file", str(output_path),
            ],
            cwd=self.workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if process.returncode not in {0, 1} or not output_path.is_file():
            raise RuntimeError(f"offline scanner failed with exit code {process.returncode}")
        if output_path.stat().st_size > 10 * 1024 * 1024:
            raise RuntimeError("offline scanner output exceeds limit")
        output = json.loads(output_path.read_text(encoding="utf-8"))
        if not isinstance(output, dict) or not isinstance(output.get("results"), list):
            raise RuntimeError("offline scanner returned invalid JSON")
        return output
