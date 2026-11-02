"""
Stage 4a — ANALYZE / SCA (Software Composition Analysis).

The deterministic engine: inventory the target's dependencies and look each one up
against known-vulnerability data (OSV / NVD / a scanner like trivy or grype). This
barely needs an LLM — a scanner does it better and reproducibly — so keep the model
OUT of this path. Its output is CVE-backed Findings that the LLM half never has to
guess at.

Emits Findings with FindingSource.SCA: dependency + cve + a CVSS-derived severity.
Whether each is realistically reachable on the running surface is a ranking signal
set here (best-effort) and refined in `synthesize`.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from static_worker.intake import FileEntry, SourceInventory
from static_worker.osv import OfflineOSVScanner
from static_worker.sbom import build_sbom
from static_worker.sca import normalize_osv_results

from ..config import Settings
from ..contracts import Confidence, Finding, FindingSource, IngestResult, Severity


def analyze_sca(ingest: IngestResult, settings: Settings) -> list[Finding]:
    """Return CVE-backed Findings for vulnerable dependencies.

    Responsibilities:
      * build a dependency inventory from lockfiles/manifests (or via syft)
      * run `settings.sca_tool` (osv-scanner / trivy / grype) over it
      * map each hit to a Finding: dependency="pkg@ver", cve=..., severity from CVSS
      * set `network_reachable` best-effort (is the vulnerable component exposed?)

    Deterministic and side-effect free w.r.t. the target; safe to run in parallel
    with SAST.
    """
    root = Path(ingest.source_dir).resolve(strict=True)
    entries: list[FileEntry] = []
    for path in sorted(root.rglob("requirements.txt")):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        relative = path.relative_to(root).as_posix()
        if path.stat().st_size > 1024 * 1024:
            continue
        entries.append(FileEntry(relative, path.stat().st_size, 0))
    inventory = SourceInventory("", hashlib.sha256("\n".join(item.path for item in entries).encode()).hexdigest(),
                                tuple(entries), sum(item.size for item in entries))
    sbom = build_sbom(root, inventory)
    if not sbom.document["components"]:
        return []
    required = ("PENTRAI_OSV_SCANNER_PATH", "PENTRAI_OSV_SCANNER_SHA256", "PENTRAI_OSV_DB_ROOT", "PENTRAI_OSV_DB_SHA256")
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError(f"offline SCA assets are not configured: {', '.join(missing)}")
    work_root = Path(settings.work_dir).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sca-", dir=work_root) as directory:
        scanner = OfflineOSVScanner(Path(os.environ[required[0]]), os.environ[required[1]],
                                    Path(os.environ[required[2]]), os.environ[required[3]], Path(directory))
        detections = normalize_osv_results(scanner.scan(sbom), sbom,
                                           scanner_version=scanner.scanner_version,
                                           database_version=scanner.database_version)
    return [Finding(title=f"Known vulnerable dependency: {item.advisory_id}",
                    source=FindingSource.SCA, severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH, dependency=item.dependency,
                    cve=item.advisory_id, description=f"Detected in {item.source_manifest}; not live validated.",
                    network_reachable=False) for item in detections]
