"""Authorized, static-only archive-to-report workflow.

The scanner receives a normalized SBOM, never the customer source directory.
The production caller must run this module in the isolated static worker.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .intake import IntakeLimits, SourceInventory, extract_archive, inspect_archive
from .report import render_static_report
from .sbom import SbomArtifact, build_sbom
from .sca import DetectedFinding, normalize_osv_results
from .sast import analyze_python_source


class DependencyScanner(Protocol):
    scanner_version: str
    database_version: str

    def scan(self, sbom: SbomArtifact) -> dict: ...


@dataclass(frozen=True)
class StaticJob:
    archive_path: Path
    workspace: Path
    authorized: bool
    scope: str
    profile: str = "standard"


@dataclass(frozen=True)
class StaticResult:
    inventory: SourceInventory
    sbom: SbomArtifact
    findings: tuple[DetectedFinding, ...]
    report_markdown: str


def run_static_job(job: StaticJob, scanner: DependencyScanner, limits: IntakeLimits | None = None) -> StaticResult:
    if not job.authorized:
        raise PermissionError("source authorization is required")
    limits = limits or IntakeLimits()
    inventory = inspect_archive(job.archive_path, limits)
    source = extract_archive(job.archive_path, job.workspace, limits)
    sbom = build_sbom(source, inventory)
    findings = normalize_osv_results(
        scanner.scan(sbom), sbom,
        scanner_version=scanner.scanner_version,
        database_version=scanner.database_version,
    ) if sbom.document["components"] else []
    if job.profile not in {"quick", "standard", "deep"}:
        raise ValueError("unsupported static profile")
    if job.profile != "quick":
        findings.extend(analyze_python_source(source, inventory,
                                               max_findings=30 if job.profile == "standard" else 100))
    report = render_static_report(findings, scope=job.scope, unresolved=sbom.unresolved,
                                  profile=job.profile)
    return StaticResult(inventory, sbom, tuple(findings), report)
