"""Local static worker adapter; never runs source code or dynamic tools."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from static_worker.worker import DependencyScanner, StaticJob, run_static_job

from .artifacts import ObjectStore
from .events import append_visible_event
from .grants import verify_grant
from .models import AuditEvent, OutboxEvent, Scan, ScanFinding, ScanReport, ScanState, SourceArtifact


class LocalStaticRunRejected(ValueError):
    pass


def run_local_static_scan(
    session: Session,
    organization_id: str,
    scan_id: str,
    token: str,
    signing_key: bytes,
    store: ObjectStore,
    scanner: DependencyScanner,
    workspace_root: Path,
) -> ScanReport:
    """Run one queued scan in a disposable local workspace, staging DB changes.

    The caller commits the transaction after return. Production workers require
    a separate isolation boundary and durable lease before using this adapter.
    """
    scan = session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == organization_id).with_for_update()
    )
    if (scan is None or scan.state is not ScanState.QUEUED
            or scan.execution_backend != "local_static" or not scan.source_artifact_id):
        raise LocalStaticRunRejected("queued static scan not found")
    claims = verify_grant(session, token, signing_key, scan.source_digest)
    if claims.scan_id != scan_id or claims.organization_id != organization_id:
        raise LocalStaticRunRejected("grant does not authorize this scan")
    artifact = session.scalar(
        select(SourceArtifact).where(
            SourceArtifact.id == scan.source_artifact_id,
            SourceArtifact.organization_id == organization_id,
            SourceArtifact.project_id == scan.project_id,
        )
    )
    if artifact is None or artifact.sha256 != scan.source_digest:
        raise LocalStaticRunRejected("source artifact binding changed")
    if session.scalar(select(ScanReport).where(ScanReport.scan_id == scan_id)) is not None:
        raise LocalStaticRunRejected("scan already has a report")

    root = workspace_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    job_dir = (root / scan_id).resolve()
    if job_dir == root or not job_dir.is_relative_to(root):
        raise LocalStaticRunRejected("invalid scan workspace")
    job_dir.mkdir(exist_ok=False)
    try:
        archive = job_dir / "source.zip"
        digest = hashlib.sha256()
        size = 0
        with archive.open("xb") as output:
            for chunk in store.read_chunks(artifact.object_key):
                size += len(chunk)
                if size > artifact.size_bytes:
                    raise LocalStaticRunRejected("source grew after finalization")
                digest.update(chunk)
                output.write(chunk)
        if size != artifact.size_bytes or digest.hexdigest() != artifact.sha256:
            raise LocalStaticRunRejected("source bytes differ from finalized digest")
        scan.state = ScanState.INTAKE
        append_visible_event(session, scan_id, organization_id, "intake", "Source archive verified")
        result = run_static_job(
            StaticJob(archive, job_dir, True, scan.scope_note or f"scope sha256 {scan.scope_digest}",
                      profile=scan.profile),
            scanner,
        )
        scan.state = ScanState.STATIC
        append_visible_event(session, scan_id, organization_id, "scanner", "Dependency analysis completed")
        markdown = result.report_markdown
        if len(markdown.encode("utf-8")) > 2 * 1024 * 1024:
            raise LocalStaticRunRejected("report exceeds size limit")
        for finding in result.findings:
            session.add(ScanFinding(
                organization_id=organization_id, scan_id=scan_id,
                state=finding.state, source=finding.source,
                dependency=finding.dependency, advisory_id=finding.advisory_id,
                source_manifest=finding.source_manifest,
                scanner_version=finding.scanner_version,
                database_version=finding.database_version,
                scanner_output_sha256=finding.scanner_output_sha256,
            ))
        report = ScanReport(
            organization_id=organization_id, scan_id=scan_id, markdown=markdown,
            sha256=hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
        )
        session.add(report)
        scan.state = ScanState.REPORTING
        append_visible_event(session, scan_id, organization_id, "report", "Assessment report ready")
        scan.state = ScanState.CLEANUP
        session.add(AuditEvent(
            organization_id=organization_id, scan_id=scan_id, actor_id="local-static-worker",
            action="scan.static_complete",
            payload={"report_sha256": report.sha256, "finding_count": len(result.findings)},
        ))
        session.add(OutboxEvent(
            organization_id=organization_id, scan_id=scan_id, kind="scan.static_complete",
            payload={"scan_id": scan_id, "report_sha256": report.sha256},
        ))
        scan.state = ScanState.COMPLETED
        append_visible_event(session, scan_id, organization_id, "status", "Assessment completed")
        session.flush()
        return report
    finally:
        shutil.rmtree(job_dir)
