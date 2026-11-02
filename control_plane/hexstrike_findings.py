"""Store evidence-linked HexStrike findings in an authorized scan."""

from __future__ import annotations

import hashlib
from sqlalchemy import select
from sqlalchemy.orm import Session

from pentrai_pipeline.agents.hexstrike_findings import FindingDraft
from .models import Scan, ScanFinding, ScanState


def persist_finding_drafts(
    session: Session,
    organization_id: str,
    scan_id: str,
    drafts: list[FindingDraft],
) -> int:
    """Persist drafts after the caller validates its runner grant and evidence.

    This internal function does not grant scan access. It checks the scan
    binding and active state again before writing and leaves commit to caller.
    """
    scan = session.scalar(select(Scan).where(
        Scan.id == scan_id, Scan.organization_id == organization_id))
    if scan is None or scan.state not in {ScanState.STATIC, ScanState.VALIDATING, ScanState.REPORTING}:
        raise PermissionError("scan is not active for HexStrike findings")
    inserted = 0
    for draft in drafts:
        if not isinstance(draft, FindingDraft) or not draft.evidence_sha256:
            raise ValueError("HexStrike finding lacks verified run evidence")
        identity = hashlib.sha256((draft.title + "\0" + "\0".join(draft.evidence_sha256)).encode()).hexdigest()
        advisory_id = "HS-" + identity[:32]
        existing = session.scalar(select(ScanFinding.id).where(
            ScanFinding.scan_id == scan_id, ScanFinding.dependency == "",
            ScanFinding.advisory_id == advisory_id))
        if existing:
            continue
        session.add(ScanFinding(
            organization_id=organization_id, scan_id=scan_id,
            state="detected", source="hexstrike", dependency="",
            advisory_id=advisory_id, source_manifest="",
            scanner_version="HexStrike MCP", database_version="",
            scanner_output_sha256=draft.evidence_sha256[0],
            title=draft.title, severity=draft.severity,
            explanation=draft.explanation, evidence_sha256=list(draft.evidence_sha256),
        ))
        inserted += 1
    return inserted
