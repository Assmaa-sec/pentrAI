"""Authenticate and persist one HexStrike runner result without raw tool output."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import hmac
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from pentrai_pipeline.agents.hexstrike_findings import FindingDraft
from .events import append_visible_event
from .grants import GrantError, verify_grant
from .hexstrike_findings import persist_finding_drafts
from .credits import CreditRejected, settle_scan_credits
from .models import AuditEvent, OutboxEvent, RunnerLease, Scan, ScanReport, ScanState


class RunnerResultRejected(ValueError):
    pass


def _sha256(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _parse_payload(payload: object) -> tuple[dict, list[FindingDraft]]:
    if not isinstance(payload, dict) or set(payload) != {
        "scan_id", "organization_id", "lease_id", "scope_digest", "usage", "events", "findings"
    }:
        raise RunnerResultRejected("invalid runner result envelope")
    if not _sha256(payload["scope_digest"]):
        raise RunnerResultRejected("invalid scope digest")
    try:
        for key in ("scan_id", "organization_id", "lease_id"):
            if not isinstance(payload[key], str) or str(UUID(payload[key])) != payload[key]:
                raise ValueError(key)
    except ValueError as exc:
        raise RunnerResultRejected("invalid runner identity") from exc
    usage = payload["usage"]
    if (not isinstance(usage, dict) or set(usage) - {
        "prompt_tokens", "completion_tokens", "total_tokens"
    } or any(type(value) is not int or value < 0 or value > 10_000_000
             for value in usage.values())):
        raise RunnerResultRejected("invalid model usage")
    events = payload["events"]
    if not isinstance(events, list) or len(events) > 64:
        raise RunnerResultRejected("invalid tool event count")
    evidence: set[str] = set()
    for event in events:
        if (not isinstance(event, dict) or set(event) != {
            "tool", "arguments_sha256", "output_sha256", "output_chars", "is_error"
        } or not isinstance(event["tool"], str) or not 1 <= len(event["tool"]) <= 100
                or not _sha256(event["arguments_sha256"]) or not _sha256(event["output_sha256"])
                or type(event["output_chars"]) is not int or not 0 <= event["output_chars"] <= 10_000_000
                or type(event["is_error"]) is not bool):
            raise RunnerResultRejected("invalid tool evidence event")
        if not event["is_error"]:
            evidence.add(event["output_sha256"])
    items = payload["findings"]
    if not isinstance(items, list) or len(items) > 100:
        raise RunnerResultRejected("invalid finding count")
    drafts: list[FindingDraft] = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "title", "severity", "explanation", "evidence_sha256"
        }:
            raise RunnerResultRejected("invalid finding")
        title, severity, explanation, digests = (
            item["title"], item["severity"], item["explanation"], item["evidence_sha256"])
        if (not isinstance(title, str) or not 1 <= len(title.strip()) <= 200
                or not isinstance(severity, str)
                or severity not in {"critical", "high", "medium", "low", "info"}
                or not isinstance(explanation, str) or not 1 <= len(explanation.strip()) <= 8000
                or not isinstance(digests, list) or not 1 <= len(digests) <= 8
                or any(not isinstance(digest, str) or digest not in evidence for digest in digests)):
            raise RunnerResultRejected("finding lacks current-run evidence")
        drafts.append(FindingDraft(title.strip(), severity, explanation.strip(), tuple(digests)))
    return payload, drafts


def _report_markdown(drafts: list[FindingDraft], event_count: int) -> str:
    lines = ["# PentrAI assessment", "",
             "Findings below are detected hypotheses supported by HexStrike tool results. "
             "They have not been independently validated against a running application.", "",
             f"HexStrike tool calls: {event_count}.", ""]
    if not drafts:
        lines.extend(["No findings were detected within this scan's scope, tools, and work budget.", ""])
    for draft in drafts:
        lines.extend([f"## {html.escape(draft.title)}", "",
                      f"Severity: {draft.severity}", "",
                      html.escape(draft.explanation), "",
                      "Evidence SHA-256: " + ", ".join(draft.evidence_sha256), ""])
    markdown = "\n".join(lines)
    if len(markdown.encode("utf-8")) > 2 * 1024 * 1024:
        raise RunnerResultRejected("runner report exceeds size limit")
    return markdown


def accept_runner_result(
    session: Session, payload: object, token: str, signing_key: bytes, *,
    release_dynamic_enabled: bool = False, now: datetime | None = None,
) -> ScanReport:
    result, drafts = _parse_payload(payload)
    now = now or datetime.now(timezone.utc)
    scan = session.scalar(select(Scan).where(
        Scan.id == result["scan_id"], Scan.organization_id == result["organization_id"]
    ).with_for_update())
    if (scan is None or scan.execution_backend not in {"hexstrike", "hexstrike_local"}
            or scan.scope_digest != result["scope_digest"]):
        raise RunnerResultRejected("runner scan binding mismatch")
    if scan.target_url and not release_dynamic_enabled:
        raise RunnerResultRejected("URL scan release gate is closed")
    lease = session.scalar(select(RunnerLease).where(
        RunnerLease.id == result["lease_id"], RunnerLease.scan_id == scan.id,
        RunnerLease.organization_id == scan.organization_id,
    ).with_for_update())
    if (lease is None or lease.cleaned_at is not None
            or (lease.expires_at.replace(tzinfo=timezone.utc)
                if lease.expires_at.tzinfo is None else lease.expires_at) <= now):
        raise RunnerResultRejected("live runner lease is required")
    try:
        claims = verify_grant(session, token, signing_key, scan.source_digest, now=now)
    except GrantError as exc:
        raise RunnerResultRejected("valid runner grant is required") from exc
    if (claims.scan_id != scan.id or claims.organization_id != scan.organization_id
            or claims.record.id != lease.scan_grant_id):
        raise RunnerResultRejected("runner grant does not match lease")
    markdown = _report_markdown(drafts, len(result["events"]))
    digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
    existing = session.scalar(select(ScanReport).where(ScanReport.scan_id == scan.id))
    if existing is not None:
        if scan.state in {ScanState.CLEANUP, ScanState.COMPLETED} and hmac.compare_digest(existing.sha256, digest):
            return existing
        raise RunnerResultRejected("scan already has a different result")
    if scan.state is not ScanState.QUEUED:
        raise RunnerResultRejected("scan is not awaiting a runner result")
    try:
        settle_scan_credits(session, scan, result["usage"])
    except CreditRejected as exc:
        raise RunnerResultRejected(str(exc)) from exc
    scan.state = ScanState.REPORTING
    persist_finding_drafts(session, scan.organization_id, scan.id, drafts)
    report = ScanReport(organization_id=scan.organization_id, scan_id=scan.id,
                        markdown=markdown, sha256=digest)
    session.add(report)
    append_visible_event(session, scan.id, scan.organization_id, "analysis",
                         f"HexStrike assessed the authorized scope with {len(result['events'])} tool calls")
    append_visible_event(session, scan.id, scan.organization_id, "report", "Assessment report ready")
    session.add(AuditEvent(
        organization_id=scan.organization_id, scan_id=scan.id,
        actor_id="hexstrike-runner", action="scan.hexstrike_complete",
        payload={"lease_id": lease.id, "report_sha256": digest,
                 "finding_count": len(drafts), "usage": result["usage"]},
    ))
    session.add(OutboxEvent(
        organization_id=scan.organization_id, scan_id=scan.id,
        kind="scan.hexstrike_complete", payload={"scan_id": scan.id, "report_sha256": digest},
    ))
    scan.state = ScanState.CLEANUP
    append_visible_event(session, scan.id, scan.organization_id, "status",
                         "Assessment results ready; isolated runner cleanup in progress")
    session.flush()
    return report
