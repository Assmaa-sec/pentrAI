"""Customer-safe progress derived from persisted assessment evidence."""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .assessment_health import FAILURES, HEALTH_RECOVERED, HEALTH_WARNINGS
from .local_hexstrike_readiness import local_worker_available
from .models import AuditEvent, RunnerLease, Scan, ScanEvent, ScanReport, ScanState


PUBLIC_FAILURES = {
    "admission": "The assessment could not start because its authorization or uploaded source could not be verified. Review the approved scope and upload before retrying.",
    "source": "The uploaded source could not be verified. Upload your source ZIP again and start a new assessment.",
    "archive": "The source archive could not be prepared. Check that it is a supported ZIP archive within the upload limits, then try again.",
    "deadline": "The assessment reached its time limit. Review the assessment scope before retrying.",
    "budget": "The assessment reached its work limit or its usage could not be verified. Review the scope and available credits before retrying.",
}
SERVICE_FAILURE = "The assessment could not finish because the assessment service encountered a problem. Try again later, or share the assessment reference with your administrator."
PUBLIC_HEALTH = (
    "Final checks are delayed. Completion will be confirmed only after they finish. Share the assessment reference with your administrator if the delay continues.",
    "This assessment has stopped reporting activity. Progress cannot be confirmed. We are continuing to check for updates.",
    "Assessment progress cannot be verified. Share the assessment reference with your administrator.",
    "The assessment service is not responding. Progress cannot be confirmed. We are continuing to check for updates.",
    "Your assessment is waiting to start. Earlier assessments may still be running. We are continuing to check its progress.",
)
PUBLIC_RECOVERED = "Assessment updates are available again. Monitoring continues."


def public_event_summary(kind: str, summary: str) -> str:
    """Translate old diagnostic events as well as events from current workers."""
    if summary in HEALTH_WARNINGS:
        return PUBLIC_HEALTH[HEALTH_WARNINGS.index(summary)]
    if summary == HEALTH_RECOVERED:
        return PUBLIC_RECOVERED
    for code, diagnostic in FAILURES.items():
        if summary == diagnostic or summary.startswith(diagnostic + " Cleanup"):
            return PUBLIC_FAILURES.get(code, SERVICE_FAILURE)
    if summary.startswith("Assessment service is responding. Current step:"):
        return "Assessment monitoring is active. The current stage has not finished yet."
    labels = {
        "Waiting for the model provider": "Reviewing source and analysis results",
        "Starting assessment tools": "Preparing the source analysis",
        "Verifying and saving assessment results": "Preparing your assessment report",
        "Assessment results ready; isolated runner cleanup in progress": "Your report is ready. Final checks are in progress.",
        "Assessment service is responding again": PUBLIC_RECOVERED,
        "Assessment cleanup could not finish. Ask your administrator to check Docker access. Cleanup will be retried while the assessment service is running.": PUBLIC_HEALTH[0],
        "Worker lost; retry is available": "Assessment interrupted. Retry is available.",
        "Static worker failed": SERVICE_FAILURE,
    }
    if summary in labels:
        return labels[summary]
    if summary.startswith("HexStrike assessed the authorized scope with "):
        return "Analysis of the approved scope has finished. Review the report for coverage and limitations."
    if kind == "warning":
        # Only fixed, user-meaningful warnings cross the customer API boundary.
        allowed = ("Assessment interrupted", "Assessment authorization", "Organization authorization")
        return summary if summary.startswith(allowed) else SERVICE_FAILURE
    return summary


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def progress_snapshot(session: Session, scan: Scan, *, now: datetime | None = None) -> dict:
    """An authenticated caller supplies a tenant-checked scan; no lifecycle writes."""
    now = _utc(now or datetime.now(timezone.utc))
    scope = (ScanEvent.scan_id == scan.id, ScanEvent.organization_id == scan.organization_id)
    latest = session.scalar(select(ScanEvent).where(*scope).order_by(ScanEvent.sequence.desc()).limit(1))
    phase_event = session.scalar(select(ScanEvent).where(
        *scope, ScanEvent.kind.in_(("intake", "scanner", "analysis", "validation", "report")),
    ).order_by(ScanEvent.sequence.desc()).limit(1))
    lease = session.scalar(select(RunnerLease).where(
        RunnerLease.scan_id == scan.id, RunnerLease.organization_id == scan.organization_id,
        RunnerLease.cleaned_at.is_(None),
    ))
    report_ready = session.scalar(select(ScanReport.id).where(
        ScanReport.scan_id == scan.id, ScanReport.organization_id == scan.organization_id,
    ).limit(1)) is not None
    stage = {"intake": "source", "scanner": "analysis", "analysis": "analysis",
             "validation": "analysis", "report": "report"}.get(phase_event.kind if phase_event else "", "queued")
    state_stage = {ScanState.INTAKE: "source", ScanState.STATIC: "analysis",
                   ScanState.DYNAMIC_ELIGIBLE: "analysis", ScanState.VALIDATING: "analysis",
                   ScanState.REPORTING: "report", ScanState.CLEANUP: "finalizing",
                   ScanState.COMPLETED: "finalizing"}
    stage = state_stage.get(scan.state, stage)
    terminal = scan.state in {ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED}
    health = "healthy"
    message = "Progress is based on confirmed assessment activity. Stage durations vary."
    if scan.state == ScanState.COMPLETED:
        health, message = "completed", "Your assessment is complete. Review the findings and report for coverage and limitations."
    elif scan.state == ScanState.CANCELLED:
        health, message = "cancelled", "This assessment was cancelled. It will not continue."
        if lease:
            message += " Final checks are still pending."
    elif scan.state == ScanState.FAILED:
        health = "failed"
        audit = session.scalar(select(AuditEvent).where(
            AuditEvent.scan_id == scan.id, AuditEvent.organization_id == scan.organization_id,
            AuditEvent.action.in_(("scan.execution_failed", "scan.start_failed")),
        ).order_by(AuditEvent.created_at.desc()).limit(1))
        message = PUBLIC_FAILURES.get(audit.payload.get("reason") if audit else None, SERVICE_FAILURE)
    elif scan.execution_backend != "local_static" and scan.state == ScanState.CLEANUP and lease and lease.cleanup_error:
        health, message = "delayed", PUBLIC_HEALTH[0]
    elif lease and _utc(lease.expires_at) <= now:
        health, message = "interrupted", PUBLIC_HEALTH[0]
    elif lease and (now - _utc(lease.heartbeat_at)).total_seconds() > 45:
        health, message = "interrupted", PUBLIC_HEALTH[1]
    elif scan.execution_backend == "hexstrike_local" and not local_worker_available(session, now=now):
        health, message = "interrupted", PUBLIC_HEALTH[3]
    elif scan.execution_backend != "local_static" and scan.state in {ScanState.QUEUED, ScanState.CLEANUP} and lease is None:
        health, message = "interrupted", PUBLIC_HEALTH[2]
    elif stage == "queued":
        health, message = "waiting", "Your assessment is waiting to start. You can leave this page and return to it later."
        if (now - _utc(scan.created_at)).total_seconds() > 120:
            health, message = "delayed", PUBLIC_HEALTH[4]
    elif phase_event and (now - _utc(phase_event.created_at)).total_seconds() > 120:
        health, message = "delayed", "No new analysis activity has been confirmed in the last two minutes. We are continuing to check for updates."
    updated = _utc(latest.created_at) if latest else _utc(scan.updated_at)
    # Keep analysis activity separate from liveness-only monitoring notices.
    activity = _utc(phase_event.created_at) if phase_event else _utc(scan.created_at)
    ended = _utc(scan.updated_at) if terminal else now
    return {
        "stage": stage, "health": health, "message": message,
        "checked_at": now.isoformat(), "last_update_at": updated.isoformat(),
        "last_activity_at": activity.isoformat(),
        "last_signal_at": _utc(lease.heartbeat_at).isoformat() if lease else None,
        "deadline_at": _utc(lease.expires_at).isoformat() if lease else None,
        "elapsed_seconds": max(0, int((ended - _utc(scan.created_at)).total_seconds())),
        "report_ready": report_ready,
    }
