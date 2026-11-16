"""Fixed, model-safe diagnostics for local source assessments."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .events import append_visible_event
from .local_hexstrike_readiness import local_worker_available
from .models import RunnerLease, Scan, ScanEvent, ScanState


FAILURES = {
    "admission": "Assessment authorization or the uploaded source record could not be verified. Review the organization authorization and uploaded source before retrying.",
    "database": "Assessment records could not be read or saved. Ask your administrator to check database access and migrations before retrying.",
    "configuration": "Assessment configuration is incomplete. Ask your administrator to check the model endpoint, model ID, and API key, then retry.",
    "credential": "The model API key is missing from the assessment service configuration. Ask your administrator to configure it, then retry.",
    "model": "The selected model or its credit rates changed. Ask your administrator to check the model configuration, then retry.",
    "docker": "The assessment environment is unavailable. Ask your administrator to check Docker access and the installed assessment image, then retry.",
    "source": "The uploaded source could not be read or did not match the upload record. Upload the source again, then retry.",
    "archive": "The source archive could not be prepared within the supported format and size limits. Check the archive, then retry.",
    "tools": "Assessment tools could not be started. Ask your administrator to check the assessment image, then retry.",
    "provider_auth": "The model provider rejected authentication or access. Ask your administrator to check the API key and model permissions, then retry.",
    "provider_limit": "The model provider reported a quota or rate limit. Ask your administrator to check provider capacity and billing before retrying.",
    "provider_timeout": "The model provider did not respond in time. Check provider availability before retrying.",
    "provider": "The model provider request failed or returned an unsupported response. Ask your administrator to check the endpoint and tool-calling model, then retry.",
    "budget": "The assessment credit budget was exhausted or usage could not be verified. Review assessment credits and provider usage support before retrying.",
    "deadline": "The assessment exceeded its time limit and was stopped. Review the source scope before retrying.",
    "runner": "The assessment process stopped or returned an invalid response. Ask your administrator to check the assessment service, then retry.",
    "result": "Assessment results could not be verified or saved. Ask your administrator to check authorization, credits, and database availability before retrying.",
}

STAGES = {
    "source": ("intake", "Checking the uploaded source"),
    "archive": ("intake", "Preparing the source archive"),
    "tools": ("analysis", "Starting assessment tools"),
    "analysis": ("analysis", "Analyzing source within the approved scope"),
    "model": ("analysis", "Waiting for the model provider"),
    "result": ("report", "Verifying and saving assessment results"),
}


class AssessmentFailure(ValueError):
    def __init__(self, code: str):
        if code not in FAILURES:
            raise ValueError("unknown assessment failure code")
        self.code = code
        super().__init__(FAILURES[code])


HEALTH_WARNINGS = (
    "The assessment is awaiting cleanup after a failure or time limit. Ask your administrator to check Docker access and restart the assessment service. Completion has not been confirmed.",
    "This assessment has stopped reporting activity. Progress cannot be confirmed. Ask your administrator to check the assessment service; its time limit and cleanup requirements still apply.",
    "The assessment execution record is missing. Progress and cleanup cannot be confirmed. Ask your administrator to check the assessment records before retrying.",
    "The assessment service is not responding. Progress cannot be confirmed. Ask your administrator to check the service, database connection, Docker, and model configuration.",
    "The assessment is still waiting to start. The assessment service may be busy with an earlier assessment. Ask your administrator to check the queue if this wait continues.",
)
HEALTH_RECOVERED = "The assessment service is responding again. Assessment monitoring continues; completion has not been confirmed."


def observe_local_health(session: Session, scan: Scan, *, now: datetime | None = None) -> None:
    """Record a deduplicated warning; never execute or clean resources in the API."""
    if scan.execution_backend != "hexstrike_local" or scan.state not in {
        ScanState.AUTHORIZED, ScanState.QUEUED, ScanState.CLEANUP,
    }:
        return
    now = now or datetime.now(timezone.utc)
    lease = session.scalar(select(RunnerLease).where(
        RunnerLease.scan_id == scan.id, RunnerLease.organization_id == scan.organization_id,
        RunnerLease.cleaned_at.is_(None),
    ))
    summary = None
    if lease and (lease.cleanup_error or lease.expires_at.replace(tzinfo=timezone.utc) <= now):
        summary = HEALTH_WARNINGS[0]
    elif lease and lease.heartbeat_at.replace(tzinfo=timezone.utc) < now - timedelta(seconds=45):
        summary = HEALTH_WARNINGS[1]
    elif scan.state in {ScanState.QUEUED, ScanState.CLEANUP} and lease is None:
        summary = HEALTH_WARNINGS[2]
    elif not local_worker_available(session, now=now):
        summary = HEALTH_WARNINGS[3]
    elif scan.state == ScanState.AUTHORIZED:
        created = scan.created_at.replace(tzinfo=timezone.utc)
        if now - created > timedelta(minutes=2):
            summary = HEALTH_WARNINGS[4]
    # Health messages have fixed text; never copy a lease error or exception.
    last = session.scalar(select(ScanEvent).where(
        ScanEvent.scan_id == scan.id, ScanEvent.organization_id == scan.organization_id,
        ScanEvent.summary.in_((*HEALTH_WARNINGS, HEALTH_RECOVERED)),
    ).order_by(ScanEvent.sequence.desc()).limit(1))
    if summary is None:
        if last is not None and last.summary != HEALTH_RECOVERED:
            append_visible_event(session, scan.id, scan.organization_id, "status", HEALTH_RECOVERED)
    elif last is None or last.summary != summary:
        append_visible_event(session, scan.id, scan.organization_id, "warning", summary)
