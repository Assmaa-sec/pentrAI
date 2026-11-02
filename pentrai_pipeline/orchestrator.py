"""
The orchestrator wires the stages together in order and owns the two things that
must never be skipped: **teardown** of the sandbox (in a finally block, even on
error) and **event emission** so the eventual web layer can stream progress.

The control flow here is the whole pipeline at a glance. The stages it calls are
still stubs (they raise NotImplementedError); this file is intentionally complete
so the skeleton is genuinely *wired* and each stage can be filled in independently.
"""

from __future__ import annotations

from typing import Optional

from .config import Settings
from .contracts import PipelineResult, Posture, Target
from .jobs.job import Job, JobStatus
from .stages import (
    analyze_sast,
    analyze_sca,
    exploit,
    ingest,
    recon,
    report,
    sandbox,
    synthesize,
)


def run_pipeline(target: Target, settings: Optional[Settings] = None, job: Optional[Job] = None) -> PipelineResult:
    """Run the full ingest -> ... -> report pipeline for one target.

    Returns a PipelineResult even on partial failure (whatever stages completed).
    The sandbox is always torn down.
    """
    settings = settings or Settings.from_env()
    job = job or Job.create(target)
    result = PipelineResult(target=target)

    if not target.authorized:
        # Authorization is a hard gate: we rebuild and attack a private copy, but
        # the user must still attest they are allowed to test this code.
        job.fail("target is not marked authorized; refusing to run")
        return result

    deployed = None
    try:
        # 1. INGEST — normalize input, detect stack, locate a container recipe.
        job.enter(JobStatus.INGESTING)
        result.ingest = ingest.ingest(target, settings)

        if not settings.isolated_runner_verified:
            raise PermissionError("dynamic pipeline requires a verified isolated runner; use the static product flow locally")

        # 2. DEPLOY — build + run inside the isolated, egress-controlled sandbox.
        job.enter(JobStatus.DEPLOYING)
        deployed = sandbox.deploy(result.ingest, settings)

        # 3. RECON — map the external surface of the running target.
        job.enter(JobStatus.RECON)
        result.recon = recon.recon(deployed, settings)

        # 4. ANALYZE — two engines. SCA is deterministic; SAST is the LLM's job.
        job.enter(JobStatus.ANALYZING)
        sca_findings = analyze_sca.analyze_sca(result.ingest, settings)
        sast_findings = analyze_sast.analyze_sast(result.ingest, result.recon, settings)
        result.findings = sca_findings + sast_findings

        # 5. SYNTHESIZE — rank + filter into the attack plan (phase1 -> phase2 handoff).
        job.enter(JobStatus.SYNTHESIZING)
        result.attack_plan = synthesize.synthesize(result.findings, result.recon, target, settings)

        # 6. EXPLOIT — live validation. The attack is the verification oracle.
        job.enter(JobStatus.EXPLOITING)
        result.validated = exploit.exploit(result.attack_plan, deployed, settings)

        # 7. REPORT — one technical, one client-facing.
        job.enter(JobStatus.REPORTING)
        result.reports = report.build_reports(result.validated, target, result.recon, settings)

        job.complete()
    except NotImplementedError as e:
        # Expected while the scaffold is being filled in: record where we stopped.
        job.fail(f"stage not yet implemented: {e or job.status.value}")
    except Exception as e:  # noqa: BLE001 - top-level guard; detail is on the job
        job.fail(f"{type(e).__name__}: {e}")
    finally:
        if deployed is not None:
            try:
                sandbox.teardown(deployed, settings)
            except Exception as e:  # noqa: BLE001
                job.note(f"teardown error: {type(e).__name__}: {e}")

    return result
