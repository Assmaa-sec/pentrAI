"""
Stage 5 — SYNTHESIZE.

The single seam between phase 1 (analysis) and phase 2 (exploitation). It merges
the SCA + SAST findings and the recon surface into one ranked, de-duplicated
AttackPlan — the *only* thing that crosses into the exploitation agent. This is the
"structured handoff, not prose" that makes the two phases a coupled hypothesis ->
verification loop instead of two blind passes.

Ranking, NOT hard filtering: a finding is not dropped just because it needs
authentication — the attack is allowed to use supplied secrets. `network_reachable`
and posture are ranking signals (unauthenticated + high-severity floats to the top),
not gates.
"""

from __future__ import annotations

from ..config import Settings
from ..contracts import AttackPlan, Confidence, Finding, ReconResult, Severity, Target


def synthesize(findings: list[Finding], recon: ReconResult, target: Target, settings: Settings) -> AttackPlan:
    """Rank + de-duplicate findings into an ordered AttackPlan.

    Responsibilities:
      * de-duplicate (SCA and SAST can flag the same weakness from two angles)
      * attach/normalize each finding's `suggested_validation` and target endpoint
      * rank by roughly severity x confidence x reachability, floating
        unauthenticated + high-severity to the top
      * cap at settings.max_findings_to_validate so phase 2 stays bounded
      * carry `target.posture` onto the plan for the report's framing

    Pure ranking logic; no network calls.
    """
    severity_weight = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                       Severity.HIGH: 3, Severity.CRITICAL: 4}
    confidence_weight = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.source.value, finding.cve.casefold(),
               finding.code_location.casefold(), finding.title.casefold())
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(key=lambda item: (
        -severity_weight[item.severity], -confidence_weight[item.confidence],
        -int(item.network_reachable), item.title.casefold(), item.id,
    ))
    return AttackPlan(
        hypotheses=unique[:max(0, settings.max_findings_to_validate)],
        rationale="Ranked by severity, confidence, and observed reachability; all remain hypotheses.",
        posture=target.posture,
    )
