"""
Stage 7 — REPORT.

Render two artifacts from the same validated dataset (their audiences differ, the
facts don't):

  * TECHNICAL — full detail per confirmed finding: CWE/CVE, code location, the PoC,
    exact reproduction steps, and remediation. For the client's engineers.
  * CLIENT    — business-risk framing: what an attacker could actually do, which
    attacks WORKED, a prioritized fix list. No exploit gore.

Only CONFIRMED findings carry the "we proved this" weight; refuted/inconclusive
ones are shown as such (or omitted from the client report) so the document never
overclaims. Markdown out now; PDF/branding can wrap this later.
"""

from __future__ import annotations

import html
import re

from ..config import Settings
from ..contracts import Audience, Report, ReconResult, Target, ValidatedFinding, ValidationOutcome


def _plain(value: str, limit: int = 500) -> str:
    printable = "".join(char if char.isprintable() else " " for char in value[:limit])
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", html.escape(printable, quote=True))


def build_reports(
    validated: list[ValidatedFinding],
    target: Target,
    recon: ReconResult,
    settings: Settings,
) -> list[Report]:
    """Produce [technical_report, client_report] from the validated findings.

    Responsibilities:
      * summarize scope, posture (external vs authenticated), and what was tested
      * technical: per-finding PoC + reproduction + remediation + CWE/CVE refs
      * client: prioritized, plain-language "what worked / what to fix first"
      * an LLM may help with prose, but severities/outcomes come from the data,
        not the model — the report must not invent findings

    Returns both Report objects (Audience.TECHNICAL, Audience.CLIENT).
    """
    confirmed = [item for item in validated if item.outcome is ValidationOutcome.CONFIRMED and item.evidence]
    common = [
        "# PentrAI assessment", "",
        f"Scope: {_plain(target.scope_note)}", f"Posture: {target.posture.value}",
        f"Observed endpoints: {len(recon.endpoints)}; observed ports: {len(recon.open_ports)}", "",
        "This assessment does not certify that the application is safe. Results are limited to the declared scope, tools, and budget.",
        "",
    ]
    technical = common + ["## Validation outcomes", ""]
    for item in validated:
        finding = item.finding
        technical.extend([
            f"### {_plain(finding.title)}", "",
            f"Outcome: {item.outcome.value}; severity: {finding.severity.value}; source: {finding.source.value}",
            f"CWE: {_plain(finding.cwe)}; CVE: {_plain(finding.cve)}",
            f"Location: {_plain(finding.code_location or finding.dependency or finding.endpoint)}",
            f"Description: {_plain(finding.description, 2000)}",
            f"Notes: {_plain(item.notes, 2000)}", "",
        ])
        if item.outcome is ValidationOutcome.CONFIRMED and item.evidence:
            technical.extend([f"Evidence: {_plain(item.evidence.summary, 2000)}", ""])
    client = common + ["## Confirmed findings", ""]
    if not confirmed:
        client.append("No findings were independently confirmed within this assessment. This is not a safety guarantee.")
    for item in confirmed:
        client.extend([f"### {_plain(item.finding.title)}", "",
                       f"Severity: {item.finding.severity.value}",
                       f"Observed result: {_plain(item.evidence.summary, 1000)}", ""])
    client.extend(["", f"Other outcomes: {len(validated) - len(confirmed)} inconclusive, refuted, or skipped hypotheses."])
    return [
        Report(Audience.TECHNICAL, "PentrAI technical assessment", "\n".join(technical).rstrip() + "\n"),
        Report(Audience.CLIENT, "PentrAI client assessment", "\n".join(client).rstrip() + "\n"),
    ]
