"""Markdown reports from normalized static records, with untrusted text escaped."""

from __future__ import annotations

import html
import re
from collections.abc import Sequence

from .sca import DetectedFinding


_MARKDOWN_META = re.compile(r"([\\`*_{}\[\]()#+.!|>~-])")


def _safe(value: str) -> str:
    bounded = "".join(char if char.isprintable() else " " for char in value[:500])
    return _MARKDOWN_META.sub(r"\\\1", html.escape(bounded, quote=True))


def render_static_report(
    findings: Sequence[DetectedFinding],
    *,
    scope: str,
    unresolved: Sequence[str] = (),
    profile: str = "standard",
) -> str:
    """Report detections as hypotheses; static evidence never means confirmation."""
    lines = [
        "# PentrAI source assessment",
        "",
        f"Scope: {_safe(scope)}",
        "",
        "This report covers supported dependency manifests and selected Python source checks. Findings require verification; this assessment does not execute the submitted application.",
        "It does not certify that the application is safe.",
        "",
        "## Coverage and limitations",
        "",
        ("SCA covers exact Python package pins in requirements.txt. The quick profile does not run source checks."
         if profile == "quick" else
         "SCA covers exact Python package pins in requirements.txt. SAST covers a small set of Python AST call patterns (dynamic evaluation, pickle deserialization, and shell execution). It does not establish exploitability or comprehensive code coverage."),
    ]
    if unresolved:
        lines.extend(["", "Unresolved requirements:"])
        lines.extend(f"- {_safe(item)}" for item in unresolved[:100])
    lines.extend(["", "## Detected findings", ""])
    if not findings:
        lines.append("No finding was detected by the configured dependency scanner or selected Python source checks within their stated coverage.")
    else:
        for finding in sorted(findings, key=lambda item: (item.advisory_id, item.dependency)):
            lines.extend(
                [
                    f"### {_safe(finding.advisory_id)}: {_safe(finding.dependency)}",
                    "",
                    f"Source: {_safe(finding.source)}; state: detected; not live validated.",
                    f"Manifest: {_safe(finding.source_manifest)}",
                    f"Scanner version: {_safe(finding.scanner_version)}; database version: {_safe(finding.database_version)}",
                    f"Scanner output SHA-256: {_safe(finding.scanner_output_sha256)}",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"
