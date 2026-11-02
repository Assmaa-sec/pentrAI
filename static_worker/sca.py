"""Normalize pinned OSV-Scanner JSON into detected dependency findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .sbom import SbomArtifact


@dataclass(frozen=True)
class DetectedFinding:
    state: str
    source: str
    dependency: str
    advisory_id: str
    source_manifest: str
    scanner_version: str
    database_version: str
    scanner_output_sha256: str


def normalize_osv_results(
    output: dict,
    sbom: SbomArtifact,
    *,
    scanner_version: str,
    database_version: str,
) -> list[DetectedFinding]:
    if not scanner_version or not database_version or not isinstance(output.get("results"), list):
        raise ValueError("scanner output or provenance is incomplete")
    encoded = json.dumps(output, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 10 * 1024 * 1024:
        raise ValueError("scanner output exceeds limit")
    output_digest = hashlib.sha256(encoded).hexdigest()
    known = {(component["name"].casefold(), component["version"]): component for component in sbom.document["components"]}
    findings: list[DetectedFinding] = []
    seen: set[tuple[str, str]] = set()
    for result in output["results"]:
        for item in result.get("packages", []):
            package = item.get("package", {})
            name, version = package.get("name"), package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            component = known.get((name.casefold(), version))
            if component is None:
                continue
            manifest = component["properties"][0]["value"]
            for vulnerability in item.get("vulnerabilities", []):
                aliases = vulnerability.get("aliases", [])
                cves = sorted(alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-"))
                identifier = cves[0] if cves else vulnerability.get("id")
                if not isinstance(identifier, str) or not identifier:
                    continue
                key = (component["purl"], identifier)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    DetectedFinding(
                        state="detected",
                        source="sca",
                        dependency=f"{name}@{version}",
                        advisory_id=identifier,
                        source_manifest=manifest,
                        scanner_version=scanner_version,
                        database_version=database_version,
                        scanner_output_sha256=output_digest,
                    )
                )
    return findings
