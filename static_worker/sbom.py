"""Deterministic CycloneDX inventory for supported pinned Python dependencies."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .intake import SourceInventory


_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
_UNRESOLVED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*[<>=!~][A-Za-z0-9.,<>=!~ _-]{1,180}$")


@dataclass(frozen=True)
class SbomArtifact:
    document: dict
    sha256: str
    unresolved: tuple[str, ...]
    source_manifest_sha256: str


def build_sbom(source_root: Path, inventory: SourceInventory) -> SbomArtifact:
    components: list[dict] = []
    unresolved: list[str] = []
    for entry in inventory.files:
        if Path(entry.path).name != "requirements.txt":
            continue
        manifest = source_root / entry.path
        if not manifest.is_file() or manifest.stat().st_size != entry.size:
            raise ValueError("source manifest changed after intake")
        for raw in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = _PIN.fullmatch(line)
            if match is None:
                unresolved.append(line if _UNRESOLVED.fullmatch(line) else "unsupported requirement")
                continue
            name, version = match.groups()
            normalized = re.sub(r"[-_.]+", "-", name).lower()
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{normalized}@{version}",
                    "bom-ref": f"pkg:pypi/{normalized}@{version}",
                    "properties": [{"name": "pentrai:manifest", "value": entry.path}],
                }
            )
    components.sort(key=lambda item: item["purl"])
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return SbomArtifact(
        document=document,
        sha256=hashlib.sha256(encoded).hexdigest(),
        unresolved=tuple(unresolved),
        source_manifest_sha256=inventory.manifest_sha256,
    )
