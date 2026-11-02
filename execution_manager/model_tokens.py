"""Short-lived, job-bound access to the private managed-model gateway."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hmac
import json
from uuid import UUID

from sqlalchemy.orm import Session

from control_plane.models import RunnerLease, Scan, ScanGrant, ScanState, WebTargetProof


class ModelTokenRejected(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def mint_model_token(lease: RunnerLease, signing_key: bytes, *,
                     now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if len(signing_key) < 32 or lease.cleaned_at is not None or _aware(lease.expires_at) <= now:
        raise ModelTokenRejected("live runner lease is required")
    data = {"lease_id": lease.id, "scan_id": lease.scan_id,
            "organization_id": lease.organization_id,
            "expires_at": int(_aware(lease.expires_at).timestamp())}
    payload = _b64(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    signature = _b64(hmac.digest(signing_key, b"pentrai-model-v1." + payload.encode(), "sha256"))
    return f"m1.{payload}.{signature}"


def verify_model_token(
    session: Session, token: str, signing_key: bytes, *,
    dynamic_scans_enabled: bool = False, now: datetime | None = None,
) -> RunnerLease:
    now = now or datetime.now(timezone.utc)
    if not isinstance(token, str) or not 20 <= len(token) <= 4096 or len(signing_key) < 32:
        raise ModelTokenRejected("invalid model token")
    try:
        version, payload, signature = token.split(".")
        if version != "m1" or not hmac.compare_digest(
            signature, _b64(hmac.digest(signing_key,
                         b"pentrai-model-v1." + payload.encode("ascii"), "sha256"))
        ):
            raise ModelTokenRejected("invalid model token")
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if set(data) != {"lease_id", "scan_id", "organization_id", "expires_at"}:
            raise ValueError("model claims")
        for key in ("lease_id", "scan_id", "organization_id"):
            if not isinstance(data[key], str) or str(UUID(data[key])) != data[key]:
                raise ValueError("model identity")
        if type(data["expires_at"]) is not int or data["expires_at"] <= int(now.timestamp()):
            raise ValueError("model expiry")
    except (ValueError, TypeError, UnicodeError, KeyError, binascii.Error) as exc:
        raise ModelTokenRejected("invalid or expired model token") from exc
    lease = session.get(RunnerLease, data["lease_id"])
    scan = session.get(Scan, data["scan_id"])
    grant = session.get(ScanGrant, lease.scan_grant_id) if lease else None
    if (lease is None or scan is None or grant is None
            or lease.scan_id != scan.id or lease.organization_id != data["organization_id"]
            or scan.organization_id != lease.organization_id
            or scan.state is not ScanState.QUEUED
            or scan.execution_backend != "hexstrike"
            or lease.cleaned_at is not None or grant.revoked_at is not None
            or grant.scan_id != scan.id or grant.organization_id != scan.organization_id
            or _aware(lease.expires_at) <= now or _aware(grant.expires_at) <= now
            or data["expires_at"] != int(_aware(lease.expires_at).timestamp())):
        raise ModelTokenRejected("live authorized runner is required")
    if scan.target_url:
        proof = session.get(WebTargetProof, scan.web_target_proof_id)
        if (not dynamic_scans_enabled or proof is None
                or proof.organization_id != scan.organization_id
                or proof.project_id != scan.project_id
                or proof.verified_until is None or _aware(proof.verified_until) <= now):
            raise ModelTokenRejected("URL scan release gate or proof is invalid")
    return lease
