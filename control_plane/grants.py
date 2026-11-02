"""Expiring HMAC grants bound to immutable scan authority."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import Scan, ScanGrant, ScanState, WebTargetProof, new_uuid


class GrantError(ValueError):
    pass


@dataclass(frozen=True)
class ScanGrantClaims:
    scan_id: str
    organization_id: str
    project_id: str
    source_digest: str
    target_url: str | None
    web_target_proof_id: str | None
    scope_digest: str
    profile: str
    dynamic_authorized: bool
    issued_at: int
    expires_at: int
    record: ScanGrant


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _signed_token(scan: Scan, grant_id: str, issued_at: int,
                  expires_at: int, signing_key: bytes) -> str:
    claims = {
        "grant_id": grant_id,
        "organization_id": scan.organization_id,
        "project_id": scan.project_id,
        "scan_id": scan.id,
        "source_digest": scan.source_digest,
        "target_url": scan.target_url,
        "web_target_proof_id": scan.web_target_proof_id,
        "scope_digest": scan.scope_digest,
        "profile": scan.profile,
        "dynamic_authorized": bool(scan.dynamic_authorized),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    payload = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.digest(signing_key, payload.encode("ascii"), "sha256"))
    return f"{payload}.{signature}"


def issue_grant(
    session: Session,
    scan: Scan,
    signing_key: bytes,
    ttl: timedelta,
    *,
    now: datetime | None = None,
) -> str:
    if len(signing_key) < 32:
        raise GrantError("grant signing key must have at least 32 bytes")
    if not timedelta(0) < ttl <= timedelta(hours=1):
        raise GrantError("grant lifetime must be at most one hour")
    if scan.state not in {ScanState.AUTHORIZED, ScanState.QUEUED}:
        raise GrantError("scan is not authorized for a new grant")
    now = now or datetime.now(timezone.utc)
    if scan.target_url:
        proof = session.get(WebTargetProof, scan.web_target_proof_id)
        if (proof is None or proof.organization_id != scan.organization_id
                or proof.project_id != scan.project_id or proof.verified_until is None
                or now >= (proof.verified_until.replace(tzinfo=timezone.utc)
                           if proof.verified_until.tzinfo is None else proof.verified_until)):
            raise GrantError("verified web target proof expired or changed")
    expires_at_second = int((now + ttl).timestamp())
    if expires_at_second <= int(now.timestamp()):
        raise GrantError("grant lifetime is too short")
    expires = datetime.fromtimestamp(expires_at_second, timezone.utc)
    grant_id = new_uuid()
    issued_at_second = int(now.timestamp())
    token = _signed_token(scan, grant_id, issued_at_second,
                          expires_at_second, signing_key)
    session.add(
        ScanGrant(
            id=grant_id,
            organization_id=scan.organization_id,
            scan_id=scan.id,
            token_digest=hashlib.sha256(token.encode("ascii")).hexdigest(),
            issued_at=issued_at_second,
            expires_at=expires,
        )
    )
    session.flush()
    return token


def recover_grant_token(
    session: Session, grant_id: str, signing_key: bytes,
    *, now: datetime | None = None,
) -> str:
    """Recreate an unexpired grant after dispatcher restart without storing it.

    A changed scan, rotated key, revoked grant, or legacy grant without an issue
    second fails closed. The token never enters the database or an audit event.
    """
    if len(signing_key) < 32:
        raise GrantError("invalid grant signing key")
    record = session.get(ScanGrant, grant_id)
    scan = session.get(Scan, record.scan_id) if record else None
    if record is None or scan is None or record.issued_at is None:
        raise GrantError("recoverable grant not found")
    expiry = (record.expires_at.replace(tzinfo=timezone.utc)
              if record.expires_at.tzinfo is None else record.expires_at)
    token = _signed_token(scan, record.id, record.issued_at,
                          int(expiry.timestamp()), signing_key)
    verify_grant(session, token, signing_key, scan.source_digest, now=now)
    return token


def verify_grant(
    session: Session,
    token: str,
    signing_key: bytes,
    expected_source_digest: str,
    *,
    now: datetime | None = None,
) -> ScanGrantClaims:
    if len(signing_key) < 32 or len(token) > 4096:
        raise GrantError("invalid grant")
    try:
        payload, signature = token.split(".", 1)
        expected = _b64(hmac.digest(signing_key, payload.encode("ascii"), "sha256"))
        if not hmac.compare_digest(signature, expected):
            raise GrantError("invalid grant signature")
        data = json.loads(_decode(payload))
        grant_id = data["grant_id"]
        expires_at = int(data["expires_at"])
        issued_at = int(data["issued_at"])
    except (ValueError, KeyError, UnicodeError, TypeError) as exc:
        raise GrantError("invalid grant") from exc
    now = now or datetime.now(timezone.utc)
    if int(now.timestamp()) >= expires_at:
        raise GrantError("grant expired")
    if issued_at > int(now.timestamp()) + 30:
        raise GrantError("grant issued in the future")
    if data.get("source_digest") != expected_source_digest:
        raise GrantError("source digest mismatch")
    record = session.get(ScanGrant, grant_id)
    if record is None or not hmac.compare_digest(record.token_digest, hashlib.sha256(token.encode("ascii")).hexdigest()):
        raise GrantError("unknown grant")
    if record.revoked_at is not None:
        raise GrantError("grant revoked")
    if record.issued_at is not None and record.issued_at != issued_at:
        raise GrantError("grant issue time mismatch")
    record_expiry = record.expires_at.replace(tzinfo=timezone.utc) if record.expires_at.tzinfo is None else record.expires_at
    if now >= record_expiry:
        raise GrantError("grant expired")
    scan = session.get(Scan, data.get("scan_id"))
    if scan is None or any(
        (
            record.scan_id != scan.id,
            record.organization_id != scan.organization_id,
            data.get("organization_id") != scan.organization_id,
            data.get("project_id") != scan.project_id,
            data.get("source_digest") != scan.source_digest,
            data.get("target_url") != scan.target_url,
            data.get("web_target_proof_id") != scan.web_target_proof_id,
            data.get("scope_digest") != scan.scope_digest,
            data.get("profile") != scan.profile,
            data.get("dynamic_authorized") != scan.dynamic_authorized,
        )
    ):
        raise GrantError("grant binding mismatch")
    if scan.target_url:
        proof = session.get(WebTargetProof, scan.web_target_proof_id)
        if (proof is None or proof.organization_id != scan.organization_id
                or proof.project_id != scan.project_id or proof.verified_until is None
                or now >= (proof.verified_until.replace(tzinfo=timezone.utc)
                           if proof.verified_until.tzinfo is None else proof.verified_until)):
            raise GrantError("verified web target proof expired or changed")
    return ScanGrantClaims(
        scan_id=scan.id,
        organization_id=scan.organization_id,
        project_id=scan.project_id,
        source_digest=scan.source_digest,
        target_url=scan.target_url,
        web_target_proof_id=scan.web_target_proof_id,
        scope_digest=scan.scope_digest,
        profile=scan.profile,
        dynamic_authorized=scan.dynamic_authorized,
        issued_at=issued_at,
        expires_at=expires_at,
        record=record,
    )
