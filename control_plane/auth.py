"""OIDC bearer verification and local user mapping."""

from __future__ import annotations

import time
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, HTTPException, Request, status
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_session
from .models import User


@dataclass(frozen=True)
class CurrentActor:
    user_id: str


class OIDCVerifier:
    def __init__(self, issuer: str, audience: str, jwks_url: str):
        parsed = urlsplit(jwks_url)
        if not issuer or not audience or parsed.scheme != "https" or not parsed.hostname or parsed.username:
            raise ValueError("OIDC issuer, audience, and HTTPS JWKS URL are required")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url
        self._jwks: dict | None = None
        self._refresh_at = 0.0

    def verify(self, token: str) -> str:
        if len(token) > 16_384:
            raise ValueError("invalid bearer token")
        if self._jwks is None or time.monotonic() >= self._refresh_at:
            response = httpx.get(self.jwks_url, timeout=5.0, follow_redirects=False)
            response.raise_for_status()
            if len(response.content) > 64_000:
                raise ValueError("JWKS response too large")
            jwks = response.json()
            if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                raise ValueError("invalid JWKS")
            self._jwks = jwks
            self._refresh_at = time.monotonic() + 600
        verified = jwt.decode(token, KeySet.import_key_set(self._jwks), algorithms=["RS256"])
        claims = verified.claims
        registry = JWTClaimsRegistry(
            iss={"essential": True, "value": self.issuer},
            aud={"essential": True, "values": [self.audience]},
            sub={"essential": True},
            exp={"essential": True},
        )
        try:
            registry.validate(claims)
        except Exception as exc:
            raise ValueError(f"invalid issuer, audience, or expiry: {exc}") from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ValueError("invalid subject")
        return f"{self.issuer}|{subject}"


def mint_local_token(subject: str, key: bytes, expires_at: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(
        {"sub": subject, "exp": expires_at}, separators=(",", ":"), sort_keys=True,
    ).encode()).decode().rstrip("=")
    signature = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return f"local.{payload}.{signature}"


def verify_local_token(token: str, key: bytes) -> str:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "local" or len(token) > 4096:
        raise ValueError("invalid local token")
    expected = hmac.new(key, parts[1].encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts[2]):
        raise ValueError("invalid local token signature")
    claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    if not isinstance(claims, dict) or not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise ValueError("invalid local token subject")
    if type(claims.get("exp")) is not int or claims["exp"] <= int(time.time()):
        raise ValueError("expired local token")
    return f"urn:pentrai:local|{claims['sub']}"


def current_actor(request: Request, session: Session = Depends(get_session)) -> CurrentActor:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")
    verifier = getattr(request.app.state, "oidc_verifier", None)
    try:
        settings = request.app.state.settings
        if settings.local_dev_auth and request.client and request.client.host in {"127.0.0.1", "::1", "testclient"}:
            subject = verify_local_token(token, settings.grant_signing_key.get_secret_value().encode())
        elif verifier is not None:
            subject = verifier.verify(token)
        else:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="identity provider not configured")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token") from exc
    user = session.scalar(select(User).where(User.oidc_subject == subject))
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user is not provisioned")
    return CurrentActor(user.id)
