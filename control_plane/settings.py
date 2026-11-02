"""Validated control-plane configuration. Secrets never enter repr/logs."""

from __future__ import annotations

import os

from pydantic import BaseModel, SecretStr, field_validator, model_validator


class Settings(BaseModel):
    database_url: str
    grant_signing_key: SecretStr
    dynamic_scans_enabled: bool = False
    native_runner_ready: bool = False
    local_static_enabled: bool = False
    local_hexstrike_enabled: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    local_artifact_root: str | None = None
    local_dev_auth: bool = False

    @field_validator("grant_signing_key")
    @classmethod
    def strong_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw.encode("utf-8")) < 32 or raw.lower() in {"change-me", "changeme"}:
            raise ValueError("grant signing key must be at least 32 bytes and not a default")
        return value

    @model_validator(mode="after")
    def local_static_is_development_only(self) -> "Settings":
        if self.local_static_enabled and not self.local_dev_auth:
            raise ValueError("local static execution requires local development authentication")
        if self.local_static_enabled and self.native_runner_ready:
            raise ValueError("only one scan execution backend may be enabled")
        if self.local_hexstrike_enabled and not self.local_dev_auth:
            raise ValueError("local HexStrike execution requires local development authentication")
        if self.local_hexstrike_enabled and (self.local_static_enabled or self.native_runner_ready):
            raise ValueError("only one scan execution backend may be enabled")
        return self

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_url=os.environ["PENTRAI_DATABASE_URL"],
            grant_signing_key=os.environ["PENTRAI_GRANT_SIGNING_KEY"],
            dynamic_scans_enabled=False,
            native_runner_ready=os.getenv("PENTRAI_NATIVE_RUNNER_READY", "").lower() == "true",
            local_static_enabled=os.getenv("PENTRAI_LOCAL_STATIC_ENABLED", "").lower() == "true",
            local_hexstrike_enabled=os.getenv("PENTRAI_LOCAL_HEXSTRIKE_ENABLED", "").lower() == "true",
            oidc_issuer=os.getenv("PENTRAI_OIDC_ISSUER", ""),
            oidc_audience=os.getenv("PENTRAI_OIDC_AUDIENCE", ""),
            oidc_jwks_url=os.getenv("PENTRAI_OIDC_JWKS_URL", ""),
            local_artifact_root=os.getenv("PENTRAI_LOCAL_ARTIFACT_ROOT") or None,
            local_dev_auth=os.getenv("PENTRAI_LOCAL_DEV_AUTH", "").lower() == "true",
        )
