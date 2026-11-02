"""Ordered isolated workload launch for an admitted native HexStrike scan."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import ipaddress
import socket
from typing import Callable, Protocol
from urllib.parse import urlsplit

from .admission import PreparedRunnerJob
from .model_tokens import mint_model_token
from .policy import base_namespace_objects
from .preflight import ClusterFacts, preflight_failures
from .staging_workload import SourceBrokerEnvironment, source_staging_objects
from .workload import RunnerEnvironment, runner_objects


class ClusterClient(Protocol):
    def apply(self, document: dict) -> None: ...
    def runner_job_exists(self, expected: dict) -> bool: ...
    def source_stage_marked(self, lease_id: str, source_digest: str) -> bool: ...
    def wait_job_complete(self, name: str, *, deadline_seconds: int,
                          heartbeat: Callable[[], None] | None = None) -> None: ...
    def delete_stage_job(self) -> None: ...
    def delete_namespace(self, namespace: str) -> None: ...


def resolve_target_ips(target_url: str) -> tuple[tuple[str, ...], int]:
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid authorized target")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        answers = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("target DNS lookup failed") from exc
    addresses = tuple(sorted({item[4][0] for item in answers}))
    if not addresses or len(addresses) > 8 or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise ValueError("target DNS must resolve only to bounded public addresses")
    return addresses, port


def _identity_secret(prepared: PreparedRunnerJob, model_token: str) -> dict:
    if (not isinstance(model_token, str) or not 16 <= len(model_token) <= 4096
            or "\n" in model_token or "\r" in model_token):
        raise ValueError("scoped managed model token is required")
    if not prepared.grant_token or len(prepared.grant_token) > 4096:
        raise ValueError("runner grant token is missing")
    encode = lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii")
    return {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "runner-identity", "namespace": prepared.lease.namespace},
        "type": "Opaque",
        "data": {"scan-grant": encode(prepared.grant_token),
                 "collector-token": encode(prepared.grant_token),
                 "model-token": encode(model_token)},
    }


def launch_prepared_job(
    prepared: PreparedRunnerJob, cluster: ClusterClient,
    runner: RunnerEnvironment, broker: SourceBrokerEnvironment | None,
    signing_key: bytes, facts: ClusterFacts, *,
    containment_verified: bool = False,
    dynamic_scans_enabled: bool = False,
    now: datetime | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> None:
    """Apply closed namespace first, stage source, then start native HexStrike.

    ``containment_verified`` must reflect an external live acceptance result,
    not merely structural manifest inspection. The default refuses all jobs.
    """
    now = now or datetime.now(timezone.utc)
    failures = preflight_failures(facts)
    if failures or not containment_verified:
        raise ValueError("execution cluster containment is not verified")
    if prepared.scope.target_url and not dynamic_scans_enabled:
        raise ValueError("URL scan release gate is closed")
    if prepared.scope.expires_at <= now:
        raise ValueError("runner lease expired before launch")
    if prepared.scope.source_present != bool(prepared.artifact_id):
        raise ValueError("runner source binding changed")
    if prepared.artifact_id and (prepared.artifact_bytes is None or broker is None):
        raise ValueError("source staging broker is required")
    source_pvc = "staged-source" if prepared.artifact_id else None
    target_ips, target_port = (resolve_target_ips(prepared.scope.target_url)
                               if prepared.scope.target_url else ((), None))
    base = base_namespace_objects(prepared.lease)
    secret = _identity_secret(prepared, mint_model_token(prepared.lease, signing_key,
                                                        now=now))
    staged = (source_staging_objects(
        prepared.lease, prepared.claims, runner, broker,
        artifact_id=prepared.artifact_id, artifact_bytes=prepared.artifact_bytes,
        source_pvc=source_pvc, identity_secret="runner-identity", now=now,
    ) if prepared.artifact_id else ())
    job_objects = runner_objects(
        prepared.lease, runner, prepared.scope, prepared.claims,
        source_pvc=source_pvc, identity_secret="runner-identity",
        target_ips=target_ips, target_port=target_port, now=now,
    )
    def pulse() -> None:
        if heartbeat is not None:
            heartbeat()

    def apply(document: dict) -> None:
        pulse()
        cluster.apply(document)

    try:
        for document in base:
            apply(document)
        apply(secret)
        if staged:
            for document in staged[:-1]:
                apply(document)
            pulse()
            marked = cluster.source_stage_marked(
                prepared.lease.id, prepared.scope.source_digest)
            if not marked:
                apply(staged[-1])
                cluster.wait_job_complete("stage-source", deadline_seconds=min(
                    900, max(1, int((prepared.scope.expires_at - now).total_seconds()))),
                    heartbeat=heartbeat)
                apply({
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": "source-staged", "namespace": prepared.lease.namespace},
                    "data": {"lease-id": prepared.lease.id,
                             "source-sha256": prepared.scope.source_digest},
                })
            pulse()
            cluster.delete_stage_job()
        for document in job_objects[len(base):-1]:
            apply(document)
        native_job = job_objects[-1]
        pulse()
        if not cluster.runner_job_exists(native_job):
            apply(native_job)
    except Exception:
        try:
            cluster.delete_namespace(prepared.lease.namespace)
        except Exception:
            pass  # the durable lease reaper retries namespace deletion
        raise
