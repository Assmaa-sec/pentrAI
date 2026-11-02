"""Long-running native HexStrike dispatcher and lease cleanup loop."""

from __future__ import annotations

import logging
from threading import Event
from typing import Callable

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from control_plane.models import RunnerLease

from .dispatch import ClusterClient
from .dispatch_worker import dispatch_tick
from .leases import reap_expired_leases
from .preflight import ClusterFacts, preflight_failures
from .staging_workload import SourceBrokerEnvironment
from .workload import RunnerEnvironment


class _NamespaceRouter:
    def __init__(self, cluster_for_namespace: Callable[[str], ClusterClient]) -> None:
        self.cluster_for_namespace = cluster_for_namespace

    def delete_namespace(self, namespace: str) -> None:
        self.cluster_for_namespace(namespace).delete_namespace(namespace)


def service_cycle(
    engine: Engine, signing_key: bytes,
    cluster_for_namespace: Callable[[str], ClusterClient],
    runner: RunnerEnvironment, broker: SourceBrokerEnvironment,
    facts: ClusterFacts, revoke_artifact_grant: Callable[[RunnerLease], None], *,
    containment_verified: bool = False, dynamic_scans_enabled: bool = False,
) -> tuple[bool, int]:
    """Dispatch one scan and reap completed, cancelled, or expired leases."""
    if not containment_verified or preflight_failures(facts):
        raise ValueError("execution cluster containment is not verified")
    launched = False
    dispatch_error: Exception | None = None
    try:
        launched = dispatch_tick(
            engine, signing_key, cluster_for_namespace, runner, broker, facts,
            containment_verified=True, dynamic_scans_enabled=dynamic_scans_enabled,
        )
    except Exception as exc:
        dispatch_error = exc
    with Session(engine) as session:
        with session.begin():
            cleaned = reap_expired_leases(
                session, _NamespaceRouter(cluster_for_namespace), revoke_artifact_grant,
            )
    if dispatch_error is not None:
        raise dispatch_error
    return launched, cleaned


def serve(
    engine: Engine, signing_key: bytes,
    cluster_for_namespace: Callable[[str], ClusterClient],
    runner: RunnerEnvironment, broker: SourceBrokerEnvironment,
    facts: ClusterFacts, revoke_artifact_grant: Callable[[RunnerLease], None],
    stop: Event, *, containment_verified: bool = False,
    dynamic_scans_enabled: bool = False, poll_seconds: float = 2.0,
) -> None:
    """Poll until stopped; failed cycles are retried while the process is live."""
    if not containment_verified or preflight_failures(facts):
        raise ValueError("execution cluster containment is not verified")
    if not 0.1 <= poll_seconds <= 60:
        raise ValueError("poll interval must be between 0.1 and 60 seconds")
    while not stop.is_set():
        try:
            service_cycle(
                engine, signing_key, cluster_for_namespace, runner, broker,
                facts, revoke_artifact_grant,
                containment_verified=True,
                dynamic_scans_enabled=dynamic_scans_enabled,
            )
        except Exception as exc:
            logging.warning("native runner cycle failed: %s", type(exc).__name__)
        stop.wait(poll_seconds)
