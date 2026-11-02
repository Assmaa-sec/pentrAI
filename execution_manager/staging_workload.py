"""Separate, broker-only Kubernetes job that stages source before HexStrike."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from uuid import UUID

from control_plane.grants import ScanGrantClaims
from control_plane.models import RunnerLease
from .policy import base_namespace_objects
from .workload import RunnerEnvironment, _egress


_DNS_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


@dataclass(frozen=True)
class SourceBrokerEnvironment:
    ip: str
    port: int
    storage_class: str

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.ip)
        if (address.version != 4 or not address.is_private
                or address.is_loopback or address.is_link_local
                or not 1 <= self.port <= 65535
                or not _DNS_NAME.fullmatch(self.storage_class)
                or len(self.storage_class) > 63):
            raise ValueError("invalid private source broker environment")


def source_staging_objects(
    lease: RunnerLease, claims: ScanGrantClaims, runner: RunnerEnvironment,
    broker: SourceBrokerEnvironment, *, artifact_id: str, artifact_bytes: int,
    source_pvc: str, identity_secret: str, now: datetime | None = None,
) -> tuple[dict, ...]:
    """Create staging resources; caller applies base namespace and identity first.

    The cluster adapter must await successful Job completion, delete its Pod,
    and only then create the HexStrike job using this PVC read-only.
    """
    base_namespace_objects(lease)
    now = now or datetime.now(timezone.utc)
    expiry = (lease.expires_at.replace(tzinfo=timezone.utc)
              if lease.expires_at.tzinfo is None else lease.expires_at)
    if expiry <= now or not 0 < artifact_bytes <= 50 * 1024 * 1024:
        raise ValueError("staging lease or artifact size is invalid")
    if (claims.record.id != lease.scan_grant_id or claims.scan_id != lease.scan_id
            or claims.organization_id != lease.organization_id
            or claims.source_digest == hashlib.sha256(b"").hexdigest()):
        raise ValueError("verified source grant does not match lease")
    try:
        if str(UUID(artifact_id)) != artifact_id:
            raise ValueError("invalid artifact id")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid artifact id") from exc
    for name in (source_pvc, identity_secret):
        if len(name) > 63 or not _DNS_NAME.fullmatch(name):
            raise ValueError("invalid staging resource name")
    labels = {"pentrai.io/lease-id": lease.id, "pentrai.io/scan-id": lease.scan_id,
              "pentrai.io/component": "source-stager"}
    deadline = min(900, max(1, int((expiry - now).total_seconds())))
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
    return ({
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": source_pvc, "namespace": lease.namespace},
        "spec": {"accessModes": ["ReadWriteOnce"], "volumeMode": "Filesystem",
                 "storageClassName": broker.storage_class,
                 "resources": {"requests": {"storage": "512Mi"}}},
    }, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "stager-egress", "namespace": lease.namespace},
        "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Egress"],
                 "egress": [_egress(broker.ip, broker.port)]},
    }, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "stage-source", "namespace": lease.namespace, "labels": labels},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": deadline,
                 "ttlSecondsAfterFinished": 3600,
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "serviceAccountName": lease.service_account,
                     "automountServiceAccountToken": False,
                     "runtimeClassName": "runv", "restartPolicy": "Never",
                     "hostNetwork": False, "hostPID": False, "hostIPC": False,
                     "securityContext": {"runAsNonRoot": True, "fsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [
                         {"name": "source", "persistentVolumeClaim": {"claimName": source_pvc}},
                         {"name": "scratch", "emptyDir": {"sizeLimit": "64Mi"}},
                         {"name": "identity", "secret": {"secretName": identity_secret,
                                                         "items": [{"key": "scan-grant", "path": "scan-grant"}],
                                                         "defaultMode": 256}},
                     ],
                     "containers": [{
                         "name": "stage", "image": runner.image,
                         "imagePullPolicy": "IfNotPresent", "workingDir": "/job/tmp",
                         "command": ["python", "-m", "execution_manager.stage_source",
                                     "--broker", f"https://{broker.ip}:{broker.port}",
                                     "--artifact-id", artifact_id,
                                     "--token-file", "/job/identity/scan-grant",
                                     "--scratch", "/job/tmp", "--workspace", "/job/staged",
                                     "--sha256", claims.source_digest,
                                     "--bytes", str(artifact_bytes)],
                         "volumeMounts": [
                             {"name": "source", "mountPath": "/job/staged"},
                             {"name": "scratch", "mountPath": "/job/tmp"},
                             {"name": "scratch", "mountPath": "/tmp"},
                             {"name": "identity", "mountPath": "/job/identity", "readOnly": True},
                         ],
                         "securityContext": security,
                         "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                                       "limits": {"cpu": "2", "memory": "2Gi"}},
                     }],
                 }}},
    })
