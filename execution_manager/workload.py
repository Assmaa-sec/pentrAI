"""Per-lease runner objects; admission remains gated on live containment checks.

The source PVC is populated by an isolated artifact stager before this job is
created. This module never fetches customer source or provider credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import re
from urllib.parse import urlsplit

from control_plane.models import RunnerLease
from control_plane.grants import ScanGrantClaims
from .job_agent import JobScope
from .policy import base_namespace_objects


_DIGEST_IMAGE = re.compile(r"^[a-zA-Z0-9._/-]+(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_DNS_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


@dataclass(frozen=True)
class RunnerEnvironment:
    image: str
    model_gateway_ip: str
    model_gateway_port: int
    collector_ip: str
    collector_port: int
    dns_ip: str | None = None
    model_name: str = "managed"

    def __post_init__(self) -> None:
        if not _DIGEST_IMAGE.fullmatch(self.image):
            raise ValueError("runner image must be pinned by sha256 digest")
        for field in ("model_gateway_ip", "collector_ip"):
            address = ipaddress.ip_address(getattr(self, field))
            if (address.version != 4 or not address.is_private
                    or address.is_loopback or address.is_link_local):
                raise ValueError(f"{field} must be a private IPv4 service address")
        if self.dns_ip is not None and not ipaddress.ip_address(self.dns_ip).is_private:
            raise ValueError("DNS service must have a private address")
        if not all(1 <= port <= 65535 for port in (self.model_gateway_port, self.collector_port)):
            raise ValueError("internal service port is invalid")
        if not self.model_name or len(self.model_name) > 100:
            raise ValueError("managed model name is required")


def _egress(ip: str, port: int, protocol: str = "TCP") -> dict:
    return {"to": [{"ipBlock": {"cidr": f"{ip}/{32 if ':' not in ip else 128}"}}],
            "ports": [{"protocol": protocol, "port": port}]}


def runner_objects(
    lease: RunnerLease, env: RunnerEnvironment, scope: JobScope,
    claims: ScanGrantClaims, *,
    source_pvc: str | None, identity_secret: str,
    target_ips: tuple[str, ...] = (), target_port: int | None = None,
    now: datetime | None = None,
) -> tuple[dict, ...]:
    """Build closed policies and one job; the caller must check scan/grant first.

    A URL job must resolve and recheck ownership immediately before creation.
    Only the resulting public IPs are admitted; DNS changes cannot widen egress.
    """
    base = base_namespace_objects(lease)
    lease_expiry = (lease.expires_at.replace(tzinfo=timezone.utc)
                    if lease.expires_at.tzinfo is None else lease.expires_at)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or scope.expires_at <= now or lease_expiry <= now:
        raise ValueError("runner lease expired before job creation")
    deadline_seconds = min(3600, max(1, int((scope.expires_at - now).total_seconds())))
    if (scope.lease_id != lease.id or scope.scan_id != lease.scan_id
            or scope.organization_id != lease.organization_id or scope.expires_at > lease_expiry):
        raise ValueError("job scope does not match runner lease")
    if (claims.record.id != lease.scan_grant_id or claims.scan_id != scope.scan_id
            or claims.organization_id != scope.organization_id
            or claims.source_digest != scope.source_digest
            or claims.scope_digest != scope.scope_digest
            or claims.target_url != scope.target_url
            or claims.profile != scope.profile
            or claims.dynamic_authorized != bool(scope.target_url)
            or scope.expires_at.timestamp() > claims.expires_at):
        raise ValueError("job scope does not match verified grant")
    if bool(source_pvc) != scope.source_present or bool(target_ips) != bool(scope.target_url):
        raise ValueError("job target does not match authorized scope")
    if scope.target_url:
        parsed = urlsplit(scope.target_url)
        expected_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if target_port != expected_port:
            raise ValueError("target port does not match authorized URL")
    if not _DNS_NAME.fullmatch(identity_secret) or len(identity_secret) > 63:
        raise ValueError("invalid runner identity secret name")
    if source_pvc is not None and (len(source_pvc) > 63 or not _DNS_NAME.fullmatch(source_pvc)):
        raise ValueError("invalid staged source volume name")
    if bool(target_ips) != (target_port is not None):
        raise ValueError("target IPs and port must be supplied together")
    if target_ips and env.dns_ip is None:
        raise ValueError("URL jobs require a pinned private DNS service")
    if not source_pvc and not target_ips:
        raise ValueError("runner requires staged source or a verified target")
    if target_port is not None and not 1 <= target_port <= 65535:
        raise ValueError("invalid target port")
    if len(target_ips) > 8 or len(set(target_ips)) != len(target_ips):
        raise ValueError("too many or duplicate target addresses")
    for ip in target_ips:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("target address must be public")

    egress = [_egress(env.model_gateway_ip, env.model_gateway_port),
              _egress(env.collector_ip, env.collector_port)]
    if env.dns_ip:
        egress.extend((_egress(env.dns_ip, 53, "UDP"), _egress(env.dns_ip, 53)))
    egress.extend(_egress(ip, target_port) for ip in target_ips)
    labels = {"pentrai.io/lease-id": lease.id, "pentrai.io/scan-id": lease.scan_id}
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
    volumes = [{"name": "server-scratch", "emptyDir": {"sizeLimit": "1Gi"}},
               {"name": "agent-scratch", "emptyDir": {"sizeLimit": "256Mi"}},
               {"name": "job-scope", "configMap": {"name": "job-scope"}},
               {"name": "identity", "secret": {"secretName": identity_secret,
                                                "items": [{"key": "model-token", "path": "model-token"},
                                                          {"key": "collector-token", "path": "collector-token"}],
                                                "defaultMode": 256}}]
    if source_pvc:
        volumes.append({"name": "source", "persistentVolumeClaim": {
            "claimName": source_pvc, "readOnly": True}})
    source_mount = [{"name": "source", "mountPath": "/job/source",
                     "subPath": "source", "readOnly": True}] if source_pvc else []
    server_scratch = [{"name": "server-scratch", "mountPath": "/job/tmp"},
                      {"name": "server-scratch", "mountPath": "/tmp"}]
    agent_scratch = [{"name": "agent-scratch", "mountPath": "/job/tmp"},
                     {"name": "agent-scratch", "mountPath": "/tmp"},
                     {"name": "job-scope", "mountPath": "/job/scope", "readOnly": True},
                     {"name": "identity", "mountPath": "/job/identity", "readOnly": True}]
    pod = {
        "serviceAccountName": lease.service_account,
        "automountServiceAccountToken": False,
        "runtimeClassName": "runv",
        "restartPolicy": "Never",
        "hostNetwork": False, "hostPID": False, "hostIPC": False,
        "securityContext": {"runAsNonRoot": True, "fsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumes": volumes,
        "containers": [
            {"name": "hexstrike", "image": env.image, "imagePullPolicy": "IfNotPresent",
             "command": ["python", "/opt/pentrai/pentrai_server.py"],
             "workingDir": "/job/tmp",
             "env": [{"name": "PENTRAI_HOST", "value": "127.0.0.1"},
                     {"name": "PENTRAI_PORT", "value": "8888"},
                     {"name": "TMPDIR", "value": "/job/tmp"}],
             "ports": [{"name": "hexstrike", "containerPort": 8888}],
             "volumeMounts": source_mount + server_scratch,
             "securityContext": security,
             "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                           "limits": {"cpu": "2", "memory": "2Gi"}}},
            {"name": "agent", "image": env.image, "imagePullPolicy": "IfNotPresent",
             "command": ["sh", "-c", "cp /opt/pentrai/pentrai_mcp.py /job/tmp/pentrai_mcp.py && exec python -m execution_manager.job_agent"],
             "workingDir": "/job/tmp",
             "env": [{"name": "PENTRAI_SCAN_ID", "value": lease.scan_id},
                     {"name": "PENTRAI_LEASE_ID", "value": lease.id},
                     {"name": "PENTRAI_MODEL_NAME", "value": env.model_name},
                     {"name": "PENTRAI_MODEL_GATEWAY", "value": f"https://{env.model_gateway_ip}:{env.model_gateway_port}/v1"},
                     {"name": "PENTRAI_COLLECTOR", "value": f"https://{env.collector_ip}:{env.collector_port}"},
                     {"name": "TMPDIR", "value": "/job/tmp"}],
             "volumeMounts": source_mount + agent_scratch,
             "securityContext": security,
             "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                           "limits": {"cpu": "2", "memory": "2Gi"}}},
        ],
    }
    scope_data = {
        "scan_id": scope.scan_id, "organization_id": scope.organization_id,
        "lease_id": scope.lease_id, "source_digest": scope.source_digest,
        "scope_digest": scope.scope_digest, "source_present": scope.source_present,
        "target_url": scope.target_url, "scope_note": scope.scope_note,
        "profile": scope.profile, "expires_at": scope.expires_at.isoformat(),
    }
    return (*base, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "job-scope", "namespace": lease.namespace},
        "data": {"job.json": json.dumps(scope_data, sort_keys=True)},
    }, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "runner-egress", "namespace": lease.namespace},
        "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Egress"], "egress": egress},
    }, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "hexstrike", "namespace": lease.namespace, "labels": labels},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": deadline_seconds,
                 "ttlSecondsAfterFinished": 3600,
                 "template": {"metadata": {"labels": labels}, "spec": pod}},
    })
