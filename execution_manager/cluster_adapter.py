"""Explicit, namespace-bound kubectl adapter for isolated runner resources.

Kubectl receives manifests on stdin, never as command arguments or files. The
execution manager needs a dedicated kubeconfig restricted to the execution
cluster; this adapter does not itself prove network containment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import time
from copy import deepcopy
from typing import Callable


_NAMESPACE = re.compile(r"^scan-[0-9a-f]{32}$")
_RESOURCE_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_KINDS = frozenset({"Namespace", "ServiceAccount", "ResourceQuota", "LimitRange",
                    "NetworkPolicy", "ConfigMap", "PersistentVolumeClaim", "Secret", "Job"})


class ClusterOperationFailed(RuntimeError):
    """A cluster command failed; stderr is deliberately excluded."""


class KubectlCluster:
    def __init__(self, kubeconfig: Path, context: str, namespace: str,
                 *, executable: str = "kubectl") -> None:
        if not _NAMESPACE.fullmatch(namespace):
            raise ValueError("invalid scan namespace")
        if not kubeconfig.is_file() or kubeconfig.is_symlink():
            raise ValueError("dedicated execution kubeconfig is required")
        if not context or len(context) > 200 or context.startswith("-"):
            raise ValueError("explicit execution context is required")
        if not executable:
            raise ValueError("kubectl executable is required")
        self.kubeconfig = kubeconfig.resolve(strict=True)
        self.context = context
        self.namespace = namespace
        self.executable = executable

    def _run(self, args: list[str], *, document: dict | None = None,
             timeout: int = 30) -> str:
        command = [self.executable, f"--kubeconfig={self.kubeconfig}",
                   f"--context={self.context}", *args]
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}}
        try:
            result = subprocess.run(
                command, input=json.dumps(document) if document is not None else None,
                text=True, capture_output=True, timeout=timeout, check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ClusterOperationFailed(f"cluster command unavailable: {type(exc).__name__}") from exc
        if result.returncode != 0:
            raise ClusterOperationFailed(f"cluster command failed: {args[0]}")
        return result.stdout

    def apply(self, document: dict) -> None:
        if not isinstance(document, dict) or document.get("kind") not in _KINDS:
            raise ValueError("unsupported cluster resource")
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("cluster resource metadata is required")
        name = metadata.get("name")
        if not isinstance(name, str) or len(name) > 63 or not _RESOURCE_NAME.fullmatch(name):
            raise ValueError("invalid cluster resource name")
        if document["kind"] == "Namespace":
            if name != self.namespace or metadata.get("namespace") is not None:
                raise ValueError("resource is outside scan namespace")
        elif metadata.get("namespace") != self.namespace:
            raise ValueError("resource is outside scan namespace")
        self._run(["apply", "--server-side", "--field-manager=pentrai-execution-manager",
                   "--validate=strict", "-f", "-"], document=document)

    def wait_job_complete(self, name: str, *, deadline_seconds: int,
                          heartbeat: Callable[[], None] | None = None) -> None:
        if not _RESOURCE_NAME.fullmatch(name) or not 1 <= deadline_seconds <= 3600:
            raise ValueError("invalid job wait")
        deadline = time.monotonic() + deadline_seconds
        while True:
            if heartbeat is not None:
                heartbeat()
            output = self._run(["-n", self.namespace, "get", "job", name, "-o=json"])
            try:
                status = json.loads(output).get("status", {})
            except (ValueError, TypeError, AttributeError) as exc:
                raise ClusterOperationFailed("cluster returned invalid job status") from exc
            conditions = status.get("conditions") or []
            if any(item.get("type") == "Failed" and item.get("status") == "True"
                   for item in conditions):
                raise ClusterOperationFailed("source staging job failed")
            if status.get("succeeded", 0) >= 1 and any(
                item.get("type") == "Complete" and item.get("status") == "True"
                for item in conditions
            ):
                return
            if time.monotonic() >= deadline:
                raise ClusterOperationFailed("source staging job timed out")
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def delete_stage_job(self) -> None:
        self._run(["-n", self.namespace, "delete", "job", "stage-source",
                   "--cascade=foreground", "--wait=true", "--ignore-not-found=true",
                   "--timeout=120s"], timeout=130)
        output = self._run(["-n", self.namespace, "get", "pods",
                            "-l", "pentrai.io/component=source-stager", "-o=json"])
        try:
            items = json.loads(output)["items"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ClusterOperationFailed("cluster returned invalid pod list") from exc
        if items:
            raise ClusterOperationFailed("source staging pod has not been removed")

    def source_stage_marked(self, lease_id: str, source_digest: str) -> bool:
        output = self._run(["-n", self.namespace, "get", "configmap", "source-staged",
                            "--ignore-not-found=true", "-o=json"])
        if not output.strip():
            return False
        try:
            document = json.loads(output)
            data = document["data"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ClusterOperationFailed("invalid source staging marker") from exc
        if data != {"lease-id": lease_id, "source-sha256": source_digest}:
            raise ClusterOperationFailed("source staging marker does not match lease")
        return True

    def runner_job_exists(self, expected: dict) -> bool:
        if expected.get("kind") != "Job" or expected.get("metadata", {}).get("name") != "hexstrike":
            raise ValueError("expected native runner Job is required")
        output = self._run(["-n", self.namespace, "get", "job", "hexstrike",
                            "--ignore-not-found=true", "-o=json"])
        if not output.strip():
            return False
        try:
            observed = json.loads(output)
        except ValueError as exc:
            raise ClusterOperationFailed("invalid native runner Job response") from exc
        stable = deepcopy(expected)
        stable["spec"].pop("activeDeadlineSeconds", None)
        if not _contains(observed, stable):
            raise ClusterOperationFailed("existing native runner Job does not match lease")
        return True

    def delete_namespace(self, namespace: str) -> None:
        if namespace != self.namespace:
            raise ValueError("cannot delete another scan namespace")
        self._run(["delete", "namespace", namespace, "--wait=true",
                   "--ignore-not-found=true", "--timeout=180s"], timeout=190)


def _contains(observed: object, expected: object) -> bool:
    """Compare owned fields while tolerating Kubernetes defaulted fields."""
    if isinstance(expected, dict):
        return isinstance(observed, dict) and all(
            key in observed and _contains(observed[key], value)
            for key, value in expected.items())
    if isinstance(expected, list):
        return (isinstance(observed, list) and len(observed) == len(expected)
                and all(_contains(actual, wanted)
                        for actual, wanted in zip(observed, expected)))
    return observed == expected
