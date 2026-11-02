"""Fail-closed ACK execution-cluster capability check.

An infrastructure adapter supplies observed values. Passing this structural
check does not replace the live network and containment acceptance suite.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClusterFacts:
    managed_ack: bool
    separate_execution_vpc: bool
    runtime_classes: frozenset[str]
    sandbox_nodes_bare_metal: bool
    sandbox_nodes_alibaba_linux_3: bool
    terway_mode: str
    network_policy_enabled: bool
    pod_security_admission_enabled: bool
    signed_image_admission_enforced: bool
    private_api_endpoint: bool
    public_node_egress_blocked: bool


def preflight_failures(facts: ClusterFacts) -> tuple[str, ...]:
    failures: list[str] = []
    if not facts.managed_ack:
        failures.append("managed ACK cluster required")
    if not facts.separate_execution_vpc:
        failures.append("separate execution VPC required")
    if "runv" not in {item.lower() for item in facts.runtime_classes}:
        failures.append("runV RuntimeClass unavailable")
    if not facts.sandbox_nodes_bare_metal:
        failures.append("runV bare-metal node pool required")
    if not facts.sandbox_nodes_alibaba_linux_3:
        failures.append("Alibaba Cloud Linux 3 sandbox nodes required")
    if facts.terway_mode != "shared-eni":
        failures.append("Terway shared ENI mode required")
    if not facts.network_policy_enabled:
        failures.append("Terway NetworkPolicy enforcement required")
    if not facts.pod_security_admission_enabled:
        failures.append("Pod Security admission enforcement required")
    if not facts.signed_image_admission_enforced:
        failures.append("signed image admission enforcement required")
    if not facts.private_api_endpoint:
        failures.append("private ACK API endpoint required")
    if not facts.public_node_egress_blocked:
        failures.append("node public egress must be blocked")
    return tuple(failures)
