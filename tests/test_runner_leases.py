from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


class _Cluster:
    def __init__(self):
        self.deleted: list[str] = []
        self.fail = False

    def delete_namespace(self, namespace: str) -> None:
        self.deleted.append(namespace)
        if self.fail:
            raise OSError("sensitive infrastructure detail")


class RunnerLeaseTests(unittest.TestCase):
    def setUp(self):
        from control_plane.models import Base, Organization, Project, Scan, ScanState
        from control_plane.grants import issue_grant, verify_grant

        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        org = Organization(name="Owned fixture")
        self.session.add(org)
        self.session.flush()
        project = Project(organization_id=org.id, name="Fixture")
        self.session.add(project)
        self.session.flush()
        self.scan = Scan(
            organization_id=org.id, project_id=project.id,
            source_digest="a" * 64, scope_digest="b" * 64,
            profile="standard", dynamic_authorized=False, state=ScanState.QUEUED,
        )
        self.session.add(self.scan)
        self.session.flush()
        self.now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        key = b"k" * 32
        token = issue_grant(self.session, self.scan, key, timedelta(minutes=15), now=self.now)
        self.token = token
        self.signing_key = key
        self.claims = verify_grant(self.session, token, key, self.scan.source_digest, now=self.now)
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_lease_is_unique_and_expires_no_later_than_grant(self):
        from execution_manager.leases import create_lease

        lease = create_lease(self.session, self.claims, timedelta(hours=1), now=self.now)
        self.assertEqual(self.now + timedelta(minutes=15), lease.expires_at)
        self.assertEqual(self.scan.organization_id, lease.organization_id)
        self.assertTrue(lease.namespace.startswith("scan-"))
        with self.assertRaisesRegex(ValueError, "active runner lease"):
            create_lease(self.session, self.claims, timedelta(minutes=1), now=self.now)

    def test_grant_and_lease_expiry_match_with_fractional_issue_time(self):
        from control_plane.grants import issue_grant, verify_grant
        from execution_manager.leases import create_lease

        issued = self.now + timedelta(microseconds=500_000)
        token = issue_grant(self.session, self.scan, self.signing_key,
                            timedelta(minutes=5), now=issued)
        claims = verify_grant(self.session, token, self.signing_key,
                              self.scan.source_digest, now=issued)
        lease = create_lease(self.session, claims, timedelta(minutes=5), now=issued)
        self.assertEqual(claims.expires_at, int(lease.expires_at.timestamp()))
        self.assertEqual(float(claims.expires_at), lease.expires_at.timestamp())

    def test_lease_rejects_mismatched_grant_claims(self):
        from execution_manager.leases import create_lease

        forged = replace(self.claims, scope_digest="different")
        with self.assertRaisesRegex(ValueError, "live grant"):
            create_lease(self.session, forged, timedelta(minutes=1), now=self.now)
        with self.assertRaisesRegex(ValueError, "live grant"):
            create_lease(self.session, replace(self.claims, target_url="https://example.com/"),
                         timedelta(minutes=1), now=self.now)
        with self.assertRaisesRegex(ValueError, "live grant"):
            create_lease(self.session, replace(self.claims, web_target_proof_id="changed"),
                         timedelta(minutes=1), now=self.now)

    def test_expired_lease_deletes_namespace_and_revokes_grants(self):
        from control_plane.models import AuditEvent, ScanGrant, ScanState
        from execution_manager.leases import create_lease, reap_expired_leases

        lease = create_lease(self.session, self.claims, timedelta(seconds=1), now=self.now)
        cluster = _Cluster()
        revoked: list[str] = []
        later = self.now + timedelta(seconds=2)
        count = reap_expired_leases(self.session, cluster, lambda item: revoked.append(item.id), now=later)
        self.session.commit()
        self.assertEqual(1, count)
        self.assertEqual([lease.namespace], cluster.deleted)
        self.assertEqual([lease.id], revoked)
        self.assertEqual(later, lease.cleaned_at.replace(tzinfo=timezone.utc))
        self.assertEqual(later, lease.artifact_grant_revoked_at.replace(tzinfo=timezone.utc))
        self.assertIsNotNone(self.session.get(ScanGrant, lease.scan_grant_id).revoked_at)
        self.assertEqual(ScanState.FAILED, self.scan.state)
        self.assertEqual(0, reap_expired_leases(self.session, cluster, lambda _: None, now=later))
        self.assertTrue(self.session.scalars(select(AuditEvent).where(
            AuditEvent.action == "runner.lease_cleaned")).all())

    def test_cleanup_failure_remains_retriable_and_does_not_log_detail(self):
        from control_plane.models import ScanState
        from execution_manager.leases import create_lease, reap_expired_leases

        lease = create_lease(self.session, self.claims, timedelta(seconds=1), now=self.now)
        cluster = _Cluster()
        cluster.fail = True
        later = self.now + timedelta(seconds=2)
        self.assertEqual(0, reap_expired_leases(self.session, cluster, lambda _: None, now=later))
        self.session.commit()
        self.assertIsNone(lease.cleaned_at)
        self.assertEqual(ScanState.QUEUED, self.scan.state)
        self.assertEqual("namespace:OSError", lease.cleanup_error)
        self.assertNotIn("sensitive", lease.cleanup_error)
        cluster.fail = False
        self.assertEqual(1, reap_expired_leases(self.session, cluster, lambda _: None,
                                                now=later + timedelta(seconds=1)))
        self.session.commit()
        self.assertEqual(2, lease.cleanup_attempts)
        self.assertIsNotNone(lease.cleaned_at)
        self.assertEqual(ScanState.FAILED, self.scan.state)

    def test_cancelled_scan_reaps_lease_before_expiry(self):
        from control_plane.models import ScanState
        from execution_manager.leases import create_lease, reap_expired_leases

        lease = create_lease(self.session, self.claims, timedelta(minutes=5), now=self.now)
        self.scan.state = ScanState.CANCELLED
        cluster = _Cluster()
        cleaned = reap_expired_leases(self.session, cluster, lambda _: None,
                                     now=self.now + timedelta(seconds=1))
        self.session.commit()
        self.assertEqual(1, cleaned)
        self.assertEqual([lease.namespace], cluster.deleted)
        self.assertEqual(ScanState.CANCELLED, self.scan.state)
        self.assertIsNotNone(lease.cleaned_at)

    def test_base_namespace_policy_is_restricted_and_default_deny(self):
        from execution_manager.leases import create_lease
        from execution_manager.policy import base_namespace_objects

        lease = create_lease(self.session, self.claims, timedelta(minutes=1), now=self.now)
        objects = {item["kind"]: item for item in base_namespace_objects(lease)}
        labels = objects["Namespace"]["metadata"]["labels"]
        self.assertEqual("restricted", labels["pod-security.kubernetes.io/enforce"])
        self.assertFalse(objects["ServiceAccount"]["automountServiceAccountToken"])
        self.assertEqual("1", objects["ResourceQuota"]["spec"]["hard"]["persistentvolumeclaims"])
        self.assertEqual([], objects["NetworkPolicy"]["spec"]["ingress"])
        self.assertEqual([], objects["NetworkPolicy"]["spec"]["egress"])
        self.assertEqual(["Ingress", "Egress"], objects["NetworkPolicy"]["spec"]["policyTypes"])

        lease.namespace = "default"
        with self.assertRaisesRegex(ValueError, "namespace"):
            base_namespace_objects(lease)

    def test_runner_job_is_isolated_and_target_egress_is_exact(self):
        from execution_manager.leases import create_lease
        from execution_manager.job_agent import JobScope
        from execution_manager.workload import RunnerEnvironment, runner_objects

        lease = create_lease(self.session, self.claims, timedelta(minutes=1), now=self.now)
        env = RunnerEnvironment(
            image="registry.example/pentrai@sha256:" + "a" * 64,
            model_gateway_ip="10.4.0.2", model_gateway_port=443,
            collector_ip="10.4.0.3", collector_port=443, dns_ip="10.4.0.10",
        )
        scope = JobScope(
            self.scan.id, self.scan.organization_id, lease.id,
            self.scan.source_digest, self.scan.scope_digest, True,
            "https://dns.google/", "Authorized fixture", "standard", lease.expires_at,
        )
        web_claims = replace(self.claims, target_url=scope.target_url, dynamic_authorized=True)
        objects = runner_objects(lease, env, scope, web_claims, source_pvc="staged-source",
                                 identity_secret="runner-identity",
                                 target_ips=("8.8.8.8",), target_port=443, now=self.now)
        job = next(item for item in objects if item["kind"] == "Job")
        self.assertEqual(60, job["spec"]["activeDeadlineSeconds"])
        pod = job["spec"]["template"]["spec"]
        self.assertEqual("runv", pod["runtimeClassName"])
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod["hostNetwork"])
        self.assertTrue(all(container["securityContext"]["readOnlyRootFilesystem"]
                            for container in pod["containers"]))
        self.assertTrue(all(container["securityContext"]["capabilities"]["drop"] == ["ALL"]
                            for container in pod["containers"]))
        source_volume = next(item for item in pod["volumes"] if item["name"] == "source")
        self.assertTrue(source_volume["persistentVolumeClaim"]["readOnly"])
        server_mounts = {mount["name"] for mount in pod["containers"][0]["volumeMounts"]}
        agent_mounts = {mount["name"] for mount in pod["containers"][1]["volumeMounts"]}
        self.assertNotIn("agent-scratch", server_mounts)
        self.assertNotIn("server-scratch", agent_mounts)
        self.assertNotIn("identity", server_mounts)
        self.assertIn("identity", agent_mounts)
        identity_volume = next(item for item in pod["volumes"] if item["name"] == "identity")
        self.assertEqual({"model-token", "collector-token"},
                         {item["key"] for item in identity_volume["secret"]["items"]})
        self.assertTrue(next(item for item in pod["containers"][1]["volumeMounts"]
                             if item["name"] == "source")["readOnly"])
        self.assertEqual("source", next(item for item in pod["containers"][1]["volumeMounts"]
                                        if item["name"] == "source")["subPath"])
        config = next(item for item in objects if item["kind"] == "ConfigMap")
        self.assertEqual(scope.scan_id, __import__("json").loads(config["data"]["job.json"])["scan_id"])
        policy = next(item for item in objects if item["kind"] == "NetworkPolicy"
                      and item["metadata"]["name"] == "runner-egress")
        cidrs = {rule["to"][0]["ipBlock"]["cidr"] for rule in policy["spec"]["egress"]}
        self.assertEqual({"10.4.0.2/32", "10.4.0.3/32", "10.4.0.10/32", "8.8.8.8/32"}, cidrs)
        source_only = runner_objects(lease, env, replace(scope, target_url=None), self.claims,
                                     source_pvc="staged-source", identity_secret="runner-identity",
                                     now=self.now)
        source_policy = next(item for item in source_only if item["kind"] == "NetworkPolicy"
                             and item["metadata"]["name"] == "runner-egress")
        self.assertNotIn("8.8.8.8/32", {rule["to"][0]["ipBlock"]["cidr"]
                                         for rule in source_policy["spec"]["egress"]})
        with self.assertRaisesRegex(ValueError, "public"):
            runner_objects(lease, env, scope, web_claims, source_pvc="staged-source",
                           identity_secret="runner-identity",
                           target_ips=("127.0.0.1",), target_port=443, now=self.now)
        with self.assertRaisesRegex(ValueError, "DNS"):
            runner_objects(lease, RunnerEnvironment(env.image, "10.4.0.2", 443, "10.4.0.3", 443),
                           scope, web_claims, source_pvc="staged-source", identity_secret="runner-identity",
                           target_ips=("8.8.8.8",), target_port=443, now=self.now)
        with self.assertRaisesRegex(ValueError, "verified grant"):
            runner_objects(lease, env, scope, self.claims, source_pvc="staged-source",
                           identity_secret="runner-identity", target_ips=("8.8.8.8",),
                           target_port=443, now=self.now)

    def test_source_stager_only_reaches_artifact_broker(self):
        from execution_manager.leases import create_lease
        from execution_manager.staging_workload import SourceBrokerEnvironment, source_staging_objects
        from execution_manager.workload import RunnerEnvironment

        lease = create_lease(self.session, self.claims, timedelta(minutes=5), now=self.now)
        runner = RunnerEnvironment("registry.example/pentrai@sha256:" + "a" * 64,
                                   "10.4.0.2", 443, "10.4.0.3", 443)
        broker = SourceBrokerEnvironment("10.4.0.4", 443, "encrypted-scans")
        objects = source_staging_objects(
            lease, self.claims, runner, broker, artifact_id=self.scan.id,
            artifact_bytes=1024, source_pvc="staged-source", identity_secret="runner-identity",
            now=self.now,
        )
        policy = next(item for item in objects if item["kind"] == "NetworkPolicy")
        self.assertEqual(["10.4.0.4/32"], [rule["to"][0]["ipBlock"]["cidr"]
                                            for rule in policy["spec"]["egress"]])
        pvc = next(item for item in objects if item["kind"] == "PersistentVolumeClaim")
        self.assertEqual("512Mi", pvc["spec"]["resources"]["requests"]["storage"])
        job = next(item for item in objects if item["kind"] == "Job")
        pod = job["spec"]["template"]["spec"]
        self.assertEqual("runv", pod["runtimeClassName"])
        self.assertFalse(pod["automountServiceAccountToken"])
        identity = next(item for item in pod["volumes"] if item["name"] == "identity")
        self.assertEqual(["scan-grant"], [item["key"] for item in identity["secret"]["items"]])
        self.assertEqual("/job/staged", pod["containers"][0]["volumeMounts"][0]["mountPath"])
        self.assertTrue(pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
        with self.assertRaisesRegex(ValueError, "pinned"):
            RunnerEnvironment("registry.example/pentrai:latest", "10.4.0.2", 443,
                              "10.4.0.3", 443)

    def test_ack_preflight_rejects_missing_runtime_and_network_enforcement(self):
        from execution_manager.preflight import ClusterFacts, preflight_failures

        facts = ClusterFacts(
            managed_ack=True, separate_execution_vpc=True,
            runtime_classes=frozenset({"runv"}), sandbox_nodes_bare_metal=True,
            sandbox_nodes_alibaba_linux_3=True, terway_mode="shared-eni",
            network_policy_enabled=True, pod_security_admission_enabled=True,
            signed_image_admission_enforced=True, private_api_endpoint=True,
            public_node_egress_blocked=True,
        )
        self.assertEqual((), preflight_failures(facts))
        unsafe = ClusterFacts(**{**facts.__dict__, "runtime_classes": frozenset(),
                                 "terway_mode": "exclusive-eni", "public_node_egress_blocked": False})
        failures = preflight_failures(unsafe)
        self.assertTrue(any("RuntimeClass" in item for item in failures))
        self.assertTrue(any("shared ENI" in item for item in failures))
        self.assertTrue(any("egress" in item for item in failures))

    def test_runner_result_requires_live_lease_and_current_run_evidence(self):
        from control_plane.models import ScanFinding, ScanState
        from control_plane.runner_results import RunnerResultRejected, accept_runner_result
        from execution_manager.leases import create_lease, reap_expired_leases

        lease = create_lease(self.session, self.claims, timedelta(minutes=5), now=self.now)
        event = {"tool": "list_files", "arguments_sha256": "c" * 64,
                 "output_sha256": "d" * 64, "output_chars": 42, "is_error": False}
        payload = {"scan_id": self.scan.id, "organization_id": self.scan.organization_id,
                   "lease_id": lease.id, "scope_digest": self.scan.scope_digest,
                   "usage": {"prompt_tokens": 20, "completion_tokens": 8},
                   "events": [event], "findings": [{"title": "Example issue", "severity": "low",
                       "explanation": "The model explains the observed issue.",
                       "evidence_sha256": [event["output_sha256"]]}]}
        with self.assertRaisesRegex(RunnerResultRejected, "current-run evidence"):
            accept_runner_result(self.session,
                                 {**payload, "findings": [{**payload["findings"][0],
                                                            "evidence_sha256": ["e" * 64]}]},
                                 self.token, self.signing_key, now=self.now)
        with self.assertRaisesRegex(RunnerResultRejected, "current-run evidence"):
            accept_runner_result(self.session,
                                 {**payload, "events": [{**event, "is_error": True}]},
                                 self.token, self.signing_key, now=self.now)
        with self.assertRaisesRegex(RunnerResultRejected, "binding"):
            accept_runner_result(self.session, {**payload, "scope_digest": "e" * 64},
                                 self.token, self.signing_key, now=self.now)
        report = accept_runner_result(self.session, payload, self.token, self.signing_key, now=self.now)
        self.session.commit()
        self.assertEqual(ScanState.CLEANUP, self.scan.state)
        finding = self.session.scalar(select(ScanFinding).where(ScanFinding.scan_id == self.scan.id))
        self.assertEqual("hexstrike", finding.source)
        self.assertEqual("The model explains the observed issue.", finding.explanation)
        self.assertEqual(report.id, accept_runner_result(
            self.session, payload, self.token, self.signing_key, now=self.now).id)
        self.assertEqual(1, reap_expired_leases(self.session, _Cluster(), lambda _: None,
                                                now=self.now + timedelta(seconds=1)))
        self.session.commit()
        self.assertEqual(ScanState.COMPLETED, self.scan.state)


if __name__ == "__main__":
    unittest.main()
