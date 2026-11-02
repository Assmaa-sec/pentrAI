from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from execution_manager.cluster_adapter import ClusterOperationFailed, KubectlCluster


class ClusterAdapterTests(unittest.TestCase):
    def setUp(self):
        self.kubeconfig = Path("CODEX.md")
        self.namespace = "scan-" + "a" * 32
        self.cluster = KubectlCluster(self.kubeconfig, "execution-context", self.namespace)

    def test_apply_uses_stdin_and_refuses_other_namespace(self):
        document = {"apiVersion": "v1", "kind": "Secret",
                    "metadata": {"name": "runner-identity", "namespace": self.namespace},
                    "data": {"model-token": "c2VjcmV0"}}
        with patch("execution_manager.cluster_adapter.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, "created", "")) as called:
            self.cluster.apply(document)
        args = called.call_args.args[0]
        self.assertEqual("-", args[-1])
        self.assertNotIn("c2VjcmV0", " ".join(args))
        self.assertEqual(document, json.loads(called.call_args.kwargs["input"]))
        with self.assertRaisesRegex(ValueError, "outside scan namespace"):
            self.cluster.apply({**document, "metadata": {"name": "runner-identity",
                                                       "namespace": "default"}})
        with patch("execution_manager.cluster_adapter.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 1, "", "secret leaked in stderr")):
            with self.assertRaises(ClusterOperationFailed) as raised:
                self.cluster.apply(document)
        self.assertNotIn("secret leaked", str(raised.exception))

    def test_stage_wait_and_pod_removal_are_observed(self):
        pending = json.dumps({"status": {"active": 1}})
        complete = json.dumps({"status": {"succeeded": 1,
                         "conditions": [{"type": "Complete", "status": "True"}]}})
        with (patch.object(self.cluster, "_run", side_effect=[pending, complete]) as called,
              patch("execution_manager.cluster_adapter.time.sleep")):
            self.cluster.wait_job_complete("stage-source", deadline_seconds=5)
        self.assertEqual(2, called.call_count)
        with patch.object(self.cluster, "_run", side_effect=["deleted", '{"items":[]}']):
            self.cluster.delete_stage_job()
        with patch.object(self.cluster, "_run", side_effect=["deleted", '{"items":[{}]}']):
            with self.assertRaisesRegex(ClusterOperationFailed, "pod has not been removed"):
                self.cluster.delete_stage_job()

    def test_staging_marker_must_match_lease_and_source(self):
        with patch.object(self.cluster, "_run", return_value=""):
            self.assertFalse(self.cluster.source_stage_marked("lease", "a" * 64))
        marker = json.dumps({"data": {"lease-id": "lease", "source-sha256": "a" * 64}})
        with patch.object(self.cluster, "_run", return_value=marker):
            self.assertTrue(self.cluster.source_stage_marked("lease", "a" * 64))
            with self.assertRaisesRegex(ClusterOperationFailed, "does not match"):
                self.cluster.source_stage_marked("other", "a" * 64)

    def test_existing_native_job_must_match_owned_manifest_fields(self):
        expected = {"apiVersion": "batch/v1", "kind": "Job",
                    "metadata": {"name": "hexstrike", "namespace": self.namespace,
                                 "labels": {"pentrai.io/lease-id": "lease"}},
                    "spec": {"activeDeadlineSeconds": 55, "backoffLimit": 0,
                             "template": {"spec": {"runtimeClassName": "runv"}}}}
        with patch.object(self.cluster, "_run", return_value=""):
            self.assertFalse(self.cluster.runner_job_exists(expected))
        observed = deepcopy(expected)
        observed["metadata"]["uid"] = "server-uid"
        observed["spec"]["activeDeadlineSeconds"] = 60
        with patch.object(self.cluster, "_run", return_value=json.dumps(observed)):
            self.assertTrue(self.cluster.runner_job_exists(expected))
        observed["spec"]["template"]["spec"]["runtimeClassName"] = "unsafe"
        with patch.object(self.cluster, "_run", return_value=json.dumps(observed)):
            with self.assertRaisesRegex(ClusterOperationFailed, "does not match"):
                self.cluster.runner_job_exists(expected)


if __name__ == "__main__":
    unittest.main()
