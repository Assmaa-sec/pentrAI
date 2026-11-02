# Execution Isolation Implementation Plan

> **For implementers:** Work through the tasks in order and verify each step. Checkboxes (`- [ ]`) track completion.

**Goal:** Provision and prove the Alibaba Cloud execution security domain and managed Flask runtime while keeping dynamic validation disabled.

**Architecture:** The control plane requests an execution-manager workload through private mTLS. The execution cluster uses dedicated ACK runV capacity and per-scan namespaces. Kubernetes policy, admission rules, short-lived artifact grants, and lease cleanup enforce isolation before the harness is connected.

**Tech Stack:** Terraform or ROS, ACK Pro, runV, Terway, Helm, Kubernetes NetworkPolicy, Gatekeeper, ACR, OSS, KMS, pytest/Kubernetes client.

**Spec:** `docs/superpowers/specs/2026-08-30-deployable-pilot-design.md`

## Global Constraints

- Validate the actual Alibaba China region/node/Runtimes before enabling the plan.
- No host Docker, Docker-in-Docker, customer recipe, hostPath, device, privileged pod, host namespace, root user, or arbitrary image.
- Target egress is off; builder egress is only internal registry/package mirror; execution has no RDS route.
- Dynamic validation remains false until this plan's staging acceptance tests pass.

---

### Task 1: Create reproducible control and execution VPC infrastructure

**Files:**
- Create: `infra/terraform/modules/network/main.tf`
- Create: `infra/terraform/modules/ack/main.tf`
- Create: `infra/terraform/environments/staging/main.tf`
- Create: `infra/terraform/environments/staging/variables.tf`
- Create: `infra/terraform/environments/staging/outputs.tf`
- Test: `infra/terraform/tests/plan.tftest.hcl`

**Interfaces:**
- Produces: private control/execution VPC IDs, ACK cluster IDs, node-pool IDs, RDS/OSS/KMS/ACR IDs

- [ ] **Step 1: Write a failing Terraform policy test**

```hcl
run "execution_cluster_has_no_public_node_ip" {
  command = plan
  assert {
    condition = alltrue([for pool in module.execution.node_pools : !pool.public_ip])
    error_message = "execution nodes must not have public IPs"
  }
}
```

- [ ] **Step 2: Run the test**

Run: `terraform -chdir=infra/terraform/environments/staging test`

Expected: FAIL because modules do not exist.

- [ ] **Step 3: Implement minimal private infrastructure**

Create separate VPC/vSwitch/security-group boundaries for control and execution. Create ACK Pro clusters with private API endpoint access, dedicated execution nodes compatible with runV, Terway NetworkPolicy enabled, private RDS, OSS buckets, KMS keys, ACR namespaces, and least-privilege RAM roles. Output IDs only, never secrets.

- [ ] **Step 4: Run Terraform validation**

Run: `terraform -chdir=infra/terraform/environments/staging fmt -check && terraform -chdir=infra/terraform/environments/staging validate && terraform -chdir=infra/terraform/environments/staging test`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add infra/terraform
git commit -m "infra: add isolated ACK staging foundation"
```

### Task 2: Add admission and network policy as code

**Files:**
- Create: `deploy/helm/pentrAI-execution/templates/gatekeeper-constraints.yaml`
- Create: `deploy/helm/pentrAI-execution/templates/default-deny.yaml`
- Create: `deploy/helm/pentrAI-execution/templates/allow-target-harness.yaml`
- Create: `deploy/helm/pentrAI-execution/templates/resource-quota.yaml`
- Test: `tests/execution/test_policy_manifests.py`

**Interfaces:**
- Produces: `render_execution_namespace(scan_id: str) -> list[dict]`

- [ ] **Step 1: Write a failing manifest test**

```python
def test_rendered_target_has_no_egress_and_runv_runtime():
    manifests = render_execution_namespace("scan-1")
    target = find_pod(manifests, "target")
    assert target["spec"]["runtimeClassName"] == "runv"
    assert default_deny_egress(manifests, "scan-1")
    assert not has_host_path(target)
    assert not is_privileged(target)
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/execution/test_policy_manifests.py::test_rendered_target_has_no_egress_and_runv_runtime -q`

Expected: FAIL because chart/manifests do not exist.

- [ ] **Step 3: Implement deny-by-default policy**

Install constraints rejecting privileged, host namespace, hostPath, Docker socket, devices, missing resource limits, untrusted registries, and root workloads. Render default deny ingress/egress, then explicit DNS, target/harness, collector, artifact broker, registry, and package-mirror rules. Add quota, deadline, and labels used for lease cleanup.

- [ ] **Step 4: Run rendering tests**

Run: `helm lint deploy/helm/pentrAI-execution && pytest tests/execution/test_policy_manifests.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/helm/pentrAI-execution tests/execution/test_policy_manifests.py
git commit -m "infra: enforce execution namespace isolation"
```

### Task 3: Define the managed Flask template and safe classifier

**Files:**
- Create: `managed_templates/flask/template.py`
- Create: `managed_templates/flask/requirements.lock`
- Create: `managed_templates/flask/Dockerfile`
- Create: `managed_templates/classifier.py`
- Test: `tests/managed_templates/test_flask_classifier.py`

**Interfaces:**
- Produces: `classify_managed_flask(inventory: SourceInventory) -> TemplateMatch | None`; `build_plan(match: TemplateMatch) -> ManagedBuildPlan`

- [ ] **Step 1: Write failing classification tests**

```python
def test_flask_requirements_and_wsgi_entrypoint_match_template(tmp_path):
    inventory = inventory_for(tmp_path, {
        "requirements.txt": "flask==3.0.0\n",
        "wsgi.py": "from app import app\n",
        "app.py": "from flask import Flask\napp=Flask(__name__)\n",
    })
    assert classify_managed_flask(inventory).entrypoint == "wsgi:app"

def test_customer_dockerfile_does_not_make_dynamic_eligible(tmp_path):
    inventory = inventory_for(tmp_path, {"Dockerfile": "FROM evil", "app.py": ""})
    assert classify_managed_flask(inventory) is None
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/managed_templates/test_flask_classifier.py -q`

Expected: FAIL because classifier does not exist.

- [ ] **Step 3: Implement a strict allowlist classifier**

Accept only a reviewed manifest and entrypoint shape, supported pinned Python minor version, no native build requirement, and an allowlisted dependency set. Treat all other projects as static-only. The template copies source as non-root, uses an immutable base digest, and permits only the internal package mirror.

- [ ] **Step 4: Run tests and image policy scan**

Run: `pytest tests/managed_templates/test_flask_classifier.py -q && trivy image --exit-code 1 managed-flask:local`

Expected: PASS after building from the pinned template.

- [ ] **Step 5: Commit**

```bash
git add managed_templates tests/managed_templates/test_flask_classifier.py
git commit -m "feat: add managed Flask dynamic template"
```

### Task 4: Implement lease creation, cleanup, and containment acceptance tests

**Files:**
- Create: `execution_manager/client.py`
- Create: `execution_manager/leases.py`
- Create: `execution_manager/reaper.py`
- Test: `tests/execution/test_leases.py`
- Test: `tests/execution/test_containment_staging.py`

**Interfaces:**
- Produces: `create_lease(grant: ScanGrantClaims) -> RunnerLease`; `reap_expired_leases(now) -> int`

- [ ] **Step 1: Write a failing cleanup test**

```def test_expired_lease_deletes_namespace_revokes_tokens_and_marks_cleaned(fake_cluster, lease):
    lease.expires_at = utcnow() - timedelta(seconds=1)
    assert reap_expired_leases(utcnow()) == 1
    assert fake_cluster.deleted_namespaces == [lease.namespace]
    assert lease.cleaned_at is not None
    assert lease.artifact_grant_revoked_at is not None
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/execution/test_leases.py -q`

Expected: FAIL because lease service does not exist.

- [ ] **Step 3: Implement idempotent lease lifecycle**

Create namespace/service account/artifact grant labels from a verified scan grant. Persist resource IDs and heartbeat. Reaper locks expired leases, deletes namespace, revokes grants, records audit events, and retries failures without declaring terminal cleanup prematurely.

- [ ] **Step 4: Run staging containment suite**

Run: `pytest tests/execution/test_leases.py -q && pytest tests/execution/test_containment_staging.py -m staging -q`

Expected: PASS proving target cannot reach public network, metadata, RDS, control plane, or a sibling namespace.

- [ ] **Step 5: Commit**

```bash
git add execution_manager tests/execution
git commit -m "feat: add isolated runner leases and cleanup"
```
