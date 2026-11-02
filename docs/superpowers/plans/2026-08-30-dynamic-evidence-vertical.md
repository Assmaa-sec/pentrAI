# Dynamic Evidence Vertical Implementation Plan

> **For implementers:** Work through the tasks in order and verify each step. Checkboxes (`- [ ]`) track completion.

**Goal:** Validate one owned Flask vulnerability class end-to-end through the reviewed harness, producing redacted immutable evidence and correct finding outcomes.

**Architecture:** The runner receives verified grant claims, constructs the existing policy-limited harness, and exposes only reviewed structured actions to a deterministic validator. The legacy tool server is runner-local; the target and model never receive its generic endpoints.

**Tech Stack:** existing `pentrai_pipeline/harness`, FastAPI runner adapter, Kubernetes client, pytest, internal Flask fixture.

**Spec:** `docs/superpowers/specs/2026-08-30-deployable-pilot-design.md`

## Global Constraints

- Run this work only after execution-isolation staging tests pass.
- Begin with one non-destructive ownership-authorization validation class against company-owned fixtures.
- The model may not create raw requests, paths, targets, commands, or tool flags.
- Confirmation requires predicate-checked evidence, not a model assertion.

---

### Task 1: Make harness audit and policy records durable

**Files:**
- Modify: `pentrai_pipeline/harness/contracts.py`
- Modify: `pentrai_pipeline/harness/agent_harness.py`
- Create: `execution_manager/collector.py`
- Test: `tests/test_agent_harness.py`
- Create: `tests/execution/test_harness_collector.py`

**Interfaces:**
- Produces: `collect_harness_event(event: HarnessEvent) -> None`; `collect_tool_result(result: ToolResult) -> EvidenceRecord`

- [ ] **Step 1: Write a failing redaction persistence test**

```python
def test_collector_persists_redacted_output_not_raw_secret(session):
    record = collect_tool_result(ToolResult(
        request_id="r", tool="http_probe", status=ResultStatus.SUCCEEDED,
        summary="ok", raw={"stdout": "token=supersecret"}, redacted_output="token=[REDACTED]",
    ))
    assert record.redacted_output == "token=[REDACTED]"
    assert "supersecret" not in serialize(record)
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/execution/test_harness_collector.py::test_collector_persists_redacted_output_not_raw_secret -q`

Expected: FAIL because collector does not exist.

- [ ] **Step 3: Implement collector boundary**

Persist scan ID, request ID, tool ID, decision, bounded summary, redacted output, output digest, policy version, and timestamps. Never serialize `ToolResult.raw`; place sealed raw evidence, if required, behind a separate restricted artifact path.

- [ ] **Step 4: Run harness and collector tests**

Run: `pytest tests/test_agent_harness.py tests/execution/test_harness_collector.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pentrai_pipeline/harness execution_manager/collector.py tests
git commit -m "feat: persist redacted harness evidence"
```

### Task 2: Add runner-local reviewed adapter and target binding

**Files:**
- Create: `runner_adapter/app.py`
- Create: `runner_adapter/routes.py`
- Create: `runner_adapter/auth.py`
- Create: `deploy/helm/pentrAI-execution/templates/runner-adapter.yaml`
- Test: `tests/runner_adapter/test_routes.py`

**Interfaces:**
- Produces: `POST /v1/actions/{tool}` accepting `ToolRequest`; `verify_runner_token(token) -> ScanGrantClaims`

- [ ] **Step 1: Write a failing generic-route denial test**

```python
def test_adapter_refuses_legacy_command_route(client, runner_token):
    response = client.post("/api/command", headers={"Authorization": f"Bearer {runner_token}"})
    assert response.status_code == 404

def test_adapter_injects_own_target(client, runner_token):
    response = client.post("/v1/actions/http_probe", json={"parameters": {}},
                           headers={"Authorization": f"Bearer {runner_token}"})
    assert response.status_code == 200
    assert response.json()["target"] == "http://target:8000"
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/runner_adapter/test_routes.py -q`

Expected: FAIL because adapter does not exist.

- [ ] **Step 3: Implement minimal adapter**

Bind one verified scan grant to one harness and one `SandboxTarget`. Serve only catalog action names, deny all unknown routes, validate bearer audience/expiry/scan ID, and forward only policy-injected fields to the runner-local legacy service.

- [ ] **Step 4: Run adapter tests**

Run: `pytest tests/runner_adapter/test_routes.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add runner_adapter deploy/helm/pentrAI-execution/templates/runner-adapter.yaml tests/runner_adapter
git commit -m "feat: add reviewed runner action adapter"
```

### Task 3: Implement one ownership-bypass validator and evidence predicate

**Files:**
- Create: `pentrai_pipeline/validators/contracts.py`
- Create: `pentrai_pipeline/validators/object_ownership.py`
- Create: `tests/validators/test_object_ownership.py`
- Create: `tests/fixtures/flask_owned_target/`

**Interfaces:**
- Produces: `validate_object_ownership(context: ValidationContext) -> ValidationAttempt`; `OwnershipEvidence.is_confirmed() -> bool`

- [ ] **Step 1: Write failing positive and negative tests**

```python
def test_confirms_when_second_principal_reads_first_principal_object(fake_target):
    attempt = validate_object_ownership(fake_target.context(vulnerable=True))
    assert attempt.outcome is ValidationOutcome.CONFIRMED
    assert attempt.evidence.is_confirmed()

def test_refutes_when_target_returns_forbidden(fake_target):
    attempt = validate_object_ownership(fake_target.context(vulnerable=False))
    assert attempt.outcome is ValidationOutcome.REFUTED
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/validators/test_object_ownership.py -q`

Expected: FAIL because validator does not exist.

- [ ] **Step 3: Implement deterministic proof criteria**

Use two approved test identities resolved by opaque broker profiles. Create/read only fixture-owned records, request the same object under a second identity through the harness, and confirm only if the expected foreign object identifier is returned. Capture redacted request metadata, response status, object digest, and reproduction steps. Return refuted for authorization denial and inconclusive for timeout/ambiguous response.

- [ ] **Step 4: Run validator tests**

Run: `pytest tests/validators/test_object_ownership.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pentrai_pipeline/validators tests/validators tests/fixtures/flask_owned_target
git commit -m "feat: validate object ownership evidence"
```

### Task 4: Wire lifecycle, target reset, and staging acceptance

**Files:**
- Create: `execution_manager/reset.py`
- Modify: `pentrai_pipeline/orchestrator.py`
- Create: `tests/execution/test_dynamic_vertical_staging.py`
- Modify: `docs/RELEASE_ASSURANCE.md`

**Interfaces:**
- Produces: `reset_target(lease: RunnerLease) -> None`; persisted `ValidationAttempt` and `Evidence`

- [ ] **Step 1: Write a failing reset-before-attempt test**

```python
def test_each_destructive_attempt_starts_from_baseline(fake_execution_manager):
    run_validation_plan(fake_execution_manager, two_attempt_plan())
    assert fake_execution_manager.reset_calls == 2
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/execution/test_dynamic_vertical_staging.py::test_each_destructive_attempt_starts_from_baseline -q`

Expected: FAIL because reset orchestration does not exist.

- [ ] **Step 3: Implement lifecycle wiring**

Before each active attempt, replace target state from the immutable managed-template baseline. Emit state/audit events, collect evidence, map predicates to finding state, and always invoke lease cleanup. Keep `PENTRAI_DYNAMIC_SCANS_ENABLED=false` unless the staging test command explicitly supplies an internal-fixture environment.

- [ ] **Step 4: Run owned-fixture staging test**

Run: `pytest tests/execution/test_dynamic_vertical_staging.py -m staging -q`

Expected: PASS for one confirmed and one refuted ownership case, with no surviving namespace or artifact grant.

- [ ] **Step 5: Commit**

```bash
git add execution_manager/reset.py pentrai_pipeline/orchestrator.py tests/execution/test_dynamic_vertical_staging.py docs/RELEASE_ASSURANCE.md
git commit -m "feat: add evidence-backed dynamic validation vertical"
```
