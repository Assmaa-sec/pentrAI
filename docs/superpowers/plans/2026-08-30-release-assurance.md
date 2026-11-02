# Release Assurance Implementation Plan

> **For implementers:** Work through the tasks in order and verify each step. Checkboxes (`- [ ]`) track completion.

**Goal:** Produce the automated operational evidence, deployment controls, runbooks, and signed acceptance record required for an opt-in one-customer pilot.

**Architecture:** CI builds immutable images and SBOMs, runs unit/integration/adversarial suites, signs artifacts, and promotes the same digests through staging. Staging exercises real ACK containment, cleanup, restore, and rollback; the release controller refuses dynamic enablement without a complete signed evidence record.

**Tech Stack:** GitHub Actions or GitLab CI, ACR, cosign/KMS signing, Helm, Terraform/ROS, OpenTelemetry, Prometheus, SLS, pytest, Playwright.

**Spec:** `docs/superpowers/specs/2026-08-30-deployable-pilot-design.md`

## Global Constraints

- Use only company-owned fixtures and synthetic credentials in CI/staging.
- Deploy identical signed image digests to staging and pilot.
- Dynamic enablement is a release decision, not an environment variable an operator can casually toggle.
- Backup/restore and rollback are release tests, not documentation-only claims.

---

### Task 1: Build signed images, SBOMs, and admission verification

**Files:**
- Create: `.github/workflows/build.yml`
- Create: `scripts/build-images.ps1`
- Create: `scripts/verify-image-policy.py`
- Create: `tests/release/test_image_policy.py`
- Modify: `deploy/helm/pentrAI-execution/templates/gatekeeper-constraints.yaml`

**Interfaces:**
- Produces: `release-manifest.json` containing image digest, SBOM digest, signature identity, scanner result

- [ ] **Step 1: Write failing unsigned-image test**

```python
def test_release_manifest_rejects_unsigned_execution_image(tmp_path):
    manifest = {"images": [{"name": "runner", "digest": "sha256:1", "signed": False}]}
    with pytest.raises(ReleasePolicyError, match="unsigned"):
        verify_release_manifest(manifest)
```

- [ ] **Step 2: Run test**

Run: `pytest tests/release/test_image_policy.py -q`

Expected: FAIL because verifier does not exist.

- [ ] **Step 3: Implement build and verification**

Build each service from a pinned base digest, generate SBOM, scan vulnerabilities, sign the resulting immutable ACR digest through KMS-backed signing, and write a manifest. The Helm chart accepts only digest references and admission rejects unsigned registries/images.

- [ ] **Step 4: Run build-policy suite**

Run: `pytest tests/release/test_image_policy.py -q && python scripts/verify-image-policy.py release-manifest.json`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/build.yml scripts deploy/helm tests/release/test_image_policy.py
git commit -m "ci: sign and verify release images"
```

### Task 2: Turn the release corpus into executable acceptance tests

**Files:**
- Create: `tests/corpus/manifest.json`
- Create: `tests/corpus/runner.py`
- Create: `tests/corpus/test_cases.py`
- Create: `tests/fixtures/prompt_injection/`
- Create: `tests/fixtures/rendering/`
- Modify: `docs/RELEASE_ASSURANCE.md`

**Interfaces:**
- Produces: `run_corpus(environment: str) -> CorpusResult`

- [ ] **Step 1: Write failing corpus-manifest test**

```python
def test_every_corpus_fixture_declares_expected_state_and_cleanup():
    result = load_corpus_manifest()
    for case in result.cases:
        assert case.expected_scan_state
        assert case.expected_findings
        assert case.expected_cleanup is True
```

- [ ] **Step 2: Run test**

Run: `pytest tests/corpus/test_cases.py -q`

Expected: FAIL because corpus manifest/loader does not exist.

- [ ] **Step 3: Implement fixtures and runner**

Include true positives/negatives, malicious archives, template mismatches, prompt injection, secret redaction, report HTML/formula injection, unsafe workload requests, cleanup failure simulation, remediation scope violation, and guinea-pig expected outcomes. Each case declares expected terminal scan state, findings, visible redactions, network assertion, and cleanup assertion.

- [ ] **Step 4: Run local corpus**

Run: `pytest tests/corpus/test_cases.py -q && python -m tests.corpus.runner --environment local`

Expected: PASS with dynamic cases skipped outside staging.

- [ ] **Step 5: Commit**

```bash
git add tests/corpus tests/fixtures docs/RELEASE_ASSURANCE.md
git commit -m "test: add deployment acceptance corpus"
```

### Task 3: Add observability, audit export, backup restore, and rollback drills

**Files:**
- Create: `deploy/helm/pentrAI-control/templates/otel-config.yaml`
- Create: `deploy/helm/pentrAI-control/templates/alerts.yaml`
- Create: `scripts/backup-restore-verify.py`
- Create: `scripts/rollback-verify.py`
- Create: `docs/runbooks/backup-restore.md`
- Create: `docs/runbooks/rollback.md`
- Create: `tests/release/test_operational_drills.py`

**Interfaces:**
- Produces: `verify_restore(snapshot_id) -> RestoreEvidence`; `verify_rollback(previous_manifest) -> RollbackEvidence`

- [ ] **Step 1: Write failing drill tests**

```python
def test_restore_evidence_requires_scans_artifacts_and_audit():
    evidence = verify_restore("snapshot-1", fake_restore_missing_audit=True)
    assert evidence.passed is False
    assert "audit" in evidence.failures

def test_rollback_requires_previous_signed_manifest():
    with pytest.raises(ReleasePolicyError, match="signed"):
        verify_rollback({"images": [{"digest": "sha256:old", "signed": False}]})
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/release/test_operational_drills.py -q`

Expected: FAIL because drill code does not exist.

- [ ] **Step 3: Implement evidence-producing drills**

Emit structured metrics for scan state, lease age, cleanup failure, policy denial, SSE lag, queue age, provider errors, and secret-redaction failure. Configure alert thresholds. Restore encrypted RDS/OSS snapshots into isolated staging and compare scan/artifact/audit digests. Roll back Helm release to the previous signed manifest and prove health plus schema compatibility.

- [ ] **Step 4: Run drills**

Run: `pytest tests/release/test_operational_drills.py -q && python scripts/backup-restore-verify.py --staging && python scripts/rollback-verify.py --staging`

Expected: PASS with saved evidence artifacts.

- [ ] **Step 5: Commit**

```bash
git add deploy/helm/pentrAI-control scripts docs/runbooks tests/release/test_operational_drills.py
git commit -m "ops: add restore rollback and observability drills"
```

### Task 4: Enforce pilot release decision and produce acceptance record

**Files:**
- Create: `control_plane/app/releases/service.py`
- Create: `control_plane/app/api/releases.py`
- Create: `tests/control_plane/test_release_gate.py`
- Create: `docs/runbooks/pilot-release.md`

**Interfaces:**
- Produces: `evaluate_release(candidate: ReleaseCandidate) -> ReleaseDecision`; `POST /v1/releases/{id}/approve-pilot`

- [ ] **Step 1: Write failing dynamic-gate test**

```python
def test_release_refuses_dynamic_enablement_without_containment_evidence(candidate):
    candidate.evidence["containment"] = None
    decision = evaluate_release(candidate)
    assert decision.approved is False
    assert "containment" in decision.missing

def test_only_owner_can_approve_pilot(client, candidate, developer_token):
    assert client.post(f"/v1/releases/{candidate.id}/approve-pilot",
                       headers={"Authorization": f"Bearer {developer_token}"}).status_code == 403
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/control_plane/test_release_gate.py -q`

Expected: FAIL because release service does not exist.

- [ ] **Step 3: Implement signed acceptance record**

Require signed image/SBOM/scanner data; passing corpus; containment/reset/cleanup evidence; report/redaction checks; backup/restore and rollback evidence; documented supported targets; deferred-risk approvals; and independent security-review reference. Only an owner may approve an opt-in pilot. Persist the decision and publish a human-readable release record; the dynamic toggle reads this record instead of a raw environment variable.

- [ ] **Step 4: Run full release gate**

Run: `pytest tests/control_plane/test_release_gate.py -q && python -m tests.corpus.runner --environment staging`

Expected: PASS only with a complete staging evidence bundle.

- [ ] **Step 5: Commit**

```bash
git add control_plane/app/releases control_plane/app/api/releases.py tests/control_plane/test_release_gate.py docs/runbooks/pilot-release.md
git commit -m "feat: enforce pilot release acceptance gate"
```
