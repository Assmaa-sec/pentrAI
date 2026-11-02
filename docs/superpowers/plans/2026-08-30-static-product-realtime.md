# Static Product and Real-Time UX Implementation Plan

> **For implementers:** Work through the tasks in order and verify each step. Checkboxes (`- [ ]`) track completion.

**Goal:** Deliver the complete static-analysis product vertical: safe archive upload/intake, SBOM/SCA, normalized findings, reports, durable SSE updates, and the conversation-first React workspace.

**Architecture:** The API grants tenant-scoped uploads and writes scan events through the outbox. Isolated static workers consume artifact IDs, produce normalized immutable records, and never run customer code. The web client resumes the event stream from `Last-Event-ID`; scan Q&A is read-only.

**Tech Stack:** FastAPI, PostgreSQL, OSS S3-compatible client, Python stdlib archive parsing, CycloneDX SBOM, osv-scanner, React, TypeScript, Vite, SSE.

**Spec:** `docs/superpowers/specs/2026-08-30-deployable-pilot-design.md`

## Global Constraints

- Archive extraction rejects traversal, symlinks, hard links, duplicate names, over-limit member count, expanded size, nesting, and compression ratio.
- Workers receive opaque artifact IDs and write only collector-approved result records.
- All visible events persist before broadcast; browser reconnect must not duplicate or skip events.
- Reports disclose static coverage and never represent a detection as confirmed live validation.

---

### Task 1: Add tenant-scoped artifact metadata and upload grants

**Files:**
- Create: `control_plane/app/artifacts/models.py`
- Create: `control_plane/app/artifacts/service.py`
- Create: `control_plane/app/api/uploads.py`
- Test: `tests/control_plane/test_uploads.py`

**Interfaces:**
- Produces: `create_upload_grant(actor, project_id, content_type, size) -> UploadGrant`; `finalize_upload(grant_id, sha256, object_key) -> SourceArtifact`

- [ ] **Step 1: Write a failing cross-tenant grant test**

```python
def test_upload_grant_cannot_finalize_other_org_object(client, owner_token, foreign_object_key):
    grant = create_grant(client, owner_token)
    response = client.post(f"/v1/uploads/{grant['id']}/finalize", json={
        "sha256": "a" * 64, "object_key": foreign_object_key,
    })
    assert response.status_code == 422
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/control_plane/test_uploads.py::test_upload_grant_cannot_finalize_other_org_object -q`

Expected: FAIL because upload API does not exist.

- [ ] **Step 3: Implement grants and immutable finalization**

Generate an OSS object key from organization/project/grant UUIDs, not user input. Limit content type and declared bytes. On finalization, verify the object belongs to the grant prefix, record SHA-256/size/content type, mark the source immutable, and append audit/outbox rows.

- [ ] **Step 4: Run upload tests**

Run: `pytest tests/control_plane/test_uploads.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control_plane/app/artifacts control_plane/app/api/uploads.py tests/control_plane/test_uploads.py
git commit -m "feat: add scoped source artifact uploads"
```

### Task 2: Implement isolated archive intake and static job contract

**Files:**
- Create: `static_worker/contracts.py`
- Create: `static_worker/intake.py`
- Create: `static_worker/worker.py`
- Create: `tests/static_worker/test_intake.py`
- Create: `tests/fixtures/archives/`

**Interfaces:**
- Produces: `inspect_archive(path: Path, limits: IntakeLimits) -> SourceInventory`; `run_static_job(job: StaticJob) -> StaticResult`

- [ ] **Step 1: Write failing malicious-archive tests**

```python
@pytest.mark.parametrize("fixture,reason", [
    ("zip-slip.zip", "path escapes destination"),
    ("symlink.zip", "links are not allowed"),
    ("oversize.zip", "expanded size limit"),
])
def test_intake_rejects_unsafe_archive(fixture, reason):
    with pytest.raises(IntakeRejected, match=reason):
        inspect_archive(FIXTURES / fixture, IntakeLimits(max_expanded_bytes=1024))
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/static_worker/test_intake.py -q`

Expected: FAIL because intake does not exist.

- [ ] **Step 3: Implement metadata-first extraction**

Read ZIP metadata before extracting. Normalize every member with `PurePosixPath`; reject absolute/traversal paths, non-regular files, duplicate normalized names, excessive members/ratio/depth/size. Extract only after all checks pass into a job-owned temporary directory. Produce inventory and a manifest digest.

- [ ] **Step 4: Run intake suite**

Run: `pytest tests/static_worker/test_intake.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add static_worker tests/static_worker tests/fixtures/archives
git commit -m "feat: add bounded static intake worker"
```

### Task 3: Produce SBOM/SCA findings and safe reports

**Files:**
- Create: `static_worker/sbom.py`
- Create: `static_worker/sca.py`
- Create: `control_plane/app/findings/service.py`
- Create: `control_plane/app/reports/render.py`
- Test: `tests/static_worker/test_sca.py`
- Test: `tests/control_plane/test_reports.py`

**Interfaces:**
- Produces: `build_sbom(inventory) -> SbomArtifact`; `scan_dependencies(sbom) -> list[DetectedFinding]`; `render_report(scan_id, audience) -> ReportArtifact`

- [ ] **Step 1: Write failing scanner normalization test**

```python
def test_osv_hit_becomes_detected_sca_finding(fake_osv):
    findings = scan_dependencies(sample_sbom(), osv_client=fake_osv)
    assert findings[0].state == FindingState.DETECTED
    assert findings[0].source == FindingSource.SCA
    assert findings[0].cve == "CVE-2024-0001"
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/static_worker/test_sca.py::test_osv_hit_becomes_detected_sca_finding -q`

Expected: FAIL because SCA module does not exist.

- [ ] **Step 3: Implement deterministic scan and report rendering**

Generate CycloneDX JSON from supported manifests. Invoke the pinned scanner with a fixed timeout and parse only JSON. Persist scanner version/database version, dependency, advisory, severity, and provenance. Render Markdown from records; escape all source-derived text before PDF/DOCX conversion and label findings as detected, not confirmed.

- [ ] **Step 4: Run static/report suites**

Run: `pytest tests/static_worker/test_sca.py tests/control_plane/test_reports.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add static_worker control_plane/app/findings control_plane/app/reports tests/static_worker/test_sca.py tests/control_plane/test_reports.py
git commit -m "feat: add static SBOM scanning and reports"
```

### Task 4: Stream durable events and build the scan workspace

**Files:**
- Create: `control_plane/app/api/events.py`
- Create: `control_plane/app/api/scan_questions.py`
- Create: `web/src/pages/ScanWorkspace.tsx`
- Create: `web/src/lib/scanEvents.ts`
- Create: `web/src/components/LiveFeed.tsx`
- Create: `web/src/components/ScanContext.tsx`
- Test: `tests/control_plane/test_sse.py`
- Test: `web/src/lib/scanEvents.test.ts`

**Interfaces:**
- Produces: `GET /v1/scans/{scan_id}/events`; `POST /v1/scans/{scan_id}/questions`; `useScanEvents(scanId) -> ScanEvent[]`

- [ ] **Step 1: Write failing resume test**

```python
def test_sse_resumes_after_last_event_id(client, scan, events):
    response = client.get(
        f"/v1/scans/{scan.id}/events",
        headers={"Last-Event-ID": str(events[0].sequence)},
    )
    assert str(events[0].sequence) not in response.text
    assert str(events[1].sequence) in response.text
```

- [ ] **Step 2: Run the API test**

Run: `pytest tests/control_plane/test_sse.py::test_sse_resumes_after_last_event_id -q`

Expected: FAIL because SSE endpoint does not exist.

- [ ] **Step 3: Implement SSE and read-only questions**

Query durable visible events by organization, scan ID, and sequence. Emit `id: <sequence>` plus JSON data; poll the outbox-backed event table with a bounded heartbeat. Build question context only from visible redacted summaries and evidence; reject tool/state/policy verbs and record the question/audit event.

- [ ] **Step 4: Implement the React workspace**

Render the approved production workspace: feed, risk/coverage/budget/evidence metrics, current check, activity, scope, cancel action, and report links. Use `EventSource` with browser-managed reconnect. Keep the Q&A composer separate from the SSE feed and never render raw tool/model payloads.

- [ ] **Step 5: Run API and UI tests**

Run: `pytest tests/control_plane/test_sse.py -q && npm --prefix web test -- --run scanEvents.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add control_plane/app/api/events.py control_plane/app/api/scan_questions.py web tests/control_plane/test_sse.py
git commit -m "feat: add live conversation-first scan workspace"
```
