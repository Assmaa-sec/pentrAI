# Control Plane Foundation Implementation Plan

> **For implementers:** Work through the tasks in order and verify each step. Checkboxes (`- [ ]`) track completion.

**Goal:** Build the organization-scoped FastAPI control plane, durable scan state, signed scan grants, audit history, and transactional outbox with no dynamic execution.

**Architecture:** `control_plane` owns authority and PostgreSQL owns durable state. HTTP handlers authenticate a user, authorize organization membership, update state and append audit/outbox rows in one transaction; a separate worker claims outbox rows using `FOR UPDATE SKIP LOCKED`.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL, Authlib OIDC.

**Spec:** `docs/superpowers/specs/2026-08-30-deployable-pilot-design.md`

## Global Constraints

- No customer code executes in `control_plane`.
- Every primary entity is organization-scoped and every mutable endpoint requires an idempotency key.
- Scan grants bind organization, project, source digest, profile, scope, dynamic authorization, issuance, and expiry.
- The API returns opaque artifact IDs, never filesystem paths or provider keys.

---

### Task 1: Create the installable control-plane package and configuration

**Files:**
- Create: `pyproject.toml`
- Create: `control_plane/app/__init__.py`
- Create: `control_plane/app/settings.py`
- Create: `control_plane/app/main.py`
- Test: `tests/control_plane/test_settings.py`

**Interfaces:**
- Produces: `Settings.from_env() -> Settings`; `create_app(settings: Settings) -> FastAPI`

- [ ] **Step 1: Write the failing settings test**

```python
def test_settings_rejects_default_signing_key(monkeypatch):
    monkeypatch.setenv("PENTRAI_DATABASE_URL", "postgresql+psycopg://x")
    monkeypatch.setenv("PENTRAI_GRANT_SIGNING_KEY", "change-me")
    with pytest.raises(ValueError, match="grant signing key"):
        Settings.from_env()
```

- [ ] **Step 2: Run the test to verify failure**

Run: `pytest tests/control_plane/test_settings.py::test_settings_rejects_default_signing_key -q`

Expected: FAIL because `Settings` does not exist.

- [ ] **Step 3: Write the minimal implementation**

```python
class Settings(BaseModel):
    database_url: str
    grant_signing_key: SecretStr
    dynamic_scans_enabled: bool = False

    @classmethod
    def from_env(cls) -> "Settings": ...

def create_app(settings: Settings) -> FastAPI:
    app = FastAPI()
    app.get("/healthz")(lambda: {"status": "ok"})
    return app
```

- [ ] **Step 4: Run the focused test**

Run: `pytest tests/control_plane/test_settings.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml control_plane/app tests/control_plane/test_settings.py
git commit -m "feat: add control plane application shell"
```

### Task 2: Add organization-scoped database schema and Alembic migration

**Files:**
- Create: `control_plane/app/db.py`
- Create: `control_plane/app/models.py`
- Create: `alembic.ini`
- Create: `alembic/env.py`
- Create: `alembic/versions/001_control_plane_core.py`
- Test: `tests/control_plane/test_models.py`

**Interfaces:**
- Produces: `Organization`, `User`, `Membership`, `Project`, `Scan`, `AuditEvent`, `OutboxEvent`

- [ ] **Step 1: Write the failing ownership test**

```python
def test_project_is_unique_per_organization(session):
    org = Organization(name="Northstar")
    session.add_all([org, Project(organization=org, name="Payments")])
    session.flush()
    session.add(Project(organization=org, name="Payments"))
    with pytest.raises(IntegrityError):
        session.flush()
```

- [ ] **Step 2: Run the test to verify failure**

Run: `pytest tests/control_plane/test_models.py::test_project_is_unique_per_organization -q`

Expected: FAIL because models do not exist.

- [ ] **Step 3: Implement models and migration**

Use UUID IDs, UTC timestamps, foreign keys with `ON DELETE RESTRICT`, and `organization_id` on every customer-owned table. Define a unique `(organization_id, name)` project constraint. Store audit/outbox payloads in JSONB and prohibit source/secret bytes in their schema.

- [ ] **Step 4: Run migration and tests**

Run: `alembic upgrade head && pytest tests/control_plane/test_models.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control_plane/app/db.py control_plane/app/models.py alembic.ini alembic tests/control_plane/test_models.py
git commit -m "feat: add organization scoped control plane schema"
```

### Task 3: Implement OIDC identity mapping and RBAC query boundary

**Files:**
- Create: `control_plane/app/auth.py`
- Create: `control_plane/app/deps.py`
- Create: `control_plane/app/api/projects.py`
- Modify: `control_plane/app/main.py`
- Test: `tests/control_plane/test_rbac.py`

**Interfaces:**
- Produces: `CurrentActor`; `require_role(*roles) -> Dependency`
- Consumes: OIDC subject, `Membership`, project ID

- [ ] **Step 1: Write the cross-organization denial test**

```python
def test_member_cannot_read_another_organization_project(client, other_project, member_token):
    response = client.get(
        f"/v1/projects/{other_project.id}",
        headers={"Authorization": f"Bearer {member_token}"},
    )
    assert response.status_code == 404
```

- [ ] **Step 2: Run the failing test**

Run: `pytest tests/control_plane/test_rbac.py::test_member_cannot_read_another_organization_project -q`

Expected: FAIL because endpoint/dependency does not exist.

- [ ] **Step 3: Implement minimal RBAC**

Map owner, security engineer, developer, and viewer through memberships. Every project or scan query filters both requested ID and `CurrentActor.organization_id`; return 404 outside the organization. Only owner/security engineer may create scans.

- [ ] **Step 4: Run RBAC suite**

Run: `pytest tests/control_plane/test_rbac.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control_plane/app/auth.py control_plane/app/deps.py control_plane/app/api/projects.py control_plane/app/main.py tests/control_plane/test_rbac.py
git commit -m "feat: enforce organization scoped RBAC"
```

### Task 4: Add state transitions, audit, idempotency, and transactional outbox

**Files:**
- Create: `control_plane/app/scans/state.py`
- Create: `control_plane/app/scans/service.py`
- Create: `control_plane/app/workers/outbox.py`
- Test: `tests/control_plane/test_scan_state.py`

**Interfaces:**
- Produces: `transition_scan(session, scan_id, actor, to_state, key) -> Scan`; `claim_outbox(session, limit) -> list[OutboxEvent]`

- [ ] **Step 1: Write failing transition tests**

```python
def test_completed_scan_cannot_reenter_static(session, scan, actor):
    scan.state = ScanState.COMPLETED
    with pytest.raises(InvalidTransition):
        transition_scan(session, scan.id, actor, ScanState.STATIC, "k1")

def test_same_idempotency_key_returns_original_transition(session, scan, actor):
    first = transition_scan(session, scan.id, actor, ScanState.AUTHORIZED, "k2")
    second = transition_scan(session, scan.id, actor, ScanState.AUTHORIZED, "k2")
    assert second.audit_event_id == first.audit_event_id
```

- [ ] **Step 2: Run the failing tests**

Run: `pytest tests/control_plane/test_scan_state.py -q`

Expected: FAIL because the state service does not exist.

- [ ] **Step 3: Implement the one-transaction transition**

Lock the scan row, check the idempotency table, validate the state graph, update state, append an audit event, append an outbox event, and store the idempotency response in one transaction. Claim pending outbox rows with `FOR UPDATE SKIP LOCKED` and mark delivery only after success.

- [ ] **Step 4: Run state tests**

Run: `pytest tests/control_plane/test_scan_state.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control_plane/app/scans control_plane/app/workers/outbox.py tests/control_plane/test_scan_state.py
git commit -m "feat: add durable scan state and outbox"
```

### Task 5: Issue and verify bound expiring scan grants

**Files:**
- Create: `control_plane/app/scans/grants.py`
- Modify: `control_plane/app/models.py`
- Test: `tests/control_plane/test_grants.py`

**Interfaces:**
- Produces: `issue_grant(scan: Scan, ttl: timedelta) -> str`; `verify_grant(token: str, expected_source_digest: str) -> ScanGrantClaims`

- [ ] **Step 1: Write expiry and binding tests**

```python
def test_grant_rejects_wrong_source_digest(scan):
    token = issue_grant(scan, timedelta(minutes=5))
    with pytest.raises(GrantError, match="source digest"):
        verify_grant(token, expected_source_digest="different")

def test_grant_rejects_expired_token(frozen_time, scan):
    token = issue_grant(scan, timedelta(seconds=1))
    frozen_time.tick(delta=timedelta(seconds=2))
    with pytest.raises(GrantError, match="expired"):
        verify_grant(token, expected_source_digest=scan.source_digest)
```

- [ ] **Step 2: Run the failing tests**

Run: `pytest tests/control_plane/test_grants.py -q`

Expected: FAIL because grant functions do not exist.

- [ ] **Step 3: Implement HMAC-signed claims**

Include grant ID, organization ID, project ID, scan ID, source digest, profile, scope digest, dynamic flag, issued-at, and expiry. Persist a grant digest and revocation time. Reject revoked, expired, or mismatched claims.

- [ ] **Step 4: Run the foundation suite**

Run: `pytest tests/control_plane -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control_plane/app/scans/grants.py control_plane/app/models.py tests/control_plane/test_grants.py
git commit -m "feat: issue bound expiring scan grants"
```
