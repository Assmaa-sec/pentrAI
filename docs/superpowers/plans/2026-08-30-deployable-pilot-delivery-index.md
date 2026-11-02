# Deployable Pilot Delivery Index Implementation Plan

> **For implementers:** Work through the tasks in order and verify each step. Checkboxes (`- [ ]`) track completion.

**Goal:** Deliver the approved one-customer Alibaba Cloud pilot without enabling dynamic validation before containment and release evidence exist.

**Architecture:** Build the control plane and static product first, then add an isolated ACK execution cluster, a policy-limited dynamic harness, remediation/reporting, and release assurance. PostgreSQL is the durable source of truth; its transactional outbox is the durable dispatcher, so no queue message contains source, secrets, or prompts.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, Alembic, PostgreSQL, React/TypeScript, SSE, PostgreSQL outbox worker, Kubernetes/Helm, Terraform or ROS, Alibaba Cloud ACK/RDS/OSS/KMS/ACR.

**Spec:** `docs/superpowers/specs/2026-08-30-deployable-pilot-design.md`

## Global Constraints

- Preserve `pentrai_server.py` and `pentrai_mcp.py`; they are never a control-plane API.
- Dynamic scans are disabled by default and only support PentrAI-managed Flask templates after all runner gates pass.
- Never execute a customer Dockerfile, Compose file, arbitrary image, generic shell, or public-Internet target.
- All persisted records are organization-scoped; runners never access RDS directly.
- Secrets are opaque references outside the KMS-backed secret broker and never enter prompts, logs, reports, or browser state.
- Every visible scan event is persisted before SSE publication and resumes by `Last-Event-ID`.
- Report no application as safe; distinguish finding outcomes and disclose scope, coverage, tools, and budget.
- Add no dependency where Python stdlib, FastAPI, PostgreSQL, or existing project dependencies solve the requirement.

---

## Locked file structure

| Path | Responsibility |
|---|---|
| `control_plane/` | FastAPI app, database schema, RBAC, scan state machine, artifact broker, model gateway, outbox workers |
| `web/` | React conversation-first customer interface |
| `execution_manager/` | Control-plane client that creates isolated runner jobs; no source execution in this process |
| `managed_templates/flask/` | Reviewed builder/runtime templates and template classifier |
| `pentrai_pipeline/` | Retained typed analysis seed, refactored only behind new runner contracts |
| `infra/terraform/` | VPC, ACK, RDS, OSS, KMS, ACR, RAM, monitoring and policy-as-code |
| `deploy/helm/` | Signed application deployment charts and environment values |
| `tests/` | Unit, API, integration, fixture, runner, and acceptance coverage |
| `docs/runbooks/` | Release, incident, backup/restore, key rotation, and rollback procedures |

## Workstream order

1. [Control-plane foundation](2026-08-30-control-plane-foundation.md): durable schema, RBAC, grants, audit, state and outbox.
2. [Static product and real-time UX](2026-08-30-static-product-realtime.md): safe upload/intake/SBOM/SCA, reports, SSE, React workspace.
3. [Execution isolation](2026-08-30-execution-isolation.md): ACK/OSS/KMS/ACR infrastructure and managed Flask template, with dynamic disabled.
4. [Dynamic evidence vertical](2026-08-30-dynamic-evidence-vertical.md): reviewed harness, runner manager, one validation class and evidence lifecycle.
5. [Model and remediation](2026-08-30-model-remediation.md): consent-gated providers, SAST hypotheses, bounded patches and export.
6. [Release assurance](2026-08-30-release-assurance.md): CI/CD, corpus, observability, restore/rollback and pilot acceptance.

### Task 1: Establish delivery sequencing

**Files:**
- Create: all six workstream plan files listed above
- Modify: `docs/PROGRESS.md`

**Interfaces:**
- Consumes: approved design spec
- Produces: ordered implementation gates; no runtime code

- [ ] **Step 1: Record the six workstreams in `docs/PROGRESS.md`**

Add the exact names and dependency order above; mark every dynamic workstream blocked until Workstream 3 and its acceptance tests pass.

- [ ] **Step 2: Verify the index and progress tracker agree**

Run: `python -c "from pathlib import Path; a=Path('docs/PROGRESS.md').read_text(); b=Path('docs/superpowers/plans/2026-08-30-deployable-pilot-delivery-index.md').read_text(); assert 'Dynamic evidence vertical' in a and 'Dynamic evidence vertical' in b"`

Expected: PASS.

- [ ] **Step 3: Commit the planning index**

```bash
git add docs/PROGRESS.md docs/superpowers/plans/
git commit -m "docs: add deployable pilot delivery plans"
```

## Execution gates

- Workstream 2 may deploy to internal development but has no dynamic executor.
- Workstream 3 may provision staging resources but cannot enable dynamic scan traffic.
- Workstream 4 may run only against company-owned fixtures in staging.
- Workstream 6 alone authorizes enabling managed Flask dynamic validation for the opt-in pilot.
