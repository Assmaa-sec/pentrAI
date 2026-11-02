# PentrAI Pipeline — Build Progress & Playbook

**Shared source of truth for the pipeline build.** If you're picking up work, read this
file top to bottom once, then start at [How to build a phase](#how-to-build-a-phase).

- **What we're building & why:** [`ARCHITECTURE.md`](ARCHITECTURE.md)
- **Containment / safety rules:** [`THREAT_MODEL.md`](THREAT_MODEL.md)
- **This file:** where things stand · how to build the next phase · how to document a done one.

### How to use this file
1. The **[Phase status](#phase-status)** table is the at-a-glance tracker. Update the Status/Owner cells when you start and finish.
2. **[Invariants](#invariants-hold-in-every-phase)** must hold in every phase — read them once and don't break them.
3. **[How to build a phase](#how-to-build-a-phase)** is the repeatable process. Follow it every time.
4. When you finish, add a **[Phase log](#phase-logs)** entry from the template. *A phase is not "done" until its log exists.*
5. Manual/visual verification is **batched**: the product owner verifies in one pass. Never mark a phase user-verified yourself — append items to **[Pending manual verification](#pending-manual-verification)** instead.

---

## Phase status

### Deployable pilot workstreams

The approved pilot follows the [delivery index](superpowers/plans/2026-08-30-deployable-pilot-delivery-index.md)
and [design](superpowers/specs/2026-08-30-deployable-pilot-design.md). This
workstream sequence supersedes the legacy local-pipeline phase order below for
product release decisions. A completed local pipeline phase does not imply a
customer-ready release gate has passed.

| Order | Workstream | Status | Gate |
|---|---|---|---|
| 1 | [Control-plane foundation](superpowers/plans/2026-08-30-control-plane-foundation.md) | In progress | Durable ownership, grants, audit, and outbox |
| 2 | [Static product and real-time UX](superpowers/plans/2026-08-30-static-product-realtime.md) | In progress | Safe intake, static findings, reports, and persisted events |
| 3 | [Execution isolation](superpowers/plans/2026-08-30-execution-isolation.md) | Not started | Isolation and containment acceptance tests |
| 4 | [Dynamic evidence vertical](superpowers/plans/2026-08-30-dynamic-evidence-vertical.md) | Blocked by workstream 3 | Company-owned fixtures only until release assurance passes |
| 5 | [Model and remediation](superpowers/plans/2026-08-30-model-remediation.md) | Not started | Consent, typed hypotheses, bounded patches |
| 6 | [Release assurance](superpowers/plans/2026-08-30-release-assurance.md) | Not started | Required before opt-in pilot dynamic validation |

Dynamic validation remains disabled for production until workstream 3 and its
acceptance tests pass, and remains limited to internal fixtures until workstream
6 authorizes the opt-in pilot.

Phase A groundwork: versioned local JSON output and a read-only legacy tool
inventory are implemented. Run `python -m pentrai_pipeline.harness.inventory`
to emit the inventory. It currently discovers 176 HTTP routes and 169 MCP tools;
nine tool-to-route mappings require manual review. The inventory marks every
tool unsupported by the production broker. The control plane now has an
organization-scoped schema and migrations, OIDC JWT verification, signed scan
grants, upload metadata, local ZIP storage, scan creation, guarded transitions,
audit/outbox records, persisted scan events, tenant-scoped finding and report
reads, and a local static worker adapter that persists results. The static
worker has bounded ZIP intake, a pinned offline OSV adapter, normalized SCA
output, a partial CycloneDX SBOM, and escaped Markdown reports. These are
tested components, not yet a complete worker queue or customer release.

### Pilot implementation log — local static foundation (2026-10-03)

- **Built:** pinned installable control-plane dependencies; organization and
  scan migrations; OIDC verifier; tenant-scoped local upload and scan API;
  signed scan grants; persisted status events, findings, and reports; bounded
  static ZIP intake and offline SCA; one-shot local static worker with failure
  recording and workspace cleanup; React/Vite
  workspace for status, findings, report, events, and read-only questions.
- **Verified:** `pentrai-env/Scripts/python.exe -m unittest discover -s tests -q`
  passed 49 tests; `python -m compileall -q control_plane static_worker
  pentrai_pipeline` passed; fresh SQLite Alembic upgrade, downgrade, upgrade,
  and `check` passed; `pip check` found no broken requirements.
- **Package install:** `pip install -e ".[test]"` succeeded in the ignored
  Python 3.14 virtual environment; control-plane, static-worker, pipeline,
  FastAPI, Psycopg, and Authlib imports passed.
- **Live loopback check:** Uvicorn served `/healthz` with HTTP 200; a protected
  route returned HTTP 401 without a bearer token and HTTP 503 with a placeholder
  bearer token while OIDC was intentionally unconfigured.
- **Browser build:** `npm --prefix web run build` passed TypeScript and Vite.
  The managed command sandbox blocked a Vite child process with EPERM, so this
  check ran outside that sandbox after approval.
- **Browser smoke:** Playwright opened the local workspace at `127.0.0.1:5173`;
  the scan form rendered, the screenshot was inspected, and the console had no
  errors after adding a local favicon. Authenticated scan views still need a
  provisioned local OIDC test identity for manual review.
- **Local environment:** Python 3.14.3; FastAPI 0.142.2; Psycopg 3.3.6;
  Authlib 1.8.0; joserfc 1.7.5; OSV Scanner v2.6.0 with a SHA-256-pinned
  offline PyPI database for the guinea-pig positive corpus.
- **PostgreSQL proof:** an ephemeral official PostgreSQL 17 Alpine container
  accepted the full Alembic upgrade, downgrade, upgrade, `check`, and a
  transactional Psycopg write/read. The round trip exposed an orphaned
  `scanstate` enum; the initial migration now removes it on downgrade.
  The verification container was stopped afterward.
- **Open:** durable dispatch/leases/recovery, isolated
  runner and build service, SAST and validation, full broker registry, customer
  UX, encrypted artifact storage, remediation, and release assurance. Dynamic
  validation is closed. Deployment configuration remains unbound for local
  testing.

Legend: ⬜ not started · 🟨 in progress · ✅ code-complete (verified programmatically) · ✔️ user-verified

Model = suggested effort if building with Claude Code (Opus for the hard/security-critical spots, Sonnet for the bulk, Haiku for trivial edits). Wt = rough build/limit cost.

| # | Phase | Owner | Model | Wt | Status | Manual input / verification needed |
|---|-------|-------|-------|----|--------|-------------------------------------|
| 0 | Scaffold (contracts, orchestrator, stubs, docs) | — | Opus | med | ✅ | Skim `ARCHITECTURE.md` + `contracts.py`, confirm design matches intent (verif #1) |
| 1 | **Guinea pig** — vuln containerized web app + ground-truth `SOLUTIONS.md` | — | Opus | med | ✅ | V1/V2/V3 exploited live; Docker bring-up done in Phase 2; V4 (SCA) waits for Phase 4 |
| 2 | `ingest` + `sandbox` — target runs, isolated, egress blocked · **make-or-break** | — | Opus | high | ✅ | Verified live here (Docker Desktop): guinea pig built, isolated, egress cut, torn down clean |
| 3 | `recon` + `pentrai_client` — reach the running target via the engine | — | Sonnet | med | ⬜ | `pentrai_server.py` running on `PENTRAI_SERVER_URL` |
| 4 | `analyze_sca` — deps → CVE (deterministic) | — | Sonnet | low | ⬜ | `osv-scanner`/`trivy` installed |
| 5 | `analyze_sast` — LLM logic/authz, injection-hardened | — | Opus | high | ⬜ | LLM endpoint (`llm_proxy` + key) |
| 6 | `synthesize` + `exploit` — first validated finding end-to-end | — | Opus | high | ⬜ | **Verify the CONFIRMED finding + its evidence are real** |
| 7 | `report` — technical + client-facing | — | Sonnet | med | ⬜ | Read both reports for accuracy |
| 8 | Widen vuln classes / stacks | — | Sonnet | ongoing | ⬜ | — |
| 9 | Web front-end (deferred — last) | — | Sonnet | later | ⬜ | — |

---

## Invariants (hold in EVERY phase)

These are non-negotiable; a change that breaks one is wrong even if it "works":

1. **Never modify `pentrai_server.py` / `pentrai_mcp.py`.** Reach the 150-tool engine only through `pentrai_pipeline/tools/pentrai_client.py`.
2. **Stages communicate only through `contracts.py` artifacts.** If you must change a contract, update *every* consumer in the same change and note it in your phase log.
3. **Safety holds** (see `THREAT_MODEL.md`): sandbox egress stays **off** by default; code-under-test is treated as **data, never instructions**; the `Target.authorized` gate stays; every tool call is scoped to the sandbox target.
4. **Each stage stub names itself** in its `NotImplementedError` (e.g. `stages.ingest.ingest`). Replacing that stub with a real implementation is the unit of work — don't widen a phase's scope silently.
5. **The engine stays untouched and the package stays importable.** `python -m compileall pentrai_pipeline` and `import pentrai_pipeline` must pass at the end of every phase.

---

## How to build a phase

The process is the same for every stage — the stub's own docstring is the spec.

1. **Claim it.** In the table above, set the phase Status to 🟨 and put your name in Owner.
2. **Read the spec.** The stage module's docstring lists its exact responsibilities and I/O. Cross-read the [build order in `ARCHITECTURE.md`](ARCHITECTURE.md#build-order-recommended) and the [Invariants](#invariants-hold-in-every-phase) above.
3. **Branch.** `git checkout -b phase-<N>-<short-name>` (e.g. `phase-2-ingest-sandbox`).
4. **Build against the guinea pig.** Everything from Phase 2 on is tested against the Phase 1 target. If there's no guinea pig yet, you're on Phase 1 or 2.
5. **Implement to the contract.** Fill the stub; consume the previous artifact, return the next one. Keep contracts stable (Invariant 2).
6. **Prove it** — see [Definition of done](#definition-of-done-per-phase). Write the exact command that reproduces your result; you'll paste it into the log.
7. **Document it.** Add a [Phase log](#phase-logs) entry from the template. Append anything needing human eyes to [Pending manual verification](#pending-manual-verification).
8. **Land it.** Set Status ✅, commit, and open a PR / hand off. Reference the phase number in the commit.

### Definition of done (per phase)

A phase is code-complete (✅) when **all** of these are true:

- [ ] The stage's `NotImplementedError` is gone and the orchestrator flows past it (the stage trail advances one step further).
- [ ] A **documented command** reproduces the result (a `curl`, `python -m pentrai_pipeline …`, or a test).
- [ ] Programmatic checks pass: `python -m compileall pentrai_pipeline`, `import pentrai_pipeline`, and the orchestrator smoke test.
- [ ] The [Invariants](#invariants-hold-in-every-phase) still hold — spot-check: engine files untouched, sandbox egress off.
- [ ] A **Phase log entry exists**, and anything needing human eyes is in [Pending manual verification](#pending-manual-verification) (never assumed done).

✅ means *the builder verified it programmatically*. ✔️ (user-verified) is set **only** by the product owner after the batched manual pass.

---

## How to document a done phase

Copy this template into [Phase logs](#phase-logs) and fill every field. Keep it terse but reproducible — someone should be able to re-run and re-check your phase from the log alone.

```markdown
### Phase <N> — <name>  <status emoji>
- **Owner:** <name>   **Model:** <model>   **Date:** <YYYY-MM-DD>   **Commit:** <short sha / PR #>
- **Goal:** <one line — what this phase makes true>
- **Built / changed:**
  - `path/to/file.py` — <one line>
- **Key decisions / deviations:** <anything that differs from ARCHITECTURE.md, or a judgment call a reviewer should know; "none" is a valid answer>
- **Run / verify:**
  ```bash
  <exact command(s) that reproduce the result>
  ```
- **Verified (programmatic):** <what was checked and the outcome — compile/import/smoke test/curl result>
- **Pending manual verification:** <cross-ref the numbered item(s) you added below, or "none">
- **Known gaps / handoffs:** <TODOs, things a later phase must handle>
```

---

## Pending manual verification

Batched — the product owner checks these in one pass, not per phase. Add a numbered item whenever a phase produces something only a human should sign off (a rendered report, a running target, a planted-bug set). Give enough detail to check it **cold**.

1. **(Phase 0)** Read `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `pentrai_pipeline/contracts.py` and confirm the pipeline shape, the posture=label-not-gate decision, and the typed artifacts match what we actually want before stages get built on top of them.
2. ~~(Phase 1) Build + run the guinea pig under Docker~~ — **✅ resolved in Phase 2**: built via `ingest`→`sandbox` and reachable on the internal net (Docker Desktop 29.1.3).
3. ~~(Phase 1) V3 command injection on a Linux target~~ — **✅ resolved in Phase 2**: returned `uid=0(root)` through the sandbox.
4. **(Phase 1/4)** V4 SCA — spot-check that `osv-scanner`/`trivy` flags the pinned deps in `guinea_pig/target/requirements.txt` (Werkzeug 2.0.3, Jinja2 3.0.3, requests 2.25.1 + urllib3). Becomes automatic once Phase 4 lands.

---

## Phase logs

### 2026-10-12 — Assessment workspace redesign

- Rebuilt the React assessment workspace with a clear project and assessment
  hierarchy, scoped submission form, completed assessment summary, searchable
  findings, activity, report downloads, and assessment questions. Added a
  responsive layout and a self-contained interactive design review under
  `.frontend-design/assessments/`.
- Added a customer-copy rule to `CODEX.md`. Replaced implementation-facing
  status language in new events, mapped older persisted events in the UI, and
  clarified report scope and limitations without claiming exploit validation.
- Verified the completed Guinea Pig assessment in Chrome, findings search,
  narrow-screen layout, 66 Python tests, and the TypeScript/Vite build.
- The current access form still requires organization ID and a signed token;
  browser sign-in and the broader release gates remain open.

### 2026-10-12 — Local product verification

- Added an end-to-end local API/worker test using the pinned offline OSV scanner
  and the Guinea Pig dependency fixture. It checks authenticated upload,
  worker completion, persisted findings/events, questions, grant revocation,
  workspace cleanup, and Markdown/PDF/DOCX exports.
- Fixed the local polling worker's preflight directory creation on this Windows
  environment. Fixed browser requests for reports before a report exists.
- Verified a fresh SQLite migration upgrade/check, 66 Python tests, Python
  compilation, Vite/TypeScript build, and `git diff --check`.
- In a live Chrome session against loopback API, Vite, and worker processes,
  uploaded the fixture and saw a completed scan with 21 detected findings,
  six persisted activity events, and a ready report. This verifies the local
  static workflow; dynamic validation and deployment gates remain open.

### 2026-10-12 — Outbox relay groundwork

- Removed the Superpowers workflow requirement from `CODEX.md` and the pilot
  plan headers at the product owner's request. The approved pilot design and
  release gates remain the implementation reference.
- Added a single-event outbox relay that sends only event and routing IDs,
  commits delivery acknowledgement after the receiver returns, and leaves a
  failed delivery available for retry. Receivers must deduplicate on event ID
  if a process fails after delivery but before database commit.
- Added persistent runner lease metadata, a migration, retryable cleanup with
  namespace deletion and token revocation hooks, fail-closed ACK capability
  preflight, and per-scan base namespace objects with restricted Pod Security,
  quota, limits, and default-deny networking. No cluster adapter is wired.
- Added a conservative managed Flask classifier: only a pinned Flask dependency
  and a simple reviewed entrypoint shape match; submitted Docker/Compose recipes,
  native packages, extra dependencies, and executable WSGI statements remain
  static-only. Classification is not connected to dynamic dispatch.
- Added a strict preflight validator for remediation diffs. It rejects paths
  outside approved roots, hidden/unsafe paths, binary/mode/rename metadata,
  malformed hunks, and file or changed-line budget violations. It does not
  apply patches; clean isolated worktree verification and approval remain open.
- Added durable idempotency for project creation and scan cancellation, with
  matching browser request keys. Repeated requests return the original result
  without duplicate audit/outbox events.
- Verified 65 Python tests, compilation of the control plane, static worker,
  execution manager, pipeline, and tests, a fresh SQLite migration upgrade,
  check, downgrade, and upgrade, plus `git diff --check`.
- Production queue delivery, cloud cluster provisioning, live containment
  proof, and the later pilot workstreams remain open. Dynamic validation stays
  disabled.

### 2026-10-06 — Local static product flow

- Added explicit loopback development identity bootstrap, project listing/creation, scan listing, pre-dispatch cancellation, and retry as a new authorized scan.
- Added a polling local worker with asset preflight and recovery of abandoned queued scans. The browser now uploads a ZIP, finalizes its digest, starts a scan, follows events, and downloads Markdown, PDF, or DOCX reports. Scope notes are persisted for human-readable reports.
- Added limited Python AST SAST hypotheses to the static worker, deterministic ranking and two-audience report rendering in the legacy pipeline, plus consent-gated model client/analyst plumbing and a harness-only legacy client facade. The legacy dynamic pipeline is stopped before host Docker deployment unless an isolated runner is verified; live validation remains unavailable in the local product.
- Built an ignored portable Windows Python 3.14.3 runtime from the official checksum-verified embeddable archive plus installed application packages. Verified its independent interpreter/import path and FastAPI, Psycopg, Authlib, and Uvicorn imports.
- Verified Python compilation/imports, TypeScript type checking, `pip check`, report export byte formats, 49 Python tests, and a Vite production build using its native config loader. Local customer-flow acceptance testing is left to the product owner.
- Remaining release work: isolated execution and network controls, production dispatch/leases and object storage, broader SCA/SAST coverage, evidence-backed dynamic validation, consent/secret-broker persistence, remediation, quotas, and release assurance.

### Phase 0 — Scaffold  ✅  *(worked example of the template above)*
- **Owner:** — (initial scaffold)   **Model:** Opus   **Date:** 2026-08-06   **Commit:** _uncommitted (working tree)_
- **Goal:** wire the whole pipeline skeleton so every stage is independently buildable against a stable, typed contract — without touching the engine.
- **Built / changed:**
  - `pentrai_pipeline/contracts.py` — typed artifacts passed between stages (the backbone: `Target`, `IngestResult`, `DeployedTarget`, `ReconResult`, `Finding`, `AttackPlan`, `ValidatedFinding`, `Report`, plus the enums).
  - `pentrai_pipeline/orchestrator.py` — `run_pipeline()`: the stage sequence + authorization gate + guaranteed sandbox teardown in `finally`.
  - `pentrai_pipeline/config.py` — env-driven `Settings` (PentrAI server, LLM, sandbox egress, budgets).
  - `pentrai_pipeline/cli.py` + `__main__.py` — `python -m pentrai_pipeline <src> --authorized`.
  - `pentrai_pipeline/stages/*.py` — the 7 stage stubs (ingest, sandbox, recon, analyze_sca, analyze_sast, synthesize, exploit, report), each a spec in its docstring.
  - `pentrai_pipeline/agents/*.py` — `LLMClient` (provider-agnostic, defaults to `llm_proxy`), `AnalystAgent` (phase 1), `OperatorAgent` (phase 2).
  - `pentrai_pipeline/tools/pentrai_client.py` — the single bridge to the engine.
  - `pentrai_pipeline/jobs/job.py` — `Job`/`JobStore` the web layer will poll.
  - `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `guinea_pig/README.md`, this file.
- **Key decisions / deviations:** three locked calls — (1) ingest **requires a container recipe**, no auto-build; (2) **white-box analysis, live validation** (the attack is the verification oracle); (3) **secrets are allowed to the attacker → `posture` is a label, not a gate** (reversed from an earlier black-box idea; do not reintroduce a no-secrets constraint). Two static engines (deterministic SCA + LLM SAST). Egress-off sandbox is the containment boundary.
- **Run / verify:**
  ```bash
  python -m compileall -q pentrai_pipeline
  python -c "import pentrai_pipeline as p; print(p.__version__)"
  python -m pentrai_pipeline --help
  python -c "from pentrai_pipeline.contracts import Target, SourceKind; from pentrai_pipeline.orchestrator import run_pipeline; from pentrai_pipeline.jobs.job import Job; t=Target(source_ref='./x', kind=SourceKind.FOLDER, authorized=True); j=Job.create(t); run_pipeline(t, job=j); print(' -> '.join(e.status.value for e in j.events))"
  ```
- **Verified (programmatic):** compile OK; import OK (v0.0.1); CLI `--help` OK; orchestrator smoke test flows `queued -> ingesting -> failed` and reports `stage not yet implemented: stages.ingest.ingest`; the unauthorized path refuses before any stage. Engine files (`pentrai_server.py`/`pentrai_mcp.py`) untouched.
- **Pending manual verification:** item **#1** above (design/contract review).
- **Known gaps / handoffs:** all 7 stages + both agents + `pentrai_client` + `LLMClient` are stubs (`NotImplementedError`); no guinea pig yet (Phase 1); Job store is in-memory (persistence lands with the web layer, Phase 9).

### Phase 1 — Guinea pig  ✅
- **Owner:** —   **Model:** Opus   **Date:** 2026-08-06   **Commit:** _Phase 1 commit (this change)_
- **Goal:** a real, runnable, deliberately-vulnerable web app the later stages can attack, plus a ground-truth key that makes it the precision/recall eval harness.
- **Built / changed:**
  - `guinea_pig/target/app.py` — Flask "shop" API; 4 planted weakness classes + deliberate true-negatives.
  - `guinea_pig/target/requirements.txt` — pinned to known-CVE versions (feeds SCA).
  - `guinea_pig/target/{config.yaml,Dockerfile,docker-compose.yml,.dockerignore}` — safe config + container recipe (satisfies the ingest contract; no auto-build needed).
  - `guinea_pig/SOLUTIONS.md` — ground-truth answer key, kept OUT of `target/` so it is never ingested.
  - `guinea_pig/README.md` — harness doc + the two eval-integrity rules.
  - `.gitignore` — ignore `*.db` (runtime sqlite regenerated on boot).
- **Key decisions / deviations:** submit `target/` only (SOLUTIONS.md sits one level up, never ingested); **zero hints inside `target/`** so SAST gets a fair test; SQLite single-container for deterministic bring-up; deps chosen outdated-but-3.11-compatible so the app runs on `python:3.11-slim` and the logic is testable on the host; planted secret `AKIAIOSFODNN7EXAMPLE` matches the engine's `SECRET_PATTERNS`.
- **Run / verify:**
  ```bash
  # local logic proof (V1/V2), no Docker:
  python -m venv env && env/Scripts/pip install flask pyyaml
  PORT=8017 env/Scripts/python guinea_pig/target/app.py &
  curl -s localhost:8017/search --get --data-urlencode "q=%' UNION SELECT id, username||':'||password, role FROM users -- "
  # full stack + V3 + SCA: docker compose -f guinea_pig/target/docker-compose.yml up --build
  ```
- **Verified (programmatic):** `py_compile` OK; **live V1 SQLi** exfiltrated alice/bob/admin credentials via the `/search` UNION payload (benign `?q=Widget` returns 1 row → injection confirmed); **live V2 BAC** returned all users + secret `AKIAIOSFODNN7EXAMPLE` to non-admin alice.
- **Pending manual verification:** #2 (Docker bring-up), #3 (V3 cmd-injection on the Linux container), #4 (SCA flags the pinned deps).
- **Known gaps / handoffs:** V3 and the full vulnerable-dep stack only run under Docker/Linux (proven at Phase 2). One vertical for now (Python/Flask web app); widen to Node/PHP + more classes later.

### Phase 2 — ingest + sandbox  ✅
- **Owner:** —   **Model:** Opus   **Date:** 2026-08-06   **Commit:** _Phase 2 commit (this change)_
- **Goal:** the make-or-break — get a submitted codebase built and running inside an isolated, egress-off container the later stages can reach, then torn down cleanly.
- **Built / changed:**
  - `pentrai_pipeline/stages/ingest.py` — normalize folder/zip/git → src tree; detect stack; **require** a Dockerfile/compose recipe (no auto-build); best-effort exposed-port extraction; zip-slip guard.
  - `pentrai_pipeline/stages/sandbox.py` — `deploy()` builds the image and runs it on a Docker network created `--internal` (Dockerfile) or via a compose `networks.default.internal: true` override (compose); healthcheck + reachability via a throwaway probe container on the same net; `teardown()` idempotent (containers by compose-project label + our own, networks, volumes, built image).
  - `pentrai_pipeline/config.py` — `SandboxSettings.probe_image` (default `busybox`).
  - **guinea-pig build fix:** dropped PyYAML (C-extension, no wheel for a slim base → build wall) → config now stdlib `json`; base `python:3.11-slim` → `python:3.9-slim` to match the pinned old Flask. Touched `guinea_pig/target/{app.py,config.json (was config.yaml),requirements.txt,Dockerfile}` + SOLUTIONS.md/README.md. Still 4 planted classes; V4 SCA deps now Werkzeug/Jinja2/requests(+urllib3).
- **Key decisions / deviations:** isolation = internal Docker network (keeps embedded DNS for name-based reachability, cuts internet). Build runs on the host daemon (has internet for base image + pip); only the target's *runtime* network is isolated. Target is NOT published to a host port — later stages reach it via a container on `network_name`. Scope: single-service targets; multi-service compose topology is a later refinement. Forced UTF-8 on all subprocess I/O (Windows cp1252 was crashing a log-read thread).
- **Run / verify:** `PENTRAI_WORK_DIR=<tmp> python <scratch>/verify_phase2.py` — ingest → deploy → exploit-via-sandbox → teardown against `guinea_pig/target/`.
- **Verified (programmatic, live Docker):** INGEST detected `python/flask` + compose + port 8000; DEPLOY built + ran the guinea pig, healthcheck passed; through the sandbox net — REACH `/` OK, **V1 SQLi** leaked `alice:alice123`, **V3 cmd-injection** returned `uid=0(root)`; **egress cut** (`example.com` → bad address); TEARDOWN left zero containers/networks. Clean re-run, no errors.
- **Pending manual verification:** none new — this phase *resolved* #2 and #3. #4 (SCA scanner over the deps) still waits for Phase 4.
- **Hardening follow-up (same day):** added runtime hardening — cap-drop `NET_RAW` + `no-new-privileges` + pids/mem/cpu limits, verified *applied* via `docker inspect` on both the compose and Dockerfile paths, without breaking apps (an initial `cap-drop ALL` was reverted — it breaks nginx, which needs SETUID/SETGID/NET_BIND_SERVICE to start; full lockdown is now opt-in). **Multi-service compose now supported** — all services hardened + isolated, target resolves to the port-publishing service (verified live with nginx+redis). Build-time RCE now explicitly owned in `THREAT_MODEL.md` (rootless/microVM builds are the real fix — infra, not a code patch; `SandboxSettings.build_network` cuts build egress for vendored targets).
- **Known gaps / handoffs:** egress `allowlist` still all-or-nothing (via `--internal`); full `cap_drop: ALL` lockdown is opt-in (unsafe as a default); Phase 3 recon/exploit will run their tooling in a container attached to `network_name`.
