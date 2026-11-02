# PentrAI final-product architecture and implementation roadmap

This document is the working source of truth for turning the current repository
from an internal pipeline scaffold into a deployable, defensive product.

## 1. Product definition

PentrAI accepts software that a customer owns or is authorized to assess. It
creates an isolated per-job runner, analyzes the submitted source, optionally
deploys a private copy of the application, validates only against that private
copy, and returns evidence-backed findings, remediation guidance, and reports.

The product must never claim that software is completely safe. The strongest
valid conclusion is: no validated findings within the declared scope, coverage,
tools, and budget.

The product boundary is:

```text
Customer browser/API
        -> control plane
        -> durable job queue
        -> isolated runner plane
        -> encrypted artifact/evidence plane
        -> reports and approved remediation patch
```

The legacy HexStrike/PentrAI server remains an internal runner capability. The
agent should ultimately be able to use the complete HexStrike tool catalog, but
only through a runner-side broker that enforces authorization, target scope,
budgets, credentials, logging, and output limits. The product must not give a
model an unrestricted shell, arbitrary URL, arbitrary file path, or raw legacy
HTTP API.

## 2. SCA and SAST

SCA means Software Composition Analysis. It inventories third-party packages
and compares exact versions against vulnerability databases. Example: finding
that a pinned Flask, Werkzeug, npm, or Go dependency has a known CVE. SCA is
primarily deterministic and should use tools such as OSV-Scanner, Trivy, Grype,
or an approved equivalent. The result needs package/version, vulnerability ID,
severity, database/tool version, and provenance.

SAST means Static Application Security Testing. It examines the application's
own source without running it, looking for code-level weaknesses such as broken
authorization, injection sinks, unsafe deserialization, path traversal, or
missing validation. PentrAI's LLM can assist with semantic SAST, but model
output is only a hypothesis. A finding becomes confirmed only after controlled
validation against the job-owned sandbox target.

## 3. Runtime data flow

1. A user authenticates and creates a scan under an organization.
2. The control plane records authorization, scope, posture, profile, consent,
   quotas, and provider policy.
3. Source is uploaded or fetched from an approved private Git reference. Intake
   records a digest and stores the original artifact encrypted.
4. A queue assigns a job to an isolated runner.
5. The runner materializes source into a job-owned workspace and performs static
   intake checks.
6. A hardened isolated build service creates a target image or rejects the
   recipe. Builds must not execute untrusted Dockerfiles on the control-plane
   host Docker daemon.
7. The target runs on a private per-job network with no public, control-plane,
   metadata-service, artifact-store, or cross-job reachability.
8. Recon, SCA, and SAST produce typed artifacts. SCA is deterministic; SAST
   findings are hypotheses.
9. Synthesis ranks and deduplicates findings into a bounded attack plan.
10. The operator uses the complete HexStrike catalog through the runner broker.
    Every call receives the job target from policy, not from the model.
11. Evidence is captured, hashed, redacted, sealed, and classified as confirmed,
    refuted, inconclusive, or skipped.
12. Reports and optional remediation patches are produced from validated data.
13. The user receives tenant-scoped, expiring artifact links. The runner,
    credentials, target, network, and temporary workspace are destroyed.

## 4. Repository map and exact responsibilities

### Root

- `CODEX.md`: repository safety rules, product boundary, workflow, and release
  invariants. Read before implementation work.
- `README.md`: legacy engine setup. Expand later with product setup and clearly
  distinguish legacy runner operation from customer use.
- `LICENSE`: MIT license.
- `requirements.txt`: legacy Python dependencies. Replace with separated,
  pinned dependency sets for control plane, runner, tests, and development.
- `pentrai_server.py`: restored legacy Flask tool server. Internal runner only;
  it exposes the large HexStrike-derived tool catalog and must never be exposed
  directly to customers or an unrestricted model.
- `pentrai_mcp.py`: legacy MCP adapter for the tool server. Keep internal and
  place the new broker in front of it or its HTTP routes.
- `pentrai-mcp.json`: local MCP client configuration template.
- `prompt_generator.py`: legacy CTF/research prompt utility, not product flow.

### `assets/`

Screenshots and logo assets used by documentation or demos. They are not
runtime dependencies.

### `hooks/`

- `llm_proxy.py`: legacy OpenAI-compatible proxy experiment. Replace its
  implicit local trust assumptions with a provider broker, explicit key policy,
  request budgets, and audit metadata.
- `tool_logger_hook.py`: legacy local tool logging. The production audit trail
  must be durable, tenant-scoped, tamper-evident, redacted, and queryable.

### `pentrai_pipeline/`

- `__init__.py`: package metadata.
- `__main__.py`: enables `python -m pentrai_pipeline`.
- `README.md`: pipeline status and local usage.
- `contracts.py`: typed artifacts shared by stages. This is the stable contract
  backbone; update all consumers when changing a contract.
- `config.py`: environment-derived local settings. Production configuration and
  secrets belong in a control-plane configuration/secrets system.
- `cli.py`: local command-line entrypoint. It is a development driver, not a
  customer API. Implement JSON output or remove the currently accepted but
  unused `--json` option.
- `orchestrator.py`: stage order, authorization gate, job transitions, and
  guaranteed teardown. Add cancellation, retry, timeout, worker leases, durable
  events, and failure recovery.

### `pentrai_pipeline/stages/`

- `ingest.py`: folder/ZIP/Git materialization, stack detection, and container
  recipe discovery. Already partially implemented; add archive quotas,
  symlink/hard-link rules, submodule/LFS policy, digesting, SSRF controls, and
  resource limits.
- `sandbox.py`: Docker/Compose development deployment, internal networking,
  health probing, runtime hardening, and teardown. Runtime isolation exists but
  host-daemon builds are not production-safe.
- `recon.py`: implement observational discovery through the broker: services,
  ports, HTTP technology, routes, methods, and parameters.
- `analyze_sca.py`: implement deterministic dependency inventory, scanner
  invocation, normalized vulnerability results, and scanner provenance.
- `analyze_sast.py`: implement safe source selection/chunking and analyst-agent
  invocation. Source is untrusted data, never instructions.
- `synthesize.py`: implement deduplication, severity/confidence/reachability
  ranking, validation-plan normalization, and finding budgets.
- `exploit.py`: implement bounded live validation, evidence capture, target reset
  rules, and confirmed/refuted/inconclusive outcomes.
- `report.py`: implement technical and client reports from validated artifacts;
  escape untrusted content and disclose scope, coverage, and limitations.

### `pentrai_pipeline/agents/`

- `llm.py`: implement provider-neutral chat and structured output with timeouts,
  retries, schema validation, provider policy, token/cost budgets, and version
  recording.
- `analyst_agent.py`: source-analysis agent that emits only typed hypotheses.
  Add prompt-injection resistance and provenance.
- `operator_agent.py`: validation agent that can request brokered tools but cannot
  alter policy, severity, target, or final outcome directly.

### `pentrai_pipeline/harness/`

- `contracts.py`: policy, target, request, decision, result, context, and audit
  contracts.
- `policy.py`: currently a small reviewed catalog and deterministic request
  checks. Its model must change from a small hard-coded product catalog to a
  complete server-side registry of all HexStrike tools, schemas, risk classes,
  and target semantics.
- `agent_harness.py`: policy decision, transport execution, budget accounting,
  redaction, and bounded output. Add durable audit/evidence hooks and stronger
  failure handling.
- `transport.py`: private HTTP adapter to the runner tool server. Add runner
  authentication, response schemas, retries, timeout classes, and server
  identity checks.
- `factory.py`: constructs the per-job harness. Extend it with job lease,
  tenant, credential broker, evidence sink, and complete tool-policy snapshot.

### `pentrai_pipeline/tools/`

- `pentrai_client.py`: currently a stub and intended single bridge to the legacy
  engine. Implement HTTP calls, timeout/error normalization, target scoping,
  authentication, and typed convenience methods.

The complete HexStrike requirement should be implemented as follows:

1. Inventory every route/tool exposed by `pentrai_server.py` and the MCP adapter.
2. Generate or maintain a versioned internal tool registry containing tool name,
   route, input schema, output schema, risk, target fields, credential needs,
   timeout, resource cost, and whether it is observational or active.
3. Expose the registry to the model as structured tool descriptions.
4. Let the model request any registered tool, but never let it supply policy-owned
   target, command, path, host, template, or credential values.
5. Inject the job-owned target and fixed policy parameters server-side.
6. Enforce authorization, allowed scan profile, active-validation consent,
   per-tool and total budgets, concurrency, timeout, output size, and audit logging.
7. Reject tools that cannot be safely scoped until they are wrapped with a safe
   adapter. “All tools available” means all tools with a reviewed adapter, not
   unrestricted arbitrary execution.
8. Add one contract/regression test per tool family and a full catalog smoke test.

### `pentrai_pipeline/jobs/`

- `job.py`: currently an in-memory job state machine and store. Replace or wrap
  it with database persistence, queue messages, worker leases, cancellation,
  retry, idempotency, organization ownership, and reaping.

### `guinea_pig/`

- `target/`: deliberately vulnerable Flask target used only for internal tests.
- `SOLUTIONS.md`: ground truth; never ingest or expose to the analysis agent.
- `README.md`: evaluation instructions.

### `docs/`

- `ARCHITECTURE.md`: original pipeline design.
- `THREAT_MODEL.md`: security threats and known build/runtime limitations.
- `PROGRESS.md`: phase tracker and verification rules.
- `PRODUCT_BLUEPRINT.md`: desired control, runner, and artifact planes.
- `RELEASE_ASSURANCE.md`: required release tests and evidence.
- `superpowers/`: design and implementation plans.
- `FINAL_PRODUCT_ROADMAP.md`: this consolidated implementation source of truth.

### `tests/`

- `test_agent_harness.py`: currently five policy/harness unit tests. Expand into
  unit, integration, isolation, corpus, failure-recovery, and release suites.

## 5. Implementation order

### Phase A: repository and contracts

- Keep the restored `pentrai_server.py` and verify the Git diff.
- Freeze typed contracts and add serialization/versioning.
- Decide the control-plane API and database schema.
- Add a complete tool inventory generated from the legacy server.
- Define the broker policy schema for every tool.

### Phase B: complete the first vertical

- Implement `pentrai_client.py`.
- Implement recon using brokered HexStrike tools.
- Implement SCA against the guinea pig.
- Implement LLM client and analyst SAST.
- Implement synthesis.
- Implement operator validation using the complete broker registry.
- Implement evidence and Markdown reports.
- Prove the guinea pig positive and true-negative corpus.

### Phase C: production runner

- Build isolated build workers using rootless or microVM isolation.
- Validate and reject unsafe Docker/Compose features.
- Enforce network and DNS policy at infrastructure level.
- Add resource quotas, cancellation, timeout, restart recovery, and reaping.
- Pin scanner databases, runner images, and tool versions.

### Phase D: control plane and artifacts

- Add authentication, organizations, roles, authorization grants, scan profiles,
  and consent records.
- Add upload/Git intake API, queue, worker manager, persistent jobs, events, and
  realtime status.
- Add encrypted object storage, evidence sealing, report storage, retention,
  deletion, and expiring download links.

### Phase E: remediation and product UX

- Add bounded patch generation in a clean temporary worktree.
- Run tests and security checks on patches.
- Require explicit approval before export, merge, or deployment.
- Build customer scan creation, progress, findings, evidence, reports, and
  remediation review screens.

### Phase F: release hardening

- Run full internal corpus and isolation tests in CI.
- Perform independent security review of control plane, runner, broker, and model
  gateway.
- Produce signed release evidence with commit, image, scanner, model, and test
  versions.
- Start with an opt-in staging pilot, conservative quotas, monitoring, rollback,
  incident response, key rotation, and backup/restore.

## 6. Definition of product-ready

Do not call the product deployable until all of the following are true:

- The pipeline completes from authorized intake through report generation.
- Every supported HexStrike tool has a reviewed adapter or is explicitly marked
  unsupported; no generic shell bypass exists.
- SCA and SAST findings have provenance and validation states.
- Confirmed findings contain reproducible evidence.
- Jobs, events, findings, reports, and artifacts persist durably.
- Tenant and role isolation is tested.
- Source, credentials, provider keys, and evidence are protected and redacted.
- Builds run in an isolated build service, not the control-plane Docker daemon.
- Runtime egress, cross-job access, metadata access, and host access are blocked.
- Cancellation, timeout, crash, restart, and worker-loss cleanup are proven.
- Reports cannot be controlled by submitted source, tool output, or model output.
- Remediation is bounded, tested, and approval-gated.
- CI runs unit, integration, corpus, security, and failure-recovery tests.
- A release record contains immutable build digests, dependency/scanner/model
  versions, test evidence, limitations, and risk acceptances.
