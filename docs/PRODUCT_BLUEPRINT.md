# PentrAI Product Blueprint

> **Current scope update (2026-10-30):** The product direction in
> [HEXSTRIKE_GUI_PLAN.md](HEXSTRIKE_GUI_PLAN.md) supersedes this blueprint where
> they conflict. PentrAI is a GUI for the full native HexStrike MCP catalog.
> Customers may submit source, a verified live URL, or both. The model chooses
> tools; per-job runner isolation enforces authorized target and tenant scope.
> The private-sandbox-only and four-tool-catalog passages below are historical
> design assumptions pending a full rewrite. Dynamic execution remains gated
> until runner containment is proven.

## Purpose

PentrAI will be a beginner-friendly, authorization-gated application-security
assessment product. A customer signs in, submits software they own or are
authorized to test, chooses a model-effort mode when model analysis is available,
then receives
evidence-backed findings, remediation patches, and technical and executive
reports.

**The product must never claim that software is 100% safe.** Its strongest
verdict is: *no validated findings within the declared scope, coverage, and
budget.*

## Product boundary

The existing `pentrai_server.py` / `pentrai_mcp.py` pair is the rebranded
HexStrike engine. It remains a private tool catalog, not a customer-facing API.
It contains local shell execution and therefore runs only inside a disposable,
per-job worker environment.

The product has three planes:

```text
Browser / API clients
        |
        v
Control plane: identity, authorization, jobs, policy, encrypted metadata
        |
        v
Runner plane: one isolated workspace + tools + target runtime per job
        |
        v
Artifact plane: encrypted source upload, evidence, reports, approved patches
```

No runner can initiate a connection to the control-plane database, another
customer job, or the public Internet unless an explicit policy permits it.

## Assumptions for the first release

1. The initial deployment is self-hosted or inside a private customer VPC.
2. A scan targets uploaded source, a user-supplied Git revision, or a private
   image; it does not scan arbitrary public Internet assets.
3. Dynamic testing happens only against the per-job sandbox deployment.
4. A user supplies an explicit authorization attestation and scope note.
5. Generated remediation is always a patch/proposed pull request; PentrAI never
   merges or deploys a fix without a user approval.

These assumptions deliberately keep the first product narrow, safe, and
verifiable. External asset testing and multi-tenant hosted execution are later
projects with separate network, legal, and abuse-prevention requirements.

## Core user journey

1. **Sign in and create a workspace.** Users belong to an organization and have
   owner, security-engineer, developer, or viewer roles.
2. **Create a scan.** Select source (folder/ZIP/Git/image) and, when
   model-assisted analysis is available, a model-effort mode (`quick`,
   `standard`, `deep`). Provider/model selection and optional test credentials
   are administrator or advanced settings.
3. **Attest authorization.** The user confirms ownership/permission, declares
   scope, and accepts that testing runs against a private sandbox copy.
4. **Preflight.** The service validates archive safety, file limits, container
   recipe, declared secrets, stack, SBOM, and tool availability.
5. **Analyze and validate.** Deterministic scanners and LLM-assisted analysis
   create hypotheses. The runner attempts only allowed, sandbox-scoped checks
   and records reproducible evidence.
6. **Review findings.** Results clearly distinguish confirmed, refuted,
   inconclusive, and skipped hypotheses. Users can filter by severity, source,
   component, and remediation status.
7. **Approve remediation.** Users review generated diffs, test results, and a
   focused re-scan. They export a patch or open a pull request themselves.
8. **Export reports.** Technical Markdown, PDF, and DOCX reports show scope,
   evidence, limitations, remediation, and scan provenance.

## Beginner-first, managed experience

The default user journey is intentionally short:

```text
Sign in -> upload/select private source -> attest ownership -> Start secure scan
                                                        -> review findings/fixes
```

PentrAI, not the customer, selects the target classification, enforced scan
policy, tool subset, scanner versions, resource limits, evidence rules, and report
format. The interface explains what is happening in plain language and shows
progress as stages, not tool commands.

The product has three default choices at scan creation when model-assisted
analysis is available:

1. source to assess; and
2. Quick, Standard, or Deep model effort (Standard by default); and
3. whether the user authorizes a deeper sandbox validation when PentrAI can
   safely run the target.

The effort choice changes model reasoning effort and bounded model budget only.
Static scanner coverage and runner tool permissions come from a separate
versioned policy. Where no model-assisted stage runs, omit the effort choice
and disclose the actual static coverage. Provider adapters resolve the three
customer modes to distinct levels supported by the approved model, recording
both requested mode and effective effort; unsupported levels are not silently
substituted. See `docs/PRODUCT_UX_REDESIGN_PROPOSAL.md` for the migration plan.

Everything else uses a secure default. Model/provider selection is optional and
lives in organization settings: PentrAI-managed credentials and a recommended
model are the beginner default; bring-your-own provider/API key is an advanced
administrator option with a clear data-sharing notice.

### Managed target onboarding

Customers should not have to write Docker or Compose configuration to obtain
basic value. Intake has three outcomes:

- **Static-only ready:** analyze any supported source archive/repository without
  executing it; always available when intake succeeds.
- **Managed sandbox ready:** for an allowlisted framework and lockfile, PentrAI
  generates a minimal, versioned sandbox recipe from a reviewed template and
  runs it only in the isolated builder/runner. It never guesses arbitrary shell
  setup commands.
- **Needs a deployment recipe:** if a safe managed template cannot be chosen,
  finish the static assessment and present one plain-language next step (upload
  an existing Docker/Compose recipe or ask an administrator to provide it).

An uploaded recipe remains subject to the Compose/build policy gates. A managed
recipe gives beginners an easy path without letting arbitrary build logic bypass
the security boundary.

## Services

| Service | Responsibility | Must not do |
|---|---|---|
| Web application | UI, session handling, uploads, report review | Execute tools or customer code |
| API/control service | RBAC, policy, jobs, artifact references, audit | Shell out to HexStrike tools |
| Queue/scheduler | Durable job states, retries, cancellation, quotas | Store source or secrets in messages |
| Artifact store | Versioned encrypted uploads/evidence/reports | Be mounted read-write by the API and runner together |
| Secret broker | Per-job, short-lived credential material | Log secret values or expose provider keys to runners |
| Runner manager | Create and reap isolated job environments | Accept an unauthenticated user request |
| Runner | Static tools, target sandbox, PentrAI adapter, evidence capture | Reach other jobs, the control plane, or unrestricted Internet |
| Model gateway | Provider adapters, redaction, budget/accounting | Directly execute tools or make findings authoritative |

## Data model

The control plane owns durable records; runner artifacts are immutable and
addressed by ID rather than trusted file paths.

| Entity | Essential fields |
|---|---|
| Organization | id, name, plan, retention policy |
| User / membership | user id, organization id, role, MFA state |
| Project | organization id, name, repository/source policy |
| Authorization | project id, attestor, scope, accepted-at, expiry |
| Scan | project id, requested mode, resolved model/effort, policy version, declared scope, state, timestamps |
| Source artifact | content digest, type, size, encryption key reference, retention |
| Secret reference | scan id, vault reference, allowed purpose, expiry |
| Runner lease | scan id, image digest, network policy, started/ended timestamps |
| Finding | normalized title, CWE/CVE, severity, confidence, source, state |
| Evidence | finding id, request/command redacted form, output excerpt, artifact refs |
| Remediation | finding id, patch artifact, tests, re-scan outcome, approval state |
| Report | scan id, audience, format, artifact ref, generation metadata |
| Audit event | actor/service, action, object, policy decision, timestamp |

## Typed job contract

The existing pipeline contracts are the seed. Expand them rather than passing
LLM prose between stages.

```text
ScanRequest
  -> IntakeResult
  -> SourceInventory + SBOM
  -> ExecutionPolicy
  -> StaticFindings[] + TargetProfile
  -> SandboxDeployment? + ReconResult?
  -> AttackPlan
  -> ValidationAttempt[]
  -> ValidatedFinding[]
  -> RemediationCandidate[]
  -> Report[]
```

Every object must include `scan_id`, artifact digests, timestamps, and a schema
version. Findings are hypotheses until a `ValidationAttempt` supplies evidence
and an outcome.

## Execution policy

Policy is evaluated before every state-changing or network-capable action.

Required checks:

- authorization is current and matches the project/source;
- the tool is allowlisted by the versioned execution policy and target type;
- parameters refer only to the job workspace or private sandbox hostname;
- resource, tool-call, token, and elapsed-time budgets remain;
- credentials are available only to the stage approved to use them;
- destructive actions are off by default and require an explicit per-scan flag;
- all commands, outputs, and policy decisions are recorded after secret
  redaction.

The existing generic command endpoint, file endpoints, host process controls,
and public-network tooling must not be surfaced in the product API.

## Runner and sandbox design

Each scan gets a fresh runner identity and workspace. The runner image contains
only the policy-approved tool set. Submitted source is copied into a non-root
working directory; credentials are mounted read-only for their short-lived
stage; generated artifacts are copied out through a controlled collector.

For dynamic assessment, the target is built in stronger isolation than the
control service. Runtime uses an internal-only network with no host-published
ports. The tester container may access only that network. Build-time execution
is a separate threat: production deployment requires rootless BuildKit or a
microVM/remote build worker, not the control-plane Docker daemon.

Every runner has CPU, memory, PID, disk, wall-clock, and log-output limits. A
lease reaper destroys abandoned containers, volumes, networks, and credentials.

### Non-negotiable runner release gates

The current Docker sandbox is a useful development harness, but it is **not**
safe enough to run arbitrary customer code on the same host as the control
plane. Production dynamic execution does not ship until all of these are true:

1. **Build isolation:** customer Dockerfiles build in a disposable microVM,
   rootless remote builder, or equivalent isolated build service. A host Docker
   daemon is not an acceptable build boundary.
2. **Compose policy:** reject recipes that request privileged containers, host
   networking/PID/IPC namespaces, host-path or Docker-socket mounts, devices,
   unsafe security options, host users, remote build contexts, or unsupported
   Compose extensions. A hardening override does not neutralize those settings.
3. **Image supply chain:** use pinned runner/tool images, verified digests,
   controlled registry access, SBOMs, and a documented CVE-database update
   process. Do not let a runner pull arbitrary public images at scan time.
4. **Network enforcement:** restrict both DNS and IP routing. The runner can
   address only named sandbox services and approved internal mirrors; it cannot
   resolve or connect to arbitrary addresses, metadata services, or the control
   plane. Validate targets after DNS resolution inside the runner namespace.
5. **Filesystem containment:** source, secrets, tool caches, build caches, and
   output mounts are separate; no inherited host mounts, symlink escapes, or
   writable shared artifact paths. Cleanup includes image layers and build
   cache, not only containers and volumes.
6. **Snapshot and reset:** dynamic validation uses disposable target data.
   Reset the target between destructive test attempts and preserve the baseline
   image/configuration required to reproduce an outcome.

## Intake, privacy, and artifact safeguards

Source code and tool output can contain customer intellectual property,
credentials, personal data, and hostile content. Intake must be treated as an
untrusted supply-chain boundary.

- Browser upload supports resumable, size-limited uploads to a tenant-scoped
  temporary area; a CLI/local collector packages full folders deterministically
  because browsers cannot reliably submit a whole source tree.
- ZIP/TAR extraction enforces member-count, expanded-size, nesting-depth,
  compression-ratio, symlink, hard-link, path-normalization, and duplicate-name
  limits. String-prefix path checks alone are insufficient for containment.
- Git intake permits only configured repositories/hosts, pins a commit SHA,
  disables submodules and hooks by default, controls LFS, and runs in a fetcher
  with no access to internal services. Repository URLs are otherwise an SSRF
  and data-exfiltration path.
- Static parsers and scanners run as isolated workers too: malformed source,
  archives, lockfiles, binaries, and language-server plugins are not assumed
  safe merely because the stage is called “static.”
- Artifacts have tenant-scoped encryption, immutable digests, retention and
  legal-hold state, secure deletion/cryptographic-erasure behavior, backup
  handling, and expiring download URLs. Cross-tenant content deduplication is
  forbidden unless the encrypted isolation design makes it non-observable.
- Logs, evidence, prompts, HTML previews, Markdown/PDF/DOCX renderers, and
  notifications sanitize control characters, links, HTML, and formula-like
  values. They are separate untrusted-input and data-leak boundaries.

## Identity, API, and workflow safeguards

- Use OIDC/SAML-capable authentication, MFA for privileged roles, short-lived
  sessions, CSRF protection, service accounts, scoped API tokens, and optional
  SCIM only after the core authorization model is proven.
- Authorization is a signed, expiring scan grant tied to organization, project,
  source digest/commit, immutable policy-plan digest, and sandbox-only target. A bare boolean is not
  sufficient.
- Every state transition is idempotent and authorized. Jobs need cancellation,
  retry classification, lease heartbeats, poison-job handling, race-safe reaping,
  and an operator-visible recovery path.
- The API never exposes legacy generic-command, file, process, package-install,
  or arbitrary URL endpoints. Runner tools use a declarative allowlist with
  typed parameters and a single policy-enforcing adapter.
- Scan profiles expose simple language for beginners while mapping to explicit,
  reviewable limits: permitted tool families, target types, rate/concurrency,
  elapsed time, token budget, data retention, and whether dynamic validation is
  enabled.

## Findings, evidence, and model safeguards

- Use separate states for `scanner-detected`, `triaged`, `validated`,
  `refuted`, `inconclusive`, `accepted-risk`, and `fixed-verified`. An SCA match
  is not equivalent to a live exploitable vulnerability.
- Severity is versioned and explainable: source evidence, exposure/context,
  impact assumptions, and the scoring rule are captured. CVSS/CWE/CVE metadata
  must retain scanner and database provenance plus freshness date.
- Evidence is immutable, hashed, access-controlled, and independently checked
  by a validator before a finding becomes confirmed. Evidence capture must have
  redacted and sealed forms so customers can view proof without indiscriminately
  disclosing credentials or sensitive data.
- LLM prompts, tool output, and generated patches are untrusted. Enforce
  schemas, output-length limits, provenance, prompt-injection markers, and a
  deterministic policy layer outside the model.
- Provider choice includes data-residency, retention/training policy, allowed
  model regions, per-model feature support, spend caps, and outage behavior. A
  fallback provider is used only when the organization has separately approved
  that provider for the same data classification.

## Remediation, reporting, and quality safeguards

- Generated patches obey an explicit change budget and file allowlist; they
  cannot modify CI, deployment, identity, billing, secrets, or dependency
  sources unless the user grants a focused exception.
- Patch verification runs in a clean worktree with dependency-lock and supply
  chain checks, relevant tests, rebuild, and a regression scan. “Fixed” means
  the intended evidence predicate no longer holds; it does not imply no new
  regressions unless the configured test suite passed.
- Reports disclose coverage, skipped/inconclusive work, unavailable tools,
  scanner database age, model/provider, and target reset state. They must not
  overstate security posture or conceal failed stages.
- The product needs a versioned adversarial evaluation suite: safe/unsafe
  targets, known findings, true negatives, malformed archives, malicious
  Docker/Compose files, prompt-injection fixtures, remediation regression cases,
  and organization-isolation tests. Track precision, recall, validation rate,
  false-confirmation rate, cost, duration, and cleanup success by release.

## Analysis pipeline

### 0. Preflight and intake

- Verify authentication, role, authorization, source type, size, digest, and
  retention choice.
- Defend against archive traversal, symlinks, decompression bombs, embedded
  credentials, and unsupported binaries.
- Copy or clone source into the job workspace; never modify the original.
- Detect languages, frameworks, manifests, deployment recipes, and candidate
  entrypoints.

### 1. Deterministic static analysis

- Generate SBOM and dependency vulnerability findings (SCA).
- Run language-aware SAST, secret detection, IaC, container, and license checks.
- Normalize external scanner output into `Finding` records with tool version and
  source locations.
- Do not let the LLM invent CVEs or severity scores without evidence.

### 2. Target classification and planning

- Produce a `TargetProfile`: website/API, worker/service, mobile/desktop,
  library, IaC/cloud, container/Kubernetes, binary, or mixed.
- Select an approved tool subset from the target type and execution policy, not from an
  unconstrained agent prompt.
- Let the LLM correlate source, scanner results, and architecture into a typed,
  ranked hypothesis plan. Treat source text as untrusted data to resist prompt
  injection.

### 3. Sandbox deployment and recon

- Require a reviewed Dockerfile/Compose recipe or a private image reference;
  fail with an actionable message instead of guessing how to run a repository.
- Deploy only on the job-internal network; confirm health through a probe
  container.
- Map ports, frameworks, endpoints, authentication paths, and public interfaces
  only inside that network.

### 4. Validation

- The operator receives a plan, private base URL, and policy-limited tools.
- It validates one hypothesis at a time, records request/response evidence, and
  stops at policy/budget boundaries.
- Outcomes: `confirmed`, `refuted`, `inconclusive`, or `skipped`.
- A model cannot set `confirmed`; evidence predicates and a validator service do.

### 5. Remediation and verification

- A remediation agent proposes the smallest source patch for a confirmed
  finding, plus explanation and tests.
- Apply the patch only in a new temporary worktree/branch.
- Run relevant tests, rebuild the sandbox, and run a focused regression check.
- Present the diff and verification outcome; export a patch or create a PR only
  after explicit user approval.

### 6. Reporting

- Technical report: exact scope, inventory, tool/model versions, findings,
  severity rationale, evidence, reproduction, remediation, and limitations.
- Executive report: risk themes, confirmed impact, prioritised remediation, and
  residual uncertainty; never include sensitive proof by default.
- Generate Markdown first, then PDF and DOCX from the same immutable report
  model. Redact secrets in every customer-visible report.

## LLM provider gateway

Users may choose Codex, Claude, DeepSeek, or another supported provider. The
gateway exposes one internal interface:

```text
analyze(messages, structured_schema, budget, data_classification)
plan(context, policy, budget)
propose_patch(context, finding, test_contract)
```

Provider adapters own model IDs, API calls, retries, token accounting, and
structured-output validation. Provider keys are encrypted at rest, never placed
in browser state or tool prompts, and can be organization-owned or user-owned.
Before external model calls, the gateway enforces source-sharing consent and
redacts secrets where possible. Every response is recorded as provenance, not
ground truth.

The control plane resolves and stores the model capability snapshot and
effective reasoning effort when it creates a scan. The runner receives an
immutable, signed plan and applies the provider-specific parameter and budget.
The report records the actual model/version, effort, coverage, and incomplete
stages. A retry cannot silently change these values.

## First implementation milestones

1. **Foundation:** FastAPI control service, PostgreSQL schema/migrations,
   object-store abstraction, auth/RBAC, audit events, and job state machine.
2. **Safe scan vertical:** source upload + authorization + intake + SBOM/SCA +
   static report. No dynamic tools yet.
3. **Runner vertical:** isolated runner leases, current ingest/sandbox logic,
   health/reaper checks, and a single Flask target profile.
4. **Evidence vertical:** recon adapter, one deterministic validation class,
   structured evidence, finding lifecycle, and report view.
5. **Model vertical:** provider gateway, source-as-data prompts, SAST hypotheses,
   budgets, and human-readable planner output.
6. **Remediation vertical:** patch worktree, tests/re-scan, approval and export.
7. **Product completion:** frontend, DOCX/PDF output, notifications, retention,
   quotas, observability, backups, CI, and penetration testing of PentrAI.

8. **Release assurance:** execute the internal acceptance programme in
   `docs/RELEASE_ASSURANCE.md` against company-owned local targets before any
   customer deployment; ship gradually through an isolated staging environment
   and a monitored opt-in pilot.

## Definition of done for the first safe vertical

- A signed-in user can submit a small authorized source archive.
- The API stores it by digest and creates a durable scan job.
- Intake rejects unsafe archives and records a clear reason.
- The worker produces an SBOM/SCA result without running uploaded code.
- Findings and a Markdown report are visible only to the owning organization.
- The audit log shows authorization, policy decisions, scanner versions, and
  artifact digests.
- Integration tests cover organization isolation, authorization refusal,
  archive traversal rejection, job retry/cancellation, and report redaction.
