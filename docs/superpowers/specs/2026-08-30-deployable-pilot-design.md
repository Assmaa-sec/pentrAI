# PentrAI deployable pilot design

## Status and decisions

This is the approved design for PentrAI's first deployable release.

- Deploy one isolated instance per customer in an Alibaba Cloud mainland-China VPC.
- Enable static assessment for accepted source archives by default.
- Enable dynamic assessment only for Python/Flask applications matching a reviewed PentrAI-managed template.
- Treat customer Dockerfiles, Compose files, arbitrary image references, and arbitrary Git URLs as static-only in the pilot.
- Permit foreign model providers only after organization-level approval of the provider, model, region, and source-sharing policy.
- Use a conversation-first scan workspace with durable real-time updates; never expose chain-of-thought, raw commands, secrets, or unredacted tool output.
- Release as a controlled pilot, not as shared multi-tenant SaaS.

The existing Python pipeline is a seed, not a deployable product. The legacy `pentrai_server.py` and `pentrai_mcp.py` remain private runner capabilities and are never customer-facing services.

## Product outcome and first-pilot success criteria

A signed-in, authorized user uploads a supported source archive, starts a scan, follows plain-language live updates, and receives evidence-backed findings, bounded remediation patches, and reports. PentrAI may report only **no validated findings within the declared scope, coverage, tools, and budget**; it never certifies an application safe.

The pilot is complete only when:

1. Organization members can create projects, upload authorized source, create/cancel/retry scans, and view only their own organization's artifacts.
2. Static assessment produces inventory, SBOM/SCA results, normalized findings, redacted evidence, and Markdown/PDF/DOCX reports.
3. A supported Flask source enters dynamic validation only after template, authorization, and containment checks pass.
4. Confirmed, refuted, inconclusive, skipped, detected, triaged, accepted-risk, and fixed-verified finding states remain distinct.
5. A proposed patch is bounded, tested in a clean isolated worktree, and downloadable only after review. The pilot never writes to a customer repository, creates a PR, merges, deploys, or rotates credentials.
6. Every release candidate has automated evidence for access control, containment, cleanup, redaction, scanner correctness, backup/restore, and rollback.

## Explicit non-goals

- Public-Internet scanning, shared multi-tenant execution, arbitrary deployment recipes, arbitrary customer images, and dynamic support beyond the approved Flask template.
- Generic shell capability, raw legacy-tool access, direct model-to-tool access, or browser-visible provider credentials.
- A generic dashboard that hides scan reasoning, or a chat interface that exposes unsafe internals.

## Deployment architecture

```text
Browser
  -> Alibaba Cloud WAF and HTTPS load balancer
  -> Control ACK Pro cluster
       React web app, FastAPI API, identity integration, scheduler,
       event dispatcher, artifact broker, report renderer, model gateway
       | RDS PostgreSQL | OSS | KMS/secret broker | durable queue |
       |                 private mTLS job grant                   |
  -> Execution ACK Pro cluster
       Per-scan namespace: intake/static worker, managed builder,
       managed Flask target, validation harness, runner-local legacy adapter
```

### Control cluster

The control cluster owns the durable authority: authentication, organization membership, authorization grants, policy compilation, job state, audit events, artifact metadata, reports, model consent, and remediation approval. It may reach RDS, KMS, the durable queue, the artifact broker, and approved model providers. It never runs customer code, mounts a Docker socket, or calls raw legacy-tool endpoints.

The control plane is a new FastAPI service and a separate TypeScript React application. It uses a mature OIDC/SAML identity service for login, MFA, and enterprise integration rather than building custom authentication. Product roles are owner, security engineer, developer, and viewer.

### Execution cluster

The execution cluster is a separate VPC/security domain. It has no direct RDS access, no public ingress, and no reusable scan workspace. Its dynamic node pool uses ACK Sandboxed Container `runV` only after a deployment preflight validates the selected region, compatible node SKU, Terway mode, NetworkPolicy support, and RuntimeClass.

Each scan creates one namespace and service account with a unique lease ID, ResourceQuota, LimitRange, default-deny network policy, ephemeral volumes, deadline, and expiry finalizer. A runner gets only a signed grant and time-limited artifact tokens. It cannot reach the control database, another scan, cloud metadata, the public Internet, or another artifact prefix.

The managed builder and target are separate runV workloads. The builder accepts only a PentrAI template plus reviewed manifests; it never interprets a customer Dockerfile or Compose file. Builder egress is limited to internal package mirrors and the image registry. Target egress is disabled. Only the validation harness can reach the target. No workload is privileged or may mount host paths, devices, or a Docker socket.

### Managed cloud services

| Service | Responsibility | Enforcement |
|---|---|---|
| ACK Pro control cluster | durable application services | private nodes, least-privilege RAM, signed images |
| ACK Pro execution cluster | per-scan untrusted workloads | runV node pool, default-deny networking, no public endpoint |
| RDS PostgreSQL | metadata and audit history | private endpoint, encrypted backup, no execution access |
| OSS | source, evidence, patches, reports | KMS encryption, tenant/scan prefixes, broker-only runner access |
| KMS/secret manager | data keys and submitted test credentials | opaque references outside the broker |
| durable queue | job/outbox delivery | identifiers and grants only; no source, secrets, or prompts |
| ACR | PentrAI and managed-template images | immutable digests, scan, sign, admission verification |

## Durable data and scan workflow

Core tables are `organizations`, `users`, `memberships`, `projects`, `source_artifacts`, `scan_grants`, `scans`, `scan_events`, `runner_leases`, `findings`, `validation_attempts`, `evidence`, `remediations`, `reports`, append-only `audit_events`, and an outbox. Every row includes organization scope, scan scope where applicable, actor/service identity, timestamps, schema version, and immutable content digests where relevant.

```text
draft -> uploaded -> authorized -> queued -> intake -> static
     -> dynamic_eligible -> validating -> reporting -> completed
                                  \-> cleanup -> failed/cancelled
```

Every transition requires an organization-authorized actor or scheduler identity, an idempotency key, and an append-only audit event. Cancellation becomes terminal only after cleanup completes or a retriable cleanup failure is recorded.

1. The browser uploads a size-limited archive to temporary tenant-scoped OSS through a short-lived upload grant.
2. The API validates metadata, creates an immutable source artifact digest, and issues an expiring signed `ScanGrant` bound to organization, project, source digest, scope, profile, and dynamic authorization.
3. The scheduler locks the scan, creates a runner lease, and sends only IDs plus an opaque grant reference through the queue.
4. Isolated intake validates the archive, builds inventory/SBOM/classification, and runs deterministic static analysis.
5. A managed Flask match plus dynamic authorization creates isolated build, target, and harness workloads. Otherwise, the scan reports static-only results with a plain-language explanation.
6. The policy-limited harness records redacted observations and immutable evidence through the collector.
7. Reports are rendered from normalized records, not model claims. The finalizer deletes execution resources and revokes credentials.

## Identity, secrets, models, and remediation

OIDC/SAML handles authentication and MFA. The application uses secure HTTP-only sessions, CSRF protection, RBAC, short-lived service credentials, and audit events for every authorization or policy decision.

Submitted test credentials live only in the KMS-backed secret broker. Every other service sees an opaque credential-profile ID. The approved validation workload may receive a read-only, short-lived file mount; no secret may enter browser state, prompts, logs, evidence, reports, or database event payloads.

The model gateway owns provider/model/region consent, adapters, redaction, structured output validation, cost/token budgets, retry/timeout handling, and provenance. Source and tool output are untrusted data within fixed task/schema instructions. A model can propose typed hypotheses and explanations but cannot choose targets, execute tools, alter policy, or mark a finding confirmed.

Only confirmed findings enter remediation. A remediation is a unified diff under strict path/file/line budgets, applied in a clean isolated worktree, tested, and focused-re-scanned. The pilot exposes patch download after review only.

## Conversation-first real-time UX

After scan creation, the user lands in one operational conversation workspace: a plain-language live feed, coverage and time budget, current validation, recent activity, scope, sealed-evidence links, cancellation, and report access. The newest useful update is primary; technical evidence is one click away.

Server-Sent Events provide the stream because the flow is server-to-browser and needs simple reconnection. Each visible `ScanEvent` is committed with a monotonic per-scan sequence before outbox publication. The browser resumes via `Last-Event-ID`; updates are never simulated, lost, or reordered.

"Ask about this scan" is a separately audited read-only request built from user-visible scan summaries and redacted evidence. It has no tool access and cannot change policy, job state, or findings. The interface never displays raw model token streaming, chain-of-thought, raw commands, raw tool output, or secrets.

## Security and release gates

1. **Intake:** enforce MIME/type, member-count, expanded-size, compression-ratio, nesting-depth, duplicate-name, symlink/hard-link, normalization, and archive-member limits. Git remains disabled until an isolated pinned-commit fetcher exists.
2. **Build/runtime:** forbid host Docker and arbitrary recipes. Admission policy denies privileged pods, host namespaces, host paths, Docker sockets, devices, unsafe capabilities, root users, untrusted images, and missing limits.
3. **Network:** default-deny at namespace/pod and VPC/security-group layers. Explicitly permit only DNS, target/harness, collector, artifact broker, internal package mirror, and registry paths. Target resolution is validated inside the execution namespace before every dynamic action.
4. **Supply chain:** pin, scan, sign, and verify all PentrAI images by digest. Record scanner database and managed-template versions.
5. **Data and operations:** use KMS encryption, artifact retention/legal-hold state, expiring URLs, secure deletion policy, tested encrypted backups, Terraform or ROS infrastructure, Helm delivery, migrations, health checks, metrics/logs/traces, alerts, runbooks, key rotation, and rollback to a prior signed release.

Dynamic validation is disabled until staging repeatedly proves hostile-input rejection; no public/control-plane/metadata/cross-job egress; policy and image enforcement; cleanup after cancellation, timeout, crash, restart, and worker loss; target reset between destructive attempts; correct internal-fixture outcomes; and no false safe result.

## Verification and delivery sequence

The corpus covers safe applications, true negatives, supported Flask templates, malicious archives, malformed manifests, prompt injection, secret redaction, renderer injection, model-schema failures, unsafe workload requests, cleanup failures, remediation-budget violations, and expected guinea-pig outcomes.

Required suites are unit, API/authorization, database migration, queue/outbox, SSE reconnect, artifact isolation, secret-broker, model-gateway, static scanner, execution-manager, Kubernetes policy, end-to-end staging, restore, and rollback tests. CI emits signed image digests, SBOMs, test results, and a release-acceptance record. An independent security review is required before pilot onboarding.

Delivery proceeds in six independently deployable milestones:

1. Control-plane foundation and durable schema; dynamic work disabled.
2. Complete safe static vertical, real-time UX, reports, and audit trail.
3. Provision and prove execution isolation plus managed Flask template.
4. Add reviewed harness, evidence lifecycle, and one validation class end to end.
5. Add bounded remediation and report export.
6. Complete corpus, observability, backup/restore, incident/rollback drills, independent review, staging acceptance, and opt-in one-customer pilot.

Each milestone preserves the preceding safety gates; dynamic validation cannot enable early.
