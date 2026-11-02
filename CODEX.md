# PentrAI — Codex Working Guide

## Product mission

PentrAI is a beginner-friendly, authorization-gated software security assessment
product. Companies submit software, source archives, private Git revisions,
authorized live URLs, or both source and URL. PentrAI creates a job-owned
isolated environment, analyzes source without running the uploaded application,
uses native HexStrike for model-selected tool work, and produces customer reports.

This is a defensive product. Live network activity is allowed only against a
customer-approved URL after proof of control, with target-bound runner egress
and separate authorization for disruptive tests. Never probe unrelated systems.

Never claim that an application is “100% safe” or “completely secure.” The
strongest valid conclusion is: **no validated findings within the declared
scope, coverage, tools, and budget.**

## Mandatory agent workflow

1. **Planning.** Before a non-trivial feature, clarify the goal, write a small
   approved design, break implementation into verified steps, and prefer tests
   before broad refactors. Do not begin a large feature merely from an
   ambiguous sentence.
2. **Scope confirmation — use Grill Me.** Before changing a security boundary,
   pipeline stage, or customer-facing behavior, use Grill Me to check the
   maintainer's understanding of the relevant existing behavior. Ask one
   evidence-based question at a time. Grill Me checks understanding; it does
   not replace an explicit product/scope decision from the user.
3. **Execution — use Ponytail.** Use Ponytail during implementation to favor the
   smallest correct, tested change: standard-library/platform features first,
   no speculative abstractions, and no dependencies or configuration that the
   product does not need. Security invariants, explicit tests, and clear audit
   behavior always override minimalism.
4. **Completion.** Run the relevant tests and `git diff --check`, report actual
   verification, and distinguish implemented behavior from design intent.

Ponytail is a user-level Codex plugin. Grill Me is installed as a Codex skill.
Ponytail has lifecycle hooks; review/trust them in Codex's
`/hooks` interface before relying on automatic activation.

## Mandatory tool handling

When the user explicitly asks for a tool, skill, plugin, or connector, do not
silently skip it or substitute another workflow. If the requested capability is
not immediately available: (1) explicitly tell the user it cannot yet be used,
(2) locate its installed path or connection/configuration and make a good-faith
attempt to enable it, then (3) use it or report the concrete remaining blocker.

## Repository map

| Path | Role | Status |
|---|---|---|
| `pentrai_server.py` | Rebranded HexStrike Flask tool server | Legacy local engine; do not expose to customers |
| `pentrai_mcp.py` | Rebranded HexStrike FastMCP client | Legacy agent/MCP bridge; do not expose directly to product users |
| `pentrai-mcp.json` | Local MCP configuration template | Points an MCP client to the private tool server |
| `hooks/llm_proxy.py` | OpenAI-compatible LLM proxy and tool-call logging | Legacy experiment/integration support |
| `hooks/tool_logger_hook.py` | Local tool-call logger | Legacy experiment/integration support |
| `prompt_generator.py` | Standalone CTF prompt GUI/CLI | Legacy research support, not product UI |
| `pentrai_pipeline/` | New product pipeline | Scaffold plus implemented ingest/sandbox/harness work |
| `pentrai_pipeline/contracts.py` | Typed artifacts between stages | Product backbone |
| `pentrai_pipeline/orchestrator.py` | Stage sequence, authorization gate, teardown | Wired; later stages remain stubs |
| `pentrai_pipeline/stages/ingest.py` | Folder/ZIP/Git materialization and recipe detection | Implemented; requires additional hardening before production intake |
| `pentrai_pipeline/stages/sandbox.py` | Docker/Compose deployment and teardown | Development harness only; build isolation is a production gate |
| `pentrai_pipeline/harness/` | Policy-limited tool interface for job agents | Implemented initial core; not yet wired into recon/operator stages |
| `guinea_pig/target/` | Deliberately vulnerable Flask target | Internal evaluation target only |
| `guinea_pig/SOLUTIONS.md` | Ground-truth answer key | Never ingest or expose to the analysis agent |
| `docs/ARCHITECTURE.md` | Original pipeline design | Product pipeline design reference |
| `docs/THREAT_MODEL.md` | Existing containment and prompt-injection model | Mandatory reading before sandbox changes |
| `docs/PRODUCT_BLUEPRINT.md` | Current product architecture and release gates | Primary product-design reference |
| `docs/RELEASE_ASSURANCE.md` | Internal test and pilot plan | Required before customer rollout |
| `tests/test_agent_harness.py` | Harness unit tests | Initial test coverage |

## History and naming

The repository is the rebranded HexStrike codebase. Commit
`eddf893af62f4b08b7c2eb381d4c3abbff218ee9` renamed:

- `hexstrike_server.py` -> `pentrai_server.py` (93% similarity)
- `hexstrike_mcp.py` -> `pentrai_mcp.py` (77% similarity)

The parent commit `90980973ba6a805d91df697176bbcd043ce6e67a` contains the
former HexStrike README and removed research/feature documentation. Inspect it
read-only when historical behavior or capability coverage is unclear; never
restore or check out historical files over current work without explicit user
approval.

## Existing engine: what it does

The legacy engine has a Flask server on `127.0.0.1:8888` by default and a FastMCP
client that exposes a large security-tool catalog. It contains roughly 169 MCP
tools and 176 HTTP routes across reconnaissance, web testing, dependency/cloud
and container assessment, binary/forensics analysis, CTF/research helpers, and
tool/process utilities.

The engine is useful because it has already been tested by the team, but it was
designed as a local single-operator tool. It contains generic shell execution,
file operations, process controls, and raw tool parameters. Those interfaces
are never part of the customer API and must not be passed unfiltered to an LLM.

The product uses the full native HexStrike MCP capability inside each isolated
runner. The model may choose tools, but the runner enforces job scope, network,
filesystem, resource, and tenant boundaries independently of the model.

## Product architecture and boundaries

```text
Customer browser/API
    -> control plane (identity, authorization, job policy, audit)
    -> per-job runner plane (native HexStrike + read-only source and/or approved URL)
    -> artifact plane (encrypted source, evidence, reports, approved patches)
```

Rules:

- The control plane never executes customer code or shells out to legacy tools.
- Each job has an isolated workspace, runner identity, network, resource budget,
  and cleanup lease.
- A runner may reach only its approved public target and explicit internal
  services needed for the job. It may not reach unrelated systems, the control
  plane, other jobs, cloud metadata, or customer artifact storage directly.
- The model receives no raw provider key, raw customer credential, or host path.
  It may call native HexStrike command and file tools inside the job runner.
- Credentials are resolved by a runner-side broker from an opaque profile name,
  mounted only for the approved stage, and never copied into prompts/logs/reports.
- Findings are hypotheses until independently checked evidence validates them.
- Automatic remediation produces a bounded patch in a temporary worktree. It
  never merges, deploys, or modifies customer source without explicit approval.

## Beginner-first operating model

Customer-facing product copy must never expose implementation or evaluation
language such as "local testing," "local preview," "bootstrap token," "worker,"
"fixture," or "internal." Treat testing as validation of the product intended
for deployment. Write precise, professional copy that states the capability,
scope, coverage, and current finding state without implying that unavailable
features are working. Keep development setup details in developer documentation,
not in the customer interface.

The default customer flow is:

```text
Sign in -> upload private source -> attest ownership -> Start secure scan
        -> review findings, evidence, remediation, and reports
```

PentrAI chooses target classification, work budget, runner
limits, scanner versions, report format, and recommended managed model. The
customer does not configure command lines, containers, ports, templates, or
security-tool flags.

The upload flow has three outcomes:

1. **Static-only ready:** assess supported source without executing it.
2. **Managed sandbox ready:** for supported frameworks and lockfiles, generate a
   reviewed, versioned sandbox recipe from a controlled template.
3. **Needs a deployment recipe:** complete static assessment and request an
   existing vetted Docker/Compose recipe through a plain-language prompt.

Customer-provided model/API keys are optional administrator-only settings. The
default is a managed, recommended provider with explicit data-sharing policy.

## Pipeline stages

```text
authorization + intake
  -> source inventory + SBOM
  -> deterministic static analysis (SCA/SAST/secrets/IaC/container)
  -> target classification + typed plan
  -> managed sandbox deployment when eligible
  -> private recon + policy-limited validation
  -> evidence-based finding lifecycle
  -> bounded remediation patch + clean verification
  -> Markdown, PDF, and DOCX reports
```

Pipeline implementation status:

- Implemented: typed contracts, config, CLI/job model, authorization gate,
  folder/ZIP/Git intake, Docker/Compose development sandbox, guaranteed teardown,
  guinea-pig target, product blueprint, release assurance plan, and initial
  agent harness.
- Still stubbed: recon, SCA, SAST, synthesis, exploit/validation workflow,
  reports, LLM provider client, analyst agent, operator agent, and the legacy
  PentrAI pipeline client.
- Do not describe the product as end-to-end complete until those stages and their
  acceptance tests are implemented.

## Agent harness

`pentrai_pipeline/agents/hexstrike_mcp.py` is the native MCP connection for
the job runner. `pentrai_pipeline/agents/hexstrike_loop.py` lets the model choose
from the complete native catalog and requires a scope guard on every call.
The existing `pentrai_pipeline/harness/` is legacy product scaffolding:

- `contracts.py`: typed policy, target, request, decision, result, audit event,
  and model-safe context contracts.
- `policy.py`: small reviewed catalog and deterministic policy checks.
- `agent_harness.py`: executes approved structured actions, applies budgets,
  records audit events, bounds output, and redacts common secret patterns.
- `transport.py`: private HTTP adapter to the runner-local PentrAI server.
- `factory.py`: constructs a per-job harness from `Target`, `IngestResult`,
  `DeployedTarget`, and `Settings`.

Do not expand the four-tool legacy catalog as the product integration path.
All native HexStrike tools are runner-side capabilities. Contain their effects
with runner isolation, target-scoped egress, read-only mounts, quotas, grant
checks, and audit logs rather than a small model-visible allowlist.

## Non-negotiable security release gates

Dynamic scans must remain disabled for production until all gates in
`docs/PRODUCT_BLUEPRINT.md` and `docs/RELEASE_ASSURANCE.md` pass. In particular:

- Build untrusted Dockerfiles in a microVM, rootless remote builder, or equivalent
  isolated build service; never through the control-plane host Docker daemon.
- Reject unsafe Docker/Compose features: privileged mode, host network/PID/IPC,
  host or Docker-socket mounts, devices, unsafe security options, host users,
  remote build contexts, and unsupported extensions.
- Pin/verify runner images and scanner databases; do not pull arbitrary images at
  scan time.
- Enforce network policy at DNS and IP layers, not merely by prompt wording or
  URL validation.
- Isolate all source parsing/scanning; “static” input can still exploit a parser.
- Defend archive and Git intake against traversal, symlinks, decompression bombs,
  submodules, hooks, LFS abuse, SSRF, and unexpected egress.
- Encrypt and tenant-scope artifacts; use immutable digests, redacted/sealed
  evidence, retention, secure deletion, and expiring downloads.
- Treat source, tool output, model output, patch output, report renderers, and
  notifications as untrusted input.
- Keep scanner-detected, triaged, validated, refuted, inconclusive, accepted-risk,
  and fixed-verified finding states distinct.

## Release assurance

Before any customer deployment, use only company-owned code and local/internal
fixtures. Required corpus and release checks are in `docs/RELEASE_ASSURANCE.md`.

At minimum prove:

- organization isolation, roles, scan-grant expiry, audit trail, cancellation,
  retry, and reaper behavior;
- archive/Git rejection, source-path containment, source digest consistency, and
  no cross-tenant artifact access;
- no runner egress outside the specifically approved public target and required
  internal services; no control-plane, sibling-job, or host-metadata access;
- no leaked provider keys or customer secrets in the UI, worker, logs, evidence,
  or reports;
- correct positive/true-negative results on the guinea pig and other internal
  fixtures, with no false “safe” verdict;
- remediation stays in its worktree/change budget and requires approval;
- evidence, reports, and cleanup behavior remain correct after timeout, crash,
  cancellation, host restart, and worker loss.

Start customer use with an isolated staging environment and an opt-in pilot,
conservative quotas, static assessment by default, dynamic scans behind the
release gates, monitoring, rollback, incident response, key rotation, and an
independent security review of PentrAI itself.

## Local commands and verification

From the repository root:

```powershell
# Compile pipeline code and tests
python -m compileall -q pentrai_pipeline tests

# Run harness tests
python -m unittest discover -s tests -v

# Check whitespace errors
D:\Apps\Git\cmd\git.exe diff --check

# Inspect the historical HexStrike documentation without modifying the worktree
D:\Apps\Git\cmd\git.exe show 90980973ba6a805d91df697176bbcd043ce6e67a:README.md
```

The legacy local engine can be started with `python pentrai_server.py`, but do
not expose it on a network or use it as the product API. It depends on optional
external security tools listed in `requirements.txt` and the README.

## Repository hygiene

- Preserve unrelated user changes. Do not reset, force-checkout, or delete broad
  paths.
- Do not edit `pentrai_server.py` or `pentrai_mcp.py` when building the product
  pipeline unless the user explicitly authorizes an engine change. The product
  boundary belongs in `pentrai_pipeline/`.
- Never ingest `guinea_pig/SOLUTIONS.md`; it is the test answer key.
- Do not add customer source, credentials, runtime logs, generated databases,
  sandbox artifacts, or provider keys to Git.
- Prefer `apply_patch` for file edits and verify every substantive change.
