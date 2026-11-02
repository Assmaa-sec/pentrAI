# Product workspace redesign proposal

Status: product direction approved by the maintainer on 2026-10-27; the model
effort clarification below is included. This document describes work to
implement and verify; it does not claim that the proposed features exist.

## Implemented local slice (2026-10-27)

The React workspace now has distinct Overview, Projects, Assessments, and
owner-only Administration views. The assessment form is shorter and removes the
decorative guidance panel. The palette uses graphite navigation, an off-white
canvas, and cobalt actions. Project creation, project switching, recent scan
search, scan detail, findings, reports, and cancellation/retry continue to use
the existing APIs. The local owner can list members, change an existing member's
role, revoke membership, and read recent audit events. The server enforces the
owner role, tenant boundaries, and last-owner protection; a developer cannot
gain access by navigating directly to an admin endpoint. New identities still
require identity-provider provisioning, so this is not a complete invitation
flow or a production sign-in experience.

The live static worker still has no model stage. New scans use the existing
`standard` static profile, and the customer form states its actual coverage.
Quick/Standard/Deep as LLM effort modes remain an approved architecture change
to implement only with provider capabilities, an immutable scan plan, and model
E2E tests. No dynamic scanning or deployment readiness is claimed by this slice.

## What the current product actually supports

The local customer flow supports project creation, ZIP upload (50 MB limit),
ownership attestation, quick/standard/deep static profiles, scan history within
one selected project, scan status and events, detected findings, a read-only
assessment question endpoint, retry/cancel at supported states, and Markdown,
PDF, and DOCX report downloads. The static worker checks exact Python package
pins in `requirements.txt`; standard and deep also run a small set of Python
AST checks. Deep raises the code-finding cap. A local API end-to-end test covers
upload through report exports. This is not evidence of dynamic scanning or
deployment readiness.

The database has users, organization memberships, roles, and audit events.
Authorization checks already distinguish owners/security engineers from other
members for selected actions. There is no customer API or page to invite users,
change roles, remove access, inspect audit history, or configure an organization.
The browser currently asks for an organization UUID and bearer token; those are
local access mechanics, not a finished sign-in experience.

## Information architecture

Keep the existing sidebar and assessment terminology, but make every visible
navigation item lead to a real view. Remove the generic guidance card and the
footer slogan. Use the freed space for the user's work and honest coverage.

| View | First useful content | Required backing |
| --- | --- | --- |
| Overview | Recent assessments, status, latest findings, action needed | Existing project/scan APIs for one project; organization-wide summary API later |
| Projects | Searchable project list, create project, project detail | Existing project create/list; add project metadata before showing it |
| Assessments | Searchable scan table, state and created date, new assessment | Existing per-project scan list; add pagination/filtering for scale |
| Assessment detail | Progress, source identity, findings, coverage, activity, report | Existing scan/finding/event/report APIs; add explicit coverage data |
| Findings | Actionable finding list and details across projects | New finding list, severity/provenance, triage/ownership APIs |
| Administration | Members and roles, policies, integrations, audit, retention | New role-gated APIs and audit events; no decorative admin links |

The main customer route should begin with sign-in and a remembered organization
selection. In local development, keep the explicit test credentials in developer
documentation. The first signed-in screen should show recent work and one clear
primary action, “New assessment.” Empty states should explain the next step.

### Architecture decision: the smallest reliable product shape

Keep one FastAPI control plane, one tenant-scoped database, one artifact store,
and a separately isolated scan worker. Add bounded modules and APIs inside that
shape instead of introducing a service per feature. The browser never speaks to
the legacy HexStrike server or directly chooses runner tools. Identity, role
checks, scan-plan resolution, and audit writes remain server-side.

Use stored `scan_events` plus server-sent events for progress. The API checks
organization membership and scan ownership before streaming, and replays rows
whose sequence is greater than `Last-Event-ID`. The browser keeps the last
sequence for a live connection and ignores older frames. On a full reload it
replays from the database; no browser event cache, WebSocket service, or second
message broker is needed for the customer view. Stop retrying on authorization
failure and show a reconnect state for transient network failure. Test replay,
duplicate suppression, cross-tenant denial, reload, and worker interruption.

For the frontend, use clear route-level views (Overview, Projects, Assessments,
Assessment detail, Administration) while sharing the existing React API client
and design tokens. Implement only backed actions. Keep account administration
behind server-returned capabilities and matching API authorization; hiding a
button alone is never access control.

## Assessment creation

Use a short guided flow: (1) select project, (2) add supported source, (3) review
scope and authorization, (4) start. Default to Standard. Keep Quick and Deep in
an expandable “Assessment options” section. The maintainer wants these choices
to set the LLM's reasoning effort when model-assisted analysis is available:

| Customer choice | Intended relative model effort |
| --- | --- |
| Quick | Low |
| Standard | Medium |
| Deep | High (called “hard” in the request) |

This is a product-level intent, not a universal request parameter. The backend
must resolve each tier against the selected provider/model's supported levels,
record the requested and effective levels with the model/version, and reject or
clearly disclose a combination that cannot preserve three distinct tiers.
Keep scan scope, scanner coverage, model effort, and cost/time budget as separate
recorded fields. Do not equate increased reasoning effort with broader security
coverage or validated findings. Do not expose HexStrike commands, ports,
targets, arbitrary URLs, or scanner flags.

The current live static worker does not call an LLM. Its existing profile field
changes whether the small Python AST check runs and its finding cap. Do not
claim that today's selector controls model effort. Before presenting the new
meaning in the UI, introduce the provider capability mapping and make the
worker/API semantics explicit; when no LLM is used, show the actual static
coverage and omit an ineffective effort selector.

### Architecture decision: assessment mode is an LLM effort preset

Use **one customer-facing assessment mode** (`quick`, `standard`, `deep`) and
resolve it on the server against the organization's approved model. The three
modes change only the model's reasoning effort and its bounded time/token/spend
budget. They do not change authorization, tool permissions, network access,
scanner set, or the meaning of a finding. Keep deterministic static coverage
consistent across modes so a faster choice cannot quietly skip a vulnerability
class. A separate versioned `ScanPolicy` owns scanner selection and the
dynamic-validation/tool allowlist; it remains internal and enforced by the
runner. `dynamic_authorized` stays a separate, explicit gate.

```text
Browser: mode + source + scope + authorization
  -> Control plane: tenant/role/consent checks; resolve approved model and
     capability snapshot; persist immutable scan plan
  -> Static worker: same deterministic checks for every mode
  -> Isolated model stage, when enabled: apply provider-specific effort and
     bounded budget; produce hypotheses with provenance
  -> Report: actual coverage, requested mode, effective effort, model/version,
     policy version, limits, and incomplete-stage reasons
```

The capability resolver maps relative tiers to **three distinct supported
levels** for the configured model. For example, a model supporting
`low/medium/high` uses those values; a model supporting `low/high/max` uses
those. The adapter translates into that provider's request shape. If three
distinct levels cannot be enforced, the unavailable mode is disabled with a
clear reason or the admin selects another approved model. A provider rejecting
the resolved level fails the model stage visibly; the system never retries at a
different effort without recording and disclosing the change. There is no
generic pass-through of an unverified `reasoning_effort` field to every
OpenAI-compatible endpoint.

Persist `requested_mode`, `provider`, `model_id`, `effective_effort`,
`capability_version`, `scan_policy_version`, and per-stage budgets/results in
the scan plan before dispatch. Bind its digest into the signed worker grant and
audit trail, then show these values in the report. Retry uses the same plan;
an intentional model or mode change creates a new assessment. Do not put API
keys, source text, or raw model reasoning in the browser, grant, or audit log.

Migration: preserve the meaning of historical `profile` records and reports.
Introduce `requested_mode` as a new field rather than silently reinterpreting
old scans. Migrate the existing static worker to one explicit deterministic
coverage policy and replace harness `ScanProfile` tool gating with policy-owned
permissions. Only then surface the new mode labels on a model-backed flow.

After upload, show the source filename and digest, chosen mode when applicable, the precise
checks available for the submitted language/manifests, and any unsupported
coverage. On completion, show detected hypotheses separately from independently
validated findings. Do not infer “safe” from an empty finding list.

## Administration and user management

Start with a real owner-only members page: list members and roles, invite or
provision a member, change a role, revoke membership, and show the resulting
audit entry. Every action needs server-side authorization, tenant isolation,
idempotency where retries matter, and E2E tests for owner and denied roles.

Then add organization policy and operations views: approved scan defaults,
quotas, artifact retention, identity provider configuration, scanner/database
versions and health, failed-job visibility, and audit export. Do not expose
settings until their enforcement exists. Dynamic scan controls stay absent until
isolation and release gates pass.

## Visual and interaction direction

Use a denser, calmer workspace: clear page title, one primary action, project
context in the header, tables for repeatable records, and a detail panel for
the selected item. Reserve colored badges for scan state and finding state.
Replace the current mint/teal palette with graphite navigation (`#111827`),
off-white canvas (`#F8FAFC`), white record surfaces, and a single cobalt action
color (`#2563EB`). Reserve amber/red/green for statuses with text labels; do
not encode status by color alone. Increase text contrast, reduce tinted cards,
and provide consistent focus, loading, error, and empty states. Replace decorative
symbols with a consistent icon set or simple text labels. Support keyboard use
and narrow screens. Do not add decorative metrics with no backed calculation.

## Verified implementation slices

Current local implementation includes a focused connection screen, loopback-only
automatic access when local development authentication is explicitly enabled,
organization-wide project/assessment/finding views, backed overview counts,
assessment depth selection for the static worker, and owner-only member role and
revocation controls with audit entries. The local source assessment flow and
report exports have end-to-end coverage. The organization lists currently show
the newest 100 assessments and 200 findings; pagination, finding triage,
identity-provider provisioning, and model effort integration remain open. The
static assessment path does not invoke an LLM, so its depth selector must not
be described as model reasoning effort.

1. **Workspace shell and assessment list.** Remove guidance filler, show project
   context and an actual scan table using existing APIs, preserve scan creation
   and report access. Browser E2E: connect, select project, open an existing scan,
   filter list, reload, use the same flow at desktop and mobile widths.
2. **Coverage and assessment detail.** Persist structured scanner coverage and
   source digest metadata; show unsupported ecosystems and incomplete checks.
   API/E2E: Python-positive and JavaScript-only source, zero-finding states,
   failed/retried scans, and report consistency.
   Add model-effort selection only when the model-assisted stage is connected:
   test Quick/Standard/Deep against each configured provider's supported levels,
   unavailable-level behavior, requested/effective effort provenance, and the
   no-model static path.
3. **Members and roles.** Add owner-only API and UI with audit trail. E2E: invite,
   role change, revoke, cross-organization denial, stale-session behavior, and
   read-only developer view. OIDC provisioning must be configured before pilot.
4. **Finding workflow.** Add severity/provenance, triage state, owner, reason,
   comments, and repeat-scan comparison. E2E: state changes and auditability;
   never label a scanner detection “validated” without independent evidence.
5. **Operations and integrations.** Add enforceable policies, quotas, retention,
   scanner health, Git integration and notifications only with matching backend
   controls and E2E coverage. Dynamic capabilities require separate isolation
   and release-gate evidence.

## External product patterns reviewed

GitHub Security Overview separates overview, risk, coverage, and remediation
campaigns and limits views by permissions:
https://docs.github.com/en/code-security/concepts/security-at-scale/security-overview

GitLab exposes enforced scan policies and distinguishes vulnerability triage
from detection:
https://docs.gitlab.com/user/application_security/policies/

Semgrep lets teams filter and triage findings by project/branch with explicit
states and reasons:
https://semgrep.dev/docs/for-developers/resolve-findings-through-app

These are patterns to evaluate, not claims that PentrAI already implements them.
