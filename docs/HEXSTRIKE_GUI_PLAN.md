# HexStrike GUI implementation plan

## Agreed product behavior

PentrAI is the customer interface and control plane for native HexStrike. The
model inspects submitted source and/or an authorized live URL, chooses and
sequences HexStrike MCP tools, and explains evidence-backed findings. A source
submission is analyzed without running the uploaded application. Live network
scans use the customer-approved URL and scope. Customers may submit either or
both.

All native HexStrike tools and APIs are the intended runner-side capability,
including command and file tools. The model is not limited to a handpicked
catalog. The product still enforces job, tenant, target, resource, and network
boundaries outside the model. Out-of-scope calls fail before reaching HexStrike.

The intake flow requires organization authorization and, for a live site, proof
of control. The owner can delegate access through roles. Each scan records its
actor, source digest, URL scope, and authorization. Disruptive live tests require
separate approval. Uploads go directly into a per-job sandbox with ready workers;
when capacity is exhausted, the UI shows a queue. Failures offer Retry or Cancel.

The model chooses scans according to its understanding of the application and
the selected Low, Medium, or High work budget. Findings require traceable tool
or source evidence, carry uncertainty and coverage limits, and appear as PentrAI
findings with model-written explanations. They never claim complete safety.

The company supplies model access by default; an administrator may configure a
separate account key. Credits are reserved before work, charged for actual
usage, and unused credit is returned on failure or cancellation. Account
credentials and target credentials remain separate.

## Implementation sequence

1. Add native model tool-call parsing, a bounded agent loop, and a runner-local
   MCP adapter. Verify schema, chaining, rejection, usage, and failure paths.
2. Build the isolated per-job HexStrike runtime and enforce source mount,
   tenant, network, target, and command boundaries outside the model. Prove the
   boundaries with containment tests before customer dispatch.
3. Connect intake, proof of control, scoped job authorization, worker dispatch,
   retries, cancellation, usage accounting, and durable events.
4. Convert model assessments and tool evidence into PentrAI finding lifecycle,
   progress, reports, and customer UI. Test source, URL, and combined jobs.

The loop and adapter are integration components only. They do not establish
runner isolation, live-site authorization, customer dispatch, or release
readiness. Dynamic execution remains gated until containment is verified.

## Current implementation state

The model client accepts native function calls, the bounded loop checks each
call through a required runner guard, and the MCP adapter connects to the native
bridge on runner-local loopback. Model-written finding drafts must cite result
digests from the same run. The database, findings API, and workspace display
those explanations. The authenticated runner result receiver checks the live
scan grant, lease, scope digest, and current-run evidence before persistence.
The lease reaper completes scans only after runner cleanup succeeds.
Runner admission now verifies the finalized source binding and release gate,
then stages the queued state, short-lived grant, lease, and exact job scope in
one database transaction. The local static reaper leaves scans with active
HexStrike leases alone. This admission step still needs a deployed cluster
dispatcher and credential provisioner before customer intake can use it.
An ordered workload launcher and namespace-bound kubectl adapter now exist,
with fake-cluster tests for source staging before HexStrike and failure cleanup.
There is no configured execution cluster, so no live provisioning or containment
proof has been established.
Runner grants can now be reconstructed after a dispatcher restart, and source
staging has a digest-bound marker so it is not repeated after its writable Pod
is deleted. A private managed-model gateway verifies lease-bound tokens and
keeps the provider key outside the runner; it is currently mock-tested only.
A database-backed dispatch tick now claims authorized scans, launches their
prepared workloads, renews its claim during staging, and retries failed starts
up to three times. It checks for an existing matching HexStrike Job after a
restart. The lease reaper fails unfinished scans after expiry and successful
cleanup. This is tested against a fake cluster; it is not a deployed service.
Cancellation revokes the grant, stops staging at the next dispatch heartbeat,
and makes the lease immediately eligible for namespace cleanup.
New scans now persist an execution backend. The customer API rejects a scan
while no configured native dispatcher is ready, rather than silently sending
it to the old static worker. The latter remains an explicit local development
mode. Both workers filter by the persisted backend, and retries preserve it.
The readiness setting does not prove containment; the native dispatcher keeps
its separate fail-closed release gate. The API now also requires a fresh
dispatcher heartbeat before accepting HexStrike scans, so a setting alone does
not represent worker availability. A polling service loop combines dispatch
and cleanup, but it is not wired to a live cluster or deployed yet.

The local runner image builds with MCP 1.30. A restricted Docker probe verified
the native server, 169-tool MCP catalog, and one tool call. A second probe used
a deterministic fixture model to select a native HexStrike command that read
staged source and produce an evidence-linked, model-written finding.
All 169 native MCP tool schemas are forwarded to the selected model, without a
PentrAI tool allowlist. This is the same client/bridge/server connection described
in the upstream HexStrike README for Claude Desktop, Cursor, VS Code, and Roo
Code. The native server's external executable availability check is incomplete
(62 of 124 names) in the local image; this affects whether a selected tool
can execute, not whether the MCP catalog is connected. A local grant-bound
source broker, digest-checking ZIP stager, and
separate source-staging job specification exist. There is no deployed
dispatcher, artifact broker deployment, model gateway, collector deployment,
or ACK cluster yet. A separate development-only Docker route now connects
authenticated source upload, native HexStrike MCP, a model exchange over stdio,
evidence-linked PentrAI findings, report persistence, and container cleanup.
It accepts source-only scans while a local Docker worker heartbeat is fresh.
The end-to-end test passes with an owned fixture and a simulated
OpenAI-compatible endpoint; analysis quality with a real provider is untested.
The old local static route remains available only when explicitly selected in
development configuration. Neither local route proves production isolation.

Source-only, verified-URL-only, and combined scan records now have distinct
intake data. A web target proof uses a short-lived token served at a fixed path;
the verifier pins a public DNS address, bounds the response, and refuses
redirects. Scan grants bind the exact URL and proof record. The frontend has
the two-step site verification flow. The default control-plane capability gate
keeps the URL flow unavailable until a real isolated HexStrike runner is ready;
this is not yet an end-to-end URL scan.

Organization owners can now record a time-limited assessment authorization with
an explicit scope, source and URL permissions, and an accepted terms version.
Native scans bind that authorization and refuse creation, admission, or retry
after it expires or is revoked. Revocation cancels pending scans and their
grants. The customer workspace exposes approval and revocation to owners.
Source scans no longer use a repeated per-scan authorization checkbox. URL
scans also require separate, short-lived proof of control.

Customers can select from operator-configured model options. The choice and its
input/output credit rates are bound to the scan and preserved across retries.
The local worker and private gateway route model turns to that selected option;
the provider credential remains outside the runner. Options are configured by
the operator, and the browser receives only names and rates. Native scans
reserve a profile-sized credit budget multiplied by the option's higher rate. The
local worker and private model gateway record provider-reported usage per model
turn; success charges that usage and refunds the rest. Cancellation or failure
charges usage already returned by the provider and releases the balance. A late
provider response after cancellation is still charged to the organization.
Credits are provider-reported tokens weighted by each model's input and output
credit rates. These rates are deployment-owned configuration, not a live price
feed or payment integration. Local
bootstrap provisions a development balance; production credit provisioning and
billing are not configured.

The local source route is verified by three opt-in Docker integration cases:
native finding persistence, an OpenAI-compatible model exchange, and failed
model cleanup with retry. The model endpoint is simulated in these cases.
Unfinished work includes a real managed provider acceptance run, administrator
optional provider-key storage, complete external HexStrike executable packaging,
source/URL combined execution through an isolated runner, live ACK containment
proof, and deployment configuration. The URL and production dynamic gates stay
closed until those checks pass.
