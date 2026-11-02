# PentrAI initial-version handover — 2026-11-02

## What this checkout contains

This commit captures the local PentrAI product work in the current checkout:
the control plane, authenticated project and scan APIs, organization assessment
authorization, source upload and digest checks, local static worker, native
HexStrike worker path, model gateway and usage-credit records, browser
workspace, per-job execution specifications, and tests. The legacy
`pentrai_server.py` and `pentrai_mcp.py` remain internal runner components.
Read `CODEX.md`, `docs/PRODUCT_BLUEPRINT.md`, `docs/RELEASE_ASSURANCE.md`, and
`docs/LOCAL_PRODUCT_TESTING.md` before extending or deploying it.

Source assessments are designed to inspect code without launching the uploaded
application. A customer may submit source, a verified website URL, or both.
The model chooses from the native HexStrike MCP catalog; all security issues
are intended to appear as PentrAI findings with model-written explanations.
The runner boundary, target authorization, evidence, and credit accounting are
separate from the model's judgment.

## Verified locally

- The native MCP bridge enumerated **169 tool schemas** and completed harmless
  calls inside a non-root, read-only, network-disabled Docker runner. The route
  audit finds 164 matched Flask routes, four MCP-local or composite tools, and
  one missing route: `burpsuite_scan` calls `/api/tools/burpsuite`.
- The last completed restricted smoke test measured **111/124** health-list
  command names in PATH, with no health/PATH disagreements. It exercised
  Hashcat-utils, SpiderFoot, libc-database, Metasploit, SearchSploit,
  pwntools, Sleuth Kit, Volatility, Postman Newman against local `/health`,
  and Insomnia Inso CLI in addition to earlier runner checks.
- A later Docker image build added pinned GraphQL scanner, JWT analyzer, and
  HashPump fork source. The user stopped the task before their restricted
  smoke test completed. Treat these three as **built but unverified** and do
  not claim 114/124 operational tools until a completed check passes.
- The local product testing instructions describe API, browser, proxy,
  authenticated upload, worker, and fixture-model checks. Those local checks
  establish a development vertical, not a customer-ready deployment.

The `/health` denominator is a list of executable names checked with `which`.
It is **not** the MCP tool count and does not prove a named tool can scan a
target. The 169-tool catalog also does not prove every route and dependency
works. Do not add placeholder commands to improve this number.

## Remaining health names and constraints

The 13 names missing in the last completed 111/124 smoke were:

| Names | Remaining work or constraint |
| --- | --- |
| `graphql-scanner`, `jwt-analyzer`, `hashpump` | Newly built from pinned sources; run and evaluate restricted fixtures before counting. |
| `burpsuite`, `maltego`, `stegsolve` | Desktop/licensed or interactive tools need a real headless integration, license where applicable, and an appropriate runner environment. Burp's native MCP route is currently missing. |
| `clair` | The native route invokes `clairctl analyze`, which does not match the documented current Clair CLI; Clair also needs a service/database. Reconcile the route and deploy dependencies. |
| `docker-bench-security`, `falco`, `kismet`, `responder` | Need Docker socket/host access, kernel tracing, wireless hardware, or raw network capabilities that conflict with the current unprivileged per-job runner. They need separate scoped execution designs. |
| `have-i-been-pwned` | Hosted API capability requires credentials and policy-controlled egress; a local executable name alone is not meaningful. |
| `api-schema-analyzer` | No verified matching upstream executable or native route integration has been established. |

Command presence is only a first check. Each tool still needs a recorded
version, license, inputs, service/data dependencies, authorization scope, and
a bounded functional fixture. In particular, the small baked libc-database
corpus only identifies the runner's libc; it is not a broad exploit corpus.

## Open product and release work

- Complete and evaluate real provider model configuration, token pricing,
  managed key handling, and customer billing. Current credits are internal
  units; no payment configuration is deployed.
- Provide deployment configuration for the control plane, queues, encrypted
  artifact storage, model gateway, isolated runner, and network policies.
  No live Kubernetes environment or production containment proof exists.
- Prove URL ownership and target-bound egress end to end before enabling live
  network scans. Keep source-only assessment from executing uploaded apps.
- Resolve the Burp route gap, verify remaining HexStrike tools with real
  fixtures, and record honest availability rather than treating 124/124 as a
  synonym for complete functionality.
- Finish release assurance: tenant isolation, source/parser isolation,
  evidence handling, cancellation and cleanup under failure, finding quality,
  secret leakage checks, and independent security review. Dynamic validation
  remains behind the gates in `docs/RELEASE_ASSURANCE.md`.
- Continue reviewing the browser layout and interaction details against the
  reference screens. The UI has been worked on locally, but this handover does
  not certify a final visual design or production accessibility pass.

## Reproduce the runner inventory

From the repository root, with Docker Desktop running:

```powershell
docker build -f runner/Dockerfile -t pentrai/hexstrike-runner:local .
docker run --rm --hostname localhost --network none --read-only `
  --tmpfs /job/tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001 `
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001 `
  --cap-drop ALL --security-opt no-new-privileges `
  --pids-limit 256 --memory 2g `
  pentrai/hexstrike-runner:local python /opt/pentrai/runner_smoke.py --missing
```

For the wider local API and browser flow, follow
`docs/LOCAL_PRODUCT_TESTING.md`. Do not commit local bootstrap tokens,
provider keys, customer archives, database files, or generated runner state.
