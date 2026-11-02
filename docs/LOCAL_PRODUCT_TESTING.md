# Local product testing

The deployment account, region, object store, and OIDC provider are deliberately
unbound. These steps exercise the current local vertical on Windows without
enabling dynamic validation.

From `main/pentrAI` in PowerShell:

```powershell
py -3.14 -m venv pentrai-env
Remove-Item Env:PIP_NO_INDEX -ErrorAction SilentlyContinue
.\pentrai-env\Scripts\python.exe -m ensurepip --upgrade
.\pentrai-env\Scripts\python.exe -m pip install -e ".[test]"
.\pentrai-env\Scripts\python.exe -m unittest discover -s tests -q
.\pentrai-env\Scripts\python.exe -m compileall -q control_plane static_worker pentrai_pipeline
```

The repository's `pentrai-env` directory is ignored. The tested environment
uses Python 3.14.3 with FastAPI 0.142.2, Psycopg 3.3.6, Authlib 1.8.0,
and joserfc 1.7.5. These packages are installed in the local virtual
environment and pinned by `pyproject.toml`. To build a standalone local Python
runtime after installing dependencies, run:

```powershell
.\pentrai-env\Scripts\python.exe scripts\build_portable_python.py
.\.tmp\python-runtime\python.exe -m uvicorn --version
```

The builder downloads the official [CPython 3.14.3 Windows embeddable package](https://www.python.org/downloads/release/python-3143/),
checks its published SHA-256, and copies the installed application packages
beside it. The resulting ignored `.tmp/python-runtime` has its own interpreter
and isolated import path, so the API, worker, and bootstrap commands below can
use `.\.tmp\python-runtime\python.exe` instead of the virtual-environment
interpreter. The [Python embedding guide](https://docs.python.org/3/using/windows.html#the-embeddable-package)
recommends installing third-party packages alongside the embedded runtime rather
than using pip inside it. Rebuild the runtime when project dependencies change.
If `py` is unavailable, invoke the installed Python executable directly.
If a managed shell blocks writes to Python's temporary directory, run the
bootstrap in a normal local PowerShell window; the package installation itself
requires access to PyPI or a mirror.

To verify the schema on local SQLite:

```powershell
$env:PENTRAI_DATABASE_URL = 'sqlite+pysqlite:///.tmp/control-plane-local.db'
.\pentrai-env\Scripts\alembic.exe upgrade head
.\pentrai-env\Scripts\alembic.exe check
```

To run the control plane's health endpoint locally, keep the database variable
above and start a server bound to loopback:

```powershell
$env:PENTRAI_GRANT_SIGNING_KEY = .\pentrai-env\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
$env:PENTRAI_LOCAL_ARTIFACT_ROOT = '.tmp/local-artifacts'
$env:PENTRAI_LOCAL_DEV_AUTH = 'true'
$env:PENTRAI_LOCAL_STATIC_ENABLED = 'true'
.\pentrai-env\Scripts\python.exe -m control_plane.local_bootstrap
.\pentrai-env\Scripts\python.exe -m uvicorn control_plane.asgi:app --host 127.0.0.1 --port 8765
```

In another shell, `Invoke-RestMethod http://127.0.0.1:8765/healthz` should
return `status: ok`. Requests without a bearer token return 401. Set
`PENTRAI_LOCAL_DEV_AUTH=true` only for
local loopback testing. The bootstrap command provisions an owner, organization,
and project and prints a 24-hour signed token plus IDs. Keep the same signing
key for bootstrap, API, and worker. With this switch absent, protected routes
require real OIDC configuration and provisioned users.

For the browser workspace, keep the API on port 8765 and run:

```powershell
npm --prefix web ci
npm --prefix web run build
npm --prefix web run dev
```

Open `http://127.0.0.1:5173`. Vite proxies API requests to the local control
plane. Paste the bootstrap organization ID, project ID, and bearer token, then
upload a ZIP from the Start a static scan form. The worker picks up the job.
The workspace shows status, findings, event feed, report text, read-only scan
questions, and Markdown/PDF/DOCX downloads. The browser client resumes the
event feed using the last persisted event sequence.

For a native HexStrike scan, the organization owner first opens Administration
and records the approved source or website assessment scope and duration. They
must accept the authorization statement. The local bootstrap provisions one
million token credits for the development organization. Native scan creation
reserves 20,000, 80,000, or 200,000 credits for quick, standard, or deep work.
The Credits endpoint and Administration view show available, reserved, and
provider-metered spent credits. Each model option specifies integer credits per
input and output token. Credits are an internal unit, not money.
The legacy static development route retains its per-scan attestation.

## Local native HexStrike source assessment

This separate development mode runs a source-only scan inside one Docker
container per job. The container has no network, a read-only image filesystem,
job-owned tmpfs, dropped capabilities, a process limit, and CPU/memory limits.
The ZIP is checked and extracted inside that container. Native HexStrike tools
are visible to the model; model calls cross the container's stdio channel so
the provider key stays in the local worker process. This does not establish
production runner containment or enable URL scans.

Build the local runner image from the repository root, then set the same database,
signing key, and artifact root in the API and worker shells:

```powershell
docker build -f runner/Dockerfile -t pentrai/hexstrike-runner:local .
$env:PENTRAI_LOCAL_DEV_AUTH = 'true'
$env:PENTRAI_LOCAL_HEXSTRIKE_ENABLED = 'true'
$env:PENTRAI_LOCAL_STATIC_ENABLED = 'false'
$env:PENTRAI_LLM_BASE_URL = 'https://YOUR-OPENAI-COMPATIBLE-ENDPOINT/v1'
$env:PENTRAI_LLM_MODEL = 'YOUR-MODEL'
$env:PENTRAI_LLM_API_KEY = 'YOUR-LOCAL-SECRET'
.\pentrai-env\Scripts\python.exe -m control_plane.local_hexstrike_worker --serve
```

For multiple model choices, set `PENTRAI_MODEL_OPTIONS_JSON` in both API and
worker shells to a JSON array of operator-owned options. Each option has `id`,
`label`, `provider_model`, HTTPS `base_url` ending in `/v1`, `key_env`, and
integer `prompt_credit_rate` and `completion_credit_rate`. `key_env` names a
separate environment variable holding the provider key in the worker or private
gateway; the JSON catalog contains no key. For example, one option may use
`key_env: PENTRAI_FAST_KEY` and another `PENTRAI_DEEP_KEY`. Without the JSON
catalog, the single `managed` option uses the `PENTRAI_LLM_*` values above and
one credit per token. The UI lists the configured options and their rates.

Run the API in another shell with `PENTRAI_LOCAL_HEXSTRIKE_ENABLED=true` and
`PENTRAI_LOCAL_STATIC_ENABLED=false`. Start the worker first: the API requires
its fresh heartbeat before accepting source scans. After the organization owner
has recorded source assessment authority, upload a ZIP through the existing UI
and start a scan. For an owned fixture with no model
provider, the deterministic integration test exercises authenticated upload,
native MCP tool selection, finding persistence, and cleanup:

```powershell
$env:PENTRAI_DOCKER_INTEGRATION = 'true'
.\pentrai-env\Scripts\python.exe -m unittest tests.test_local_hexstrike_docker -v
```

The fixture model tests wiring and cleanup; it does not measure real LLM
analysis quality. The local worker uses a real OpenAI-compatible model client
when `PENTRAI_LOCAL_FIXTURE_MODEL` is unset. Keep the fixture switch limited to
company-owned test archives, since it expects an exact fixture file.

The API integration test `tests/test_control_plane_api.py` covers the local
upload grant, bounded ZIP upload, SHA-256 finalization, authorization-scoped
scan creation, idempotency, tenant denial, finding/report reads, read-only scan
questions, and event replay.
`tests/test_local_static_run.py` runs an authorized queued scan through static
intake, a fixture scanner, persisted findings/report, and workspace cleanup.
The same test also exercises the one-shot local worker's success and failure
paths. To run the worker on an authorized scan in the local database:

`tests/test_local_product_e2e.py` exercises the complete local API contract
with a real pinned offline scanner: authenticated ZIP upload, scan creation,
worker completion, findings, events, read-only answers, and Markdown/PDF/DOCX
exports. Run it with `./pentrai-env/Scripts/python.exe -m unittest
tests.test_local_product_e2e -v` from the repository root.

```powershell
$env:PENTRAI_OSV_SCANNER_PATH = '.tmp/osv-scanner.exe'
$env:PENTRAI_OSV_SCANNER_SHA256 = 'e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6'
$env:PENTRAI_OSV_DB_ROOT = '.tmp/osvdb'
$env:PENTRAI_OSV_DB_SHA256 = '8df9bbfa70f951082f9e00b8871a6ca628c4a8c58f3128594050033636429f50'
.\pentrai-env\Scripts\python.exe -m control_plane.local_worker --organization-id <organization-uuid> --scan-id <scan-uuid>
```

For normal local use, start a second long-lived PowerShell process with the
same database, signing key, artifact root, and scanner variables:

```powershell
.\pentrai-env\Scripts\python.exe -m control_plane.local_worker --serve
```

The local static route requires `PENTRAI_LOCAL_STATIC_ENABLED=true` in both
API and worker processes. New customer scans otherwise require a configured
native HexStrike dispatcher; the API responds with 503 while that dispatcher is
unavailable. `PENTRAI_NATIVE_RUNNER_READY=true` is only an operator enablement
setting; the API also requires a fresh heartbeat from a dispatcher that passed
cluster preflight and live containment acceptance. The dispatcher still refuses
launch without those checks. Do not set both execution modes at once.

The polling worker processes authorized static scans, cleans abandoned local
workspaces, and marks queued jobs failed after ten minutes, making a fresh retry available. Cancellation is
accepted before the worker claims a scan; in-flight cancellation is not yet
supported.

The worker runs in a separate process, verifies both scanner assets and the
source digest, marks the scan completed or failed, and removes its job
workspace. It accepts only an authorized static scan. The local worker is a
development path; production still needs durable dispatch, leases, and an
isolated worker environment.

Local object bytes live under an ignored `.tmp` directory. The local API and
worker are separate processes. The development token is opt-in and accepted
only for loopback requests; production authentication remains OIDC. This local
path is static only. Dynamic validation remains behind isolation and release
gates.

For the offline SCA integration test, provision the pinned OSV Scanner binary
and local vulnerability database under `.tmp` as documented in
`tests/test_offline_osv_adapter.py`. The test skips if those assets are absent.
