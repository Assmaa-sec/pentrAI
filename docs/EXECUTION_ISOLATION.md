# Execution isolation status

The execution manager now contains lease records, retryable cleanup hooks,
structural ACK preflight, and a per-scan Kubernetes job/policy builder. The job
builder requires a digest-pinned image, a staged read-only source volume for
source scans, and pinned public IPs plus private DNS for URL scans. It places
the native HexStrike server and model agent in separate containers with a
runV runtime class, restricted security context, no service-account token,
and narrow IP/port egress. The namespace quota permits one staged source PVC.

The local Docker runner image now builds from `runner/Dockerfile`. In a
non-root, read-only, no-external-network Docker container, `runner/smoke.py`
started the native HexStrike server, opened its MCP bridge, listed 169 native
tools, and made one harmless native MCP call. The local image now includes
Debian-packaged security tools, Python analysis packages, and ten pinned,
SHA-256-verified upstream Linux binaries (ProjectDiscovery httpx, Nuclei,
Subfinder, Katana, Trivy, Feroxbuster, Amass, Dalfox, Gau, and Terrascan),
plus Nikto's pinned source release, WPScan 4.1.0, Uro 1.0.2, and headless
ZAP 2.17.0. The last fully exercised image had 101 of 124 checked
external tool names available. Some health entries name Python modules,
umbrella packages, GUI applications, or hosted services rather than executable
commands; `ropgadget`, `sleuthkit`, `pwntools`, and `volatility3` have working
commands under different names. The `httpx` name previously resolved to the
unrelated Python HTTP client; the image now installs and verifies ProjectDiscovery
httpx. Thus the native server's `which` count neither proves nor measures complete
scanner usability. This proves the basic local
tool path, not full catalog executability or production containment.

A subsequent image build added Prowler 5.47.0, Scout Suite 5.14.0, and
kube-hunter 0.6.8 in isolated Python environments, plus SHA-256-pinned
`anew`, `waybackurls`, and `qsreplace` releases. Isolated environments are
needed because Prowler and Scout Suite require incompatible versions of
`python-dateutil`. The local smoke exercises `anew` and `qsreplace` with
local data. The image also includes RustScan, Censys CLI, Shodan CLI,
Social Analyzer, Wireshark, Autopsy, Ophcrack, zsteg, one_gadget, kube-bench,
Evil-WinRM, enum4linux-ng, ParamSpider, x8, theHarvester, Hakrawler, Jaeles,
enum4linux, DotDotPwn, Hash Identifier, radare2, Ghidra 12.2, AutoRecon,
NetExec, and XSSer. The kube-bench Debian package is
verified against the upstream release SHA-256 and includes benchmark config.
Evil-WinRM and both Python source installs have pinned versions or commits.
The measured health/PATH inventory is 101/124 after the latest image
build. The restricted offline smoke passed startup checks for AutoRecon,
NetExec, XSSer, pwninit, and bulk_extractor; SearchSploit returned a result
from a pinned local Exploit-DB corpus. Metasploit Framework 6.5.9 passed a
version check and `msfvenom` listed a built-in payload in the offline runner.
The bulk_extractor 2.2.0 build applies
a one-line Expat 2.7 compatibility fix to its pinned source. NetExec's upstream pinned release declares `certipy-ad`, while its
current dependency metadata identifies as `certipy-nxc`; the Docker build
changes that dependency name in the pinned source checkout before install.
The smoke passed a real Ghidra headless import of the runner's
harmless ELF binary.
Command presence
alone does not establish target-specific usability.

WPScan's version command alone was insufficient: an offline localhost scan
initially aborted because its database was absent. The image now downloads that
database during its build and its launcher uses the baked database without a
runtime update. In the non-root, read-only, network-disabled runner, WPScan's
default command then reached the expected result that the localhost fixture is
not a WordPress site. Its database is not yet pinned to an immutable digest, so this
is local validation rather than a production scanner-data release gate.

The remaining native health names need a per-tool dependency audit. For each
MCP tool, record the actual command or library invoked, version, required data
files, credential needs, target type, and a bounded fixture call. Some names
such as `burpsuite`, `postman`, and `maltego` refer to GUI products; `sleuthkit`
and `pwntools` are package names whose installed entry points are `fls` and
`pwn`; `ropgadget` is installed as `ROPgadget`. Other real scanner commands,
  commands may need additional data or runtime setup. The model
continues to receive all 169 native MCP schemas; the health count must not be
presented as the number of usable MCP tools.

The native tool audit in `HEXSTRIKE_NATIVE_TOOL_AUDIT.json` checks paths and
HTTP methods for all 169 declared MCP names: 164 have a corresponding Flask route,
four are MCP-local
or composite, and `burpsuite_scan` calls a missing `/api/tools/burpsuite`
route. The audit also exposed a POST/DELETE mismatch in `delete_file`; its MCP
bridge now uses the route's DELETE method. The audit exits with failure while
the Burp gap remains. A separate runtime
check compares the exact 169 MCP names against the declarations, verifies
selected binary identities, and makes a harmless MCP call. ZAP also completed
a bounded localhost scan in the network-disabled, read-only runner. Neither
the route audit nor the health inventory proves that every tool is executable:
23 health names remain unresolved, and individual tool calls require their
own dependencies, data, target fixtures, and sometimes service credentials.

The 23 unresolved health names, as of the 101/124 offline smoke, are:

| Kind | Names | Current state |
| --- | --- | --- |
| Installed capability under a different upstream name | `exploit-db`, `metasploit`, `pwntools`, `sleuthkit`, `volatility` | The pinned Exploit-DB corpus and `searchsploit`, Metasploit Framework with `msfconsole` and `msfvenom`, Python pwntools, Sleuth Kit commands including `fls`, and Volatility 3's `vol` are installed. These umbrella or older-version names are not equivalent standalone commands. |
| Desktop applications | `burpsuite`, `insomnia`, `maltego`, `postman`, `stegsolve` | No headless, licensed runner integration is verified. |
| Privileged or specialized host capabilities | `docker-bench-security`, `falco`, `kismet`, `responder` | Docker socket, kernel tracing, wireless hardware, or raw network access conflict with the current isolated runner profile. |
| Hosted API or data repository | `have-i-been-pwned`, `libc-database` | These require a service key/egress or a pinned data checkout and do not have a command with the health-list name. |
| Suites or services needing packaging and functional validation | `clair`, `hashcat-utils`, `spiderfoot` | No passing restricted-runner fixture yet. `hashcat-utils` is a suite name rather than an individual command name. |
| Unresolved command identity | `api-schema-analyzer`, `graphql-scanner`, `hashpump`, `jwt-analyzer` | No pinned matching upstream executable has been verified for these native health names. The historical HashPump upstream URL is unavailable. |

Do not add placeholder executables to make this inventory reach 124. A health
entry passes only when the actual native command or capability works within the
job's isolation and license conditions.

The Kubernetes job definition is still a deployment specification. A runner
agent entrypoint now validates a short-lived job scope, builds a bounded source
inventory, lets the model select native MCP tools, and submits evidence digests
and model-written finding drafts to an authenticated control-plane receiver.
A deterministic local model probe completed a source-to-model-to-MCP command
flow and produced an evidence-linked finding. The digest-checking ZIP stager
also extracted a one-file fixture in the rebuilt non-root, read-only,
network-disabled Docker image. A grant-bound local source broker,
digest-checking ZIP stager, and separate staging-job policy/specification now
exist. The staging job must finish and release its writable volume before the
HexStrike job mounts the extracted `source` directory read-only. A production
artifact broker deployment, managed model gateway deployment, actual collector deployment,
live cluster-adapter verification, remaining external-tool packaging, and live network containment proof
are still missing. There is no configured Kubernetes context. Dynamic
execution remains off.

A private model-gateway ASGI app now verifies a short-lived lease-bound token
before forwarding bounded OpenAI-compatible requests to a configured managed
provider. The provider key remains at the gateway, and dispatch mints a scoped
token for each job. This gateway has only been verified with a mocked upstream;
it has not been deployed or connected to a real provider. The gateway still
now records provider-returned token usage in the scan credit ledger. Production
key management and a live provider acceptance run remain open.

`execution_manager/admission.py` now stages a source-bound grant, lease, and job
scope for an authorized scan in one transaction. It does not provision the
cluster resources. `execution_manager/dispatch.py` now orders namespace and
default-deny policy, identity, source staging, staging-Pod removal, and native
HexStrike Job creation. `execution_manager/cluster_adapter.py` supplies a
namespace-bound kubectl adapter, but it has only been tested with a fake
cluster: no live ACK cluster, kubeconfig, scoped model token issuer, or
containment acceptance record is available. The dispatcher defaults to refusing
all jobs until live containment is explicitly verified. Runner Job lifetime is
bounded by the lease. Runner HTTPS clients ignore environment proxy settings;
the private broker, collector, and model gateway certificates must be trusted
by the runner image itself.

New scan grants record their signed issue second, allowing a restarted
dispatcher to reconstruct the exact token without storing token plaintext.
The source-staging Job remains observable until the dispatcher records a
lease-and-source-digest marker in the scan namespace. A retry checks that marker
and waits for the staging Pod to be removed before scheduling HexStrike.
`execution_manager/dispatch_worker.py` now claims one authorized scan or
recoverable queued lease at a time with a renewable database claim. It retries
failed launches at most three times; a restarted worker can resume after claim
expiry. Before creating HexStrike again, the cluster adapter checks for an
existing matching Job. The lease reaper marks an expired, uncompleted scan
failed after successful namespace and grant cleanup. These paths have unit and
fake-cluster coverage, but no deployed worker process or live ACK validation.
Cancellation is also a cleanup trigger before lease expiry. Dispatch heartbeats
check that the scan remains queued and its grant remains live, so cancellation
during source staging stops the launch and deletes its namespace.
The dispatcher records a short-lived readiness heartbeat after preflight; the
customer API requires that heartbeat as well as operator enablement before
accepting a native scan. A crashed worker's heartbeat expires after 30 seconds.
Staging polls renew that heartbeat while an admitted source scan is running.
This does not replace live cluster containment evidence.
`execution_manager/service.py` now polls dispatch and lease cleanup together,
including cancellation cleanup before expiry. It is tested with a fake cluster;
there is no deployment configuration or live ACK acceptance evidence yet.

To reproduce the local native-tool check from the repository root:

```powershell
docker build -f runner/Dockerfile -t pentrai/hexstrike-runner:local .
python runner/audit_catalog.py --output docs/HEXSTRIKE_NATIVE_TOOL_AUDIT.json
docker run --rm --hostname localhost --network none --read-only `
  --tmpfs /job/tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001 `
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001 `
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g `
  pentrai/hexstrike-runner:local python /opt/pentrai/runner_smoke.py

# Replace the final script path with /opt/pentrai/zap_smoke.py for the fixed
# localhost ZAP scan. Use --hostname localhost and a 512m /job/tmp tmpfs.

# Replace the final script path with /opt/pentrai/assessment_smoke.py to
# exercise source inventory, a fixture model-selected command, and the MCP loop.
```

## Required before wiring a runner

1. Provision separate private control and execution VPCs and an ACK Pro
   execution cluster. Inspect the actual region, cluster version, bare-metal
   node SKU, Alibaba Cloud Linux image, and runV RuntimeClass.
2. Use Terway shared ENI mode with NetworkPolicy enabled. Alibaba's current
   documentation says exclusive ENI and DataPath v2 are incompatible with the
   relevant runV / NetworkPolicy combination.
3. Apply the namespace, restricted Pod Security, quota, limit, and default-deny
   objects before admitting any workload. Add only reviewed DNS, target/harness,
   collector, artifact-broker, registry, and mirror rules.
4. Verify the namespace-bound cluster adapter against ACK and deploy an artifact-token broker. The
   namespace delete and token revoke operations must be idempotent because the
   lease reaper retries after a crash or failed commit.
5. In staging, prove no public, control-plane, metadata, RDS, host, or sibling
   namespace reachability, and prove cleanup after cancellation, timeout,
   worker loss, and restart. Record the evidence under the release candidate.

Structural preflight values supplied by an adapter are not a live containment
test. Keep the release gate closed until the staging checks in
`RELEASE_ASSURANCE.md` pass.

Current vendor references:

- [Alibaba Cloud sandboxed container limitations](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/overview-10/)
- [Alibaba Cloud Terway NetworkPolicy modes](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/work-with-terway)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes default-deny NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
