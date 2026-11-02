# PentrAI Release Assurance Programme

> **Current scope update (2026-10-30):** Live URL scanning is part of the
> approved product direction in [HEXSTRIKE_GUI_PLAN.md](HEXSTRIKE_GUI_PLAN.md).
> Replace historical blanket no-public-egress checks with tests proving that
> each runner can reach only its verified, approved target and required internal
> services. Keep denial tests for other public addresses, private networks,
> sibling jobs, the control plane, and host metadata. No live URL scanning is
> enabled until those containment tests and the other release gates pass.

## Goal

Prove that PentrAI is ready for a controlled customer pilot using only
company-owned source code, local files, and intentionally vulnerable internal
test applications. This programme produces evidence of release readiness; it
cannot honestly prove that any complex system is “perfect” or completely secure.

## Environments

| Environment | Purpose | Data rule |
|---|---|---|
| Local developer | Unit tests and safe fixtures | Synthetic or company-owned only |
| Isolated CI | Repeatable integration and adversarial tests | Disposable fixtures only |
| Internal staging | Full control/runner/artifact integration | Company-owned targets only |
| Pilot | Small opt-in customer group after approval | One organization per isolated deployment boundary |

No production customer source, credentials, or API keys are used to debug a
release. Staging accounts, storage buckets, vaults, runner pools, and model keys
are distinct from production.

## Test target corpus

Maintain a versioned internal corpus with expected outcomes:

- existing `guinea_pig/target` for the initial Flask vertical;
- safe reference applications and deliberate true negatives;
- small applications for every supported managed template/framework;
- source archives with ZIP/TAR traversal, symlinks, hard links, nested archives,
  decompression bombs, malformed manifests, and huge-file limits;
- Git fixtures containing submodules, LFS references, malicious repository URLs,
  unusual branches/tags, and credential-like content;
- malicious Docker/Compose recipes attempting privileged mode, host namespace
  sharing, Docker socket/host mounts, devices, unsafe capabilities, remote build
  contexts, and image-pull abuse;
- prompt-injection, report-rendering, log-control-character, and secret-redaction
  fixtures;
- remediation fixtures with both valid small patches and misleading/broad patch
  proposals.

Every fixture identifies expected scan state, finding states, visible redactions,
network behavior, artifact retention outcome, and cleanup result.

## Required automated checks

1. **Control-plane correctness:** authentication, organization isolation, role
   permissions, expiring scan grants, CSRF/session controls, idempotent job
   submission, cancellation, retry, and audit-event completeness.
2. **Intake safety:** archive and Git policy rejection tests; file/resource
   quotas; digest consistency; no source path can escape its tenant/job area.
3. **Runner containment:** no public or control-plane egress; no host mounts or
   Docker socket; no cross-job DNS/network/filesystem access; CPU/memory/PID/disk
   limits apply; every canceled/failed lease is reaped.
4. **Analysis quality:** deterministic scanners produce normalized provenance;
   known positive and true-negative results stay stable; no scanner detection is
   mislabeled as live validation.
5. **Model safety:** provider keys never appear in browser, runner, logs, or
   reports; source-sharing consent is enforced; prompt injection cannot alter a
   policy decision; schema and budget failures degrade safely.
6. **Evidence and reports:** evidence hashes verify; redacted views do not leak
   secrets; sealed evidence is access-controlled; PDF/DOCX/HTML generation
   cannot execute injected content; reports disclose coverage and limitations.
7. **Remediation:** generated patches stay within their file/change budget,
   execute only in a clean worktree, pass declared checks, and cannot be merged
   or deployed without an explicit approval.

## Dynamic-scan release gates

Dynamic target execution is disabled until the following checks pass repeatedly
in staging:

- isolated build service rejects hostile Docker/Compose fixtures;
- runner DNS and network tests demonstrate only private sandbox reachability;
- a target cannot reach the host, another job, cloud metadata, artifact store,
  database, model gateway, or public Internet;
- each destructive validation resets the target to its known baseline;
- a timeout, crash, host restart, and worker loss all result in eventual lease
  cleanup with no surviving secret or artifact mount;
- the guinea pig produces the intended confirmed/refuted outcomes with complete
  evidence and no false “safe” verdict.

## Pilot and deployment process

1. Generate SBOMs, sign and pin PentrAI images, review dependencies, and run
   the full test corpus in isolated CI.
2. Deploy the same image digests to internal staging; record an acceptance report
   for every release candidate.
3. Conduct an independent application-security review of PentrAI itself,
   including the control plane, runner manager, artifact service, and model
   gateway.
4. Start with an opt-in pilot, conservative quotas, static analysis enabled by
   default, dynamic analysis behind the runner gates, and active monitoring.
5. Maintain rollback, incident response, customer notification, backup/restore,
   vulnerability disclosure, and key-rotation procedures before broad release.

## Release evidence

A release candidate is eligible for a pilot only when it has a signed record of:

- source commit and immutable build/image digests;
- passing unit, integration, and corpus test results;
- containment and cleanup test evidence;
- known limitations and unsupported target types;
- model/provider and scanner-database versions;
- an approved risk acceptance for any deferred control.
