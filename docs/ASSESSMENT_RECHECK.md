# Assessment verification — 2026-11-15

The local native source-assessment diagnostics were re-reviewed and tested on
Windows with Python 3.12 and Node.js 24.22.0. No security tool or customer
application was executed. No live provider credentials or requests were used.

## Bugs reproduced and fixed

- Partial writes to raw subprocess pipes could truncate the source archive or
  model response. The worker now sends every byte or fails explicitly.
- A provider response arriving after cancellation and cleanup could skip usage
  metering. Completed provider work is now recorded using the ledger's existing
  late-usage handling; a cancelled scan still cannot accept the result.
- Lifetime warning deduplication could hide a later service outage. Health
  observations now record recovery and warn again for a subsequent outage,
  without claiming that the assessment has completed.
- Already-expired jobs are rejected before a process is launched; the deadline
  timer no longer rounds a sub-second remaining lifetime up to a full second.

## Results

| Check | Result |
| --- | --- |
| Full unittest discovery | 167 tests: 161 passed, six skipped |
| Five shuffled runs of the 25 assessment-focused tests | 125 passed; seeds 20261115–20261119 |
| Real subprocess protocol exchanges within those five runs | 100 passed |
| Dashboard TypeScript check and Vite production build | Passed |
| Python compilation | Passed |
| Whitespace checks for changed implementation and new tests | Passed |

Real pipe trials varied source sizes from one byte through 2 MB, one-byte versus
1 KB output fragments, one versus three model turns, and Unicode responses.
They verified source digests, complete framed messages, model-turn counts, process
exit, and closed pipes. Other tests covered provider rejection/quota errors,
missing source, authorization expiry, stalled model cancellation/deadlines,
invalid results, credit release, cleanup retry, repeat outages, event replay,
fresh event polling, and tenant/state guards.

The subprocess peer is test-owned Python code, not the Linux Docker runner.
Its success proves pipe behavior, not scanner installation or containment.

## Remaining environment limits

- Docker is not installed in this Windows session. The three opt-in Docker
  integration tests and three scanner-asset-dependent checks were skipped.
- Real provider authentication, quota, billing availability, and tool-calling
  compatibility require a configured provider and an authorized assessment.
- The existing shared Windows `pentrai-env` reports conflicts between legacy
  mitmproxy/pyOpenSSL and the product's cryptography/h11 dependencies. No Python
  packages were changed during this recheck. Use the separate product venv in
  `sartup.txt`; this report does not claim the shared legacy environment is healthy.
- Repository-wide `git diff --check` still reports trailing whitespace in the
  pre-existing `requirements.txt` changes. That file was left untouched.
- These results cover the tested source-assessment path; they do not certify
  production deployment, the legacy CLI pipeline, or every external failure.

## Linux activation and final validation

Follow `sartup.txt` for the separate Linux venv and shared configuration. Rebuild
the image after syncing the source changes, then run:

```bash
docker build -f runner/Dockerfile -t pentrai/hexstrike-runner:local .
python -m control_plane.local_hexstrike_worker --check
python -m unittest discover -s tests -q
PENTRAI_DOCKER_INTEGRATION=true python -m unittest discover -s tests -p test_local_hexstrike_docker.py -v
```

Restart both API and worker. Run one company-owned source ZIP assessment with
the configured provider. Observe the Activity feed and worker output through
report creation and cleanup before submitting more work.
