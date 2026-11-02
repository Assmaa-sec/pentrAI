# Local E2E assessment of security training applications (2026-10-20)

## Scope

This run exercised PentrAI's local, authorized **static source assessment** path against source from two intentionally vulnerable web applications. It did not start the target websites or perform live probing or exploit validation. The local dynamic runner remains disabled pending its isolation and release gates. Docker Desktop's Linux engine was unavailable during this run.

The source came from the public project repositories and was kept under ignored `.tmp/` paths. Application answer keys and agent instruction files were excluded from both archives. PyGoat packaging also omitted project documentation and editor/CI metadata. Juice Shop packaging omitted screenshots, tests, documentation, infrastructure examples, and other non-application support directories. No external website was probed.

| Application | Source commit | Archive SHA-256 | Scan ID |
| --- | --- | --- | --- |
| [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat) | `19d17cc8874861142b330636d068bbde54e86b85` | `93bf6ac7f262b7c4a06365011b6fd629ef31bfbb73c106b73664ad349d37b811` | `ebe9be77-765b-4c83-bf74-1770b585955a` |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `399fba76194305a312693eee44f4df64bdf0c3ce` | `e3e73cddd369614b8b693215917372a333192046409a9e7738b389fd1999cf36` | `f40f25af-c5ca-4525-94d6-869b5bf419a0` |

The successful Juice Shop archive excluded five additional deeply nested frontend files after the first archive failed on Windows path length. Its hash above identifies that reduced archive, not the full repository snapshot.

## End-to-end checks

For each successful scan, a live HTTP client created a project, requested an upload grant, uploaded the ZIP, finalized its SHA-256, created an authorized scan, waited for the separate polling worker, and read the completed scan, findings, events, report, and read-only status answer. Markdown, PDF, and DOCX downloads returned the expected file signatures. The reports explicitly state that the application was not executed and that a completed assessment does not certify safety.

| Application | Final state | Detected findings | Report downloads | Interpretation |
| --- | --- | ---: | --- | --- |
| PyGoat | Completed | 190: 184 dependency, 6 Python source pattern | MD, PDF, DOCX succeeded | Detections are hypotheses; none was live validated. |
| Juice Shop, reduced archive | Completed | 0 | MD, PDF, DOCX succeeded | Current checks cover pinned Python `requirements.txt` and selected Python calls, not this JavaScript/TypeScript application's dependency and code risks. Zero is a coverage gap, not a safe verdict. |

The PentrAI browser landing page loaded in Chrome. The authenticated results view was not checked in the browser; the project, scan, finding, report, event, and question endpoints were checked over the live API.

## Defect exposed by the first Juice Shop archive

The first Juice Shop archive contained 1,272 application files and passed ZIP intake inspection, but scan `54253512-faa6-433d-8da0-5fe84c8d0796` failed while extracting a frontend file under the local worker workspace. The worker logged `FileNotFoundError` for a path approximately 277 characters long. This is a Windows local workspace path length defect. A second archive with five long-path files omitted (1,267 files) completed. The local worker should either support long paths safely or reject this archive before accepting the scan with a clear intake error.

## Existing gates

These runs do not establish dynamic scan readiness, JavaScript/TypeScript analysis coverage, vulnerability confirmation, production worker isolation, or pilot release assurance. The original failed Juice Shop scan and the five omitted files remain explicit limitations of this local E2E result.
