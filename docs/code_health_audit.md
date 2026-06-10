# HexStrike-AI — Code-Health & Maintainability Audit

**Scope:** the repository as shipped — `hexstrike_server.py`, `hexstrike_mcp.py`, `requirements.txt`, `hexstrike-ai-mcp.json`, `README.md`.
**Method:** read-only. Metrics sweep (grep/wc), then deep-reads of the densest/riskiest areas; repetitive patterns sampled (2–3 cases + count N).
**Lens:** maintainability / technical debt — not feature completeness, not a pentest.
**Date:** 2026-06-10

A deliberately short, high-impact list. Web-app-checklist items that don't apply to a local single-operator
offensive tool (CORS, rate-limiting) and self-acknowledged non-issues are excluded; what remains is what an
engineer picking this up would actually need to fix.

---

## Executive summary — the findings that matter

| # | Severity | Where | One-line |
|---|----------|-------|----------|
| F1 | **High** | `hexstrike_server.py` (17,289 lines, 54 classes, 156 routes) | One monolithic module holds the whole system — decision engine, managers, exploit gen, every Flask route — with routing fused to logic. |
| F2 | **High** | `:10378`, `:10533`, `:10581` (+~150 more) | The same parse→`params.get`→f-string-command→`execute_command`→`jsonify`→`except` skeleton is copy-pasted across 156 routes, mirrored in ~150 MCP wrappers. |
| F3 | **High** | `:584-680`, command templates throughout | Hardcoded values with no rationale — magic scoring/threshold numbers and fixed command chains/flags — plus baked-in Kali paths (43× `/usr/`, 35× `/tmp/`). |
| F4 | **High** | `hexstrike_mcp.py:2676` & `:3392` | `httpx_probe` is registered twice as `@mcp.tool()`; the second silently shadows the first, so a documented tool is dead. |
| F5 | **High** | `hexstrike_server.py:17289` | `app.run(host="0.0.0.0", …)` ignores the `API_HOST` loopback default (`:99`, read but never used); trust boundary undocumented and unenforced. |
| F6 | **Medium** | `:10545` vs `:8659`; `:10382`(`url`) vs `:10434`(`target`) | No single contract across the HTTP↔MCP boundary — two response shapes coexist and the same concept is named `url`/`target`/`targets`. |
| F7 | **High** | repo-wide | No tests, CI, or lint/type config are present in the repo — nothing here is verifiable or replicable by a new maintainer. |

---

## Metrics snapshot

| Metric | Value | How obtained |
|--------|-------|--------------|
| Lines — server / mcp | **17,289** (751 KB) / **5,470** (223 KB) | `wc -l` |
| Classes / `def`s — server | 54 / 498 | `grep -E '^class '` / `'^\s*def '` |
| HTTP endpoints (`@app.route`) | **156** | `grep -c` |
| MCP tools (`@mcp.tool()`) | **151** (≈150 unique — `httpx_probe` dup) | `grep -c` |
| Bare `except:` / blanket `except Exception` | **18** / **255** | `grep -E` |
| `shell=True` | 2 (both command executors) | `grep` |
| Hardcoded `/tmp/` / `/usr/` | 35 / 43 | `grep` |
| `localhost` / `127.0.0.1` / `0.0.0.0` | 3 / 11 / 3 | `grep` |
| Return type hints | server ~37% (185/498), mcp ~98% | `grep -c -- '->'` |
| Docstrings (triple-quote) | 548 server / 321 mcp — genuinely good | `grep -c '"""'` |
| Tests / lint / CI config | **none found** | `find` (no `*test*`, `pytest.ini`, `pyproject.toml`, `.flake8`, `mypy.ini`, CI) |
| Dependencies | 13, **all version-bounded**; `bcrypt==4.0.1` pinned with a rationale | `cat requirements.txt` |

> **Honesty note:** the classic red-flag greps are **false positives here** — `os.system`/`exec(` matches live inside intentionally-generated exploit/webshell *script templates* (`:8207`, `:2725`), the 9 "TODO/HACK" hits are a `HACKER_RED` colour constant, and the 128 `print(` hits are almost all inside generated script strings. Effectively **zero** real markers/debug prints. Reported so the numbers aren't misread as findings.

---

## Findings

### F1 — One monolithic module · Structure · High · effort L
`hexstrike_server.py` is 17,289 lines / 751 KB with 54 classes — decision engine, error handler, CTF and bug-bounty managers, exploit generators, process pool, browser agent, **and** all 156 Flask routes in one file. Routing is interleaved with business logic (`:9023-17230`): each tool's command-building lives inside its route function, so nothing is reusable between the HTTP and MCP layers or testable without Flask. Several methods run 200+ lines (`_initialize_recovery_strategies` 211, `__init__` 206, `analyze_cve_exploitability` 238).
**Fix:** split into a package (`core/`, `tools/`, `intel/`, `exploits/`, `managers/`) and extract a `run_<tool>(params)->dict` service layer so routes become thin wrappers.

### F2 — 156× copy-pasted endpoint boilerplate · Duplication · High · effort L
Every route repeats the identical skeleton — `params=request.json` → `params.get(...)` → `if not target: return {"error":…},400` → `command=f"tool {target} …"` → `execute_command` → `jsonify` → `except Exception …500` — across all 156 handlers (`:10378` gobuster, `:10533` trivy, `:10581` scout-suite, …), and the MCP side mirrors it in ~150 wrappers (`hexstrike_mcp.py:307`, `:350`, …). That is ~150 places to change any cross-cutting concern (validation, logging shape, error envelope, command quoting), and drift is already visible — some handlers catch `traceback`, most don't.
**Fix:** a declarative tool spec (name, required params, arg-template) + one generic handler/decorator; generate the MCP wrappers from the same spec. Highest-leverage change in this list — it also turns "harden command-building" from a 150-site edit into a one-site edit.

### F3 — Hardcoded values & command chains with no provenance · Hardcoding · High · effort M–L
Behaviour is governed by mystery constants with no comment or rationale: tool-effectiveness scores (`0.8/0.9/0.95…`, `:584-680`), resource thresholds (`:5225`), timeouts — none of which can be tuned or even understood without reverse-engineering the author's intent. Command templates are hardcoded the same way: fixed tools, flags and argument chains baked into f-strings with no explanation of *why* those flags, so changing how a tool is invoked means editing code in scattered places. Absolute Kali paths are baked in too (`/usr/share/wordlists/...`, `/tmp/...`; 43× `/usr/`, 35× `/tmp/`), so it only runs on Kali. This is one of the most felt problems day-to-day: the system's decisions are opaque because the numbers and command lines behind them carry no reasoning.
**Fix:** externalize the magic tables to a data file (YAML/JSON) **with provenance comments**; lift command templates into the declarative spec from F2; put paths behind a config map with env overrides.

### F4 — `httpx_probe` registered twice · Interface / dead code · High · effort S
`httpx_probe` is defined twice, both as `@mcp.tool()`, with conflicting signatures (`hexstrike_mcp.py:2676` vs `:3392`). The second registration silently overwrites the first, so the documented first tool is unreachable — a latent bug masquerading as live code.
**Fix:** delete/rename one; add a duplicate-name guard (a registration-time check or a lint rule).

### F5 — Binds all interfaces, ignores its own host config · Config / trust boundary · High · effort S
`app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)` (`:17289`) overrides `API_HOST` (`HEXSTRIKE_HOST`, default `127.0.0.1`, `:99`), which is read but never used — the one safety knob is dead and the server always binds every interface. More broadly the trust boundary is undocumented and unenforced: by design the server runs operator-authorized commands via `shell=True`, which is acceptable for a local single-operator tool, but that intent should be *stated* and the default should be loopback, not all-interfaces.
**Fix:** use `host=API_HOST`, default to loopback, and document the trust model in one README paragraph.

### F6 — No single contract across HTTP↔MCP · Consistency · Medium · effort M
Two response shapes coexist: validation errors return `{"error": msg}` (no `success` key); the success path returns `{"success", "stdout", "return_code", …}`. The MCP wrappers test `result.get("success")`, which is absent on validation errors and only works by accident because `safe_post` re-wraps non-2xx responses (`hexstrike_mcp.py:241`). The same concept is named inconsistently too — `target` for nmap, `url` for gobuster, `targets` for httpx — so the AI client must memorize per-tool names. (Same class of mismatch we hit live: the `evtx_parser` wrapper exposes `evtx_file/output_format` while the endpoint reads `file/grep`.)
**Fix:** one envelope `{success, data, error}` everywhere; one canonical param name with documented aliases.

### F7 — Nothing is verifiable or replicable · Testing · High · effort M
There are no tests, no CI, and no lint/type/format config anywhere in the repository. **Note:** this is a statement about what is present and reproducible *to us*, not a claim that the tool was never tested — the upstream author may well have tested on their end, but there is no harness, fixture, or CI in the repo that anyone else can run to verify behaviour or catch a regression. For a 23k-line codebase this bites hardest on F2: the deduplication that would help most is exactly the change you can't make safely without a net.
**Fix:** add a `pytest` smoke harness (the command executor, the error handler, a few routes via Flask's test client) plus `ruff` + `mypy` in CI — enough that future changes become verifiable.

---

## What's already sound

- **No hardcoded secrets.** Grep for keys/tokens/passwords found only request-param reads (`api_key` `:14325`) and exploit-payload strings — nothing embedded.
- **Dependencies are responsibly version-bounded** (13 deps, `flask>=2.3,<4.0`, etc.; `bcrypt==4.0.1` exact-pinned with a "why" comment).
- **Strong docstring & MCP-tool documentation** (548 server / 321 mcp blocks); the AI-facing tool descriptions are clear.
- **A real error-handling framework already exists** — `ErrorType`/`RecoveryAction`/`IntelligentErrorHandler` (`:1558-2200`) with retry/backoff and alternative-tool logic. The bones for robust handling are present; the problem is the 255 ad-hoc catches that *bypass* it.
- **Clean import hygiene** — no commented-out code, no TODO graveyard, no stray debug prints (the grep hits are the false positives noted above).
- **The MCP client centralizes HTTP** — `safe_get`/`safe_post` (`hexstrike_mcp.py:192-243`) give one place for retry/error normalization; the right instinct, just not mirrored by a server-side service layer.

---

## Prioritized remediation roadmap

| Rank | Item | Finding | Effort | Unblocks |
|------|------|---------|--------|----------|
| 1 | Bind `API_HOST` (loopback default); document the trust boundary. | F5 | S | Removes the most dangerous default; precondition for any networked use. |
| 2 | Minimal `pytest` smoke harness + `ruff`/`mypy` + CI. | F7 | M | Makes every later refactor verifiable — do this **before** #4. |
| 3 | Fix the duplicate `httpx_probe` registration; scan for other shadowed tools. | F4 | S | Restores a silently-dead tool; quick win. |
| 4 | Declarative tool spec + one generic handler + `run_<tool>()` service layer. | F2 | L | Collapses ~150 boilerplate sites into one; the hub for validation/quoting/error-shape. |
| 5 | Externalize magic tables, command templates and paths to config, with provenance. | F3 | M–L | Behaviour becomes legible and tunable off-Kali; pairs with #4. |
| 6 | Standardize the response envelope and canonical param names. | F6 | M | One predictable contract across HTTP↔MCP. |
| 7 | Split the 17k-line module into a package. | F1 | L | Navigability and reviewable diffs. |

---

*Audit is self-contained and based solely on the code in the original repository `https://github.com/0x4m4/hexstrike-ai`.*
