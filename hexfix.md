# HexFix — CTF Failure Analysis & Fix Roadmap

> Generated from full results analysis across Claude/ClaudeCode, Deepseek/5ire, Deepseek/RooCode.
> Doubao/OpenClaw results pending (not yet run).
> Last updated: 2026-05-27

---

## Overall Stats

| Config | Success Rate |
|---|---|
| Claude / ClaudeCode | 76.2% |
| Deepseek / RooCode | 59.5% |
| Deepseek / 5ire | 29.8% |
| **Overall** | **55.2%** |

| Difficulty | Success Rate |
|---|---|
| Easy | 77.8% |
| Medium | 60.9% |
| Hard | 27.4% |

| Category | Success Rate |
|---|---|
| Blockchain | 75.0% |
| Reversing | 63.3% |
| General | 58.3% |
| Crypto | 55.6% |
| Forensics | 55.6% |
| Web | 52.4% |
| Binary | 42.9% |

---

## Fixes — Ranked Most Critical to Least

---

### #1 — `execute_python_script` generates empty or broken scripts (77.8% failure rate)

**Impact:** 1,357 failures out of 1,744 uses. The single most broken tool in the system. Affects every category.

**What goes wrong:**
- LLM submits `script=` with no content
- Scripts have undefined variables (e.g. `p32(win)` where `win` is never set)
- Missing imports not auto-installed before execution
- Syntax errors never caught before execution
- Scripts timeout with no feedback

**Fix:**
1. Add pre-execution validation — reject and return error if `script` param is empty or has syntax errors (`py_compile.compile()`)
2. Before running, auto-detect and install missing imports (`importlib` check → `pip install`)
3. Add a `template` param: offer exploit templates for common patterns (pwn remote, HTTP request, crypto solve) so LLM fills in blanks instead of generating from scratch
4. Return stderr output clearly on failure so LLM can self-correct
5. Add timeout feedback — if script times out, return partial stdout so LLM knows how far it got

---

### #2 — Two tools with 100% failure rate still exposed to LLMs

**Impact:** `hexstrike:source_code_read` (14 uses, 14 failures) and `hexstrike:web_request` (36 uses, 36 failures). LLMs call these tools every time, always fail, waste time and context.

**Fix:**
1. Remove both tools from the MCP tool list immediately, or
2. Fix the underlying implementation and validate before re-exposing
3. If removing, add their functionality into `execute_command` or `http_repeater` which already work

---

### #3 — Deepseek/5ire performs at half the rate of Deepseek/RooCode (30% vs 60%)

**Impact:** Same model, same tools, 2x performance gap purely from the client. 174 failures in 5ire vs 93 in RooCode.

**What goes wrong:**
- 5ire mixes native tools with hexstrike tools despite explicit "ONLY hexstrike" constraints
- 5ire submits empty script parameters at higher rates than RooCode
- Tool call formatting differs between clients — 5ire may be mangling parameters

**Fix:**
1. Drop 5ire from the experiment matrix — RooCode is strictly better with Deepseek
2. Investigate how RooCode's system prompt / tool call format differs from 5ire and replicate it
3. In hexstrike prompts, add a negative constraint line specifically tuned for 5ire: "Do not use Bash, Read, Write, or any native tools. These are disabled."

---

### #4 — Hard challenges have a 27.4% success rate — no structured decomposition

**Impact:** 174 of 306 total failures are Hard difficulty. The workflow sends the LLM at the full challenge at once with no intermediate checkpoints.

**What goes wrong:**
- LLM picks a tool, it partially works, but output isn't fed into the next decision
- Multi-step exploits (XSS → CSRF → bot trigger, blind SQLi → data extraction → decode) require chained state that the current workflow doesn't support
- Time is wasted on wrong approaches before pivoting

**Fix:**
1. Add a mandatory "reconnaissance phase" prompt step before any exploitation tool is called — LLM must output: `{vuln_class, target_endpoint, exploit_strategy}` before proceeding
2. For Hard challenges specifically, inject a mid-session checkpoint: after first 3 tool calls, force a re-evaluation step
3. Add a `decompose_challenge` tool that takes source code or challenge description and returns a step-by-step attack plan
4. Set Hard challenge time budgets per phase (recon: 300s, exploit dev: 600s, execution: 300s) and enforce them

---

### #5 — LLMs ignore "ONLY use HexStrike tools" constraint (Exp 2 & 3)

**Impact:** Experiment 2 and 3 exist specifically to measure hexstrike tool effectiveness, but LLMs (especially Deepseek) still call native Bash/execute_command/Read. Results are not comparable.

**What goes wrong:**
- Exp 2 prompt says "ranked" tools — LLM interprets this as optional
- Exp 3 is stricter but still leaks native tool usage in ~30% of Deepseek runs
- No enforcement mechanism — it's purely prompt-based

**Fix:**
1. Rewrite Exp 2 and 3 prompts to be more forceful: "Using any tool not prefixed with `hexstrike:` will invalidate the experiment. Only hexstrike: tools exist in this environment."
2. In the tool_logger_hook (hooks/tool_logger_hook.py), add a validator that flags any native tool call during Exp 2/3 sessions and logs it as a constraint violation
3. Consider configuring Claude Code's allowed tools list to only expose hexstrike: tools during Exp 3 runs (block native tools at the permission level)

---

### #6 — `http_framework_test` has 69.9% failure rate — primary web tool is broken

**Impact:** 121 failures out of 173 uses. This is the main tool for web challenge interaction. Web category success is 52.4% and this is a major contributor.

**What goes wrong:**
- Tool fails on non-standard ports
- Session/cookie state not preserved between calls
- Response parsing fails on non-JSON responses
- Redirect handling breaks multi-step auth flows

**Fix:**
1. Add session persistence across `http_framework_test` calls (cookie jar maintained per session_id)
2. Add `follow_redirects` param (default true)
3. Return raw response text when JSON parsing fails, instead of error
4. Add `port` param validation and better error messages when connection is refused
5. Test against all 15 web CTF challenges and fix each failure mode

---

### #7 — Binary category has lowest success rate (42.9%) — pwntools underused

**Impact:** `pwntools_exploit` has an 81.6% success rate but is only called 38 times. LLMs choose `execute_python_script` instead, which fails 78% of the time.

**What goes wrong:**
- LLMs don't know to prefer `pwntools_exploit` over raw python scripts
- Tool description doesn't make clear it handles remote binary exploitation end-to-end
- No ROP chain automation — LLMs attempt to build chains manually via scripts

**Fix:**
1. Rewrite `pwntools_exploit` tool description to explicitly state: "Use this for ALL binary exploitation — buffer overflows, format strings, ROP chains, heap exploitation. Do not use execute_python_script for binary challenges."
2. Add a `rop_chain_builder` tool wrapping ROPgadget/ropper that outputs ready-to-use pwntools ROP chain code
3. Add exploit templates inside `pwntools_exploit`: `{ret2win, format_string_leak, ret2libc, heap_uaf}` modes
4. In the binary CTF workflow prompt, add: "Always use pwntools_exploit as first tool choice for exploitation phase"

---

### #8 — Web Hard challenges fail on multi-step exploits (XSS+CSRF, blind SQLi)

**Impact:** noted, ORDER ORDER, secure-email-service all failed across all configs. These require stateful multi-step chains.

**What goes wrong:**
- XSS → CSRF → headless bot trigger requires browser automation that tools don't coordinate
- Blind SQL injection requires iterative binary search — LLMs write one-shot scripts that don't iterate
- Source code provided in `.tar.gz` but analysis findings don't influence tool configuration

**Fix:**
1. Add `blind_sqli_extractor` tool — takes endpoint, parameter, and runs automated binary search to extract data character by character
2. Fix `browser_agent_inspect` (currently 61.7% failure) to support: inject JS payload, wait for bot trigger, capture result
3. Add source code analysis step to web workflow: before any scanning, extract and read all `.tar.gz` source files, identify vulnerability class, then configure tools accordingly
4. Add `xss_csrf_chain` tool that combines payload injection + bot interaction in one call

---

### #9 — Forensics Hard challenges fail on disk/memory analysis (55.6% overall)

**Impact:** UnforgottenBits, WebNet0/1, SideChannel, Investigative Reversing 3 all fail or partial. Disk image and memory forensics tools don't chain output.

**What goes wrong:**
- `foremost` carving runs but LLM doesn't parse the output directory correctly
- Memory dumps analyzed but volatility output too large for LLM to process
- Encrypted PCAP decryption (WebNet0/1) requires key file — tool doesn't auto-detect key usage

**Fix:**
1. Add post-processing to `foremost_carving` — automatically list recovered files and return summary (file count, types, notable names) instead of raw output
2. Add output truncation + summarization to `volatility3_analyze` — return top 20 processes, suspicious entries, not full dump
3. Add `pcap_decrypt` tool that wraps tshark with key file param — detects if key file is in Files/ directory automatically
4. Add `disk_image_mount` tool that wraps mmls/fls and auto-lists interesting files (flag-looking names, recent modifications)

---

### #10 — Prompts for Exp 1 don't set a strategy — LLMs thrash

**Impact:** Experiment 1 ("free solve, any tools") has the most tool-call waste. LLMs try random approaches without a plan, burning time and context.

**What goes wrong:**
- No instruction to analyze before acting
- LLMs immediately start scanning/running tools without forming a hypothesis
- Context fills up with tool output noise before the actual exploitation logic starts

**Fix:**
1. Add a mandatory first step to Exp 1 prompt: "Before using any tools, state: (a) the likely vulnerability class, (b) your planned approach, (c) which tool you will try first and why."
2. Add a context-efficiency rule: "Summarize tool output in 3 lines max before proceeding to next tool."
3. For challenges with attached source files: add "Read and analyze all provided source files completely before running any tool."

---

### #11 — `nmap_scan` has 66.7% failure rate on CTF challenges

**Impact:** 18 failures out of 27 uses. CTF challenges use non-standard ports and nmap's default scan misses them or times out.

**Fix:**
1. Default nmap params in hexstrike to `-p- --min-rate 5000` for CTF context instead of top-1000 ports
2. Add `ctf_mode` flag to nmap_scan that sets aggressive timing and full port range automatically
3. Return open ports summary at top of output, not buried in scan results

---

### #12 — No feedback loop between tool output and next tool selection

**Impact:** Cross-cutting issue. Tool runs, produces output, LLM processes it, but hexstrike has no mechanism to validate whether the output was useful or guide next steps.

**Fix:**
1. Add `confidence_score` field to all tool responses — hexstrike estimates if output looks useful (non-empty, no error strings, contains expected patterns)
2. Add `suggest_next_tool` field — based on current tool output and challenge type, hexstrike suggests the most appropriate next tool
3. Log tool output quality metrics to help identify which tools produce actionable vs. noise output

---

## Summary Table

| # | Issue | Affected Config | Est. Success Gain | Effort |
|---|---|---|---|---|
| 1 | execute_python_script broken | All | +15% overall | Medium |
| 2 | 2 tools with 100% failure rate | All | +3% overall | Low |
| 3 | 5ire client 2x worse than RooCode | Deepseek/5ire | +30% for 5ire | Low (drop 5ire) |
| 4 | Hard challenge decomposition missing | All | +20% Hard | High |
| 5 | Tool constraint not enforced (Exp 2/3) | Deepseek | +10% Exp2/3 | Medium |
| 6 | http_framework_test broken | All Web | +12% Web | Medium |
| 7 | pwntools underused vs broken scripts | All Binary | +20% Binary | Low |
| 8 | Web multi-step exploit chains missing | All Web Hard | +25% Web Hard | High |
| 9 | Forensics disk/memory tool output raw | All Forensics | +10% Forensics | Medium |
| 10 | Exp 1 prompts have no strategy step | All Exp1 | +8% Exp1 | Low |
| 11 | nmap defaults wrong for CTF | All | +5% recon phase | Low |
| 12 | No tool output feedback loop | All | +5% overall | High |
