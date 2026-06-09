# HexStrike AI — Agent Knowledge Base

> This file is maintained by Claude Code and updated as new information is discovered.
> Last updated: 2026-05-27

---

## Project Overview

**HexStrike AI v6.0** is an AI-powered penetration testing and CTF automation platform built on the Model Context Protocol (MCP) architecture. It integrates AI agents with 150+ security tools and exposes 170 MCP tools to AI clients.

**Project path:** `/home/kali/hexstrike-ai-1/`
**Git user:** Assmaa Zeghaider

---

## Architecture

### Two-Script Core
| File | Role | Size |
|------|------|------|
| `hexstrike_server.py` | Flask REST API backend (port 8888), tool execution, decision engine, logging | ~17,600 lines |
| `hexstrike_mcp.py` | FastMCP interface exposing 170 tools to AI agents via stdio | ~6,000 lines |

### Communication Flow
```
AI Client (OpenClaw / Claude Code / RooCode / etc.)
    ↓  MCP (stdio)
hexstrike_mcp.py  ←→  hexstrike_server.py (Flask, port 8888)
                            ↓
                    150+ External Security Tools
```

---

## Configuration Files

### `hexstrike_config.json` — Runtime session state
Persists across sessions; tracks LLM identity, active CTF metadata, session timer.
```json
{
  "llm_model": "sonnet-4.6",
  "client": "claude",
  "session_id": "<uuid>",
  "ctf_name": "<challenge>",
  "ctf_difficulty": "Easy|Medium|Hard",
  "ctf_type": "Web|Crypto|Pwn|Forensics|Rev|General|Blockchain",
  "timer_start": "<iso8601>",
  "timer_end": "<iso8601>",
  "elapsed_seconds": 0
}
```

### `.mcp.json` — MCP server definition (for Claude Code)
```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/kali/hexstrike-ai-1/hexstrike_mcp.py"],
      "env": {}
    }
  }
}
```

### `.claude/settings.local.json` — Claude Code permissions
200+ whitelisted bash command patterns and MCP tool permissions.

### `hexstrike-ai-mcp.json` — Template for remote server config
Used when connecting to a remote hexstrike server (non-local).

---

## Supported AI Clients

| Client | Integration Method |
|--------|-------------------|
| **OpenClaw** | MCP stdio — configured in `~/.openclaw/openclaw.json` |
| **Claude Code** | MCP stdio — configured in `.mcp.json` |
| **Claude Desktop** | MCP stdio |
| **VS Code Copilot** | MCP stdio |
| **Roo Code** | MCP stdio + LLM API proxy (`hooks/llm_proxy.py`) |
| **Cursor** | MCP stdio + LLM API proxy |
| **5ire** | MCP stdio + LLM API proxy |
| **Trae** | MCP stdio + LLM API proxy |

---

## OpenClaw Integration

### Installation
- **Version:** 2026.5.22
- **Installed via:** npm (tarball downloaded directly due to network timeouts)
- **Binary location:** `/home/kali/.npm-global/bin/openclaw`
- **PATH:** Added `$HOME/.npm-global/bin` to `~/.zshrc`
- **npm version used:** 11.15.0 (at `/home/kali/.npm-global/bin/npm`)

### Configuration
- **Config file:** `~/.openclaw/openclaw.json`
- **hexstrike-ai MCP server entry:**
```json
{
  "mcp": {
    "servers": {
      "hexstrike-ai": {
        "command": "python3",
        "args": ["/home/kali/hexstrike-ai-1/hexstrike_mcp.py"],
        "cwd": "/home/kali/hexstrike-ai-1",
        "env": {}
      }
    }
  }
}
```
- **Validation:** `openclaw config validate` → passes

### OpenClaw Setup Notes
- OpenClaw uses JSON5 format for its config
- Config can be edited via `openclaw config patch --stdin` (takes JSON)
- Gateway must be restarted after config changes: `openclaw` or gateway process
- OpenClaw is a self-hosted AI agent that supports messaging platforms (Slack, Discord, Telegram, etc.) as UI
- MCP tools from hexstrike are available to any OpenClaw agent after gateway restart

---

## MCP Tools (170 Total)

### Session Management
`set_llm_identity`, `get_llm_identity`, `set_ctf_metadata`, `get_ctf_session_info`, `start_timer`, `stop_timer`

### Network Reconnaissance (20+)
`nmap_scan`, `nmap_advanced_scan`, `rustscan_fast_scan`, `masscan_high_speed`, `autorecon_comprehensive`, `autorecon_scan`, `amass_scan`, `subfinder_scan`, `fierce_scan`, `dnsenum_scan`, `nbtscan_netbios`, `arp_scan_discovery`, `enum4linux_scan`, `enum4linux_ng_advanced`, `rpcclient_enumeration`, `smbmap_scan`, `netexec_scan`, `responder_credential_harvest`, `httpx_probe`

### Web Application Testing (35+)
`gobuster_scan`, `feroxbuster_scan`, `dirsearch_scan`, `dirb_scan`, `ffuf_scan`, `nikto_scan`, `nuclei_scan`, `katana_crawl`, `hakrawler_crawl`, `gau_discovery`, `waybackurls_discovery`, `sqlmap_scan`, `wpscan_analyze`, `arjun_scan`, `dalfox_xss_scan`, `wafw00f_scan`, `zap_scan`, `wfuzz_scan`, `api_fuzzer`, `graphql_scanner`, `jwt_analyzer`, `burpsuite_scan`, `http_repeater`, `http_intruder`, `browser_agent_inspect`

### Binary Analysis / Reverse Engineering (20+)
`gdb_analyze`, `gdb_peda_debug`, `radare2_analyze`, `ghidra_analysis`, `binwalk_analyze`, `checksec_analyze`, `strings_extract`, `objdump_analyze`, `ropgadget_search`, `ropper_gadget_search`, `one_gadget_search`, `libc_database_lookup`, `pwninit_setup`, `pwntools_exploit`, `angr_symbolic_execution`, `volatility_analyze`, `volatility3_analyze`, `foremost_carving`, `steghide_analysis`

### Password / Auth
`hashcat_crack`, `john_crack`, `hydra_attack`

### Cloud / Container Security
`prowler_scan`, `scout_suite_assessment`, `pacu_exploitation`, `kube_hunter_scan`, `docker_bench_security_scan`, `trivy_scan`, `checkov_iac_scan`, `terrascan_iac_scan`

### Exploit & Vulnerability Research
`generate_exploit_from_cve`, `discover_attack_chains`, `research_zero_day_opportunities`, `hashpump_attack`, `dotdotpwn_scan`, `monitor_cve_feeds`, `generate_payload`, `msfvenom_generate`, `advanced_payload_generation`

### AI-Powered Intelligence
`analyze_target_intelligence`, `select_optimal_tools_ai`, `intelligent_smart_scan`, `detect_technologies_ai`, `optimize_tool_parameters_ai`, `create_attack_chain_ai`, `ai_generate_payload`, `ai_generate_attack_suite`, `ai_vulnerability_assessment`, `ai_reconnaissance_workflow`, `threat_hunting_assistant`, `vulnerability_intelligence_dashboard`

### Bug Bounty Workflows
`bugbounty_reconnaissance_workflow`, `bugbounty_vulnerability_hunting`, `bugbounty_business_logic_testing`, `bugbounty_osint_gathering`, `bugbounty_authentication_bypass_testing`, `bugbounty_file_upload_testing`, `bugbounty_comprehensive_assessment`

### Utility / System
`execute_command`, `execute_python_script`, `install_python_package`, `create_file`, `modify_file`, `delete_file`, `list_files`, `server_health`, `get_telemetry`, `get_process_status`, `get_process_dashboard`, `list_active_processes`, `pause_process`, `resume_process`, `terminate_process`, `display_system_metrics`, `create_scan_summary`, `create_vulnerability_report`, `format_tool_output_visual`, `clear_cache`

### CTF Capability Tools (hexfix)
Runtime-verified: `disk_image_mount`, `pcap_decrypt`, `rop_chain_builder`, `xss_csrf_chain`.
New (hexfix §3 — built, pending live Kali verification): `evtx_parser`, `rsa_factor`, `compression_oracle`, `sqli_order_oracle`, `timing_oracle`, `smb_ipp_exploit`, `blockchain_exploit`.

---

## Logging System

### Hooks
| Hook | Purpose | Used With |
|------|---------|-----------|
| `hooks/tool_logger_hook.py` | PreToolUse hook for Claude Code | Claude Code |
| `hooks/llm_proxy.py` | OpenAI-compatible LLM API proxy; intercepts calls from RooCode, Cursor, 5ire, Trae | Non-Claude clients |

### Log Files
- `tool_logger.log` — Structured session log (primary)
- `hexstrike.log` — Server activity log

### Session Log Structure
```
[SESSION: <uuid>]
  [SETUP] LLM identity, client, CTF metadata
  [CONTEXT] Challenge info
  [TIMER:START]
  ... tool activity entries ...
  [TIMER:END] elapsed_seconds
```

---

## CTF Automation Engine

### Categories Supported
`web`, `crypto`, `pwn`, `forensics`, `rev`, `general_skills`, `blockchain`

### Core Components
- `CTFChallenge` — dataclass for challenge metadata
- `CTFWorkflowManager` — generates per-category solving plans
- `CTFToolManager` — maps 55+ tools to 17 tool groups
- `CTFChallengeAutomator` — executes workflows, extracts flags
- `CTFTeamCoordinator` — optimizes multi-agent task allocation

---

## Experiment Framework

- **264 total exercises** (88 challenges × 3 variants × multiple configs)
- **Challenge categories:** Web, Crypto, Pwn, Forensics, Reversing, General Skills, Blockchain
- **3 experiment variants per challenge:**
  - Exp 1: Free solve (any tools)
  - Exp 2: HexStrike tools only, ranked
  - Exp 3: HexStrike tools only, strict adherence
- **Configs tested:** Claude+ClaudeCode, DeepSeek+5ire, DeepSeek+RooCode, DeepSeek+Trae
- **Results stored in:** `results/` directory (do NOT write to these files)
- **Prompt generation:** `prompt_generator.py` — a standalone GUI (no server/import needed) that
  builds each run's Prompt 2 (STEP 1 setup + STEP 2 task with the strategy preamble + per-category
  tool nudges). Mirrors the `/api/ctf/get-experiment-prompt` endpoint. The `get_experiment_prompt`
  MCP tool was removed — the human generates prompts with this app, the model does not.

---

## Key Constraints / Conventions

- **Do NOT write to `results/` files** — experiment result files are manually annotated
- Run scripts/commands directly without confirmation prompts
- Filter output aggressively in scripts to avoid large dumps
- Python virtual environment: `hexstrike_env/`

---

## Starting hexstrike Server

The hexstrike Flask server must be running on port 8888 for the MCP client to function:
```bash
cd /home/kali/hexstrike-ai-1
source hexstrike_env/bin/activate
python3 hexstrike_server.py
```

The MCP client (`hexstrike_mcp.py`) connects to `http://localhost:8888` by default.
For remote servers: `python3 hexstrike_mcp.py --server http://<IP>:8888`
