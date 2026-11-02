"""Local-only native HexStrike MCP handshake, with no external network."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.request import urlopen

from pentrai_pipeline.agents.hexstrike_mcp import HexStrikeMCP
from runner.audit_catalog import audit_catalog


async def main() -> None:
    bridge = Path("/job/tmp/pentrai_mcp.py")
    shutil.copyfile("/opt/pentrai/pentrai_mcp.py", bridge)
    server = subprocess.Popen(
        [sys.executable, "/opt/pentrai/pentrai_server.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            if server.poll() is not None:
                raise RuntimeError("HexStrike server exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", 8888), timeout=1):
                    break
            except OSError:
                await asyncio.sleep(0.5)
        else:
            raise RuntimeError("HexStrike server did not become ready")
        async with HexStrikeMCP(bridge, "http://127.0.0.1:8888") as mcp:
            tools = await mcp.list_tools()
            response = await mcp.call_tool("get_llm_identity", {})
            fixture = Path("/tmp/pentrai_files/native-delete-fixture.txt")
            created = await mcp.call_tool("create_file", {
                "filename": fixture.name, "content": "local tool audit fixture"})
            if created.get("isError") or not fixture.exists():
                raise RuntimeError("native create_file fixture failed")
            deleted = await mcp.call_tool("delete_file", {"filename": fixture.name})
            if deleted.get("isError") or fixture.exists():
                raise RuntimeError("native delete_file route failed")
        with urlopen("http://127.0.0.1:8888/health", timeout=5) as health_response:
            health = json.load(health_response)
        audited = audit_catalog(Path("/opt/pentrai"))
        declared_names = {tool["name"] for tool in audited["tools"]}
        runtime_names = {tool["name"] for tool in tools}
        if runtime_names != declared_names or len(tools) != len(runtime_names):
            raise RuntimeError(
                "MCP runtime catalog differs from native declarations: "
                f"missing={sorted(declared_names - runtime_names)}, "
                f"unexpected={sorted(runtime_names - declared_names)}"
            )
        if response.get("isError"):
            raise RuntimeError("native HexStrike tool call failed")
        for command, marker in (
            (["httpx", "-version"], "projectdiscovery.io"),
            (["nikto", "-Version"], "Nikto 2.6.1"),
            (["wpscan", "--version"], "Current Version: 4.1.0"),
            (["zaproxy", "-version"], "2.17.0"),
        ):
            check = subprocess.run(command, capture_output=True, text=True,
                                   timeout=20, check=True)
            if marker not in check.stdout + check.stderr:
                raise RuntimeError(f"{command[0]} resolves to the wrong program")
        for command in ("prowler", "scout", "kube-hunter", "anew", "waybackurls",
                        "qsreplace", "kube-bench", "evil-winrm", "enum4linux-ng",
                        "paramspider", "x8", "theHarvester", "theharvester",
                        "hakrawler", "ropgadget", "volatility3", "jaeles",
                        "enum4linux", "dotdotpwn", "hash-identifier", "radare2",
                        "ghidra", "analyzeHeadless", "autorecon", "nxc", "xsser",
                        "pwninit", "bulk_extractor", "searchsploit",
                        "msfconsole", "msfvenom"):
            if shutil.which(command) is None:
                raise RuntimeError(f"packaged scanner command is missing: {command}")
        for command in (["kube-bench", "version"], ["evil-winrm", "--help"],
                        ["enum4linux-ng", "-h"], ["paramspider", "--help"],
                        ["x8", "--version"], ["theHarvester", "-h"],
                        ["ropgadget", "--help"], ["volatility3", "--help"],
                        ["jaeles", "--help"], ["radare2", "-v"],
                        ["autorecon", "--help"], ["nxc", "--help"],
                        ["xsser", "--version"], ["pwninit", "--help"],
                        ["bulk_extractor", "-V"]):
            subprocess.run(command, capture_output=True, text=True, timeout=20,
                           check=True)
        framework = subprocess.run(["msfconsole", "--version"],
                                   capture_output=True, text=True, timeout=20,
                                   check=True)
        if "Framework Version: 6.5.9" not in framework.stdout + framework.stderr:
            raise RuntimeError("Metasploit Framework version mismatch")
        payloads = subprocess.run(["msfvenom", "-l", "payloads"],
                                  capture_output=True, text=True, timeout=30,
                                  check=True)
        if "linux/x64/exec" not in payloads.stdout:
            raise RuntimeError("msfvenom did not list its built-in payloads")
        if not Path("/etc/kube-bench/cfg/config.yaml").is_file():
            raise RuntimeError("kube-bench benchmark configuration is missing")
        exploitdb = subprocess.run(["searchsploit", "--cve", "2021-44228"],
                                   capture_output=True, text=True, timeout=20,
                                   check=True)
        if "Log4j" not in exploitdb.stdout:
            raise RuntimeError("SearchSploit did not query the offline Exploit-DB corpus")
        for command, marker in ((["enum4linux", "-h"], "enum4linux v"),
                                (["dotdotpwn"], "DotDotPwn")):
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            if marker not in result.stdout + result.stderr:
                raise RuntimeError(f"{command[0]} failed to load its upstream script")
        identified = subprocess.run(["hash-identifier"],
                                    input="098f6bcd4621d373cade4e832627b4f6\n\n",
                                    capture_output=True, text=True, timeout=20)
        if "MD5" not in identified.stdout:
            raise RuntimeError("hash-identifier did not recognize the local fixture")
        Path("/job/tmp/ghidra-smoke").mkdir(exist_ok=True)
        ghidra = subprocess.run(
            ["analyzeHeadless", "/job/tmp/ghidra-smoke", "native-smoke",
             "-import", "/usr/bin/true", "-deleteProject", "-noanalysis"],
            capture_output=True, text=True, timeout=90,
        )
        if ghidra.returncode:
            raise RuntimeError("Ghidra import failed: " +
                               (ghidra.stdout + ghidra.stderr)[-1800:])
        if "Import succeeded" not in ghidra.stdout + ghidra.stderr:
            raise RuntimeError("Ghidra did not import the local ELF fixture")
        with tempfile.TemporaryDirectory(dir="/job/tmp") as directory:
            output = Path(directory) / "unique.txt"
            subprocess.run(["anew", str(output)], input="one\none\ntwo\n",
                           text=True, capture_output=True, timeout=10, check=True)
            if output.read_text(encoding="utf-8").splitlines() != ["one", "two"]:
                raise RuntimeError("anew did not deduplicate the local fixture")
        replaced = subprocess.run(["qsreplace", "audit"],
                                  input="https://localhost/?a=1\n",
                                  text=True, capture_output=True, timeout=10, check=True)
        if replaced.stdout.strip() != "https://localhost/?a=audit":
            raise RuntimeError("qsreplace did not rewrite the local URL fixture")
        spiderfoot = subprocess.run(["spiderfoot", "-M"], capture_output=True,
                                    text=True, timeout=30, check=True)
        if "sfp_accounts" not in spiderfoot.stdout:
            raise RuntimeError("SpiderFoot failed to load its native module catalog")
        hashcat_utils = subprocess.run(["hashcat-utils", "len", "3", "3"],
                                       input="abc\nxy\n", capture_output=True,
                                       text=True, timeout=10, check=True)
        if hashcat_utils.stdout != "abc\n":
            raise RuntimeError("hashcat-utils failed its local length-filter fixture")
        libc = subprocess.run(
            ["libc-database", "identify", "/lib/x86_64-linux-gnu/libc.so.6"],
            capture_output=True, text=True, timeout=20, check=True)
        if not libc.stdout.strip().startswith("local-"):
            raise RuntimeError("libc-database failed to identify its offline fixture")
        for alias in ("metasploit", "exploit-db", "pwntools", "sleuthkit",
                      "volatility"):
            if shutil.which(alias) is None:
                raise RuntimeError(f"upstream suite alias is missing: {alias}")
        aliases = (
            (["metasploit", "--version"], "Framework Version: 6.5.9"),
            (["exploit-db", "--cve", "2021-44228"], "Log4j"),
            (["pwntools", "--help"], "usage:"),
            (["sleuthkit", "fls", "-V"], "Sleuth Kit"),
            (["volatility", "--help"], "Volatility"),
        )
        for command, marker in aliases:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=30, check=True)
            if marker.lower() not in (result.stdout + result.stderr).lower():
                raise RuntimeError(f"suite alias did not run its upstream CLI: {command[0]}")
        collection = Path("/job/tmp/postman-smoke.json")
        collection.write_text(json.dumps({
            "info": {"name": "local-runner-smoke", "schema":
                     "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [{"name": "native-health", "request": {"method": "GET",
                      "url": "http://127.0.0.1:8888/health"},
                      "event": [{"listen": "test", "script": {"exec": [
                          "pm.test('local health responds', function () {",
                          "  pm.response.to.have.status(200);",
                          "});"]}}]}],
        }), encoding="utf-8")
        postman = subprocess.run(["postman", "run", str(collection), "--color", "off"],
                                 capture_output=True, text=True, timeout=30)
        if postman.returncode or "local health responds" not in postman.stdout:
            raise RuntimeError("Postman Newman failed its localhost collection fixture: "
                               + (postman.stdout + postman.stderr)[-700:])
        inso = subprocess.run(["insomnia", "--version"], capture_output=True,
                              text=True, timeout=15, check=True)
        if inso.stdout.strip() != "13.4.0":
            raise RuntimeError("Insomnia Inso CLI version mismatch")
        status = health.get("tools_status", {})
        available = sum(bool(value) for value in status.values())
        print(f"native MCP handshake and exact catalog match passed: {len(tools)} tools; "
              f"route gaps {audited['counts']['missing_route']}; "
              f"installed binaries {available}/{len(status)}")
        if "--missing" in sys.argv:
            print("missing binaries: " + ", ".join(sorted(
                name for name, installed in status.items() if not installed)))
            direct = {name: shutil.which(name) is not None for name in status}
            print("health/PATH disagreements: " + ", ".join(sorted(
                name for name in status if bool(status[name]) != direct[name])))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())
