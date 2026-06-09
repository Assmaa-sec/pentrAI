#!/usr/bin/env bash
# ============================================================================
# HexStrike — dependency check for the hexfix tools (sections 1-3)
#
# Run on the machine that runs the server, INSIDE the venv, from the repo dir:
#     source hexstrike-env/bin/activate
#     bash check_deps.sh
#
# Reports OK / MISSING for every binary + Python lib the fixes need, prints the
# exact install command for anything missing, and verifies the updated server
# file was actually copied over.
# ============================================================================

miss_apt=()
miss_pip=()
miss_other=()
need_foundry=""

chk_bin () {  # $1 command   $2 apt-package-if-missing ("" = handled elsewhere)
    if command -v "$1" >/dev/null 2>&1; then
        printf "  %-18s OK\n" "$1"
    else
        printf "  %-18s MISSING\n" "$1"
        [ -n "$2" ] && miss_apt+=("$2")
    fi
}

chk_py () {   # $1 import-name   $2 pip-package-if-missing
    if python3 -c "import $1" >/dev/null 2>&1; then
        printf "  %-18s OK\n" "$1"
    else
        printf "  %-18s MISSING\n" "$1"
        [ -n "$2" ] && miss_pip+=("$2")
    fi
}

echo "=================================================================="
echo " HexStrike fix dependencies — environment check"
echo "=================================================================="

echo
echo "[ System binaries (apt) ]"
chk_bin nmap        nmap
chk_bin foremost    foremost
chk_bin tshark      tshark
chk_bin mmls        sleuthkit
chk_bin fls         sleuthkit
chk_bin chromium    chromium
chk_bin chromedriver chromium-driver
# ROPgadget is a pip CLI -> bucket it under pip if missing
if command -v ROPgadget >/dev/null 2>&1; then
    printf "  %-18s OK\n" "ROPgadget"
else
    printf "  %-18s MISSING\n" "ROPgadget"; miss_pip+=("ROPgadget")
fi
# volatility3: any one entry point is enough (server auto-detects vol/vol.py/volatility3)
if command -v vol >/dev/null 2>&1 || command -v vol.py >/dev/null 2>&1 || command -v volatility3 >/dev/null 2>&1; then
    printf "  %-18s OK\n" "vol(atility3)"
else
    printf "  %-18s MISSING\n" "vol(atility3)"; miss_pip+=("volatility3")
fi
# --- §3 capability tools ---
chk_bin smbclient   smbclient
chk_bin ipptool     cups-ipp-utils
if command -v nxc >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
    printf "  %-18s OK\n" "netexec (nxc)"
else
    printf "  %-18s MISSING\n" "netexec (nxc)"
    miss_other+=("netexec: pipx install netexec   ||   sudo apt install -y netexec")
fi
# foundry cast/anvil — foundryup installs to ~/.foundry/bin, often OFF the server's PATH
for fb in cast anvil; do
    if command -v "$fb" >/dev/null 2>&1 || [ -x "$HOME/.foundry/bin/$fb" ]; then
        printf "  %-18s OK\n" "$fb"
    else
        printf "  %-18s MISSING\n" "$fb"; need_foundry=1
    fi
done

echo
echo "[ Python libraries — must be in the ACTIVE venv ]"
chk_py flask       flask
chk_py requests    requests
chk_py psutil      psutil
chk_py mcp         fastmcp
chk_py bs4         beautifulsoup4
chk_py selenium    selenium
chk_py aiohttp     aiohttp
chk_py mitmproxy   mitmproxy
chk_py pwn         pwntools
chk_py Crypto      pycryptodome
chk_py Evtx        python-evtx
chk_py sympy       sympy

echo
echo "[ Which fix / tool needs what ]"
cat <<'MAP'
  rop_chain_builder (#7)    ROPgadget + pwn
  pwntools templates (#7)   pwn
  disk_image_mount (#9)     mmls / fls   (sleuthkit)
  pcap_decrypt (#9)         tshark
  volatility3 (#9)          vol / vol.py / volatility3
  foremost (#9)             foremost
  xss_csrf_chain (#8)       chromium + chromedriver + selenium
  blind_sqli / http (#6,#8) requests
  nmap (#11)                nmap
  crypto_solve template     Crypto (pycryptodome)
  evtx_parser (§3)          Evtx (python-evtx)
  rsa_factor (§3)           sympy   (optional: RsaCtfTool)
  compression_oracle (§3)   requests   (emits a harness)
  sqli_order_oracle (§3)    requests
  timing_oracle (§3)        requests
  smb_ipp_exploit (§3)      smbclient + ipptool (cups-ipp-utils) + netexec
  blockchain_exploit (§3)   cast (foundry; also ~/.foundry/bin)
  (server boots at all)     flask requests psutil mcp bs4 selenium aiohttp mitmproxy
MAP

echo
echo "[ Code freshness — did the updated files get copied over? ]"
SRV="${1:-hexstrike_server.py}"
if [ -f "$SRV" ]; then
    for marker in rop-chain-builder disk-image-mount pcap-decrypt xss-csrf-chain \
                  evtx-parser rsa-factor compression-oracle sqli-order-oracle \
                  timing-oracle smb-ipp-exploit blockchain-exploit; do
        if grep -q "$marker" "$SRV"; then printf "  %-20s present\n" "$marker"
        else printf "  %-20s MISSING — old %s?\n" "$marker" "$SRV"; fi
    done
else
    echo "  ($SRV not found — run from the hexstrike-ai dir, or pass the path: bash check_deps.sh /path/to/hexstrike_server.py)"
fi

echo
echo "[ Install hints for anything MISSING above ]"
if [ ${#miss_apt[@]} -gt 0 ]; then
    echo "  sudo apt install -y $(printf '%s\n' "${miss_apt[@]}" | sort -u | tr '\n' ' ')"
fi
if [ ${#miss_pip[@]} -gt 0 ]; then
    echo "  pip install $(printf '%s\n' "${miss_pip[@]}" | sort -u | tr '\n' ' ')   # inside the venv"
fi
if [ ${#miss_other[@]} -gt 0 ]; then
    printf '  %s\n' "${miss_other[@]}"
fi
if [ -n "$need_foundry" ]; then
    echo "  foundry (cast/anvil):  curl -L https://foundry.paradigm.xyz | bash    THEN open a NEW shell and run:  foundryup"
    echo "    behind the firewall:  https_proxy=http://127.0.0.1:7890 curl -L https://foundry.paradigm.xyz | bash   (new shell, then foundryup)"
    echo "    if the binary download still fails: grab foundry_<ver>_linux_amd64.tar.gz  (amd64 == x86_64!) from"
    echo "    https://github.com/foundry-rs/foundry/releases , confirm 'file' shows clean gzip, then:"
    echo "      mkdir -p ~/.foundry/bin && tar -xzf foundry_*_linux_amd64.tar.gz -C ~/.foundry/bin cast anvil && chmod +x ~/.foundry/bin/{cast,anvil}"
fi
if [ ${#miss_apt[@]} -eq 0 ] && [ ${#miss_pip[@]} -eq 0 ] && [ ${#miss_other[@]} -eq 0 ] && [ -z "$need_foundry" ]; then
    echo "  Nothing missing — you're good to go."
fi
echo
echo "Note: chromedriver MISSING is usually fine — selenium >=4.15 auto-downloads it on first use."
echo "=================================================================="
