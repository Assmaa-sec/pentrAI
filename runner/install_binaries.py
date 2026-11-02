"""Install pinned upstream scanner releases into the local HexStrike runner."""

import hashlib
import http.client
import io
import os
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path


# URL, upstream GitHub release SHA-256 digest, executable inside the archive.
RELEASES = {
    "httpx": (
        "https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip",
        "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76",
        "httpx",
    ),
    "nuclei": (
        "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip",
        "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
        "nuclei",
    ),
    "subfinder": (
        "https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_amd64.zip",
        "a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37",
        "subfinder",
    ),
    "katana": (
        "https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip",
        "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2",
        "katana",
    ),
    "trivy": (
        "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz",
        "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
        "trivy",
    ),
    "feroxbuster": (
        "https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz",
        "7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80",
        "feroxbuster",
    ),
    "amass": (
        "https://github.com/owasp-amass/amass/releases/download/v5.1.3/amass_linux_amd64.tar.gz",
        "4c12b725e4ce4981ece93a5e1566bd7391be1f349468856a79d31a43012ae201",
        "amass_linux_amd64/amass",
    ),
    "dalfox": (
        "https://github.com/hahwul/dalfox/releases/download/v3.2.4/dalfox-v3.2.4-linux-x86_64-musl.tar.gz",
        "c11cfd2f8261973f0a2a2a1eba5a147ce77712a29acfa6343f9847fb8bb7eca2",
        "dalfox-v3.2.4-linux-x86_64-musl/dalfox",
    ),
    "gau": (
        "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz",
        "10e2e248c37cafb0be3f6d2931125296b95cd4186066d596d47fa417237529a9",
        "gau",
    ),
    "terrascan": (
        "https://github.com/tenable/terrascan/releases/download/v1.19.9/terrascan_1.19.9_Linux_x86_64.tar.gz",
        "9275d75210b7df52f8870252035803288646674f5701ced82812037700a39670",
        "terrascan",
    ),
}


def install(name: str, url: str, expected: str, member: str) -> None:
    print(f"Downloading {name} from {url}", flush=True)
    request = urllib.request.Request(url, headers={"User-Agent": "PentrAI-runner-build"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                archive = response.read()
            break
        except (OSError, EOFError, http.client.HTTPException) as error:
            if attempt == 3:
                raise
            print(f"Retrying {name} download after {error}", flush=True)
            time.sleep(2 ** attempt)
    actual = hashlib.sha256(archive).hexdigest()
    if actual != expected:
        raise ValueError(f"{name} release digest mismatch: {actual}")
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            binary = package.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            extracted = package.extractfile(member)
            if extracted is None:
                raise ValueError(f"{member} absent from {name} release")
            binary = extracted.read()
    target = Path("/usr/local/bin") / name
    target.write_bytes(binary)
    os.chmod(target, 0o755)
    print(f"Installed {name}", flush=True)


if __name__ == "__main__":
    for tool, release in RELEASES.items():
        install(tool, *release)
