"""Install additional checksum-pinned HexStrike command releases."""

from install_binaries import install


RELEASES = {
    "anew": (
        "https://github.com/tomnomnom/anew/releases/download/v0.1.1/anew-linux-amd64-0.1.1.tgz",
        "149527b1b79550bbbd3d7768568cb981db78787ee24b5da454e9cc42e9166032",
        "anew",
    ),
    "waybackurls": (
        "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz",
        "884786132d11c8eb838fc88626dad96494207c79e436a72870a7d69f147500a6",
        "waybackurls",
    ),
    "qsreplace": (
        "https://github.com/tomnomnom/qsreplace/releases/download/v0.0.3/qsreplace-linux-amd64-0.0.3.tgz",
        "1dac67a5010cdeb1e63d9d4aa1973f90baf98d3a26a3107e586677d3eff54ad8",
        "qsreplace",
    ),
}


if __name__ == "__main__":
    for name, release in RELEASES.items():
        install(name, *release)
