FROM golang:1.25.3-alpine@sha256:aee43c3ccbf24fdffb7295693b6e33b21e01baec1b2a55acc351fde345e9ec34 AS go-scanners
RUN CGO_ENABLED=0 go install github.com/hakluke/hakrawler@61905593d82e8bac87ff7a7cca32b2adde42bb60

FROM eclipse-temurin:25-jdk-jammy@sha256:e4f029273ed9e4444697df30bb6098dbe51477291598aebc54dd0b48d95d6ae7 AS ghidra-jdk

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/job/tmp \
    TMPDIR=/job/tmp

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl file git nmap binutils \
    aircrack-ng arp-scan binwalk dirb dnsenum ffuf foremost gdb gobuster \
    hashcat hydra john masscan medusa nbtscan patator scalpel sqlmap \
    steghide tcpdump testdisk tshark xxd libimage-exiftool-perl samba-common-bin \
    arjun checksec dirsearch fierce httpie outguess python3-pwntools \
    python3-ropgadget sleuthkit smbclient smbmap wafw00f wfuzz && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 pentrai && useradd -u 10001 -g 10001 -d /job/tmp pentrai && \
    mkdir -p /job/tmp /job/source && chown pentrai:pentrai /job/tmp

WORKDIR /opt/pentrai
COPY pyproject.toml ./
COPY control_plane ./control_plane
COPY execution_manager ./execution_manager
COPY pentrai_pipeline ./pentrai_pipeline
COPY static_worker ./static_worker
COPY pentrai_server.py pentrai_mcp.py ./

RUN python -m pip install --no-cache-dir '.[runner]' \
    'flask>=2.3,<4' 'psutil>=5.9,<6' 'beautifulsoup4>=4.12,<5' \
    'selenium>=4.15,<5' 'aiohttp>=3.8,<4' 'mitmproxy==12.3.1' \
    'angr==9.3.4' 'checkov==3.4.0' 'pwntools==4.15.0' \
    'ropper==1.13.13' 'volatility3==2.28.2'

# angr 9.3 needs APIs removed by newer bitstring and pycparser releases.
RUN python -m pip install --no-cache-dir 'bitstring==4.3.1' 'pycparser==3.0'

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    recon-ng sherlock && rm -rf /var/lib/apt/lists/*

COPY runner/install_binaries.py /opt/pentrai/install_binaries.py
RUN python /opt/pentrai/install_binaries.py
COPY runner/install_nikto.py /opt/pentrai/install_nikto.py
RUN python /opt/pentrai/install_nikto.py

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ruby ruby-dev build-essential libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/* && \
    gem install wpscan -v 4.1.0 --no-document && \
    mkdir -p /opt/pentrai/wpscan-cache && \
    XDG_CACHE_HOME=/opt/pentrai/wpscan-cache wpscan --update && \
    chmod -R a+rX /opt/pentrai/wpscan-cache
ENV XDG_CACHE_HOME=/opt/pentrai/wpscan-cache
RUN mv /usr/local/bin/wpscan /usr/local/bin/wpscan-real
COPY runner/wpscan-launcher /usr/local/bin/wpscan
RUN chmod 0755 /usr/local/bin/wpscan
RUN python -m pip install --no-cache-dir --no-deps 'uro==1.0.2'

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openjdk-21-jre-headless && rm -rf /var/lib/apt/lists/*
RUN curl --retry 4 --retry-delay 2 -fsSL \
    https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz \
    -o /tmp/zaproxy.tar.gz && \
    echo 'efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a  /tmp/zaproxy.tar.gz' | sha256sum -c - && \
    mkdir -p /opt/zaproxy && \
    tar -xzf /tmp/zaproxy.tar.gz -C /opt/zaproxy --strip-components=1 && \
    rm /tmp/zaproxy.tar.gz
COPY runner/zaproxy-launcher /usr/local/bin/zaproxy
RUN chmod 0755 /usr/local/bin/zaproxy

# Keep cloud scanner dependency trees separate. Prowler and Scout Suite pin
# incompatible python-dateutil releases and must not share the server venv.
RUN python -m venv /opt/scanners/prowler && \
    /opt/scanners/prowler/bin/pip install --no-cache-dir 'prowler==5.47.0' && \
    ln -s /opt/scanners/prowler/bin/prowler /usr/local/bin/prowler
RUN python -m venv /opt/scanners/scout-suite && \
    /opt/scanners/scout-suite/bin/pip install --no-cache-dir 'scoutsuite==5.14.0' && \
    ln -s /opt/scanners/scout-suite/bin/scout /usr/local/bin/scout && \
    ln -s /opt/scanners/scout-suite/bin/scout /usr/local/bin/scout-suite
RUN python -m venv /opt/scanners/kube-hunter && \
    /opt/scanners/kube-hunter/bin/pip install --no-cache-dir 'kube-hunter==0.6.8' && \
    ln -s /opt/scanners/kube-hunter/bin/kube-hunter /usr/local/bin/kube-hunter

COPY runner/install_more_binaries.py /opt/pentrai/install_more_binaries.py
RUN python /opt/pentrai/install_more_binaries.py

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    autopsy ophcrack wireshark xvfb && rm -rf /var/lib/apt/lists/*
RUN gem install zsteg -v 0.2.14 --no-document && \
    gem install one_gadget -v 2.1.1 --no-document && \
    ln -s /usr/local/bin/one_gadget /usr/local/bin/one-gadget

COPY runner/install_rustscan.py /opt/pentrai/install_rustscan.py
RUN python /opt/pentrai/install_rustscan.py

# The upstream health list uses names different from these real CLI entry points.
RUN test -x /opt/scanners/prowler/bin/shodan && \
    ln -s /opt/scanners/prowler/bin/shodan /usr/local/bin/shodan-cli
RUN python -m venv /opt/scanners/censys && \
    /opt/scanners/censys/bin/pip install --no-cache-dir 'censys==2.3.0' && \
    test -x /opt/scanners/censys/bin/censys && \
    ln -s /opt/scanners/censys/bin/censys /usr/local/bin/censys-cli
RUN python -m venv /opt/scanners/social-analyzer && \
    /opt/scanners/social-analyzer/bin/pip install --no-cache-dir 'social-analyzer==0.45' && \
    test -x /opt/scanners/social-analyzer/bin/social-analyzer && \
    ln -s /opt/scanners/social-analyzer/bin/social-analyzer /usr/local/bin/social-analyzer

# The upstream Debian package includes kube-bench's benchmark configuration.
RUN curl --retry 4 --retry-delay 2 -fsSL \
    https://github.com/aquasecurity/kube-bench/releases/download/v0.16.0/kube-bench_0.16.0_linux_amd64.deb \
    -o /tmp/kube-bench.deb && \
    echo 'f1a95c6c4ff08631382ae00438b8f3bf0eceedc229192e451bdba0e4c8803019  /tmp/kube-bench.deb' | sha256sum -c - && \
    dpkg -i /tmp/kube-bench.deb && rm /tmp/kube-bench.deb
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libreadline-dev && rm -rf /var/lib/apt/lists/* && \
    gem install evil-winrm -v 4.1 --no-document
RUN python -m venv /opt/scanners/enum4linux-ng && \
    /opt/scanners/enum4linux-ng/bin/pip install --no-cache-dir \
      'git+https://github.com/cddmp/enum4linux-ng.git@f34e7bb3bc2bcd10267a7257fb3658154434ccf4' && \
    ln -s /opt/scanners/enum4linux-ng/bin/enum4linux-ng /usr/local/bin/enum4linux-ng
RUN python -m venv /opt/scanners/paramspider && \
    /opt/scanners/paramspider/bin/pip install --no-cache-dir \
      'git+https://github.com/devanshbatham/ParamSpider.git@1591b80c1994518b57801d01bd516dc2bc94d61b' && \
    ln -s /opt/scanners/paramspider/bin/paramspider /usr/local/bin/paramspider
RUN curl --retry 4 --retry-delay 2 -fsSL \
    https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz \
    -o /tmp/x8.gz && \
    echo 'b3e54da4c0cc62163a3485addea6671368ee69342ea5740e56d6d6112196bd0e  /tmp/x8.gz' | sha256sum -c - && \
    gzip -dc /tmp/x8.gz > /usr/local/bin/x8 && \
    chmod 0755 /usr/local/bin/x8 && rm /tmp/x8.gz
RUN python -m venv /opt/scanners/theharvester && \
    /opt/scanners/theharvester/bin/pip install --no-cache-dir \
      'git+https://github.com/laramies/theHarvester.git@ba85366644131d5f170cc7016d4ed99b9817889a' && \
    ln -s /opt/scanners/theharvester/bin/theHarvester /usr/local/bin/theHarvester && \
    ln -s /opt/scanners/theharvester/bin/theHarvester /usr/local/bin/theharvester
COPY --from=go-scanners /go/bin/hakrawler /usr/local/bin/hakrawler
# Expose the actual upstream entry points under HexStrike's inventory names.
RUN test -x /usr/local/bin/ROPgadget && test -x /usr/local/bin/vol && \
    mv /usr/local/bin/vol /usr/local/bin/vol-real && \
    ln -s /usr/local/bin/ROPgadget /usr/local/bin/ropgadget && \
    ln -s /usr/local/bin/vol /usr/local/bin/volatility3
COPY runner/vol-launcher /usr/local/bin/vol
RUN chmod 0755 /usr/local/bin/vol
COPY runner/install_jaeles.py /opt/pentrai/install_jaeles.py
RUN python /opt/pentrai/install_jaeles.py
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libnet-tftp-perl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/scanners/enum4linux /opt/scanners/dotdotpwn /opt/scanners/hash-identifier && \
    git -C /opt/scanners/enum4linux init -q && \
    git -C /opt/scanners/enum4linux fetch -q --depth 1 https://github.com/CiscoCXSecurity/enum4linux.git 0a5b7d48a97bbda648aaf7ace47a9e4f736ef8d7 && \
    git -C /opt/scanners/enum4linux checkout -q FETCH_HEAD && \
    git -C /opt/scanners/dotdotpwn init -q && \
    git -C /opt/scanners/dotdotpwn fetch -q --depth 1 https://github.com/wireghoul/dotdotpwn.git 1d3af99d7de1ab7f2a321934891ecd3ff1a02734 && \
    git -C /opt/scanners/dotdotpwn checkout -q FETCH_HEAD && \
    git -C /opt/scanners/hash-identifier init -q && \
    git -C /opt/scanners/hash-identifier fetch -q --depth 1 https://gitlab.com/kalilinux/packages/hash-identifier.git 0438e2a80ca28681a2c7a25275fe9c245988334f && \
    git -C /opt/scanners/hash-identifier checkout -q FETCH_HEAD && \
    ln -s /opt/scanners/enum4linux/enum4linux.pl /usr/local/bin/enum4linux && \
    chmod 0755 /opt/scanners/enum4linux/enum4linux.pl
COPY runner/dotdotpwn-launcher /usr/local/bin/dotdotpwn
COPY runner/hash-identifier-launcher /usr/local/bin/hash-identifier
RUN chmod 0755 /usr/local/bin/dotdotpwn /usr/local/bin/hash-identifier
RUN curl --retry 4 --retry-delay 2 -fsSL \
    https://github.com/radareorg/radare2/releases/download/6.2.4/radare2_6.2.4_amd64.deb \
    -o /tmp/radare2.deb && \
    echo '7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90  /tmp/radare2.deb' | sha256sum -c - && \
    dpkg -i /tmp/radare2.deb && rm /tmp/radare2.deb
RUN curl --retry 4 --retry-delay 2 -fsSL \
    https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip \
    -o /tmp/ghidra.zip && \
    echo '2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67  /tmp/ghidra.zip' | sha256sum -c - && \
    mkdir -p /opt/ghidra && \
    python -c "import zipfile; zipfile.ZipFile('/tmp/ghidra.zip').extractall('/opt/ghidra')" && \
    rm /tmp/ghidra.zip && \
    ln -s /opt/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless /usr/local/bin/analyzeHeadless && \
    ln -s /usr/local/bin/analyzeHeadless /usr/local/bin/ghidra
RUN chmod 0755 /opt/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless \
               /opt/ghidra/ghidra_12.2_PUBLIC/support/launch.sh
COPY --from=ghidra-jdk /opt/java/openjdk /opt/ghidra-jdk
RUN rm /usr/local/bin/analyzeHeadless
COPY runner/ghidra-headless-launcher /usr/local/bin/analyzeHeadless
RUN chmod 0755 /usr/local/bin/analyzeHeadless
RUN python -m venv /opt/scanners/autorecon && \
    /opt/scanners/autorecon/bin/pip install --no-cache-dir \
      'git+https://github.com/Tib3rius/AutoRecon.git@e7e98f60bdc5fb1695159c1bbcdfdf2746d30fa6' && \
    ln -s /opt/scanners/autorecon/bin/autorecon /usr/local/bin/autorecon
RUN mkdir -p /opt/scanners/netexec-src && \
    git -C /opt/scanners/netexec-src init -q && \
    git -C /opt/scanners/netexec-src fetch -q --depth 1 https://github.com/Pennyw0rth/NetExec.git c7dc286ba65daf10402cdc470e531b84e6d3d911 && \
    git -C /opt/scanners/netexec-src checkout -q FETCH_HEAD && \
    sed -i 's|certipy-ad @ git+https://github.com/Pennyw0rth/Certipy|certipy-nxc @ git+https://github.com/Pennyw0rth/Certipy|' \
      /opt/scanners/netexec-src/pyproject.toml && \
    python -m venv /opt/scanners/netexec && \
    /opt/scanners/netexec/bin/pip install --no-cache-dir /opt/scanners/netexec-src && \
    ln -s /opt/scanners/netexec/bin/nxc /usr/local/bin/nxc
RUN python -m venv /opt/scanners/xsser && \
    /opt/scanners/xsser/bin/pip install --no-cache-dir \
      'git+https://github.com/epsylon/xsser.git@dc72706d2c0dcfe52e355194d1be3b1aed4afca2' && \
    ln -s /opt/scanners/xsser/bin/xsser /usr/local/bin/xsser
RUN mkdir -p /opt/scanners/xsser-src && \
    git -C /opt/scanners/xsser-src init -q && \
    git -C /opt/scanners/xsser-src fetch -q --depth 1 https://github.com/epsylon/xsser.git dc72706d2c0dcfe52e355194d1be3b1aed4afca2 && \
    git -C /opt/scanners/xsser-src checkout -q FETCH_HEAD && \
    rm /usr/local/bin/xsser
COPY runner/xsser-launcher /usr/local/bin/xsser
RUN chmod 0755 /usr/local/bin/xsser

# Pinned official static release; the native /api/tools/pwninit route invokes this CLI.
RUN curl --retry 4 --retry-delay 2 -fsSL \
    https://github.com/io12/pwninit/releases/download/3.3.1/pwninit \
    -o /usr/local/bin/pwninit && \
    echo '1b72653be59f8f13ea934d1153e8d845eac0dbac62a8c4d9dc4a25577f009362  /usr/local/bin/pwninit' | sha256sum -c - && \
    chmod 0755 /usr/local/bin/pwninit

# Official bulk_extractor release, built with its documented Debian dependencies.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    autoconf automake flex libabsl-dev libexpat1-dev libgcrypt20-dev \
    libgpg-error-dev libre2-dev libssl-dev libtool pkg-config zlib1g-dev && \
    rm -rf /var/lib/apt/lists/* && \
    curl --retry 4 --retry-delay 2 -fsSL \
      https://github.com/simsong/bulk_extractor/releases/download/v2.2.0/bulk_extractor-2.2.0.tar.gz \
      -o /tmp/bulk_extractor.tar.gz && \
    echo 'b9e15d40d711aa43590e1bf1a25d30943e3bad8371281d7c80d3803a6f34c268  /tmp/bulk_extractor.tar.gz' | sha256sum -c - && \
    mkdir -p /tmp/bulk_extractor-src && \
    tar -xzf /tmp/bulk_extractor.tar.gz -C /tmp/bulk_extractor-src --strip-components=1 && \
    cd /tmp/bulk_extractor-src && \
    sed -i 's/XML_GetCurrentLineNumber(parser)/XML_GetCurrentLineNumber64(parser)/' \
      src/bulk_extractor_restarter.h && \
    ./configure --disable-libewf && \
    make -j2 && make install && ldconfig && \
    ln -s /usr/local/bin/bulk_extractor /usr/local/bin/bulk-extractor && \
    cd / && rm -rf /tmp/bulk_extractor-src /tmp/bulk_extractor.tar.gz

# SearchSploit requires the local Exploit-DB CSV and source corpus.
RUN mkdir -p /opt/exploitdb && git -C /opt/exploitdb init -q && \
    git -C /opt/exploitdb fetch -q --depth 1 \
      https://gitlab.com/exploit-database/exploitdb.git \
      f08907b131f851c2ec3c052906f82ca83703ebef && \
    git -C /opt/exploitdb checkout -q FETCH_HEAD && \
    chmod 0755 /opt/exploitdb/searchsploit
COPY runner/searchsploit-launcher /usr/local/bin/searchsploit
RUN chmod 0755 /usr/local/bin/searchsploit

# Rapid7's official omnibus package, pinned to the archived package hash.
RUN curl --retry 4 --retry-delay 2 -fsSL \
      'https://downloads.metasploit.com/data/releases/metasploit-framework/apt/pool/main/m/metasploit-framework/metasploit-framework_6.5.9~20261101055705.git.3.494135f~1rapid7-1_amd64.deb' \
      -o /tmp/metasploit-framework.deb && \
    echo 'f5b85eb05086489e60844330ebbf903148b5a89b1b704acce581bb918c425150  /tmp/metasploit-framework.deb' | sha256sum -c - && \
    dpkg -i /tmp/metasploit-framework.deb && \
    rm /tmp/metasploit-framework.deb

# Hashcat-utils is a suite of individual native commands. Keep its complete
# pinned source build and expose a dispatcher that runs only those commands.
RUN mkdir -p /opt/scanners/hashcat-utils && \
    git -C /opt/scanners/hashcat-utils init -q && \
    git -C /opt/scanners/hashcat-utils fetch -q --depth 1 \
      https://github.com/hashcat/hashcat-utils.git \
      b55e433d187e6b04c526f67ea508a0e98c3f814a && \
    git -C /opt/scanners/hashcat-utils checkout -q FETCH_HEAD && \
    make -C /opt/scanners/hashcat-utils/src -j2 native && \
    cp /opt/scanners/hashcat-utils/src/*.bin /opt/scanners/hashcat-utils/bin/ && \
    test -x /opt/scanners/hashcat-utils/bin/len.bin
COPY runner/hashcat-utils-launcher /usr/local/bin/hashcat-utils
RUN chmod 0755 /usr/local/bin/hashcat-utils

# SpiderFoot's CLI runs from its source tree; its dependencies stay isolated
# from the HexStrike server's Python environment.
RUN mkdir -p /opt/scanners/spiderfoot-src && \
    git -C /opt/scanners/spiderfoot-src init -q && \
    git -C /opt/scanners/spiderfoot-src fetch -q --depth 1 \
      https://github.com/smicallef/spiderfoot.git \
      0f815a203afebf05c98b605dba5cf0475a0ee5fd && \
    git -C /opt/scanners/spiderfoot-src checkout -q FETCH_HEAD && \
    python -m venv /opt/scanners/spiderfoot && \
    /opt/scanners/spiderfoot/bin/pip install --no-cache-dir \
      -r /opt/scanners/spiderfoot-src/requirements.txt
COPY runner/spiderfoot-launcher /usr/local/bin/spiderfoot
RUN chmod 0755 /usr/local/bin/spiderfoot

# Keep a small, immutable offline libc offset corpus. The native HexStrike
# route changes into /opt/libc-database and invokes its original scripts.
RUN mkdir -p /opt/libc-database && \
    git -C /opt/libc-database init -q && \
    git -C /opt/libc-database fetch -q --depth 1 \
      https://github.com/niklasb/libc-database.git \
      7dd77047221f3e2f014d3d55d6575bd684477ea9 && \
    git -C /opt/libc-database checkout -q FETCH_HEAD && \
    cd /opt/libc-database && \
    ./add /lib/x86_64-linux-gnu/libc.so.6 && \
    chmod -R a+rX /opt/libc-database
COPY runner/libc-database-launcher /usr/local/bin/libc-database
RUN chmod 0755 /usr/local/bin/libc-database

# These health names are umbrella names for already installed upstream CLIs.
# Aliases point to the real programs, and Sleuth Kit dispatches its native CLI.
RUN ln -s /usr/local/bin/searchsploit /usr/local/bin/exploit-db && \
    ln -s /usr/local/bin/pwn /usr/local/bin/pwntools && \
    ln -s /usr/local/bin/vol /usr/local/bin/volatility
COPY runner/metasploit-launcher /usr/local/bin/metasploit
COPY runner/sleuthkit-launcher /usr/local/bin/sleuthkit
RUN chmod 0755 /usr/local/bin/metasploit /usr/local/bin/sleuthkit

# Vendor-supported headless collection runners for Postman and Insomnia.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      --no-install-recommends nodejs npm xz-utils && \
    rm -rf /var/lib/apt/lists/* && \
    npm install -g --ignore-scripts newman@6.2.3
RUN curl --retry 4 --retry-delay 2 -fsSL \
      'https://github.com/Kong/insomnia/releases/download/core%4013.4.0/inso-linux-x64-13.4.0.tar.xz' \
      -o /tmp/inso.tar.xz && \
    echo 'cd317f27c945a4e076b45e2a576b3dda352308c43568b32f5c0d5670462d1b24  /tmp/inso.tar.xz' | sha256sum -c - && \
    mkdir -p /opt/inso && \
    tar -xJf /tmp/inso.tar.xz -C /opt/inso && \
    rm /tmp/inso.tar.xz && \
    test -x /opt/inso/inso && \
    mkdir -p /opt/inso/native-cache && \
    PKG_NATIVE_CACHE_PATH=/opt/inso/native-cache /opt/inso/inso --version && \
    chmod -R a+rX /opt/inso/native-cache
COPY runner/postman-launcher /usr/local/bin/postman
COPY runner/insomnia-launcher /usr/local/bin/insomnia
RUN chmod 0755 /usr/local/bin/postman /usr/local/bin/insomnia

# Genuine command-line tools for three native health names. The GraphQL and
# JWT Python dependencies remain separate from the HexStrike server process.
RUN mkdir -p /opt/scanners/graphql-scanner && \
    git -C /opt/scanners/graphql-scanner init -q && \
    git -C /opt/scanners/graphql-scanner fetch -q --depth 1 \
      https://github.com/davidfortytwo/graphql-scanner.git \
      af812d89ba7829ffa75361339ecb8b0ed11fb025 && \
    git -C /opt/scanners/graphql-scanner checkout -q FETCH_HEAD && \
    python -m venv /opt/scanners/graphql-scanner-venv && \
    /opt/scanners/graphql-scanner-venv/bin/pip install --no-cache-dir \
      -r /opt/scanners/graphql-scanner/requirements.txt
COPY runner/graphql-scanner-launcher /usr/local/bin/graphql-scanner
RUN chmod 0755 /usr/local/bin/graphql-scanner
RUN mkdir -p /opt/scanners/jwt-analyzer-src && \
    git -C /opt/scanners/jwt-analyzer-src init -q && \
    git -C /opt/scanners/jwt-analyzer-src fetch -q --depth 1 \
      https://github.com/ItsWanheda/jwt-analyzer.git \
      38503111eb2d495c86fe2f5d88890ac988354143 && \
    git -C /opt/scanners/jwt-analyzer-src checkout -q FETCH_HEAD && \
    python -m venv /opt/scanners/jwt-analyzer-venv && \
    /opt/scanners/jwt-analyzer-venv/bin/pip install --no-cache-dir \
      /opt/scanners/jwt-analyzer-src && \
    ln -s /opt/scanners/jwt-analyzer-venv/bin/jwt-analyzer /usr/local/bin/jwt-analyzer

# The original HashPump repository is unavailable. This pinned source fork
# retains the native hashpump executable and its original CLI argument shape.
RUN mkdir -p /opt/scanners/hashpump-src && \
    git -C /opt/scanners/hashpump-src init -q && \
    git -C /opt/scanners/hashpump-src fetch -q --depth 1 \
      https://github.com/2H-K/hashpumpy_changed.git \
      a7e7b842123acabde9f1ef7d0e18d9fea9dccdf9 && \
    git -C /opt/scanners/hashpump-src checkout -q FETCH_HEAD && \
    make -C /opt/scanners/hashpump-src -j2 && \
    cp /opt/scanners/hashpump-src/hashpump /usr/local/bin/hashpump && \
    chmod 0755 /usr/local/bin/hashpump

COPY runner/smoke.py /opt/pentrai/runner_smoke.py
COPY runner/audit_catalog.py /opt/pentrai/runner/audit_catalog.py
COPY runner/zap_smoke.py /opt/pentrai/zap_smoke.py
COPY runner/assessment_smoke.py /opt/pentrai/assessment_smoke.py
COPY runner/local_assessment.py /opt/pentrai/local_assessment.py
ENV PYTHONPATH=/opt/pentrai
USER 10001:10001
WORKDIR /job/tmp
CMD ["python", "/opt/pentrai/pentrai_server.py"]
