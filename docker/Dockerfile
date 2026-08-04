# HTB lab box — Kali rolling, native arm64 under OrbStack.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TERM=xterm-256color

# Package list is installed as one apt transaction; on failure we retry package
# by package so a single unavailable arm64 build does not sink the whole image.
# The glob picks up packages.local.txt when it exists and is a no-op when it
# does not, so an operator's own list never has to be merged into ours.
COPY packages*.txt /tmp/
RUN apt-get update && \
    PKGS="$(cat /tmp/packages.txt /tmp/packages.local.txt 2>/dev/null | grep -vE '^\s*(#|$)' | tr '\n' ' ')" && \
    (apt-get install -y --no-install-recommends $PKGS || \
     for p in $PKGS; do \
       apt-get install -y --no-install-recommends "$p" || echo "$p" >> /opt/skipped-packages.txt; \
     done) && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Post-exploitation helpers staged locally so the agent can serve them to a
# target instead of fetching from the internet mid-engagement.
RUN mkdir -p /opt/static && cd /opt/static && \
    for u in \
      https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
      https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe \
      https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 \
      https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 \
      https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz \
      https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_arm64.gz \
      https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz \
      https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/socat \
    ; do curl -fsSL -O "$u" || echo "download failed: $u" >> /opt/skipped-downloads.txt ; done && \
    gunzip -f chisel_*.gz 2>/dev/null || true ; chmod +x /opt/static/* 2>/dev/null || true

# Pivoting and Windows post-exploitation. A multi-host lab needs a tunnel agent
# for the target's platform, not just a proxy for ours — the single most common
# way a campaign stalls is landing on a Windows host with nothing to run on it.
COPY fetch-release.sh /usr/local/bin/fetch-release
RUN chmod +x /usr/local/bin/fetch-release && \
    mkdir -p /opt/static/windows && \
    # ligolo-ng: TUN-based pivot. The proxy runs here, agents run on targets.
    fetch-release nicocha30/ligolo-ng 'proxy.*linux_arm64'   /opt/static         'ligolo-ng|proxy' ; \
    fetch-release nicocha30/ligolo-ng 'agent.*linux_amd64'   /opt/static         'ligolo-ng|agent' ; \
    fetch-release nicocha30/ligolo-ng 'agent.*windows_amd64' /opt/static/windows 'agent.*\.exe' ; \
    # Windows AD toolkit — precompiled, so no build chain is needed mid-run.
    fetch-release SpecterOps/SharpHound  'SharpHound.*\.zip$'    /opt/static/windows 'SharpHound\.exe' ; \
    fetch-release gentilkiwi/mimikatz    'mimikatz_trunk\.zip$'  /opt/static/windows 'x64/mimikatz\.exe' ; \
    fetch-release antonioCoco/RunasCs    'RunasCs\.zip$'         /opt/static/windows 'RunasCs\.exe' ; \
    fetch-release BeichenDream/GodPotato 'GodPotato-NET4\.exe$'  /opt/static/windows ; \
    for u in \
      https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Rubeus.exe \
      https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Certify.exe \
      https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Seatbelt.exe \
      https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpUp.exe \
      https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 \
      https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Privesc/PowerUp.ps1 \
    ; do curl -fsSL -o "/opt/static/windows/$(basename "$u")" "$u" || \
         echo "download failed: $u" >> /opt/skipped-downloads.txt ; done ; \
    chmod +x /opt/static/windows/* 2>/dev/null || true

# Normalise the names the methodology refers to. ligolo's archives unpack to
# bare 'proxy' and 'agent', which are ambiguous next to chisel's agent and
# unguessable from a reference file — so pin the names references/pivoting.md
# actually documents, and drop the archives that survived extraction.
RUN cd /opt/static && \
    rm -f ./*.tar.gz ./*.tgz ./*.zip windows/*.tar.gz windows/*.zip ; \
    [ -f proxy ] && mv -f proxy ligolo-proxy ; \
    [ -f agent ] && mv -f agent ligolo-agent ; \
    [ -f windows/agent.exe ] && mv -f windows/agent.exe windows/ligolo-agent.exe ; \
    [ -f chisel_1.10.1_windows_amd64 ] && mv -f chisel_1.10.1_windows_amd64 windows/chisel.exe ; \
    chmod +x /opt/static/* /opt/static/windows/* 2>/dev/null ; true

# Kali ships rockyou compressed; every playbook expects the plain file.
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Python tooling that is not packaged (or is stale) in Kali.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pipx install certipy-ad     || echo "certipy-ad"      >> /opt/skipped-packages.txt ; \
    pipx install bloodhound     || echo "bloodhound-python" >> /opt/skipped-packages.txt ; \
    pipx install bloodhound-ce  || echo "bloodhound-ce"   >> /opt/skipped-packages.txt ; \
    pipx install git-dumper     || echo "git-dumper"      >> /opt/skipped-packages.txt ; \
    pipx install ldapdomaindump || echo "ldapdomaindump"  >> /opt/skipped-packages.txt

# kerbrute ships no linux/arm64 release, so build it natively from source (works
# on both arm64 and amd64). Go is left in the image for building other tools.
RUN apt-get update && apt-get install -y --no-install-recommends golang-go && \
    GOBIN=/usr/local/bin GOPATH=/root/go GOFLAGS=-buildvcs=false \
      go install github.com/ropnop/kerbrute@latest || \
      echo "kerbrute" >> /opt/skipped-packages.txt ; \
    rm -rf /root/.cache/go-build /var/lib/apt/lists/*

RUN mkdir -p /engagements /campaigns /vpn && \
    ln -sf /usr/share/seclists /opt/seclists 2>/dev/null || true

# git refuses to commit without an identity, which blocks plumbing-based
# exploitation (crafting tree objects to push at a target forge).
RUN git config --global user.email "operator@lab.local" && \
    git config --global user.name "operator" && \
    git config --global safe.directory '*'

WORKDIR /engagements
CMD ["sleep", "infinity"]
