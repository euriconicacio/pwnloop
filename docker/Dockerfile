# HTB lab box — Kali rolling, native arm64 under OrbStack.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TERM=xterm-256color

# Package list is installed as one apt transaction; on failure we retry package
# by package so a single unavailable arm64 build does not sink the whole image.
COPY packages.txt /tmp/packages.txt
RUN apt-get update && \
    PKGS="$(grep -vE '^\s*(#|$)' /tmp/packages.txt | tr '\n' ' ')" && \
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
    ; do curl -fsSL -O "$u" || echo "download failed: $u" >> /opt/skipped-downloads.txt ; done && \
    gunzip -f chisel_*.gz 2>/dev/null || true ; chmod +x /opt/static/* 2>/dev/null || true

# Kali ships rockyou compressed; every playbook expects the plain file.
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Python tooling that is not packaged (or is stale) in Kali.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pipx install certipy-ad     || echo "certipy-ad"      >> /opt/skipped-packages.txt ; \
    pipx install bloodhound     || echo "bloodhound-python" >> /opt/skipped-packages.txt ; \
    pipx install git-dumper     || echo "git-dumper"      >> /opt/skipped-packages.txt ; \
    pipx install ldapdomaindump || echo "ldapdomaindump"  >> /opt/skipped-packages.txt

RUN mkdir -p /engagements /vpn && \
    ln -sf /usr/share/seclists /opt/seclists 2>/dev/null || true

# git refuses to commit without an identity, which blocks plumbing-based
# exploitation (crafting tree objects to push at a target forge).
RUN git config --global user.email "operator@lab.local" && \
    git config --global user.name "operator" && \
    git config --global safe.directory '*'

WORKDIR /engagements
CMD ["sleep", "infinity"]
