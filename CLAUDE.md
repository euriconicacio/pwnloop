# pwnloop

Working directory for autonomous lab-machine engagements.

- Offensive tooling runs **only** inside the `pwnloop-box` container, via
  `./bin/pwnloop x '<command>'`. Never install pentest tooling on the macOS host.
- Engagement state lives in `engagements/<machine>/`; that directory and `vpn/`
  are gitignored and must stay that way.
- The methodology is in `skills/pwnloop/` — that is the source of truth,
  symlinked into `~/.claude/skills/`. Edit it here, not there.
- Targets are lab hosts over the HTB VPN. Anything outside that (public IPs,
  third-party domains, the local LAN) is out of scope — stop and confirm.
