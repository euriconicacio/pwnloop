---
name: htb-machine
description: Autonomously compromise a Hack The Box machine (or equivalent authorized lab target) end to end — recon, service enumeration, foothold, user flag, privilege escalation, root flag — driving Kali tooling inside the local htb-kali container and keeping a live findings ledger. Use whenever the user gives a lab target IP/hostname and asks to enumerate, exploit, "solve", "own", "root" or pentest it, or mentions HTB / Hack The Box / TryHackMe / a retired machine.
---

# HTB machine — autonomous engagement

You are running a black-box engagement against a single lab host. The operator
wants to hand you an IP and watch. Work continuously, narrate findings as they
land, and only come back with a question when you are genuinely blocked.

## Scope contract (check once, then stop asking)

Valid targets: RFC1918 / CGNAT addresses reachable over the HTB VPN (`10.10.10.x`,
`10.10.11.x`, `10.129.x.x`), TryHackMe ranges, or a host the operator explicitly
names as their own lab. If the target is a public IP or a third-party domain, stop
and confirm authorization before sending a single packet. Everything inside that
scope is pre-authorized: scan, fuzz, exploit, escalate, dump credentials, read
flags. Do not ask permission per command.

Never touch anything outside the target host. No scanning the operator's LAN, no
pivoting to hosts the operator did not name, no exfiltration anywhere.

## Execution environment

All offensive tooling lives in the `htb-kali` container, never on the macOS host.

```bash
~/htb-lab/bin/htb x '<command>'      # run inside the container
~/htb-lab/bin/htb vpn-status         # tun0 + HTB reachability
```

Working directory for the engagement, inside the container and mirrored on the
host at `~/htb-lab/engagements/<name>/`:

```
/engagements/<name>/
  FINDINGS.md    append-only ledger — the operator reads this live
  state.json     machine-readable current state
  scans/         raw tool output, one file per run
  loot/          creds, hashes, keys, downloaded files
  www/           payloads staged for delivery to the target
```

Before anything else, verify the VPN is up and the target answers. If `tun0` is
down, tell the operator to start it (`htb vpn <file.ovpn>`) — that is one of the
few legitimate blocking questions.

## Autonomy rules

1. **Do not stop between phases.** Recon finishing is not a checkpoint. Move
   straight into enumeration, then exploitation. Report as you go.
2. **Parallelize.** Full TCP sweep, UDP top-100, and web fuzzing all run at once
   in background shells while you analyse whatever landed first. Never idle
   waiting on a single scan.
3. **Time-box rabbit holes to ~15 minutes.** If a lead has not produced a
   concrete artifact (a credential, a file read, a shell) in that window, log it
   as `PARKED` in FINDINGS.md and switch to the next-best lead. Come back only
   after the other leads are exhausted.
4. **Enumerate before exploiting.** On a lab box the intended path is almost
   always visible in banners, versions, vhosts, SMB shares, or a comment in
   HTML. Reach for a public exploit only after you have a version number.
5. **Every claim needs evidence.** A finding is real when you have command
   output proving it. Write the proof into `scans/` and reference the file.
6. **Prefer manual exploitation over frameworks** — a hand-written request or a
   short Python PoC is faster to debug and far more legible in a demo than
   `msfconsole`.
7. **Come back to the operator only for:** VPN down, target unreachable for
   >5 min (machine may need a reset), a genuine scope question, or three full
   loops with zero new leads. Everything else you decide yourself.

## Findings ledger

Create `FINDINGS.md` at the start and append after every meaningful discovery.
This file is the demo — keep it clean and readable.

```markdown
# <machine> — <ip>
Started: <UTC timestamp>

| # | Time | Phase | Finding | Evidence | Status |
|---|------|-------|---------|----------|--------|
| 1 | 14:02 | recon | 22/tcp OpenSSH 8.2p1, 80/tcp Apache 2.4.41 | scans/nmap-tcp.txt | CONFIRMED |
| 2 | 14:09 | web | /backup.zip directory listing exposed | scans/feroxbuster-80.txt | CONFIRMED |
| 3 | 14:15 | web | Suspected SSTI in /search q= | scans/ssti-probe.txt | PARKED |

## Access
- [ ] foothold — <user>@<host> via <vector>
- [ ] user.txt — <hash>
- [ ] privesc — <vector>
- [ ] root.txt — <hash>

## Credentials
| user | secret | source | works on |
```

Status values: `CONFIRMED` (proven), `LEAD` (worth chasing), `PARKED`
(time-boxed out), `DEAD` (ruled out — record why, it stops you re-testing it).

## The loop

Run this cycle; each pass should either produce access or new leads.

### 1. Recon
Fast top-ports scan first so you have something to work with in ~30s, then a
full-range scan in the background. Add the machine's hostname and any vhosts to
the container's `/etc/hosts` immediately — half of all HTB web paths are
vhost-gated. See `references/recon.md`.

### 2. Service enumeration
One track per open port, in parallel. Web gets directory + vhost fuzzing and a
manual read of the actual pages. SMB/NFS/FTP get anonymous-access checks.
Anything with a version number gets a `searchsploit` lookup. See
`references/services.md` and `references/web.md`.

### 3. Foothold
Exploit the most promising lead. Catch shells with a listener you started
beforehand; upgrade to a PTY the moment you land. Log the exact reproduction
steps — the demo value is in the chain being explainable. See
`references/foothold.md`.

### 4. Local enumeration and lateral movement
Read `user.txt` and log its hash. Then enumerate as the current user before
reaching for privesc scripts: home directories, config files with credentials,
readable databases, `sudo -l`, cron, running processes. Reuse every credential
you find against every service and user — password reuse is the most common
intended path. See `references/privesc-linux.md`,
`references/privesc-windows.md`, `references/ad.md`.

### 5. Privilege escalation
Work the enumeration output, not a blind exploit list. Prefer misconfiguration
(sudo rule, SUID binary, writable service, cron script, capability, token) over
kernel exploits — labs rarely intend a kernel exploit and it often breaks the
box. Read `root.txt`.

### 6. Report and write-up
When both flags are captured, produce **two** documents next to the ledger —
they have different audiences and must not be merged:

- `REPORT.md` — the defender's document: attack chain as a numbered path, each
  step with its evidence file, findings with impact and remediation, and the
  single control that would have broken the chain earliest.
  See `references/reporting.md`.
- `WRITEUP.md` — the teaching document: the narrative of how the box fell,
  including the leads that failed and why. Flags redacted; publishable only if
  the machine is confirmed retired. See `references/writeup.md`.

Write both without being asked. The engagement is not finished at `root.txt`.

## Common failure modes on lab boxes

- Machine unresponsive after a while → it was reset or expired; ask the operator
  to re-spawn, do not spend twenty minutes debugging your tooling.
- Web app 302s everything → you are missing a vhost or a `Host:` header.
- Exploit PoC "does not work" → check the reverse-shell IP is your `tun0`
  address, not the container's Docker IP. `htb x "ip -4 addr show tun0"`.
- Reverse shell dies instantly → the payload needs URL-encoding, or the target
  has no `bash`. Try `sh`, `nc -e`, `mkfifo`, or a Python one-liner.
- Everything filtered → the machine may not be started on the HTB panel.

## References

Read these on demand, not upfront:

- `references/recon.md` — scan strategy, hostname/vhost handling
- `references/web.md` — directory/vhost fuzzing, common web vulns, auth bypass
- `references/services.md` — per-port playbooks (SMB, FTP, SSH, DNS, SNMP, LDAP, SQL, Redis, RPC, WinRM)
- `references/foothold.md` — reverse shells, TTY upgrade, file transfer both ways
- `references/artifacts.md` — mining recovered files (pcaps, archives, git, key material) for credentials
- `references/privesc-linux.md` — sudo, SUID, capabilities, cron, containers
- `references/privesc-windows.md` — tokens, services, AlwaysInstallElevated, UAC
- `references/ad.md` — AS-REP/Kerberoast, BloodHound-less enumeration, DCSync
- `references/pivoting.md` — chisel, ssh tunnels, proxychains
- `references/reporting.md` — defender-facing report structure
- `references/writeup.md` — publishable write-up structure and redaction rules
