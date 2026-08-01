# htb-lab

An autonomous lab-machine engagement setup for Claude Code: a disposable Kali
container, a skill that drives it, and a slash command that turns "here is an
IP" into a full recon → foothold → privilege-escalation → report run you can
watch happen.

> **Authorized targets only.** This is built for Hack The Box, TryHackMe and
> similar training platforms, and for lab environments you own. The skill refuses public IPs
> and third-party domains without explicit authorization. Nothing here is novel
> offensive capability — it is standard Kali tooling with an agent driving it.
> Running it against systems you do not have written permission to test is a
> crime in most jurisdictions.

## Platform rules

This repository contains tooling and methodology, not solutions, and publishing
it breaks no platform rule. What you produce with it is a different matter — on
Hack The Box specifically:

- Solutions, writeups and streams are allowed **only for content confirmed
  retired**. Sharing how you solved active Machines, Challenges, Sherlocks or
  Pro Labs is prohibited.
- "Expired" is not "retired". An expired machine has merely stopped counting
  toward seasonal points and may still be active — check the status explicitly
  before you publish anything about it.
- Flags are never shareable, whatever the target's status. The report template
  keeps flag hashes in the local engagement directory and tells you to strip
  them from anything you distribute.
- `engagements/` is gitignored for exactly this reason. Keep it that way.

Use this in accordance with the terms of service of whatever platform you point
it at, and only against targets you are authorized to test.

## Why a container

macOS is a poor host for offensive tooling: half the toolchain is Linux-only,
the useful builds are Debian packages, and an HTB VPN connection rewrites your
host's routing table. The container gets `NET_ADMIN` and `/dev/net/tun`, so
OpenVPN runs inside it and the lab network never touches the host. On Apple
Silicon the image is native arm64 — no emulation, no performance penalty.

## Install

```bash
git clone <this-repo> ~/htb-lab
cd ~/htb-lab
./install.sh
```

This symlinks the skill into `~/.claude/skills/htb-machine` and the command into
`~/.claude/commands/htb.md`, then builds and starts the container. Requires
Docker (OrbStack, Docker Desktop, or Colima).

## Use

```bash
# 1. drop your HTB VPN profile in place
cp ~/Downloads/lab_yourname.ovpn ~/htb-lab/vpn/

# 2. connect
~/htb-lab/bin/htb vpn lab_yourname.ovpn
~/htb-lab/bin/htb vpn-status          # expect a tun0 address

# 3. spawn a machine on the platform, then hand Claude the IP
cd ~/htb-lab && claude
> /htb 10.10.11.42 machinename
```

The agent creates `engagements/machinename/` and works there. Open
`engagements/machinename/FINDINGS.md` in another window — it is an append-only
ledger updated as discoveries land, and it is the thing to project if you are
demonstrating this to an audience.

When both flags are captured it writes two more files without being asked:
`REPORT.md` (the defender's view — chain, impact, remediation) and `WRITEUP.md`
(the teaching view — the narrative including the leads that failed, flags
redacted).

## The `htb` wrapper

```
htb build              rebuild the image
htb up / down          create-start / remove the container
htb sh                 interactive shell inside the container
htb x '<cmd>'          run one command inside the container
htb vpn <file.ovpn>    start OpenVPN in the container
htb vpn-status         tun0 address and last OpenVPN log lines
htb status             image, container, tooling and VPN summary
```

## What is in the box

`nmap`, `masscan`, `ffuf`, `feroxbuster`, `gobuster`, `nikto`, `whatweb`,
`wfuzz`, `sqlmap`, `wpscan`, `netexec`, `smbclient`, `smbmap`, `enum4linux-ng`,
`impacket-scripts`, `evil-winrm`, `certipy`, `bloodhound-python`, `ldap-utils`,
`krb5-user`, `hydra`, `john`, `searchsploit`, `proxychains4`, `chisel`,
SecLists and rockyou, plus `linpeas` / `winPEAS` / `pspy` staged under
`/opt/static` for delivery to targets.

Adding tooling: edit `docker/packages.txt` and `htb build`. A package that has
no arm64 build is logged to `/opt/skipped-packages.txt` inside the image instead
of failing the build.

## The skill

`skills/htb-machine/SKILL.md` defines the operating contract — scope checks,
autonomy rules, the findings-ledger format, and the engagement loop. Methodology
lives in `references/`, loaded on demand rather than all at once:

| file | covers |
|------|--------|
| `recon.md` | layered scanning, vhost/hostname handling, port triage |
| `web.md` | fuzzing strategy, LFI/SSTI/upload/SQLi/deserialization |
| `services.md` | per-port playbooks: SMB, FTP, SNMP, LDAP, NFS, SQL, Redis, WinRM |
| `foothold.md` | reverse shells, TTY upgrade, file transfer both directions |
| `artifacts.md` | mining downloaded files — pcaps, archives, git history, key material |
| `privesc-linux.md` | sudo, SUID, capabilities, cron, container escapes |
| `privesc-windows.md` | token privileges, services, credential hunting |
| `ad.md` | AS-REP roasting, Kerberoast, ACL abuse, DCSync, ADCS |
| `pivoting.md` | chisel, SSH tunnels, proxychains |
| `reporting.md` | chain-first, defender-facing report structure |
| `writeup.md` | publishable write-up structure, including redaction rules |

The design choices that matter for autonomy: **never stop between phases**,
**parallelize scans instead of waiting**, **time-box any lead to ~15 minutes**
before parking it, and **every finding needs an evidence file**. Without the
time-box the agent will spend an hour on a promising-looking dead end; without
the evidence rule it will report things it merely inferred.

## Permissions

`.claude/settings.json` allowlists the `htb` wrapper so the agent is not
prompted on every command, while keeping the blast radius inside the container.
It is deliberately narrow — this is meant to be read before it is trusted, which
is also why the skill is hand-written rather than pulled from a marketplace.

## License

MIT.
