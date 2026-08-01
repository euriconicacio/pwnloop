# htb-lab

An autonomous lab-machine engagement kit for Claude Code: a disposable Kali
container, a skill that drives it, and a slash command that turns "here is an
IP" into a full recon → foothold → privilege-escalation → cleanup → report run
you can watch happen.

> **Authorized targets only.** This is built for Hack The Box, TryHackMe and
> similar training platforms, and for lab environments you own. The skill
> refuses public IPs and third-party domains without explicit authorization.
> Nothing here is novel offensive capability — it is standard Kali tooling with
> an agent driving it. Running it against systems you do not have written
> permission to test is a crime in most jurisdictions.

---

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [VPN](#vpn)
- [Running an engagement](#running-an-engagement)
- [What you get](#what-you-get)
- [Command reference](#command-reference)
- [Cleanup policy](#cleanup-policy)
- [What is in the container](#what-is-in-the-container)
- [The skill](#the-skill)
- [Platform rules](#platform-rules)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- **Docker** — OrbStack, Docker Desktop or Colima. The image is built for the
  host's native architecture; on Apple Silicon it is arm64 with no emulation.
- **Claude Code** — the skill and slash command are linked into `~/.claude/`.
- **A VPN profile** from your lab platform (`.ovpn`).

Nothing is installed on the host itself. All offensive tooling, and the VPN
connection, live inside the container.

### Why a container

macOS is a poor host for offensive tooling: much of the toolchain is Linux-only,
the useful builds are Debian packages, and a lab VPN connection rewrites your
host's routing table. The container gets `NET_ADMIN` and `/dev/net/tun`, so
OpenVPN runs inside it and the lab network never touches the host. Tear the
container down and every trace of the engagement's tooling goes with it.

## Install

```bash
git clone <this-repo> ~/htb-lab
cd ~/htb-lab
./install.sh
```

`install.sh` symlinks `skills/htb-machine` into `~/.claude/skills/` and
`commands/htb.md` into `~/.claude/commands/`, then builds and starts the
container. Use `./install.sh --no-build` to link only.

**Then trust the directory once — this step is not optional:**

```bash
cd ~/htb-lab && claude      # accept the trust dialog, then exit
```

Until you do, Claude Code ignores `.claude/settings.json` and prompts for
permission on every single command, which makes autonomous runs unusable. You
will see this warning if you skipped it:

```
Ignoring N permissions.allow entries from .claude/settings.json:
this workspace has not been trusted.
```

Verify the whole setup:

```bash
./bin/htb status
```

## VPN

The VPN runs **inside the container**. Your Mac's routing table is never
touched, and closing your laptop's other connections has no effect on it.

### Connect

Download the OpenVPN profile from your platform (on HTB: *Connect to HTB* →
*Machines* → *OpenVPN* → download `.ovpn`), then:

```bash
cp ~/Downloads/lab_yourname.ovpn ~/htb-lab/vpn/
~/htb-lab/bin/htb vpn lab_yourname.ovpn
```

The profile must be inside `~/htb-lab/vpn/` — that directory is mounted
read-only into the container at `/vpn`, and it is gitignored.

### Verify

```bash
~/htb-lab/bin/htb vpn-status
```

A working connection shows a `tun0` address in the lab range and
`Initialization Sequence Completed` in the log:

```
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 ...
    inet 10.10.14.205/23 brd 10.10.15.255 scope global tun0
--- last log ---
... Initialization Sequence Completed
```

That `tun0` address is your attacker IP — it is what reverse shells must call
back to. The agent reads it automatically; you need it only if you are running
payloads by hand.

### Disconnect

```bash
~/htb-lab/bin/htb vpn-stop
```

### Switch server or profile

Stop the current connection first — two OpenVPN processes will fight over the
routing table:

```bash
~/htb-lab/bin/htb vpn-stop
cp ~/Downloads/lab_other-server.ovpn ~/htb-lab/vpn/
~/htb-lab/bin/htb vpn lab_other-server.ovpn
```

### Important: the VPN dies with the container

`htb down`, `htb build` followed by a container recreate, or a Docker restart
all kill the connection. Reconnect afterwards:

```bash
~/htb-lab/bin/htb down && ~/htb-lab/bin/htb up
~/htb-lab/bin/htb vpn lab_yourname.ovpn
```

## Running an engagement

Spawn the machine on the platform, then:

```bash
cd ~/htb-lab && claude
> /htb 10.129.50.240 cap
```

The agent verifies the VPN and reachability, creates
`engagements/cap/`, and works from there without stopping between phases. It
announces each flag in chat the moment it reads it, so you can paste it into
the platform without waiting for the run to finish.

To watch the run rather than the transcript, tail the ledger in another window —
this is also what to project if you are demonstrating to an audience:

```bash
tail -f ~/htb-lab/engagements/cap/FINDINGS.md
```

It will come back to you only for: VPN down, target unreachable for more than
five minutes (the machine probably needs a reset), a genuine scope question, or
three full enumeration loops with no new leads.

## What you get

```
engagements/<machine>/
  FINDINGS.md    append-only ledger, updated live — findings, evidence, status
  REPORT.md      defender-facing: chain, impact, remediation, earliest break point
  WRITEUP.md     teaching-facing: the narrative, including the leads that failed
  scans/         raw tool output, one file per run
  loot/          credentials, hashes, keys, downloaded artifacts
  www/           payloads staged for delivery to the target
flags.local.md   every flag captured, across all machines — gitignored
```

`engagements/`, `flags.local.md` and `vpn/` are gitignored and must stay that
way. Flag values never enter version control.

`REPORT.md` and `WRITEUP.md` are deliberately separate documents. The report
argues to a defender: what is broken, what it costs, what to fix, and which
single control would have broken the chain earliest. The write-up teaches a
reader: how the box fell, and — the part most write-ups omit — which leads were
dead ends and why. Merging them serves neither audience.

```bash
~/htb-lab/bin/htb flags     # all captured flags, newest engagement last
```

## Command reference

```
htb build              rebuild the image
htb up                 create/start the container
htb down               stop and remove the container (kills the VPN)
htb sh                 interactive shell inside the container
htb x '<cmd>'          run one command inside the container
htb vpn <file.ovpn>    start OpenVPN inside the container
htb vpn-status         tun0 address and last OpenVPN log lines
htb vpn-stop           stop the VPN
htb status             image, container, tooling and VPN summary
htb flags              show locally captured flags
```

## Cleanup policy

The agent removes what it created — web shells, planted SSH keys, accounts and
repositories, staging directories — as a standard final step, then verifies each
removal and records it in the report. You do not have to ask.

It does **not** touch logs or audit records. The engagement's footprint in them
is the defender's evidence and part of what makes the exercise worth anything.

If an artifact must stay (removing it would break the machine, or you want to
re-run the chain), the agent says so explicitly and gives the exact command to
remove it later.

## What is in the container

`nmap`, `masscan`, `ffuf`, `feroxbuster`, `gobuster`, `nikto`, `whatweb`,
`wfuzz`, `sqlmap`, `wpscan`, `netexec`, `smbclient`, `smbmap`, `enum4linux-ng`,
`impacket-scripts`, `evil-winrm`, `certipy`, `bloodhound-python`, `ldap-utils`,
`krb5-user`, `hydra`, `john`, `sshpass`, `searchsploit`, `tshark`, `tcpdump`,
`binwalk`, `exiftool`, `proxychains4`, `chisel`, SecLists and an uncompressed
rockyou, plus `linpeas` / `winPEAS` / `pspy` staged under `/opt/static` for
delivery to targets.

Adding tooling: edit `docker/packages.txt`, then `htb build`. A package with no
build for your architecture is logged to `/opt/skipped-packages.txt` inside the
image rather than failing the build — check it after a rebuild.

## The skill

`skills/htb-machine/SKILL.md` defines the operating contract: scope checks,
autonomy rules, flag handling, the findings-ledger format, the engagement loop,
and the cleanup and close-out steps. Methodology lives in `references/`, loaded
on demand rather than all at once:

| file | covers |
|------|--------|
| `recon.md` | layered scanning, vhost/hostname handling, port triage |
| `web.md` | fuzzing strategy, LFI/SSTI/upload/SQLi/deserialization |
| `services.md` | per-port playbooks: SMB, FTP, SNMP, LDAP, NFS, SQL, Redis, WinRM |
| `foothold.md` | reverse shells, TTY upgrade, file transfer both directions |
| `artifacts.md` | mining downloaded files — pcaps, archives, git history, key material |
| `privesc-linux.md` | sudo, SUID, capabilities, cron and timers, container escapes |
| `privesc-windows.md` | token privileges, services, credential hunting |
| `ad.md` | AS-REP roasting, Kerberoast, ACL abuse, DCSync, ADCS |
| `pivoting.md` | chisel, SSH tunnels, proxychains |
| `reporting.md` | chain-first, defender-facing report structure |
| `writeup.md` | publishable write-up structure and redaction rules |

The design choices that matter for autonomy: **never stop between phases**,
**parallelize scans instead of waiting**, **time-box any lead to ~15 minutes**
before parking it, and **every finding needs an evidence file**. Without the
time-box the agent spends an hour on a promising-looking dead end; without the
evidence rule it reports things it merely inferred.

## Platform rules

This repository contains tooling and methodology, not solutions, and publishing
it breaks no platform rule. What you produce with it is a different matter — on
Hack The Box specifically:

- Solutions, write-ups and streams are allowed **only for content confirmed
  retired**. Sharing how you solved active Machines, Challenges, Sherlocks or
  Pro Labs is prohibited.
- "Expired" is not "retired". An expired machine has merely stopped counting
  toward seasonal points and may still be active — check the status explicitly
  before you publish anything about it.
- Flags are never shareable, whatever the target's status. They are written to
  `flags.local.md` and the engagement directory, both gitignored; redaction is a
  publication step, so the local copies stay complete.

Use this in accordance with the terms of service of whatever platform you point
it at, and only against targets you are authorized to test.

## Troubleshooting

| symptom | cause | fix |
|---------|-------|-----|
| Permission prompt on every command | workspace not trusted | `cd ~/htb-lab && claude`, accept the dialog |
| `tun0: down` after a rebuild | the VPN lives in the container | `htb vpn <file.ovpn>` again |
| Target unreachable, VPN up | machine not spawned, or expired | re-spawn it on the platform |
| Web app 302s everything | vhost gating | add the hostname to the container's `/etc/hosts`, then fuzz `Host:` for more |
| Reverse shell never connects | payload points at the container IP | use the `tun0` address: `htb x "ip -4 addr show tun0"` |
| `sed -i` fails on `/etc/hosts` | bind-mounted file cannot be renamed | append instead of editing in place |
| A tool is missing | not in `packages.txt`, or no build for your arch | add it and `htb build`; check `/opt/skipped-packages.txt` |

## License

MIT.
