```
                                 dP
                                 88
    88d888b. dP  dP  dP 88d888b. 88 .d8888b. .d8888b. 88d888b.
    88'  `88 88  88  88 88'  `88 88 88'  `88 88'  `88 88'  `88
    88.  .88 88.88b.88' 88    88 88 88.  .88 88.  .88 88.  .88
    88Y888P' 8888P Y8P  dP    dP dP `88888P' `88888P' 88Y888P'
    88                                                88
    dP                                                dP

    v1.1.0 by Eurico Nicacio (h3llh0und)
    autonomous lab-machine engagement loop
```

An autonomous lab-machine engagement kit for Claude Code: a disposable Kali
container, a skill that drives it, and a slash command that turns "here is an
IP" into a full recon → foothold → privilege-escalation → cleanup → report run
you can watch happen.

```
> /pwnloop 10.129.50.240

  [recon]    3 ports — 21 vsftpd 3.0.3, 22 OpenSSH 8.2p1, 80 Gunicorn
  [web]      /capture → 302 /data/1 — sequential id, no ownership check
  [web]      /data/0 belongs to another user. IDOR confirmed
  [analysis] pcap holds a cleartext FTP login
  [foothold] password reused on SSH
             user.txt — <32-hex-flag>
  [privesc]  cap_setuid on /usr/bin/python3.8
             root.txt — <32-hex-flag>
  [cleanup]  1 artifact removed, verified
```

> **Authorized targets only.** This is built for Hack The Box, TryHackMe and
> similar training platforms, and for lab environments you own. The skill
> refuses public IPs and third-party domains without explicit authorization.
> Nothing here is novel offensive capability — it is standard Kali tooling with
> an agent driving it. Running it against systems you do not have written
> permission to test is a crime in most jurisdictions.

---

## Contents

- [Loop engineering](#loop-engineering)
- [Requirements](#requirements)
- [Install](#install)
- [VPN](#vpn)
- [Running an engagement](#running-an-engagement)
- [What you get](#what-you-get)
- [Command reference](#command-reference)
- [Cleanup policy](#cleanup-policy)
- [What is in the container](#what-is-in-the-container)
- [The skill](#the-skill)
- [What this is not](#what-this-is-not)
- [Platform rules](#platform-rules)
- [Troubleshooting](#troubleshooting)

---

## Loop engineering

An agent is a loop: observe, decide, act, verify, repeat. In practice most
agent failures are not model failures — they are **loop** failures. The loop
does not terminate, or it terminates too early. It re-derives what it already
knew because nothing was written down. It cycles through the same three ideas
because nothing records that an idea was already ruled out. It acts on state it
inferred rather than state it observed.

So `skills/pwnloop/SKILL.md` is not written as a prompt. It is written as a
control structure, and every rule in it exists to make the loop converge:

| loop property | how it is enforced |
|---|---|
| **State** | `FINDINGS.md` is an append-only ledger and the engagement directory holds every artifact. The loop reads its own state instead of reconstructing it, and a run survives a context reset. |
| **Termination** | The run ends at both flags **plus** cleanup verified **plus** report and write-up written — not at `root.txt`. An underspecified end condition is why agents stop three steps early. |
| **Divergence guard** | Any lead that has produced no concrete artifact in ~15 minutes is marked `PARKED` and the loop moves on. Without this the agent will spend an hour on the most *interesting* lead rather than the most *productive* one. |
| **Cycle prevention** | The status lattice is `LEAD → CONFIRMED / PARKED / DEAD`. `DEAD` carries the reason it was ruled out, which is what stops the loop re-testing it on the next pass. |
| **Grounding invariant** | No finding without an evidence file. This is the rule that keeps the loop operating on observed state rather than plausible state — the single highest-value constraint in the whole document. |
| **Concurrency** | Full-port, UDP and web scans run at once rather than in sequence, so wall-clock is bounded by the slowest branch, not their sum. |
| **Escalation predicate** | Exactly four conditions return control to the human: VPN down, target unreachable >5 min, a scope question, or three passes with no new leads. Everything else the loop decides. Broad escalation criteria are how "autonomous" degrades into a chat session. |

The second loop is the one around the first. Every engagement is required to
change the methodology before it closes out: a pattern that generalises is
appended to memory — which the *next* engagement reads before it starts — a
missing tool becomes a package, a technique becomes a reference section, a
mistake becomes a rule. Memory is deliberately short and holds no machine
specifics, no credentials and no flags; an entry earns its place only if a run
against a different box could act on it.

Memory is split so that your clone and this repository never fight:

| file | owner | conflicts on `git pull` |
|---|---|---|
| [`memory/patterns.md`](memory/patterns.md) | upstream, curated | never — runs do not write here |
| `memory/local.md` | you, created at install | never — upstream does not ship it |

Your runs write to `local.md`; both files are read before every engagement. Same
split for `docker/packages.local.txt`, which the image installs after the shared
list. `pwnloop ship` commits and pushes both to *your* remote after a leak
check. If one of your entries generalises beyond your own lab, open a pull
request moving it into `patterns.md` — that is how the shared methodology
improves from other people's engagements and not only mine.

Re-running a target is the measurement rather than a repeat: same box, changed
methodology, and the ledger records what memory short-circuited and what stayed
slow anyway. The second half is the useful one — a phase that is still slow
across two runs is the next thing to fix.

Four machines have produced a dozen such changes — packages that were missing
when credential reuse, pcap analysis or PDF extraction needed them; a preset git
identity, without which `git commit-tree` refuses and plumbing-based
exploitation is impossible; the fact that `sed -i` cannot edit a bind-mounted
`/etc/hosts`; and techniques promoted into references after they worked.

The one worth singling out is a **deletion**. An earlier run left the rule "fix
Kerberos skew with `ntpdate -u <dc>`". A later one proved that cannot work — the
container has no `CAP_SYS_TIME`, so `ntpdate` measures the offset and then fails
to apply it — and would have blocked PKINIT outright. That entry was removed and
replaced with a `faketime` shim. A loop that only accumulates gets worse over
time; the interesting property is that it can also take something out.

That is the actual claim of this repository. Not that an agent can solve a lab
machine — that is a demo. The claim is that the loop gets measurably better
every time it runs, because the run is required to write back into it.

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
git clone <this-repo> ~/pwnloop
cd ~/pwnloop
./install.sh
```

`install.sh` symlinks `skills/pwnloop` into `~/.claude/skills/` and
`commands/pwnloop.md` into `~/.claude/commands/`, then builds and starts the
container. Use `./install.sh --no-build` to link only.

**Then trust the directory once — this step is not optional:**

```bash
cd ~/pwnloop && claude      # accept the trust dialog, then exit
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
./bin/pwnloop status
```

## VPN

The VPN runs **inside the container**. Your Mac's routing table is never
touched, and closing your laptop's other connections has no effect on it.

### Connect

Download the OpenVPN profile from your platform (on HTB: *Connect to HTB* →
*Machines* → *OpenVPN* → download `.ovpn`), then:

```bash
cp ~/Downloads/lab_yourname.ovpn ~/pwnloop/vpn/
~/pwnloop/bin/pwnloop vpn lab_yourname.ovpn
```

The profile must be inside `~/pwnloop/vpn/` — that directory is mounted
read-only into the container at `/vpn`, and it is gitignored.

### Verify

```bash
~/pwnloop/bin/pwnloop vpn-status
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
~/pwnloop/bin/pwnloop vpn-stop
```

### Switch server or profile

Stop the current connection first — two OpenVPN processes will fight over the
routing table:

```bash
~/pwnloop/bin/pwnloop vpn-stop
cp ~/Downloads/lab_other-server.ovpn ~/pwnloop/vpn/
~/pwnloop/bin/pwnloop vpn lab_other-server.ovpn
```

### Important: the VPN dies with the container

`pwnloop down`, `pwnloop build` followed by a container recreate, or a Docker restart
all kill the connection. Reconnect afterwards:

```bash
~/pwnloop/bin/pwnloop down && ~/pwnloop/bin/pwnloop up
~/pwnloop/bin/pwnloop vpn lab_yourname.ovpn
```

## Running an engagement

Spawn the machine on the platform, then:

```bash
cd ~/pwnloop && claude
> /pwnloop 10.129.50.240
```

**Pass the address only — not the machine's name.** The name is the strongest
recall trigger there is: a well-known one returns its published chain before a
port has been scanned. Withholding it means the agent can only recognise the box
*after* enumeration has earned the fingerprint, by which point the search order
was set honestly. It is the one control on recall that you can enforce rather
than trust.

The agent verifies the VPN and reachability, creates
`engagements/10-129-50-240/`, and works from there without stopping between phases. It
announces each flag in chat the moment it reads it, so you can paste it into
the platform without waiting for the run to finish.

To watch the run rather than the transcript, tail the ledger in another window —
this is also what to project if you are demonstrating to an audience:

```bash
tail -f ~/pwnloop/engagements/10-129-50-240/FINDINGS.md
```

It will come back to you only for: VPN down, target unreachable for more than
five minutes (the machine probably needs a reset), a genuine scope question, or
three full enumeration loops with no new leads.

## What you get

```
engagements/<address>/
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

Two directories in the repository are written *by* engagements rather than for
them: [`memory/patterns.md`](memory/patterns.md), the cross-engagement pattern
file the next run reads first, and [`writeups/`](writeups/), publication-ready
copies that have been through the redaction step.

`REPORT.md` and `WRITEUP.md` are deliberately separate documents. The report
argues to a defender: what is broken, what it costs, what to fix, and which
single control would have broken the chain earliest. The write-up teaches a
reader: how the box fell, and — the part most write-ups omit — which leads were
dead ends and why. Merging them serves neither audience.

```bash
~/pwnloop/bin/pwnloop flags     # all captured flags, newest engagement last
```

## Command reference

```
pwnloop build              rebuild the image
pwnloop up                 create/start the container
pwnloop down               stop and remove the container (kills the VPN)
pwnloop sh                 interactive shell inside the container
pwnloop x '<cmd>'          run one command inside the container
pwnloop vpn <file.ovpn>    start OpenVPN inside the container
pwnloop vpn-status         tun0 address and last OpenVPN log lines
pwnloop vpn-stop           stop the VPN
pwnloop status             image, container, tooling and VPN summary
pwnloop flags              show locally captured flags
pwnloop engagements        list past engagements and what each one was
pwnloop banner             print the startup banner
pwnloop ship [msg]         commit and push your learnings to your own remote
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
`krb5-user`, `hydra`, `john`, `hashcat`, `cewl`, `responder`, `sshpass`, `swaks`,
`searchsploit`, `git-dumper`, `ldapdomaindump`, `tshark`, `tcpdump`, `binwalk`,
`exiftool`, `gdb`, `pwntools`, `proxychains4`, `chisel`, SecLists and an
uncompressed rockyou, plus `linpeas` / `winPEAS` / `pspy` staged under
`/opt/static` for delivery to targets.

Adding tooling: edit `docker/packages.txt`, then `pwnloop build`. A package with no
build for your architecture is logged to `/opt/skipped-packages.txt` inside the
image rather than failing the build — check it after a rebuild.

## The skill

`skills/pwnloop/SKILL.md` defines the operating contract: scope checks,
autonomy rules, flag handling, the findings-ledger format, the engagement loop,
and the cleanup and close-out steps. Methodology lives in `references/`, loaded
on demand rather than all at once:

| file | covers |
|------|--------|
| `recon.md` | layered scanning, vhost/hostname handling, port triage |
| `web.md` | fuzzing strategy, LFI/SSTI/upload/SQLi/deserialization |
| `api.md` | REST/GraphQL discovery, JWT attacks, IDOR, race conditions, SSRF |
| `source-review.md` | reading recovered source: secrets in history, sinks, authorization gaps |
| `cracking.md` | hash identification, john/hashcat formats, spraying strategy |
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

## What this is not

Scope discipline is what keeps this useful, so the exclusions are deliberate
rather than pending:

- **No command-and-control, EDR evasion, or malware development.** Lab machines
  do not require them, and a repository that ships them is a different kind of
  artifact with a different set of obligations.
- **No phishing or social-engineering infrastructure.** There is no human on the
  other side of a lab box.
- **No mobile, blockchain, or cloud-provider assessment.** Different targets,
  different tooling, no shared loop with a single-host engagement.
- **No write-up lookup, and no acting on recall.** Fetching someone else's
  solution mid-run would raise the completion rate and destroy the only thing
  being demonstrated. Prior knowledge of a well-known machine is not removable,
  so the skill handles it by rule instead: every action must trace to an artifact
  already collected, and recognition of the target must be declared at the top of
  the ledger. See *Discovery discipline* in `SKILL.md`. Researching a
  technology — a CVE, a protocol, an exploit's source — is the opposite of this
  and is expected.
- **No log or audit tampering.** Cleanup removes the operator's artifacts and
  nothing else — see [Cleanup policy](#cleanup-policy).

Other Claude Code security repositories cover several of these well and at much
greater breadth; `pwnloop` is deliberately one workflow done thoroughly rather
than thirty covered thinly.

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
| Permission prompt on every command | workspace not trusted | `cd ~/pwnloop && claude`, accept the dialog |
| `tun0: down` after a rebuild | the VPN lives in the container | `pwnloop vpn <file.ovpn>` again |
| Target unreachable, VPN up | machine not spawned, or expired | re-spawn it on the platform |
| Web app 302s everything | vhost gating | add the hostname to the container's `/etc/hosts`, then fuzz `Host:` for more |
| Reverse shell never connects | payload points at the container IP | use the `tun0` address: `pwnloop x "ip -4 addr show tun0"` |
| `sed -i` fails on `/etc/hosts` | bind-mounted file cannot be renamed | append instead of editing in place |
| A tool is missing | not in `packages.txt`, or no build for your arch | add it and `pwnloop build`; check `/opt/skipped-packages.txt` |

## Keeping engagement data out of the repository

`install.sh` links `hooks/pre-commit`, which refuses a commit that contains a
flag-shaped string, a path under `engagements/` or `vpn/`, private key material,
or an attacker VPN address. The `.gitignore` is the first line of defence and
this is the second, because the realistic failure is the maintainer pasting
engagement output into a reference file — not an outsider.

```bash
git commit --no-verify     # bypass, when you are deliberately adding a placeholder
```

On the GitHub side, enable **secret scanning with push protection** (free for
public repositories). It catches token-shaped secrets the hook does not know
about; the hook catches flags and lab credentials that GitHub does not recognise
as secrets. They cover different halves of the problem.

## Versioning

The version lives in [`VERSION`](VERSION), is printed by `pwnloop banner`, and
is tagged in git. Changes are recorded in [`CHANGELOG.md`](CHANGELOG.md), which
also explains what major, minor and patch mean for a methodology rather than a
library — briefly: major breaks a workflow, minor adds capability, patch fixes
something upstream broke.

Because engagements are required to write back into the methodology, minor
releases are the normal cadence. What earns a changelog entry is what a run
*changed*, not that a run happened.

## License

MIT — see [LICENSE](LICENSE).
