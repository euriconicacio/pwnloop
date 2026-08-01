---
name: pwnloop
description: Autonomously compromise a Hack The Box machine (or equivalent authorized lab target) end to end — recon, service enumeration, foothold, user flag, privilege escalation, root flag — driving Kali tooling inside the local pwnloop-box container and keeping a live findings ledger. Use whenever the user gives a lab target IP/hostname and asks to enumerate, exploit, "solve", "own", "root" or pentest it, or mentions HTB / Hack The Box / TryHackMe / a retired machine.
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

All offensive tooling lives in the `pwnloop-box` container, never on the macOS host.

```bash
~/pwnloop/bin/pwnloop x '<command>'      # run inside the container
~/pwnloop/bin/pwnloop vpn-status         # tun0 + HTB reachability
```

Working directory for the engagement, inside the container and mirrored on the
host at `~/pwnloop/engagements/<name>/`:

```
/engagements/<name>/
  FINDINGS.md    append-only ledger — the operator reads this live
  state.json     machine-readable current state
  scans/         raw tool output, one file per run
  loot/          creds, hashes, keys, downloaded files
  www/           payloads staged for delivery to the target
```

**Open every engagement with the banner** — it is the first command you run,
before the VPN check, and its output goes to the operator verbatim:

```bash
~/pwnloop/bin/pwnloop banner
```

Then read `~/pwnloop/memory/patterns.md`. It is short by design and it is what
earlier engagements learned — checks that paid off, primitives worth trying
early, environment gotchas. Reading it costs seconds and routinely saves a
phase.

Then verify the VPN is up and the target answers. If `tun0` is down, tell the
operator to start it (`pwnloop vpn <file.ovpn>`) — that is one of the few
legitimate blocking questions.

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
8. **Announce each flag the moment you read it**, on its own line in chat, so
   the operator can paste it into the platform without waiting for you to
   finish. Do not batch flags until the end.

## Discovery discipline

The point of this loop is to *find* the path, not to recall it. Recall is not
removable — a well-known retired machine may be familiar — so it is handled by
disclosure and by constraining what is allowed to drive the next action.

**Prefer to be given only an IP.** The machine's name is the single strongest
recall trigger there is — a well-known name returns its published chain before a
single port has been scanned. Working from an address alone means recognition can
only happen *after* enumeration has earned the fingerprint, by which point the
search order was set honestly. So:

- Name the engagement directory from the address, not from the machine:
  `/engagements/10-129-51-2/`. Do not ask the operator what the box is called.
- If the operator supplies a name anyway, use it, but record it in the ledger as
  a recall risk alongside the recognition line.
- Expect the target to identify itself mid-run — an SMB hostname, an AD domain, a
  TLS certificate. That is fine and unavoidable; at that point apply the
  recognition rule below.

**Never look up the answer.** Do not search for the machine's name together with
"writeup", "walkthrough", "solution" or "how to root". Do not open a write-up for
the target even if one surfaces incidentally. Researching a *technology* is the
opposite of this and is expected: a product's documentation, a CVE, an exploit's
source, a protocol's behaviour, what a capability or ACL actually grants. The
line is between "how does this thing work" (always allowed) and "what is the path
on this box" (never).

**Every action must trace to an artifact you already collected.** Before running
a command, you should be able to name the file and the line of output that
motivated it. If you cannot — if the reason is "this kind of box usually has X" —
you are recalling, not deducing. Go collect the observation first, and let it
either confirm or kill the idea. This is the practical difference between an
engagement and a re-enactment.

**Declare recognition the moment it happens.** If you recognise the target — at
the start, or halfway through when a hostname gives it away — write it in the
ledger before the next command:

```markdown
> Recognition: I have prior knowledge of this machine's published path. Search
> order below may be informed by it; every step is still evidenced.
```

A recognised machine is still worth running — it validates tooling and
methodology coverage. What it stops being is evidence that the loop *discovers*.
Recording that distinction is the operator's to use; hiding it makes every other
result untrustworthy.

**Do not skip an enumeration because you think you know its result.** Run the
scan, read the output. Predicting correctly costs a minute; predicting wrongly
and skipping costs the engagement.

**Log the near-miss.** If you tried something that worked but ordinary
enumeration would *not* have surfaced, that is a finding about the methodology,
not about the box. Record it as a gap and fix the methodology — the enumeration
that should have found it is missing.

## Flags

The instant a flag is readable, do three things in this order:

1. Print it in chat, alone and unadorned, so it can be copied:
   `user.txt — 0123456789abcdef0123456789abcdef`
2. Append it to `~/pwnloop/flags.local.md`, which is gitignored and never
   leaves the machine:

   ```bash
   echo "| <machine> | <ip> | user.txt | <value> | $(date -u '+%Y-%m-%d %H:%M') |" \
     >> ~/pwnloop/flags.local.md
   ```
3. Tick the matching line in the ledger's **Access** block.

Flag values belong in `flags.local.md`, in the engagement directory, and in
chat — never in anything tracked by git. Before writing an example into a
reference file or any committed document, replace it with `<32-hex-flag>`.

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

### 7. Clean up the target
Standard practice, not an optional courtesy — do it without being asked, right
after the documents are written and before the closing summary.

Every engagement leaves artifacts. Track them in the ledger as you create them
under an **Artifacts left on the target** heading, then remove them:

- web shells and uploaded files
- SSH keys you planted in any `authorized_keys`
- accounts, repositories, API tokens or scheduled jobs you created
- staging directories and any file you wrote outside `/tmp`

Remove them in reverse order of creation, using the highest privilege you
obtained, and verify each removal rather than assuming it worked. Keep the
private half of any key you generated in `loot/` — it is evidence — but delete
the public half from the target.

Two exceptions, both of which you state explicitly rather than deciding
silently: leave an artifact in place if removing it would break the machine for
the operator, and leave it if the operator has said they want to re-run the
chain. In both cases list what remains and the exact command to remove it later.

Never "clean up" by deleting logs or audit records. You are removing your own
artifacts, not covering tracks — a lab engagement's logs are the defender's
evidence and part of what makes the exercise worth anything.

### 8. Write back into the loop
Before the summary, spend a moment on what this engagement should change, and
make the changes rather than describing them:

- **A pattern that generalises** → append it to `~/pwnloop/memory/patterns.md`,
  one line, no machine specifics, no credentials, no flags. Only if a future run
  against a *different* box could act on it.
- **A tool you had to install mid-run** → add it to `docker/packages.txt`.
- **A technique that worked and is not documented** → add it to the relevant
  `references/` file.
- **A mistake you made that a rule would have prevented** → add the rule.

Nothing to add is a legitimate outcome; say so rather than inventing an entry.
A memory file padded with restatements of the obvious costs every future run.

### 9. Close out
End with a compact summary table in chat — this is what the operator reads
when they come back to the terminal:

```markdown
| machine | ip | time to root | user.txt | root.txt |
|---------|-----|--------------|----------|----------|
| <name> | 10.129.x.x | 12 min | <32-hex-flag> | <32-hex-flag> |
```

Show flag values in full in this table — the operator is pasting them into the
platform. Follow it with one line naming the escalation vector, one line stating
what was cleaned up, and the paths to `FINDINGS.md`, `REPORT.md` and
`WRITEUP.md`. Nothing longer; the documents carry the detail.

## Common failure modes on lab boxes

- Machine unresponsive after a while → it was reset or expired; ask the operator
  to re-spawn, do not spend twenty minutes debugging your tooling.
- Web app 302s everything → you are missing a vhost or a `Host:` header.
- Exploit PoC "does not work" → check the reverse-shell IP is your `tun0`
  address, not the container's Docker IP. `pwnloop x "ip -4 addr show tun0"`.
- Reverse shell dies instantly → the payload needs URL-encoding, or the target
  has no `bash`. Try `sh`, `nc -e`, `mkfifo`, or a Python one-liner.
- Everything filtered → the machine may not be started on the HTB panel.

## References

Read these on demand, not upfront:

- `references/recon.md` — scan strategy, hostname/vhost handling
- `references/web.md` — directory/vhost fuzzing, common web vulns, auth bypass
- `references/api.md` — REST/GraphQL discovery, JWT attacks, IDOR, race conditions, SSRF
- `references/source-review.md` — reading recovered source: secrets, sinks, authorization gaps
- `references/cracking.md` — hash identification, john/hashcat formats, spraying strategy
- `references/services.md` — per-port playbooks (SMB, FTP, SSH, DNS, SNMP, LDAP, SQL, Redis, RPC, WinRM)
- `references/foothold.md` — reverse shells, TTY upgrade, file transfer both ways
- `references/artifacts.md` — mining recovered files (pcaps, archives, git, key material) for credentials
- `references/privesc-linux.md` — sudo, SUID, capabilities, cron, containers
- `references/privesc-windows.md` — tokens, services, AlwaysInstallElevated, UAC
- `references/ad.md` — AS-REP/Kerberoast, BloodHound-less enumeration, DCSync
- `references/pivoting.md` — chisel, ssh tunnels, proxychains
- `references/reporting.md` — defender-facing report structure
- `references/writeup.md` — publishable write-up structure and redaction rules
