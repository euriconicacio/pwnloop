---
name: pwnloop
description: Autonomously compromise a Hack The Box machine (or equivalent authorized lab target) end to end — recon, service enumeration, foothold, user flag, privilege escalation, root flag — driving Kali tooling inside the local pwnloop-box container and keeping a live findings ledger. Use whenever the user gives a lab target IP/hostname and asks to enumerate, exploit, "solve", "own", "root" or pentest it, or mentions HTB / Hack The Box / TryHackMe / a retired machine.
---

# HTB machine — autonomous engagement

You are running a black-box engagement against a single lab host. The operator
wants to hand you an IP and watch. Work continuously, narrate findings as they
land, and only come back with a question when you are genuinely blocked.

## Operating contract

This is what the operator expects of the run itself, whether it was started as a
slash command or by invoking this skill directly — both must behave the same:

- **Work from the address alone.** Do not ask what the machine is called; the
  name is a recall trigger the operator is withholding on purpose. Name the
  engagement directory after the address. If the box names itself mid-run and you
  recognise it, record that in the ledger and keep going. See *Discovery
  discipline*.
- **Confirm once, in one line, then go:** VPN state, target reachability, and the
  engagement directory you created. Do not wait for acknowledgement.
- **Do not pause between phases and do not ask permission per command** — the
  target is pre-authorized. Move straight from recon into enumeration into
  exploitation.
- **Report by appending to `FINDINGS.md` as discoveries land.** In chat, give a
  one-or-two-line status at each phase transition and nothing longer — the
  operator is reading the ledger, not the chat.
- **Print each flag in chat the moment you read it,** on its own line, so it can
  be submitted while you keep working.
- **Come back only when genuinely blocked:** VPN down, target unreachable for
  >5 min (may need a platform reset), a real scope question, or three full
  enumeration loops with no new leads.

**If the target is a network rather than a host** — a CIDR, a named Pro Lab, or
an engagement already under `campaigns/` — this is the wrong skill on its own.
Use `pwnloop-lab`, which keeps the network state across sessions and calls
this loop once per host.

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

Then read **both** memory files — `~/pwnloop/memory/patterns.md` (the shared,
curated set) and `~/pwnloop/memory/local.md` (this operator's own). They are
short by design and they are what earlier engagements learned — checks that paid
off, primitives worth trying early, environment gotchas. Reading them costs
seconds and routinely saves a phase.

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
9. **Operator-in-the-loop at a genuine dead end.** On a hard machine you may
   exhaust every evidenced lead and still be one decision or one tool short. That
   is a legitimate moment to surface a *precise* status to the operator — what is
   confirmed, what is ruled out and why, and the specific fork you are stuck on —
   and to accept a steer (a technique to try, a tool to build, a decision to
   make). This is not a licence to look up the box's answer or to skip
   enumeration; it is the escape hatch for after enumeration is done. **If the
   steer brings in outside knowledge (a hint, a reference, a pointer), declare it
   in that engagement's ledger** exactly as you would declare recognition — the
   run then stops being evidence that the loop *discovered* that step, and hiding
   it makes every other result untrustworthy. Keep such assistance in the
   (gitignored) engagement ledger; do not fold it into the shared methodology
   memory as if it were a self-found pattern.

## Re-running a target

**Never write into an existing engagement directory.** If `engagements/<addr>/`
already holds a `FINDINGS.md`, the address has been engaged before — platforms
do recycle addresses. Create `engagements/<addr>-2/` (then `-3`) and start
clean. Overwriting a previous ledger destroys the only record of that run.

Correlate runs of the same machine by what recon *discovered* — the hostname,
the AD domain, the certificate subject — recorded in the ledger, never by a name
supplied up front. A re-spawn usually has a different address, so the discovered
hostname is what ties the two together, and it costs nothing in recall terms
because you found it rather than being told it.

**A re-run is the measurement, so treat it as one.** It is the only way to test
whether the loop actually improved: same target, methodology that has since
changed. When the ledger's first line notes a previous run, record at the end:

```markdown
## Replay
Previous run: engagements/<addr>/ — <time to root>, <n> PARKED, <n> DEAD
This run:     <time to root>, <n> PARKED, <n> DEAD
Short-circuited by memory: <entries that removed a step, or "none">
Still slow: <what took longest despite the methodology>
```

"Still slow" is the useful half. An entry that saved time proves the loop
learned; a phase that stayed slow across both runs is the next thing the
methodology should fix.

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
manual read of the actual pages. SMB/NFS/FTP get anonymous-access checks. See
`references/services.md` and `references/web.md`.

**Pin the exact version of every service, then hunt CVEs and PoCs — this is a
primary activity, not an afterthought.** For each service with any version
banner (and for the product even when the banner is vague, e.g. "Samba 4"):

1. **Pin the precise version** — use protocol-specific probes, not just the
   nmap `-sV` guess (`smbclient`/`rpcclient` for Samba, HTTP headers/`/version`
   endpoints for web apps, package strings, TLS certs). "Samba 4" is not a
   version; get `4.x.y`.
2. **`searchsploit <product>`** for the offline copy — but know it is stale.
3. **Web + GitHub search for CVEs and public PoCs** — `searchsploit` will not
   have anything recent. Search `"<product> <version> CVE"`, the vendor
   advisories, and **GitHub for a PoC** (`<product> CVE-XXXX-YYYY PoC`). A
   current, high-severity CVE with a public exploit is very often the intended
   foothold on a modern lab box, and it will be invisible if you only read
   banners. Read the CVE/PoC to learn the *mechanism* (which field is the sink,
   which tool delivers it) — that is technology research and is always allowed;
   reading the target's own walkthrough is not.

Do this **before** hand-rolling blind exploitation. On this loop's ABDUCTED box,
skipping the CVE/PoC hunt cost the entire run: the path was CVE-2026-4480 (Samba
`%J` print-command injection) and the delivery detail (sink = SPOOLSS
`document_name`, not the smbclient filename) came straight from the PoC.

**This applies to privesc CVEs too, not just the foothold, and doubly before you
write a memory-corruption exploit from scratch.** For the pinned version,
enumerate *all* the CVEs — a daemon commonly has several at once — then reason
about the set rather than tunnelling on one: rank by cost/reliability (an auth
bypass or argument injection beats a memory-corruption bug on a hardened target),
consider chaining, and **exhaust public exploits before hand-rolling**.
`searchsploit` and web/sploitus hits often return only a *detection/leak* PoC
while a working weaponized exploit lives in a GitHub repo they don't index — run
`gh search repos "CVE-XXXX-YYYY"` / `gh search code "CVE-XXXX-YYYY"` and follow
the advisory's "references" links. For a memory bug, reverse the actual primitive
(arbitrary vs linear write, mitigations, whether a public exploit even exists)
before committing hours — on this loop's ORION box that discipline was violated:
deep exploit-dev went into the hard memory-corruption CVE while a cheaper
logic-bug CVE in the *same* binary was the intended door.

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
`references/privesc-windows.md`, `references/ad.md`. In AD specifically:
`references/adcs.md` (certificate paths) and `references/relay.md` (coercion +
relay) are frequent modern routes — check `certipy find` and signing state early.
If the foothold landed in a container or the host runs a cluster
(k3s/kubeadm/microk8s), see `references/containers.md` and
`references/kubernetes.md`; if the box holds cloud credentials or an SSRF reaches
a metadata service, `references/cloud.md`; for flow/agent/MCP platforms,
`references/llm-apps.md`. When a Windows control blocks your command (AMSI, CLM,
AppLocker), see `references/evasion.md` rather than assuming the technique failed.

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

- **A pattern that generalises** → append it to `~/pwnloop/memory/local.md`,
  one line, no machine specifics, no credentials, no flags. Only if a future run
  against a *different* box could act on it. Write to `local.md`, never to
  `patterns.md` — the shared file is upstream's, and editing it is what makes an
  operator's `git pull` conflict. Promoting an entry into the shared set is a
  pull request the operator chooses to open, not something a run decides.
- **A tool you had to install mid-run** → add it to
  `docker/packages.local.txt`, for the same reason.
- **A technique that worked and is not documented** → add it to the relevant
  `references/` file. This is a *required* half of the write-back, not optional:
  the `local.md` one-liner is your private memory, but the tracked `references/`
  are the shared skill that must keep growing — do both. **Write it as method,
  never as a box's answer.** A reference entry teaches how to *reason* — pin the
  version, enumerate the CVEs, choose/chain, find the sink — with the specific
  CVE/version/payload as at most a compact *example* of the class. Never leave an
  entry that reads "product X vN → CVE-Y → run this payload": that bakes one
  box's solution into the methodology and turns the next run into recall instead
  of discovery. Keep box-specific CVE recipes in `local.md`; keep the transferable
  technique/class in `references/`.
- **A mistake you made that a rule would have prevented** → add the rule.

Nothing to add is a legitimate outcome; say so rather than inventing an entry.
A memory file padded with restatements of the obvious costs every future run.

### 9. Name the engagement
Now — and only now — ask the operator what the machine is called, and rename the
directory from the address to that name (`engagements/10-129-51-240/` →
`engagements/ghostlink/`). Update the ledger's first line to match.

Asking at the start would hand you the recall trigger the whole discipline
exists to avoid. Asking at the end costs nothing: the work is done, the search
order is already on record, and an address is a terrible way to find an
engagement six months later. If the name collides with an existing directory,
suffix it (`ghostlink-2`) rather than merging — see *Re-running a target*.

### 10. Close out
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
- `references/web.md` — fuzzing, LFI/upload/SQLi/SSTI/XXE/deserialization/SSRF, prototype pollution, smuggling, auth bypass
- `references/api.md` — REST/GraphQL discovery, JWT attacks, IDOR, race conditions, SSRF
- `references/llm-apps.md` — Langflow/Flowise/MCP platforms: unauth flow-execution RCE, alg:none, tool registries, RAG poisoning
- `references/source-review.md` — reading recovered source: secrets, sinks, authorization gaps
- `references/cracking.md` — hash identification, john/hashcat formats, spraying strategy
- `references/services.md` — per-port playbooks (SMB, FTP, SSH, DNS, SNMP, LDAP, SQL, Redis, RPC, WinRM, SMTP, rsync, RMI/JDWP, app servers, NoSQL, IPMI/VNC)
- `references/binary.md` — custom network services and SUID binaries: triage, command-injection handlers, stack overflow, ret2libc/ROP, format string
- `references/foothold.md` — reverse shells, TTY upgrade, file transfer both ways
- `references/evasion.md` — getting past AMSI, Constrained Language Mode, AppLocker/WDAC, Defender on a lab box
- `references/artifacts.md` — mining recovered files (pcaps, archives, git, key material) for credentials
- `references/privesc-linux.md` — sudo, SUID, capabilities, cron, PATH, polkit, kernel last-resort
- `references/containers.md` — container escape: docker.sock, privileged/caps, cgroup release_agent, host mounts
- `references/kubernetes.md` — SA RBAC, kubelet exec via `get nodes/proxy`, privileged-pod escape, secrets/etcd
- `references/cloud.md` — IMDS/SSRF credential theft, AWS IAM privesc, Azure/Entra, GCP, cloud↔on-prem pivots
- `references/privesc-windows.md` — tokens/potato selection, services, DPAPI, LAPS/gMSA, UAC bypass, AlwaysInstallElevated
- `references/ad.md` — AS-REP/Kerberoast, DACL edges, delegation (unconstrained/constrained/RBCD), shadow credentials, DCSync, local Kerberos relay
- `references/adcs.md` — AD CS ESC1–ESC16, certificate theft, golden-cert and DACL persistence
- `references/relay.md` — NTLM/Kerberos coercion (PetitPotam/PrinterBug/DFSCoerce) and relay target matrix
- `references/devops.md` — configuration-management and deployment platforms: fleet-wide RCE, agent certificates, catalogs as credential stores
- `references/c2-ops.md` — operating through a C2 framework: operator configs as credentials, per-call state, quoting, in-band transport limits
- `references/pivoting.md` — mechanism choice, ligolo-ng/chisel/SSH, double pivots, agent delivery, tunnel recovery
- `references/reporting.md` — defender-facing report structure
- `references/writeup.md` — publishable write-up structure and redaction rules
