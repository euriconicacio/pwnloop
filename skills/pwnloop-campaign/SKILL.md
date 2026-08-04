---
name: pwnloop-campaign
description: Run a multi-host lab campaign end to end — an HTB Pro Lab (Dante, Offshore, RastaLabs, Cybernetics, APTLabs, Zephyr, Genesis), a multi-machine AD range, or any authorized network engagement where the target is a subnet rather than a single host. Handles network state across sessions, pivoting into internal subnets, credential replay at scale and per-host delegation. Use whenever the operator gives a CIDR instead of an IP, names a Pro Lab, or asks to resume a campaign already in progress.
---

# Lab campaign — multi-host autonomous engagement

A campaign is not a long machine. A machine is one target and one context; a
campaign is a *graph* of hosts that outlives your context window many times over,
where most hosts are unreachable until you have owned another one, and where the
expensive mistakes are organisational rather than technical: spraying a
credential you already sprayed, losing a tunnel and not noticing, forgetting
which of nineteen hosts still has an unexplored port.

So this skill is mostly about **state**. The single-host methodology is not
replaced — `skills/pwnloop/SKILL.md` and all of its `references/` are the inner
loop, and you run them per host, unchanged. What is added here is the outer loop
that decides *which* host, keeps the network model on disk, and survives being
resumed by a session that remembers nothing.

## The two-level loop

```
campaign loop  ── pick the highest-value lead from the frontier
     │             (unowned reachable host · untried credential · new subnet)
     │
     ├─→ host loop   ── the pwnloop skill, scoped to one IP
     │                   recon → enum → foothold → privesc → flag
     │
     └─→ write back  ── every host, credential, route, flag and lead goes into
                        campaign.json through the CLI, never by hand
```

The rule that makes this work: **nothing important lives in your context.** If a
fact matters after the current host, it goes through the state CLI the moment you
learn it. Assume you will be resumed by a session that has read nothing but
`pwnloop campaign resume`.

## Scope contract

A campaign's scope is the CIDR(s) the operator named when it was created, plus
**subnets discovered from inside an owned host** — a second interface, a route
table, an ARP cache, a DNS zone. Those are in scope because the lab put them
there; record each one with `pwnloop lead add kind=subnet` and expand into it.

Out of scope, always: anything not reachable through the lab VPN or an owned lab
host, the operator's own LAN, public IPs, and any address a `traceroute` shows
leaving the lab. A Pro Lab's entry subnet often shares a range style with real
infrastructure — check the route, do not assume.

Inside scope, everything is pre-authorized: scan, exploit, dump, escalate, pivot,
read flags. Do not ask permission per command or per host.

## Starting a campaign

```bash
~/pwnloop/bin/pwnloop banner
~/pwnloop/bin/pwnloop campaign new <lab> <entry-cidr>
~/pwnloop/bin/pwnloop vpn-status
```

Read `~/pwnloop/memory/patterns.md` and `~/pwnloop/memory/local.md` first, as in
any engagement. Then confirm in one line: VPN state, entry CIDR reachable,
campaign directory created. Then go.

```
campaigns/<lab>/
  campaign.json   canonical state — hosts, creds, attempts, routes, leads, flags
  CAMPAIGN.md     the narrative ledger: decisions, in order, with evidence paths
  network.md      auto-rendered dashboard (the operator tails this)
  hosts/<ip>/     one directory per host — FINDINGS.md, scans/, loot/, www/
  loot/           campaign-wide: krb tickets, ntds dumps, cracked hashes
  routes/         tunnel configs, generated proxychains, PIDs
```

**Naming.** A Pro Lab name is a mild recall trigger — weaker than a Machine name,
since published Pro Lab solutions are scarce and prohibited, but not zero. Use
the lab name for the directory (a campaign runs for days; a CIDR is a terrible
handle), and if you recognise the lab, declare it in `CAMPAIGN.md` exactly as the
single-host skill requires. Every other discovery rule from that skill carries
over unchanged: never look up the lab's solution, every action traces to an
artifact you collected, log the near-miss.

## Resuming — read this before anything else

A campaign is resumed far more often than it is started. When the operator says
"continue", or your context was just reset:

```bash
~/pwnloop/bin/pwnloop campaign use <lab>
~/pwnloop/bin/pwnloop campaign resume
```

That prints the state, tests every registered route, and names the open work.
Then, in this order:

1. **VPN first.** `pwnloop vpn-status`. A dead VPN makes every route look dead.
2. **Re-establish every route reported `down`** before touching anything behind
   it — see `pwnloop/references/pivoting.md`. A lab reset kills every tunnel
   while `campaign.json` still claims the subnet is reachable; acting on a stale
   route wastes a whole cycle and looks like the target changed.
3. **Re-verify one owned host per subnet** (`nxc smb <ip>` with a known
   credential). Labs get reset. If an owned host no longer accepts the
   credential, mark it `status=seen` and re-own it before trusting anything
   downstream.
4. Read the last ~20 lines of `CAMPAIGN.md` for the reasoning you are inheriting.
5. Only then pick a lead.

## Picking what to work on

Every cycle, choose from the frontier — never improvise a target. In priority
order:

1. **A credential you have not replayed.** `pwnloop try next` prints untried
   (credential, host, service) triples. This is almost always the cheapest win in
   a lab: reuse across hosts is the intended path far more often than a fresh
   exploit.
2. **An unowned host on a subnet you already reach**, ranked by how out of place
   its services are (the one host running something unusual is where the lab
   wants you).
3. **A subnet you can see but not reach** — that is a pivot to build, and it
   usually unlocks several hosts at once.
4. **A BloodHound/AD edge** that leads toward a domain controller.
5. **A parked host** you time-boxed out of earlier, once the above are dry.

Time-box a single host to ~45 minutes of no progress, not the 15 of a single-box
run: on a campaign, switching costs more, and the credential you need may come
from a host you have not touched yet. Park it (`pwnloop host set <ip>
status=seen notes=...`) and move on.

**Do not chase depth on the first host that gives you a shell.** Sweep the entry
subnet for footholds first — a campaign's early value is breadth (more hosts →
more credentials → more reach), and depth on host #1 often needs a secret that
lives on host #4.

## Recording state — the CLI is the only writer

Full reference: `references/state-cli.md`. The habits that matter:

```bash
pwnloop host add 10.10.110.100 os=linux subnet=10.10.110.0/24 ports="22 80 445"
pwnloop host set 10.10.110.100 status=foothold access="www-data via CVE-…"
pwnloop cred add user=james secret='S3cret!' source=/var/www/.env host=10.10.110.100
pwnloop try c3 10.10.110.101 smb ok        # every spray result, win or lose
pwnloop route add subnet=172.16.1.0/24 via=10.10.110.100 type=ligolo canary=172.16.1.5:445
pwnloop flag 10.10.110.100 flag.txt <value>
pwnloop lead add kind=subnet target=172.16.2.0/24 note="route print on .100" prio=1
```

Host status vocabulary — keep it honest, the frontier is computed from it:
`seen` (discovered, not enumerated) · `enum` (being worked) · `foothold`
(unprivileged shell) · `owned` (root/SYSTEM/DA) · `dead` (ruled out, note why).

**Record failures too.** `pwnloop try c3 <host> winrm fail` is worth as much as a
success: it is what stops the next session re-running it. An empty attempt log on
a twenty-host lab means the matrix is doing nothing for you.

## Credentials at scale

A campaign accumulates dozens of secrets, and the naive "try everything on
everything" of a single box becomes both slow and *dangerous*:

- **Lockout is the one irreversible mistake.** Read the domain policy the moment
  you have any domain credential (`nxc smb <dc> -u u -p p --pass-pol`). Until you
  have read it, spray at most one password per account per window. The instant an
  attempt returns a lockout, record it (`… locked`) — the CLI then refuses to
  suggest that credential again and warns you.
- **Spray by user across hosts, not by password across users**, when the policy
  is unknown. A single password against every host tests reuse without touching
  the per-account counter more than once.
- **Hashes are credentials.** Record NT hashes, Kerberos tickets and private keys
  with `type=nthash|ticket|key` — pass-the-hash across a lab is the standard
  lateral path, and `try next` will suggest them like any other secret.
- **Re-run `try next` after every new credential**, not once per session. One
  cracked hash can open four hosts, and the matrix is what shows you that.

## Pivoting

`pwnloop/references/pivoting.md` is the operational detail. The campaign-level
rules:

- **Every tunnel gets registered with a canary** — an IP:port behind it that is
  known to answer. Without one, `route check` cannot tell you the truth, and an
  unverifiable route is worse than no route.
- **Prefer ligolo-ng.** A TUN route makes `nmap -sS`, UDP and raw tooling work
  natively; a SOCKS proxy silently breaks half of them and you will misread the
  results as "host has nothing open".
- **Keep proxies inside the container, backgrounded, one per subnet.** The
  container outlives your context — that is exactly what you want.
- **Re-establishing a pivot is a first-class task, not an interruption.** After
  any reset, fix routes before anything else.

## Delegating a host

When a subnet has three or more live hosts, stop enumerating them in your own
context — you will run out long before the lab does. Dispatch a subagent per
host: it follows the `pwnloop` skill, writes everything through the state CLI,
and returns a short structured receipt. You keep the campaign; it keeps the box.

The exact brief, the required return shape, and what must never be delegated
(scope decisions, cleanup, methodology write-back) are in
`references/delegation.md`. Use them literally — a free-form brief produces a
prose summary you cannot merge with four others.

## Per-host work

Inside a host, run the single-host loop exactly as written in
`skills/pwnloop/SKILL.md`: recon → service enumeration (pin versions, hunt CVEs
and public PoCs) → foothold → local enumeration → privesc → flag. Its
`references/` are the technique library for both skills. Keep the host's own
`FINDINGS.md` under `campaigns/<lab>/hosts/<ip>/` and let the campaign ledger
carry only what crosses host boundaries.

Two additions that only matter in a campaign:

- **Harvest before you escalate.** The moment you have any shell, take the
  credentials — config files, browser/keepass stores, `.ssh`, LSASS, SAM,
  registry — and record them. A campaign is won by credential flow, and an
  unprivileged shell that yields a domain password beats a root shell that
  yields nothing.
- **Map from the inside.** Every owned host is a vantage point: `ip route`, `arp
  -a`, `ipconfig /all`, `netstat -ano`, DNS servers, the domain it is joined to.
  Turn each into `host add` or `lead add kind=subnet` immediately.

## Active Directory across a campaign

Pro Labs are mostly AD, often multiple domains and a forest trust. Collect
BloodHound data from every domain as soon as you have any domain credential
(`bloodhound-python`/`bloodhound-ce -c All`, or `SharpHound.exe` from
`/opt/static/windows/`), merge collections rather than replacing them, and let
the graph drive lead priority. `pwnloop/references/ad.md`, `adcs.md` and
`relay.md` carry the techniques; at campaign scale the additions are:

- **Enumerate trusts explicitly** once you own a domain — a second domain is a
  second set of flags, and cross-forest paths (unconstrained delegation on a
  trusted DC, ADCS templates published forest-wide, `ExtraSids` on a trust key)
  are standard Pro Lab endgame.
- **DCSync is not the end of a campaign.** After it, the campaign continues:
  every dumped hash is a credential to record and replay against hosts in other
  subnets.

## Reporting — and the Pro Lab publication rule

At the end of a campaign, write two documents in `campaigns/<lab>/`:

- `REPORT.md` — defender-facing, per `pwnloop/references/reporting.md`, but
  structured as a *network* compromise: entry point, the host-by-host chain with
  the credential or trust that carried each hop, a topology of what reached what,
  and the earliest single control that would have contained the breach (usually
  a credential-reuse or segmentation control, not a patch).
- `CAMPAIGN.md` — already written incrementally; close it with the timeline.

**Do not write a publishable `WRITEUP.md` for a Pro Lab.** Unlike Machines, Pro
Labs are never retired, so a write-up can never become publishable and HTB's
rules prohibit sharing solutions. The teaching document a single-host run
produces is deliberately skipped here; everything stays in the (gitignored)
campaign directory. If the operator asks for one anyway, say this once, and if
they confirm, write it and mark it clearly as non-publishable.

Flags follow the same rule as always: `pwnloop flag` writes them to
`flags.local.md` and the campaign state, both gitignored, and they are printed in
chat the moment they are read — one per line, so the operator can submit while
you keep working.

## Write back into the loop

Same discipline as a single-host run, and it matters more here because a campaign
produces many hosts' worth of lessons at once:

- a transferable technique → the relevant `pwnloop/references/` file, as method
  and never as this lab's answer;
- an operator-specific pattern → `memory/local.md`, one line;
- a tool you had to install → `docker/packages.local.txt`;
- a mistake a rule would have prevented → the rule.

Campaign-scale lessons — an ordering that wasted a day, a state habit that saved
one — belong in this skill, not in the single-host one.

## Reporting to the operator

They are watching `network.md` and `CAMPAIGN.md`, not the chat. In chat give:
one line per host owned, each flag on its own line the moment it is read, and a
one-line note when you switch subnets or build a pivot. Nothing longer.

Come back to them only for: VPN down, the lab needing a reset, a genuine scope
question (a route that appears to leave the lab), or a full cycle across the
whole frontier with no new leads.

## References

- `references/state-cli.md` — every state command, the schema, and the habits
- `references/delegation.md` — per-host subagent brief and required return
- `pwnloop/references/pivoting.md` — tunnels, multi-hop, route recovery
- `pwnloop/references/*` — the full technique library, shared with the host loop
