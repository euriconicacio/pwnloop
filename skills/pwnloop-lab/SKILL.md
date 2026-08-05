---
name: pwnloop-lab
description: Run a multi-host lab campaign end to end — an HTB Pro Lab (Dante, Offshore, RastaLabs, Cybernetics, APTLabs, Zephyr, Genesis), a multi-machine AD range, or any authorized network engagement whose target is a network rather than one box. Handles network state across sessions, pivoting into internal subnets, credential replay at scale and per-host delegation. Use whenever the operator gives a CIDR, names a Pro Lab, gives a single entry host that fronts an internal network, or asks to resume a campaign already in progress.
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

## When the entry point is a single host

Many labs hand you one address and nothing else — the network exists, but none of
it is reachable until that host falls. Then the campaign has a shape the rest of
this skill does not describe yet:

**Phase 0 is a single-host engagement.** Run `skills/pwnloop/SKILL.md` against
the entry IP exactly as written, with its 15-minute rabbit-hole time-box, not the
45-minute one below. There is no breadth to prefer and no frontier to rank: the
entry host *is* the frontier, and depth on it is the only move. Record state
through the campaign CLI from the first minute anyway (`host add`, `cred add`,
`try`) — that is what makes the transition free.

**The campaign begins at the first shell.** The moment you have any access on the
entry host, mapping outward outranks escalating locally:

```bash
ip route; ip -4 addr; arp -a; cat /etc/resolv.conf; cat /etc/hosts
route print; ipconfig /all; arp -a; nltest /domain_trusts
```

Every interface, route, ARP entry, DNS server and domain becomes a
`lead add kind=subnet` or a `host add` before you go back to privesc. A second
NIC on the entry host is the actual entry point to the lab; root on the entry
host without it is a dead end with a flag attached.

Then build the pivot (`references/pivoting.md`) and register it with a canary.
From that point the normal campaign loop applies: breadth first, matrix replay,
frontier ranking.

**The entry host is a single point of failure for everything behind it.** Every
route's `via` chain terminates there, so if it is reset, the whole campaign goes
dark at once and each tunnel has to be rebuilt from scratch. On resume, verify
the entry host *before* testing any route — a dead entry host explains every
other symptom, and debugging the far end of a chain whose first hop is gone is
the most expensive mistake available here. Keep the foothold cheap to re-enter:
prefer a mechanism you can replay in a minute (a credential, a key you planted
and recorded) over an exploit chain you would have to rebuild.

## Scope contract

A campaign's scope is the address or CIDR(s) the operator named when it was
created, plus
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
~/pwnloop/bin/pwnloop campaign new 10.10.110.0/24    # an entry range
~/pwnloop/bin/pwnloop campaign new 10.10.110.5       # or a single entry host
~/pwnloop/bin/pwnloop vpn-status
```

Read `~/pwnloop/memory/patterns.md` and `~/pwnloop/memory/local.md` first, as in
any engagement. Then confirm in one line: VPN state, entry CIDR reachable,
campaign directory created. Then go.

```
campaigns/<lab>/
  campaign.json   canonical state — hosts, creds, attempts, routes, leads, flags
  CAMPAIGN.md     the ledger: an event row per discovery, plus your reasoning
  network.md      auto-rendered dashboard (the operator tails this)
  hosts/<ip>/     one directory per host — FINDINGS.md, scans/, loot/, www/
  loot/           campaign-wide: krb tickets, ntds dumps, cracked hashes
  routes/         tunnel configs, generated proxychains, PIDs
```

### What lands where — and what only you can write

Four layers, and knowing which is which is the difference between a campaign
that can be handed over and one that only exists in your context:

| layer | written by | holds |
|---|---|---|
| `campaign.json` | the CLI, exclusively | the current truth: hosts, credentials, the spray matrix, routes, leads, flags |
| `network.md` | the CLI, on every write | a rendered snapshot of the above — **no history** |
| `CAMPAIGN.md` | the CLI (one row per event) **and you** | the timeline, plus the *why* behind each decision |
| `hosts/<ip>/` | you | per-host ledger, raw scan output, loot, staged payloads |

The CLI now logs a ledger row for every host discovered, status change,
credential, successful or locked authentication, pivot and flag — so the
timeline builds itself and you never have to maintain it. Two things it cannot
write, and they are the two that matter most six hours later:

- **Reasoning.** Why a lead was ranked first, what a failure ruled out, the
  theory you are working from. Append a line to `CAMPAIGN.md` whenever a decision
  was not obvious from the evidence.
- **Per-host detail.** `hosts/<ip>/FINDINGS.md` is created for you the moment a
  host is added; filling it in with findings and their evidence files is the
  same discipline as a single-host run.

If you find yourself inventing a file to hold state — a `RESUME.md`, a notes
file, a scratch list of hosts — stop: that state belongs in the CLI or the
ledger, and anything outside them is invisible to `resume` and to the operator.
Long handoffs go in `campaign checkpoint`, which accepts as much text as you
need.

**Work from the entry range alone — do not ask what the lab is called.** The
directory is named from the CIDR (`campaigns/10-10-110-0-24/`) for exactly the
reason the single-host loop names engagements after the address: a lab's name is
a recall trigger, and the most-documented Pro Labs are the ones whose names carry
the most. You do not need it as a handle either — `campaigns/.current` tracks the
campaign you are on, so `pwnloop campaign resume` needs no argument.

If the operator supplies a name anyway, use it and record it in `CAMPAIGN.md` as
a recall risk. Expect the lab to identify itself mid-run through an AD domain or
a certificate; declare recognition in the ledger the moment it happens, exactly
as the single-host skill requires, and keep going.

At the very end — after the flags, the report and the write-back — ask what the
lab is called and `pwnloop campaign rename <name>`. Asking then costs nothing:
the search order is already on record, and a CIDR is a terrible way to find a
campaign six months later.

Every other discovery rule carries over unchanged: never look up the lab's
solution, every action traces to an artifact you collected, log the near-miss.

## Sessions are hours; the lab is longer

Assume the operator has a few hours, not a weekend. That is the normal way a
campaign is run and the design expects it — but it only works if every session
ends deliberately instead of just stopping.

**Close every session with a checkpoint**, and write it *before* you are out of
room, not after:

```bash
pwnloop campaign checkpoint "172.16.1.5: SeImpersonate confirmed, GodPotato \
uploaded to C:\\Windows\\Temp\\a.exe but not run — run it first. 10.10.110.11 \
parked on a 403 at /admin. Next: replay c7 across 172.16.1.0/24."
```

Write one when: the operator says they are stopping, you are approaching the end
of your context, or you are about to switch to a different subnet. It is the one
piece of state the CLI cannot infer — `campaign.json` records what is *true*,
while the checkpoint records what you were *in the middle of* and why. `resume`
prints it before anything else.

**Prefer stopping at a clean boundary.** Finish the host you are on, or park it
explicitly (`host set <ip> status=seen notes="…"`), rather than leaving a
half-run exploit chain that only exists in your context. A session that ends
having owned two hosts and written a good checkpoint is worth more than one that
ends mid-exploit on a third.

Budget roughly: the opening session takes the entry point — a subnet sweep and
its first footholds, or, when the entry is one host, that host plus the map of
what lies behind it. Each session after that is one pivot plus the hosts it
exposes. Depth is what to defer, never breadth — breadth is what makes the next
session cheap.

## Resuming — read this before anything else

A campaign is resumed far more often than it is started. When the operator says
"continue", or your context was just reset:

```bash
~/pwnloop/bin/pwnloop campaign resume          # the current campaign
~/pwnloop/bin/pwnloop campaign list            # if you need to pick another
~/pwnloop/bin/pwnloop campaign use <dir-name>  # then switch to it
```

That prints the last session's checkpoint, the state, a live test of every
registered route, and the open work. Then, in this order:

1. **VPN first.** `pwnloop vpn-status`. A dead VPN makes every route look dead.
2. **Then the entry host**, before any route: it is the first hop of every chain,
   so if it was reset, every route below is dead for one reason and re-testing
   them individually tells you nothing.
3. **Re-establish every route reported `down`** before touching anything behind
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

**Once you reach a subnet, do not chase depth on the first host that answers.**
Sweep it for footholds first — a campaign's early value is breadth (more hosts →
more credentials → more reach), and depth on one host often needs a secret that
lives on another. The exception is the single entry host above, where breadth
does not exist yet and depth is the only path.

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

**Then materialise the result in all three places, in this order** — they must
agree, so update them in one pass rather than leaving two of them to rot:

1. **`labs.md`** (repository root) — the row: hosts owned/total, flags
   captured/total, sessions, wall-clock, links to the CHANGELOG entries the run
   produced, and a link to the platform's completion certificate or badge. Read
   the file first; it states exactly what may and may not go in that row.
2. **`CHANGELOG.md`**, under `[Unreleased]` — what the campaign *changed*: each
   reference entry added, each tool staged, each rule written. Describe the
   technique class, never the lab's chain. A campaign that changed nothing says
   so in one line.
3. **The `README.md` track-record table** — only if the campaign moved what that
   table claims (a first completed lab, a new platform).

Numbers and platform-issued proof are not a solution: they say a network fell
and what the loop learned, without saying what any host was running. Those three
updates, the `references/` entries, and an optional post-mortem *about the
harness* are the whole publishable output of a campaign.

A campaign that captured every flag and changed nothing in the methodology is
worth reporting as exactly that. It means the loop already knew everything the
lab had to teach — a real result, and a rarer one than a new reference entry.

Flags follow the same rule as always: `pwnloop flag` writes them to
`flags.local.md` and the campaign state, both gitignored, and they are printed in
chat the moment they are read — one per line, so the operator can submit while
you keep working.

## Write back into the loop

This is not optional and it is not the report's job. A campaign produces many
hosts' worth of lessons at once, and they are transversal by nature — the
techniques that move you through a lab are the same ones a single machine needs:

- a transferable technique → the relevant `pwnloop/references/` file;
- a campaign-scale lesson (an ordering that wasted a session, a state habit that
  saved one) → **this** skill, not the single-host one;
- an operator-specific pattern → `memory/local.md`, one line;
- a tool you had to install → `docker/packages.local.txt`;
- a mistake a rule would have prevented → the rule.

### The Pro Lab constraint on what you may write

`skills/` and `references/` are **tracked and public**. A Pro Lab is **never
retired**, so publishing its solution is prohibited indefinitely — which means
the write-back rule that is about methodology quality on a machine is also a
platform-rules boundary here, and it is the one place where a well-intentioned
reference entry can do real damage.

Write the **class**, never the chain. The difference is in what the entry lets a
reader do:

> ✗ An entry that names the product and version, the port, the exact endpoint
> you called and the order you called it in. Filing off the hostnames does not
> help: anyone holding the lab can follow it step by step, and the product alone,
> in an entry added the week a lab was completed, is enough to identify which lab
> it was.
>
> ✓ An entry that names the *class* of system, explains why that class is a
> credential hub or an RCE fan-out, and says what to enumerate and in what order
> — written so it applies to targets that have nothing to do with this lab, and
> so that someone who has never heard of the lab gets the full value.

If the technique genuinely needs a concrete example to be teachable, take one
from a **retired machine** or from public vendor documentation — never from the
campaign that prompted the entry.

**The test before you commit an entry:** could a reader use it to identify the
lab, or to skip a step on it? If yes, it belongs in `memory/local.md`, which is
gitignored, or in the campaign directory — not in `references/`. When in doubt,
write the class in `references/` and keep the specifics local; the specifics are
the half that ages worst anyway.

**Published metadata is not a solution.** A lab's own page states its name, entry
point, how many machines it has and what they run, the flag names, and a blurb
describing the scenario. Repeating any of that discloses nothing — it is the
vendor's marketing copy — and `labs.md` names the lab for exactly this reason.

What must never be published is what *enumeration* found: the AD domain, internal
subnets and hostnames, account names, service versions and ports you discovered,
credential and flag values, and above all the order of steps that turns one into
the next. The line is between what the platform tells everyone and what the lab
told you.

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
- `pwnloop/references/devops.md` — deployment platforms as fleet-wide RCE
- `pwnloop/references/c2-ops.md` — operating through a C2 framework
- `pwnloop/references/pivoting.md` — tunnels, multi-hop, route recovery
- `pwnloop/references/*` — the full technique library, shared with the host loop
