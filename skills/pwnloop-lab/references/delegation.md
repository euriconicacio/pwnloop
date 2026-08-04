# Delegating a host to a subagent

On a twenty-host lab your context is the scarce resource, not time. Enumerating
every host yourself means the campaign dies of context exhaustion somewhere
around host six, usually while holding the one credential that would have opened
the rest.

So: **you keep the network, a subagent keeps the box.** The state CLI is what
makes that safe — a subagent that writes through it cannot corrupt the model, and
when its context ends nothing is lost, because nothing that mattered was ever
only in its context.

## When

- Delegate once a subnet has **three or more live hosts** to work through.
- Delegate any host you are time-boxing out of but do not want to abandon.
- Do **not** delegate the host you are actively exploiting — handing off a
  half-built exploit chain costs more than it saves.
- Do **not** delegate pivot construction. Routes are campaign-level state and
  need the console session you already hold.

Run delegated hosts in parallel when they are independent. Two agents on the same
host will fight over the same shell and the same lockout counter.

## The brief

Keep it small — everything the subagent needs and nothing about the rest of the
lab. A long brief defeats the purpose.

```
Target: 172.16.1.5 (windows, reachable — the ligolo route for 172.16.1.0/24 is up)
Campaign: dante. Use the `pwnloop` skill for the host loop.

Working directory: /campaigns/dante/hosts/172.16.1.5/  (create it)
Known credentials worth trying first:
  c3  DANTE\svc_backup : Backup2024!   (from web.config on 10.10.110.100)
  c7  DANTE\jdoe : <nthash>            (pass-the-hash)
Already tried on this host: none.

Do:
- full recon, service enumeration, foothold, local enumeration, privesc, flag
- record everything through the state CLI as it lands:
    pwnloop host set 172.16.1.5 status=… access=… ports="…"
    pwnloop cred add user=… secret=… source=… host=172.16.1.5
    pwnloop try <cred-id> 172.16.1.5 <service> <ok|fail|locked>
    pwnloop flag 172.16.1.5 <name> <value>
    pwnloop lead add kind=… target=… note=…
- keep raw output under hosts/172.16.1.5/scans/, one file per run
- respect the lockout rule: if any attempt returns locked, record it and stop
  spraying immediately

Do not: build tunnels, touch other hosts, or read another host's directory.
Report back in the structured form below and nothing longer.
```

## The required return

Demand this shape. Prose summaries are unusable at campaign scale — you will be
merging five of them while deciding the next move.

```
host:    172.16.1.5
status:  owned | foothold | enum | seen | dead
access:  SYSTEM via GodPotato          (or why not, in a few words)
ports:   135 445 3389 5985
flags:   flag.txt captured             (values go through `pwnloop flag`, not chat)
creds:   c9 (local admin hash), c10 (svc_sql password from registry)
leads:   subnet 172.16.2.0/24 seen in route print; DC is 172.16.1.2
blocked: <what stopped it, if anything>
```

Everything in that summary should **already be in the state file** — the return
is a receipt, not the record. If a subagent reports a credential that
`pwnloop cred list` does not show, it did not follow the brief: add it yourself
before you forget, and tighten the next brief.

## After a delegated host returns

1. `pwnloop campaign status` — confirm the state matches the report.
2. `pwnloop try next` — a new credential usually unlocks work on hosts that were
   already exhausted.
3. Fold any new subnet into the frontier (`lead add kind=subnet`) before starting
   the next host, or it will be forgotten by the time you come back.

## What not to delegate to a subagent's judgement

- **Scope decisions.** A route that looks like it leaves the lab comes back to
  you, and you take it to the operator.
- **Cleanup.** Artifacts are removed at campaign close, by you, from the ledger's
  artifact list — a subagent that cleans up as it goes destroys evidence the
  report needs.
- **Write-back into the methodology.** Lessons land in `references/` and
  `memory/local.md` once, at the end, filtered by you. Five subagents each
  appending their own version of the same lesson is how a memory file becomes
  unreadable.
