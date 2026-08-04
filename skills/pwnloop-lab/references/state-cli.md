# Campaign state CLI

Every fact that outlives the current host goes through these commands. They are
the only writer of `campaigns/<lab>/campaign.json`; `network.md` is re-rendered
after each mutation, so the operator's `tail -f` is always current.

All commands act on the *current* campaign (`campaigns/.current`, set by
`campaign new` / `campaign use`). Override for one command with `PWNLOOP_LAB=x`.

## Campaign

```bash
pwnloop campaign new <cidr>[,<cidr>…] [name]  # create, set current
pwnloop campaign use <dir-name>               # switch
pwnloop campaign rename <name>                # at the end, once the name is free
pwnloop campaign list                         # all campaigns, owned/total
pwnloop campaign status                       # the dashboard
pwnloop campaign resume                       # checkpoint + dashboard + route check + next
pwnloop campaign checkpoint "<handoff note>"  # what you were in the middle of
pwnloop campaign dir                          # absolute path, for scripting
```

`checkpoint` is the last command of every session. The state file says what is
true; the checkpoint says what you were doing, what is half-done, and what you
would have picked up next — the part that is expensive to reconstruct and
impossible to infer. `resume` prints it first.

The name argument is optional and normally omitted — the directory is derived
from the entry range (`10.10.110.0/24` → `campaigns/10-10-110-0-24/`) so the
lab's name never has to be spoken before the work is done. `campaigns/.current`
is what identifies the campaign you are on, so no command needs the name.

`resume` is the first command of every new session on an existing campaign. It
tests each route's canary and tells you what is stale before you act on it.

## Hosts

```bash
pwnloop host add <ip> [k=v …]      # idempotent: same ip updates in place
pwnloop host set <ip> k=v …        # fails if the host is unknown
pwnloop host list [status]         # all, or filtered by status
pwnloop host show <ip>             # full record + its credential attempts
```

Fields: `name os subnet status access via ports notes`.

- `status` — `seen` → `enum` → `foothold` → `owned`, or `dead` (say why in
  `notes`). The frontier is computed from this; a stale status sends the next
  session at a host you already finished.
- `ports` — space-separated, e.g. `"22 80 445"`. `try next` reads this to decide
  which services to suggest a credential against, so fill it in after recon.
- `via` — the host or route this one is reached through.
- `access` — how you hold it, in a few words: `SYSTEM via GodPotato`.

## Credentials

```bash
pwnloop cred add user=<u> [secret=<s>] [type=password|nthash|key|ticket] \
                 [domain=<d>] [source=<where you found it>] [host=<ip>]
pwnloop cred list
```

Returns the credential id (`c1`, `c2`, …) on stdout — capture it. Adding the
same (domain, user, secret) twice is a no-op that prints the existing id, so
re-adding a credential you rediscover elsewhere is safe.

Record where it came from. On a campaign the source is what tells the next
session whether a password is a personal one (likely reused) or a service
account's (likely privileged).

## The credential matrix

```bash
pwnloop try <cred-id> <host> <service> <ok|fail|locked|error>
pwnloop try next [n]        # untried (credential, host, service) triples
```

- Record **every** attempt, including failures — the matrix exists to stop the
  next session repeating them.
- `locked` is special: the credential is excluded from all future suggestions and
  the command warns you. Stop spraying it immediately and check the domain
  lockout policy before continuing.
- `try next` only suggests unowned hosts (`seen`/`enum`/`foothold`), and derives
  services from each host's `ports`. If a host has no ports recorded it assumes
  `smb` and `ssh`.

## Routes

```bash
pwnloop route add subnet=<cidr> via=<ip> type=<ligolo|chisel|ssh|socat> \
                  [listener=<port>] [canary=<ip:port>] [note=<text>]
pwnloop route list
pwnloop route check     # TCP-connects each canary from inside the container
pwnloop route del <cidr>
```

**Always set a canary** — an address:port behind the route known to answer.
Without it `route check` can only report "cannot verify", which is how a session
ends up spending twenty minutes debugging a scan against a subnet whose tunnel
died an hour ago.

`route check` updates each route's status in the state file, so the dashboard and
the next `resume` reflect reality rather than intent.

## Flags

```bash
pwnloop flag <host> <name> <value>
```

Writes the flag into the host's record and appends it to `flags.local.md`
(gitignored). Print it in chat on its own line at the same moment. If the host is
not yet recorded it is created, so a flag can never be lost to a missing `host
add`.

## Leads

```bash
pwnloop lead add kind=<host|cred|subnet|edge|service> target=<x> note=<text> [prio=1-3]
pwnloop lead list
pwnloop lead done <id>      # resolved
pwnloop lead dead <id>      # ruled out
```

Leads are the campaign's memory of "something to come back to". `prio=1` is
work that unlocks other work — a subnet, a DC path — and it is what a resumed
session should pick up first.

## Schema

`campaign.json`, all timestamps UTC ISO-8601:

```jsonc
{
  "lab": "dante", "created": "…", "scope": ["10.10.110.0/24"],
  "hosts":    [{ "ip", "name", "os", "subnet", "status", "access", "via",
                 "ports", "notes", "flags": [{"name","value","captured"}], "updated" }],
  "creds":    [{ "id", "domain", "user", "secret", "type", "source", "added" }],
  "attempts": [{ "cred", "host", "service", "result", "time" }],
  "routes":   [{ "subnet", "via", "type", "listener", "canary", "note", "status", "added" }],
  "leads":    [{ "id", "kind", "target", "note", "prio", "status", "added" }]
}
```

Reading it directly with `jq` is fine and often the fastest way to answer a
question ("which hosts on this subnet are still `seen`?"). Writing it directly is
not — the CLI enforces the shape, dedupes, and keeps `network.md` in step.
