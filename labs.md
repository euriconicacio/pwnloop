# Lab campaigns

Multi-host campaigns run with `pwnloop-lab`. This index is deliberately not a
write-up index: it records **that** a network fell and what the run changed in
the loop, never **how** the network fell.

That is not modesty, it is the rule. Pro Labs are never retired, so unlike a
retired machine there is no future date at which a solution becomes publishable —
sharing one is prohibited indefinitely. Everything that would constitute a
solution (the chain, the discovered hostnames and domains, the credentials, the
flags, the per-host ledgers and reports) stays in `campaigns/<lab>/`, which is
gitignored and never leaves the machine that ran it.

The lab's *own page* is a different matter: its name, entry point, machine count
and roster, flag names and scenario blurb are published by the platform itself.
Naming a lab here, and saying how much of it fell, repeats what anyone can read
before buying it.

| lab | platform | hosts | flags | sessions | wall-clock | what it changed | verified |
|-----|----------|-------|-------|----------|------------|-----------------|----------|
| _no campaign closed out yet_ | | | | | | | |

**Columns.** `hosts` is owned/total-discovered and `flags` is captured/total —
both are progress figures the platform already displays on a public profile, not
solution detail. `sessions` and `wall-clock` are the numbers that actually matter
for this repository's claim: they are what a second run of the same lab, on a
later version of the methodology, gets measured against. `what it changed` links
the CHANGELOG entries the run produced. `verified` links the platform's own
completion certificate or badge — the platform is the witness, which is the point:
proof of completion is *issued by the target*, not asserted by the attacker.

**`verified` takes a verification URL, never an image.** An image proves nothing
— anyone can produce one — while a certificate URL or ID is checkable at the
source by a reader who has no reason to trust this repository. A screenshot in
`assets/` is for a slide deck, where the job is visual rather than evidentiary.

**A partially completed lab has no certificate**, because the platform issues one
only at 100%. That row still belongs here: it carries the honest hosts and flags
figures and says `partial` in this column. A campaign that got most of the way is
a real result and the numbers say exactly how far it got — writing anything that
implies completion would make every other row in this table worth less.

## Why the numbers are the interesting artifact

A write-up proves a machine fell to *someone*. It does not prove much about a
loop, because a good write-up reads the same whether the path took forty minutes
or was known in advance.

A campaign's numbers do carry that signal. Hosts owned per session, how much of
the frontier was still open when a session ended, how long a resumed session took
to get back to productive work, how many credentials the matrix replayed into a
foothold — those describe the *loop*, not the lab, and they are exactly what
should improve between one campaign and the next. They are also safe to publish,
because none of them says what any host was running.

## What a campaign may contribute to the repository

- **Methodology**, in `skills/*/references/`, written as a technique class and
  never as this lab's chain. The test is in the write-back section of
  `skills/pwnloop-lab/SKILL.md`: if a reader could identify the lab or skip a
  step on it, it belongs in the gitignored `memory/local.md` instead.
- **Tooling** — a package, a staged binary, a wrapper subcommand.
- **A row in this table**, added at close-out.
- **A loop post-mortem** (optional): what the state model got wrong, where the
  resume protocol cost time, what delegation did to context. Fully publishable,
  because it is about the harness rather than the target — and more useful to
  anyone reading this repository than a chain would be.

Nothing else. No campaign report, no host ledger, no topology, no flag.
