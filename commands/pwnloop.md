---
description: Run an autonomous engagement against a lab machine (HTB/THM). Usage: /pwnloop <ip> — pass the address only, not the machine's name.
argument-hint: <ip>
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, TaskCreate, TaskUpdate, WebSearch, WebFetch
---

Target: $ARGUMENTS

Work from the address alone. Do not ask me what the machine is called — the name
is a recall trigger and I am withholding it deliberately. Name the engagement
directory after the address (`engagements/10-129-51-2/`). If the box identifies
itself mid-run and you recognise it, record that in the ledger and keep going.

Use the `pwnloop` skill and run the engagement autonomously from recon to
root. Do not pause between phases and do not ask for permission per command —
the target is a pre-authorized lab host.

Before starting, confirm in one line: VPN state, target reachability, and the
engagement directory you created. Then go.

Report progress by appending to `FINDINGS.md` as discoveries land, and give me
a one-or-two-line status in chat at each phase transition — nothing longer, I am
reading the ledger.

Print each flag in chat on its own line the moment you read it, so I can submit
it while you keep working. Clean up everything you created on the target before
you finish, and close with the summary table.

Stop and ask me only if: the VPN is down, the target has been unreachable for
more than 5 minutes (it may need a reset on the platform), or you have run three
complete enumeration loops with no new leads.
