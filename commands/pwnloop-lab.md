---
description: Run or resume an autonomous multi-host campaign (HTB Pro Lab, AD range). Usage: /pwnloop-lab <entry-ip-or-cidr> — pass the entry point only, not the lab's name. /pwnloop-lab resume continues the current one.
argument-hint: <entry-ip|entry-cidr> | resume
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Task, TaskCreate, TaskUpdate, WebSearch, WebFetch
---

Campaign: $ARGUMENTS

Use the `pwnloop-campaign` skill.

If the argument is `resume` (optionally followed by a campaign directory name),
this is an existing campaign: run `pwnloop campaign resume`, re-establish every
route reported down, re-verify one owned host per subnet, and continue from the
frontier. Do not re-enumerate what the state file says is already done.

Otherwise create it with `pwnloop campaign new <entry>` and start there. If the
entry point is a single host, that host is the whole campaign until it falls: run
the single-host loop against it, and the moment you have any shell, map outward
(interfaces, routes, ARP, DNS, domain trusts) before escalating locally — the
internal subnets are the campaign.

**Work from the entry point alone — do not ask me what the lab is called.**
The name is a recall trigger and I am withholding it deliberately; the directory
is named after the CIDR. Ask me for the name at the very end and
`pwnloop campaign rename` it then. If the lab identifies itself mid-run and you
recognise it, record that in `CAMPAIGN.md` and keep going.

Run it autonomously. Do not pause between hosts and do not ask permission per
command — the lab is pre-authorized. Sweep the entry subnet for footholds before
going deep on any single host.

Record every host, credential, attempt, route, flag and lead through the state
CLI as it lands — I am reading `campaigns/<dir>/network.md` and `CAMPAIGN.md`,
not the chat. In chat give me one line per host owned, one line when you build a
pivot or move to a new subnet, and each flag on its own line the moment you read
it.

When a subnet has three or more live hosts, delegate per-host enumeration to
subagents using the brief in `references/delegation.md`, so your own context
stays on the campaign rather than on any one box.

Stop and ask me only if: the VPN is down, the lab needs a reset, a route appears
to leave the lab (a real scope question), or you have cycled the entire frontier
with no new leads.
