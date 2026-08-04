---
description: Run or resume an autonomous multi-host campaign (HTB Pro Lab, AD range). Usage: /pwnloop-lab <lab-name> <entry-cidr>, or /pwnloop-lab resume <lab-name>.
argument-hint: <lab-name> <entry-cidr> | resume <lab-name>
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Task, TaskCreate, TaskUpdate, WebSearch, WebFetch
---

Campaign: $ARGUMENTS

Use the `pwnloop-campaign` skill.

If the first argument is `resume`, this is an existing campaign: run
`pwnloop campaign use <lab>` then `pwnloop campaign resume`, re-establish every
route reported down, re-verify one owned host per subnet, and continue from the
frontier. Do not re-enumerate what the state file says is already done.

Otherwise create the campaign (`pwnloop campaign new <lab> <cidr>`) and start
from the entry subnet.

Run it autonomously. Do not pause between hosts and do not ask permission per
command — the lab is pre-authorized. Sweep the entry subnet for footholds before
going deep on any single host.

Record every host, credential, attempt, route, flag and lead through the state
CLI as it lands — I am reading `campaigns/<lab>/network.md` and `CAMPAIGN.md`,
not the chat. In chat give me one line per host owned, one line when you build a
pivot or move to a new subnet, and each flag on its own line the moment you read
it.

When the entry subnet has several live hosts, delegate per-host enumeration to
subagents with tight briefs and have them write back through the CLI, so your own
context stays on the campaign rather than on any one box.

Stop and ask me only if: the VPN is down, the lab needs a reset, a route appears
to leave the lab (a real scope question), or you have cycled the entire frontier
with no new leads.
