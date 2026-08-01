# Report

Written to `/engagements/<name>/REPORT.md` once both flags are captured. The
point is that someone who was not watching can follow the chain and understand
why each step worked.

```markdown
# <Machine> — <IP>
Engagement: <start> → <end> (<duration>)
Result: root / SYSTEM obtained

## Attack chain

1. **Recon** — <n> TCP ports open; <service> <version> on <port>.
   Evidence: `scans/nmap-deep.txt`
2. **<Vector>** — <what was wrong and why it was exploitable>.
   Evidence: `scans/<file>`
3. **Foothold** — shell as `<user>` via <technique>.
   Evidence: `scans/<file>`
4. **user.txt** — `<hash>`
5. **Escalation** — <misconfiguration>, exploited by <technique>.
   Evidence: `scans/<file>`
6. **root.txt** — `<hash>`

## Timeline
| Time | Event |

## Findings and remediation

### F1 — <title> (Critical/High/Medium)
**Where:** <host:port/path>
**What:** one paragraph, no jargon padding.
**Proof:** exact command and its output, or the request/response pair.
**Impact:** what an attacker gets — be concrete, not "may lead to compromise".
**Fix:** the specific change that breaks this step of the chain.

## What would have stopped this
The single control that would have broken the chain earliest, and why it beats
patching the last step.

## Credentials recovered
| user | source | reuse observed |
```

Two things make this useful rather than decorative:

- **Chain-first framing.** Individual findings ranked by CVSS lose the story.
  The chain is what convinces an audience that a medium-severity information
  disclosure plus a medium-severity weak sudo rule equals total compromise.
- **Earliest break point.** For every engagement, name the one control that
  would have stopped the chain closest to the start. That is the recommendation
  that actually gets funded.

Keep the flag hashes in the local report — they are the proof of completion —
but strip them from anything that leaves the machine. Platform rules treat flag
sharing as a violation regardless of the target's status, and solutions may only
be published for content that is confirmed **retired**. "Expired" is not
"retired": an expired machine no longer scores seasonal points but can still be
active, and publishing its solution is a ToS violation.
