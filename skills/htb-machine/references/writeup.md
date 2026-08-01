# Write-up

Written to `/engagements/<name>/WRITEUP.md` alongside the report. The two serve
different audiences and should not be merged:

- **REPORT.md** argues to a defender: what is broken, what it costs, what to fix.
- **WRITEUP.md** teaches a reader: how you got there, what you tried, and why
  the wrong turns were wrong.

A write-up that only shows the winning path is the least useful kind. The dead
ends are the content — they are what a reader facing an unfamiliar box actually
needs.

## Publish only what is publishable

Before writing, confirm the machine is **retired** on the platform (not merely
"expired" — expired machines can still be active). If it is not retired, still
write the file, but mark it `DO NOT PUBLISH — <machine> is active` on line one.

Never include flag values. Replace them with `<user flag redacted>` /
`<root flag redacted>`. Redact anything from the engagement that is not a
property of the machine itself: your VPN address, your key material, your
account names.

## Structure

```markdown
# <Machine> — <platform>, <difficulty>, <OS>

**TL;DR:** <the chain in one sentence: "Exposed X leaks Y, which authenticates
to Z, and a misconfigured W hands over root.">

## Reconnaissance

What the scan showed and — more importantly — what it *suggested*. Include the
trimmed command and the part of the output that mattered, not the full dump.

    nmap -Pn -sCV -p22,80 10.10.11.x
    ...only the lines a reader needs...

Note the observation that set the direction: an unusual version, a redirect to
a hostname, a service that should not be internet-facing.

## Enumeration

Each service, what you looked for, and what you found. Show the reasoning:
"the page referenced /api/v1/, so before fuzzing blindly I read the JS bundle."

## Foothold

The vulnerability, named properly (IDOR, SSTI, unauthenticated file upload —
not "a bug"). Then:

- why it exists — the code or config pattern behind it
- the exact request or payload, in a copy-pasteable block
- what you got back

Then getting the shell, and stabilising it.

## Privilege escalation

Same treatment. What in the local enumeration output pointed here, why that
misconfiguration is exploitable, and the escalation itself.

## What did not work

The leads you parked, with the reason each was a dead end. Two or three is
plenty. This is the section that saves a reader an hour, and it is the one most
write-ups skip.

## Lessons

Two or three sentences of transferable technique, not a summary of the above.
"Anywhere a numeric ID appears in a download endpoint, test adjacent IDs before
anything else" is a lesson. "This machine was a good exercise" is not.

## Defensive takeaway

One paragraph: the control that would have broken the chain earliest, and why
that beats fixing the last step. This is the bridge to REPORT.md and the reason
a defensive audience should care about a CTF write-up at all.
```

## Voice

Write it as prose with commands embedded, not as a numbered list of commands
with captions. Present tense, first person, no dramatics. State what you ran,
what came back, and what you concluded — a reader should be able to disagree
with a conclusion because you showed them the evidence it rested on.

Length: 800–1500 words for an easy box. If it is longer than that, you are
pasting output that does not earn its space.
