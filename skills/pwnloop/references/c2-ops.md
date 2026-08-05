# Operating through a C2 framework

Some engagements start from an implant rather than a shell, or reach a point
where a framework (Sliver, Havoc, Mythic, Cobalt Strike) is the only transport
into a segment. Driving one is a different discipline from running commands over
SSH, and most of the wasted time comes from four properties that are not obvious.

## The team server is an authentication surface

A framework's **operator configuration file is a credential** — it contains the
client certificate and the endpoint, and anyone holding it is an operator on that
team server with full control of every implant it manages. Treat any such file
you find (an operator profile, a client config, a kubeconfig, a teamserver
profile) exactly as you would a private key: it is not documentation.

The corollary is that a multiplayer/team-server port is a login prompt. Enumerate
it as one.

## Every command is a fresh process

In most frameworks each `execute`/`run` is spawned independently. State does not
carry between calls: an authenticated network mount, a changed directory, an
environment variable, a token — none of it survives to the next command. When a
step needs authentication, it must be established **inside the same call**, or
through the framework's own impersonation primitive (`make-token`, `steal_token`,
`pth`), which does persist for the session.

A machine account's own identity is usually refused by other hosts, so
impersonate an account you have credentials for before touching a remote share,
rather than assuming SYSTEM is powerful everywhere.

## Quoting is the most common failure

A framework console parses your line before the target ever sees it, and its
parser is not your shell. Nested quotes get mangled, backslash pairs collapse
unpredictably, and a command that works when typed locally fails through the
implant with no useful error.

Do not fight it. Encode the payload:

- Windows: build the command in PowerShell and pass it base64 UTF-16LE via
  `-EncodedCommand`. Nothing in it can be misparsed on the way.
- Linux: base64 the script and `echo … | base64 -d | sh`.

When you must type a path directly, double every backslash the console will
collapse, and prefer single-quoted strings where the parser leaves them intact.
Verify with a command that echoes what actually arrived before debugging the
technique itself.

## In-band transport is for control, not for bulk

A framework's SOCKS or tunnel is fine for small requests and terrible for large
file transfers — signed SMB writes in particular corrupt or stall over an
in-band proxy, and you will misread the result as a broken exploit.

**Keep bulk transfers on the internal network.** Stage the file on a host you
already own inside the segment, share it there, and have the target pull it
locally; route only the small control operations through the proxy. The same
applies in reverse for exfiltrating a large dump.

## Losing every implant at once

Implants die together for environmental reasons far more often than they are
caught: a host reboots, a domain controller you have been hammering becomes
unstable, a scheduled job re-applies configuration that removes your access.

When everything drops simultaneously, treat it as an environment event, not a
detection event. Do not hammer the fallback — repeated authentication attempts
against a directory-dependent service risk a real lockout on top of an outage.
Wait a few minutes, retest once, and use the time to write down what is already
recovered and independent of live access.

Two habits make this survivable, and both belong in the campaign state rather
than in your memory: keep at least one access path that does not depend on the
framework, and record the exact next command before you need it.

## Note what heavy operations cost

Volume snapshots, database dumps, and repeated remote process creation on a
domain controller are how a lab environment gets destabilised, and the access you
lose is your own. Prefer the lighter equivalent when there is one, take the dump
once, and pull it out of the environment immediately — a copy on your own disk
keeps its value after every session in the environment has died.
