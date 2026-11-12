# underpass — HTB write-up

> **HTB · Easy · Linux · retired.** Flags redacted.

An `.htb` box where the whole path hinges on one UDP port that most scans skip,
and an escalation that is a single `sudo -l` line once you recognise what the
binary does.

---

## Recon

TCP shows almost nothing interesting:

```
22/tcp  OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp  Apache 2.4.52 — stock Ubuntu "It works" default page
```

A full `-p-` sweep adds no ports. The web root is the genuine Apache default
page (byte-for-byte), directory and file fuzzing turn up nothing, and vhost
fuzzing against `*.htb` with both the 20k and 110k subdomain lists returns
nothing. Two ports, both apparently dead ends — which is the cue to stop
trusting the TCP picture and look at **UDP**.

A UDP top-100 scan finds the lead:

```
161/udp  open  snmp
```

## SNMP is the whole introduction

SNMP answers to the default `public` community, and the system group has been
filled in by hand:

```
sysDescr    = Linux underpass 5.15.0-126-generic ... x86_64
sysContact  = steve@underpass.htb
sysName     = underpass
sysLocation = "UnDerPass.htb is the only daloradius server in the basin!"
```

That one `sysLocation` string hands over three things web enumeration never
would: the real hostname, the domain, and the **product** — daloRADIUS, the PHP
management front end for FreeRADIUS. Add `underpass.htb` to `/etc/hosts` and go
looking for it.

**Methodology note:** on a box that shows only a default web page, UDP 161 is a
hostname/vhost oracle. It is worth a top-100 UDP scan early rather than as a
last resort — here it was the only thing that named the application.

## daloRADIUS operator console

The app sits at `/daloradius/`. The operator login is
`/daloradius/app/operators/login.php` — daloRADIUS **2.2 beta**. Two small
gotchas:

- The form **posts to `dologin.php`**, not back to `login.php`; posting to the
  page you fetched just re-renders the form and looks like a failed login.
- It carries a `csrf_token`, so you must fetch the page, scrape the token, and
  submit it with the session cookie.

With that handled, the **shipped default operator credential works**:

```
administrator : radius
```

## From operator to a host password

The console lists managed RADIUS users. There is exactly one real subscriber:

```
username : svcMosh
MD5-Password : 412dd475…b382403
```

An unsalted MD5 of a dictionary word does not survive rockyou:

```
hashcat -m 0 svcmosh.hash rockyou.txt
412dd475…b382403 : underwaterfriends
```

The password is reused for the box's SSH account:

```
ssh svcMosh@underpass.htb      # underwaterfriends
```

…and that is the user flag.

## Privilege escalation: sudo mosh-server

`sudo -l` is a one-liner:

```
(ALL) NOPASSWD: /usr/bin/mosh-server
```

`mosh-server` is the server half of **mosh** (mobile shell). Run it and it prints
a connection line and spawns a **login shell for whoever connects** — and here it
runs as **root**:

```
$ sudo /usr/bin/mosh-server new
MOSH CONNECT 60001 <base64-key>
```

Connect the matching client to localhost with that key and you are root:

```
MOSH_KEY=<base64-key> mosh-client 127.0.0.1 60001
```

**The generalising lesson:** a NOPASSWD sudo entry for *any* program that forks
its own interactive session daemon — mosh-server, `screen`, `tmux`, `script` —
is equivalent to `sudo bash`. You don't need a GTFOBins trick; the program's
normal job is to hand you a shell, and sudo just made that shell root's.

### Driving mosh-client non-interactively

mosh-client wants a real terminal. Two traps when scripting it:

- It aborts with `Terminal::Framebuffer ... Assertion 's_height > 0' failed`
  if the pty has no window size — run it inside `script` and `stty rows/cols`
  first.
- Feed your commands as its stdin (keystrokes forwarded to the root shell).

A compact driver: start the server, parse port+key, then
`script -qc "stty rows 40 cols 120; mosh-client 127.0.0.1 $PORT" /dev/null`
with a small command file on stdin that does `chmod u+s /bin/bash` — turning the
one-shot root session into a reliable `bash -p` root shell for the rest of the
engagement. Read `/root/root.txt` and you're done.

---

## Chain in one line

SNMP `public` → product disclosure → daloRADIUS default `administrator:radius`
→ crack subscriber MD5 → reuse password over SSH → `sudo mosh-server` → root.

## What would have stopped it

Rotating the daloRADIUS default credentials alone breaks the chain before the
hash is ever exposed. Closing SNMP removes the signpost that makes the box
approachable in the first place.
