# Conversor — Hack The Box, Easy, Linux

**TL;DR:** A "prettify your Nmap XML" web app converts an uploaded XML with an
uploaded XSLT sheet — user-controlled XSLT is arbitrary code waiting to happen.
The processor is libxslt (via Python lxml); external entities are disabled, but
EXSLT `exsl:document` still gives arbitrary file **write** as `www-data`. A
downloadable `source_code.tar.gz` hands over the app layout and, crucially, a
deployment note: a per-minute cron runs every `.py` in a web-writable `scripts/`
directory. Write a Python file there → code execution → dump the SQLite users
table → crack an MD5 → SSH as `fismathack`. Root is a `sudo NOPASSWD` on
`needrestart` 3.5, vulnerable to CVE-2024-48990.

*Flags redacted. Machine address generalised to `10.129.x.x`. Service versions,
hostname and the app's own files are kept, as they are properties of the box.*

---

## Two ports, one vhost

`22` and `80`. Port 80 (Apache 2.4.52) redirects the raw IP to `conversor.htb`,
so the hostname goes into `/etc/hosts` before anything else. The app is Flask
(Werkzeug's redirect pages give it away) and everything sits behind a login;
registration is open, so a throwaway account gets you to the one interesting
feature: **Conversor**, which takes an XML file *and an XSLT stylesheet* and
returns a rendered result. A converter that accepts a user-supplied stylesheet is
handing you the transform language, and XSLT is Turing-complete with I/O
extensions.

## Fingerprint the processor before firing

The first XSLT is a probe, not an exploit — ask the engine what it is:

```xml
<xsl:value-of select="system-property('xsl:vendor')"/>
```

Answer: **libxslt 1.0** — the C library behind Python's lxml. That decides which
primitives are on the table. Two tests map the surface:

- **`document('file:///etc/fonts/fonts.conf')`** returns content → file **read**
  works, but only for well-formed XML (reading `/etc/passwd` throws "Cannot
  resolve URI" because it will not parse).
- **`document('http://<me>/')`** never arrives → outbound is firewalled, so SSRF
  is out (this is the target's egress, not an lxml restriction).
- **`exsl:document href="file:///tmp/x.xml"`** followed by reading it back →
  arbitrary file **write** works.

XXE via external entities (in the XML *or* in the XSLT DOCTYPE) is dead: the app
parses the XML with `resolve_entities=False, no_network=True, load_dtd=False`.
But it builds the XSLT with a *default* parser and no `XSLTAccessControl`, so the
transform's own file I/O — `document()` and `exsl:document` — is wide open. Read
is limited to XML; **write is not limited at all**.

## The source archive removes the guesswork

Content discovery turns up `/static/source_code.tar.gz` — the whole application.
It confirms the app lives at `/var/www/conversor.htb`, runs under mod_wsgi as
`www-data`, stores users in `instance/users.db` (passwords hashed with plain
MD5), and — in `install.md` — documents the deployment's own foot-gun:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

A root-adjacent cron that executes **any** `.py` in a directory the web app can
write to. The arbitrary-write primitive from step one now has a target.

## Write → execute → dump the database

`exsl:document` writes a Python payload into `scripts/`. One libxslt quirk costs
a few iterations: `exsl:document` does not preserve newlines the way you expect
across the text method, so a multi-line script silently becomes a syntax error —
collapse the payload to a single line of `;`-separated statements and it runs.
The script base64-encodes its output into an XML file under `uploads/`, which the
same `document()` read primitive fetches back — a clean request/response channel
despite the firewalled egress.

The payload dumps `id` (`www-data`), `/etc/passwd` (the human user is
`fismathack`), and the live `users.db`:

```
fismathack : 5b5c3ac3a1c897c94caad48e6c71fdec   (MD5)
```

Unsalted MD5 falls to `rockyou` instantly: **`Keepmesafeandwarm`**. It is reused
for the system account, so `ssh fismathack@…` lands the shell and `user.txt`.

## needrestart, the modern sudo classic

```
fismathack may run: (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

`needrestart` 3.5 (< 3.8) is vulnerable to **CVE-2024-48990**. When it scans
running processes to decide what to restart, it reads each process's
`PYTHONPATH` from `/proc/<pid>/environ` and re-invokes the Python interpreter
**as root** with that path inherited. So:

1. Drop a malicious `importlib/__init__.py` in a directory — its top-level code
   runs `cp /bin/bash /tmp/bash; chmod u+s /tmp/bash`, guarded by
   `if getuid()==0` so it only fires for root.
2. Start a bait `python3` process with `PYTHONPATH` pointed at that directory.
3. `sudo needrestart`. Root scans the bait, runs Python with our `PYTHONPATH`,
   imports our `importlib`, and creates a SUID root shell.

`/tmp/bash -p` → `euid=0`, and `root.txt`.

## What did not work, and the near-misses

- **XXE, both ways.** External general entities in the XML and an external entity
  in the XSLT DOCTYPE both return empty — the XML parser is locked down. The win
  was to stop trying to *read* text and start *writing* files instead.
- **`document()` on text files.** libxslt 1.0 has no `unparsed-text`; `document()`
  parses as XML, so `/etc/passwd` is unreadable through it. Text came out later,
  base64-wrapped in XML, via the code-execution channel — not via the reader.
- **`exsl:document` and directories.** It will not create parent directories and
  silently aborts the transform if they are missing, which reads like "write is
  blocked." It is not — the target directory simply has to exist (and `scripts/`
  did).
- **The reverse shell reflex.** Egress is filtered, so every callback attempt
  dies. The whole engagement is inbound: read results back through `document()`
  and `/view`, and take the shell over SSH with recovered creds.

## Defensive takeaway

The vulnerability is a single design decision: **running user-supplied XSLT
without an access-control policy.** lxml ships `XSLTAccessControl.DENY_ALL` for
exactly this; without it, a "make my XML pretty" feature is an arbitrary file
write. The rest of the chain is ordinary untidiness that the write primitive
weaponises — a source archive left in `/static`, a cron executing files from a
web-writable directory, unsalted MD5 password storage, and a blanket `sudo`
grant on an unpatched `needrestart`. Deny the XSLT I/O and the foothold never
forms; patch `needrestart` and the shell never becomes root.
