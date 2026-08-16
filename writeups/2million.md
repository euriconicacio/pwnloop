# 2Million — Hack The Box (retired)

**Easy · Linux**

*Flag values redacted; target/VPN addresses generalised.*

**OS:** Linux (Ubuntu 22.04)
**Path:** unauthenticated API abuse → mass-assignment admin → command injection →
credential reuse → CVE-2023-0386 local root

---

## Recon

Two ports:

```
22/tcp  OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp  nginx  → 301 http://2million.htb/
```

The 301 from the raw IP is the first tell: the site is vhost-gated, so
`2million.htb` goes into `/etc/hosts`. The homepage is a pixel-clone of the old
Hack The Box landing page, with `/invite` and `/login`.

## Foothold — the invite API

`/invite` loads a packed script, `js/inviteapi.min.js`. Unpacking the
`eval(function(p,a,c,k,e,d)...)` wrapper reveals two API calls:

```
POST /api/v1/invite/verify
POST /api/v1/invite/how/to/generate
```

Calling the second returns a hint whose `enctype` is literally `ROT13`:

```json
{"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr","enctype":"ROT13"}}
```

ROT13 → *"In order to generate the invite code, make a POST request to
/api/v1/invite/generate"*. That endpoint hands out a base64-wrapped code with no
authentication:

```
POST /api/v1/invite/generate → "SlVORVAt...=" → JUNEP-O6GON-MS17T-5XAF9
```

Register with it, log in (the login/register handlers only accept
**form-encoded** bodies — JSON is silently ignored, a five-minute detour worth
noting), and land on `/home`.

## Privilege escalation inside the app

The single most useful authenticated request is `GET /api/v1` — it returns the
entire route table, including an `admin` group the UI never links:

```
PUT  /api/v1/admin/settings/update
POST /api/v1/admin/vpn/generate
GET  /api/v1/admin/auth
```

`admin/settings/update` walks the caller through its required parameters via
error messages (`Missing parameter: email` → `Missing parameter: is_admin`) and
then **just does what it's told** — there is no check that the caller is already
an admin:

```
PUT /api/v1/admin/settings/update  {"email":"pwnloop@2million.htb","is_admin":1}
→ {"id":13,"username":"pwnloop","is_admin":1}
```

`GET /api/v1/admin/auth` now returns `true`.

## RCE — the VPN generator

The admin endpoint `admin/vpn/generate` builds an OpenVPN profile for a named
user. The `username` goes straight into a shell. Since the response body is the
`.ovpn` file (not command output), I confirmed injection with a timing oracle
rather than guessing:

```
{"username":"aa"}          → 6.1 s
{"username":"aa; sleep 7; #"} → 20.7 s
```

Clean 7-second delta. Swap the payload for a base64'd bash reverse shell and
catch `www-data`.

## user.txt — read the deployed config, not the leak

First move as `www-data` is the app's live `.env`:

```
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Password reuse is the most common intended lateral path on these boxes, and it
holds here: `ssh admin@2million.htb` with `SuperDuperPass123` works. `user.txt`
is in `admin`'s home.

## root.txt — the mail told me which door

`admin` has no sudo, no unusual SUID/caps/cron. But `/var/mail/admin` is a
plant:

> *"...can you also upgrade the OS on our web host? ... That one in
> OverlayFS / FUSE looks nasty."*

That names the vulnerability class outright. The kernel is mainline **5.15.70**
on Ubuntu 22.04 — squarely in range for **CVE-2023-0386**, the OverlayFS SUID
copy-up bug. Preconditions all present: unprivileged user namespaces enabled
(`max_user_namespaces=15248`), world-writable `/dev/fuse`, and `libfuse-dev` +
`gcc` on the box so the PoC compiles in place.

The mechanism: OverlayFS copies a file up from `lowerdir` into `upperdir`
without checking that the file's owner is mapped in the caller's user namespace.
Serve a **root-owned setuid** binary from a FUSE filesystem as the lower layer,
trigger a copy-up, and the upper copy is a *genuine* root setuid binary.

```
./fuse ./ovlcap/lower ./gc     # FUSE serves -rwsrwxrwx root:root "file"
./exp                          # unshare userns, mount overlay, touch merge/file
                               # → ./upper/file executes as real root
uid=0(root) gid=0(root) groups=0(root),1000(admin)
```

I patched the PoC's payload to a reverse shell so it runs non-interactively.
`root.txt` follows.

---

## Leads that cost time (and why)

- **JSON vs form-encoded auth.** `login`/`register` ignore JSON bodies and
  return `Please enter an email`; only `-d "email=...&password=..."` works. Two
  wasted requests before I read the register form's `enctype`.
- **Route-list disclosure is the whole engagement.** Everything after the
  foothold came from `GET /api/v1`. On an unfamiliar app, ask the API to
  describe itself before fuzzing.

## What would have stopped it

Authorization on `/api/v1/admin/*`. The mass-assignment is the hinge — remove
self-promotion to admin and the command-injection endpoint is unreachable from
the network, collapsing the remote half of the chain. The credential reuse and
the kernel CVE then need an attacker who is already local.
