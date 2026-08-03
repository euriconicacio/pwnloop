# Snapped — Hack The Box, Hard, Linux

**TL;DR:** An `admin.` vhost runs **Nginx UI 2.3.2**, whose `GET /api/backup`
endpoint is reachable with no authentication *and* returns the AES key+IV for the
archive in the `X-Backup-Security` response header. The backup contains the app's
`app.ini` and SQLite database: the node secret (a full API-auth bypass via
`X-Node-Secret`), the JWT secret, and two bcrypt hashes. `jonathan`'s hash cracks
to `linkinpark`, which is reused for the system SSH account (user). Root is
**PackageKit CVE-2026-41651 "Pack2TheRoot"** — a TOCTOU race in the `InstallFiles`
D-Bus method that installs an attacker `.deb` as root — left deliberately unpatched
while sudo on the same host was patched.

---

## Two ports and a redirect

```
22/tcp open ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open http    nginx 1.24.0 (Ubuntu)  ->  302 http://snapped.htb/
```

Full-range scan confirmed nothing else. `snapped.htb` itself is a static brochure —
no forms, directory fuzzing finds only `/` and `style.css`. So the content is on
another vhost.

The first `ffuf` for vhosts found nothing because the filter was set to the size
of the *brochure* (`-fs 20199`). A non-existent vhost here returns a **302 of size
154**, not the brochure — so nothing got filtered and nothing stood out. Filtering
on the size of a *deliberately wrong* `Host` is the fix; a short list of likely
names by hand found it immediately:

```
admin -> 200 1407      # everything else -> 302 154
```

`admin.snapped.htb` is **Nginx UI** (0xJacky/nginx-ui).

## The backup route that needs no login

Nginx UI's API mostly requires auth — `/api/settings` returns `403 Authorization
failed`. Walking the API surface from the frontend bundle turned up one route that
does not:

```
$ curl -s -D- http://admin.snapped.htb/api/backup -o backup.zip
HTTP/1.1 200 OK
Content-Disposition: attachment; filename=backup-20260101-000000.zip
X-Backup-Security: <base64-key>:<base64-iv>
```

Two gifts in one response. The body is an encrypted archive — and the
`X-Backup-Security` header is `base64(key):base64(iv)` for it. The server encrypts
the backup and hands the downloader the key. AES-256-CBC:

```python
key, iv = map(b64decode, SEC.split(":"))
AES.new(key, AES.MODE_CBC, iv).decrypt(blob)
```

Inside: `hash_info.txt` (**version 2.3.2**), and nested `nginx-ui.zip` /
`nginx.zip`. The nginx-ui archive holds `app.ini` and `database.db`.

## Everything is in app.ini

```ini
[app]     JwtSecret = <uuid>
[node]    Secret    = <uuid>
[crypto]  Secret    = <hex>
[terminal] StartCmd = login
```

and `database.db` has two users with bcrypt hashes (`admin`, `jonathan`).

The instinct is to forge a JWT. Reading the source (`internal/user/user.go` at
v2.3.2) shows the token is `HS256` over `{name,user_id,...}` signed with
`JwtSecret` — so a forged admin token is easy to mint. It is **rejected**: the
middleware (`internal/middleware/middleware.go`) looks the token up in the
`auth_tokens` table, so a signature-valid token that was never issued fails.

But the same middleware has an earlier branch:

```go
if nodeSecret := getNodeSecret(c); nodeSecret != "" && nodeSecret == settings.NodeSettings.Secret {
    c.Set("user", user.GetInitUser(c)); c.Next(); return
}
```

The **node secret** — meant for cluster-to-cluster calls — is a straight API-admin
bypass via the `X-Node-Secret` header (or `?node_secret=`). `GET /api/settings`
with it returned the full live config. Full app admin, no password.

## The app-admin dead ends (worth knowing)

Being API admin as `www-data`, the obvious next thought is RCE. Both clean-looking
routes are closed on 2.3.2:

- **`/api/pty`** is a WebSocket terminal. It authorises (node secret in the query
  string) and connects — but it runs `settings.TerminalSettings.StartCmd`, which is
  `login`, and Nginx UI runs as `www-data`, so `login` aborts: *"Cannot possibly
  work without effective root."*
- **`/api/settings` → set `nginx.reload_cmd`/`test_config_cmd` → `/api/nginx/test`**
  would be command execution (the handler even returns stdout). But every nginx
  command field is tagged `protected:"true"` and `ProtectedFill` skips them on
  save, so they cannot be set through the API.

## The oldest trick: reuse

`jonathan`'s bcrypt fell to rockyou in seconds:

```
jonathan:linkinpark
```

and it is the *system* password too:

```
$ sshpass -p linkinpark ssh jonathan@10.129.x.x id
uid=1000(jonathan) gid=1000(jonathan)
```

`user.txt`. The application credential and the shell credential were the same.

## Root: the one package left behind

`jonathan` has no sudo, no special groups, standard SUID/caps, no writable units,
no exploitable cron; `pspy` shows only DHCP and tmpfiles noise. One dead end ate
real time: `/var/metrics`, a non-default `root:whoopsie` world-writable setgid
directory — exactly the shape of a "root job processes files you drop here"
privesc. But nothing references it (no cron, timer, `.path` unit, or binary
containing the string), and a canary file sits untouched. It is a decoy. The
lesson: a suggestive directory is not a vulnerability until you find its consumer —
verify the consumer before investing.

The real escalation is a patch **asymmetry**. sudo is `1.9.15p5` — in range for
CVE-2025-32463 — but the package is `1.9.15p5-3ubuntu5.24.04.2`, the *patched*
security update, and a hand-built portable NSS module fails cleanly against it.
PackageKit, however, was left behind:

```
PackageKit 1.2.8-2ubuntu1.4   (fixed: -3ubuntu1.5)  -> CVE-2026-41651 "Pack2TheRoot"
```

On a curated box, one carefully-patched package next to one carefully-un-patched
one is not an accident. Reading the vendor advisory: Pack2TheRoot is a TOCTOU race
in PackageKit's `InstallFiles` D-Bus method. `FLAG_SIMULATE` is treated as a safe
operation and passes polkit; the daemon re-caches the transaction's flags on every
`InstallFiles` call with no state guard. So:

1. `InstallFiles(FLAG_SIMULATE=4, [dummy.deb])` — polkit authorises the "safe"
   simulate.
2. Immediately `InstallFiles(FLAG_NONE=0, [payload.deb])` on the **same**
   transaction, before the first resolves.
3. When authorization lands, the daemon reads the overwritten flags and does a real
   install — of the payload — as root.

The payload is a one-line `.deb`:

```
postinst:  install -m 4755 /bin/bash /var/tmp/.suid_bash
```

The target had everything the public PoC needs (`python3-gi`, `dpkg-deb`, the
D-Bus-activatable daemon). It won on the first race:

```
[+] Confirmed: /var/tmp/.suid_bash is SUID root
$ /var/tmp/.suid_bash -p -c id
uid=1000(jonathan) euid=0(root)
```

`root.txt`. (Note for cleanup: each race run registers a `.deb` in dpkg, and
`dpkg --purge` needs a real uid 0 — `bash -p` only sets euid — so purge with
`python3 -c 'os.setresuid(0,0,0)'` and wait out the PackageKit-held frontend lock.)

## The shape of it

- **Front door:** an unauthenticated backup endpoint that returns its own
  decryption key. Encryption you hand the key to is not a control.
- **Amplifier:** one config file holding a secret that *is* API admin, plus a
  password reused between the app and the shell.
- **Root:** an inconsistent patch cadence — sudo fixed, PackageKit one version
  short — turned a generic any-user CVE into the intended escalation.

Any single fix breaks a link, but the one that matters is the backup route: it is
the only unauthenticated step, and everything else is what that one archive
contained.

---

*Flag values redacted; the machine is retired. The privilege-escalation CVE was
studied from its public advisory and proof-of-concept — technology research, not a
walkthrough of this host.*
