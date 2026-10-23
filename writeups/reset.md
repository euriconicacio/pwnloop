# Reset — Hack The Box, Easy, Linux

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

## Recon

Two TCP ports: `22` (OpenSSH 8.9p1, Ubuntu Jammy) and `80` (Apache 2.4.52).
Port 80 serves an "Admin Login" with a "Forgot password?" modal that POSTs to
`reset_password.php`.

## Foothold — the reset *is* the bug

`reset_password.php` resets a user's password and **returns the new password in
the JSON response**:

```
POST /reset_password.php   username=admin
→ {"username":"admin","new_password":"62a8abe7","timestamp":"…"}
```

Reading the source later (via RCE) confirmed it: it generates
`bin2hex(random_bytes(4))`, stores `sha1()` of it, and echoes the cleartext back.
It is also a user-enumeration oracle (`{"error":"User not found"}`).

Logging in with that password lands on `dashboard.php`, a log viewer with a
`file=` select limited to syslog/auth.log. Its validation:

```php
define('ALLOWED_BASE_DIR', '/var/log');
function isValidFile($f){ $r=realpath($f); return $r && strpos($r,ALLOWED_BASE_DIR)===0; }
...
ob_start(); include($file); $logs = explode("\n", ob_get_clean());
```

It **`include()`s** the file. Any existing, readable file under `/var/log` is
therefore executed as PHP. `/var/log/apache2/access.log` is both readable (by
www-data) and attacker-writable (via the request line / `User-Agent`), so:

1. send a request whose `User-Agent` is `<?php system(base64_decode($_GET['c']));?>`
2. select `file=/var/log/apache2/access.log` with `?c=<base64 cmd>`

→ RCE as `www-data`. A marker (`<?php echo 7*191; ?>` → `1337`) confirmed it.

### A self-inflicted lesson
On the first spawn I fingerprinted PHP by passing a snippet *through the
container shell wrapper*, which mangled a quote into a stray backslash inside the
`<?php … ?>` I'd written to `access.log`. PHP compiles the included log as one
unit, so that one syntax error made every later `include(access.log)` return 0
bytes — the channel was burned. The box had to be reset. On the clean box I drove
the whole channel from Python (payloads built in code, never through the shell)
and dropped a webshell into a world-writable `private_*` dir in the webroot.

## user.txt

`/home/sadm/user.txt` is world-readable.

## www-data → sadm — the audit log is a credential store

`id` shows www-data is in group **`adm`**. On this box
`/var/log/audit/audit.log` is `root:adm 0640` — **adm-readable**. auditd is
configured with EXECVE capture (and LAUREL is installed), so every command's
arguments are logged.

The root unit `boot.service` runs `/usr/bin/expect /root/.scripts/auto.expect`,
which keeps a detached `sadm` tmux session (`sadm_session`) and periodically
drives it with `sudo -u sadm tmux send-keys …`. Decoding the hex EXECVE argv in
the audit log:

```
tmux send-keys -t sadm_session 'echo 7lE2PAfVHfjz4HpE | sudo -S nano /etc/firewall.sh' C-m
```

The box types sadm's password into `sudo -S` — so it sits in cleartext in a log
the web user can read. `grep -a type=EXECVE /var/log/audit/audit.log` and decode
the hex-encoded args (any arg with special characters is hex).

`sadm`'s password: `7lE2PAfVHfjz4HpE`. SSH in.

## sadm → root — sudo nano

```
$ sudo -l
  (ALL) PASSWD: /usr/bin/nano /etc/firewall.sh
  (ALL) PASSWD: /usr/bin/tail /var/log/syslog
  (ALL) PASSWD: /usr/bin/tail /var/log/auth.log
```

`nano` run as root is a GTFObin: press `^T` (Execute) and type a command, which
runs as root. (Equivalently `^R^X`.) I used it to drop a NOPASSWD sudoers rule,
then read `root.txt` at the non-standard path `/root/root_279e22f8.txt`.

## Leads that cost time (and why)

- **r-services as the privesc.** inetd serves 512/513/514, SUID `netkit-rsh`
  exists, `/etc/hosts.equiv` has `+ sadm`, and `local` is in the `lxd` group — a
  textbook "become the trusted host" setup. I spent real time here before
  realising it is a dead end *as www-data*: the box's egress DNS is firewalled, so
  `rshd`'s `getnameinfo()` on the attacker IP returns `EAI_AGAIN` and it refuses
  the connection; and from the box itself www-data can neither bind a privileged
  source port nor present `ruser=sadm`. The trust is only usable *after* you are
  already `sadm`/`local`. It was flavour, not the door. The real door was the
  boring, adm-readable audit log.
- **A root "reset" cron** — there isn't one; `boot.service` runs once at boot.
  Deleting the root-owned `db.sqlite` did not trigger a recreate.

## Chain

unauth password-reset disclosure → authenticated log-poison LFI→RCE (www-data) →
`adm`-readable audit log leaks sadm's `sudo -S` password → SSH as sadm →
`sudo nano` execute → root.
