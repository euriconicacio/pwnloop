# Forgotten — Hack The Box, Easy, Linux

**TL;DR:** A LimeSurvey box with a twist: the app ships **uninstalled**, and the
installer trusts *your* database. Point it at a MariaDB you control, walk the
wizard, create your own admin account, and an admin plugin upload is PHP
execution as `www-data` in a container. The container's environment carries a
password that is reused for SSH on the host; the container's app directory is a
writable bind mount of a host directory with no user-namespace remapping, so
container-root plants a setuid-root shell that the host — mounted without
`nosuid` — happily executes.

*Flags redacted. Machine address generalised to `10.129.x.x`.*

---
A LimeSurvey box with a twist: the app ships **uninstalled**, and the installer
trusts *your* database. Foothold is turning that into an admin account and then a
plugin webshell; privilege escalation is a container escape through a bind mount.

---

## Recon

Two ports:

```
22/tcp  OpenSSH 8.9p1 Ubuntu (22.04)
80/tcp  Apache 2.4.56 (Debian)   -> Service Info: Host: 172.17.0.2
```

The `Host: 172.17.0.2` in nmap's service info is the first tell: the web server
answers from a Docker bridge address, so port 80 is a container.

The web root is `403`. Content discovery is what opens the box:

```
feroxbuster ... http://10.129.x.x/
301  /survey  ->  /survey/{admin,plugins,modules,themes,upload,installer}
```

`/survey/` is **LimeSurvey** (PHP/8.0.30, Yii), and it redirects straight to
`index.php?r=installer/welcome`. The application has never been installed.

## Foothold — install LimeSurvey against a DB you control

The installer's pre-check confirms version **6.3.7** and that `application/config`,
`upload`, and `tmp` are writable. The database step asks for a DB host — and it
accepts *any* host. The target has no local database, so point it at one you own:

1. Stand up MariaDB on the VPN-facing attacker host, bound to `0.0.0.0`, with a
   remotely-usable account.
2. Walk the installer (`welcome → license → precheck → database → createdb →
   populatedb → optional`), keeping a cookie jar so the Yii `YII_CSRF_TOKEN`
   cookie matches the form token on every POST. In the *database* step give your
   attacker host/user/pass; in *optional* create the admin account.

The installer writes `config.php` on the target (pointing at your DB) and reports
100%. You can now log in at `index.php/admin/authentication/sa/login`.

> **Gotcha worth writing down:** once `config.php` points at a *remote* DB, every
> LimeSurvey page round-trips queries across the VPN. Fire requests concurrently
> and you exhaust Apache's workers and wedge the box. Drive it strictly one request
> at a time, with generous timeouts.

## Foothold — plugin upload → webshell

LimeSurvey admin = PHP execution. Package a minimal plugin (a valid `config.xml`, a
`PluginBase` subclass so validation passes, and a one-line PHP command file) into a
zip and upload it:

- `POST /admin/pluginmanager/sa/upload` (path-style route; the query-style
  `?sa=upload` tripped CSRF handling in testing — use `/sa/upload`).
- Follow up with `?sa=uploadConfirm` → `sa=installUploadedPlugin`.

The confirm step moves the plugin under the **web-served** `upload/plugins/PwnPlugin/`.
The PHP command file is a plain script (it never loads LimeSurvey's framework), so
calling it is instant and DB-free even while the admin UI crawls:

```
GET /survey/upload/plugins/PwnPlugin/lime.php?c=id
-> uid=2000(limesvc) gid=2000(limesvc) groups=2000(limesvc),27(sudo)
   hostname: efaa6f5097ed         # the container
```

## From container webshell to host user

The container environment hands you a credential:

```
LIMESURVEY_PASS=5W5HN4K4GCXf9E
```

`limesvc` is in the container's `sudo` group *and* the password is reused for SSH on
the host:

```
ssh limesvc@10.129.x.x      # host hostname: forgotten
cat ~/user.txt                 # <redacted>
```

## Privilege escalation — container escape via bind mount

On the host, `limesvc` has no sudo. The interesting fact:

- The container runs the app from `/var/www/html/survey`, which is the host's
  `/opt/limesurvey` **bind-mounted** in.
- Inside the container `limesvc` has `sudo (ALL) ALL` (the env password again).
- Docker here uses **no user-namespace remapping**, so container uid 0 == host uid 0
  *on the mount*.

Verify the mapping — a file written by container-root shows up as `root:root` on the
host:

```
# in container:  sudo bash -c 'echo x > /var/www/html/survey/t2.txt'
# on host:       -rw-r--r-- 1 root root ... /opt/limesurvey/t2.txt
```

Host `/` is `ext4 rw,relatime` — **not `nosuid`**. So plant a setuid-root shell
through the mount and run it from the host:

```
# in container (as root):
cp /bin/bash /var/www/html/survey/.rb
chown root:root /var/www/html/survey/.rb
chmod 4755 /var/www/html/survey/.rb

# on host (as limesvc):
/opt/limesurvey/.rb -p -c 'id; cat /root/root.txt'
-> euid=0(root)
   <redacted>
```

Root.

## Leads that didn't pan out

- **`127.0.0.1:42665`** — a root-owned Go HTTP service returning only
  `404: Page Not Found`. Fuzzing found no routes; the only non-404 was Go's
  `cleanPath` 301 on any `//`, which made a phantom `/render/<url>` look real. As
  root, `ss` showed the owner is **containerd** — container-runtime plumbing, not a
  path. Parked correctly; don't chase runtime infra ports.
- `amazon-ssm-agent`, `laurel` auditing — cloud/base-image furniture, not the box.

## Takeaways

- An **uninstalled** web app whose installer trusts an attacker-supplied database is
  full unauthenticated takeover — the installer is the vulnerability.
- Web-tier RCE → host is almost always **credential reuse**; grep the environment
  first.
- A read-write **bind mount + no userns-remap + suid-capable host FS** is a clean
  container escape: container-root drops a setuid-root binary that the host executes.
