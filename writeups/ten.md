# Ten — Hack The Box, Hard, Linux

**TL;DR:** A "free static-page hoster" hands out **FTP** accounts and a
`<domain>.ten.vl` vhost per signup. PHP is disabled on customer vhosts and every
dotfile (`.htaccess`, `.user.ini`) is blocked at upload, so the obvious
"re-enable PHP" routes are dead ends. The real door is a **second virtual host**,
`webdb.ten.vl` — an unauthenticated **WebDB** database GUI proxied to the local
MySQL — that only shows up with a large subdomain wordlist. WebDB *guesses* the
MySQL credentials for you and gives arbitrary SQL over the **Pure-FTPd virtual-user
table**. Rewrite your own FTP row to `Uid/Gid 1000` and, defeating a
`dir LIKE '/srv%'` CHECK constraint with `/srv/../home/tyrell/.ssh/`, point the
account at another user's `.ssh`; upload `authorized_keys` and SSH in as `tyrell`.
Root is a **template-injection**: the signup handler writes your domain into
**etcd**, a root `remco` daemon renders that value into an Apache vhost file and
restarts Apache, so a newline in the etcd value injects a `CustomLog "|command"`
**piped-log** directive that runs as root.

*Flags redacted. Machine address generalised to `10.129.x.x`. Hostname (`ten.vl`),
service versions, and the app's own logic are kept — they are properties of the box.*

---

## Recon: three ports and a hosting company

`21` (Pure-FTPd), `22` (OpenSSH 8.9p1, Ubuntu 22.04), `80` (Apache 2.4.52). The
site is *Ten*, a retro "static file hosting" company. `/signup.php` posts a
`domain` to `/get-credentials-please-do-not-spam-this-thanks.php`, which after a
deliberate ten-second delay returns a random FTP username/password and a personal
`<domain>.ten.vl` vhost. `/info.php` is a full **phpinfo** — the main site runs
PHP as `www-data` with `disable_functions` empty and no `open_basedir`.

Log into FTP with the issued creds and files uploaded there are served at your
subdomain. Two things are enforced:

- **PHP does not execute on customer vhosts.** `shell.php`, `.phtml`, `.phar`,
  `.php3-7`, `.pht` all come back as source with static `ETag`/`Accept-Ranges`
  headers — the handler is removed for those directories.
- **No dotfiles.** Pure-FTPd answers `553 Prohibited file name` to any name whose
  path has a component starting with `.` — on `STOR`, `RNTO`, `DELE` and `MKD`
  alike. The site even brags about it: *"we can't allow .htaccess files anymore —
  for obvious reasons."*

## The wall (and the dead ends worth knowing)

With PHP off and dotfiles blocked, the standard "turn PHP back on in my own
directory" moves are gone, and it is easy to burn hours confirming it:

- `.htaccess` / `.user.ini` — both are dotfiles; blocked four different ways.
  Even a non-dot `AccessFileName` guess (`htaccess`, `apache.conf`, …) does
  nothing: `AccessFileName` is default.
- **mod_negotiation is active** — a `.var` type-map is parsed — but it can only
  serve files inside your own docroot (traversal is rejected), and forcing
  `Content-Type: application/x-httpd-php` does not execute the target, because
  PHP is bound by `SetHandler` on the extension, not by MIME type.
- No LFI anywhere in the five PHP pages (parameter-mined with a 6.5k list, GET and
  POST, plus PATH_INFO / header / cookie), no injection in the `domain` parameter
  (strict `^[a-z0-9]+$`, no newline/HPP/array bypass), no SSRF, no admin bot, no
  background job that consumes uploaded files.

The lesson: when the write primitive you have (static upload to an isolated,
PHP-less vhost) cannot reach code execution *no matter what*, the intended path is
usually **a different service you haven't found yet**, not a cleverer bypass of
the one in front of you.

## The turn: a second vhost

The site is clearly vhost-routed (`<domain>.ten.vl`), so the subdomain space is
worth fuzzing — but with a **large** wordlist. A short list (top-5000) returns
only the domains you registered yourself and reads like "there's nothing here";
the top-20000 list surfaces the one that matters:

```
ffuf -u http://10.129.x.x -H 'Host: FUZZ.ten.vl' \
     -w subdomains-top1million-20000.txt -ac
webdb   [Status: 200, Size: 1685]
```

`webdb.ten.vl` is a **WebDB** instance (an Angular DB-management SPA) reverse-proxied
to a local database. A single unlisted vhost was the entire entry point.

## WebDB → the Pure-FTPd user table

WebDB's API lives under `/api/`:

- `GET /api/server/scan` → `[{"wrapper":"MySQL","host":"127.0.0.1","port":3306}]`.
- `POST /api/server/guess` with that server object → WebDB brute-guesses common
  credentials and hands back the working pair: **`user:pa55w0rd`**.
- `POST /api/query/run` runs arbitrary SQL. The SPA passes the connection context
  in request headers — `Server: <json of the server>` and `Database: <name>` —
  which is easy to miss if you only look at the JSON body; read it out of the
  bundle (`http.post(apiRootUrl+…, body, {headers})`).

The MySQL database is `pureftpd`, and its `users` table **is** the Pure-FTPd
virtual-user store: `User`, a `crypt`ed `Password`, `Uid`, `Gid`, and `Dir`.

## Foothold: rewrite your own FTP account

Pure-FTPd re-reads this table on every login, so editing your own row changes who
you are on the next connection. Two constraints shape the exploit:

- A DB **CHECK constraint** `dir_must_start_with_slash_srv` rejects any `Dir` that
  does not begin `/srv`. Bypass it with traversal that *starts* with `/srv`:
  `/srv/../home/tyrell/.ssh/` passes the string check and resolves to
  `/home/tyrell/.ssh`.
- `/etc/passwd` (readable once you traverse) shows one non-root shell user,
  `tyrell` (uid 1000). Set your row's `Uid`/`Gid` to `1000` so the FTP session
  runs *as* tyrell and can write into their `.ssh`.

```sql
UPDATE users SET Uid=1000, Gid=1000, Dir='/srv/../home/tyrell/.ssh/'
WHERE User='ten-xxxxxxxx';
```

Reconnect over FTP: the session is now chrooted to tyrell's `.ssh`, running as uid
1000. The dotfile filter blocks `.ssh` as a *path*, but the base directory was set
in the database, so the filename you upload — `authorized_keys` — has no leading
dot and is accepted. Drop your public key and SSH in as `tyrell` for `user.txt`.

(Setting `Dir` straight to `/home/tyrell/.ssh` is rejected by the constraint;
`/srv/..`-prefixing is the whole trick. Overwriting an existing `authorized_keys`
is destabilising for a shared box — append instead where you can.)

## Root: etcd → remco → Apache piped logs

Reading the site source as tyrell explains the ten-second signup and the vhost
magic. `get-credentials-…php` does:

```php
system("ETCDCTL_API=3 /usr/bin/etcdctl put /customers/$username/url " . $_POST['domain']);
```

and a root daemon, **remco**, watches etcd and templates the customer list into
Apache config:

```toml
# /etc/remco/config
src        = "/etc/remco/templates/010-customers.conf.tmpl"
dst        = "/etc/apache2/sites-enabled/010-customers.conf"
reload_cmd = "systemctl restart apache2.service"
```

```jinja
{% for customer in lsdir("/customers") %}
<VirtualHost *:80>
	ServerName {{ getv(printf("/customers/%s/url",customer)) }}.ten.vl
	DocumentRoot /srv/{{ customer }}/
</VirtualHost>
{% endfor %}
```

etcd on `127.0.0.1:2379` has no auth, and tyrell can write it directly. The
`url` value is dropped verbatim into the `ServerName` line, so a **newline** in the
value injects arbitrary Apache directives into a root-generated config that root
then loads. The primitive to reach for is an Apache **piped log** — `CustomLog
"|<program>"` runs `<program>` as root when Apache (re)opens its logs, which is
exactly what `systemctl restart apache2` does:

```bash
ETCDCTL_API=3 /usr/bin/etcdctl put /customers/ten-xxxxxxxx/url 'privesc.ten.vl
	CustomLog "|/bin/bash -c '\''mkdir -p /root/.ssh && cat /home/tyrell/.ssh/authorized_keys >> /root/.ssh/authorized_keys'\''" combined
	#'
```

The trailing `#` comments out the `.ten.vl` the template appends. Within a few
seconds remco re-renders the config and restarts Apache; the pipe runs as root and
appends your key to `/root/.ssh/authorized_keys`. SSH in as root for `root.txt`.

## What would have stopped it

- **The database is the security boundary and it is unauthenticated.** WebDB
  exposed the Pure-FTPd credential store with a guessable password and no access
  control; the `Uid`/`Gid`/`Dir` columns are effectively "become any user, chroot
  anywhere." A CHECK constraint on `Dir` is not containment when `../` satisfies it.
- **remco renders an attacker-controlled string into a privileged config with no
  escaping.** Treat any value that crosses from a user request into a root-rendered
  config/template as injection: validate it to a strict charset (the app already
  validates `domain` to `[a-z0-9]` for its own use — the same value reaches etcd
  *unvalidated*), or render through a mechanism that cannot express directives.
