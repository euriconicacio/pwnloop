# race — Hack The Box, Hard, Linux

**TL;DR:** A Grav CMS box that is a chain of *disclosure* bugs. An unauth
file-existence oracle (Apache 403 vs Grav 404) enumerates accounts; phpSysInfo's
`ps` plugin leaks a `backup` password (Grav-panel-only, not SSH); the backup tool
plus Grav's password-reset flow takes `backup`→`patrick`; a Twig SSTI gap
(`file_get_contents`/`scandir` not on the denylist) leaks `max`'s password from a
commented script line; and a root cron that md5-validates then executes a script
in a `racers`-writable directory is a **TOCTOU race** (symlink flip) to root.

*Machine status: retired. Flag values are redacted here; the local copy keeps
them as evidence.*

Two open ports, one CMS, and a box whose name turns out to be the privesc.
The whole engagement is a chain of *disclosure* bugs — each one hands you the
next credential — capped by a textbook time-of-check/time-of-use race.

## Recon

`nmap` finds only 22 (OpenSSH 8.9p1) and 80 (Apache 2.4.52, Ubuntu 22.04).
Two ports means the path is on the web. `/` bounces to `/racers/`, a **Grav
CMS** site. Feroxbuster on the raw root also turns up one oddity: `/phpsysinfo`,
which answers `401` with realm `phpsysinfo (admin access only)`.

Fingerprinting Grav without a version header: md5-bisect the served static
assets against the upstream git tags. The bundled `jquery-3.x.min.js` matches
core ≤1.7.43 (1.7.44 bumped jQuery), and the admin theme CSS/JS pin the admin
plugin to 1.10.40–1.10.47. Later the backup confirms **core 1.7.43, admin
1.10.43** exactly.

## An unauthenticated file-existence oracle

Grav's stock `.htaccess` only routes *non-existent* paths into `index.php`
(`RewriteCond %{REQUEST_FILENAME} !-f`), then blanket-denies real files under
`bin|cache|logs|backup|…` and denied extensions under `user/`. The consequence:

- a path that **exists** → Apache `403` (279-byte error)
- a path that **doesn't** → Grav's `404` page (7350 bytes)

That's a free oracle. Fuzzing `user/accounts/FUZZ.yaml` enumerates three
accounts — `admin`, `patrick`, `backup` — and `user/plugins/*/blueprints.yaml`
lists the installed plugins. No credential needed for any of it.

## phpSysInfo hands over a password

The Basic-auth realm falls to `admin:admin` (a bounded, no-lockout guess of the
enumerated names against a short password list). Inside, phpSysInfo 3.4.3 has
the **`ps` plugin** enabled — it publishes the full argument vector of every
process. And there in the process list:

```
/usr/bin/curl --insecure --connect-timeout 60 \
  -u backup:Wedobackupswithsecur3password5.Noonecanhackus! \
  -T /var/www/html/racers/backup/ sftp://offsite-backup.race.htb/backups/
```

A root cron job passing a credential on the command line. That password is
**rejected by SSH** — a deliberate dead end if you assume service creds reuse to
shells — but it logs into the **Grav admin panel** as `backup`.

## backup → patrick, without cracking anything

`backup` only has `admin.maintenance`, so the one tool it can reach is
**Tools → Backups**. Trigger a site backup, download it: it contains
`user/accounts/*.yaml` — every bcrypt hash, and Grav's password-**reset token**
field.

The bcrypt hashes resist rockyou (slow, no hits), so cracking is the wrong turn.
The better move uses the backup tool as a read primitive against Grav's own
reset flow:

1. POST `login.forgot` for `patrick@race.htb` → Grav writes a fresh
   `reset: <token>::<expiry>` into `patrick.yaml`.
2. Run another backup, download it, read the new token.
3. POST `login.reset` with that token → set patrick's password.

`patrick` has Pages, Themes, and Config — the account that can reach code.

## Twig SSTI (the file_* gap)

Grav 1.7.43 ships `system.twig.undefined_functions: true`, and its
`Utils::isDangerousFunction()` denylist covers `system`, `exec`, `include`, and
the callback family — but **not** `file_get_contents`, `file_put_contents`,
`scandir`, `read_file`. So a page authored with `process.twig` enabled runs
those as `www-data`:

```
{{ 7*6 }}                                   -> 42
{{ read_file('/etc/passwd') }}              -> full passwd
{{ implode(',', scandir('/home')) }}        -> max,patrick
```

`/home/max/user.txt` exists but isn't readable by `www-data`. Instead, reading
`/usr/local/share/race-scripts/offsite-backup.sh` pays off — the earlier
`curl -u` came from *this* script, and its source carries a commented line the
process list never showed:

```
# OFFSITE_USER="max"
# OFFSITE_PASS="ruxai0GaemaS1Rah"
```

## user.txt

```
max@race:~$ id
uid=1001(max) gid=1001(max) groups=1001(max),1002(racers)
max@race:~$ cat user.txt
<32-hex-flag>
```

## Privilege escalation: the box earns its name

As `max` (`sudo` is denied outright), enumeration lands on the same script the
password came from. `/usr/local/bin/secure-cron-runner.sh` runs as **root every
minute**:

```bash
sig=$(/usr/bin/md5sum ${scripts[$j]} | awk '{print $1}')
if [[ "x$sig" == "x${sigs[$j]}" ]] ; then
    ${scripts[$j]}          # executed as root
fi
```

`scripts[0]` is `/usr/local/share/race-scripts/offsite-backup.sh`, whitelisted
by md5. The file is `root:root` and unwritable — but its **directory** is
`drwxrwsr-x root racers`, and `max ∈ racers`. Directory-write means I can
atomically *replace* entries even though I can't edit the file. The check
(`md5sum`) and the use (`${scripts[$j]}`) are two separate opens of a path I
control between them: a **TOCTOU race**, which is the entire point of a box
called RACE.

Exploit: keep the legitimate script (md5 matches) and an evil payload both
staged, and flip a symlink named `offsite-backup.sh` between them in a tight
loop. When `md5sum` opens it during a "legit" window and the exec opens it
during an "evil" window, root runs the payload:

```bash
# evil payload
cp /bin/bash /var/tmp/.rb; chown root:root /var/tmp/.rb; chmod 4755 /var/tmp/.rb
cat /root/root.txt > /var/tmp/.rt
```

`/var/tmp` is on the (non-nosuid) root fs, so a SUID bash there is viable —
`/dev/shm` and `/tmp`-family mounts are `nosuid` here, worth checking first. The
race won on the first cron cycle.

## root.txt

```
max@race:~$ /var/tmp/.rb -p -c 'id; cat /root/root.txt'
uid=1001(max) gid=1001(max) euid=0(root) groups=1001(max),1002(racers)
<32-hex-flag>
```

## Wrong turns worth recording

- **The `backup` password on SSH.** It reads like classic service→shell reuse;
  it isn't. It's a Grav-panel-only credential. Testing SMB/SSH/panel in one pass
  is what kept this a two-minute detour instead of a rabbit hole.
- **Cracking the bcrypt hashes.** They don't fall to rockyou. The intended read
  path (reset-token-in-backup) sidesteps the hash entirely — a reminder that a
  recovered hash is a fallback, not the plan.
- **Basic-auth bypass on phpSysInfo.** Every path/verb trick still 401'd; the
  realm is honest. The way in was a weak credential, not a bypass.

## The shape of it

Every step is a disclosure: a process list, a backup archive, a reset token, a
commented password. None of them is a memory-corruption exploit or even a CVE
with a number — they are configuration decisions that each leak the next
secret. The final race is the only "exploit" in the classic sense, and it's a
logic bug: validating a file an unprivileged group can swap.
