# Down — HTB (Linux, Easy)

> Flags redacted. Publishable only once the machine is confirmed retired.

## Overview

`Down` is an Easy Linux box built around one idea: a PHP “website up/down checker”
that shells out to `curl` with insufficient sanitisation. That single bug yields an
arbitrary file read, which leaks a password-manager vault; cracking the vault gives
the user, who has full `sudo` to `root`.

## Recon

Only two ports:

```
22/tcp open ssh     OpenSSH 8.9p1 (Ubuntu)
80/tcp open http    Apache 2.4.52 (Ubuntu)
```

Port 80 serves “Is it down or just me?”, a form that POSTs a `url` field to
`index.php`. Submitting `http://<target>` returns *“It is up”* and reflects the
fetched page body; an external URL returns *“It is down”* (the box has no outbound
internet, though it **can** reach the VPN — worth confirming, because it means a
reverse shell still works).

## The bug: curl argument injection

Probing the fetcher shows it is the `curl` binary (the `User-Agent` is `curl/7.81.0`),
and that the URL is passed through a shell with **word-splitting but no metacharacter
interpretation** — the signature of `escapeshellcmd()`. Injecting `-A`/`-H` changes
the outgoing request, confirming we control `curl`’s argv.

Because the PHP scheme check (`preg_match('|^https?://|', $url)`) only inspects the
*start* of the string, we can append a second URL argument with any scheme:

```
url=http://127.0.0.1/ file:///etc/passwd
```

`curl` fetches both and the app reflects the concatenated bodies — an **arbitrary
file read** as `www-data`. `/etc/passwd` reveals the user `aleks`.

Reading the app source confirms the root cause:

```php
$ec = escapeshellcmd("/usr/bin/curl -s $url");
exec($ec . " 2>&1", $output, $rc);
```

`escapeshellcmd()` escapes `; | & $ \` …` but **not spaces**, so argument injection
is wide open. (The same primitive also writes files via `-o`, but only into
`www-data`-writable directories — the webroot is root-owned, so no webshell.)

## Foothold: the password-manager vault

Enumerating `aleks`’ home (traversable; dotfiles are world-readable) turns up a vault
belonging to **pswm**, a small Python password manager that stores its data at
`~/.local/share/pswm/pswm` and encrypts it with the `cryptocode` module under a master
password. The file is world-readable, so the file-read primitive retrieves it:

```
<b64>*<b64>*<b64>*<b64>
```

`cryptocode` blobs are four base64 fields joined by `*`, and `cryptocode.decrypt()`
returns `False` on a wrong key — a perfect offline oracle. A short script over
`rockyou.txt` finds the master password almost immediately:

```python
import cryptocode
blob = open("pswm.blob").read().strip()
for pw in open("/usr/share/wordlists/rockyou.txt", encoding="latin-1"):
    pw = pw.strip()
    out = cryptocode.decrypt(blob, pw)
    if out:
        print(pw); print(out); break
```

Master password: `flower`. The decrypted vault holds the entries in
`alias / username / password` form, including the SSH password for `aleks`.

```
$ ssh aleks@down
aleks@down:~$ id
uid=1000(aleks) ... groups=...,27(sudo),...
```

## Privilege escalation: sudo

`aleks` is in the `sudo` group with an unrestricted rule:

```
$ sudo -l
User aleks may run the following commands on down:
    (ALL : ALL) ALL
```

```
$ sudo su -
# id
uid=0(root) ...
```

Root. `user.txt` lives in the webroot under a randomised name
(`/var/www/html/user_<rand>.txt`), which is why a naive `find -name user.txt`
comes up empty — but as root it’s trivial, and it was in fact readable through the
original file-read primitive all along.

## Lessons

- `escapeshellcmd()` is **not** a substitute for not using a shell. It leaves spaces
  intact, so any command built by concatenation is argument-injectable. Use an argv
  array and validate the URL with `FILTER_VALIDATE_URL` + a scheme allow-list.
- A scheme filter that checks only the *prefix* of user input is bypassed by
  appending a second argument.
- A password manager is only as strong as its master password and its file
  permissions — a world-readable vault plus a `rockyou` master password is game over.
- When `find -name user.txt` is empty, search by content/pattern; flags can live
  anywhere.
