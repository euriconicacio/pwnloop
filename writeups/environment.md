# environment.htb — write-up

> Retired-box write-up. Flags redacted. The path: a leaked dev shortcut, a
> framework CVE that lets the request pick the environment, a trailing-dot
> upload, a password vault its own key unlocked, and a sudo script that trusts
> `BASH_ENV`.

## Recon

Two ports: OpenSSH 9.2p1 and nginx 1.22.1. The root redirects to
`http://environment.htb`, so that goes in `/etc/hosts`. The site is a small
Laravel app for an environmental charity with a `/login`.

The tell comes from asking `/upload` with the wrong method: instead of a clean
405 it returns a **Laravel Ignition debug page** — debug mode is on in
production. That page carries two gifts: exact versions (Laravel **11.30.0**,
PHP 8.2.28) and, in its stack frames, **application source**.

## The leaked shortcut + CVE-2024-52301

Forcing a second error in the `/login` handler (omit the `remember` field, then
send a junk value) walks the Ignition code window far enough to read
`routes/web.php`:

```php
if(App::environment() == "preprod") { // QOL: login directly as me in dev/local/preprod
    $request->session()->regenerate();
    $request->session()->put('user_id', 1);
    return redirect('/management/dashboard');
}
```

So if the app thinks it is in `preprod`, `/login` hands you user 1 with no
password. Laravel 11.30.0 is vulnerable to **CVE-2024-52301**: with PHP's
`register_argc_argv=On`, the framework reads `argv` even under the HTTP SAPI, so
a query string like `?--env=preprod` sets the environment. Fixed in 11.31.0.

`POST /login?--env=preprod` → 302 to `/management/dashboard`. We are **Hish**.

## Foothold: trailing-dot upload

The admin profile page has a picture upload posting to `/upload` (UniSharp
Laravel File Manager). It validates the MIME type from the file's *content*, so
a raw PHP file is rejected ("Unexpected MimeType: application/octet-stream") — but
a real PNG passes. The filter does not, however, normalise the name: uploading a
PNG-magic + PHP polyglot called `shell.php.` (trailing dot) stores it as
`shell.php` in the publicly served `storage/files/` directory. Requesting it
executes PHP as `www-data`.

Egress note: a reverse shell to an arbitrary port landed fine once the staging
path was corrected — the box is not heavily egress-filtered. `user.txt` is read
from `/home/hish/` immediately (the app and hish share the box).

## Lateral: a vault unlocked by its own key

`www-data` can read `/home/hish/.gnupg` — it is mode **755**, and the private
key inside has **no passphrase**. Next to it, `/home/hish/backup/keyvault.gpg`.
Import the key into a scratch `GNUPGHOME`, decrypt the vault:

```
PAYPAL.COM      -> ********
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM    -> ********
```

The `ENVIRONMENT.HTB` entry is hish's SSH password.

## Root: sudo + BASH_ENV

As hish:

```
(ALL) /usr/bin/systeminfo
Defaults env_keep+="ENV BASH_ENV"
```

`/usr/bin/systeminfo` is a **bash script**, and sudo is configured to **keep
`BASH_ENV`**. Bash sources `$BASH_ENV` on non-interactive startup, so:

```
echo 'chmod u+s /bin/bash' > /tmp/x.sh
sudo BASH_ENV=/tmp/x.sh /usr/bin/systeminfo
/bin/bash -p      # euid 0
```

`root.txt` falls out.

## Lessons

- An Ignition debug page is not just a version banner — it is a **source-code
  reader**. The whole box hinges on reading `routes/web.php` through it.
- CVE-2024-52301 is the class "the request can choose the environment"; always
  pin the Laravel version off the debug page and check it against 11.31.0.
- `env_keep` with `BASH_ENV`/`ENV` turns *any* sudo-allowed shell script into
  root, regardless of the script's contents.
