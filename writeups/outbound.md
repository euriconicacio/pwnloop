# Outbound — Hack The Box, Easy, Linux

**TL;DR:** A Roundcube webmail box. **CVE-2025-49113** (pre-1.6.11 PHP object
injection via `_from`) gives `www-data`; the webmail's `config.inc.php` leaves
`des_key` at the shipped default, so the 3DES-encrypted IMAP passwords in the
`session` table decrypt to a real user (`jacob`); his mailbox hands over a
rotated SSH password for the user flag; and `sudo below` (**CVE-2025-27591**,
below < 0.9.0, symlink-follow on a world-writable log) escalates to root.

*Machine status: retired. Flag values are redacted here; the local copy keeps
them as evidence.*

A webmail box that falls in three moves: a headline Roundcube RCE for the
foothold, the webmail's own stored passwords for a real user, and a monitoring
daemon's fresh LPE for root. What makes it a good teaching box is that every
step is *evidenced from the box itself* — the vhost, the config, the session
table, the mailbox, the sudo rule — with the only outside input being the public
mechanics of two named CVEs.

## Recon
The raw IP 302-redirects to `mail.outbound.htb`, so the first move is a hosts
entry — half of HTB web paths are vhost-gated. Behind it: Roundcube webmail.
Pin the product; a current Roundcube is the loudest possible lead.

## Foothold — CVE-2025-49113
Roundcube < 1.6.11 deserializes the `_from` upload parameter without validation
(PHP object injection → RCE). Authenticated as `tyler`, a crafted upload request
runs commands as `www-data`. Two lessons this box reinforces:

- **Confirm exec with an oracle that ignores egress.** Rather than firing a
  reverse shell, write `id` into a web-served directory and read it back over
  HTTP. That proves RCE without a listener and without assuming the box can call
  home — and it doubles as the enumeration channel.
- **Then build an in-band exec wrapper, not a shell.** A one-line PHP endpoint
  that runs `base64_decode($_POST['c'])` under a served path gives scriptable,
  egress-free command output for the rest of the engagement.

## Lateral — the webmail is a credential store
`config.inc.php` had two gifts: local MySQL creds, and `des_key` left at
Roundcube's shipped default `rcmail-!24ByteDESkey*Str`. Roundcube stashes each
logged-in user's IMAP password in the `session` table, 3DES-encrypted with
`des_key`. Default key ⇒ every stored password is recoverable. Dumping the
session table and decrypting yields `jacob`'s password — a *different* user than
the one we logged in as.

Generalisable point: **an app that authenticates to something else has to keep a
usable secret somewhere.** Webmail keeps the IMAP password; if the key protecting
it is a shipped default, the session store is a plaintext credential dump.

## User — read the mail
`su jacob` works with the decrypted password, and jacob's Maildir holds the
actual path forward: a message from `tyler` handing over a *rotated* system
password, and one from `mel` mentioning that `below` monitoring is now enabled
and jacob may inspect its logs. That second mail is the privesc hint in prose.
SSH with the rotated password lands the user flag.

## Root — CVE-2025-27591 (below < 0.9.0)
`sudo -l` shows `NOPASSWD: /usr/bin/below *` (with `--config`/`--debug`/`-d`
blocked), and `/var/log/below` is world-writable. below < 0.9.0 opens its
per-user error log following symlinks and world-writable. The chain:

1. `ln -s /etc/passwd /var/log/below/error_root.log`
2. `sudo below record` (allowed) runs as root, follows the symlink, and leaves
   `/etc/passwd` mode 0666 — verify this rather than assuming it.
3. Append a UID-0 account and `su` to it.

Non-destructive detail worth keeping: **append, don't `cp`-overwrite.** Public
PoCs clobber `/etc/passwd` with a single line; appending one line and removing it
afterward leaves the file byte-for-byte as found.

The methodological point for privesc: the mail *named the mechanism* (below), so
the move was to pin below's version and enumerate its CVEs — not to run a blind
privesc script. A monitoring/maintenance daemon that runs as root and writes to a
group- or world-writable path is a recurring root primitive; the sudo rule just
supplied the trigger.

## Chain
CVE-2025-49113 (www-data) → default `des_key` decrypts session → jacob →
mailed rotated password → user → CVE-2025-27591 via `sudo below` → root.
Break any one link and it stops.
