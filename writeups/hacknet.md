# HackNet — Hack The Box, Medium, Linux

**TL;DR:** A Django social network that escapes its output almost everywhere. The
exception is the `/likes/<id>` AJAX fragment, which builds a template *string*
from the raw username and calls `engine.from_string(...).render()` — so the
username field is not an XSS sink, it is a **server-side template** sink, and
`{{ users.values }}` dumps every account with its cleartext password. One of those
emails is a real Linux username, and the password is reused for SSH. From there,
gunicorn runs as `sandy` and Django's `FileBasedCache` pickles its entries into a
world-writable directory, so poisoning a cache file and triggering the
`@cache_page`-decorated view is code execution as the web user. Root is a GPG key
whose passphrase is in `rockyou`, guarding database backups that contain a chat
message where two users swap the MySQL root password — which is also the system
root password.

*Flags redacted. Machine address generalised to `10.129.x.x`. Hostname, service
versions and the credentials planted by the box author are kept, as they are
properties of the machine.*

---

## Recon

Two ports, which is the entire hint about where the box lives.

```
22/tcp  open  ssh    OpenSSH 9.2p1 Debian 2+deb12u7 (Debian 12)
80/tcp  open  http   nginx 1.22.1
```

Port 80 redirects the raw address to `hacknet.htb`, so the vhost goes in
`/etc/hosts` before anything else. Behind it is "HackNet", a Django social network
— profiles, posts, comments, likes, direct messages, contact requests — with 25
seeded users and open self-registration. Authentication is by **email**, not by
username, which turns out to matter later.

No other vhost answers (20k list against both `*.htb` and `*.hacknet.htb`, with
the response size filtered correctly), UDP's top 100 is empty, and there is no
`/admin` mounted. Everything is in the app.

## Pinning what you are actually attacking

Django deliberately gives away almost nothing — `DEBUG=False`, no version header,
no admin URL. It does, however, still serve the admin's **static files** even when
the admin URLs are not routed, and those files change byte-for-byte between
releases:

```
/static/admin/css/dark_mode.css                 present   → ≥ 4.1
/static/admin/css/unusable_password_field.css   absent    → < 5.1
/static/admin/css/base.css                      21544 bytes
/static/admin/js/core.js                         6208 bytes
```

That byte pair matches the 5.0.x line and not 4.2.x. Pinning a framework this way
costs two `curl`s and decides which behaviours you are allowed to assume — here,
that the template engine autoescapes by default, and that `FileBasedCache` still
uses pickle.

The same trick works on the image library. The avatar uploader validates content
rather than extension, and *which* formats it accepts is a fingerprint: QOI is
accepted, AVIF is rejected, and it takes PCX/IM/DDS/TGA — formats `imghdr` has
never heard of. That is Pillow, somewhere in `≥ 9.5, < 11.3`. Worth knowing, and
worth ruling out: an EPS with an infinite PostScript loop comes back in 0.48
seconds, which proves the validator only calls `Image.open()` and never hands the
file to Ghostscript. No `gs` RCE here.

## The access-control bug that is a boolean oracle

Seven of the seeded profiles are private, and their posts do not appear in
`/explore` — not even through the keyword search. The pagination gives the bug
away: pages come back holding 9, 6, 8 and 2 posts instead of a steady 10.

`/explore` **paginates first and applies the privacy filter second**. The page is
sliced out of the *unfiltered* queryset and the private rows are dropped on the
way to the template, so the page count and the `Pages` block are computed over
posts you are not allowed to read. Feed it a keyword that matches only a private
post and you get a `Pages` block with zero posts rendered — a clean boolean oracle
over text you cannot see.

Character by character, that extracts all eight hidden posts. And they are
flavour text. The oracle is worth running anyway, because it is also how you
*prove* a negative: sweeping it for `password`, `passwd`, `creds`, `key`, `login`,
`secret`, `token`, `ssh`, `root`, `admin`, `flag`, `hash`, `.htb`, `http`, a path
separator and an IP octet returns nothing. The hidden content contains no
credential, and that is now a fact rather than an assumption.

Two more facts fall out of the same style of counting. Forcing `/search`'s
pagination to flip from three pages to four establishes there were exactly 25
accounts before registration — so there is **no hidden staff account**. And the
profile-edit form is an oracle that distinguishes "user exists" from "email
exists", which says the seeded users' emails are none of
`<handle>@hacknet.htb|.local|.com|...` and not the bare handle either. Since login
is email-only, the seeded accounts are not directly authenticable. The way in is
not a login.

## Foothold — the same field, a different sink

The username is reflected in several places. On the profile heading and in search
results it is escaped, as everything else in this app is. In the `/likes/<id>`
fragment — the little popup listing who liked a post — it is not:

```html
<span title="<username>">…</span>
```

A `"` in the username breaks out of the `title` attribute, which is the obvious
read: stored HTML injection, needing someone to open the popup. There is no such
someone. Contact requests sit unanswered for 45 minutes, messages stay unread,
and nothing on this box ever visits a page on your behalf.

The obvious read is the wrong one. That fragment does not merely interpolate the
username into HTML — the view concatenates it into a template *string* and runs it
through `engine.from_string(...).render()`. The username is evaluated by the
Django template engine before it is ever escaped as output.

The test that separates the two hypotheses is to fire the probe **in the sink that
is not escaped**, and to compare it against one that is:

```
username = {{ 7*7 }}   → profile heading:  {{ 7*7 }}    (escaped, inert)
                       → likes popup:      49           (evaluated)
```

Django's template language is sandboxed — no `__globals__`, no attribute access
into builtins — so this is not a straight road to RCE. It does not need to be. The
sandbox still resolves **context variables**, and the view helpfully passes the
user queryset in:

```
username = {{ users.values }}
```

Set that as your username (there is a ~30-character cap and no character
validation at all), like a post, and read your own likes popup. It renders every
`SocialUser` row — including the password column, which is stored in cleartext.

One of those accounts is `backdoor_bandit`, whose email is `mikey@hacknet.htb`.
`mikey` is a real Linux account, and `mYd4rks1dEisH3re` is its SSH password.

```
mikey@hacknet:~$ cat user.txt
<redacted>
```

## mikey → sandy — a world-writable directory full of pickles

`gunicorn` runs as `sandy`, and `mikey` cannot read `sandy`'s home. What `mikey`
can do is write into `/var/tmp/django_cache`.

`/explore` is decorated with `@cache_page`, and this project uses Django's
`FileBasedCache`, which serialises cache entries with **pickle**. The individual
cache files are owned by `sandy` and are not writable — but the directory is
world-writable, and on Linux the permission that decides whether you can replace a
file is the permission on its *directory*, not on the file. Rename the existing
entry out of the way, drop your own file under the original name, and
`FileBasedCache.get()` will call `pickle.load()` on it the next time anyone hits
`/explore`.

The payload is the standard `__reduce__` gadget, and the thing it should do is
plant an SSH key rather than fire a shell — the box is far easier to work from
over SSH, and a key survives the cache entry being regenerated:

```python
class P:
    def __reduce__(self):
        return (os.system, ('...append a key to ~sandy/.ssh/authorized_keys...',))
```

One request to `/explore`, and `ssh sandy@` works.

## sandy → root — a passphrase in rockyou guarding a chat log

`sandy` owns a GPG secret key, and next to it are database backups encrypted with
it: `backups/*.sql.gpg`. That pairing is the finding — an encrypted backup whose
key sits on the same host is a delay, not a control.

```
gpg2john sandy_secret.gpg > sandy.john
john --wordlist=rockyou.txt sandy.john    →  sweetheart
```

Seconds. Decrypting the dumps gives the application's data as SQL, and inside the
message table is a conversation between two users in which one hands the other the
**MySQL root password** in cleartext: `h4ck3rs4re3veRywh3re99`.

It is also the system root password.

```
sandy@hacknet:~$ su root
root@hacknet:~# cat /root/root.txt
<redacted>
```

## What did not work

- **Everything that looked like a web-app vulnerability class.** `sqlmap` at
  level 5 / risk 3 against the search keyword, the pagination parameter and the
  comment POST (headers included) found nothing; the comment endpoint casts the
  article id to `int`, so no string reaches SQL. Profile edit has no mass
  assignment. `/message/<id>` is properly authorised. Contact accept/decline is
  guarded by `get_object_or_404` on an *incoming* request, so the direction cannot
  be forged. All correctly dead.
- **The avatar upload.** Filenames survive verbatim and the extension check passes
  anything containing `.png`, so `a.png.py` is stored — and nginx serves `/media`
  statically and executes nothing. Django's `get_valid_filename` strips traversal.
  A real weakness with no sink.
- **The nginx `alias` traversal.** There is no `alias`; `location /media` is a
  prefix with a root-style mapping, proven by `/media..%2fmedia%2f1.jpg` returning
  404 rather than the file.
- **Waiting for a bot.** The strongest wrong turn on this box. A stored-HTML
  primitive with no victim is not a foothold, and there is no scheduled user here
  — but note *why* that conclusion was reachable and still not decisive: the
  probes used to test for a bot were themselves landing in escaped sinks, so they
  were never delivered as markup at all. A negative drawn from a probe you never
  confirmed was delivered is not a negative.
- **`/profile/<id>` behaving differently for seeded and registered accounts.**
  Seeded ids return 200 and self-registered ones 302 — a real difference in the
  underlying queryset, and not reachable as a bypass. Parked, correctly.

## Lessons

- **A field is not one sink.** The same value can be reflected in half a dozen
  places with different escaping, and one unescaped reflection is all it takes.
  Enumerate every place your input comes back before concluding a class is absent
  — `{{ 7*7 }}` rendering literally on the obvious page proves something about
  *that page*, not about the application.
- **Escaping is not the only thing that happens to a string.** The question that
  separates XSS from SSTI is not "is it escaped" but "who parses it first". A view
  that builds a template out of user data has already lost, and the escaping
  downstream is irrelevant because evaluation happened before it.
- **A sandboxed template engine is still an information-disclosure primitive.**
  Django blocks the arithmetic-to-RCE road, which makes it tempting to write the
  finding off. It still resolves whatever the view put in the context — and views
  pass in querysets.
- **The directory permission is the one that matters.** A file you cannot write
  is replaceable if you can write its parent. Any deserialising cache, spool or
  queue in a world-writable directory is a code-execution primitive owned by
  whoever runs the reader.
- **Counting is enumeration.** Page sizes, pagination boundaries and
  exists/doesn't-exist form errors answered three questions here — the privacy
  filter's ordering bug, the absence of a hidden admin, and the fact that the
  seeded accounts cannot be logged into — without a single exploit.

## Defensive takeaway

The control that would have broken this chain earliest is not the template bug: it
is **storing passwords in cleartext**. The SSTI is a serious flaw and it would
still be one against hashed credentials, but what converted "an attacker can read
a database column" into "an attacker has an SSH session" was that the column held
usable passwords, and what converted a web-user shell into root was the same
mistake a second time — a working credential written into a chat message that got
swept into a backup.

Fixing the template sink (render user data as *data*, never as a template) closes
this specific door. Hashing the credential store and getting operational secrets
out of application content closes every door of that shape, including the ones on
the next box.
