# cat.htb — a walk from `.git` to `root`

> Hack The Box — retired, Medium.

> Flags redacted. A chain of small, ordinary web mistakes — each one textbook —
> that compose into a full host takeover. The interesting part is not any single
> bug but how reading the source turns three "maybe" findings into three
> certainties, and how the last step is just password reuse.

## Recon

Two ports: `22` (OpenSSH 8.2p1) and `80` (Apache 2.4.41), with `80` redirecting
to `http://cat.htb/`. Add the host, and the site is a "Best Cat Competition".

The first real finding is free: `/.git/HEAD` returns `200`. `git-dumper` pulls
the whole working tree. Now we read instead of guess.

## Reading the source

Four things jump out of the PHP:

1. `config.php` — the app is **SQLite** at `/databases/cat.db`.
2. `join.php` — registration is open, passwords are `md5()`, and login is a
   **GET** request (`loginUsername` / `loginPassword`).
3. `view_cat.php` — the cat owner's username is echoed **without**
   `htmlspecialchars`. Everything else on the page is escaped; this one line is
   not. Stored XSS, and the sink is a value *I* control at registration.
4. `accept_cat.php` — admin-only, and it builds
   `INSERT INTO accepted_cats (name) VALUES ('$cat_name')` by string
   concatenation. Every other query uses prepared statements. This one doesn't.
   SQL injection, gated behind `$_SESSION['username'] === 'axel'`.

So the plan writes itself: become `axel`, then use his SQLi.

## Foothold: XSS → admin session

Register with the *username itself* set to a script payload, then submit a cat so
it lands in the admin's review queue. The admin, `axel`, reviews pending cats;
`view_cat.php` renders the owner username unescaped, the script runs in his
browser, and since the session cookie has no `HttpOnly` flag, `document.cookie`
walks out to a listener.

With `axel`'s cookie, `admin.php` loads — we're the admin.

## Dumping users: blind SQLi in `accept_cat.php`

`accept_cat.php` doesn't reflect anything, and `accepted_cats` isn't displayed
anywhere, so this is **blind**. But the error behaviour is a clean oracle: a
valid statement returns *"The cat has been accepted..."* (HTTP 200); a broken one
throws an uncaught `PDOException` (HTTP 500).

Build a boolean out of it with a false-branch that errors only at runtime.
SQLite integer-overflow quietly promotes to float (no error), and a missing-table
reference errors at *parse* time (so it fires on both branches) — the one that
works cleanly is `load_extension(1)`:

```
catName = x'||(SELECT CASE WHEN (<cond>) THEN 7 ELSE load_extension(1) END)||'
```

`<cond>` true → `7`, statement valid → 200. False → `load_extension` is refused at
runtime → 500. Binary-search each character of
`group_concat(username||':'||password)` and the `users` table falls out as
unsalted MD5. `rockyou` cracks `rosa` immediately; `axel`'s doesn't crack.

## Lateral: `rosa` → `axel`, the boring way

`rosa`'s password works over SSH, and `rosa` is in group **adm**. `adm` reads
`/var/log/apache2/`. And recall that login is a **GET** — so `axel`'s own logins
are sitting in `access.log` as `?loginUsername=axel&loginPassword=...` in
cleartext. SSH in as `axel`. `user.txt` is his.

> Lesson worth keeping: the username field and the access log are both
> "credential stores" nobody intends. A password typed into the wrong field, or
> sent in a URL, is a password written to disk.

## Root: the reviewer bot, a private repo, and one reused password

`axel`'s mail explains the rest. A colleague asks him to email `jobert@localhost`
with a link to his **Gitea** repo, promising to "review the whole repository",
and points at a *private* repo `administrator/Employee-management`.

Gitea is **1.22.0** — **CVE-2024-6886**, stored XSS in the repository
*description* (`<a href=javascript:...>` that fires on click). Log in to Gitea as
`axel` (same password as the web app), create a repo, set the description to a
payload, email `jobert`, and the reviewer bot clicks it.

Two practical notes that cost time and are the real teaching value here:

- **The bot reviews each repo URL exactly once, then deletes the repo.** Re-using
  the same repo for a second payload gets silently ignored — every attempt needs
  a *fresh* repo name.
- **The page's CSP is `connect-src 'self'`.** A `fetch()` to an external
  collector is blocked, but the error reads like the attack failed. `img-src` is
  open, so exfiltration has to go through `new Image().src = '...'`, not `fetch`.
  Reading *same-origin* resources with `fetch` is fine; only the exfil leg has to
  be an image.

With that, the bot — a **Gitea administrator** — reads the private repo for us.
`index.php` there hardcodes `admin:IKw75eR0MR7CMIxhH0`. It isn't the Gitea admin
password, it isn't `jobert`'s SSH password... it's the host's **`root`**
password:

```
su root  →  uid=0(root)
```

`root.txt` is read.

## What actually mattered

- **The `.git` exposure is the whole game.** Blind, F2/F3 are hours of fuzzing;
  with the source, they're two `grep`s.
- **Every cleartext "store" is a credential store** — the username field
  (stored XSS sink), the access log (GET passwords).
- **The CVE got a privileged browser to read a file; password reuse made that
  file root.** The flashy bug (CVE-2024-6886) only moved laterally; the thing
  that handed over the box was `admin`'s password being `root`'s password.

## Defensive one-liner

Don't ship `.git`, don't interpolate user input into HTML or SQL, don't put
secrets in source, and never let an app password double as `root`.
