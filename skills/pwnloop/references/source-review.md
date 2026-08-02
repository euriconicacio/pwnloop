# Reading recovered source

When a machine hands you source — an exposed `.git`, a backup archive, a
readable web root, a decompiled binary — stop fuzzing and read. Source turns
guessing into a targeted request, and it is usually placed deliberately.

## Getting it

```bash
pwnloop x "git-dumper http://machine.htb/.git /engagements/$NAME/loot/src"
pwnloop x "curl -s http://machine.htb/.git/HEAD"        # 200 = the whole repo is yours
pwnloop x "wget -q -r -np -R 'index.html*' http://machine.htb/backup/"
```

Also check for editor and deployment leftovers, which are as good as source:
`.env`, `config.php.bak`, `index.php~`, `.DS_Store`, `composer.lock`,
`package-lock.json`, `web.config`, `appsettings.json`, `.vscode/sftp.json`.

## First pass — secrets and history

```bash
cd /engagements/$NAME/loot/src
git log --all --oneline
git log --all -p -- .env config.php settings.py | grep -iE 'pass|secret|key|token' | head -40
git diff HEAD~5 HEAD
```

Deleted content is where secrets live. A blanked credential in the current
commit is a signpost, not a fix — read the commit before it. Also check
stashes, dangling objects and other branches:

```bash
git stash list; git branch -a
git fsck --lost-found 2>/dev/null | grep commit | cut -d' ' -f3 | xargs -I{} git show {} | head -60
```

Then the whole tree, not just the config files:

```bash
grep -rniE '(password|passwd|secret|api[_-]?key|token|BEGIN [A-Z ]*PRIVATE KEY)\s*[=:]' . \
  --include='*' -l | head -30
```

## Second pass — where input reaches something dangerous

Work backwards from the sinks. For each hit, ask whether any request parameter
can reach it without passing a check.

| language | sinks worth grepping |
|---|---|
| PHP | `system` `exec` `shell_exec` `passthru` `popen` `eval` `assert` `preg_replace/e` `include` `require` `unserialize` `extract` `$$` `move_uploaded_file` |
| Python | `os.system` `subprocess(... shell=True)` `eval` `exec` `pickle.loads` `yaml.load` `os.path.join` `open(` `jinja2.Template(` `__import__` |
| Node | `child_process.exec` `eval` `Function(` `vm.runIn*` `require(` with a variable, `JSON.parse` into a prototype, `res.sendFile` |
| Java | `Runtime.exec` `ProcessBuilder` `ObjectInputStream.readObject` `XMLDecoder` `TemplateEngine` JNDI lookups |
| Go | `os/exec.Command` `text/template` with user data, `filepath.Join` |
| Ruby | `system` `%x` `eval` `Marshal.load` `send(` `constantize` |

Two patterns worth grepping for specifically, because they produced results on
real boxes:

- **`os.path.join(base, user_controlled)`** — does not normalise `..` and
  silently discards `base` if the second argument is absolute. Every
  extract-to-directory routine is a candidate for arbitrary write.
- **String-concatenated SQL** — `"SELECT ... WHERE id = " + id`. Grep for
  `f"SELECT`, `"SELECT ... " +`, `#{}` in Ruby, `${}` in template strings.

## Third pass — authorization, not authentication

The bug on modern lab boxes is rarely a missing login. It is a route that
authenticates the user and then never checks whether *this* user may touch
*that* object.

Read the routing table first (`routes/web.php`, `urls.py`, `app.js`,
`@RequestMapping`), list every route, and for each one ask: what does it read
from the request, and what does it check before acting? Routes with no
middleware, no decorator, or a decorator only checking "is logged in" are the
shortlist.

## Framework-specific fast wins

- **Laravel** — `APP_DEBUG=true` in `.env` leaks the environment on any error;
  `APP_KEY` allows forging signed cookies and, on older versions, decrypt-based
  RCE. Check `storage/` for anything web-servable.
- **Django** — `DEBUG=True` plus an error gives you settings and the
  `SECRET_KEY`; the key allows signing session cookies and password-reset tokens.
- **Spring Boot** — `/actuator/env`, `/actuator/heapdump`.
- **Express** — `app.use(express.static(...))` above the auth middleware serves
  the whole directory unauthenticated.
- **WordPress / other CMS** — the version in `readme.html` or a meta generator
  tag, then the plugin list; the vulnerability is almost always in a plugin.

## Decompiled binaries

```bash
pwnloop x "strings -n 8 binary | grep -iE 'pass|key|http|/tmp|sql'"
pwnloop x "objdump -d binary | head -80"
```
For .NET and Java, decompiled source reads like source — apply everything above.
Hardcoded credentials in a client binary are credentials for the server.

Decompile .NET to IL without a GUI: `ikdasm binary.dll > out.il` (or `monodis`),
then grep the sinks. A recurring Windows arbitrary-write bug is **zip-slip**:
`Path.Combine(base, entry.FullName)` + `ExtractToFile`/`SaveAs` with no
`Path.GetFileName` — a zip entry named `..\..\target\file` escapes `base`
entirely (`Path.Combine` discards `base` on an absolute/traversing second arg).
Any code that extracts an archive, or joins a user-supplied filename to a
directory, into a writable location is a candidate; pair it with an app-local
`hostfxr.dll` drop for RCE (`references/foothold.md`).

## Feed it back

Every confirmed sink becomes a request you actually send, and the result — hit
or miss — goes into the ledger with the file and line number as evidence. Source
review that does not end in a sent request is note-taking, not testing.
