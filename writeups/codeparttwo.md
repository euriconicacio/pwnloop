# CodePartTwo — Hack The Box, Easy, Linux

**Chain:** unauth js2py RCE (CVE-2024-28397) -> DB hash crack -> SSH password
reuse -> sudo npbackup-cli config `pre_exec` -> root.

## Recon
Only two ports: SSH (22) and a Gunicorn/Flask app on 8000. With a port count
that small, the path is in the web app. The landing page names the product
"CodePartTwo" and advertises that it runs user JavaScript, with a "Download App"
link.

## Reading the source instead of guessing
`/download` hands out `app.zip` — the whole Flask app. Two things jump out of
`app.py`:

- `POST /run_code` calls `js2py.eval_js(code)` and, unlike every other data
  route, has **no `if 'user_id' in session'` guard**. It is unauthenticated.
- `requirements.txt` pins `js2py==0.74`.

`js2py.disable_pyimport()` is called, so the author believed the interpreter was
sandboxed. js2py 0.74 is vulnerable to **CVE-2024-28397**: crafted JavaScript
walks Python's object graph (`{}` -> its class -> `__base__` ->
`__subclasses__()`) until it finds `subprocess.Popen`, then calls it with
`shell=True`. `disable_pyimport()` does not stop this because nothing is
imported — the classes are already reachable.

Because `Popen(...).communicate()` returns stdout synchronously, the HTTP
response itself is the output channel. No reverse shell, no callback — which is
exactly what you want when you have not characterised egress yet.

The one wrinkle: the returned stdout is Python `bytes`, which js2py cannot coerce
to a JS string (`Cannot convert object to primitive value`). Calling
`.decode("utf-8")` on it Python-side before returning fixes that. Helper in
`rce.py`.

## Foothold -> credentials
Code runs as `app` (uid 1001). No `user.txt` here — it belongs to `marco`.
The live database `instance/users.db` (not the empty one in the zip) holds MD5
hashes. `marco`'s cracks instantly against rockyou: `sweetangelbabylove`.

That password is reused for the system account — `ssh marco@target` lands the
user shell and `user.txt`. Password reuse between the web app and the OS account
is the intended lateral step.

## Root: npbackup-cli config injection
`marco` may run one thing as root without a password:
`/usr/local/bin/npbackup-cli`. npbackup takes `-c <config>`, and a backup
group's config carries `pre_exec_commands` / `post_exec_commands` that run as the
process user before/after the backup. Since the tool runs as root and the config
path is ours, those hooks are root command execution.

Take marco's readable `npbackup.conf`, add a `pre_exec_commands` entry (drop a
sudoers rule + read the flag), point sudo at it, force a backup:

```
sudo /usr/local/bin/npbackup-cli -c /tmp/.np/npbackup.conf --repo-name default -b -f
```

`pre_exec` runs first and reports `uid=0(root)`. Root.

## Leads that did not matter
- The hardcoded Flask `secret_key` ("S3cr3tK3yC0d3PartTw0") would let you forge a
  session, but `/run_code` needs no session at all, so it was never needed.
- The `app` account's own hash was left uncracked — irrelevant once SSH as marco
  worked.

## What would have stopped it
Never evaluate untrusted input in an in-process interpreter. The whole chain
starts there.
