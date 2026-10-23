# Artificial — Hack The Box, Easy, Linux

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

## Recon

Two ports: 22 (OpenSSH 8.2p1) and 80 (nginx), where `/` 302-redirects the raw IP to
`artificial.htb`. Add the vhost to `/etc/hosts` and move on — vhost/dir fuzzing found no
hidden surface, so the application itself is the target.

## The application

A Flask "AI model" host: open registration, then an authenticated dashboard that uploads
Keras `.h5` models (`POST /upload_model`) and runs them (`/run_model/<uuid>`). Helpfully, it
links `/static/requirements.txt` and `/static/Dockerfile`, pinning the stack to
`tensorflow-cpu==2.13.1` on Python 3.8.

## Foothold: Keras Lambda deserialization RCE

A Keras `Lambda` layer stores its function as **marshalled Python bytecode**; `load_model()`
reconstructs and runs it. Build an `.h5` whose Lambda runs a command and upload it —
when the server loads it, the command runs as `app`.

Two things that cost time and are worth stating as method:

- **Marshal is Python-version specific.** The bytecode must be built under **Python 3.8** to
  load on the target's 3.8. Build in a matching interpreter (here: a `uv` py3.8 venv with
  `tensorflow-aarch64==2.13.1`, since the attack host is ARM — the Keras/`.h5` format is
  arch-independent, only the Python version matters).
- **Make the payload self-contained.** Bake the command as a *string literal inside the
  function* so marshal captures it in `co_consts`. A function that references a module global
  looks fine locally but raises `NameError` on reload in the server's fresh process — the
  layer "fires" and silently does nothing, which is a very confusing dead end.

**Egress is firewalled.** A reverse shell never connects; a tcpdump on the VPN interface
shows zero target-originated SYNs on any port. So the box is *narrower*, not harder: deliver
results in-band. The hook wrote `id`/output into the web-served static directory
(`/home/app/app/static/`), fetched back over HTTP — proving execution as `app`. From there,
drop an SSH key into `app`'s `authorized_keys` (port 22 is inbound-reachable) for a stable
shell that doesn't depend on egress at all.

## app → gael

`app.py` hashes passwords as **unsalted MD5**. Dump `instance/users.db`, crack gael's hash
(`rockyou`) → a password that is **reused** for the `gael` OS account. SSH in, read
`user.txt`. gael is in group `sysadm`.

## gael → root: Backrest

`sysadm` can read `/var/backups/backrest_backup.tar.gz`. Inside,
`.config/backrest/config.json` holds the Backrest admin user `backrest_root` with a
base64-wrapped **bcrypt** hash; crack it (`rockyou`, `!@#$%^`).

Backrest listens on `127.0.0.1:9898` and runs as **root**. No tunnel needed — drive its API
from gael's shell on localhost: `Login` → JWT, then add a repo and a plan carrying a
**command hook** (`CONDITION_SNAPSHOT_START`), and trigger `Backup`. The hook command runs as
root. Repo validation requires a `guid`, so `AddRepo` first (it mints the guid and persists
the hook), then `SetConfig` the plan, then `Backup`. Plant an SSH key for root → root shell,
read `root.txt`.

## Lessons for the methodology

- Egress characterisation is cheap and changes technique selection: once outbound is known
  blocked, promote in-band channels (write to a served path, fetch it) over any callback.
- A root-readable backup is a credential store; `sysadm`-style "read the backups" groups turn
  a backup into a privesc primitive.
- A localhost service running as root with a user-editable "run a command" feature is root
  RCE the moment you have its credentials.
