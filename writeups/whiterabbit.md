# WhiteRabbit — HTB (Insane, Linux)

Flags redacted. Retired machine.

WhiteRabbit models a small phishing/pentest shop whose tooling (Uptime Kuma,
WikiJS, n8n, GoPhish) is wired together in a way that quietly hands an attacker
each next step. The chain is long but every hop is a clean, explainable primitive.

## Recon
Three ports: `22` (host SSH), `80` (Caddy), `2222` (a second SSH — different
patch level, i.e. a container). Caddy serves `whiterabbit.htb` (a static company
site) and one extra vhost, `status.whiterabbit.htb`, an **Uptime Kuma 1.23.13**
instance behind a login.

The static site advertises the stack (n8n, GoPhish, Uptime Kuma); none of those
are directly reachable. Uptime Kuma needs credentials, and there is no
unauthenticated RCE for 1.23.13 — so the way in has to be an *information leak*.

## The leak that unlocks everything: a public status page
Uptime Kuma status pages are meant to be public. Fuzzing the `/status/<slug>`
route (or reading `/api/status-page/<slug>`) finds a published page `temp`. Its
monitor list is the gift: monitor **names** embed the internal hostnames.

- GoPhish → `ddb09a8558c9.whiterabbit.htb`
- WikiJS  → `a668910b5514e.whiterabbit.htb`

*Lesson:* on any Uptime Kuma, enumerate `/status/<slug>` for published pages —
monitor names and URLs routinely leak internal topology with no auth.

## WikiJS: the manual for the next bug
The WikiJS instance answers GraphQL anonymously
(`{pages{list{id path title}}}`), revealing a page `gophish_webhooks`. Its
attachment is an **n8n flow export** documenting the GoPhish→n8n pipeline:

- the n8n webhook host `28efa8f7df.whiterabbit.htb` and path,
- the **HMAC-SHA256 signing secret**, and
- the query the flow runs:
  `SELECT * FROM victims where email = "{{ body.email }}" LIMIT 1`.

The query concatenates request data into SQL inside double quotes — injectable —
but every request must carry a valid `x-gophish-signature`.

## Reaching the SQLi: forge the signature
n8n computes the HMAC over `JSON.stringify(body)` — minified JSON, no spaces. So
the signature is `HMAC_SHA256(secret, json.dumps(body, separators=(',',':')))`.
Reproduce that and you can send arbitrary bodies. An unbalanced `"` in `email`
produces a MySQL syntax error, which a leftover **"DEBUG" respond node** echoes
straight back — a perfect error-based oracle. From there, `extractvalue(1,
concat(0x7e,(subquery)))` with `SUBSTRING` chunking dumps the DB without any
external tooling.

The prize is the `temp.command_log` table — a record of setup commands:
```
restic init --repo rest:http://75951e6ff.whiterabbit.htb
echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd   (2024-08-30 14:40:42)
```
Two gifts: restic backup credentials, and the exact time a password was generated.

## Backup → container foothold
`restic` with that password lists one snapshot; restoring it yields `bob.7z`, a
7-Zip archive (`7z2john` → crack → `1q2w3e4r5t6y`) containing **bob's SSH key**
and a config pointing at port 2222. `ssh bob@…:2222` lands in a container.

## Container root: restic is a shell
`sudo -l` shows `(ALL) NOPASSWD: /usr/bin/restic`. `restic`'s
`--password-command` runs an arbitrary command as root:
```
sudo restic check --password-command 'cp /bin/bash /tmp/rb'
sudo restic check --password-command 'chmod 6777 /tmp/rb'
/tmp/rb -p
```
*Lesson:* a sudo rule on any binary that can run a subcommand (`restic`,
`borg`, `tar --checkpoint-action`, `git`, …) is a root shell.

Container root's `/root` holds **morpheus's** SSH key → `ssh morpheus@…:22` on the
host → `user.txt`.

## Host root: a clock-seeded password
`/opt/neo-password-generator` is a tiny ELF that seeds libc `srand()` with
`gettimeofday()` in **milliseconds**, then pulls 20 chars from a fixed charset.
Because `command_log` recorded *when* it was run (14:40:42 UTC), there are only
1,000 possible seeds (one per millisecond). Replaying libc `rand()` via
`ctypes.CDLL("libc.so.6")` regenerates all 1,000 candidates; spraying them finds
`neo:WBSxhWgfnMiclrV4dqfj`.

*Lesson:* a time-seeded PRNG is only as strong as the uncertainty in the seed;
logging the generation time collapses it to a tiny space.

`neo` has `sudo (ALL:ALL) ALL` → `sudo -i` → **root**.

## Leads that failed (and why)
- Brute-forcing the Uptime Kuma login: the instance has **no account lockout**,
  but the password isn't weak/themed/rockyou-reachable — it was never the path.
  The status page is the intended leak.
- Chasing CVE-2024-56331 (1.23.13 real-browser LFI): real, version-fit, but
  authenticated — a distraction when the entry is an unauthenticated status page.

## Defensive takeaway
The injectable n8n query is the keystone: parameterize it and the whole
database-driven half of the chain disappears, even with every information leak
left in place.
