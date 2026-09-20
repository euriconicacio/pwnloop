# watcher — Hack The Box, Medium, Linux

**TL;DR:** A Zabbix→TeamCity box. Zabbix 7.0.0 allows "sign in as guest"; a guest
can invoke a global script at the trapper, whose `clientip` field is the sink for
**CVE-2024-22120** (time-based blind SQLi in the audit log) — extract a live
Super-Admin session id, run a server script for code exec as `zabbix`. Root is
TeamCity (running as root, all RCEs patched): a root cron logs into the Zabbix
frontend as `Frank` on a loop, and the docroot is `zabbix`-writable, so an
`index.php` hook harvests Frank's password in transit; Frank is TeamCity
SYSTEM_ADMIN, and a build step on the root agent reads the flag.

*Machine status: retired. Flag values are redacted here; the local copy keeps
them as evidence.*

A monitoring box that turns into a CI box. The interesting part is that neither
half is exploited with a dropped exploit — the Zabbix side is a pre-auth SQLi
that lives in the *audit log*, and the TeamCity side is reached by letting a root
cron job hand you its own password.

## Recon

Two web ports and two Zabbix ports:

```
22/tcp    OpenSSH 8.9p1
80/tcp    Apache 2.4.52  -> redirects to http://watcher.htb/
10050/tcp zabbix-agent   (accepts TCP, returns nothing: Server= restricted)
10051/tcp zabbix-trapper
```

Port 80 redirects the raw IP to `watcher.htb`, the classic vhost-gating tell.
Fuzzing `Host:` finds `zabbix.watcher.htb` — a **Zabbix 7.0.0** frontend
(`apiinfo.version` returns `7.0.0` unauthenticated; the dashboard footer even
says `7.0.0alpha1`).

## Foothold: guest → CVE-2024-22120 → Super-Admin → zabbix

The login page offers *"sign in as guest"*, and it works — a valid session with
no credential. The guest role has `api.access=0`, so `api_jsonrpc.php` is closed,
but the UI is browsable and, crucially, a guest can invoke **global scripts**
straight at the trapper on 10051:

```json
{"request":"command","sid":"<guest sid>","scriptid":"2","clientip":"127.0.0.1","hostid":"10084"}
```

That returns the Traceroute output in-band. The `clientip` field is the sink for
**CVE-2024-22120**: Zabbix writes an audit-log row for the script execution and
concatenates `clientip` into the SQL unescaped. A payload of
`1' + (select sleep(5)) + '1` delays the response by five seconds — time-based
blind SQLi, as an anonymous user, no egress required (the oracle is the response
time of a call you already make).

A threaded binary-search extractor (`sqli.py`) pulls:
- `version()` → MySQL 8.0.43
- users → `Admin`(super-admin), `guest`, `Frank`(admin role)
- **a live Super-Admin `sessionid` from the `sessions` table**

That session id, presented as `Authorization: Bearer <sid>`, is accepted by the
API as Admin. From there a global script with `execute_on = Zabbix server` runs
shell commands on the host as the `zabbix` service account, output returned in
the API response — no reverse shell needed.

`/user.txt` is a symlink to `/var/lib/zabbix/user.txt` (the "non-standard
directory, /" hint), readable immediately.

user.txt: `<redacted>`

## The wall, and the pivot

Root is clearly TeamCity: `2024.03.3` running **as root** on `127.0.0.1:8111`,
with a build agent (also root) on `9090`. But:
- every named TeamCity RCE (CVE-2023-42793, CVE-2024-27198/27199) is patched in
  2024.03.3;
- no public PoC exists for anything that *does* affect 2024.03.3;
- guest login and self-registration are off;
- the data directory is under `/root` (0700), unreadable;
- the DB password from the frontend config doesn't reuse to TeamCity or SSH.

So TeamCity needs a real credential, and it isn't lying around. The lead came
from the **Zabbix audit log** (readable via the SQLi / MySQL): user *Frank*
logs in from `127.0.0.1` on a tight loop. Sampling the process table catches it:

```
root  CRON -> /bin/sh -c /usr/bin/python3 /root/scripts/login.py
```

A root cron logs into the Zabbix *web frontend* as Frank, repeatedly. The script
is unreadable — but the frontend it logs into is not: `/usr/share/zabbix` (the
Apache document root) is **writable by the `zabbix` account**. So instead of
reading Frank's password, make the login hand it over.

## Root: harvest Frank's password, then TeamCity → root

A three-line, non-destructive hook at the top of `index.php` appends any posted
`name:password` to a capture file. First attempt wrote to `/tmp` and silently
failed — Zabbix sets `open_basedir` to the docroot — so the capture file goes
*inside* the docroot. Within a minute the root cron logs in and drops:

```
Frank:<redacted password>
```

Frank authenticates to TeamCity (`/app/rest/server` → 200) and his role is
**SYSTEM_ADMIN**. With a system admin and a root Default Agent, root is a build
step. Over the REST API: create a project, a build type, a Command Line step
(`cat /root/root.txt`), and queue it. The build log shows:

```
[Step 1/1] uid=0(root) gid=0(root) groups=0(root)
[Step 1/1] <root flag>
```

root.txt: `<redacted>`

## Leads that failed (worth recording)

- **TeamCity agent XML-RPC on 9090.** Tempting — a root process with a
  localhost RPC — but modern TeamCity is agent-initiated; `system.listMethods`
  is not registered and the 9090 surface didn't accept build commands. Parked
  before it became a rabbit hole.
- **Writable systemd units.** `find -writable` flagged a dozen `.service`
  files; all were masked-unit symlinks to `/dev/null`. False positive.
- **Cracking the Zabbix bcrypt hashes.** Cost-10 bcrypt for Admin/Frank; rockyou
  (+best64) did not land Frank's password — which is why the capture-in-transit
  route mattered.

## Why it falls to one control

Disabling Zabbix guest login removes the free session that makes CVE-2024-22120
reachable pre-auth; the chain stalls at the very first step. Everything after —
the SQLi, the session theft, the frontend hook, the reused TeamCity admin
password, the root agent — is downstream of that one toggle.
