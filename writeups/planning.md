# planning.htb — write-up

> Retired-box write-up, flags redacted. An assumed-breach Grafana login, a
> DuckDB RCE, a password sitting in the container's environment, and a
> root-owned cron web UI reachable only from localhost.

## Recon

Two ports: SSH and nginx. `80` redirects to `planning.htb` and serves a static
"Edukate" template with nothing behind it. The interesting surface is a vhost —
and here is the first lesson: a 20k-subdomain fuzz found **nothing**, because
`grafana` is not in `subdomains-top1million-20000`. The name came from reasoning
about the assumed-breach creds (an app admin), not the wordlist. Methodology note: a
vhost fuzz returning empty is not proof of "no vhosts" when the list is thin.

`grafana.planning.htb` answers, and `/api/health` reports **Grafana 11.0.0**.

## Foothold: CVE-2024-9264

The assumed-breach credential `admin / 0D5oT70Fq13EvB5r`, which logs into Grafana as a full
admin. Grafana 11.0.0 is vulnerable to **CVE-2024-9264**: the experimental SQL
Expressions feature hands a user-controlled query to a bundled **DuckDB**
binary. `POST /api/ds/query` with a server-side `__expr__` datasource runs SQL.

Two wrinkles in practice:

- The expression runner only accepts **row-returning** statements. `SELECT` works;
  a bare `LOAD`/`INSTALL`/`PRAGMA` returns 500, and a multi-statement batch 400s.
  So a hand-rolled `LOAD shellfs; SELECT …` fails.
- The public PoC sidesteps this by prefixing `SELECT 1;` so the whole batch
  returns a result set: `SELECT 1; install shellfs from community; LOAD shellfs;
  SELECT * FROM read_csv('<cmd> >/tmp/out 2>&1 |')`. `shellfs` is already present,
  and the reader executes the piped command.

File read alone (`SELECT content FROM read_text('/etc/passwd')`) works with no
extension at all — worth confirming the SQL path before chasing exec. Command
execution lands as **root inside the Grafana container**.

## Lateral: the password is in the environment

Root in a container is only useful if it leads somewhere. It does:
`/proc/1/environ` holds

```
GF_SECURITY_ADMIN_USER=enzo
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
```

That password is reused for the **host** user `enzo` over SSH. `user.txt` is in
enzo's home.

## Root: a root cron UI on localhost

enzo is not a sudoer. `ss -ltnp` shows localhost services, including an Express
app on `:8000`. `/opt/crontabs/crontab.db` is world-readable and tells the whole
story: it is the store for **crontab-ui**, its jobs run as root, and one job's
command contains `zip -P P4ssw0rdS0pRi0T3c …`.

That password is reused a second time — it is the crontab-ui Basic-auth secret
for user `root`. Tunnel `:8000` out, authenticate, and you are editing root's
crontab through a web UI.

Creating a brand-new job did not persist in this instance, but **editing an
existing job** (`POST /save` with its `_id`) and then `POST /runjob` executed the
new command immediately as root. Payload: make a SUID copy of bash. `bash -p` →
`euid=0` → `root.txt`. The edited job was restored afterwards.

## Lessons

- A thin subdomain wordlist produces a false "no vhosts." Step up the list, and
  derive candidate names from the app you were pointed at.
- CVE-2024-9264 is "authenticated Grafana → DuckDB → shell." Pin the version at
  `/api/health`; the `SELECT 1;`-prefix trick is what makes the batch run.
- After any container RCE, read `/proc/1/environ` first — secrets handed to a
  container as env vars are the most common pivot to the host.
- A web UI that manages root's crontab is a root shell for whoever authenticates;
  the only defence left was a password, and it was reused from a world-readable file.
