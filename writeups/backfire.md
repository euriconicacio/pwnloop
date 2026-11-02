# backfire — write-up

**Platform:** Hack The Box · **Difficulty:** Medium · **Status:** retired

A box built around two command-and-control frameworks. The whole path is
"attack the attackers": the operators left their own C2 infrastructure
misconfigured, and every step abuses a C2 feature rather than a classic web or
system bug.

## Recon

```
22/tcp   OpenSSH 9.2p1 (Debian)
443/tcp  nginx 1.22.1 (ssl)   -> returns X-Havoc: true
8000/tcp nginx 1.22.1         -> directory listing
5000/tcp filtered (internal HardHat API)
7096/tcp filtered (internal HardHat SignalR)
```

Port 8000 is an open directory listing with two files: `havoc.yaotl` and
`disable_tls.patch`. `havoc.yaotl` is a **Havoc C2 teamserver profile**, and it
hands over almost everything:

- operator credentials in cleartext (`ilya`, `sergej`);
- the management websocket on `127.0.0.1:40056` (local-only);
- the vhost `backfire.htb`;
- a demon HTTP listener.

`disable_tls.patch` explains that the management port was switched from `wss://`
to plain `ws://` ("so I can prove sergej is not doing any work"). The 443
response carrying `X-Havoc: true` confirms nginx is reverse-proxying the Havoc
teamserver.

## Foothold — Havoc C2 (CVE-2024-41570 chain)

Havoc 0.7 has two issues that combine into unauthenticated RCE:

- **SSRF (CVE-2024-41570):** spoofing a demon agent registration and socket-open
  messages to the agent listener makes the teamserver open an arbitrary TCP
  socket you can read and write.
- **Authenticated command injection:** the `Service Name` field of a
  "Windows Service EXE" build is concatenated into the mingw cross-compile
  command line.

Chain them: use the SSRF to open a socket from the teamserver to its own
local-only management websocket (`127.0.0.1:40056`), speak the websocket
handshake through that socket, authenticate with the leaked operator password,
and trigger the build with an injected `Service Name` that runs a command. The
public chained PoC fetches a `payload.sh` and pipes it to `bash`.

Two practical notes that cost time:

- The teamserver **caches builds by config**, so re-running the exploit with an
  identical injected command silently does nothing — vary the command (e.g. a
  dummy query string on the fetch URL) to force a rebuild.
- The listener name is persistent; re-use a fresh name on each run.

The command runs as `ilya`. Rather than babysit a reverse shell, drop an SSH key
into `~ilya/.ssh/authorized_keys` and log in cleanly. `user.txt` is right there.

## Lateral movement — ilya → sergej (HardHat C2)

Process list shows `sergej` running **HardHat C2** (`TeamServer`,
`HardHatC2Client`). Its API + Swagger live on `127.0.0.1:5000`, with a SignalR
hub at `/HardHatHub`; port 7096 is a secondary listener. Tunnel 5000/7096 back
through ilya's SSH.

HardHat's authentication is forgeable because its `appsettings.json` (public in
the product's repo) hard-codes the JWT key `jtee43gt-6543-2iur-9422-83r5w27hgzaq`
and issuer `hardhatc2.com`, with an IP whitelist of `*`. Reading the server
source, the token is a plain HS256 JWT with a role claim
(`ClaimsIdentity.DefaultRoleClaimType`) of `Administrator`, and both issuer and
audience validate against `hardhatc2.com`. Forge it offline with any JWT library.

The `/HardHatHub` SignalR hub has no `[Authorize]` attribute, and two of its
methods are the whole game:

- `TriggerDownload(path)` → `File.ReadAllBytes(path)` → arbitrary file read as
  `sergej`;
- `HostFile(base64, filename)` → writes to `<app>/wwwroot/<filename>` with no
  path sanitisation → arbitrary file **write** as `sergej` via `../` traversal.

Connect to the hub (ASP.NET Core SignalR: `POST /HardHatHub/negotiate` for a
connection token, then a WebSocket with the JSON protocol handshake) and call
`HostFile` with `filename = ../../../.ssh/authorized_keys` to drop a key into
`/home/sergej/.ssh/`. SSH in as `sergej`.

## Privilege escalation — sergej → root (sudo iptables)

```
sergej@backfire$ sudo -l
(root) NOPASSWD: /usr/sbin/iptables
(root) NOPASSWD: /usr/sbin/iptables-save
```

`iptables-save -f <file>` writes the current ruleset to any path, as root — an
arbitrary file write. To control the *content*, stash it in a rule comment.
iptables comments accept an embedded newline, so:

```bash
CMT=$(printf '\n%s\n' "$PUBKEY")
sudo iptables -A INPUT -m comment --comment "$CMT" -j ACCEPT
sudo iptables-save -f /root/.ssh/authorized_keys
```

In the dump, the newline puts the public key at column 0 of its own line; sshd
reads that line as a valid key and ignores the surrounding ruleset syntax. A
periodic job flushes added rules, so run the add + dump + `ssh root@` in one
window. `root.txt` follows.

## Flags

```
user.txt — <32-hex-flag>
root.txt — <32-hex-flag>
```

## Lessons

- A C2's own config/profile file is a credential store and a map of its internal
  ports — treat "can download the profile" as "owns the teamserver".
- Hard-coded signing keys in an open-source product's default config mean "forge
  any token" the moment you fingerprint the product; always read the source for
  the exact claim shape before guessing.
- `sudo iptables-save -f` is an arbitrary-root-write primitive; combined with the
  newline-tolerant comment field it writes attacker content, not just rules.
