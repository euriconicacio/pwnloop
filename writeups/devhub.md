# DevHub — Hack The Box, Medium, Linux

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

DevHub is a box about *developer tooling left facing the wrong way*. Every step
is something a team stood up to make their own lives easier, exposed one notch
too far. There is nothing exotic here — the whole engagement is reading what each
service is willing to tell you and taking it at its word.

## Recon

Three ports: SSH, nginx, and 6274. nginx redirects the bare IP to `devhub.htb`,
so that goes into `/etc/hosts` straight away. The homepage is a static "internal
development platform" that helpfully lists its own stack: an **MCP Inspector** on
6274, a **Jupyter** analytics environment on `localhost:8888` ("analyst team
only"), and an internal git server "in maintenance." The full-port scan confirms
only 6274 is actually reachable from outside.

## Foothold: the inspector that spawns what you tell it

The SPA title gives it away — **MCPJam Inspector**, and the JS bundle pins it at
**v1.4.2**. An MCP inspector's entire job is to connect to MCP servers you
nominate, and the dominant MCP transport is stdio, i.e. *spawning a process from
caller-supplied config*. Exposed without auth, that is RCE by design — which is
exactly CVE-2026-23744 for this version.

Rather than guess the request body, you let the endpoint teach you: `POST
/api/mcp/connect` with `{}` answers `serverConfig is required`, then `serverId
is required`, and finally, given a `command`, it returns `MCP error -32000:
Connection closed`. That error is the *success* signal — your binary spawned,
wrote to stdout, and exited, so the MCP handshake failed. A quick OOB callback
confirmed the box can reach back out, and a reverse shell / planted SSH key as
`mcp-dev` made it stable.

## Lateral: a token in a process list

`mcp-dev` is a dead-end user, but local enumeration is loud with leads. `ss`
shows `127.0.0.1:5000` and `127.0.0.1:8888` bound internally, and `ps aux` hands
over the whole thing:

```
analyst … jupyter-lab --ip=127.0.0.1 --port=8888 … --ServerApp.token=a7f3b2c9…
```

The Jupyter token is right there in the command line, and Jupyter runs as
`analyst`. A token is all Jupyter wants: start a kernel over the REST API, open
the kernel websocket, send an `execute_request` running `subprocess`, and you are
executing Python as `analyst`. `user.txt` is read in that first cell.

## Root: an "operations" service that runs as root and hands out root's key

The other internal service, `127.0.0.1:5000`, calls itself **OPSMCP** and wants
an `X-API-Key`. Two things line up as `analyst`: `~/.opsmcp_key` holds that key,
and `ps` already showed OPSMCP's `server.py` running **as root**. Reading the
source (`/opt/opsmcp/server.py`, readable by analyst) shows the tell: alongside
the advertised tools there are *hidden* ones not in `/tools/list` but still
callable — including `ops._admin_dump`, whose `ssh_keys` target literally does
`open('/root/.ssh/id_rsa').read()` and returns it in the JSON response.

One authenticated `POST /tools/call` with `{"name":"ops._admin_dump",
"arguments":{"target":"ssh_keys","confirm":true}}` returns root's private key.
`ssh -i` with it, and that's root.

## Why it falls

Three widened boundaries, each sufficient on its own:

1. a local-only dev tool (MCP Inspector) published to the network;
2. a secret (Jupyter token) passed as a process argument, where every local user
   can read it;
3. a root daemon that treats "dump root's SSH key" as a feature, gated only by an
   API key a lower-privileged user can read.

The CVE got the shell; the local-convenience boundaries decided it ended at root.
The earliest fix is the cheapest: bind the inspector to localhost and there is no
door at all.

## Leads that didn't matter

- The "internal git server" the homepage advertised never materialised as an open
  port — a decoy pointing at the git theme of the box, not a path.
- `server.py` also hard-codes static `passwords` and `tokens` dump targets
  (fake-looking `$6$…` and `opsmcp_admin_*` strings). Those are noise; the only
  live primitive is the `ssh_keys` target reading a real file.
