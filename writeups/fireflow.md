# FireFlow — Hack The Box, Linux

A modern chain: LLM-workflow platform → password reuse → a bespoke MCP tool
registry with a JWT flaw → Kubernetes kubelet abuse → node root.

Recon note: worked from the IP alone; the name "FireFlow" and domain
`fireflow.htb` were discovered from the TLS certificate, not supplied. No prior
knowledge of a published path — the search order below is what the evidence
drove.

---

## Recon

Only two ports: `22` (OpenSSH 9.6p1, Ubuntu 24.04) and `443` (nginx). The TLS
cert gives `CN=fireflow.htb`, SAN `*.fireflow.htb`, org "Task Force Nightfall".
Add `fireflow.htb`. The landing page leaks a vhost in a header:

```
X-Frame-Options: ALLOW-FROM https://flow.fireflow.htb
```

and links a "public playground" flow id. `flow.fireflow.htb` is **Langflow
1.8.2**.

## Foothold — unauthenticated Langflow RCE

Auto-login is off and `/api/v1/flows/` needs auth, but two things are open:

- `GET /api/v1/flows/public_flow/<id>` returns the **entire flow graph** of the
  public flow, including each component's inline Python source and the parent
  project id.
- `GET /openapi.json` (unauth) maps all 77 routes. One stands out:
  `POST /api/v1/build_public_tmp/{flow_id}/flow` — description "Build a public
  flow without requiring authentication", `security: None`, body is a
  caller-supplied `FlowDataRequest` (`nodes`/`edges`, `additionalProperties`).

Langflow executes each node's code from `template.code.value`. So: fetch the
public flow, swap the `TextOperations` node's code for our own `Component`
subclass whose output method runs `subprocess`, and POST it back to
`build_public_tmp`. A `client_id` cookie is required (any UUID). Poll
`/build_public_tmp/{job_id}/events` for the result.

```
uid=33(www-data) gid=33(www-data)  host fireflow  Ubuntu 24.04.4
```

See `exploit.py`. This is unauthenticated code execution.

## Lateral — env secret + password reuse (user.txt)

`www-data`'s environment (and `/etc/langflow/.env`, group-readable) contains:

```
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=<superuser-pass>
```

That password logs straight into SSH as **nightfall** → **user.txt**.

## Enumeration as nightfall

No sudo rights. Stock SUID/caps. But localhost is a **k3s** node (6443, 10250,
10259, …) and `~/.mcp/config.json` holds:

```json
{"server":"http://10.129.x.x:30080","user":"langflow-bot","password":"<mcp-password>"}
```

`:30080` is a k3s NodePort (localhost-only) serving a custom **"MCP AI Tool
Registry"**. Its `/api/v1/version` advertises `"supported_algorithms":["HS256",
"none"]`, and `/openapi.json` shows `POST /api/v1/tools [admin]` taking a `code`
string. Reading `/app/main.py` (via the pod, later) confirms it:

```python
if alg == "none":
    payload = jose_jwt.decode(token, key="", options={"verify_signature": False})
```

## In-cluster RCE — JWT alg:none

Forge `{"alg":"none"}.{"sub":"admin","role":"admin"}.` (empty signature). The
registry accepts it as admin. Register a tool whose `code` shells out, then call
it via MCP JSON-RPC `tools/call`:

```
uid=1000(mcp)  pod mcp-server-…  namespace default
```

We now execute inside a Kubernetes pod.

## The dead ends (worth recording)

- **`nightfall-admin:<admin-password>`** leaks from the registry source. It
  is *only* the registry admin — no reuse to host root (SSH/su fail).
- **sudo 1.9.15p5** is in the CVE-2025-32463 range, but `sudo -R` is rejected:
  nightfall has no sudoers rule granting chroot, so the LPE isn't reachable.
  A reminder that a pinned-vulnerable version is not automatically exploitable.

## Privilege escalation — kubelet abuse to node root (root.txt)

The `mcp-sa` service account, checked with SelfSubjectRulesReview /
SelfSubjectAccessReview, has exactly one useful permission cluster-wide:
**`get nodes/proxy`**. No exec, no create, no secrets.

`get nodes/proxy` is enough to reach the **kubelet API** through the apiserver
proxy (`/api/v1/nodes/<node>/proxy/...`) *and* directly at `:10250` from the
host. Listing pods reveals the prize:

```
monitoring/prometheus-…-node-exporter :
  container securityContext: privileged:true, runAsUser:0, allowPrivilegeEscalation:true
  hostPID:true, hostPath / -> /host/root
```

Exec (`POST`, `create nodes/proxy`) is denied — but a **GET** to
`/exec/…` returns *"Upgrade request required"*, i.e. it authorizes as
`get nodes/proxy` and only wants a streaming upgrade. The kubelet maps
`exec` to subresource `proxy`, and we have `get` on it.

So: open a **WebSocket** to the kubelet exec endpoint. `v5.channel.k8s.io` is
refused (403), **`v4.channel.k8s.io` returns `101 Switching Protocols`**. The
target container is distroless (no shell, no nsenter), but host `/` is mounted
at `/host/root`, so invoke the host's dynamic loader explicitly and run the
host's `nsenter` into PID 1's namespaces (hostPID makes PID 1 the host init;
privileged + uid 0 grants `CAP_SYS_ADMIN`):

```
/host/root/lib64/ld-linux-x86-64.so.2 \
  --library-path /host/root/usr/lib/x86_64-linux-gnu:/host/root/lib/x86_64-linux-gnu \
  /host/root/usr/bin/nsenter -t 1 -m -u -i -n -p -- /bin/bash -c '<cmd as root on the node>'
```

```
uid=0(root)  → cat /root/root.txt  → root.txt
```

A stdlib-only WebSocket client (`kwsexec.py`) does the whole thing from the host
with the pod's SA token; no external kubelet tooling needed.

## Why it worked (defender's one-liner)

The `get nodes/proxy` grant on a pod SA is the hinge: it silently exposes the
kubelet's exec channel, and one privileged monitoring pod turns that into node
root. Remove that grant, or stop node-exporter running privileged as uid 0, and
the chain breaks.

## Chain

unauth Langflow public-flow RCE → env password → SSH nightfall (user) →
`~/.mcp` creds → MCP registry JWT `alg:none` → in-pod RCE →
SA `get nodes/proxy` → kubelet WebSocket exec into privileged node-exporter →
nsenter host PID 1 → root.
