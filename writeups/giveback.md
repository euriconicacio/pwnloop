# GiveBack — Hack The Box, Medium, Linux

> A WordPress charity site fronting a k3s cluster. An unauthenticated GiveWP
> RCE lands you in a pod with no token and no egress; the way out is a
> deliberately mislabelled internal CGI that is really a root shell, a
> service account that can read Secrets, and a `sudo` runc wrapper whose
> host-mount filter is one string compare you can walk around.

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

## Recon

Three ports: SSH, WordPress on nginx, and an odd one — `30686`. The odd port
answered with JSON:

```json
{"service":{"namespace":"default","name":"wp-nginx-service"},
 "localEndpoints":1,"serviceProxyHealthy":true}
```

plus an `X-Load-Balancing-Endpoint-Weight` header. That is a **k3s kube-proxy
service health check**. Before touching the web app we already know: this is
Kubernetes, the WordPress is a Service in the `default` namespace, and the
"machine" is a cluster node.

## Foothold: GiveWP (CVE-2024-5932 / -8353)

The homepage loads `give.css?ver=3.14.0` — the **GiveWP** donation plugin at
3.14.0, vulnerable to the unauthenticated PHP Object Injection RCE
(CVE-2024-5932, and the -8353 bypass). The POP chain ends in `shell_exec`; the
command rides in the `give_title` field of a donation submission after fetching
a form id and nonce.

Two honest wrong turns here:

- **Hand-rolled serialization didn't fire.** Building the object with real NULL
  bytes (PHP-correct `s:10:"\0*\0_values"` lengths) and firing it got a clean
  302 to `/donation-confirmation/` but no execution. WordPress's
  `wp_magic_quotes` / `wp_unslash` mangles the NULL-byte string lengths. The
  Metasploit module's exact encoding (the -8353 variant) did work, so I used it
  to *deliver* a webshell rather than fighting the encoding by hand.
- **Egress is blocked.** A `curl` callback to my tun0 hung ~12 s (connect
  timeout) while DNS/wget returned instantly — the pod cannot reach the VPN. So
  the webshell, not a reverse shell, is the control channel, and everything
  afterwards is driven through small PHP proxies dropped in the uploads dir.

Landed as `uid=1001 gid=0(root)` in `beta-vino-wp-wordpress-…`. The pod `env`
is a gift: MariaDB password, WP admin password, and — crucially —
`LEGACY_INTRANET_SERVICE … 10.43.2.241:5000`. No service-account token is
mounted here, the k8s API wants auth, and the kubelet (10250) is locked. The
only forward lead is the internal CMS.

## The decoy: php-cgi / CVE-2024-4577

The intranet CMS screams CVE-2024-4577: it advertises `/cgi-bin/php-cgi`, a
"PHP-CGI Handler", and a developer note that it was "originally deployed on
Windows IIS using php-cgi.exe" with "Windows-style CGI handling retained". This
is bait.

The endpoint behaves oddly: a normal request returns `OK`, but a query
containing `auto_prepend_file=php://input` flips the Content-Type to `text/html`
and returns `[START][END]`. Hours could vanish here. The actual argument
injection never executes — no best-fit byte 0x80–0xFF maps to `-`, every
`auto_prepend` wrapper (`php://input`, `data://`, `/etc/passwd`) returns the
canned marker or baseline. The `php://input` response is pure WAF theatre.

The real tell came from varying the POST body:

```
echo 777;            -> [START]777[END]      (reflected literally)
echo 1+1;            -> [START]1+1[END]       (NOT computed -> not eval)
echo `id`;           -> [START]uid=0(root)... (backticks run in a shell!)
```

So the endpoint drops my body into a **shell**, as **root**. The whole
CVE-2024-4577 story is a costume on a plain root command injection. Lesson
logged: when an endpoint is wrapped in a named-CVE narrative that refuses to
fire, probe what it *actually* does with the input instead of iterating the CVE.

## Lateral: service account -> Secret -> user

Unlike the WP pod, the intranet pod mounts a token. `SelfSubjectRulesReview`
says it can `get,list secrets` in `default`. One secret stands out —
`user-secret-babywyrm` — holding `MASTERPASS`, which base64-decodes to a
password. `babywyrm` was WordPress user id 1; the name is also a node login.
SSH to the node as `babywyrm` with that password works. **user.txt.**

## Root: the runc wrapper and the `/.` bypass

`sudo -l` for babywyrm:

```
(ALL) /opt/debug
```

`/opt/debug` is a "Restricted runc Debug Wrapper". It first validates sudo, then
prompts for an "administrative password" — which turns out to be the **reused
MariaDB password** from the very first pod's environment. With that, the wrapper
exposes `spec` and `run <id>`.

`run` builds the OCI bundle from the **current directory** and calls `runc run`
as root. So I supply my own `config.json`. First attempt — host `/` as the
container rootfs — fails `pivot_root` ("device or resource busy"). Second
attempt — a minimal rootfs with host dirs bind-mounted in and `/` bind-mounted
to `/host` — is caught:

```
Error: Host root filesystem mount detected - not permitted
```

So there *is* a guard — but it is a string compare against `"/"`. Changing the
mount source to **`"/."`** rbinds the exact same host root and sails past the
check. The container (root, with the host filesystem at `/host`) drops a SUID
`bash` on the host and reads `root.txt`. **root.txt.**

## Chain in one line

GiveWP unauth RCE → (no token, no egress) → internal CGI that is secretly a root
shell → SA can read Secrets → OS password in a Secret → SSH as user → sudo runc
wrapper with a string-only mount filter bypassed by `/.` → host root.

## What the defender should take away

The entry CVE is loud and patchable, but the compromise is built from quiet
boundary erosions: a pod running as root, a service account that can read every
Secret, an OS password *stored in* a Secret, and a privileged `runc` wrapper
that trusts a user-supplied bundle and filters mounts by string instead of by
resolved path. Any one of those closed turns the chain into a dead end.
