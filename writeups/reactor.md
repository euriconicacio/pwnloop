# ReactorWatch — write-up

> Flags redacted.

## Recon

Two ports: `22/ssh` and `3000/http`. The full-range sweep confirmed nothing
else — a deliberately small surface, so the path is in one of the two. Port 3000
is a Next.js App-Router app, "ReactorWatch — Core Monitoring System", a static
nuclear-reactor dashboard.

Pinning mattered: there is no version header, but the runtime chunk
(`/_next/static/chunks/517-*.js`) carries `version:"15.0.3"` and React
`19.0.0-rc`. `package.json` later confirmed `next 15.0.3 / react 19.0.0`.

Dead ends worth recording: directory/route brute force found nothing (the app is
a single prerendered `/`); the `/_next/image` optimizer was locked down (400);
and there is **no middleware**, so CVE-2025-29927 (the other big Next.js bug) did
not apply — every `x-middleware-subrequest` variant returned the identical page.

## Foothold — React2Shell (CVE-2025-55182 / CVE-2025-66478)

React 19's Server Components *Flight* decoder deserializes a Server-Action
request body while trusting record types an attacker can spoof. A single
`POST /` with `Next-Action: x` and a `multipart/form-data` Flight payload walks
the prototype chain so that an internal `_formData.get` becomes the `Function`
constructor and `_prefix` becomes JavaScript that is then executed on the server.

The elegant part is the output channel: the injected JS runs the command, then
throws a `NEXT_REDIRECT` error whose digest encodes the (base64) command output
into a `/x?a=<out>` redirect. Next returns that in the **`x-action-redirect`**
response header — so the exploit is fully synchronous and needs no outbound
connectivity from the target. Result: code execution as `node`.

## Loot → user

`/opt/reactor-app` held `reactor.db` (SQLite), readable by `node`, with a
`users` table of unsalted MD5. `engineer`'s hash cracked instantly to
`reactor1` against rockyou — and that application password was also the
`engineer` Unix password, so it logged straight in over SSH. `user.txt` read.

Lesson reinforced: after any web RCE, read the deployed DB/`.env` before anything
clever; a reused application password beat every other idea here.

## Privesc → root

`ps` showed a root-owned service:
`/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js`. The V8
inspector is full code execution inside the (root) process for anyone who can
reach `127.0.0.1:9229`. It was localhost-bound, but the `engineer` SSH session
tunnels it out trivially; attaching the Chrome DevTools Protocol and calling
`Runtime.evaluate` with `child_process.execSync` runs commands as **root**.
`root.txt` read.

The misconfiguration is in the unit file itself: `User=root` plus an
`ExecStart` that carries `--inspect`. A debug flag left in a production root
service turns any local foothold into instant root.

## Chain

unauth React2Shell RCE (node) → readable app SQLite + MD5 crack → SSH password
reuse (engineer) → root Node `--inspect` debugger → root.
