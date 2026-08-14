# APIs, tokens and modern web surfaces

Increasingly the interesting surface on a lab box is an API behind a
single-page app rather than a rendered form. The JavaScript bundle is the
documentation — read it before fuzzing.

## Find the API

```bash
pwnloop x "curl -s http://machine.htb/ | grep -oE 'src=\"[^\"]+\.js\"'"
pwnloop x "curl -s http://machine.htb/static/js/app.js | grep -oE '\"/api/[a-zA-Z0-9/_{}-]+\"' | sort -u"
pwnloop x "curl -s http://machine.htb/static/js/app.js | grep -oiE '(api[_-]?key|token|secret|bearer)[\"'\'':= ]+[A-Za-z0-9._-]{12,}'"
```

Common self-documenting endpoints — always try them:

```
/api  /api/v1  /api/docs  /swagger.json  /openapi.json  /swagger-ui/
/graphql  /graphiql  /v1/graphql  /.well-known/openid-configuration
/actuator  /actuator/env  /actuator/heapdump      (Spring Boot)
/_debugbar  /telescope  /horizon                  (Laravel)
/api/v1/repos/search  /api/v1/users/search        (Gitea)
```

A Swagger or OpenAPI document hands you every route, parameter and auth scheme
at once. `/actuator/heapdump` on Spring Boot is a credential dump.

## GraphQL

Introspection is the whole game. If it is enabled, you get the entire schema:

```bash
pwnloop x "curl -s http://machine.htb/graphql -H 'Content-Type: application/json' \
  -d '{\"query\":\"{__schema{types{name fields{name args{name type{name}}}}}}\"}' | jq ."
```

Disabled introspection is not protection — try the suggestion oracle (a typo in
a field name returns "Did you mean …"), and try `/graphiql`, `/v1/graphql`,
`/api/graphql` which are often left unprotected when `/graphql` is locked down.

Then look for: queries returning more than the UI shows, mutations the UI never
calls (`deleteUser`, `updateRole`, `createInvite`), missing authorization on
individual resolvers, and batching (send an array of queries) to bypass rate
limits on a login mutation.

## JWT

```bash
pwnloop x "echo '<jwt>' | cut -d. -f1,2 | tr '_-' '/+' | base64 -d 2>/dev/null"
```

In order of likelihood on a lab box:

1. **`alg: none`** — set the algorithm to `none`, drop the signature, change
   `role` to admin.
2. **Weak HMAC secret** — crack it, then re-sign:
   ```bash
   pwnloop x "echo '<jwt>' > jwt.txt && john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt"
   pwnloop x "hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt"
   ```
3. **Algorithm confusion** — a token signed RS256 verified as HS256 using the
   public key as the HMAC secret. Get the public key from `/jwks.json` or the
   TLS certificate.
4. **`kid` injection** — path traversal or SQL injection in the key-id header.
5. **Unverified claims** — `sub`, `role`, `admin` trusted without a signature
   check at all. Test by mangling the signature: if it still works, there is no
   verification.

## Session and auth logic

- **IDOR** on any numeric or guessable identifier — the single highest-yield
  test on an authenticated API. Change the id, change the account.
- **Mass assignment** — add `"role":"admin"` or `"isAdmin":true` to a profile
  update body and see whether it sticks.
- **Method override** — a blocked `DELETE` may work as
  `POST` + `X-HTTP-Method-Override: DELETE`.
- **Missing auth on one route** — authorization enforced in the UI or on
  `/api/v1/x` but not `/api/v2/x`, or on `GET` but not `PATCH`.
- **Race conditions** — send N identical requests concurrently against a
  one-time action (coupon, withdrawal, invite):
  ```bash
  pwnloop x "seq 20 | xargs -P 20 -I{} curl -s -X POST http://machine.htb/api/redeem -H 'Authorization: Bearer <t>' -d 'code=X'"
  ```

## WebSockets

```bash
pwnloop x "curl -s -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' http://machine.htb/ws"
```

WebSocket handlers frequently skip the authorization checks the REST routes
have, because the developer assumed the socket could only be opened by the UI.
Messages are usually JSON — the same injection and IDOR tests apply.

## Server-side request forgery

Any parameter taking a URL is an SSRF candidate, and on a lab box SSRF is
usually the bridge to an internal service that holds the real vulnerability:

```
?url=http://127.0.0.1:8080/         # internal-only ports from the nmap gap
?url=http://localhost/admin
?url=file:///etc/passwd
?url=gopher://127.0.0.1:6379/_...   # Redis via gopher
```

Cross-reference with `ss -tulpn` output once you have a shell — a service bound
to `127.0.0.1` that you saw from the outside via SSRF is the intended path.

### A talkative SSRF is a loopback port scanner, and that is often its real value

Do not measure an SSRF only by whether it reaches something exploitable. Measure
what its **error messages distinguish**. A handler that wraps the transport error
and returns it verbatim gives you three separable states, which is everything a
port scan needs:

| response | meaning |
|---|---|
| `dial tcp 127.0.0.1:N: connect: connection refused` | closed |
| `HTTP status <code> for URL ...` | open, speaks HTTP, non-200 |
| a parse error naming the first byte (`invalid character '<'`) | open, and serving HTML rather than the expected JSON |

Sweep the loopback range through it before you hold any credential. The service
it uncovers is frequently where the actual foothold lives, while the app hosting
the SSRF never gets exploited at all — so the finding to chase is the *map*, not
the fetch.

Two things to check in the source or by probe, because they decide the sweep's
reach: whether the client validates scheme/host at all (`http.NewRequest` +
`client.Do` with no allow-list is the common shape), and whether it follows
redirects — a permissive fetcher plus your own `302` server extends the sweep to
schemes the parameter parser would have rejected.

**Report it even when you did not exploit it.** "Unauthenticated internal network
mapping" is a real finding, and it is the one that explains how you found
everything else.

## SOAP / JAX-WS services (and CXF MTOM file-read)

A recovered `.jar`/`.war` that decompiles to a JAX-WS service (annotations
`@WebService`, an Apache CXF `JaxWsServerFactoryBean`, a WSDL at `?wsdl`) is an
XML-parsing surface — reason about it like any XXE target, but know the modern
stacks block the naive version and have a second door:

1. **Map the operation from the WSDL/decompiled interface.** One operation that
   takes a complex type and *echoes a field back* is a reflected file-read oracle.
   Send a normal request first and confirm the echo.
2. **Try classic XXE, but expect it to be refused.** Hardened Woodstox/CXF answers
   an inline `<!DOCTYPE …>` with `Error reading XMLStreamReader: Received event
   DTD …` — that's `supportDTD`-off, not a bypassable parser. Don't grind on it.
3. **Pin the framework and hunt its *own* CVEs — the parser block doesn't cover the
   whole stack.** Read `META-INF/maven/<group>/<artifact>/pom.properties` for exact
   versions. For Apache CXF, the databinding/attachment layer is a separate attack
   surface from the StAX reader: e.g. an MTOM message
   (`Content-Type: multipart/related; type="application/xop+xml"`) whose element is
   `<xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///path"/>`
   makes CXF *fetch the href itself* — file read / SSRF that never touches the DTD
   path. (Vulnerable ranges are a version lookup; the technique is the point.) If the
   operation echoes the field, the file returns inline (often base64) — a clean,
   shell-independent read primitive you can keep using after you have a foothold.

The class: **when the obvious XML injection is patched, the databinding/attachment
layer of the same server often reaches files or URLs by a different code path.**
Pin the version, enumerate that product's CVEs, and read the PoC for *which layer*
fetches the href.
