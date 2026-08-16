# Barrier — VulnLab (retired)

**Linux**

```
public GitLab repo → password in a "removed" commit → satoru
  → CVE-2024-45409 SAML signature-wrapping forges an akadmin assertion → GitLab admin
  → admin CI variable leaks an authentik SUPERUSER token → reset any user → Guacamole SSO
  → maki's Guacamole-stored SSH key → user
  → Guacamole DB (host config) → maki_adm connection key + passphrase → maki_adm
  → sudo password in ~/.bash_history → root
```

Four services — GitLab, authentik, Guacamole, and the host — each honouring the
next one's trust and each leaking the key to it. Nothing here is memory
corruption or brute force; every step is a trust boundary that holds while the
secret behind it walks out a side door.

Flag values redacted; machine and VPN addresses generalised.

---

## Recon

Two scans mattered. The first, run the moment the box answered ping, saw only
22, 8080, 9000 and 9443. A careful re-scan a few minutes later added **80 and
443** — the box was still booting during scan one (authentik's TLS certificate
is stamped the same minute I first scanned). One early port scan under-reports a
slow-booting, multi-service host; re-scan it.

- **9000/9443 — authentik 2024.10.5.** The SSO/identity provider. The version is
  in the static asset paths (`dist/poly-2024.10.5.js`), so it gets pinned first —
  it is the component that decides who is authenticated.
- **8080 — Apache Tomcat 9.0.58**, default page. A directory sweep found only
  `manager` (401); the deployed app was invisible to the wordlist.
- **80/443 — GitLab CE 17.3.2** behind nginx (`gitlab.barrier.vl`).

authentik's OpenAPI schema is served unauthenticated and declares exactly 8 of
475 routes as no-auth. One is `/api/v3/providers/saml/{id}/metadata/`; iterating
the id returns two SAML applications, **`gitlab`** and **`guac`**. The `guac`
metadata's SSO URL is what disclosed the hostname `barrier.vl` and pointed at
`http://barrier.vl:8080/guacamole/` — the app the Tomcat wordlist had missed. The
SAML metadata, not the fuzzer, mapped the estate.

## The credential

GitLab's `/api/v4/projects` is readable unauthenticated → one public repo,
`satoru/gitconnect`. It has two commits to a single file; the second replaces the
password with `***`. The value survives in the earlier blob:

```
$ git ... /repository/files/gitconnect.py/raw?ref=<first-commit>
    'username': 'satoru',
    'password': 'dGJ2V72SUEMsM3Ca'
```

A secret removed in a later commit is not removed. That password logs into
authentik and (same password) mints a GitLab OAuth token — but `satoru` is a
nobody in both: no groups, no Guacamole connections, an ordinary GitLab user.

## The pivot: CVE-2024-45409

GitLab authenticates through authentik SAML, and GitLab 17.3.2 ships a ruby-saml
in the vulnerable range. The bug is XML signature wrapping: with any one
*genuinely signed* assertion from the IdP you can build an assertion for a
different identity that still verifies.

So I logged into authentik as `satoru` and drove the SP-initiated flow to capture
satoru's own signed `SAMLResponse` (deflate-encoded on the redirect binding —
raw-inflate with `zlib.decompress(data, -15)` before touching it), then ran the
synacktiv PoC to:

- move the `<ds:Signature>` from the Response into the Assertion,
- plant a *cloned* `<ds:Reference>` with a recomputed `DigestValue` inside
  `samlp:StatusDetail` (a node the verifier's XPath still selects but the SP
  ignores),
- rewrite `<saml:NameID>` to `akadmin`.

authentik uses the username as the NameID (satoru's assertion literally reads
`<NameID>satoru</NameID>`), so the admin's NameID is simply `akadmin`. POST the
forged document to GitLab's ACS:

```
$ curl .../api/v4/user      # with the resulting session cookie
{"id":1,"username":"akadmin","name":"akadmin", ...}   # is_admin: true
```

GitLab administrator, from a password left in a repository.

## GitLab admin → the identity provider

The reflex with GitLab admin is CI-runner RCE, and there *is* a shared runner —
but it is a non-privileged docker executor (no socket, no host mount, `CapEff
a80425fb`) and the box is airgapped, so it cannot even pull `alpine`; a plain
pipeline is a dead end for a host shell. The real prize was quieter.
`/api/v4/admin/ci/variables` held an instance CI variable **`AUTHENTIK_TOKEN`**:

```
$ curl -H "PRIVATE-TOKEN: <admin>" .../api/v4/admin/ci/variables
[{"key":"AUTHENTIK_TOKEN","value":"<authentik-superuser-token>","protected":true, ...}]
```

It is an authentik API token for `akadmin` — `is_superuser: true`:

```
$ curl -H "Authorization: Bearer <token>" .../api/v3/core/users/me/
{"user":{"pk":4,"username":"akadmin","is_superuser":true, ...}}
```

GitLab admin had handed over the entire identity provider.

## Superuser → Guacamole → maki

authentik's users: `akadmin`, `satoru`, and a fresh one, **`maki`**. Guacamole
maps its username from a SAML claim. I cannot change satoru's username
(self-service blocks it), but as superuser I can set *maki's* password to one of
my choosing, log in as maki, and ride the SP-initiated SAML into Guacamole:

```
$ curl -X POST -H "Authorization: Bearer <token>" \
    .../api/v3/core/users/35/set_password/ -d '{"password":"<chosen>"}'   # 204
```

maki owns one connection — **"Maintenance"**, SSH to `localhost` — and has
`ADMINISTER` on it, so the API returns the stored **OpenSSH private key** in
cleartext:

```
$ curl ".../api/session/data/mysql/connections/1/parameters?token=<t>"
{"hostname":"localhost","port":"22","username":"maki",
 "private-key":"<OPENSSH private-key blob — redacted>"}
```

(The container's OpenSSL rejected the key with `error in libcrypto: unsupported`.
The key was fine — re-serialising it through Python `cryptography` produced a PEM
the client accepted. That error is a tooling problem, never a reason to discard a
recovered key.)

```
maki@barrier:~$ cat user.txt
<user flag redacted>
```

## The host: Guacamole's own database

Guacamole runs on the *host* Tomcat, not in a container, so
`/etc/guacamole/guacamole.properties` is right there and world-readable:

```
mysql-username: guac_user
mysql-password: guac2024
saml-username-attribute: ...upn
```

maki's API view showed one connection; the database showed **two**. The
permission model gates the API, not the table:

```
$ mysql -h127.0.0.1 -uguac_user -pguac2024 guac_db \
    -e "select connection_id,connection_name,protocol from guacamole_connection"
1  Maintenance  ssh
2  Maki_Adm     ssh
```

Connection 2, invisible to maki through the API, is an SSH connection to
`localhost` as **`maki_adm`**, storing an *encrypted* RSA key **and its
passphrase** side by side in cleartext:

```
2  private-key  <RSA private-key blob, Proc-Type: 4,ENCRYPTED — redacted>
2  passphrase   <redacted>
2  username     maki_adm
```

Decrypt the PEM with the passphrase and `ssh maki_adm@barrier`. `maki_adm` is in
the `admin` group (sudo-capable on Ubuntu), but sudo wants a password and no
recovered credential is reused for it. It is in the account's own shell history:

```
maki_adm@barrier:~$ cat ~/.bash_history
sudo su
3V32FN6oViMPxyzC     # <- decoy: the key passphrase, not the login password
Va4kSjgTHSd55ZLv     # <- typed as if it were a command, right after `sudo su`
```

The password was typed as a command and persisted. `sudo` with it:

```
maki_adm@barrier:~$ echo 'Va4kSjgTHSd55ZLv' | sudo -S id
uid=0(root) gid=0(root) groups=0(root)
root@barrier:~# cat /root/root.txt
<root flag redacted>
```

## Leads that didn't pan out

- **Tomcat CVE-2025-24813** (partial-PUT RCE) — the default servlet is read-only
  (`PUT → 405`); the precondition is absent.
- **authentik forward-auth bypass CVEs** — no proxy provider exists;
  `/outpost.goauthentik.io/auth/*` all 404.
- **Changing satoru's username to `guacadmin`** — self-service blocks username
  edits, and Guacamole keys on the SAML username, so this was the wrong lever
  anyway. Resetting a *different* user's password was the right one.
- **GitLab-admin → CI-runner RCE** — the runner is a non-privileged docker
  executor with no socket or host mount, and the airgapped box cannot pull the
  job image. Root came from what the admin could *read* (the authentik token),
  not from CI. The paused runner is a decoy.
- **The avatar oracle** — authentik's fabricated pending-user avatar leaks whether
  a username exists (a real user's initials differ from the two characters you
  typed). A tidy unauthenticated user-enumeration primitive, off the critical path
  once the git repo named `satoru`.

## What would have stopped this

Patching GitLab past **CVE-2024-45409** breaks the chain earliest. Without the
SAML signature-wrapping bypass, the repository-leaked `satoru` password stops at
an ordinary GitLab user and never reaches the admin CI variable that unlocks the
identity provider — and every step after that depends on the admin foothold. The
secondary lessons are ordinary hygiene: don't store an IdP superuser token as a
CI variable, don't return connection secrets (or leave them in a world-readable
DB config), and don't type a password as a shell command.
