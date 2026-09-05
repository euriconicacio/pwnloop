# Expressway — Hack The Box, Easy, Linux

**TL;DR:** One TCP port, and the path is on UDP: an ISAKMP responder that agrees
to IKEv1 Aggressive Mode publishes a valid username and a crackable PSK hash to
anyone who asks. The PSK is reused as that user's SSH password. Root is a
hand-compiled `sudo` 1.9.17 dropped into `/usr/local/bin`, ahead of the held,
patched distribution package on `PATH` — vulnerable to both CVE-2025-32463
(`--chroot` runs before authorization, so your `nsswitch.conf` gets `dlopen`ed)
and CVE-2025-32462 (`--host` is honoured for command execution, not just `-l`).

*Flags redacted. Machine address generalised to `10.129.x.x`.*

---

## The shape of the problem

The scan came back almost empty, and that emptiness was the whole hint.

```
$ nmap -sS -p- --min-rate 3000 10.129.x.x
PORT   STATE SERVICE
22/tcp open  ssh
```

One port. Out of sixty-five thousand five hundred and thirty-five, exactly one
was open, and it was SSH — the one service that is never the way in on its own.
OpenSSH 10.0p2 on Debian forky, current to the week, with no username and no
password to try against it.

A TCP scan that returns a single hardened port is not a dead end; it is an
instruction. It says the path is not on TCP. So the UDP sweep, which is usually
the thing you kick off in the background and forget about, became the primary
lead:

```
$ nmap -sU --top-ports 100 10.129.x.x
PORT      STATE  SERVICE
500/udp   open   isakmp
```

ISAKMP. An IPsec VPN endpoint. There is a note in this loop's cross-engagement
memory that reads *"on a locked-down host, the one non-standard port is the
path — rank leads by how out of place the service is, not by how familiar the
protocol is."* A machine that closes 65,534 TCP ports and then leaves an IKE
responder listening on UDP is not being careless. That is the door.

---

## Phase 1: asking the VPN a question it should have refused to answer

IKEv1 has two ways to establish Phase 1. **Main Mode** takes six messages and is
careful: the identities and the authentication payload are exchanged only after
a Diffie-Hellman key has been established, so they travel encrypted. **Aggressive
Mode** does the same job in three messages, and it buys that speed by sending the
responder's nonce, DH public value, identity, and a hash derived from the
pre-shared key all in the *first reply* — before the initiator has proven a
single thing.

The consequence is that if a server will speak Aggressive Mode, anyone who can
reach it can request an offline-crackable hash of its PSK. Anonymously. Repeatedly.

So the first question to ask an ISAKMP responder is simply *which mode will you
agree to?*

```
$ ike-scan -M -A 10.129.x.x
10.129.x.x   Aggressive Mode Handshake returned
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        Hash(20 bytes)
```

It agreed. And it over-answered.

That `ID` line is worth pausing on, because it is doing more damage than the
hash is. Before authenticating anything, the server volunteered the site's
internal hostname (`expressway.htb`) **and a valid username** (`ike`). Two of the
three things you need to log into the box, disclosed by the handshake itself, to
an anonymous stranger.

The `Hash(20 bytes)` is the third. `ike-scan` will write it out in a crackable
form:

```
$ ike-scan -M -A --pskcrack=ike-psk.txt 10.129.x.x
$ psk-crack -d /usr/share/wordlists/rockyou.txt ike-psk.txt
key "freakingrockstarontheroad" matches SHA1 hash 15aacafeb7f835928d549b989c5bd524398e300d
Ending psk-crack: 8045040 iterations in 3.063 seconds
```

Three seconds. Eight million candidates, and the answer was a rockyou entry.

The `3des-sha-modp1024` proposal deserves a mention here even though it did not
need to be attacked: 3DES, SHA-1, and a 1024-bit MODP group are all obsolete, and
the last of those is the exact shape of primitive that precomputation attacks
against standard primes target. It did not matter, because the PSK fell to a
dictionary in the time it takes to read this sentence. But a strong PSK behind
that proposal would have been a much smaller comfort than it looks.

---

## Phase 2: the reuse

At this point I had a VPN pre-shared key and a username the server had handed
over unprompted. The honest next move is not to build an IPsec tunnel — it is to
try the secret where it does not belong.

This loop's memory is blunt about it: *"try every recovered credential against
every service and every user; reuse has resolved more machines here than any
single exploit."* And there is a companion note warning that a secret's field
name is a hypothesis, not a fact — a value labelled "PSK" is still just a string
somebody chose, and people choose the same string twice.

```
$ sshpass -p 'freakingrockstarontheroad' ssh ike@10.129.x.x id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

The VPN's pre-shared key was the `ike` user's login password. `user.txt` was
readable immediately.

That is the foothold, and it is worth being clear about what actually happened,
because it is easy to file this under "cracked a password". The password was
never guessed against SSH. `fail2ban` is installed and running on this host and
would have throttled that. The password was *published* by a VPN handshake to an
unauthenticated stranger, and SSH simply accepted it. No control on the SSH side
was bypassed, because none was engaged.

---

## Phase 3: two doors, one binary

Local enumeration as `ike` turned up something odd almost immediately:

```
$ find / -perm -4000 -type f 2>/dev/null
/usr/sbin/exim4
/usr/local/bin/sudo      <-- ?
/usr/bin/sudo
/usr/bin/passwd
...
```

Two `sudo` binaries. That is not a thing that happens by accident, and
`/usr/local/bin` comes first on the default Debian `PATH`, so it is the one that
actually runs.

```
$ /usr/local/bin/sudo -V | head -1
Sudo version 1.9.17
$ /usr/bin/sudo -V | head -1
Sudo version 1.9.13p3
$ dpkg -l sudo | tail -1
hi  sudo  1.9.13p3-1+deb12u1  amd64
```

Read that `hi` in the dpkg output. It means the package is **held** — someone
deliberately pinned the distribution's sudo so it would not move. The packaged
copy is patched and managed and frozen exactly where the admin wanted it. And
then a hand-compiled 1.9.17 was dropped in front of it on the search path, where
`apt` will never look and no patch cycle will ever touch it.

This is the finding, and it is worth more than the exploit that follows. The
patch management here was not neglected. It was done, and then routed around.

Sudo 1.9.17 sits below 1.9.17p1, which is where both of 2025's sudo advisories
were fixed. Following this loop's own rule — *enumerate all the CVEs for a pinned
version, then rank by precondition rather than by CVSS* — there were two
candidates, and I checked what the binary would actually accept:

```
$ /usr/local/bin/sudo -h | grep -E "chroot|host"
  -h, --host=host               run command on host (if supported by plugin)
  -R, --chroot=directory        change the root directory before running command
```

Both options present. Both bugs plausible.

### Door one: CVE-2025-32463 — the chroot that runs too early

`sudo -R <dir>` chroots before it works out who you are. That ordering is the
entire bug. Once the process is inside your directory, glibc's Name Service
Switch — which sudo needs, because it has to resolve your user record — reads
`<dir>/etc/nsswitch.conf`. That file is now *yours*.

An NSS service entry names a shared library for glibc to `dlopen()`. Point it at
a library you compiled, and its ELF constructor runs while the process is still
SUID root and has not yet decided whether you are allowed to do anything at all.

The mechanism is why this bug is nastier than it first appears: **it needs no
sudoers entry**. A user with no sudo rights whatsoever — a user `sudo -l` would
flatly refuse — still reaches root, because the vulnerable code executes before
authorization is consulted.

The staged script (`www/chwoot.sh`) builds the chroot, compiles a constructor
that calls `setreuid(0,0)`, and invokes `sudo -R`. It reported back:

```
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

Root, on the first attempt.

There was one small stumble worth keeping, because it cost a round trip. My
constructor's first act was the reflex one: copy `bash` to `/tmp`, chown it root,
set the SUID bit. The file appeared, owned by root, mode `6755` — and running it
gave me back `uid=1001(ike)`.

```
$ mount | grep /tmp
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,...)
```

`nosuid`. The SUID bit was set and the kernel was ignoring it. This is a control
that actually worked, and it is a good reminder that the drop-a-SUID-shell habit
is a habit, not a plan. The fix was to stop trying to *carry* privilege out of
the constructor and instead spend it there: the second pass had the root
constructor do the privileged work in-process — back up `authorized_keys`, plant
a key, read the flag — which no mount option can interfere with.

```
root.txt: <redacted>
```

### Door two: CVE-2025-32462 — the host that is not this host

With root I could finally read `/etc/sudoers`, and it turned out the box had been
built around the *other* bug:

```
Host_Alias  SERVERS = expressway.htb, offramp.expressway.htb
Host_Alias  PROD    = expressway.htb
ike         SERVERS, !PROD = NOPASSWD:ALL
ike         offramp.expressway.htb = NOPASSWD:ALL
```

The intent is legible: `ike` gets everything on `offramp`, and nothing here.
`SERVERS, !PROD` is a careful subtraction. And sudo reports the policy exactly as
written:

```
$ sudo -l
Sorry, user ike may not run sudo on expressway.
```

That is about as convincing a dead end as a message can be. It names the user,
names the host, and refuses.

But CVE-2025-32462 is precisely that the vulnerable build honours `--host` for
ordinary command execution, not just for `-l`. Tell it you are somewhere else and
it evaluates the rules for somewhere else:

```
$ sudo -h offramp.expressway.htb id
uid=0(root) gid=0(root) groups=0(root)
```

One flag. No compiler, no shared library, no chroot — this is the cheaper door,
and given how deliberately that sudoers file was authored, it is the intended one.

---

## The lead that failed, and the one that misled

**Squid.** The `ike` account is in group `proxy`, gid 13, which is unusual enough
to chase first — a group membership is the filesystem telling you what an account
was *for*. `find / -group proxy` returned Squid's spool and logs and nothing else.
The logs were real but historical: a scan from July 2025, no credentials, no
sessions. Their one contribution was the string `offramp.expressway.htb`, a
second hostname that meant nothing at the time and turned out later to be the
exact name CVE-2025-32462 needed. Filed as `DEAD`; it was worth the two minutes.

**The Cisco config.** TFTP on 69/udp anonymously serves
`/srv/tftp/ciscortr.cfg`, a router configuration complete with `hostname
expressway`, `username ike password *****` and `enable password *****`. Every
password in it is redacted. It is set dressing — the in-world explanation for why
this machine terminates an IPsec tunnel at all, and a nudge toward the IKE
service. It reads like a credential file and contains no credentials.

**The near-miss.** The one thing I would do differently: I ran `sudo -n -l`,
which answered "a password is required", and moved on. I *had* the password. This
loop's memory already carries the rule — *check `sudo -l` with the real password,
not `-n`* — and I did not apply it until after I was root. It would not have
handed me the answer here (the real `sudo -l` output is the refusal quoted
above), but it would have surfaced the `-h`/host-alias shape hours earlier on a
box where that mattered. Memory read at the start is not memory applied at the
moment of acting.

---

## Why this box is worth teaching

Three links, and not one of them is a memory-corruption bug or a clever payload.

The **VPN** was configured for speed over secrecy, and Aggressive Mode obliged by
publishing an authentication hash and a valid username to anyone who asked. The
**password** was the same string twice, in two places that should never have
shared one — and that reuse is what converted a tunnel-level weakness into a
shell. The **escalation** happened on a host whose administrators were, by every
visible sign, doing patch management properly: the sudo package was tracked, held
and current. They were simply undone by a second copy of the same privileged
program sitting earlier on `PATH`, in `/usr/local`, where no package manager
looks.

That last one is the transferable lesson, and it is the one to take to your own
estate. `find /usr/local -perm -4000 -type f` is a one-line audit. On this host
it would have returned the whole root compromise — twice over, because the
shadowing binary carried two independent paths to root, and fixing either the
policy or the binary alone would have left the other wide open.
