# Analysing recovered artifacts

When a machine hands you a file rather than a shell, the file is the vector.
Treat every downloaded artifact as a credential store until proven otherwise.

## Packet captures (.pcap, .pcapng)

Cleartext protocols in a capture *are* credentials — FTP, Telnet, HTTP basic
auth, unencrypted SMTP/POP3/IMAP, SNMP community strings, LDAP simple binds.

```bash
htb x "tshark -r cap.pcap -Y 'ftp || telnet || http.authorization' -T fields -e _ws.col.Info"
htb x "tshark -r cap.pcap -z conv,tcp -q"          # who talked to whom
htb x "tshark -r cap.pcap --export-objects http,/engagements/$NAME/loot/http"
htb x "tcpdump -r cap.pcap -A -nn | grep -iE 'USER |PASS |authorization|login'"
htb x "strings cap.pcap | grep -iE 'pass|user|token' | head -40"
```
`tcpdump -A` is the fallback when tshark is unavailable — less precise, but it
reads application-layer bytes fine for text protocols.

Follow a single TCP stream once you know which one matters:
```bash
htb x "tshark -r cap.pcap -q -z follow,tcp,ascii,0"
```

NTLM handshakes in a capture are crackable — extract the challenge/response and
feed it to `john` or `hashcat` in netntlmv2 format.

## Archives and backups

```bash
htb x "7z l backup.zip"                       # list before extracting
htb x "zip2john backup.zip > zip.hash && john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash"
htb x "binwalk -e firmware.bin"
```
Backups of a web root almost always contain the config file with database
credentials that the live site hides.

## Git repositories

An exposed `.git/` directory is a full source disclosure:
```bash
htb x "git clone http://target/.git /engagements/$NAME/loot/src 2>/dev/null || wget -r http://target/.git/"
htb x "cd /engagements/$NAME/loot/src && git log --all --oneline && git diff HEAD~5"
```
Look at deleted content specifically — secrets are usually committed, noticed,
and removed in a later commit that leaves them in history.

## Password databases and key material

```bash
htb x "keepass2john db.kdbx > kdbx.hash && john --wordlist=/usr/share/wordlists/rockyou.txt kdbx.hash"
htb x "ssh2john id_rsa > key.hash && john --wordlist=/usr/share/wordlists/rockyou.txt key.hash"
```

## Documents and images

```bash
htb x "exiftool file.pdf"                     # author names seed username lists
htb x "steghide extract -sf image.jpg"        # empty passphrase is worth trying first
htb x "strings -n 8 file.bin | grep -iE 'pass|key|flag'"
```

## Databases

```bash
htb x "sqlite3 app.db '.tables' ; sqlite3 app.db 'select * from users;'"
htb x "strings dump.sql | grep -iE 'insert into users|password'"
```
Hashes go to `john` with the right format; identify first with `hashid`.

## The habit

After extracting anything, sweep the whole loot directory rather than the one
file you were focused on:

```bash
htb x "grep -ariE 'password|passwd|secret|api[_-]?key|BEGIN .*PRIVATE KEY' /engagements/$NAME/loot | grep -v Binary | head -50"
```
Then try every credential you find against every service and every user. Reuse
resolves more lab machines than any single exploit.
