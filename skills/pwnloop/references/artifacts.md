# Analysing recovered artifacts

When a machine hands you a file rather than a shell, the file is the vector.
Treat every downloaded artifact as a credential store until proven otherwise.

## Packet captures (.pcap, .pcapng)

Cleartext protocols in a capture *are* credentials — FTP, Telnet, HTTP basic
auth, unencrypted SMTP/POP3/IMAP, SNMP community strings, LDAP simple binds.

```bash
pwnloop x "tshark -r cap.pcap -Y 'ftp || telnet || http.authorization' -T fields -e _ws.col.Info"
pwnloop x "tshark -r cap.pcap -z conv,tcp -q"          # who talked to whom
pwnloop x "tshark -r cap.pcap --export-objects http,/engagements/$NAME/loot/http"
pwnloop x "tcpdump -r cap.pcap -A -nn | grep -iE 'USER |PASS |authorization|login'"
pwnloop x "strings cap.pcap | grep -iE 'pass|user|token' | head -40"
```
`tcpdump -A` is the fallback when tshark is unavailable — less precise, but it
reads application-layer bytes fine for text protocols.

Follow a single TCP stream once you know which one matters:
```bash
pwnloop x "tshark -r cap.pcap -q -z follow,tcp,ascii,0"
```

NTLM handshakes in a capture are crackable — extract the challenge/response and
feed it to `john` or `hashcat` in netntlmv2 format.

## Archives and backups

```bash
pwnloop x "7z l backup.zip"                       # list before extracting
pwnloop x "zip2john backup.zip > zip.hash && john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash"
pwnloop x "binwalk -e firmware.bin"
```
Backups of a web root almost always contain the config file with database
credentials that the live site hides.

## Git repositories

An exposed `.git/` directory is a full source disclosure:
```bash
pwnloop x "git clone http://target/.git /engagements/$NAME/loot/src 2>/dev/null || wget -r http://target/.git/"
pwnloop x "cd /engagements/$NAME/loot/src && git log --all --oneline && git diff HEAD~5"
```
Look at deleted content specifically — secrets are usually committed, noticed,
and removed in a later commit that leaves them in history.

## Password databases and key material

```bash
pwnloop x "keepass2john db.kdbx > kdbx.hash && john --wordlist=/usr/share/wordlists/rockyou.txt kdbx.hash"
pwnloop x "ssh2john id_rsa > key.hash && john --wordlist=/usr/share/wordlists/rockyou.txt key.hash"
```

## Documents and images

```bash
pwnloop x "exiftool file.pdf"                     # author names seed username lists
pwnloop x "steghide extract -sf image.jpg"        # empty passphrase is worth trying first
pwnloop x "strings -n 8 file.bin | grep -iE 'pass|key|flag'"
```

## Databases

```bash
pwnloop x "sqlite3 app.db '.tables' ; sqlite3 app.db 'select * from users;'"
pwnloop x "strings dump.sql | grep -iE 'insert into users|password'"
```
Hashes go to `john` with the right format; identify first with `hashid`.

## The habit

After extracting anything, sweep the whole loot directory rather than the one
file you were focused on:

```bash
pwnloop x "grep -ariE 'password|passwd|secret|api[_-]?key|BEGIN .*PRIVATE KEY' /engagements/$NAME/loot | grep -v Binary | head -50"
```
Then try every credential you find against every service and every user. Reuse
resolves more lab machines than any single exploit.
