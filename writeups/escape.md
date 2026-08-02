# Escape — Hack The Box, Medium, Windows / AD

**TL;DR:** An unauthenticated SMB share holds an onboarding PDF that hands out a
database login. That login is `guest` in `master` with nothing to read — but it
can still make the SQL Server service account authenticate to a UNC path you
choose, which yields a crackable NetNTLMv2. The service account has WinRM on the
domain controller, and a backup SQL error log on disk contains a password
somebody typed into the username field. That user's token shows AD CS is
reachable, the certificate template is ESC1, and one certificate request later
you are the domain Administrator.

*Flags redacted. Machine addresses generalised to `10.129.x.x`, attacker VPN
address to `10.10.14.x`, and the recovered Administrator NT hash generalised —
those are properties of my engagement, not of the machine. Service versions,
hostnames and the credentials planted by the box author are kept, because they
appear in every public write-up of it.*

**Disclosure.** I had prior knowledge of a published path for this box. I did
not know that at the moment I was handed the IP — I was given an address and
nothing else — and recognition arrived at the LDAP certificate, which put the
domain name `sequel.htb` on screen alongside an MSSQL banner. From that point my
search order may have been informed by recall. I have flagged the one place
below where I think it actually was. Everything else fell out of enumeration in
the order enumeration produced it, and no write-up was opened.

---

## What the ports said

Thirteen TCP ports, and not one of them a web server. Kerberos, LDAP, SMB,
global catalog, WinRM, and — the one that does not belong — **1433/tcp, SQL
Server 2019**.

```
53,88,135,139,389,445,464,593,636,1433,3268,3269,5985 (+9389 ADWS)
```

The LDAP certificate named the domain (`sequel.htb`, `dc.sequel.htb`), so the
box identified itself before I had authenticated to anything. A domain
controller that is also a database server is already a finding — DCs are not
supposed to host applications, because everything the application does runs next
to the domain's secrets. That single anomaly framed the whole engagement, and it
turned out to be the intended route.

## Anonymous SMB, and a document that should not exist

A null session was refused for user enumeration (`enumdomusers` →
`ACCESS_DENIED`) but permitted for share listing, which is a common and awkward
middle ground. Among the default shares was one that was not default:

```
Public          Disk
```

It held a single file, `SQL Server Procedures.pdf`. `pdftotext` was not in the
container image, so the first extraction attempt produced raw PDF drawing
operators with the text encoded as CID glyph codes — readable, with the right
offset, but not worth decoding by hand when `apt-get install poppler-utils`
takes forty seconds. (The package has since been added to the image.)

The document is an onboarding guide. It complains, by name, that Ryan put a mock
SQL instance on the DC and Tom will remove it when he is back from vacation. It
names Brandon as the contact for problems. And at the bottom, under a heading
literally called **Bonus**, it hands out a database login for new hires whose
accounts are not ready yet:

> user `PublicUser` and password `GuestUserCantWrite1`

Three usernames and a working credential, from an unauthenticated share. This is
the entire foothold, and it required no exploit.

## `guest` in `master`, which is not nothing

The credential worked, and it was worth almost exactly what the document
implied:

```
SQL (PublicUser  guest@master)>
```

Instance `DC\SQLMOCK`. No sysadmin, no user databases — only `master`, `tempdb`,
`model`, `msdb`. There was nothing to read. Which is the point at which a
database that holds no data is still dangerous, because a database server is not
only a place data lives, it is a process running as an account.

`xp_dirtree` is an extended stored procedure that lists a directory. It is
executable by `public` by default, and if you hand it a UNC path it will happily
make the *service account* authenticate to whatever host you named. That is a
credential disclosure primitive available to the lowest privilege the server can
grant.

**Recall check.** Reaching for `xp_dirtree` here is where prior knowledge could
have carried me. I think it is defensible as deduction — the observation "guest
principal, no data, but a service account behind it" leads to "what can this
principal make the service account do", and coercion is the standard answer —
but I would be overstating my process if I claimed the idea arrived purely from
the artifact.

## The capture that worked but did not log

This was the messy part of the run, and it is worth writing down honestly
because it cost more time than the entire rest of the engagement.

`responder` failed to start. `impacket-smbserver` started fine and listened on
445, but logged nothing at all when the DC connected. Two restarts later, still
nothing. It would have been easy to conclude the coercion was not working and go
looking for another lead.

Instead I put a packet capture on `tun0` and triggered again:

```
10.129.x.x.49569 > 10.10.14.x.445: Flags [S]     ← the DC dialled out
...
10.129.x.x.49569 > 10.10.14.x.445: length 553    ← NTLMSSP_AUTH
10.129.x.x.49569 > 10.10.14.x.445: Flags [R]     ← and reset
```

The coercion had worked on the *first* attempt. The tool was simply not printing
the hash. A 553-byte session-setup packet is an `NTLMSSP_AUTH` message, and
everything needed to reconstruct the NetNTLMv2 is inside the capture — so I
stopped fighting the tool and read the wire instead:

```bash
tshark -r coerce2.pcap -Y ntlmssp -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmserverchallenge -e ntlmssp.auth.ntresponse
```

```
sql_svc   sequel   (challenge aaaaaaaaaaaaaaaa)   <NetNTLMv2 response>
```

Reassembled as `user::domain:challenge:proof:blob` and fed to john, it fell to
`rockyou.txt` in two seconds. The password is a name and a number in the way
that service account passwords set by a human always are.

Two lessons, one about the box and one about me. About the box: the service
account password was guessable, which is what made the coercion matter. About
me: I spent several minutes assuming a silent tool meant a failed attack. The
packet capture is ground truth and it should have been the *second* thing I
tried, not the fifth. That rule is now in the methodology.

Coerced callbacks are also negative-cached by the target — vary the UNC path on
each retry (`\\ip\pwn01`, `\\ip\pwn02`) or you will conclude the primitive
stopped working when only the cache spoke.

## A shell, and a log file with a password in it

`sql_svc` was not just a database identity — it had WinRM logon rights on the
domain controller. A service account with an interactive shell on a DC is its
own finding, and it is what made the next step visible at all.

`C:\` had a non-standard `SQLServer` directory. Most of it was installer media,
but alongside it:

```
C:\SQLServer\Logs\ERRORLOG.BAK   27608 bytes
```

SQL Server writes failed logon attempts to its error log, and it writes the
*username that was supplied*, verbatim. Two consecutive lines:

```
Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match...
Logon failed for user 'NuclearMosquito3'.        Reason: Password did not match...
```

Someone typed their password into the username box, hit enter, and the server
wrote it to disk in cleartext. It is a beautiful bug because nothing is
misconfigured — SQL Server is doing exactly what it is documented to do, and the
human error is the kind everyone has made. The file being readable by the
service account is the only actual mistake.

`Ryan.Cooper` / `NuclearMosquito3` authenticated over SMB and WinRM. `user.txt`
was on his desktop.

## The line in `whoami /all` that mattered

Ryan's group list contained something the previous user's did not:

```
BUILTIN\Certificate Service DCOM Access
```

That group exists on a machine running Active Directory Certificate Services.
This is the artifact that motivated the next command, and it is the honest
answer to "why did you run Certipy here" — not because AD CS is fashionable, but
because a group membership said the enrolment service was reachable.

```
Template Name : UserAuthentication
Enrollee Supplies Subject : True
Extended Key Usage        : Client Authentication, Secure Email, EFS
Requires Manager Approval : False
Enrollment Rights         : SEQUEL.HTB\Domain Users
[!] ESC1
```

**ESC1**, textbook. Any domain user can request a certificate, the requester
chooses whose identity goes in it, the certificate is valid for logon, and
nobody has to approve it. So you ask for a certificate that says you are the
domain Administrator, and the CA signs it:

```bash
certipy-ad req -u Ryan.Cooper@sequel.htb -p NuclearMosquito3 \
  -ca sequel-DC-CA -template UserAuthentication \
  -upn administrator@sequel.htb
```

```
[*] Request ID is 13
[*] Got certificate with UPN 'administrator@sequel.htb'
```

## Eight hours in the wrong direction

Authenticating with it failed:

```
KRB_AP_ERR_SKEW (Clock skew too great)
```

Nmap had told me about this an hour earlier and I had read past it: the DC's
clock is 7 h 59 m 55 s ahead of the container's. Kerberos rejects tickets
outside a five-minute window, and PKINIT is Kerberos.

`ntpdate` measured the offset precisely and then refused to apply it —
`step_systime: Operation not permitted`, because the container has no
`CAP_SYS_TIME` and, being a container, shares the host kernel's clock anyway.
Changing it would have meant changing the macOS host's clock, which is a
disproportionate thing to do to your laptop.

`faketime` solves this properly: it shims the time syscalls for one process
only.

```bash
faketime "$(date -u -d '+7 hours 59 minutes 55 seconds' '+%F %T')" \
  certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.x.x
```

```
[*] Got TGT
[*] Got hash for 'administrator@sequel.htb': <NT hash redacted>
```

The right fix, applied to the smallest possible scope. `faketime` is now in the
image.

## Root

Pass-the-hash over WinRM:

```
sequel\administrator
```

`root.txt` on the desktop. About eighteen minutes from the first packet.

---

## What did not work, and the near-misses

- **Anonymous RPC user enumeration** was denied outright, so the usual
  `rpcclient enumdomusers` opener produced nothing. The usernames came from a
  PDF instead. Worth remembering that a document can beat a protocol.
- **SMB with `PublicUser`** succeeded but only as `Guest` — a fallback, not a
  domain account. It is easy to misread that as lateral movement; the `(Guest)`
  annotation is the tell.
- **The whole `smbserver` detour.** Three restarts of a tool that was working
  correctly the entire time. One of the restarts killed itself, because
  `pkill -f smbserver.py` matched the shell whose own command line contained the
  string `smbserver.py`. That is a genuinely funny way to lose a listener and I
  will not do it again.
- **The near-miss worth logging.** Nothing in ordinary enumeration would have
  told me to read `ERRORLOG.BAK`. I found it by listing `C:\` and noticing a
  directory that did not belong, then listing that directory for log files. If I
  had gone straight to a privilege-escalation script I would have missed it
  entirely — WinPEAS does not flag "a backup SQL error log contains a password",
  because nothing about the file is misconfigured. The general version of this,
  now in the methodology: after any foothold, list the root of the system drive
  and read anything that is not a stock Windows directory.

## Defensive takeaway

The chain is four mistakes, none of them a vulnerability with a CVE number:

1. A convenience credential in a document nobody meant to publish.
2. A database instance on a domain controller that everyone agreed should be
   removed, and which nobody removed.
3. A password typed into the wrong box, persisted forever by correct logging.
4. A certificate template someone made permissive so that enrolment would stop
   generating helpdesk tickets.

The first three are ordinary human untidiness and will recur no matter how many
times they are cleaned up. The fourth is the one that matters, because it is
what turns any of the first three into a domain takeover rather than a nuisance.
Fix the template — enrollee-supplies-subject off, or manager approval on — and
every other mistake here costs you a shell instead of the domain.

One operational note for defenders: an ESC1 certificate **outlives the
password**. It stays valid for its full lifetime, often ten years, through
password resets. Revoking the issued certificate is part of the remediation, not
an afterthought.

That asymmetry — the messy findings get you a shell, the quietly-widened
privilege boundary gets you everything — has now held on every engagement in
this programme, which is starting to look less like a coincidence and more like
the shape of the problem.
