# DarkZero — Hack The Box, Hard, Windows / AD

**TL;DR:** A two-forest AD box. Given `john.w`, you are only `guest` on DC01's
MSSQL — but a linked server maps you to a `sysadmin` login in a *second forest*
(`darkzero.ext`), so `xp_cmdshell` on DC02 gives code execution as the SQL
service account. That token has `SeImpersonate` stripped, but the account's
service-logon token still holds it and is recoverable via a named pipe, so a
potato takes DC02 to SYSTEM. The forest trust has TGT delegation enabled and
DC02 is unconstrained, so coercing DC01 to authenticate to DC02 leaks DC01's
TGT — DCSync then pass-the-hash gives Domain Admin on the main forest.

*Machine status: retired. Flag values are redacted here; the local copy keeps
them as evidence.*

## Reconnaissance

An AD domain controller for `darkzero.htb`: the usual 53/88/135/139/389/445/636/3268/3269/5985/9389,
plus two things that stand out — **1433 (MSSQL 2022)** and TLS certs / MSSQL NTLM info naming
`DC01.darkzero.htb`. The supplied creds validate on SMB, LDAP and MSSQL, but **not** WinRM.

    nxc smb 10.129.x.x -u john.w -p '<given-password>'      # valid
    nxc winrm 10.129.x.x -u john.w -p '<given-password>'    # denied

## Foothold: linked-server hop into a second forest

On DC01's SQL, `john.w` maps to the database `guest` — no `xp_cmdshell`. But `master..sysservers` lists a
**linked server `DC02.darkzero.ext`** (note the different DNS suffix — a *second forest*). Executing
through it runs as `dc01_sql_svc`, which is **sysadmin** there:

    EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [DC02.darkzero.ext]  -->  dc01_sql_svc, 1

Enable `xp_cmdshell` on DC02 through the link — four-part naming avoids nested-quote pain:

    EXEC [DC02.darkzero.ext].master.dbo.sp_configure 'show advanced options',1
    EXEC (N'RECONFIGURE') AT [DC02.darkzero.ext]
    EXEC [DC02.darkzero.ext].master.dbo.sp_configure 'xp_cmdshell',1
    EXEC (N'RECONFIGURE') AT [DC02.darkzero.ext]
    EXEC (N'EXEC xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]   -->  darkzero-ext\svc_sql

Code execution as `darkzero-ext\svc_sql` on **DC02 (172.16.20.2)** — a DC of the second forest, reachable
only because DC01 is dual-homed and NATs the internal `172.16.20.0/24` outward.

## DC02 → SYSTEM: recovering a stripped SeImpersonate

`whoami /priv` under `xp_cmdshell` shows **no SeImpersonate** — deliberately stripped, so the obvious
"potato" is off the table. But that is a property of the *restricted* token `xp_cmdshell` hands you, not
of the account. SQL service accounts hold `SeImpersonatePrivilege` on their **service-logon** token, and
that token can be recovered: create a named pipe, connect to it over `\\localhost\pipe\…` (the SMB
redirector re-authenticates with the account's stored credentials), and impersonate the pipe client. The
recovered token carries the full privilege set — spawn a process with it and a standard SeImpersonate
abuse (e.g. GodPotato) yields **NT AUTHORITY\SYSTEM**, and `user.txt`.

*(Equivalent route: AD CS `User`-template enrollment → UnPAC-the-hash for `svc_sql` → reset its password
→ RunasCs with a **service** logon type (5), which likewise hands back a token that still has
SeImpersonate.)*

## DC01 → Domain Admin: cross-forest unconstrained delegation

Nothing local on DC02 leads to DC01. The path is in the **trust**: `darkzero.htb ↔ darkzero.ext` is a
bidirectional forest trust with **TGT delegation enabled** (`trustAttributes` carries
`0x800`), and DC02 is trusted for **unconstrained delegation**. So if DC01 ever authenticates to DC02,
DC01's own TGT is forwarded and cached on DC02, where — as SYSTEM — you can grab it.

Run `Rubeus monitor` on DC02, then make DC01 authenticate to DC02. The tidy trick is
`xp_dirtree \\DC02.darkzero.ext\C$` from DC01's SQL — but a plain incidental SMB touch can tear down too
fast to leave the forwarded ticket cached. A **coercion primitive** (MS-EFSRPC / MS-DFSNM, e.g.
`coerce_plus` with the listener pointed at `dc02.darkzero.ext`) produces a proper authentication whose
forwarded **`DC01$` TGT** lands and is captured:

    User : DC01$@DARKZERO.HTB    Flags : ... forwarded, forwardable

Convert the ticket, Pass-the-Ticket, and **DCSync** `darkzero.htb` for the Administrator hash (mind the
clock — a few seconds of skew needs `faketime`). Pass-the-Hash over WinRM lands a shell as
**darkzero.htb\Administrator** — Domain Admin of the main forest — and `root.txt`.

    impacket-secretsdump -k -no-pass darkzero.htb/'DC01$'@DC01.darkzero.htb -just-dc-user Administrator
    #  Administrator:500:aad3b435...:<administrator-nt-hash>:::
    nxc winrm 10.129.x.x -u Administrator -H <administrator-nt-hash>   -->  Pwn3d!

## Lessons

- A **linked server that maps a low-priv user to a sysadmin login in another forest** is a full
  cross-forest pivot hiding in plain sight — enumerate `sysservers` on every SQL foothold.
- "No SeImpersonate" in a service context often means *stripped*, not *absent* — the service-logon token
  can be recovered via a named pipe.
- When an unconstrained-delegation TGT capture "should" work but the monitor stays empty, swap the
  trigger from an incidental connector (a file touch) to a real **coercion** — the difference is whether
  the forwarded ticket persists long enough to be caught.
- **TGT delegation on a forest trust turns any cross-forest authentication into a takeover vector.** The
  single control that breaks the whole chain earliest is the linked server's login mapping to `sysadmin`.
