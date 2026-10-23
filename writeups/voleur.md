# Voleur — Hack The Box, Medium, Windows

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

A Kerberos-only Windows DC, handed to you assumed-breach with one weak domain
user. The spine of the box is a chain of **delegated-rights-as-a-primitive**
(recycle bin, WriteSPN) leading into **DPAPI** and finally a **world-readable AD
backup** that collapses the whole domain — with a WSL (Linux-on-Windows) twist
in the middle.

## Recon

`ryan.naylor / HollowOct31Nyt`. SMB enumeration says: domain `voleur.htb`, host
`DC`, signing required, and critically **NTLM disabled** — everything is
Kerberos, so `-k`, a ccache, and clock sync (the DC ran +8h; drive tooling under
`faketime -f +8h`). A full port scan also finds **2222/tcp = Linux OpenSSH**, a
WSL instance. Park that; it pays off at the end.

## Access Review → the service-account set

The `IT` share is readable. In `First-Line Support/` sits
`Access_Review.xlsx`, Office-encrypted. `office2john` + rockyou →
`football1`. Decrypted, it is a service-account credential table. Validating
each over Kerberos (`getTGT`): `svc_ldap` and `svc_iis` are live. (Mind the
`sharedStrings` ordering when you parse the sheet XML by hand — the column
mapping is not row-order.)

## Recycle bin + WriteSPN → svc_winrm → user

BloodHound from the owned accounts shows two edges on `svc_ldap`:
- membership of `RESTORE_USERS` (AD Recycle Bin), and
- `WriteSPN` over `svc_winrm`.

The spreadsheet also lists `todd.wolfe` as a *deleted leaver* with a known
password. Two independent paths open. The immediate one: set an SPN on
`svc_winrm` (ldap3 over GSSAPI), Kerberoast it, crack →
`AFireInside...afi`. `svc_winrm` is in Remote Management Users.

**WinRM-over-Kerberos tooling wall (worth the note):** evil-winrm's ruby GSSAPI
fails under faketime; `curl --negotiate` proves auth *works* (411, not 401); the
real gate is that the **WinRS/cmd endpoint is denied while the PSRP (PowerShell)
endpoint is allowed**. `pypsrp`'s `execute_ps` with `negotiate_service="HTTP"`
and CBT disabled gets the shell. `user.txt` is on svc_winrm's desktop.

## DPAPI → jeremy.combs

Take the second edge now. As `svc_ldap`, restore `todd.wolfe` from the recycle
bin (ldap3 + `show_deleted_control`, clear `isDeleted`, set the DN back). Todd's
archived roaming profile is in `IT\Second-Line Support\Archived Users\todd.wolfe`
and carries the DPAPI trove:

- masterkey `AppData\Roaming\Microsoft\Protect\<SID>\<guid>`
- credential `AppData\Roaming\Microsoft\Credentials\<id>`

All offline: `dpapi masterkey -sid <SID> -password <todd pw>` → the key →
`dpapi credential -key <key>` → `jeremy.combs / qT3V9pLXyN7W4m`
(the credential's Target field reads `Jezzas_Account`). No callbacks, no egress — pure crypto on files
you already pulled over SMB.

## Third-Line Support → WSL as svc_backup

`jeremy.combs` (Third-Line Technicians, RMU) reads `IT\Third-Line Support`:
an `id_rsa` and a note — *"I've had enough of Windows Backup! I've part
configured WSL to utilise backup tools from Linux."* The key logs into the
2222 WSL as **`svc_backup`**, who has `sudo NOPASSWD: ALL`. Linux root.

## World-readable ntds.dit → Domain Admin

WSL root is **not** Windows privilege: `/mnt/c` is DrvFs mapped to an
unprivileged identity, so Administrator's profile and `C:\Windows\NTDS` are
denied. But the backup the admin was fiddling with is sitting world-readable at
`C:\IT\Third-Line Support\Backups`:

```
Active Directory/ntds.dit
registry/SYSTEM
registry/SECURITY
```

That is an offline DCSync. `secretsdump -ntds ntds.dit -system SYSTEM LOCAL`
dumps every hash including `Administrator` (NTLM + AES). NTLM is disabled, so
pass-the-hash is dead — instead **overpass-the-hash**: `getTGT -aesKey <admin
aes256>` for a Kerberos TGT, then PSRP as `voleur\administrator`. `root.txt`.

## Dead ends / leads that didn't pay

- Shadow credentials on a GenericWrite target failed — **PKINIT unsupported**
  (no KDC cert), so the cert-to-TGT trick is off the table on this box.
- Restored-account PAC quirk: a *freshly* restored todd.wolfe returned 401 on
  WinRM where a stable account got through — don't read that as an authz fact.

## Lessons

- **Kerberos-only ≠ safer** once a plaintext `ntds.dit` backup is readable — the
  entire auth-hardening story is bypassed offline.
- **A primitive you can't trigger is a cue to re-enumerate**: the WinRM cmd
  endpoint being denied wasn't failure, it was pointing at PSRP.
- **WSL is an in-box Linux pivot** — treat its `/mnt/c` and `sudo` as part of the
  Windows attack surface, but remember DrvFs privilege ≠ Windows privilege.
