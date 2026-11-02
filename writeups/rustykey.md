# RustyKey — HTB (Windows, Hard)

> Assumed-breach Active Directory box. You're given one low-privileged domain user (assumed-breach) and have to
> climb a deliberately-built ACL ladder to Domain Admin. The whole thing turns on a single weak
> machine-account password and a chain of "help-desk" delegations that each hand you the next rung.

## Recon

A single Windows DC, standard AD ports. Two facts set the rules of the game up front:

- **NTLM is disabled domain-wide** (`nxc` reports `NTLM:False`) — everything is Kerberos, so set up
  `krb5.conf` and deal with the ~8 h clock skew (`faketime` on each tool rather than touching the
  container clock, which has no `CAP_SYS_TIME`).
- **SMB signing required** — no NTLM relay.

Authenticate the provided `rr.parker` with `-k`, collect BloodHound (`bloodhound-python -k`), and read
the graph.

## The ACL ladder

- `nn.marcos` ∈ **HelpDesk**. HelpDesk can **ForceChangePassword** `ee.reed`, `dd.ali`,
  `gg.anderson`, `bb.morgan`, and **AddMember** on `Protected Objects`.
- **IT-COMPUTER3$** can **AddSelf** to HelpDesk.
- `mm.turner` ∈ **DelegationManager**, which has **AddAllowedToAct** over the DC (RBCD).
- IT + Support users are nested into **Protected Users** via `Protected Objects`.

`rr.parker` itself has nothing — `bloodyAD get writable` shows only itself and ADIDNS. So the ladder
has to be *entered* somewhere, and the entry isn't an ACL edge.

## Foothold: Timeroasting IT-COMPUTER3$

Compare the computer objects' `whenCreated` against `pwdLastSet`. `IT-Computer1$` and friends set
their password at creation (auto-generated, uncrackable). **`IT-Computer3$`** set its password ~6.5 h
*after* creation — i.e. a human typed it.

Timeroast abuses MS-SNTP: the DC signs time-sync replies with a MAC derived from a computer account's
password, and it'll do so for any RID with no authentication. `nxc smb -M timeroast` dumps the
authenticators; RID 1125 is `IT-Computer3$`. Crack it offline:

```
hashcat -m 31300 it3.hash rockyou.txt -O --username
```

It falls quickly. Confirm with `getTGT` + `nxc -k`.

## Climbing to user.txt (bb.morgan)

As `IT-COMPUTER3$`:

1. `bloodyAD add groupMember HelpDesk 'IT-COMPUTER3$'`.
2. **Re-request the TGT** — a Kerberos token is fixed at logon, so the HelpDesk SID only lands in a
   ticket issued *after* the add. (Skip this and the next step fails with insufficient-access.)
3. `set password bb.morgan` (ForceChangePassword).
4. `bb.morgan` is in **Protected Users**, so its TGT is refused for WinRM. HelpDesk can edit
   `Protected Objects`, so `remove groupMember 'Protected Objects' 'IT'` lifts the restriction.
5. `getTGT bb.morgan` → WinRM. `bb.morgan` has remote-management rights → **user.txt**.

Kerberos WinRM from Linux is finicky: `evil-winrm`'s GSSAPI and `faketime` don't get along. The
reliable route is `pypsrp` with `auth="kerberos", negotiate_service="HTTP", negotiate_send_cbt=False`.

## Privesc: 7-Zip shell-extension DLL hijack → mm.turner

`bb.morgan`'s desktop has `internal.pdf`: IT is rolling out a 7-Zip context-menu feature and the
Support team got temporary extended access to fix it. Translation: look at the 7-Zip shell extension.

The CLSID `{23170F69-40C1-278A-1000-000100020000}\InprocServer32` default value is the handler DLL,
and its ACL grants **RUSTYKEY\Support → FullControl**. Point it at your own DLL and whoever next fires
the context-menu action loads it.

Compromise a Support member (`ee.reed`) with the exact same HelpDesk chain. Catch: `ee.reed` has **no
remote-logon right** — you can reset it and get a TGT, but you can't log in with it. So run the
registry write *as* `ee.reed` from inside `bb.morgan`'s session with **RunasCs** (logon type 2; types
4/8 are denied). A simulated `mm.turner` fires the shell extension about once a minute; the DLL runs as
`mm.turner`.

Rather than catch an interactive shell, have the DLL do the one thing `mm.turner` is for in a single
shot (next section).

## Root: RBCD → backupadmin → DCSync

`mm.turner` ∈ **DelegationManager**, which can write RBCD on the DC. Have the hijack DLL run, as
`mm.turner`:

```
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
```

Now S4U2proxy as `IT-COMPUTER3$`, impersonating a privileged account that is **delegatable**. The
`Administrator` is `AccountNotDelegated:True`, but **`backupadmin`** isn't — and it's in
`Administrators`:

```
getST -k -no-pass -spn cifs/dc.rustykey.htb -impersonate backupadmin 'rustykey.htb/IT-COMPUTER3$'
```

That `cifs/dc` ticket reads **root.txt** over `C$` and runs a **DCSync** for the `Administrator` hash —
full domain compromise.

## Lessons

- A computer account's `pwdLastSet` drifting away from `whenCreated` is a neon sign for Timeroasting.
- Re-issue the ticket after every group/ACL change — the PAC is a snapshot.
- "Protected Users" is only as strong as the DACL on the group that nests into it.
- `InprocServer32` write = code execution in someone else's session; treat COM-registration ACLs as
  tier-0.
- When your target account can't log in remotely, run *as* it locally (RunasCs) instead of fighting
  the logon-type wall.

*Flags redacted.*
