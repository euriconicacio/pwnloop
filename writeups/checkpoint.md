# Checkpoint — walkthrough

> Hack The Box · Active Directory · Windows Server 2025 DC
> Rooted from the assumed-breach credential `alex.turner : Checkpoint2024!`.

## Recon

The host is a lone domain controller — `DC01.checkpoint.htb`, Server 2025
(Build 26100). SMB, LDAP, Kerberos and WinRM are the live surface. LDAPS (636)
resets mid-handshake (no AD CS / no LDAPS cert), so every AD read and write in
this run went over **signed LDAP (389) via bloodyAD**; `bloodhound-python`,
`certipy` and `ldapsearch` all died on the broken 636 TLS. The DC clock runs
~7 h ahead of the attack host, so every Kerberos step is wrapped in `faketime`.

## Foothold path — alex.turner → mark.davies → ryan.brooks

**ACL enumeration** as `alex.turner` (IT-Staff) shows two interesting rights:
a **Reanimate-Tombstones** extended right on `OU=Employees`, and WRITE over a
*deleted* object, `mark.davies`, sitting in the AD Recycle Bin.

Restoring the tombstone brings `mark.davies` back as a live account:

```
bloodyAD ... set restore mark.davies
```

The account comes back but its password is unknown. The win is **password
reuse**: `mark.davies` also authenticates with `Checkpoint2024!`. (A targeted
Kerberoast via the held GenericWrite — set an SPN, force an RC4 ticket, crack a
themed `Checkpoint*` base — reaches the same place, but the reuse is the shortcut.)

`mark.davies` can **write to the `DevDrop` share**. On the box, a scheduled task
runs `C:\Scripts\vscodesync.ps1` as **`ryan.brooks`**, which installs any `.vsix`
it finds in `DevDrop` and launches VS Code. A VS Code extension whose
`extension.js` runs a command on `activate`/startup is therefore code execution
as whoever that task runs as. Dropping a minimal malicious `.vsix` (payload kept
in a file, never echoed to screen) and waiting for the task yields a shell as
**`ryan.brooks`**.

```
user.txt — <32-hex-flag>
```

## Privilege escalation — dMSA abuse → svc_deploy → memory dump → Administrator

`ryan.brooks` holds **GenericWrite on `svc_deploy`** and **CreateChild on
`OU=DMSAHolder`**. `svc_deploy` is in `BackupAccess` and `Remote Management
Users`. The modern primitive here is **dMSA migration abuse** (the
BadSuccessor / "BetterSuccessor" family, CVE-2025-53779): a *delegated* Managed
Service Account can be told it is the migrated successor of a victim account, and
a dMSA logon then yields a ticket carrying the victim's PAC.

Shadow-credential / PKINIT routes were tried first and are **dead on this box** —
there is no CA, so `KDC_ERR_PADATA_TYPE_NOSUPP` / `CLIENT_NOT_TRUSTED`. The dMSA
route works instead:

1. Create a dMSA under `OU=DMSAHolder` with, set *at creation time*,
   `msDS-DelegatedMSAState=2`, `msDS-ManagedAccountPrecededByLink = svc_deploy`,
   and a `msDS-GroupMSAMembership` SD granting `ryan.brooks` retrieval.
2. On the victim, set `msDS-SupersededManagedAccountLink` → the dMSA and
   `msDS-SupersededServiceAccountState = 1` (the bidirectional pairing).
3. `Rubeus asktgs /dmsa` (a build that supports `/dmsa`) → a TGT for the dMSA
   that inherits **`svc_deploy`**'s identity.

With that ticket, `\\dc01\VMBackups` is readable. It contains a nightly backup
folder with a **VMware memory snapshot** of a Server 2019 host —
`*.vmem` (2 GB RAM image) plus the `*.vmsn` snapshot metadata.

Pulling 2 GB over a saturated VPN with a dMSA ticket that lives only ~15 minutes
is its own small battle: `impacket`'s `get` can't resume, so the transfer is done
with a **read-only, offset-append** reader that continues from the current local
size, re-minting the short Kerberos ticket between windows. The `.vmsn` sidecar
matters — Volatility can't build a translation layer from the `.vmem` alone.

Volatility 3 `windows.registry.hashdump` on the reconstructed image (the crypto
plugins need `pycryptodomex`) yields the backup host's local accounts:

```
Administrator : <administrator-nt-hash>
```

The last misconfiguration is **credential reuse**: that local-Administrator NT
hash authenticates as the **domain Administrator**.

```
nxc winrm dc01.checkpoint.htb -u Administrator -H <administrator-nt-hash>
→ Pwn3d!
root.txt — <32-hex-flag>
```

## Takeaways

- A tombstone you can restore + write is a live account you control.
- Any user-writable location that feeds an automatic installer is a code-exec sink.
- dMSA "migration" is a first-class privesc primitive now — audit creation rights
  and the preceded-by / superseded attributes.
- A memory image is every live secret on that host; a domain-readable backup
  share holding one is game over, especially when local and domain admin share a
  password.
