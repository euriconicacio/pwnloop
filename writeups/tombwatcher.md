# TombWatcher — HTB Write-up

> Retired, Medium. Flags redacted. Domain: `tombwatcher.htb`, DC: `DC01` (Server 2019).
> Given a low-priv account `henry:H3nry_987TGV!`, the box is a pure Active Directory
> permission chain ending in an AD CS ESC15 abuse.

## Recon

`nmap` shows a domain controller — 53/88/135/139/389/445 — plus **80/http** (IIS
default page, a decoy). The SMB/LDAP banners give the domain `tombwatcher.htb` and host
`DC01`. The clock is ~4 h ahead of the VPN, so every Kerberos step runs under `faketime`.

`henry`'s creds validate on SMB and LDAP. SYSVOL/NETLOGON are readable but hold nothing.
Four real accounts exist: `henry`, `alfred`, `sam`, `john`. A small estate with valid
creds screams "DACL chain" — so collect BloodHound.

## The DACL chain

BloodHound (parsed straight from the JSON) draws a clean line:

```
henry  --WriteSPN-->        Alfred
Alfred --AddSelf-->         Infrastructure (group)
Infra  --ReadGMSAPassword-> ansible_dev$   (gMSA)
ansible_dev$ --ForceChangePassword--> sam
sam    --WriteOwner-->       john
john   --GenericAll-->       OU=ADCS
```

**1 — henry → Alfred (targeted Kerberoast).** henry can write Alfred's SPN, so set a
throwaway SPN with `bloodyAD`, request the TGS with `GetUserSPNs`, strip the SPN again,
and crack: `Alfred:basketball` (rockyou, hashcat `-m 13100`).

**2 — Alfred → Infrastructure.** `bloodyAD add groupMember Infrastructure alfred`.

**3 — Infrastructure → ansible_dev$.** Membership grants the gMSA read; `nxc ldap --gmsa`
returns `ansible_dev$`'s NT hash.

**4 — ansible_dev$ → sam.** Pass-the-hash as the gMSA and `set password sam`.

**5 — sam → john.** `WriteOwner` → set sam as owner of john, grant sam `GenericAll`, reset
john's password. john can WinRM (`Pwn3d!`) → **user.txt**.

## The tomb: AD Recycle Bin + AD CS

john's `GenericAll` is over **`OU=ADCS`** — which is *empty*. The box name is the hint:
the AD **Recycle Bin** holds three deleted `cert_admin` users, all with
`lastKnownParent: OU=ADCS`. Control of the OU means control (by inheritance) of anything
restored into it.

List tombstones with the show-deleted LDAP control:

```
ldapsearch ... -b 'CN=Deleted Objects,DC=tombwatcher,DC=htb' \
  -E '!1.2.840.113556.1.4.417' '(sAMAccountName=cert_admin)' objectSid
```

Only one of the three — SID `…-1111` — is the one that matters, because the **WebServer**
certificate template's `Enroll` ACE names exactly that SID. Restoring the wrong one first
(SID …-1109) is a dead end; `Restore-ADObject -Identity <GUID of the …-1111 one>` (after
re-deleting the wrong restore, since the sAMAccountName collides) brings back the right
account. Reset its password via john's inherited `GenericAll`.

## ESC15 (EKUwu, CVE-2024-49019)

`certipy find` flags nothing as "vulnerable", but the WebServer template is
**Schema Version 1** with **Enrollee Supplies Subject** and no manager approval — the
EKUwu condition. A v1 template lets the requester inject an arbitrary *application policy*:

```
certipy req -u cert_admin -p ... -ca tombwatcher-CA-1 -template WebServer \
  -upn administrator@tombwatcher.htb -sid <admin SID> \
  -application-policies 'Client Authentication'
```

PKINIT with the resulting cert fails ("not valid for client authentication") because the
template's baseline EKU is Server Authentication. The ESC15 trick is to authenticate over
**LDAP/Schannel** instead, which trusts the injected application policy:

```
certipy auth -pfx administrator.pfx -dc-ip <dc> -ldap-shell
# as TOMBWATCHER\Administrator:
add_user_to_group cert_admin "Domain Admins"
```

A fresh logon as `cert_admin` (tokens are fixed at logon) is now Domain Admin → read
**root.txt** and DCSync the `Administrator` NT hash.

## Leads that failed / time sinks

- **`certipy -vulnerable` returned nothing** for both john and cert_admin. The ESC15 class
  isn't flagged by certipy's conservative filter; it had to be read off the raw template
  JSON (Schema v1 + EnrolleeSuppliesSubject). Don't trust the `-vulnerable` summary alone.
- **Restoring the first tombstone (SID …-1109)** was wasted — the enroll ACE is pinned to
  a specific SID. Decode every tombstone's `objectSid` before choosing which to reanimate.
- **PKINIT on the ESC15 cert** is a dead end by design; the Schannel LDAP route is the
  intended one.

## One-line takeaway

Permission delegation, not patch level, owned this domain: a `WriteSPN` ACE opened it and
an EKUwu (CVE-2024-49019) certificate template closed it. Breaking either single link
stops the whole chain.
