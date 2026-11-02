# PUPPY.HTB — write-up

> HTB **Medium**. Flags redacted.

A Windows AD box that is entirely a **credential-chaining** exercise: every hop
is "this principal can reach the next principal's secret." No memory-corruption,
no public CVE — just ACLs, a crackable KeePass DB, a backup, and DPAPI.

## Recon

From the address alone: a Windows Server 2022 **domain controller** (`PUPPY.HTB`)
with the usual AD ports plus two oddities — NFS (111/2049, no exports) and iSCSI
(3260), both dead ends here. The assumed-breach credential is `levi.james / KingofAkron2025!`.

SMB with the creds: a non-default share **`DEV`** ("DEV-SHARE for PUPPY-DEVS")
that levi can see but not read, and nine domain users.

## levi.james → DEVELOPERS (GenericWrite)

BloodHound over the creds shows levi is in **HR**, and **HR has `GenericWrite`
over the `DEVELOPERS` group**. `GenericWrite` on a group means control of its
membership, so add levi to `DEVELOPERS`:

```
bloodyAD ... add groupMember DEVELOPERS levi.james
```

Now the `DEV` share reads: a `recovery.kdbx` KeePass database and the KeePassXC
installer.

## Cracking the KeePass DB → ant.edwards

`recovery.kdbx` is KDBX4 (Argon2), so `keepass2john` refuses it ("version
40000"). Crack it directly with `pykeepass` over rockyou — master password is
**`liverpool`**. The DB holds five "Name → password" entries. Sprayed against the
domain, only one still authenticates: **`ant.edwards : Antman2025!`**.

*(Lead that failed: the other four KeePass passwords were stale — a reminder to
spray all of them against all users rather than trusting the title mapping.)*

## ant.edwards → adam.silver (GenericAll)

ant is in **SENIOR DEVS**, which has **`GenericAll` over `adam.silver`**.
adam.silver is **disabled** but is a member of **Remote Management Users**
(WinRM). `GenericAll` lets us both clear the `ACCOUNTDISABLE` flag and reset the
password — no original needed:

```
bloodyAD ... set password adam.silver '<new>'
bloodyAD ... remove uac adam.silver -f ACCOUNTDISABLE
```

WinRM as adam.silver → **user.txt**.

## adam.silver → steph.cooper (backup on disk)

As adam.silver, `C:\Backups\site-backup-2024-12-30.zip` contains
`nms-auth-config.xml.bak` — an LDAP auth config with a cleartext **bind
password**: `steph.cooper : ChefSteph2025!`. steph.cooper is also a WinRM user.

## steph.cooper → steph.cooper_adm (DPAPI)

steph.cooper's profile holds a Windows **Credential Manager** blob
(`AppData\Roaming\Microsoft\Credentials\...`) and the DPAPI masterkey under
`Protect\<SID>\`. Decrypt offline with steph.cooper's password:

```
impacket-dpapi masterkey -file <mk> -password 'ChefSteph2025!' -sid <SID>
impacket-dpapi credential -file <cred> -key 0x<decrypted-masterkey>
```

The stored credential is **`steph.cooper_adm : FivethChipOnItsWay2025!`**.

## steph.cooper_adm → root

`steph.cooper_adm` is in `BUILTIN\Administrators` on the DC. WinRM → **root.txt**.

## Why it falls
Five hops, each one an ACL or a stored secret pointing at the next identity. The
defensive lesson is credential hygiene: a KeePass DB and a backup config, both
reachable by low-privileged users, carried the whole chain; the ACL edges only
mattered because they led to stored passwords.
