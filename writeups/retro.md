# retro.vl — write-up

> Vulnlab AD box. A pre-created computer account and an ESC1 template turn a
> guessable trainee login into Domain Admin. Flags redacted.

## Recon

A full TCP/UDP sweep shows the classic domain-controller fingerprint: 53, 88, 135,
139, 389, 445, 464, 593, 636, 3268/3269, 3389, 9389 plus dynamic RPC. The LDAP/RDP
certificates name `DC.retro.vl`, domain `retro.vl`. SMB signing is required. Nothing
sits outside the AD service set, so the path is "in the directory", not on an odd port.

## Foothold: a share that explains itself

SMB allows guest. Guest can read the `Trainees` share, which holds a note:

> "…some of you seemed to struggle with remembering strong and unique passwords.
> So we decided to bundle every one of you up into one account."

A single shared account with a weak password. RID-brute (as guest) lists `trainee`,
`jburley`, `tblack`, and a computer account `BANKING$`. The obvious guess lands:
`trainee:trainee`.

As `trainee` the `Notes` share is readable → `user.txt`, plus a `ToDo.txt`:

> "…time to clean up the mess … We should start with the pre created computer
> account. That one is older than me."

That is a direct pointer at `BANKING$`.

## The pre-created computer account

A *pre-created* (pre-Windows-2000) computer account has its password initialised to the
lowercase account name — here `banking`. The account is a machine trust account, so a
normal SMB/LDAP simple bind is refused (`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` /
LDAP `data 710`) — which reads like a wrong password. A **Kerberos TGT request succeeds**,
which is the proof the password is correct. Lesson: for a machine account, use the TGT,
not a bind.

## ESC1: Domain Computers can enrol a Domain Admin cert

`certipy find -vulnerable` flags one template: `RetroClients` on CA `retro-DC-CA` —
`EnrolleeSuppliesSubject` + Client-Authentication EKU + no manager approval. The
`-vulnerable` filter printed "Domain Admins" as the enrollment right, but the **full**
listing shows the enrollable principals also include **Domain Computers**. `BANKING$`
is a Domain Computer, so it is a valid enrollee.

Two gotchas on the request: the template enforces a **4096-bit** minimum key
(`-key-size 4096`, otherwise `CERTSRV_E_KEY_LENGTH`), and the embedded SID extension must
carry the real domain SID + RID 500 (a guessed domain SID fails `certipy auth` with
"Object SID mismatch"). With both fixed, `BANKING$` enrols a certificate whose subject is
`administrator@retro.vl`.

## PKINIT is off → authenticate over Schannel

`certipy auth` on the cert fails with `KDC_ERR_PADATA_TYPE_NOSUPP`: the KDC has no PKINIT
(no KDC/smart-card-logon cert). That does **not** kill the cert — it still authenticates
over **LDAP-over-TLS (Schannel)**. `certipy auth -pfx … -ldap-shell` binds as
`RETRO\Administrator`.

From that Administrator LDAP session, add `trainee` to `Domain Admins`, then DCSync the
Administrator NT hash and pass-the-hash to read `root.txt`.

## Dead ends / notes

- RPC certificate enrolment (`certipy req`) over Kerberos timed out intermittently
  (`NETBIOS connection timed out`) — a retry loop handled it; it was transport flakiness,
  not an auth problem.
- Web enrolment endpoints were down (timeouts in `certipy find`), so the RPC/ICertPassage
  path was the only enrolment channel.

## The one fix

Harden the `RetroClients` template: drop Enrollee-Supplies-Subject (or require manager
approval, or restrict enrolment to a non-machine group). Everything before it only buys a
machine identity; ESC1 is what makes it Domain Admin.
