# Fluffy — HTB write-up

> Flags redacted. Difficulty not independently confirmed — not asserted here.
> Flags redacted.

Fluffy is an AD box that starts from low-priv domain creds and chains a
file-based NTLM coercion, a service-account ACL cluster, and an AD CS ESC16
misconfiguration into Domain Admin. NTLM is enabled, which keeps the Kerberos
skew (+7h) from mattering much — everything can run over NTLM / pass-the-hash.

## Foothold — CVE-2025-24071 from a writable share
`j.fleischman` can READ+WRITE the `IT` share. It holds installers and an
`Upgrade_Notice.pdf` that conveniently lists 2025 CVEs — the signpost. The
writable share plus a privileged user who browses it is the classic setup for
`CVE-2025-24071`: a `.library-ms` file whose `simpleLocation/url` points at an
attacker UNC makes Explorer authenticate to you the moment the folder is viewed.

Drop `exploit.library-ms`, stand up an SMB listener, wait for the scheduled
browse. Note the capture is **silent** on impacket-smbserver — the hash never
printed to stdout; `tcpdump` on `tun0` was the ground truth, and
`tshark -Y ntlmssp.auth.ntresponse` plus impacket's static server challenge
(`aaaaaaaaaaaaaaaa` in this build) rebuilt a crackable NetNTLMv2 for **p.agila**,
which fell to rockyou instantly (`prometheusx-303`).

## Lateral — a service-account ACL cluster
BloodHound shows the shape immediately: `p.agila` (and `j.coffey`) are in
**Service Account Managers**, which has `GenericAll` over the **Service Accounts**
group, which in turn holds `GenericWrite` over `ca_svc`, `winrm_svc`, `ldap_svc`.
Add p.agila to Service Accounts (`net rpc group addmem`), and the write is yours.
`GenericWrite` is enough for **shadow credentials** (`msDS-KeyCredentialLink`);
because the box runs AD CS, PKINIT works and `certipy shadow auto` hands back the
NT hashes of `winrm_svc` and `ca_svc`. `winrm_svc` pass-the-hash over WinRM reads
`user.txt`.

## Privilege escalation — AD CS ESC16
`certipy find -vulnerable` as `ca_svc` flags the CA: **the SID security extension
is disabled (ESC16)**. With the extension off, issued client-auth certs are
mapped to accounts by UPN alone. Since we control `ca_svc`'s attributes, set its
`userPrincipalName` to `administrator@fluffy.htb`, enroll the `User` template
(RPC enrollment — target by IP with a generous timeout, it is finicky over the
named pipe), then revert the UPN. The resulting certificate authenticates via
PKINIT as the Domain Administrator; `certipy auth` yields the admin ticket, and
`root.txt` reads over SMB `C$`.

## Leads that failed / notes
- **Kerberoast** returned ca_svc/ldap_svc/winrm_svc SPNs but their passwords are
  strong — not crackable; the service accounts are reached by ACL, not by roast.
- **certipy find -vulnerable** showed no low-priv ESC template for the starting
  user; the ESC16 only surfaces once you look at the CA itself as a controlled
  service account.
- **Enrollment over RPC** threw "Failed to get DCE RPC connection" /
  "NETBIOS connection timed out" until the request was pointed at the DC by IP
  with `-timeout 40`; this is a transport quirk, not an auth failure.

## Flags
- `user.txt` — `<32-hex-flag>`
- `root.txt` — `<32-hex-flag>`
