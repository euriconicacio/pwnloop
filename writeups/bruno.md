# Bruno — Hack The Box, Windows / AD

A Windows domain controller that runs a small "sample scanner" web app and an
enterprise CA. The intended chain turns a read-only anonymous FTP share into
code execution on the DC, then escalates through a **local** Kerberos relay —
the interesting part, because every *remote* relay avenue is deliberately
hardened.

Flags redacted (`<32-hex>`); publishable once the box is retired.

## Recon

- `21` FTP (anonymous), `80/443` IIS, plus the full AD/DC service set (`88`,
  `389/636`, `445`, `5985`, `3389`). Host: `BRUNODC`, domain `bruno.vl`,
  Server 2022.
- Anonymous FTP serves `C:\samples` (`app/ benign/ malicious/ queue/`).
  `app/changelog` names a dev vhost and the automation account **`svc_scan`**.
- Fuzzing `Host: FUZZ.bruno.vl` finds one vhost: `dev.bruno.vl`, a
  **SampleUploader** ASP.NET app that accepts `.exe` uploads into a scan queue.

## Foothold

1. **AS-REP roast.** `svc_scan` has pre-auth disabled → AS-REP hash → cracks to
   `<svc-account-password>`. Kerberoasting with it shows `svc_net` shares the same password.
   Both are plain Domain Users with no ACLs (BloodHound clean).

2. **Read the scanner.** The FTP-readable `SampleScanner.dll` decompiles to a
   textbook **zip-slip**: every `*.zip` placed in `C:\samples\queue\` is
   extracted with `Path.Combine("C:\samples\queue\", entry.FullName)` +
   `ExtractToFile`, with no `Path.GetFileName`. The `queue` SMB share is
   writable by `svc_scan`, so a zip whose single entry is named
   `..\app\hostfxr.dll` lands the file in `C:\samples\app`.

3. **.NET apphost hijack.** `SampleScanner.exe` is a .NET Core apphost; it
   prefers an **app-local `hostfxr.dll`** over the shared one. Drop a malicious
   `hostfxr.dll` next to the exe and its `DllMain` runs as `svc_scan` on the next
   scan. The DC blocks outbound `80/139/445`, so the payload writes command
   output to `C:\samples\benign`, which anonymous FTP reads back — a pure
   file-system C2 — before a high-port reverse shell (egress on high ports is
   open) lands a live shell. `user.txt`.

   *Catcher lesson:* the first attempt's payload connected back fine, but the
   listener was a bare background `nc` with no stdin — a live shell read as dead.
   Holding the listener in a **tmux** session (`send-keys`/`capture-pane`) is
   what made it drivable.

## Privilege escalation — local Kerberos relay to RBCD

The DC is hardened against every *remote* relay:

- No outbound connectivity → network coercion (PetitPotam/PrinterBug to our
  host) is dead; the DC never connects back.
- `WebClient` absent → the WebDAV/HTTP coercion variant (ADCSPwn-style ESC8) has
  no trigger.
- LDAP refuses relayed binds: over `389` it wants signing the relay can't
  produce; over `636/LDAPS` it rejects the completed GSSAPI bind. (Plain simple
  binds are fine — signing is only enforced for SASL/Kerberos binds.)
- SMB signing is mandatory → SMB relay dies in the client handshake.

What still works is a **local** trigger. `svc_scan` is a member of
**Certificate Service DCOM Access**, which lets it activate the Certificate
Services DCOM class. Activating `CLSID D99E6E73-FC88-11D0-B498-00A0C90312F3` from
the foothold coerces the DC's own machine account (`BRUNODC$`, i.e. `NT/SYSTEM`
on the wire) into a Kerberos authentication over local DCOM — no egress, no
WebClient. That authentication is relayed to LDAP to configure **resource-based
constrained delegation** on the DC:

```
KrbRelayUp.exe relay -Domain bruno.vl -CreateNewComputerAccount \
    -ComputerName <pc>$ -ComputerPassword <pw> \
    -cls D99E6E73-FC88-11D0-B498-00A0C90312F3
```

This creates a machine account (`MachineAccountQuota` = 10) and writes
`msDS-AllowedToActOnBehalfOfOtherIdentity` on `BRUNODC` granting it RBCD. Then
standard S4U:

```
getST.py -spn cifs/brunodc.bruno.vl -impersonate Administrator \
    -dc-ip 10.129.x.x 'bruno.vl/<pc>$:<pw>'
KRB5CCNAME=Administrator@cifs_brunodc.bruno.vl@BRUNO.VL.ccache \
    wmiexec.py -k -no-pass brunodc.bruno.vl
```

`bruno\administrator` on the DC → `root.txt`, and a DCSync of `krbtgt` for good
measure.

## Dead ends worth recording

- **Certifried (CVE-2022-26923):** template `Machine` is enrollable and MAQ=10,
  but setting a duplicate `dNSHostName` returns `CONSTRAINT_ATT_TYPE` — KB5014754
  is applied.
- **ESC8:** confirmed present, but unusable — no coercion callback (egress) and
  no `WebClient`.
- **No ESC1/ESC2/ESC3, no gMSA, no LAPS, no local service/DLL/registry misconfig,
  no password reuse beyond the two service accounts.**
- **KrbRelay to LDAP/SMB directly** got as far as capturing the machine AP-REQ
  but could not complete the write — LDAP-bind hardening and SMB signing. Getting
  the CLSID right (`D99E6E73`, not `D99E6E70`) and using the RBCD-to-self relay is
  what closes it.

## Takeaway

Every textbook relay path was closed except the one that needs no network at
all: a **local DCOM trigger** of the machine account, relayed to LDAP for an
RBCD write. The enabling misconfiguration is the combination of a writable
application bug **on the DC**, `MachineAccountQuota > 0`, LDAP that accepts
relayed binds, and a low-privilege account sitting in *Certificate Service DCOM
Access*.
