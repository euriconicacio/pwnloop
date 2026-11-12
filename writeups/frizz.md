# frizz.htb — write-up

> **HTB · Easy · retired.** Flags redacted.

A Kerberos-only domain controller that also runs a PHP LMS. The path: unauth web
RCE → crack a domain user → Kerberos SSH → a privileged password hidden in a
deleted Recycle-Bin archive → Group-Policy abuse to SYSTEM on the DC.

## Recon

`frizzdc.frizz.htb` is a DC with the standard AD ports plus two outliers that set
the whole engagement: **22 (OpenSSH for Windows)** and **80 (Apache 2.4 / PHP
8.2)**. SMB shows NTLM disabled and signing required — this is a *Kerberos-only*
box, which matters for every later tool choice. On a locked-down DC, the
non-standard ports are the path; here it's the web app.

## Foothold — Gibbon-LMS CVE-2023-45878

`http://frizz.htb/` redirects to `/home/` which links `/Gibbon-LMS` (Gibbon
v25.0.00, pinned from `version.php`). Pin the version, hunt the CVE: Gibbon
≤25.0.01 has an **unauthenticated arbitrary file write** in
`modules/Rubrics/rubrics_visualise_saveAjax.php` — the `img` parameter is
base64-decoded and written to the `path` parameter under the web root. Writing a
one-line PHP shell yields RCE as `frizz\w.webservice`.

`config.php` hands over the MySQL login (`MrGibbonsDB`). The `gibbonPerson` table
stores one user, `f.frizzle`, as `sha256(passwordStrongSalt + password)`
(hashcat `-m 1420`). It cracks to a themed password, and — crucially — it is
also the account's **AD** password.

## User — Kerberos SSH

SSH refuses password auth (`PasswordAuthentication no`), offering only
`gssapi-with-mic`. So: get a TGT (`impacket-getTGT`, wrapped in `faketime` for the
~7 h clock skew), then authenticate over GSSAPI. A gotcha worth recording — the
GSSAPI name canonicalization fails until `rdns = false` /
`dns_canonicalize_hostname = false` is set in `krb5.conf`. `user.txt` is on
`f.frizzle`'s desktop.

## The wall (and the method to get past it)

`f.frizzle` has, on paper, *nothing*: no outbound ACL edge (BloodHound and a
`shadowCredentials` write both confirm "insufficient access"), nothing
Kerberoastable or AS-REP-roastable, no gMSA/LAPS/ADCS, no credential reuse, no
local Windows misconfig (the web account lacks `SeImpersonate`). The target is
clearly `M.SchoolBus` ("Desktop Administrator") — it is in **Group Policy Creator
Owners** and has **WriteGPLink on the Domain Controllers OU**, i.e. GPO → DC →
SYSTEM. But none of `f.frizzle`'s rights reach it.

The lesson: when every *live* avenue is exhausted on a Windows box, enumerate
what was *deleted*. `C:\$RECYCLE.BIN` has a per-SID subfolder; `f.frizzle`'s held
a deleted 30 MB archive ($R/$I pair). It is a **WAPT** deployment-server install,
and `wapt/conf/waptserver.ini` contains a base64 `wapt_password` — which is
`M.SchoolBus`'s domain password.

## Root — Group Policy abuse

`M.SchoolBus` can create a GPO (GPCO) and link it to the Domain Controllers OU
(WriteGPLink). A GPO carrying a **Group Policy Preferences immediate scheduled
task** running as `NT AUTHORITY\System` executes on the DC's next GP refresh.
Two things make this box harder than the textbook version:

- **A reset job deletes custom GPO objects every ~1–2 minutes**, faster than the
  DC's 5-minute GP refresh. The fix is to run the weaponization *on the box* in a
  tight loop that recreates the GPO every few seconds, keeping a valid, linked
  GPO continuously present so whichever refresh fires hits a live one. Keep the
  OU's `gPLink` clean (just the default + your GPO) — accumulated dangling links
  to deleted GPOs break GP processing.
- **The task XML must be complete.** A GPP `ImmediateTaskV2` that omits
  `<Triggers>` / most of `<Settings>` is silently ignored by the client-side
  extension. Use the full, known-good structure (e.g. what pyGPOAbuse emits).

The SYSTEM task adds the account to local Administrators and reads `root.txt`;
verified via `impacket-wmiexec -k`.

## Failed leads (worth the time to rule out)

- Online Kerberos brute of `M.SchoolBus` (lockout was `Never`) — abandoned once
  the foothold password proved to sit ~11 M lines deep in rockyou: themed
  passwords here are meant to be cracked *offline* from a hash, not online.
- ADCS (no CA), gMSA/LAPS (none), DnsAdmins (empty), scheduled tasks (none
  custom), MySQL `FILE` primitive (`secure_file_priv = NULL`).

## One control that breaks it

Don't run the public LMS on the DC — that single placement decision is the whole
foothold. The domain-side root cause is handing GPO-management rights (GPCO +
WriteGPLink on the DC OU) to a non-tier-0 account.
