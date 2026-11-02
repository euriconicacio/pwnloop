# nanocorp.htb — write-up

> Flags redacted.

Windows Active Directory box. Only one service is out of place on the DC — an
Apache/PHP stack on port 80 — and that is the whole way in.

## Recon
Standard DC port set (Kerberos, LDAP, SMB with signing required, ADWS, WinRM over
5986 only) **plus** Apache 2.4.58 / PHP 8.2.12 on 80. Null/anonymous SMB and LDAP
are locked down (no users, no shares), so the odd web port is the target. The
static site links to a second vhost, `hire.nanocorp.htb` — a resume-upload portal.

## Foothold — archive upload that leaks a hash
`hire/upload.php` takes ZIP/7Z/RAR and **extracts** them into `uploads/`, which is
denied at the Apache `<Directory>` level. Every "webshell" instinct fails there:

- the extracted files are never web-servable (config-level `Require all denied`);
- traversal (`../`, `..\`, absolute `C:\`, all three formats, every depth) is
  sanitised by the extractor;
- there is no read-back handler, no LFI, no filename command-injection.

The tell is the *combination*: extract-to-a-folder-nobody-can-web-read + a
"review your resume" workflow on Windows. That is an **NTLM-theft** design. A ZIP
carrying a crafted **`.library-ms`** pointing at `\\<me>\share` (CVE-2025-24071)
makes the host authenticate outward when the folder is processed. Responder caught
`NANOCORP\web_svc`; `hashcat -m 5600` cracked it.

*Lead that failed:* CVE-2024-4577 (PHP-CGI arg injection) — dead here, PHP is
mod_php, not php-cgi. Ruled out cheaply by confirming no argument injection reaches
any script.

## User — ACL chain to a Kerberos-only account
`web_svc` can write to group **IT_SUPPORT**, which can **ForceChangePassword** on
**`monitoring_svc`**. Add self to the group, reset the target's password. Because
`monitoring_svc` is in *Protected Users*, NTLM is off — authenticate with a
**Kerberos** TGT (mind the ~7h clock skew). WinRM over TLS → `user.txt`.

## Root — monitoring agent race to SYSTEM
**Check MK Agent 2.1.0.50010** executes plugins as SYSTEM through predictable
`C:\Windows\Temp\cmk_all_<PID>_<ctr>.cmd` files (CVE-2024-0670). Pre-seed those
names **read-only** (cover the PID space; Windows PIDs are 4-aligned), then force an
MSI repair (`msiexec /fa`) **in the installer's context** (RunasCs as `web_svc`,
which installed the agent). The SYSTEM process runs your seeded file → `root.txt`.

*Gotcha:* the seeded files must be **read-only** (so the agent can't overwrite them)
and the PID range must be wide enough — a narrow range simply never wins the race.

## Defensive takeaway
Block outbound SMB from the server and don't auto-extract untrusted uploads: the
`web_svc` capture never happens and the chain never starts.
