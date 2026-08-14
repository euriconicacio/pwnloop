# Write-ups

Published versions of engagement write-ups, produced by `pwnloop` and then put
through the redaction step described in
[`skills/pwnloop/references/writeup.md`](../skills/pwnloop/references/writeup.md).

Single machines only. Multi-host campaigns are indexed in
[`labs.md`](../labs.md) and never carry a chain — a Pro Lab does not retire, so
its solution never becomes publishable.

| machine | platform | difficulty | OS | chain |
|---------|----------|------------|----|-------|
| [Cap](cap.md) | Hack The Box (retired) | Easy | Linux | IDOR → pcap → cleartext FTP credential → password reuse → `cap_setuid` on the system Python |
| [Nexus](nexus.md) | Hack The Box (retired) | Easy | Linux | vhost fuzzing → secret in git history → credential reuse → CVE-2026-38526 upload RCE → production `.env` → path traversal in a root-run sync job |
| [Forest](forest.md) | Hack The Box (retired) | Easy | Windows / AD | anonymous user enum → AS-REP roast → crack → WinRM → Account Operators → Exchange `WriteDacl` on domain → DCSync → pass-the-hash |
| [Escape](escape.md) | Hack The Box (retired) | Medium | Windows / AD | anonymous SMB share → credential in an onboarding PDF → `xp_dirtree` UNC coercion → NetNTLMv2 crack → WinRM → password in a backup SQL error log → AD CS ESC1 → pass-the-hash |
| [Bruno](bruno.md) | Hack The Box (retired) | Medium | Windows / AD | service-account password → Kerberoast reuse → `MachineAccountQuota` + Certifried (CVE-2022-26923) → certificate → pass-the-hash |
| [Fireflow](fireflow.md) | Hack The Box (retired) | Medium | Linux / k8s | unauth Langflow public-flow RCE (CVE-2026-38526) → env password → SSH (user) → MCP/registry credential leak → Kubernetes `get nodes/proxy` kubelet exec → privileged pod → node root |
| [Abducted](abducted.md) | Hack The Box (retired) | Medium | Linux | CVE-2026-4480 Samba `%J` print-command injection → world-readable rclone credential (reversible) → password reuse → SMB wide-links/force-user lateral → operators-writable systemd drop-in → root |
| [Soulmate](soulmate.md) | Hack The Box (retired) | Easy | Linux | CrushFTP CVE-2025-31161 auth bypass → admin VFS `file:///` mount (root-in-container) → `PUT` webshell into bind-mounted webroot → `www-data` → root-owned Erlang/OTP SSH CVE-2025-32433 pre-auth RCE → SUID bash |
| [Baby](baby.md) | Hack The Box (retired) | Easy | Windows / AD | anonymous LDAP bind → password in a `description` field → hidden accounts via group `member` attrs → `PASSWORD_MUST_CHANGE` reset over SAMR → WinRM → Backup Operators on the DC → `diskshadow` + `robocopy /b` NTDS.dit → pass-the-hash |
| [Orion](orion.md) | Hack The Box (retired) | Easy | Linux | Craft CMS CVE-2025-32432 (Yii `PhpManager` gadget → blind `require`) → PHP session poisoning over a raw socket → `www-data` → Craft `.env` + cracked bcrypt → SSH password reuse → root-run inetutils telnetd CVE-2026-24061 `USER` argument injection → `login -f root` |
| [Support](support.md) | Hack The Box (retired) | Easy | Windows / AD | `guest` SMB share → XOR-obfuscated LDAP password in a custom .NET tool → cleartext password in a user's `info` attribute → WinRM → `Shared Support Accounts` `GenericAll` on `DC$` + `MachineAccountQuota` → RBCD → S4U2Proxy → DCSync |
| [Snapped](snapped.md) | Hack The Box (retired) | Hard | Linux | unauth Nginx UI `GET /api/backup` returning its own AES key in a header → node secret = API-auth bypass + bcrypt hashes → password reuse on SSH → PackageKit CVE-2026-41651 (Pack2TheRoot) `InstallFiles` TOCTOU → SUID root |
| [Zero](zero.md) | Hack The Box (retired) | Insane | Linux | unauth SFTP-account factory → writable `mod_userdir` `.htaccess` (`AllowOverride FileInfo`) → arbitrary www-data read via `ap_expr` `%{file:}` → reused DB password in `stats.php` → SSH → root `monit` config-check runs a command rebuilt from a process's own command line → `httpd -t` `LoadModule`s a malicious `.so` → root |
| [Lame](lame.md) | Hack The Box (retired) | Easy | Linux | full-range sweep finds `distccd` outside the top 1000 → CVE-2004-2687 unauth exec as `daemon` → world-readable `user.txt` → setuid-root `nmap` 4.53 `--interactive` `!` shell escape → root; separately, Samba 3.0.20 CVE-2007-2447 `username map script` delivered by a hand-built non-extended SMB1 `SESSION_SETUP_ANDX` → unauth RCE **as root** |
| [DevArea](devarea.md) | Hack The Box (retired) | Medium | Linux | anonymous FTP → Apache CXF 3.2.14 SOAP echo → CVE-2022-46364 MTOM `xop:Include` file read → Hoverfly admin password in a systemd unit → Hoverfly middleware RCE (user) → world-readable Flask secret → forged admin session + `$()`-through-blacklist command injection in the SysWatch GUI → `syswatch` → root `logs` CLI validates only the first symlink hop → chained symlink leaks root's SSH key |
| [Principal](principal.md) | Hack The Box (retired) | Medium | Linux | `X-Powered-By: pac4j-jwt/6.0.3` pins the auth library → unauthenticated JWKS publishes the JWE *encryption* key → JWE-wrapped unsigned PlainJWT skips signature verification (CVE-2026-29000 pattern) → forged `ROLE_ADMIN` → admin-only `/api/settings` leaks an SSH password → `svc-deploy` → `deployers` group reads an unencrypted SSH CA private key → `ssh-keygen -s ca -n root` → root by certificate |
| [Kobold](kobold.md) | Hack The Box (retired) | Easy | Linux | full-range sweep finds Arcane 1.13.0 on 3552 → unauth SSRF (CVE-2026-40242) whose verbose errors port-scan loopback → wildcard-SAN vhost fuzz finds MCPJam Inspector → unauth `POST /api/mcp/connect` spawns an arbitrary command (CVE-2026-23744) → `ben` → PackageKit one revision behind: `InstallFiles` TOCTOU (CVE-2026-41651, Pack2TheRoot) driven from `python3-gi` → SUID root |
| [Helix](helix.md) | Hack The Box (retired) | Medium | Linux / OT | vhost → Apache NiFi 1.21.0 anonymous `execute-code` → `ExecuteProcess` RCE as `nifi` → operator SSH key in the NiFi `support-bundles/` → SSH (user) → `sudo helix-maint-console` gated on an OT maintenance window → unauthenticated OPC UA write to `CalibrationOffset` spoofs a hazardous reactor temp (safety trusts `raw + writable offset`) → root safety controller opens the window → root shell |

## What is redacted, and what is not

Redacted, because these are properties of *my engagement*:

- **flag values** — replaced with `<user flag redacted>` / `<root flag redacted>`.
  Platform rules treat flag sharing as a violation regardless of a machine's
  status. The surrounding commands and output are kept so the chain still reads.
- **machine IPs** — generalised to `10.129.x.x`; they are ephemeral per-spawn.
- **attacker VPN address** — generalised to `10.10.14.x`.

Not redacted, because these are properties of *the machine* and appear in every
public write-up of it:

- service versions, hostnames and virtual hosts
- the vulnerabilities themselves, and the exact requests that trigger them
- credentials planted on the box by its author (e.g. a cracked service-account
  password), which appear in every public write-up of the machine

One extra step for Windows machines: **recovered hashes are generalised too**,
even though they are a machine property. An Administrator NT hash is a
pass-the-hash credential for the whole domain, so it reads as `<administrator-nt-hash>`
in the published copy while the technique around it stays intact.

## Publication rule

A write-up is publishable only for content confirmed **retired**. "Expired" is
not "retired" — an expired machine has merely stopped counting toward seasonal
points and may still be active. Every machine listed above was verified retired
before its file was committed.

The unredacted originals stay in `engagements/<machine>/WRITEUP.md`, which is
gitignored.
