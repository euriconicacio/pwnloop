# Cross-engagement patterns

What earlier runs learned that generalises. This is the second loop: the
engagement writes here, and the next engagement reads here before it starts.

**Rules for this file.** Patterns only — never flags, never credentials, never
anything specific to one machine that a future run cannot use. If an entry only
describes what happened on one box, it belongs in that engagement's `WRITEUP.md`
instead. Keep entries short enough that reading the whole file stays cheap.

Format: what to look for → why it pays → the check, in one line each.

## Recon

- **A 302 from the raw IP to a hostname means vhost gating.** Fuzz `Host:`
  immediately rather than later; the hostname you were handed is rarely the only
  one. Filter on the size of a deliberately wrong `Host` response.
  *(Nexus: two unlinked vhosts, both essential)*
- **Small port count raises the value of each port.** Two or three open ports
  means the path is definitely in one of them — read the application rather than
  reaching for a scanner.

## Credentials

- **A blanked secret in a repository is a signpost, not a fix.** `git log -p`
  the file. Someone noticed and removed it in a later commit, which tells you
  exactly which commit to read. *(Nexus)*
- **The application's live config beats the repository's.** After any web
  foothold, read `/var/www/*/.env`, `config.php`, `settings.py` before anything
  else — the deployed secret usually differs from the leaked one and is worth
  more. *(Nexus: the leaked password opened one door, the deployed one opened
  three)*
- **Try every recovered credential against every service and every user.**
  Reuse has resolved more machines here than any single exploit. Includes
  service-account passwords against human SSH logins, and web-app passwords
  against internal forges.
- **A capture of a cleartext protocol *is* a credential.** FTP, Telnet, HTTP
  basic, unencrypted SMTP/IMAP, SNMP, LDAP simple bind. Treat "can download a
  pcap" as "can read passwords". *(Cap)*

## Web

- **A sequential integer identifying per-user data is worth one request.**
  Try id 0 and id-1 before anything else; id 0 is usually the oldest and most
  privileged object on the box. *(Cap: `/data/0` skipped every other phase)*
- **Unauthenticated diagnostic features are the intended path more often than
  a CVE is.** Anything that runs a capture, a ping, a lookup or a conversion on
  the host.

## Privilege escalation

- **Run `getcap -r /` before any enumeration script.** One command, five lines
  of output, and on a modern Linux box capabilities are a more common escalation
  than SUID binaries. *(Cap: `cap_setuid` on the system Python)*
- **Read root-run scripts you cannot write.** A world-readable script executed
  by root tells you what root does with data you might control. Confirm the user
  with the systemd unit's `User=` and the owner of its log file. *(Nexus)*
- **`os.path.join(base, untrusted)` is an arbitrary-write primitive.** It does
  not normalise `..` and discards `base` entirely on an absolute second
  argument. Any root job extracting an archive, a git tree, a database row or an
  API response into a directory is a candidate. *(Nexus)*
- **Prefer misconfiguration to kernel exploits.** Labs rarely intend a kernel
  exploit, and it destabilises the box for whoever runs it next.
- **`uid=0` with a non-zero `gid` means you got there through a capability or
  SUID binary, not a login.** Useful orientation in an unfamiliar shell.

## Tooling and environment

- **Git's refusal to build a path is porcelain, not format.** `git add` rejects
  `..`, `git mktree` writes it anyway, and forges do not fsck incoming objects
  by default. Any consumer of `git ls-tree` output as a filesystem path is a
  traversal candidate. *(Nexus)*
- **`sed -i` cannot edit `/etc/hosts` inside a container** — the file is
  bind-mounted and `sed -i` works by rename. Append instead.
- **A missing tool costs more than the time to install it.** When a step stalls
  on tooling, add the package to `docker/packages.txt` in the same session —
  that is what the second loop is for.

## Method

- **The vulnerability with the CVE number is rarely the one that decides how bad
  the outcome is.** On both machines so far, the CVE or the flashy web bug got a
  low-privileged shell, and a local privilege boundary somebody widened for
  convenience turned it into root. Say this in the report; it is the finding
  that changes what gets funded.
