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
- **A database's lowest privilege is still a credential primitive.** A `guest`
  principal with no readable data can often still run a directory/file
  procedure (`xp_dirtree`, `xp_fileexist`, `xp_subdirs`, `LOAD_FILE`,
  `COPY ... FROM PROGRAM`) and make the *service account* authenticate to a UNC
  path you choose. Empty database, full credential. *(Escape)*
- **Application error logs record the username that was supplied, verbatim.**
  SQL Server, and most auth stacks, log failed logins with the typed name — so a
  password pasted into the username field is persisted in cleartext. Grep every
  readable log for `Logon failed`/`Login failed` and read the *next* line.
  *(Escape)*

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

## Active Directory

- **AS-REP roast is the first move against any DC where you can list users.** One
  command, zero credentials, and you can often list users anonymously via
  `rpcclient -U "" -N ... enumdomusers`. Try it before anything needing a
  password. *(Forest: `svc-alfresco` had preauth disabled; cracked in 1 s)*
- **A Windows access token is fixed at logon.** Gain a group or a right and the
  *current* session does not see it — you need a new logon, which on Kerberos
  means a new TGT. This is the most common cause of "insufficient rights" when
  the rights are, on paper, present. *(Forest: group-add over WinRM never took
  effect in the same session)*
- **On a lab DC, prefer NTLM/password auth to Kerberos unless you need it.**
  Kerberos adds `KRB_AP_ERR_SKEW` as a failure mode — the DC clock and yours
  drift minutes apart. `net rpc` / impacket with a password sidesteps it.
  *(Forest)*
- **When Kerberos is unavoidable, use `faketime`, not `ntpdate`.** The container
  has no `CAP_SYS_TIME`, so `ntpdate` measures the offset and then fails to
  apply it (`step_systime: Operation not permitted`); the clock belongs to the
  host kernel. `ntpdate -q <dc>` to read the offset, then
  `faketime "$(date -u -d '+Nh Nm Ns' '+%F %T')" <cmd>` shifts one process only.
  Required for PKINIT/certipy auth. *(Escape: 8 h skew)*
- **Beat a lab box's reset job by not depending on persistent state.** State
  changes (group membership, ACLs) get reverted every few minutes. Chain the
  add + grant + use in one Linux-side window, each step re-authenticating fresh,
  rather than modifying state and coming back later. *(Forest)*
- **`Account Operators` is a domain-takeover group, not helpdesk.** Combined with
  the default Exchange `WriteDacl`-on-domain ACL, membership is a direct path to
  DCSync. Collect BloodHound and read the domain object's ACEs before assuming
  the path. *(Forest: Account Operators → Exchange Windows Permissions → DCSync)*
- **`admincount=False` on a privileged group means its DACL is writable.**
  AdminSDHolder is not protecting it, so a lower tier with `GenericAll`/`WriteDacl`
  over it can rewrite its rights. *(Forest)*
- **`BUILTIN\Certificate Service DCOM Access` in a user's token means AD CS is
  reachable.** That group membership is the artifact that justifies running
  `certipy find -vulnerable`; check `whoami /all` for it on every Windows user
  you land as. *(Escape: ESC1 on a template enrollable by Domain Users)*
- **An ESC1 certificate outlives the password.** Enrollee-supplies-subject plus
  client-auth EKU plus no manager approval is domain admin in one request, and
  the issued cert stays valid for its full lifetime (often 10 years) through
  password resets. Revoking it is part of cleanup, and it is the finding to lead
  the report with. *(Escape)*

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
- **A silent capture tool is not a failed attack — put `tcpdump` on the
  interface.** `impacket-smbserver` captured a NetNTLMv2 correctly while
  printing nothing at all. The wire is ground truth: a 553-byte SMB
  session-setup packet *is* the `NTLMSSP_AUTH`, and
  `tshark -Y ntlmssp -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain
  -e ntlmssp.ntlmserverchallenge -e ntlmssp.auth.ntresponse` rebuilds the hash
  as `user::domain:challenge:proof:blob`. Capture before you restart the tool a
  third time. *(Escape)*
- **Coerced SMB callbacks are negative-cached by the target.** Vary the UNC path
  on each retry (`\\ip\pwn01`, `\\ip\pwn02`) or you will conclude the
  primitive stopped working when only the cache spoke. *(Escape)*
- **`pkill -f <pattern>` matches its own shell.** A command line containing the
  pattern kills the wrapper that was about to restart the process. Match on a
  path fragment the launcher does not contain, or kill by PID. *(Escape)*

## Method

- **The vulnerability with the CVE number is rarely the one that decides how bad
  the outcome is.** On both machines so far, the CVE or the flashy web bug got a
  low-privileged shell, and a local privilege boundary somebody widened for
  convenience turned it into root. Say this in the report; it is the finding
  that changes what gets funded.
