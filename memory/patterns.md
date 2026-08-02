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
- **Never triage a scan through a truncated view.** `tail`, `head` and a narrow
  `grep` are for reading a result you already understand, not for deciding what a
  scan found. Print the full list of open ports once, read all of it, and only
  then filter. Running the right scan and then not looking at its output is
  indistinguishable from never running it.
- **On a locked-down host, the one non-standard port is the path.** A domain
  controller serving 80, 1883 or anything else outside the AD set is not
  incidental — the standard ports are hardened precisely so that the odd one is
  where the machine wants you. Rank leads by how out of place the service is,
  not by how familiar the protocol is.

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
- **If the lockout policy is unreadable, spray one password per account per
  window — not a list.** `--pass-pol` needs a credential you do not have yet, so
  the threshold is unknown, and on a hardened domain it can be as low as three.
  Kerberos pre-auth answers `KDC_ERR_CLIENT_REVOKED` once an account is locked,
  which is the same code as "disabled" — by the time you can read it, the damage
  is done. A locked account cannot be used by the intended path either, so this
  mistake can end the engagement rather than merely delay it.
- **Application error logs record the username that was supplied, verbatim.**
  SQL Server, and most auth stacks, log failed logins with the typed name — so a
  password pasted into the username field is persisted in cleartext. Grep every
  readable log for `Logon failed`/`Login failed` and read the *next* line.
  *(Escape)*
- **After any web/app RCE, read the process environment before the filesystem.**
  `/proc/self/environ` and the service's systemd `EnvironmentFile` (find it in
  `systemctl cat <svc>`) routinely hold the admin password and signing keys the
  app runs with — and that password is the first thing to spray at SSH and every
  other account. *(Fireflow: `LANGFLOW_SUPERUSER_PASSWORD` → SSH as the human
  user)*
- **A service that advertises its accepted JWT algorithms is telling you how to
  forge one.** If a `/version`/`/config` endpoint lists `"none"` among supported
  algs, mint `{"alg":"none"}` with `role:admin` and an empty signature before
  anything harder — hand-rolled verifiers that special-case `alg=="none"` with
  `verify_signature:false` are common. Only lowercase `none` tends to pass.
  *(Fireflow: MCP tool registry)*

## Web

- **A sequential integer identifying per-user data is worth one request.**
  Try id 0 and id-1 before anything else; id 0 is usually the oldest and most
  privileged object on the box. *(Cap: `/data/0` skipped every other phase)*
- **Unauthenticated diagnostic features are the intended path more often than
  a CVE is.** Anything that runs a capture, a ping, a lookup or a conversion on
  the host.
- **Fuzz for files, not only directories.** A static site's real content may be
  a file no page links to. Run a second pass with a *files* wordlist and media
  or document extensions (`jpg,png,mp4,pdf,docx,zip`) — an unreferenced image on
  an otherwise empty IIS root carried the hostnames the whole engagement needed.
- **Pull `/openapi.json` and diff the writable route against the read-only one.**
  It is often served unauthenticated even when the app requires login, and it
  names every route's declared `security`. A build/run route with `security:
  None` that accepts the same object a public read handed you is RCE in these
  flow/agent builders, whose nodes carry their own code. *(Fireflow: Langflow
  `build_public_tmp` re-runs a caller-supplied flow)*

## Privilege escalation

- **Run `getcap -r /` before any enumeration script.** One command, five lines
  of output, and on a modern Linux box capabilities are a more common escalation
  than SUID binaries. *(Cap: `cap_setuid` on the system Python)*
- **`get nodes/proxy` on a pod service account is kubelet exec, not just reads.**
  Enumerate the SA with SelfSubjectRulesReview/AccessReview; that one verb reaches
  the kubelet (`:10250` from the node, or via the apiserver `nodes/<n>/proxy/`).
  A GET to `/exec/<ns>/<pod>/<c>` returning **`500 Upgrade request required`**
  (not 403) means authz passed — finish it with a WebSocket (`v5.channel.k8s.io`,
  falling back to `v4`). Target any pod with `privileged:true`+`runAsUser:0`
  (monitoring/logging DaemonSets). *(Fireflow: node-exporter → node root)*
- **Escaping a distroless/privileged container with host `/` mounted: invoke the
  host loader explicitly.** No shell or `nsenter` in the container, but the host
  bind-mount has them — run
  `/host/root/lib64/ld-linux-x86-64.so.2 --library-path <host libdirs> /host/root/usr/bin/nsenter -t 1 -m -u -i -n -p -- /bin/bash -c '…'`.
  With `hostPID`+privileged+uid 0 that enters host init's namespaces as node root.
  *(Fireflow)*
- **A pinned-vulnerable version is not automatically a usable exploit.** Confirm
  the precondition before building the PoC: sudo in the CVE-2025-32463 range still
  refuses `-R` unless the user has a sudoers rule permitting chroot — check
  `sudo -l` with the real password, not `-n`, before committing to it. *(Fireflow:
  sudo 1.9.15p5, no chroot rule → dead end)*
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
- **When RPC, LDAP and RID enumeration are all denied, look for a forge.** A
  self-hosted Git service (Gogs, Gitea) exposes its user list at `/explore/users`
  without authentication, and on a small estate those accounts are the domain
  accounts. Confirm each against the Kerberos oracle before using them —
  `KDC_ERR_C_PRINCIPAL_UNKNOWN` means it exists only in the forge.
- **Kerberos pre-auth is a user-enumeration oracle that needs no credential.**
  Invalid principal → `KDC_ERR_C_PRINCIPAL_UNKNOWN`; valid one →
  `doesn't have UF_DONT_REQUIRE_PREAUTH`. It works when SAMR, RID cycling and
  anonymous LDAP are all refused, and it is how you validate a name list from any
  other source.
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
- **Responder holds 445 and 139, which breaks your own SMB client.** With it
  running, every `nxc smb` authentication returns "NETBIOS connection timed out"
  and reads exactly like target-side rate limiting. Stop Responder before
  touching SMB, and suspect it first when SMB worked five minutes ago.
- **Backticks in a string passed through `pwnloop x` are substituted by the
  outer shell.** Markdown written into a heredoc silently loses every
  `` `word` `` as a failed command. Use the Write/Edit tools for file content
  and reserve the wrapper for actual commands.
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

- **Memory read at the start is not memory applied at the moment of acting.**
  Every rule in this file was already here when it was broken again: `pkill -f`
  matched its own shell a second time, and the lockout rule was violated by the
  run that had just read it. Before any command that is destructive, irreversible
  or noisy — spraying, killing, writing to a target — stop and check whether a
  rule covers it. The expensive mistakes are never the unknown ones.
- **The vulnerability with the CVE number is rarely the one that decides how bad
  the outcome is.** On both machines so far, the CVE or the flashy web bug got a
  low-privileged shell, and a local privilege boundary somebody widened for
  convenience turned it into root. Say this in the report; it is the finding
  that changes what gets funded.
