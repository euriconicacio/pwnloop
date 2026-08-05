# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## What a version bump means here

This is a methodology plus a container, not a library, so the usual SemVer
categories map like this:

- **Major** — a change that breaks an existing workflow: the wrapper's command
  surface, the engagement directory layout, or the skill/command names.
- **Minor** — new methodology, new references, new tooling in the image, new
  wrapper subcommands. Anything that adds capability without breaking a habit.
- **Patch** — corrections: a package that moved or disappeared upstream, a
  broken command in a reference, documentation fixes.

Engagements are expected to change the methodology (see `memory/patterns.md`),
so minor releases are the normal cadence. An entry that says only "ran a box"
does not belong here — what belongs is what the run *changed*.

## [Unreleased]

## [1.6.1] — 2026-08-05

### Fixed
- **`references/pivoting.md` documented a binary the image never installed.**
  The ligolo-ng section told the operator to run `/opt/static/ligolo-proxy`, and
  nothing in the Dockerfile ever put it there — so the one pivot mechanism that
  gives a real TUN route (and therefore working `-sS`, UDP and raw tooling) was
  unavailable exactly when a reference said to reach for it. The proxy and the
  linux agent are now staged, resolved through the GitHub API rather than a
  pinned URL so the image tracks upstream instead of 404ing on a later build.
  A failed download degrades the image and is logged, as with every other staged
  binary.
- Added the ordering constraint that makes ligolo work: the route goes in
  *after* the session is started in the proxy console. Added too early it
  blackholes the traffic, and the subnet reads as filtered — a failure that
  looks like a hardened target rather than a mistake.
- **`campaigns/` is now ignored and refused by the hook**, before anything in
  this version writes to it. A working copy can hold live engagement data while
  checked out on a branch that predates the directory, and there an ignore rule
  that ships *with* the feature ships too late: `git add -A` sweeps up private
  keys, registry hives and flags. Found exactly that way. The content rules
  (private-key material, flag-shaped strings) would have caught it at commit
  time, which is the wrong layer to rely on — a path rule that only exists on
  one branch is not a control.

## [1.6.0] — 2026-08-04

One engagement (Lame) against a deliberately antique host. The box itself was
easy; what it exposed was a blind spot in the methodology — a correct,
well-evidenced lead that **stock tooling can no longer deliver**, and which the
loop had no guidance for and very nearly recorded as a dead end.

### Added
- **Reference: a bug in the *authentication* path may be unreachable with a
  modern client — that is a delivery problem, not a patched target**
  (`references/services.md`). When the injectable field is one the client
  negotiates *around* (a username, a domain, a workstation name), `smbclient` and
  impacket pack it into an NTLMSSP/SPNEGO blob where metacharacters sit inside a
  structured field and never reach a shell. The symptom is indistinguishable from
  "not vulnerable": a clean `NT_STATUS_LOGON_FAILURE` and no side effect. The
  entry gives the diagnosis order — confirm the precondition on the target rather
  than arguing with the version; know that the legacy client knobs
  (`client use spnego = no`, `client ntlmv2 auth = no`) are *accepted and
  ignored*; emit the raw exchange yourself (NEGOTIATE offering only `NT LM 0.12`,
  then a non-extended `SESSION_SETUP_ANDX` with `WordCount 13` and the
  `EXTENDED_SECURITY` bit clear); and confirm with a side-effect oracle, since
  these bugs run the command and *then* reject the login, so a failure status is
  the success case.
- **Reference: pin the version of an unusual setuid binary before deciding it is
  uninteresting** (`references/privesc-linux.md`). GTFOBins entries are
  frequently version-conditional — a tool acquires a scripting or interactive
  mode, it gets abused, upstream removes it — so an identically-named binary is
  inert on a modern box and a one-command root on an old one. Includes what to
  look for (any subcommand that hands a string to `system()`: an interactive `!`
  escape, an embedded scripting engine, an `--exec` hook) and how to drive those
  modes non-interactively when the foothold has no TTY.

### Added — write-ups
- **Lame** (`writeups/lame.md`) — Easy, Linux. Full-range sweep finds `distccd`
  outside the top 1000 → CVE-2004-2687 unauthenticated exec as `daemon` →
  world-readable `user.txt` → setuid-root `nmap` 4.53 `--interactive` `!` shell
  escape → root. Separately: Samba 3.0.20 CVE-2007-2447 delivered by a
  hand-built non-extended SMB1 session setup — unauthenticated RCE **as root** in
  a single packet exchange, after the same vulnerability had failed through every
  stock client.

## [1.5.1] — 2026-08-03

One engagement (Zero) produced a new web read-primitive and a new root
command-injection class, plus a published write-up and a correctness pass over
the write-up metadata.

### Added
- **Reference: an attacker-controlled `.htaccess` is a file-read/RCE primitive**
  (`references/web.md`). Where a served directory is writable (an upload sink, a
  `mod_userdir` hoster), `.htaccess` itself is the payload and `AllowOverride`
  decides the grant. With FileInfo but no mod_php you still get arbitrary read as
  the web user via `ap_expr`: `ErrorDocument 404 "%{file:/path}"` (no size limit)
  or `Header set X-L "expr=%{base64:%{file:/path}}"`. Written as a class, with the
  probe to fingerprint the exact override and a pointer to CVE-2025-66200.
- **Reference: a root job that rebuilds a command from a process's command line**
  (`references/privesc-linux.md`). A supervisor/health-check (commonly `monit`
  `check program`) that runs `${proc_cmdline/…} ; $cmd` unquoted as root is a local
  root command-injection: craft a decoy process's `/proc/cmdline` with `exec -a`.
  Includes the `httpd -t` + `LoadModule` trick — a config *test* still `dlopen`s a
  module, so a `.so` constructor runs as root.
- **Reference: a read primitive is a source-disclosure primitive — read before
  you build a write** (`references/source-review.md`). The highest-value use of any
  LFI/`file:`/traversal is to read the deployed app source and configs for a
  credential or logic detail, not to pivot to a clever write; misdirection around a
  read primitive is itself the tell that the door is a plain file read.

### Changed
- **Write-up metadata corrected.** Added the confirmed HTB difficulty to every
  write-up title that omitted it and to the `writeups/README.md` table (now a
  dedicated column); difficulty is platform metadata to confirm, never to infer.
- **Troubleshooting: Opus API safeguard errors** (`README.md`). Documented the
  transient content-classifier errors that can interrupt a long autonomous run and
  how to recover.

### Added — write-ups
- **Zero** (`writeups/zero.md`) — Insane, Linux. Unauth SFTP-account factory →
  writable `mod_userdir` `.htaccess` → `ap_expr` arbitrary read → reused DB
  password in `stats.php` → SSH → `monit` config-check root command-injection via
  a crafted process command line and `httpd -t` module load.

## [1.5.0] — 2026-08-03

Two engagements (Support, Snapped) produced new privilege-escalation methodology
and two published write-ups. The reference additions are what make this a minor:
a run should be able to act on them against a different box.

### Added
- **Reference: D-Bus / system-daemon privilege escalation** (`references/privesc-linux.md`).
  A root daemon reachable by any local user over the system bus is a privesc
  surface even with no group or sudo right — the classes being a permissive polkit
  rule, argument injection, and a **TOCTOU race** (a "safe" call authorises, a
  second call swaps in a dangerous payload before the check resolves). A
  package-manager daemon is the highest-value target because "install a package as
  root" is arbitrary code via a maintainer script, so a version-gated CVE there
  beats any kernel bug. Written as a class with `PackageKit InstallFiles`
  (CVE-2026-41651, "Pack2TheRoot") as the compact example, plus the prereqs to
  check before building (`python3-gi`, `dpkg-deb`/`rpmbuild`, a `nosuid`/`noexec`-free
  drop dir).
- **Reference: verify a pinned sudo version is not a backported fix**
  (`references/privesc-linux.md`). Added CVE-2025-32463 (chroot NSS load) to the
  sudo section — reachable with **no** sudo rule — with the caveat that the
  upstream version string lies: pin the *package* version (`dpkg -l sudo`), because
  a distro can backport the fix and keep the number. Includes the `-nostdlib`
  syscall-only build so the malicious `libnss_` module carries no glibc-version
  symbols and `dlopen`s across targets.
- **Reference: prove a suspicious directory has a consumer before investing**
  (`references/privesc-linux.md`). A non-default world-writable/setgid directory is
  a compelling but common decoy; grep units and binaries for the path, check for an
  open handle, and drop a canary watched by `pspy` (for 2–3× the longest plausible
  cron period) before spending time on it.
- **Reference: sweep LDAP free-text attributes for stored secrets**
  (`references/ad.md`). Passwords land in `info`, `comment`, `title`,
  `extensionAttribute*` as often as `description`, and all are readable by any
  authenticated user. Dump every object whole and look at which attributes are
  populated at all rather than grepping for the one you expect.
- **Reference: read the deobfuscation routine, do not guess it from strings**
  (`references/source-review.md`). When a distributed binary obfuscates a secret,
  `strings -el` hands you every operand at once and a wrong guess reads as "invalid
  credential"; `monodis` + reading the `.cctor` for the constants is a minute.
- **Published write-ups: Support, Snapped** (`writeups/`) — redacted narratives for
  two more retired machines. *Support* (Windows/AD): `guest` SMB share → XOR-encoded
  LDAP password in a custom .NET tool → cleartext password in a user's `info`
  attribute → WinRM → `Shared Support Accounts` `GenericAll` on `DC$` + MAQ → RBCD →
  S4U2Proxy → DCSync. *Snapped* (Linux): unauthenticated Nginx UI `GET /api/backup`
  that returns its own AES key in the `X-Backup-Security` header → node secret =
  API-auth bypass → password reuse on SSH → PackageKit CVE-2026-41651 (Pack2TheRoot)
  `InstallFiles` TOCTOU → SUID root.

## [1.4.3] — 2026-08-03

Cosmetic release. The banner rendered wrong in the one place it is guaranteed to
be read — the agent transcript at the top of every engagement — and the README
carried a version number three releases out of date.

### Fixed
- **`pwnloop banner` no longer relies on leading whitespace to place its art.**
  The top two rows of the "p" were positioned with 33 leading spaces and nothing
  else, so any renderer that trims leading whitespace at a block boundary — the
  Claude Code tool-output view does — collapsed them to column 0 and broke the
  glyph. Every line now opens with a frame character, so column 0 is printable
  and there is no leading whitespace left to lose. The version, author and
  tagline moved inside the frame.

### Changed
- **The README no longer hardcodes a version.** It had said `v1.1.0` since 1.1.0
  and was wrong for every release after it. The banner in the README drops the
  version line entirely and a `shields.io` badge reads the latest GitHub release
  instead, so the file has nothing left to bump.
- **README reference table completed** — it listed 14 of the 22 files in
  `skills/pwnloop/references/`, omitting `adcs.md`, `relay.md`, `evasion.md`,
  `binary.md`, `containers.md`, `kubernetes.md`, `cloud.md` and `llm-apps.md`,
  all of which shipped in 1.2.0–1.4.0.

## [1.4.2] — 2026-08-03

Publication catch-up. The last two engagements had complete local write-ups that
had never been through the redaction step, and a review of the published set
turned up a wrong platform label and two IPs that the redaction pass had missed.
No methodology change — the technique those two runs produced already landed in
`references/` in 1.4.1.

### Added
- **Published write-ups: Baby, Orion** (`writeups/`) — redacted narratives for
  two more retired machines. *Baby* (Windows/AD): anonymous LDAP bind → a
  password planted in a `description` field → the accounts that matter found via
  group `member` attributes rather than user-object enumeration →
  `PASSWORD_MUST_CHANGE` reset over SAMR → WinRM → Backup Operators on the DC →
  `NTDS.dit` via `diskshadow` + `robocopy /b` → pass-the-hash. *Orion* (Linux):
  Craft CMS CVE-2025-32432 (Yii `PhpManager` gadget → blind `require`) → PHP
  session poisoning with a literal tag over a raw socket → `www-data` → Craft
  `.env` and a cracked bcrypt reused on SSH → inetutils telnetd 2.7 running as
  root on localhost, CVE-2026-24061 argument injection → `login -f root`.
  Orion's write-up also documents *why* the SLC-overflow CVE in the same binary
  (CVE-2026-32746) is not the path: the primitive is a linear-forward write, not
  an arbitrary one.

### Fixed
- **Platform labels** — `Bruno` was published as a Vulnlab machine in both
  `writeups/README.md` and `writeups/bruno.md`; every machine in the published
  set is Hack The Box. Corrected there and in the 1.4.0 changelog entry.
- **Redaction misses** — two machine IPs survived the publication pass in
  `writeups/bruno.md` (`-dc-ip`) and `writeups/fireflow.md` (an MCP registry
  URL), against the `10.129.x.x` convention the write-up index states. Both
  generalised.
- **Changelog release links** — the comparison/tag link block at the bottom of
  this file had gone stale at 1.1.0.

## [1.4.1] — 2026-08-02

*(Backfilled — 1.4.1 was tagged and released without a changelog entry.)*

Two engagements exposed the same failure mode: pinning a version, finding *a*
CVE, and tunnelling on it instead of reasoning about the set. This release turns
that into method, and backfills the reference coverage the runs produced.

### Changed
- **`SKILL.md` step 2** — for a pinned version, enumerate *all* of its CVEs and
  reason about the set: rank by cost and reliability (an auth bypass or argument
  injection beats a memory-corruption bug on a hardened target), consider
  chaining, and **exhaust public exploits before hand-rolling one** —
  `searchsploit` and web search often surface only a detection/leak PoC while a
  weaponised exploit lives in a GitHub repo they do not index, so
  `gh search repos/code "CVE-…"` and the advisory's reference links are part of
  the hunt. Applies to privesc CVEs, not just the foothold.
- **`SKILL.md` step 8** — writing to `references/` is a *required* half of the
  write-back, and it must be method, never a box's answer. Box-specific recipes
  stay in `memory/local.md`; the transferable class goes to `references/`.

### Added
- **`references/services.md`** — Telnet playbook and a reusable
  "version → CVEs" checklist; the Samba print-command / spoolss injection class.
- **`references/web.md`** — CMS RCE reframed as the general
  "framework object-injection → include/require RCE" class: blind-include
  side-effect oracles, session-file poisoning, raw-socket tag injection
  (Craft/Yii as the worked example).
- **`references/privesc-windows.md`** — Backup Operators on a DC → `NTDS.dit`
  via `diskshadow` + `robocopy /b` (the SAM hive is a DSRM dead end); .NET
  app-local `hostfxr.dll` sideload.

### Fixed
- **`references/ad.md`** — leaked box literals in the kerbrute examples
  generalised to the `machine.htb` placeholder convention.

## [1.4.0] — 2026-08-02

A large methodology-coverage expansion: six new reference files and substantial
depth added across the existing ones, so the loop reaches for a documented
technique instead of improvising in categories it previously only sketched.
Distilled into the terse, command-oriented, container-prefixed house style; no
box-specific content entered the shared methodology.

### Added
- **`references/adcs.md`** — the full AD CS escalation catalog **ESC1–ESC16**,
  each with the precise vulnerable condition, the `certipy find` signal, and the
  exact `certipy` request/auth commands; plus certificate theft (THEFT1–5,
  UnPAC-the-hash), golden-certificate and DACL persistence, and the mandatory
  revoke-by-serial cleanup. The inline AD CS section in `ad.md` is now a compact
  pointer to it.
- **`references/relay.md`** — NTLM/Kerberos coercion (**PrinterBug, PetitPotam,
  DFSCoerce, ShadowCoerce**, Coercer enumeration), the SMB-vs-HTTP/WebDAV choice,
  the `ntlmrelayx` target matrix (AD CS ESC8/ESC11, LDAP RBCD, SMB shell, SOCKS),
  and when to fall back to the local relay or to capture-and-crack.
- **`references/containers.md`** — container-escape catalog: mounted
  docker/containerd socket, `--privileged`/`CAP_SYS_ADMIN` cgroup
  `release_agent`, host-filesystem mounts, and capability-specific routes
  (`SYS_PTRACE`, `SYS_MODULE`, `DAC_READ_SEARCH`, raw host disk).
- **`references/cloud.md`** — cloud-attached targets: instance-metadata credential
  theft (IMDSv1/v2, Azure, GCP) via SSRF or a VM shell, the canonical **AWS IAM
  privilege-escalation paths**, Azure/Entra managed-identity and role abuse, GCP
  service-account impersonation, and cloud↔on-prem pivots.
- **`references/binary.md`** — custom network services and SUID binaries: checksec
  triage, command-injection handlers, stack overflow → shellcode/ret2libc/ROP,
  format-string leak-and-write, and the arm64-container-vs-x86-target caveat.
- **`references/evasion.md`** — getting a command to *run* past a lab box's
  defenses: recognizing AMSI vs Constrained Language Mode vs AppLocker/WDAC vs
  on-access Defender from the symptom, and the smallest move past each.
- **Published write-ups: Bruno, FireFlow, Abducted** (`writeups/`) — redacted
  narratives for three retired machines (HTB AD Certifried; HTB Langflow→k8s;
  HTB Samba CVE-2026-4480 print-command injection).

### Changed
- **`SKILL.md` step 2** — service enumeration now mandates pinning the exact
  service version and actively hunting **CVEs and public PoCs on the web and
  GitHub** as a primary early activity (searchsploit misses recent CVEs); read
  the CVE/PoC for the mechanism before hand-rolling blind exploitation.
- **`references/ad.md`** — added a full **DACL edge table** (GenericAll/Write,
  WriteDacl/Owner, AddKeyCredentialLink, WriteSPN, AddMember, WriteDacl→DCSync)
  with the fastest tool per edge, **Shadow Credentials** and **targeted
  Kerberoast**, and a **Kerberos delegation** section (unconstrained/constrained/
  RBCD with a complete S4U chain and Bronze Bit).
- **`references/web.md`** — added SSTI per-engine payloads, **NoSQL injection**,
  **XXE** (incl. blind/OOB), a per-stack **deserialization** table, **prototype
  pollution**, **request smuggling**, **cache poisoning/deception**, CORS/CSRF and
  client-to-server chaining.
- **`references/services.md`** — new playbooks for SMTP/IMAP, rsync, Java
  RMI/JMX/JDWP, Tomcat/Jenkins/JBoss/WebLogic, Elasticsearch/Kibana/Mongo/
  Memcached/CouchDB, Zabbix/IPMI/VNC/X11, and Postgres/MSSQL RCE.
- **`references/privesc-windows.md`** — potato-variant selection guidance,
  SeManageVolume/SeBackup/SeDebug routes, DPAPI, LAPS/gMSA reads, UAC bypass, and
  a broader credential-store sweep.
- **`references/privesc-linux.md`** — Baron Samedit, sudo token reuse,
  writable-passwd/PATH-hijack/polkit/D-Bus quick classes; the container section
  now points to `containers.md`.
- **`references/kubernetes.md`** — secrets/etcd reads and the cloud-managed
  cluster (EKS/AKS/GKE) node-IMDS pivot; generic escapes deferred to
  `containers.md`.
- **`references/cracking.md`** — more hash shapes (DCC2, NetNTLMv1, Django, MySQL,
  LM, Kerberos preauth, PDF).
- **`references/pivoting.md`** — ligolo-ng (TUN route) and socat relay.
- **`references/llm-apps.md`** — inference-server exposure (Ollama/vLLM),
  LangChain template/`eval` sinks, and RAG document-poisoning as a class.
- **`SKILL.md`** — reference index and loop steps updated to route to the six new
  files at the right phase.

## [1.3.0] — 2026-08-02

Windows AD hardened-DC methodology, proven on a domain controller where every
remote relay path was closed. The escalation was a **local** Kerberos relay off a
DCOM trigger into an RBCD write, plus the Windows foothold ergonomics
(drivable shells, egress testing, file-system C2) that the run was missing.

### Added
- **Local Kerberos relay → RBCD** methodology in `references/ad.md`: the escalation
  for code execution on a hardened DC as a low-privilege account with no
  `SeImpersonate` and no ACLs, when every *remote* relay is dead (no egress, no
  `WebClient`, mandatory SMB/LDAP signing). Covers the local DCOM trigger, CLSID
  selection and its error codes, the `Certificate Service DCOM Access` signpost,
  `KrbRelayUp relay` + `getST` S4U, and the "don't kill the slow port-finding
  step" gotcha.
- **kerbrute** built into the image (from source — no upstream arm64 release) with
  userenum/spray/AS-REP usage in `references/ad.md` and a Kerberos (88) block in
  `references/services.md`.
- Windows foothold notes in `references/foothold.md`: driving a shell from a tmux
  listener (a backgrounded `nc` has no stdin), egress ground-truth testing,
  file-system C2 when TCP egress is filtered, and the app-local `hostfxr.dll`
  sideload arbitrary-write→RCE primitive. `.NET` zip-slip sink added to
  `references/source-review.md`.

### Changed
- Autonomy contract (`SKILL.md`): a genuine, post-enumeration dead end may be
  surfaced to the operator for a decision or steer — **operator in the loop** —
  with any outside knowledge declared in that engagement's ledger, exactly as
  recognition is declared, so shared results stay trustworthy.

## [1.2.0] — 2026-08-02

Kubernetes and LLM/agent platforms validated in the field. A single-node k3s box
fell through an unauthenticated Langflow flow-execution RCE, password reuse, an
MCP tool registry with a JWT `alg:none` bypass, and finally the kubelet exec API
reached through a `get nodes/proxy` service account into a privileged pod — a
chain the methodology had no coverage for at the time and now does.

### Added

- **`references/kubernetes.md`** — the biggest gap this release closes. Service
  account RBAC enumeration (`SelfSubjectRulesReview`/`AccessReview`), the
  node-side hunt for admin kubeconfigs, and the in-pod escalation path: how
  `get nodes/proxy` alone reaches the kubelet exec API (GET `/exec` returning
  *"Upgrade request required"* is authz passing, not a denial), finishing it over
  a stdlib WebSocket (`v5`→`v4` channel fallback), triaging pod specs for a
  privileged exec target, and distroless container escape by invoking the host
  loader to run the host's `nsenter`.
- **`references/llm-apps.md`** — flow/agent/MCP platforms (Langflow, Flowise,
  Dify, MCP servers) as an RCE-first target class: pulling `/openapi.json` and
  diffing a `security: None` build route against the public read it mirrors, the
  "public object that gets executed" pattern, JWT `alg:none` forgery, hard-coded
  secrets in app source, and the reminder to treat model/tool output as data.
- `references/privesc-linux.md` now hands off to `references/kubernetes.md` when a
  service account or a local cluster is present, rather than treating containers
  as a five-line afterthought.
- **`writeups/escape.md`** — the redacted Escape (sequel.htb) write-up:
  anonymous-SMB PDF credential → `xp_dirtree` coercion → NetNTLMv2 → WinRM →
  password in a backup SQL error log → AD CS ESC1 → pass-the-hash. Flags out, IPs
  and the recovered NT hash generalised.

### Changed

- **The engagement's operating contract now lives in the skill**, not only in the
  slash command. Invoking the `pwnloop` skill directly and running `/pwnloop`
  now behave identically — address-only start, one-line pre-flight confirmation,
  one-or-two-line phase updates, flags printed on sight. This removes the trap
  where picking the skill from the menu dropped the command's operator framing.

### Methodology

- Promoted five cross-engagement patterns into `memory/patterns.md`: read the
  process environment after a web RCE; forge `alg:none` when a service advertises
  it; diff `/openapi.json` for a `security: None` executor route; `get nodes/proxy`
  is kubelet exec; distroless escape via the host loader; and the reminder that a
  pinned-vulnerable version (sudo CVE-2025-32463) is not a usable exploit without
  its precondition.

## [1.1.0] — 2026-08-02

Windows and Active Directory validated in the field, and memory split so that a
clone's learnings and this repository stop competing for the same files.

### Added

- **Split memory.** `memory/patterns.md` stays upstream's curated set;
  `memory/local.md` is created at install and is where runs write. Same split
  for `docker/packages.local.txt`, installed after the shared list. Neither
  local file can conflict on `git pull`, because upstream never ships them.
  Promoting an entry into the shared set is now a pull request — which is also
  the first path for the methodology to improve from someone else's engagements.
- **`pwnloop ship`** — commits and pushes your learnings to your own remote,
  force-adding the two gitignored local files, refusing outright if engagement
  data is staged, and pointing out entries worth upstreaming.
- **Re-run handling.** An existing engagement directory is never written into —
  a repeat becomes `<addr>-2`. Runs of the same machine correlate by the
  hostname recon *discovered*, not by a name supplied up front, and a re-run
  records a `Replay` block: what memory short-circuited, and what stayed slow
  anyway. The second half is the part that says what to fix next.
- **Address-only invocation.** `/pwnloop` takes an IP and nothing else, and the
  skill will not ask what the machine is called. A well-known name returns its
  published chain before a port has been scanned; withholding it is the one
  control on recall an operator can enforce rather than trust. Recognition is
  declared in the ledger whenever it fires. See *Discovery discipline*.
- First Windows / Active Directory validation, against a retired DC. The AD
  methodology now has live-fire behind it, and the run surfaced two gotchas that
  are now documented in `references/ad.md` and `memory/patterns.md`:
  a Windows access token is fixed at logon (a just-granted group is invisible to
  the current session), and lab DCs run a reset job that reverts state — so
  add + grant + use must be chained in one window with fresh auth each step.
- `writeups/forest.md` — redacted write-up of the AD chain (AS-REP roast →
  Account Operators → Exchange `WriteDacl` on the domain → DCSync → PtH).
  Recovered NT hashes are generalised in published copies, a new redaction rule.
- AD patterns added to `memory/patterns.md`: AS-REP first, token immutability,
  NTLM-over-Kerberos on lab DCs, and `Account Operators` as a takeover group.
- AD CS validated against a live CA — `certipy find`/`req`/`auth` end to end,
  ESC1 to Domain Admin. The reference now lists the four settings to confirm in
  `certipy find` output rather than trusting its `[!] ESC1` tag, and treats
  revoking the issued certificate as part of cleanup, since a certificate
  survives a password reset for its full lifetime.
- `faketime` and `poppler-utils` added to the image. Both were being relied on
  by accident as transitive dependencies; an upstream change would have broken a
  run silently.
- New methodology from the same run: MSSQL at guest privilege as a coercion
  primitive (`xp_dirtree` and family), application error logs as a credential
  source (a password typed into a username field is logged verbatim), listing
  the system drive root as the first command after a Windows foothold, and a
  `foothold.md` section on capture tools that log nothing — UNC negative
  caching, and `pkill -f` matching its own shell.

### Fixed

- **Corrected wrong guidance about clock skew.** `references/ad.md` told the
  operator to run `ntpdate -u <dc>` when Kerberos failed. That cannot work: the
  container has no `CAP_SYS_TIME`, so `ntpdate` measures the offset and then
  fails to apply it. Following it would have blocked PKINIT entirely. The fix is
  `ntpdate -q` to measure and a `faketime` shim on the single command that needs
  it. Every remaining mention of `ntpdate -u` now explains why it fails instead
  of recommending it.

## [1.0.0] — 2026-08-01

First public release. Validated end to end against two retired Hack The Box
machines, both Linux (one easy, one medium).

### Added

- **Kali container** (`docker/`) built for the host's native architecture, with
  `NET_ADMIN` and `/dev/net/tun` so the lab VPN runs inside it and never touches
  the host routing table. A package with no build for the target architecture is
  logged to `/opt/skipped-packages.txt` rather than failing the image.
- **`bin/pwnloop`** — wrapper covering the container and VPN lifecycle:
  `build`, `up`, `down`, `sh`, `x`, `vpn`, `vpn-status`, `vpn-stop`, `status`,
  `flags`, `banner`.
- **`skills/pwnloop/SKILL.md`** — the engagement loop as a control structure:
  scope contract, autonomy rules, live flag reporting, the findings ledger,
  the nine-phase loop, mandatory cleanup, and the write-back step.
- **Methodology references** (14): recon, web, api, services, foothold,
  artifacts, source-review, cracking, privesc-linux, privesc-windows, ad,
  pivoting, reporting, writeup.
- **`memory/patterns.md`** — cross-engagement memory. The skill reads it before
  starting and must write to it before closing.
- **`commands/pwnloop.md`** — the `/pwnloop <ip> [name]` entry point.
- **`hooks/pre-commit`** — refuses commits containing flag-shaped strings,
  engagement paths, private key material or an attacker VPN address.
- **`writeups/`** — redacted, publishable write-ups for the two validation
  machines.
- **`.claude/settings.json`** — permission allowlist scoped to the wrapper.
- MIT licence.

### Known limitations

- The image builds from a rolling-release base with unpinned packages: resilient
  to upstream churn, but not bit-for-bit reproducible. Pinning the base by digest
  and freezing the package snapshot is the fix when reproducibility matters.
- At release, validated only against Linux targets. (Windows/AD validation
  landed shortly after — see 1.1.0.)
- Small sample, and no machine has defeated the loop yet — so its failure mode
  is still unobserved.

[Unreleased]: https://github.com/euriconicacio/pwnloop/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.6.0
[1.5.1]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.5.1
[1.5.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.5.0
[1.4.3]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.4.3
[1.4.2]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.4.2
[1.4.1]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.4.1
[1.4.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.4.0
[1.3.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.3.0
[1.2.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.2.0
[1.1.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.1.0
[1.0.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.0.0
