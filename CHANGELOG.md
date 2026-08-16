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

## [1.14.1] — 2026-08-16

Corrections. Set the confirmed difficulties on the write-ups published in 1.14.0:
Data **Easy**, 2Million **Easy**, Pterodactyl **Medium**, CCTV **Easy** (Logging was
already Medium) — in both the write-up headers and the `writeups/README.md` table.

## [1.14.0] — 2026-08-16

Five write-ups published (Data, 2Million, Pterodactyl, CCTV, Logging) plus a
methodology expansion from the runs behind them; the rooted-machines count moves
21 → 27 (`darkzeroreturns` is rooted but not retired — it counts, but never gets a
write-up while active). The through-line this cycle is **read the environment's own
hints, and enumerate as the principal you actually are**: Pterodactyl's `/changelog.txt`
and a MOTD "security notice" name the exact PEAR-LFI and udisks/PAM local-root chain;
Logging is a full AD path whose privesc was only visible once AD CS was enumerated
*as the foothold user* — a low-priv identity legitimately sees zero vulnerable
templates while the next user in an ops group sees a critical one.

### Added

- `references/adcs.md` — **enumerate AD CS as each principal you pivot to; ESC17 is a
  service-impersonation primitive.** Template enrollment is a per-identity ACL, so
  `certipy find -vulnerable` run as the wrong user yields a false "AD CS dead end" —
  re-run it as every user you land as (mint a TGT with Rubeus `tgtdeleg` when you only
  have code-exec). ESC17 (Server-Auth + enrollee-supplies-subject) plus a DNS write and
  an unpinned by-name TLS client (classically **WSUS**, where a DC is a *client*, not the
  deserialization server) = code execution as whatever consumes that service.
- `references/web.md` — **LFI→RCE via `pearcmd.php`** when PEAR is present and
  `register_argc_argv=On`: the query string becomes `argv`, `config-create` plants a
  stager, and the `<?=` open tag must arrive as literal bytes (send it over a raw socket).
- `references/privesc-linux.md` — the **unprivileged-userns / FUSE-OverlayFS SUID
  copy-up** class and the **udisks/polkit `allow_active`** local-root class, both often
  signposted by a `/var/spool/mail` or MOTD "security notice".
- `references/services.md`, `references/api.md` — Guacamole connection-store credential
  recovery, and the SAML signature-wrapping / IdP-as-superuser-pivot patterns.

### Published

- `writeups/{data,2million,pterodactyl,cctv,logging}.md` — flags redacted, addresses
  generalised, retired targets only.

## [1.13.0] — 2026-08-15

Two Linux boxes, both Medium, both about reading rather than reaching for a
scanner. **VariaType** is a font-processing chain: an exposed `.git` leaks a
credential, a single-pass `str_replace("../","")` in `download.php` is defeated by
`....//`, and the arbitrary read names the one `ReadWritePaths=` the service can
write — which turns a fontTools/FontForge/setuptools sequence of CVEs into root.
**Interpreter** self-reports Mirth Connect 4.4.0 unauthenticated, and everything
follows from that one version string: an XStream deserialization RCE
(CVE-2023-43208), the app's own database password, a PBKDF2 hash that only cracks
once the cracker's `ab64` encoding is right, a reused SSH password, and a
root-owned Flask service whose "safe" template runs `eval()` over attacker input
behind a character allow-list that `os` + `chr()` walk straight through.

### Added

- `references/web.md` — **a path-traversal filter must be probed across depth,
  not at one depth.** A single-pass `str_replace("../","")` leaves `....//`
  intact; but the number of `../` needed is the depth of the app's base directory,
  which you do not know, so one probe at the wrong depth is indistinguishable from
  a working filter. Sweep the depth for every traversal form before concluding.
  Plus: `os.path.join(dir, request.files[...].filename)` is a second, independent
  arbitrary write — Werkzeug does not sanitise the multipart filename unless you
  call `secure_filename`.
- `references/privesc-linux.md` — **a root service that `eval()`s filtered input;
  a character allow-list is not a sandbox.** The reasoning to beat it: find the
  double-templating sink (`eval(f"f'''{template}'''")`), read the allow-list for
  what it still permits rather than what it blocks, rebuild every forbidden byte
  from `chr()` and whatever the eval scope already imports (`os`), and prefer a
  side-effect payload since the response shows only the function's return value.
  A specific Flask/`notif.py` pattern is the example of the class, not the recipe.

### Published

- `writeups/variatype.md` — VariaType (Medium, Linux).
- `writeups/interpreter.md` — Interpreter (Medium, Linux).

## [1.12.0] — 2026-08-14

Principal, rooted in ~13 minutes, and the entries it produced are all about
reading rather than scanning. The engagement's decisive artifact was a response
header — `X-Powered-By: pac4j-jwt/6.0.3` — naming the component that decides
whether you are authenticated, with a version. Everything else followed from
pulling that thread: a published JWKS, an unsigned token inside an encrypted
envelope, an admin API that hands out an SSH password, and an SSH CA whose
private key is readable by the accounts that authenticate with it.

### Added

- `references/api.md` — **encrypted tokens (JWE): the envelope is not the
  authentication**. RSA encryption uses the *public* key, so a published JWKS
  lets anyone produce a decryptable token; the inner signature check is then
  frequently guarded by an attacker-controlled condition
  (`if (toSignedJWT(jwt) != null) verify(...)`), which an unsigned `PlainJWT`
  walks straight past. Includes how to hand-build the `alg: none` inner token
  (libraries refuse to emit it), how to wrap it, and the reminder to lift claim
  names and role strings from the app's own client JS rather than guessing.
  CVE-2026-29000 is cited as an example of the class, not as the recipe.
- `references/services.md` — **`sshd_config` drop-ins as attack surface.**
  `TrustedUserCAKeys` means certificates are accepted, so the question becomes who
  can read the CA's private key; the two conditions that decide whether a forged
  certificate works (no `AuthorizedPrincipalsFile`, and `PermitRootLogin
  prohibit-password` permitting root *by certificate*) are both readable in the
  config. Plus: check the key blob's cipher field for `none` before cracking a
  passphrase, and backdate certificate validity or clock skew reads as an
  untrusted CA.
- `references/privesc-linux.md` — **ask the filesystem what your groups grant.**
  `for g in $(id -Gn); do find / -group "$g"; done` — a non-default supplementary
  group gates a handful of paths that usually explain each other, which beats
  reasoning about what a group's name implies.

### Changed

- `docker/packages.local.txt` — added `python3-jwcrypto`, installed mid-run to
  build the JWE forgery.

### Published

- [`writeups/principal.md`](writeups/principal.md) — Medium / Linux. Auth bypass
  by forging an administrator session against a published public key, an admin
  API that returns a live SSH password, and an SSH certificate authority whose
  signing key is group-readable and unencrypted.

## [1.11.0] — 2026-08-14

One single-host run (Kobold), and the entries it produced are mostly about
*not* spending time. Three of the four unauthenticated CVEs that matched the
target's pinned version were inert for configuration reasons the advisories
cannot tell you, and the one that paid never became an exploit at all — it was a
port scanner. Meanwhile half an hour went into fuzzing a mystery root listener
that a two-minute elimination pass would have named as containerd. So this
release is a set of cheap discriminators to run *before* the expensive step.

### Added

- `references/llm-apps.md` — **MCP clients** as a target class, distinct from MCP
  servers. An inspector/playground/IDE bridge exists to spawn a process from
  caller-supplied config, so unauthenticated exposure is pre-auth RCE by design.
  Includes the counter-intuitive success signal: a protocol error
  (`MCP error -32000: Connection closed`) means your command *ran*, and walking
  the validation errors from an empty POST is a cheaper way to learn the request
  schema than reading the client bundle.
- `references/api.md` — **a talkative SSRF is a loopback port scanner**, with the
  three response states that make it precise (refused / HTTP status N / parse
  error naming the first byte). Sweep before you hold any credential; the service
  it uncovers is often where the foothold lives, while the app hosting the SSRF
  never gets exploited. Report it even when unexploited.
- `references/web.md` — **an app's persisted state file inside a writable data
  directory is code**. Rate limiters and counters that persist as PHP source get
  `require`d every request; directory write is enough to replace a root-owned
  `0640` file; the limiter runs *before* body validation; and the app rewrites it
  after each request, so treat it as one-shot and have the payload write results
  next to itself for reading through the shared mount.
- `references/privesc-linux.md` — **UID 0 on a localhost port means "root", not
  "interesting"**. Eliminate the box's own runtime daemons (containerd, dockerd,
  docker-proxy — all root, all Go, all in `ps`) before spending a wordlist, and
  stop treating a non-default 404 body as proof of a bespoke service.

### Changed

- `references/web.md` — vhost fuzzing now says to take the filter from a
  deliberately-wrong `Host:` first. Many stacks answer an unknown vhost with a
  **redirect**, so filtering on the correct vhost's body size matches everything;
  filter the code (`-fc 302`) instead.

### Fixed

- Corrected the recorded fix version for CVE-2026-41651 (PackageKit,
  "Pack2TheRoot"). The noble fix is **`1.2.8-2ubuntu1.5`**, not `-3ubuntu1.5` —
  the wrong string would have made a vulnerable host read as patched. Verified
  against Ubuntu's tracker.

### Published

- [`writeups/kobold.md`](writeups/kobold.md) — Easy / Linux. Unauthenticated
  MCPJam Inspector RCE (CVE-2026-23744) to `ben`, then PackageKit `InstallFiles`
  TOCTOU (CVE-2026-41651) to root, driven from `python3-gi` because the target
  has no compiler. Includes the dead ends in full: the UUID-gated Arcane env
  proxy, the empty PrivateBin store, and the containerd listener.

## [1.10.0] — 2026-08-10

Two single-host runs. Both reached root, and both taught the same lesson from
opposite ends: read the *whole* surface of the thing you already have before
reaching for a harder primitive. On Helix an unauthenticated OPC UA server let a
low-priv shell forge a reactor hazard and open a root maintenance window; on
DevArea a root log-reader that validated only the first symlink hop leaked root's
SSH key — while a fragile write-race in the *same* script nearly swallowed the run.

### Added
- **`references/services.md` — OPC UA (4840) OT/ICS playbook.** Enumerate every
  variable's *access level* (not just its value) to find the writable node; look
  for a read-only value that is *derived* from a writable one (a calibrated reading
  = raw sensor + attacker-writable offset), which lets you forge a condition the
  physical sensor never produced; then find the privileged consumer (a root
  "safety"/monitor daemon) that acts on it. Same class as an anonymous MQTT broker
  a root worker drains: an unauthenticated control-plane whose integrity a
  higher-privilege component trusts.
- **`references/api.md` — SOAP/JAX-WS services and the CXF MTOM file-read.** When
  the obvious inline-DTD XXE is refused (hardened Woodstox), pin the framework from
  `META-INF/maven/**/pom.properties` and attack a *different layer*: an Apache CXF
  MTOM message with `<xop:Include href="file:///…"/>` makes the server fetch the
  href itself (file read / SSRF) with no DTD involved, and an echoing operation
  returns the file inline — a clean, shell-independent read primitive.
- **`references/privesc-linux.md` — first-hop-only symlink validation is defeated
  by a symlink chain.** A root file-reader that inspects only a symlink's immediate
  target (and rejects `/`) but then `cat`s the path will follow a two-link chain:
  hop-1 an innocent relative name, hop-2 the real target (`/root/.ssh/id_*`). The
  entry also states the run's method lesson: enumerate every subcommand of a
  root-run tool and prefer a read/logic flaw to a fragile write race.
- **`writeups/helix.md`** (Medium, Linux/OT) — Apache NiFi 1.21.0 anonymous
  `execute-code` RCE → operator SSH key in the NiFi support bundle → OPC UA
  calibration spoof opens a root maintenance window → `sudo helix-maint-console`.
- **`writeups/devarea.md`** (Medium, Linux) — anonymous FTP → CXF 3.2.14 MTOM file
  read (CVE-2022-46364) → Hoverfly middleware RCE → forged Flask session + a
  `$()`-through-blacklist command injection → root via the chained-symlink read.

### Changed
- Track record in `README.md`: 14 → 17 machines rooted, and the category list now
  includes OT.

## [1.9.0] — 2026-08-08

A single-host run that failed three times at the same three seams — a normalised
traversal that read as patched, a hash format that read as an uncrackable
password, and a sudo rule that read as restrictive. All three are cases where the
tool's *silence* was mistaken for a negative result.

### Added
- **`references/web.md` — path traversal in the URL path needs `--path-as-is`.**
  When the sink is a static/plugin/asset route rather than a parameter, `curl`
  and most HTTP libraries collapse `..` client-side, so a live vulnerability
  answers 404 and the run moves on. Also: prioritise the app's own state store
  over `/etc/passwd` (the database and config hold the hashes, API keys and the
  encryption key), read a stock config *because* an all-commented one proves the
  documented default key is in use, and recognise two structural limits instead
  of retrying them — a read bounded by a container's namespace, and a
  size-declaring handler that returns `/proc` as empty because procfs reports
  `st_size` 0.
- **`references/cracking.md` — application hash stores.** No `*2john` tool
  produces the format an app's own `user` table stores; reconstruct john's syntax
  from the hashing code (KDF, iterations, salt column, output length). The two
  failures both look exactly like "not in the wordlist": adapted-base64 encoding,
  and a digest longer than the format loads — john's `PBKDF2-HMAC-SHA256` takes
  32 bytes and says only `No password hashes loaded`. A longer PBKDF2 digest can
  be truncated, because the derivation is block-concatenated. **Validate the
  pipeline with a control hash of a password you chose before believing any
  negative result.**
- **`references/privesc-linux.md` — a trailing `*` in a sudo rule grants the
  binary's entire flag surface.** Read the rule as `sudo` implements it: any
  option is in scope, including the ones that change what privilege the work runs
  with (`--privileged`, `-u 0`, `-v /:/host`; `-o`/`-f`/`--config` write or load
  code; `-e`/`-c`/`--eval`). The escalation is a documented feature of the
  allowed binary, so nothing looks anomalous — name the wildcard as the
  vulnerability, not the runtime.
- **`references/privesc-linux.md` — map each localhost listener to its owning
  UID.** `hidepid` blinds `ps`, but `/proc/net/tcp` still carries the socket
  owner in field 8. A stack of daemons owned by UID 0 means any command sink in
  one of them is a *root* sink. Two own-goals turn such a daemon's "secret" into
  a public value — a stored credential hash accepted as the signing key, and a
  cluster token that doubles as an API bypass — after which the escalation is the
  config-as-command-sink (event hooks, `on_*`, notification "run a command") plus
  the daemon's own synchronous trigger so you don't wait on a natural event.

## [1.8.3] — 2026-08-05

### Added
- **`references/services.md` — a blocked precondition is a cue, not a dead end.**
  An approval gate, a missing role, a patched sink or an auth path with no
  approver means re-enumerating the version's *other* CVEs for a sibling with a
  different trigger.
- **`references/pivoting.md` — pivot transport reliability.** Multi-RPC
  operations (DCSync, registry `SaveKey` backups) drop through a SOCKS proxy as
  `INVALID_HANDLE`; prefer a stable SSH local-forward, keep the SMB receive host
  in-segment, and space retries around RemoteRegistry stalls.

## [1.8.2] — 2026-08-05

### Fixed
- **The README never said the kit does more than one machine.** Campaign mode
  shipped in 1.7.0 and the intro still described a single-host tool, while the
  campaign section carried "Unreleased, on the `v2-campaign` branch" — in a
  published README, naming a branch that no longer exists. The intro now states
  both scales and which version brought the second, and the banner stops calling
  itself a lab-*machine* loop.
- The banner's tagline is padded with `printf %-58s`, which counts bytes rather
  than columns, so a multi-byte dash in the art shifts the frame. ASCII only in
  that string.

## [1.8.1] — 2026-08-05

### Fixed
- **A campaign that was never named now says so.** Asking the operator for the
  lab's name and renaming the directory is the last step of a campaign, and the
  easiest one to skip — by then the flags are in and the run feels finished,
  which is exactly what happened on the first one. A campaign still named after
  its entry point while holding flags has almost certainly not closed out, so
  the dashboard says so every time it prints.
- **`references/pivoting.md` had tilted toward campaigns.** It is shared by both
  skills, but the multi-host rewrite left campaign-only instructions in the base
  path — including `pwnloop route add`, which *errors out* when no campaign is
  current, and a staging directory that only exists under `campaigns/`. A single
  machine following the reference would have hit both. Pivoting on one host —
  reaching a service bound to `127.0.0.1`, or a second interface visible only
  from inside — is the ordinary case again, and campaign registration is marked
  as the addition it is.
- The same file was still described in the skill's reference list by
  its pre-1.7.0 contents. The file had been rewritten for multi-hop labs; the
  one-line summary an agent reads to decide whether to open it had not.

## [1.8.0] — 2026-08-05

The first campaign run to completion: a mini Pro Lab, three hosts, four flags.
What follows is what it changed — the lab's own path is not here and will not be,
since a Pro Lab never retires.

Two capability gaps it exposed are worth naming, because both had been invisible
while the loop only ever ran against single machines: the reference set had
nothing on **deployment infrastructure**, and nothing on **operating through a C2
framework** — which is how a modern internal engagement actually moves.

### Added

- **`references/devops.md`** — configuration-management and deployment platforms
  (Puppet, Chef, Salt, Ansible, SCCM) as the highest-value internal target: they
  are authenticated APIs whose purpose is to run code as root or SYSTEM on every
  node they manage. Covers enumerating them as an API rather than a web server;
  mutual TLS where the client certificate sits on every managed host; why
  impersonating another node fails by design and driving an agent you already own
  succeeds instead; both directions of attack; that a hung master may be
  *defective* rather than defended, so repairing it can be a necessary step; and
  the heavier cleanup obligation that comes with a platform that re-applies
  changes on a schedule.
- **`references/c2-ops.md`** — driving a framework rather than a shell. An
  operator configuration file is a credential and a team-server port is a login
  prompt. Every `execute` is a fresh process, so authentication does not persist
  between calls and must be established in-call or through an impersonation
  primitive. Console parsers mangle nested quoting — encode the payload instead
  of fighting them. In-band SOCKS is for control traffic, never bulk: stage
  transfers inside the segment and let the target pull locally. And when every
  implant dies at once, read it as an environment event and do not hammer the
  fallback.
- **`references/ad.md`: read the failure code, not just the failure.** Windows
  error 5 means the credential is *valid* and merely unauthorised, while 1326
  means it is wrong — treating the first as a failure discards a confirmed
  account. Extended to Kerberos pre-auth codes and to SSH, where a public key
  rejected before a signature is requested is not a lockout, and where centrally
  distributed keys make access depend on the directory's health.
- **`references/privesc-windows.md`: when LSASS cannot be read.** The registry
  route needs only backup rights, and two of its three payloads are routinely
  overlooked — cached domain credentials naming the accounts that matter on that
  host, and LSA secrets holding the *cleartext* passwords of service accounts.
  Also: when an NT hash will not crack, a DPAPI machine triage often has the same
  account in plaintext, because scheduled tasks and services store credentials in
  a form the system can use.
- **`references/pivoting.md`: bulk transfer does not belong in the tunnel.**
  Large writes over a proxy corrupt or stall, and the symptom reads as a broken
  technique rather than a broken transport.
- **`labs.md`** — the first results row, with the platform's completion
  certificate as the verification.

## [1.7.0] — 2026-08-05

### Campaign mode — multi-host labs

Everything below targets a *network* rather than a host: an HTB Pro Lab, an AD
range, any engagement where most of the targets are unreachable until another one
is owned and the work outlives a single context window many times over.

The single-host loop is unchanged and becomes the inner loop.

**Added**

- `skills/pwnloop-lab/` — the outer loop: frontier-based target selection,
  the resume protocol, credential handling at lab scale, per-host delegation, and
  the Pro Lab publication rule (no publishable write-up — Pro Labs never retire).
  Skill and command share a name, as `pwnloop` and `/pwnloop` do; two names for
  one capability read as two capabilities.
- `commands/pwnloop-lab.md` — `/pwnloop-lab <entry-ip|entry-cidr>` and
  `/pwnloop-lab resume`. **The lab's name is not an argument**: the directory is
  derived from the entry point (`campaigns/10-10-110-5/`), `campaigns/.current`
  is the handle, and `campaign rename` runs at the end — the same trade the
  single-host loop makes with machine names, for the same recall reason.
- Single-host entry points, the common Pro Lab shape: phase 0 is an ordinary
  single-host engagement, the campaign begins at the first shell (interfaces,
  routes, trusts before local escalation), and resume verifies the entry host
  before any route, since it is the first hop of every chain.
- `pwnloop backup [--full]` — an encrypted archive of everything git does not
  track. The instinct that none of it needs backing up holds for most of the
  bytes, since an engagement's durable half is its published write-up, and fails
  for exactly the two things with no replication path: `memory/local.md`, which
  is the whole second loop, and `campaigns/`, which by design produces no
  publishable artifact and is therefore its own only record. `vpn/` is never
  included — re-downloadable, and the one thing whose leak costs something.
  AES-256 with PBKDF2, plus a plaintext digest beside the archive because
  `openssl enc` gives confidentiality and no integrity. Refuses to write inside
  the repository, where an archive of flags and loot is one `git add -A` from
  being committed.
- `campaign checkpoint` — a session is hours, a lab is longer. The state file
  records what is true; the checkpoint records what you were in the middle of and
  what you would have done next, which is the part that cannot be inferred.
  `resume` prints it first.
- `references/delegation.md` — the per-host subagent brief and the structured
  receipt it must return, plus what is never delegated (scope calls, cleanup,
  methodology write-back). Context, not time, is the scarce resource on a
  twenty-host lab; free-form briefs produce summaries that cannot be merged.
- `bin/lib/campaign.sh` — the state store. `campaign`, `host`, `cred`, `try`,
  `route`, `flag` and `lead` subcommands write `campaigns/<lab>/campaign.json`
  and re-render `network.md` after every mutation. The CLI is the only writer:
  on a twenty-host lab, free-form state edits drift within hours.
- Credential matrix — every spray result recorded, `try next` suggests only
  untried (credential, host, service) triples, and a `locked` result removes that
  credential from all future suggestions. Lockout is the one irreversible
  mistake available on a hardened lab.
- Route registry with canaries — `route check` proves a tunnel still carries
  traffic instead of trusting the state file. A dead tunnel is indistinguishable
  from a hardened target until you test it.
- Container: ligolo-ng proxy and agents (linux + windows), chisel for windows,
  static socat, SharpHound, Rubeus, Certify, Seatbelt, SharpUp, mimikatz,
  RunasCs, GodPotato, PowerView/PowerUp, `mitm6`, `sshuttle`, `bloodhound-ce`.
  Release assets are resolved through the GitHub API at build time
  (`docker/fetch-release.sh`) rather than pinned URLs that rot silently.
- `/campaigns` bind mount; `pwnloop up` warns when an older container lacks it.

**Fixed** — from the first live Pro Lab run

- **The ledger's event table was never written.** Mutations updated
  `campaign.json` and re-rendered `network.md`, so an operator reading both saw a
  snapshot with no history and a ledger that was empty apart from checkpoints —
  which reads, correctly, as "nothing is being persisted". Every mutation now
  appends one row (host discovered, status change, credential, successful or
  locked authentication, pivot, flag), so the timeline is a side effect of
  recording state rather than a document someone must remember to maintain.
  `campaign backfill` reconstructs it from the state file's timestamps for a
  campaign that ran without it.
- **Per-host ledgers were never created.** The skill required
  `hosts/<ip>/FINDINGS.md` and nothing made one, so host detail existed only as
  raw scan output. `host add` now scaffolds the directory and the ledger.
- **An empty credential matrix was invisible.** A campaign can accumulate
  credentials while recording no attempts, which silently disables the one
  mechanism that prevents re-spraying and lockouts. `campaign status` now says so
  loudly while both conditions hold.
- **`awk -v` ate backslashes** in ledger rows, turning `NT AUTHORITY\SYSTEM` into
  `NT AUTHORITYSYSTEM` — corruption aimed squarely at `DOMAIN\user`, the most
  common string in an AD campaign. Rows now pass through the environment.
- `references/pivoting.md` documented `/opt/static/ligolo-proxy`, which the image
  never installed. Rewritten for multi-hop labs: mechanism selection, double
  pivots, non-interactive proxy control, agent delivery, discovery from inside a
  host, and a tunnel-recovery order for after a lab reset.
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

[Unreleased]: https://github.com/euriconicacio/pwnloop/compare/v1.12.0...HEAD
[1.12.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.12.0
[1.11.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.11.0
[1.10.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.10.0
[1.9.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.9.0
[1.8.3]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.8.3
[1.8.2]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.8.2
[1.8.1]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.8.1
[1.8.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.8.0
[1.7.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.7.0
[1.6.1]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.6.1
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
