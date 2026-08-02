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

[Unreleased]: https://github.com/euriconicacio/pwnloop/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.1.0
[1.0.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.0.0
