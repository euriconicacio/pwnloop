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
- Validated only against Linux targets so far. Windows and Active Directory
  references are written but not yet exercised against a live machine.
- Two machines is two data points, and neither defeated the loop — so its
  failure mode is still unobserved.

[Unreleased]: https://github.com/euriconicacio/pwnloop/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/euriconicacio/pwnloop/releases/tag/v1.0.0
