# WebSSH Roadmap

WebSSH is a self-hosted SSH and file workspace. This roadmap explains the direction,
the current release focus, and the evidence behind completed work. It is not a release-date
promise or a replacement for issues, pull requests, and release notes.

Release status updated: **2026-11-23**, [v3.3.0](https://github.com/bifrost0x/webssh/releases/tag/v3.3.0) at
[`8b7601e`](https://github.com/bifrost0x/webssh/commit/8b7601ea9bddc4fde2c80b1e1ba65b319cf93a2f).
Check linked GitHub items for newer status.

## Product direction

- Keep terminals, files, commands, diagnostics, and notes aligned with the active server.
- Preserve explicit authentication, ownership, host-trust, network-policy and resource boundaries.
- Make the same workspace useful on mobile devices and multi-pane desktops.
- Keep deployment, upgrades, recovery and container publication verifiable and self-hosted.

These themes summarize the existing product and published release history; they do not
add new feature commitments.

## Now: WebSSH 3.3 published

The [3.3.0 release notes](docs/releases/v3.3.0.md) cover an optional Herdr
integration for agent overviews and a Herdr session mode, a password reset from
the host for local accounts, sign-in and session hardening, SFTP and editor
fixes and the Python 3.15 runtime. The scope comes from changes merged since
v3.2.0 and is recorded in the closed
[v3.3.0 milestone](https://github.com/bifrost0x/webssh/milestone/17).

[Tag CI and native image publication](https://github.com/bifrost0x/webssh/actions/runs/45263874128) passed on `8b7601ea9bddc4fde2c80b1e1ba65b319cf93a2f`.
Linux AMD64 and ARM64 images retain SPDX SBOM and SLSA provenance; the immutable
digest is in the release notes and [#367](https://github.com/bifrost0x/webssh/issues/367).
There is no database schema change, so 3.2.0 can run on the same volumes.
Automated gates do not certify every deployment.

## Published: WebSSH 3.2

The [3.2.0 release notes](docs/releases/v3.2.0.md) cover an Unraid Community
Apps template, read-only application code in the image, custom-UID recovery
volumes that survive container recreation and jump host management from route
settings. The scope comes from changes merged since v3.1.0 and is recorded in the
closed [v3.2.0 milestone](https://github.com/bifrost0x/webssh/milestone/16).

[Tag CI and native image publication](https://github.com/bifrost0x/webssh/actions/runs/43699318358) passed on `5c5c8edd53ca547d32add20edef5bc3292b526cf`.
Linux AMD64 and ARM64 images retain SPDX SBOM and SLSA provenance; the immutable
digest is in the release notes and [#347](https://github.com/bifrost0x/webssh/issues/347).
There is no data format change, so 3.1.0 can run on the same volumes. The
Community Apps listing needs acceptance on a real Unraid server and the
submission scan. Automated gates do not certify every deployment.

## Published: WebSSH 3.1

The [3.1.0 release notes](docs/releases/v3.1.0.md) cover per-host SOCKS5 proxy
routes, automation through saved jump hosts, browser login management,
workspace presets, a task-first overview, the in-app version display, a stricter
script policy, restore hardening and dependency updates. The scope comes from
changes merged since v3.0.0 and is recorded in the closed
[v3.1.0 milestone](https://github.com/bifrost0x/webssh/milestone/15).

[Tag CI and native image publication](https://github.com/bifrost0x/webssh/actions/runs/43615783301) passed on `4eac73cbc319206bce7887e8dba0643a8b0c7ad5`.
Linux AMD64 and ARM64 images retain SPDX SBOM and SLSA provenance; the immutable
digest is in the release notes and [#338](https://github.com/bifrost0x/webssh/issues/338).
Data used by 3.1 must not be opened with 3.0.0; roll back by restoring the
pre-upgrade volumes. Automated gates do not certify every deployment.

## Published: WebSSH 3.0

Version 3 combines a customizable dashboard and SSH topology, a selectable
start page and classic overview, consistent host and credential management,
and integrated automation with editable templates, command sets, schedules
and bounded run logs. Existing themes and terminal-centered workflows remain.

Saved passwords and automation are administrator-controlled and disabled by
default. Portable backups exclude stored passwords and SSH private keys;
operators must preserve a separate trusted recovery source for these secrets.
See the [release notes](docs/releases/v3.0.0.md) and the
[version 3 guide](docs/webssh-3.md) for upgrade behavior.

[Tag CI and native image publication](https://github.com/bifrost0x/webssh/actions/runs/42480130060) passed on `c6ecb87c23a1b9369b1534770f248df4a6994933`.
Linux AMD64 and ARM64 images retain SPDX SBOM and SLSA provenance. The immutable
image digest and upgrade precautions are recorded in the release notes.
Automated gates do not certify every deployment's identity provider, device,
upgrade or recovery setup.

## Next: verified feedback and security maintenance

Prioritize reproducible bugs, compatibility feedback and security updates.
Security fixes may take a separate patch path; follow [SECURITY.md](SECURITY.md)
for private vulnerability reporting. Historical release evidence below does
not certify every operator's deployment.

## Later: proposals are not promises

Keep exploratory integration and architecture proposals in
[Discussions](https://github.com/bifrost0x/webssh/discussions) until scope and constraints
are reviewed. The PostgreSQL proposal in [#62](https://github.com/bifrost0x/webssh/issues/62),
for example, was converted to a discussion; its closure is not evidence of PostgreSQL support.
An external database alone would not solve process-local SSH state or make multi-worker/HA
deployment supported. Do not promote an idea into a promised release by listing it here.

## Completed direction

| Stage | Delivered focus |
|---|---|
| [v1.0.0](https://github.com/bifrost0x/webssh/releases/tag/v1.0.0) | First official terminal/SFTP, tmux, multi-user and Docker baseline |
| [v1.1.0](https://github.com/bifrost0x/webssh/releases/tag/v1.1.0) | Threaded runtime, modern identity, isolation, backup/restore and supply-chain gates |
| [v1.2.0](https://github.com/bifrost0x/webssh/releases/tag/v1.2.0) - [v1.3.0](https://github.com/bifrost0x/webssh/releases/tag/v1.3.0) | Active-session diagnostics, navigation, commands, host organization and key maintenance |
| [v2.0.0](https://github.com/bifrost0x/webssh/releases/tag/v2.0.0) | Authentication assurance and responsive contextual workspace |
| [v2.1.0](https://github.com/bifrost0x/webssh/releases/tag/v2.1.0) | Opt-in encrypted SMB and post-redesign workflow fixes |
| [v2.2.0](https://github.com/bifrost0x/webssh/releases/tag/v2.2.0) - [v2.2.1](https://github.com/bifrost0x/webssh/releases/tag/v2.2.1) | Terminal-first mobile, GitHub authentication and focused touch-scrolling correction |
| [v2.3.0](https://github.com/bifrost0x/webssh/releases/tag/v2.3.0) | Mobile/input, account-linking, notes/transfers and validated security remediation |
| [v2.4.0](https://github.com/bifrost0x/webssh/releases/tag/v2.4.0) | Responsive high-output multi-session recovery, directory sync and verified image promotion |
| [v2.5.0](https://github.com/bifrost0x/webssh/releases/tag/v2.5.0) | Optional Warpgate, workspace continuity, host/command/mobile usability, terminal correctness and faster backgrounds |
| [v2.6.0](https://github.com/bifrost0x/webssh/releases/tag/v2.6.0) | Redesigned windows/workspace, trusted hosts, reviewable server/file actions, opt-in chmod, local fonts and startup improvements |
| [v2.7.0](https://github.com/bifrost0x/webssh/releases/tag/v2.7.0) | SSH PAM MFA, explicit tmux folder sync, file/command UX, theme-aware branding, storage hardening and Apache 2.0 |
| [v3.0.0](https://github.com/bifrost0x/webssh/releases/tag/v3.0.0) | Terminal-centered workspaces, status-first overview, discovery, automation, saved credentials and a per-account tour |
| [v3.1.0](https://github.com/bifrost0x/webssh/releases/tag/v3.1.0) | SOCKS5 proxy routes, automation through jump hosts, browser login management, workspace presets and script-policy/restore hardening |
| [v3.2.0](https://github.com/bifrost0x/webssh/releases/tag/v3.2.0) | Unraid template, read-only application code, custom-UID recovery volumes and jump host management from route settings |
| [v3.3.0](https://github.com/bifrost0x/webssh/releases/tag/v3.3.0) | Optional Herdr integration, password reset from the host, sign-in and session hardening, SFTP and editor fixes and Python 3.15 |

## How this is maintained

- [Project history](docs/project-history.md): what shipped, documented reasons and lessons.
- [Planning and release workflow](docs/project-planning.md): how issues, PRs and milestones fit together.
- [Milestones](https://github.com/bifrost0x/webssh/milestones): native release grouping, with every published-release milestone closed.
- [Retrospective mapping](docs/release-history.json): release/PR/issue membership, milestone numbers and backfill verification.

The native milestone backfill was applied on 2026-10-04: 185 items assigned and
verified. PR #98 was unavailable (HTTP 404) and is recorded as an exception in the
manifest. The 2026-10-05 release update adds PRs #249-#252 to v2.5.0, closes
release-readiness issue #248 and recorded the then-open operational follow-up #254.
The 2026-10-23 v2.6.0 update adds 24 PRs and three implementation-linked issues,
closes release record #289 and milestone 12, and tracks current deployment acceptance in #288.
On 2026-11-14 the missing v2.7.0 and v3.0.0 milestones were created from the
manifest, assigned their first-included PRs and issues, and closed; the open
v3.1.0 milestone held the work merged since v3.0.0 and closed with the release.
On 2026-11-15 milestone 16 was created for v3.2.0, assigned the PRs first
included after v3.1.0 and closed with the release. On 2026-11-23 milestone 17
was created for v3.3.0, assigned the PRs and issues first included after v3.2.0
and closed with the release.

The historical mapping was reconstructed on 2026-10-03. It does not imply that these
milestones or this roadmap existed at the time. Actual GitHub milestone creation and
closure dates must remain unchanged; original publication dates are recorded as evidence.
Existing GitHub Projects are not replaced or reorganized by this roadmap.
