# WebSSH Roadmap

WebSSH is a self-hosted SSH and file workspace. This roadmap explains the direction,
the current release focus, and the evidence behind completed work. It is not a release-date
promise or a replacement for issues, pull requests, and release notes.

Release status updated: **2026-10-05**, v2.5.0 at
[`07f4726`](https://github.com/bifrost0x/webssh/commit/07f472691e61eab6554dd6f75cf56fb8333964ba).
Check linked GitHub items for newer status.

## Product direction

- Keep terminals, files, commands, diagnostics, and notes aligned with the active server.
- Preserve explicit authentication, ownership, host-trust, network-policy and resource boundaries.
- Make the same workspace useful on mobile devices and multi-pane desktops.
- Keep deployment, upgrades, recovery and container publication verifiable and self-hosted.

These themes summarize the existing product and published release history; they do not
add new feature commitments.

## Now: v2.5.0 published, deployment acceptance remains explicit

[v2.5.0](https://github.com/bifrost0x/webssh/releases/tag/v2.5.0) delivers optional Warpgate support, workspace continuity,
host/command/mobile usability, tmux directory synchronization, paste/transcript fixes,
faster theme backgrounds and reviewed dependency updates. The
[release comparison](https://github.com/bifrost0x/webssh/compare/v2.4.0...v2.5.0) contains 17 merged PRs.

[Tag CI and native image publication](https://github.com/bifrost0x/webssh/actions/runs/37276528581) passed on `07f472691e61eab6554dd6f75cf56fb8333964ba`.
Both runtime architectures retain SBOM and provenance attestations. The release record is
[#248](https://github.com/bifrost0x/webssh/issues/248), and the
[v2.5.0 milestone](https://github.com/bifrost0x/webssh/milestone/11) is closed.

Publication was authorized with the reported real Warpgate, deployment canary,
upgrade/restore/rollback and applicable environment-specific acceptance still unverified.
These checks remain open in [#254](https://github.com/bifrost0x/webssh/issues/254); they are not counted as passed.
Warpgate remains disabled by default. No new feature release or date is committed.

## Next: choose from verified feedback

Select a small scope from reproducible bugs, user feedback and validated
security/dependency findings. State the benefit, priority reason and acceptance criteria in
an issue before assigning substantial work to the next milestone.

No additional feature release, date or large architecture migration is committed here.
Urgent security fixes may take a separate patch path rather than wait for a feature release;
follow [SECURITY.md](SECURITY.md) for private vulnerability reporting.

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

## How this is maintained

- [Project history](docs/project-history.md): what shipped, documented reasons and lessons.
- [Planning and release workflow](docs/project-planning.md): how issues, PRs and milestones fit together.
- [Milestones](https://github.com/bifrost0x/webssh/milestones): native release grouping, with eleven published-release milestones closed.
- [Retrospective mapping](docs/release-history.json): release/PR/issue membership, milestone numbers and backfill verification.

The native milestone backfill was applied on 2026-10-04: 185 items assigned and
verified. PR #98 was unavailable (HTTP 404) and is recorded as an exception in the
manifest. The 2026-10-05 release update adds PRs #249-#252 to v2.5.0, closes
release-readiness issue #248 and retains the operational acceptance follow-up in #254.

The historical mapping was reconstructed on 2026-10-03. It does not imply that these
milestones or this roadmap existed at the time. Actual GitHub milestone creation and
closure dates must remain unchanged; original publication dates are recorded as evidence.
Existing GitHub Projects are not replaced or reorganized by this roadmap.
