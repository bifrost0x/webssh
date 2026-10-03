# WebSSH Roadmap

WebSSH is a self-hosted SSH and file workspace. This roadmap explains the direction,
the current release focus, and the evidence behind completed work. It is not a release-date
promise or a replacement for issues, pull requests, and release notes.

Planning baseline: **2026-10-03**, commit
[`dc3d9bf`](https://github.com/bifrost0x/webssh/commit/dc3d9bf26f57cbeb440227afe13f9635c4d9f258).
Check the linked GitHub items for newer status.

## Product direction

- Keep terminals, files, commands, diagnostics, and notes aligned with the active server.
- Preserve explicit authentication, ownership, host-trust, network-policy and resource boundaries.
- Make the same workspace useful on mobile devices and multi-pane desktops.
- Keep deployment, upgrades, recovery and container publication verifiable and self-hosted.

These themes summarize the existing product and published release history; they do not
add new feature commitments.

## Now: consolidate the post-2.4 changes

**Proposed next release: v2.5.0.** No release date is committed. Scope and version remain
subject to maintainer review. The latest published release at this baseline is
[v2.4.0](https://github.com/bifrost0x/webssh/releases/tag/v2.4.0).

| Outcome | Implementation state at the baseline | Remaining delivery work |
|---|---|---|
| Optional Warpgate gateway authentication | [#238](https://github.com/bifrost0x/webssh/pull/238) merged; request [#237](https://github.com/bifrost0x/webssh/issues/237) closed | Final-candidate real-protocol acceptance; earlier evidence is revision-specific |
| Workspace continuity and tmux directory synchronization | [#231](https://github.com/bifrost0x/webssh/pull/231), [#233](https://github.com/bifrost0x/webssh/pull/233), [#234](https://github.com/bifrost0x/webssh/pull/234), [#235](https://github.com/bifrost0x/webssh/pull/235), [#236](https://github.com/bifrost0x/webssh/pull/236) merged | Focused multi-session and mobile canary |
| Correct paste input and saved transcripts | [#239](https://github.com/bifrost0x/webssh/pull/239), [#241](https://github.com/bifrost0x/webssh/pull/241) merged | Verify paste/control input and transcript behavior on the candidate |
| Clearer connection review and file actions | [#242](https://github.com/bifrost0x/webssh/pull/242) merged | Connection/key review and file-workspace smoke tests |
| Reviewed dependency and repository maintenance | [#232](https://github.com/bifrost0x/webssh/pull/232), [#243](https://github.com/bifrost0x/webssh/pull/243), [#246](https://github.com/bifrost0x/webssh/pull/246), [#247](https://github.com/bifrost0x/webssh/pull/247) merged | Fresh exact-candidate CI and both native image scans |

All of these changes are **merged but not included in the v2.4.0 tag**.
The [fixed-baseline comparison](https://github.com/bifrost0x/webssh/compare/v2.4.0...dc3d9bf26f57cbeb440227afe13f9635c4d9f258)
contains 13 merged PRs. Baseline [CI and native image publication](https://github.com/bifrost0x/webssh/actions/runs/37064319620)
passed; this does not complete every deployment-specific acceptance check.

The open [release-readiness issue #248](https://github.com/bifrost0x/webssh/issues/248)
is the delivery gate. It remains open until candidate validation, release publication,
and versioned-image verification have evidence. A milestone is not shipped merely because
its implementation PRs are merged.

## Next: choose from verified feedback

After this release, select a small scope from reproducible bugs, user feedback and validated
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

## How this is maintained

- [Project history](docs/project-history.md): what shipped, documented reasons and lessons.
- [Planning and release workflow](docs/project-planning.md): how issues, PRs and milestones fit together.
- [Milestones](https://github.com/bifrost0x/webssh/milestones): native release grouping, when configured.
- [Retrospective mapping](docs/release-history.json): verified release/PR/issue membership and prepared milestone descriptions.

The historical mapping was reconstructed on 2026-10-03. It does not imply that these
milestones or this roadmap existed at the time. Actual GitHub milestone creation and
closure dates must remain unchanged; original publication dates are recorded as evidence.
Existing GitHub Projects are not replaced or reorganized by this roadmap.
