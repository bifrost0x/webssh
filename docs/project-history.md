# WebSSH Project History

This retrospective explains what shipped and why the documented changes mattered.
It is reconstructed from public releases, PR descriptions, issue links and Git ancestry,
not from an original project plan. Reconstruction date: **2026-10-03**.

## Reading the evidence

- **Delivered:** the published tag contains the implementation's merge commit.
- **Documented reason:** a source explicitly describes the problem, root cause or goal.
- **Retrospective lesson:** an interpretation for future planning, not a claim about a
  decision that was documented at the time.
- Historical validation is evidence reported in the linked items, not tests rerun today.
  A historical release does not prove acceptance on every operator's real environment.

Release dates below are GitHub publication dates. They are not reconstructed deadlines.
Backfilled milestone creation/closure metadata must reflect the actual backfill operation.

## Before the first official release

The available Git history starts on **2026-01-23** with
[`2fcd38a`](https://github.com/bifrost0x/webssh/commit/2fcd38ad12cc1cf6d36563aace320ecb8a94e040).
The initial commit mentions `v1.0.0`, but that message is not a published GitHub Release.
The first official published release is **v1.0.0 on 2026-07-23**.

Early work already mixed security fixes, dependency updates and usability:
[#5](https://github.com/bifrost0x/webssh/pull/5) hardened logging, passwords, profiles and
network controls; [#20](https://github.com/bifrost0x/webssh/pull/20) addressed SSRF, login
timing, upload limits and a Socket.IO dependency issue;
[#36](https://github.com/bifrost0x/webssh/pull/36) added persistent tmux, replay and scrollback.
These belong to the first official release baseline, not invented pre-1.0 release milestones.

## Published release stages

| Release / published | Delivered outcome | Documented problem or purpose | Verified merged PRs first shipped here |
|---|---|---|---:|
| [v1.0.0](https://github.com/bifrost0x/webssh/releases/tag/v1.0.0) / 2026-07-23 | Multi-user terminal/SFTP workspace, tmux, keys, profiles and Docker deployment | Give homelabs and small teams browser access without an external service | 35 |
| [v1.1.0](https://github.com/bifrost0x/webssh/releases/tag/v1.1.0) / 2026-08-03 | Native threaded runtime, passkeys/OIDC, bounded operations, trust/isolation, backup/restore and supply-chain gates | [#60](https://github.com/bifrost0x/webssh/pull/60): the old dependency/runtime set constrained security updates and failure boundaries needed hardening; [#71](https://github.com/bifrost0x/webssh/pull/71): recoverable native admin backup/restore | 10 |
| [v1.2.0](https://github.com/bifrost0x/webssh/releases/tag/v1.2.0) / 2026-08-11 | Active-session Linux telemetry, SFTP, diagnostics, host groups/favorites and navigation | Keep server administration in one focused session workspace; [#81](https://github.com/bifrost0x/webssh/pull/81) addresses the navigation requests [#75](https://github.com/bifrost0x/webssh/issues/75), [#76](https://github.com/bifrost0x/webssh/issues/76), [#77](https://github.com/bifrost0x/webssh/issues/77) | 13 |
| [v1.3.0](https://github.com/bifrost0x/webssh/releases/tag/v1.3.0) / 2026-08-12 | Safe active-session command insertion, host ordering and in-place key replacement | Make recurring administration faster and saved connections more predictable; [#94](https://github.com/bifrost0x/webssh/pull/94), [#96](https://github.com/bifrost0x/webssh/pull/96), [#97](https://github.com/bifrost0x/webssh/pull/97), [#98](https://github.com/bifrost0x/webssh/pull/98) | 6 |
| [v2.0.0](https://github.com/bifrost0x/webssh/releases/tag/v2.0.0) / 2026-08-21 | Responsive workspace and Security/Admin Centers; TOTP, LDAP/OIDC and action-bound assurance | [#124](https://github.com/bifrost0x/webssh/pull/124): protected changes need assurance appropriate to the account and sensitive action; contextual tools must follow the active session | 16 |
| [v2.1.0](https://github.com/bifrost0x/webssh/releases/tag/v2.1.0) / 2026-08-24 | Opt-in encrypted SMB sources and cross-source transfers, versioned Wiki, SFTP/theme/login fixes | [#140](https://github.com/bifrost0x/webssh/pull/140): extend the file workspace without weakening ownership, target allowlisting and mutation boundaries; [#132](https://github.com/bifrost0x/webssh/pull/132), [#136](https://github.com/bifrost0x/webssh/pull/136): correct post-2.0 regressions | 9 |
| [v2.2.0](https://github.com/bifrost0x/webssh/releases/tag/v2.2.0) / 2026-08-30 | Terminal-first mobile/tablet UI, managed GitHub authentication, unified management, MFA/file hardening | [#163](https://github.com/bifrost0x/webssh/issues/163)/[#164](https://github.com/bifrost0x/webssh/pull/164): Android touch scrolling was unusable; [#154](https://github.com/bifrost0x/webssh/issues/154)/[#158](https://github.com/bifrost0x/webssh/pull/158): consolidate management workspaces | 15 |
| [v2.2.1](https://github.com/bifrost0x/webssh/releases/tag/v2.2.1) / 2026-08-30 | Focused normal-history scrolling correction and direct mobile session tools | [#165](https://github.com/bifrost0x/webssh/pull/165): synthetic wheel events passed a unit check but did not trigger actual browser scrollback | 1 |
| [v2.3.0](https://github.com/bifrost0x/webssh/releases/tag/v2.3.0) / 2026-09-11 | Session-duration controls, verified OIDC linking, mobile/copy/notes/transfer fixes and security remediation | [#202](https://github.com/bifrost0x/webssh/pull/202): validated repository security findings; [#208](https://github.com/bifrost0x/webssh/issues/208)/[#209](https://github.com/bifrost0x/webssh/pull/209): linking friction without weakening stable issuer/subject binding; [#210](https://github.com/bifrost0x/webssh/issues/210)/[#211](https://github.com/bifrost0x/webssh/pull/211): mobile input regression remained | 27 |
| [v2.4.0](https://github.com/bifrost0x/webssh/releases/tag/v2.4.0) / 2026-09-21 | High-output multi-session rendering/recovery, terminal/files sync, hardened remote work and native-image release gates | [#221](https://github.com/bifrost0x/webssh/pull/221): hidden-pane rendering delayed ACKs and caused reconnect loops; [#223](https://github.com/bifrost0x/webssh/pull/223)-[#226](https://github.com/bifrost0x/webssh/pull/226): verify immutable image candidates without breaking deployment compatibility | 16 |

The 148 PRs in these release stages are assigned by their **first tagged inclusion**,
not by the week in which they merged. The machine-readable
[release history](release-history.json) lists every PR number, tag SHA, release URL,
comparison and verified issue-to-implementation link. Direct commits are covered by the
Git comparisons even though they have no PR to attach to a native milestone.

## After v2.4.0: implemented, not yet version-released

At baseline [`dc3d9bf`](https://github.com/bifrost0x/webssh/commit/dc3d9bf26f57cbeb440227afe13f9635c4d9f258),
13 additional PRs are merged. They cover workspace/tmux follow-ups, optional Warpgate,
paste/transcript correctness, connection/file usability and dependency maintenance.
See the [roadmap](../ROADMAP.md) and [release-readiness issue #248](https://github.com/bifrost0x/webssh/issues/248).

Two important distinctions:

- [#237](https://github.com/bifrost0x/webssh/issues/237) is closed and
  [#238](https://github.com/bifrost0x/webssh/pull/238) is merged, but Warpgate is not part of
  the v2.4.0 tag. The proposed next milestone must remain open for release validation.
- [#245](https://github.com/bifrost0x/webssh/issues/245) was resolved by the reporter's
  Warpgate PROXY-protocol configuration. It is support evidence, not a shipped WebSSH fix.
  Likewise, [#62](https://github.com/bifrost0x/webssh/issues/62) was converted to a database
  proposal discussion. Neither is counted as implementation delivered by a release.

## Lessons for future planning

These are retrospective recommendations, not invented historical decisions:

1. **Validate observable behavior.** #165 explains why an emitted event was insufficient
   proof of scrolling. Acceptance should check what the user sees, including real devices
   when automated browser coverage cannot reproduce their input stack.
2. **Treat integration and delivery separately.** A merged feature or closed issue can
   precede a versioned release. Keep a separate release gate and record the exact candidate.
3. **Preserve compatibility explicitly.** #225 moved hardening into an opt-in overlay
   after it threatened established deployments. Capacity, identity-provider and rollback
   checks belong in the release record, not an implicit claim that green CI covers everything.
4. **Keep reasons and deferred work visible.** #20 explicitly deferred the large Paramiko
   upgrade; #60 later included Paramiko 5 with broader runtime/security work. Record such
   trade-offs instead of leaving a future reader to infer them from commit order.

## Limits of this reconstruction

No original release deadlines or complete private planning history were available. The
table summarizes documented purposes rather than claiming a pre-existing strategy.
Issue timelines show use of GitHub Projects, but this retrospective does not verify or
change the board's complete structure/status. Native milestone backfill is prepared in
the manifest and must be checked against the live GitHub milestone list before applying.
