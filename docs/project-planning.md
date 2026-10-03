# Planning and Release Workflow

Keep planning small enough to maintain. Use the roadmap for direction, milestones for
release grouping, issues for outcomes, and PRs for implementation evidence.

## What belongs where

| Surface | Question it answers | What to record |
|---|---|---|
| [Roadmap](../ROADMAP.md) | Where are we going and why? | Current release focus, next candidates and explicit non-commitments |
| [Milestone](https://github.com/bifrost0x/webssh/milestones) | Which release should deliver this? | Version, goal, acceptance, blockers and release link |
| Issue | Which problem/outcome needs work? | Benefit, reason for priority, acceptance criteria, dependencies and scope limits |
| Pull request | How was it implemented and verified? | Linked issue, implementation choices, tests, compatibility/security impact and rollout gaps |
| Release-readiness issue | Is the integrated work actually deliverable? | Exact candidate SHA, evidence, canary/upgrade results, publication and image verification |
| GitHub Release | What was actually shipped? | Published tag, user-facing changes, upgrade notes and delivery evidence |

Existing GitHub Projects can remain a work view. They do not need to duplicate release
notes, and a board status must not be interpreted as proof of versioned publication.
This setup does not add or reorganize a Project.

## A minimal working cycle

1. **Capture the reason.** For substantial work, use an issue or a reviewed proposal.
   Write the user problem, expected benefit and acceptance before implementation.
   Small bug/dependency PRs do not require a duplicate issue.
2. **Select one active release scope.** Create a version milestone, such as `v2.5.0`,
   with a short goal and a release-readiness issue. A proposed version is adjustable.
   Do not set a due date unless the maintainer actually commits to it.
3. **Assign accepted work.** Attach the implementation issue and related PR to that
   milestone. Link them with `Fixes #123` only when the PR really resolves the issue.
   Use `Refs #123` for partial work. Keep ownership and existing useful labels explicit.
4. **Review and merge normally.** Required repository checks and human review rules
   still apply. Record material trade-offs, validation environments and any deferred
   acceptance. Planning never bypasses branch protection or security gates.
5. **Validate delivery.** Keep the release-readiness issue open after feature PRs merge.
   Check the exact candidate, required CI, native image scans, relevant real-environment
   acceptance and upgrade/recovery behavior. Link the evidence, not just a checkbox.
6. **Publish and verify.** Tag the reviewed candidate, publish release notes, and verify
   the tag-triggered pipeline, versioned AMD64/ARM64 image and SBOM/provenance. Only then
   close the readiness issue and milestone; move the outcome into completed history.

Milestone progress is a count of closed work items, not effort completed or proof that
a version has shipped. A nearly complete milestone with a blocked release gate is still
not a published release. Issues and PRs can both represent the same outcome, so do not
interpret their combined count as distinct features delivered.

## Example: optional Warpgate support

[#237](https://github.com/bifrost0x/webssh/issues/237) states the user's gateway need.
[#238](https://github.com/bifrost0x/webssh/pull/238) implements selector usernames,
interactive authentication and a default-off administration gate. The request is closed
and the PR merged, but neither belongs to v2.4.0 because the tag predates their merge.

The proposed v2.5.0 scope groups that implementation with the related workspace fixes.
[#248](https://github.com/bifrost0x/webssh/issues/248) remains open for exact-candidate
protocol checks, canary, upgrade/recovery, publication and image verification. This makes
the distinction between **implemented** and **shipped** visible without reopening the
resolved feature request or making a PR that repeats code already in `main`.

## Record decisions and blockers

Use a short dated comment on the relevant issue/PR:

```text
Decision (YYYY-MM-DD): selected/deferred/changed <scope>.
Why: <observed problem, benefit or risk>.
Trade-off: <compatibility, security, maintenance or dependency constraint>.
Acceptance: <observable result and required environment>.
Blocker / next action: <exact dependency, owner and action>.
Evidence: <issue/PR/test run/release link and exact SHA where applicable>.
```

Do not make an unresolved bug disappear by removing its milestone. If work moves, record
the old/new scope and reason. Security vulnerabilities still follow the private reporting
process in [SECURITY.md](../SECURITY.md), not a new public planning issue.

## Release gate checklist

Use the focused [v2.5.0 readiness checklist](https://github.com/bifrost0x/webssh/issues/248)
as the first example. Future checklists should include:

- Confirmed scope/version and explicitly deferred items.
- Final candidate SHA and required CI/review evidence.
- Tests matching the changed risks; separate deployment-specific checks from automated CI.
- Upgrade, backup/restore and rollback results or explicit supported limitations.
- Current native AMD64/ARM64 scans and immutable source/image identity.
- Release notes, tag/release links and final versioned-image/attestation verification.

Do not close a release gate before publication or infer a final-head test from an earlier
PR revision. An accepted operational limitation needs a maintainer decision; required
CI/security gates cannot be silently waived. No automation or automatic merge is added.

## Maintaining the history

The initial [release-history manifest](release-history.json) is a dated, reviewable
snapshot of ten published releases and the proposed next scope. It includes prepared
native milestone descriptions, 160 merged PR mappings and 24 verified issue links.
The candidate entry has no tag or publication date because it is not a release.

For historical backfill:

1. Read all existing native milestones before creating anything; reuse matching versions
   and preserve their descriptions/dates unless the maintainer explicitly approves edits.
2. Use each release's first-tagged-inclusion mapping, not a merge date or a closed issue
   timestamp. Do not attach unmerged/superseded PRs as delivered implementation.
3. Assign historical work and close only milestones for actually published releases.
   Put the true publication date in the description. Do not invent historical due dates
   or rewrite commit, issue, PR or release metadata to make the plan look older.
4. Keep the proposed next milestone open and include the release-readiness issue.
   Verify every write, then update `native_milestone_backfill` in the snapshot with the
   actual result/date and milestone numbers. Preserve unrelated existing assignments.

For future releases, append evidence and a released entry when publication is verified;
retain historical tag membership. Update the roadmap's baseline/current section through
a normal documentation PR. Check links and keep reasons concise rather than copying
a commit-by-commit changelog.

## Weekly review

Read the latest release/tag comparison, recent merged/open PRs, open issues, the active
milestone and its readiness issue. Report:

- Meaningful user/security/operational changes, not every commit.
- Implemented versus published outcomes.
- Actual blockers, owner/action and evidence gaps.
- At most three decisions or next actions; mark recommendations as recommendations.

This allows a weekly status report to describe roadmap progress from public evidence
instead of guessing from the number of commits or closed tickets.
