# License transition review (draft)

This is a pending licensing proposal, not confirmation that all existing code has been relicensed.

## Copyright and permissions

- The original MIT license credits Copyright (c) 2026 H31mdall. Its exact original text is preserved in LICENSE-MIT-ORIGINAL.
- External contributor activity (including GalaxyFour) requires a complete per-file, per-commit rights review and, where necessary, express permission to relicense existing contributions.
- The original MIT grants for previously distributed versions remain effective.
- Existing third-party license files (including bundled fonts and vis-network) must remain intact and must not be represented as Apache-2.0 merely because the top-level project changes license.

## Release blockers

1. Identify all human contributors across complete history, including co-authors, imported code, and merged PRs. Record affected files and relicensing permissions.
2. Verify copyright holder identity and permission to relicense original works; do not assume repository ownership proves authorship.
3. Audit source headers, SPDX identifiers, package metadata, documentation, website, Docker image and archives, and third-party NOTICE obligations.
4. Verify the distribution carries the applicable license and attribution notices and that Apache-2.0 does not imply relicensing vendor code.
5. Define the first Apache-2.0 release and document that earlier MIT releases remain MIT.
6. Obtain legal review of liability language, commercial context, and EU CRA applicability. Neither license eliminates mandatory liability.

**Do not merge this draft before all blockers are resolved.**

## Main-history inventory (2026-10-28)

GitHub REST commit listing returned 704 commits across 8 pages (page 9 empty): bifrost0x 618, H31mdall 27, GalaxyFour 12, nguyenha935 6, Nguyễn Thanh Hà 2, GlitchWorlds 2, zocomputer 1, andejx 1, claude 1, dependabot[bot] 34. Author labels are not proof of identity or copyright ownership. Additional Co-authored-by trailers include AI tools and automation.

GalaxyFour has substantive feature and fix commits (e.g. persistent tmux sessions, session tab reconnect, clipboard behavior), so treating all outside contributions as trivial is not supportable. Determine the actual authorship and licensing authority for each affected contribution. Review all other non-owner contributions likewise, including merged PR commits and source imports. The commit listing is not a complete copyright audit of all refs or distributed artifacts.

## Verified license-reference locations requiring consistency

- README.md, CONTRIBUTING.md, LICENSE
- site/index.html, site/security.html, site/impressum.html
- Dockerfile OCI label `org.opencontainers.image.licenses`
- Docker image includes LICENSE at /app/; check whether any original copyright notices and relevant third-party notices are distributed as required.

## Critical legal note

The MIT license permits sublicensing and distribution subject to preservation of its original copyright and permission notice. A future Apache-2.0 license for an aggregate work must not falsely imply that pre-existing third-party MIT contributions were relicensed by their authors. Seek legal review on whether the proposed licensing structure and notices are adequate before release.
