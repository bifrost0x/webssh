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
