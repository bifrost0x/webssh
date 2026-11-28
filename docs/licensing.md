# Licensing

WebSSH is distributed under the [Apache License, Version 2.0](../LICENSE).

The project attribution appears in [NOTICE](../NOTICE). Historical copyright
and permission notices are retained in
[THIRD-PARTY-NOTICES](../THIRD-PARTY-NOTICES). Keep these files with redistributed
copies of WebSSH. Earlier distributions retain their applicable original terms.

## Bundled components

Third-party components retain their respective licenses. The project license
does not replace their copyright, permission or attribution notices.

| Component | License notice in the source tree |
| --- | --- |
| xterm.js | `static/vendor/xterm/LICENSE` |
| xterm fit and search addons | `static/vendor/xterm/LICENSE-addon-fit`, `static/vendor/xterm/LICENSE-addon-search` |
| highlight.js | `static/vendor/highlight/LICENSE` |
| Material Icons | `static/vendor/material-icons/LICENSE` |
| Simple Icons platform logos (CC0-1.0, except the marks listed below) | `static/icons/platforms/LICENSE.md`, upstream and per-logo sources in `static/icons/platforms/provenance.json` |
| Simple Icons service logos (CC0-1.0) | `static/icons/services/LICENSE.md`, upstream and per-logo sources in `static/icons/services/provenance.json` |
| Terminal fonts | `static/vendor/terminal-fonts/licenses/` and its `README.md` |
| Website code graph (vis-network) | `site/vendor/vis-network-9.1.6/LICENSE-APACHE-2.0`, `LICENSE-MIT` |
| Go modules linked into the binary | `THIRD-PARTY-NOTICES`, checked against the build list by `go test ./internal/architecture` |
| go-smb2 (SMB client, modified fork, BSD-2-Clause) | `third_party/go-smb2/LICENSE`, repeated in `THIRD-PARTY-NOTICES`; changes in `third_party/README.md` |

The platform logos come from [Simple Icons](https://github.com/simple-icons/simple-icons),
which releases its icon set under CC0-1.0. Some marks carry the license of
their owner instead, as `provenance.json` records per logo:

- Debian logo: CC-BY-SA-3.0, see <https://www.debian.org/logos>
- Fedora logo: custom license, see <https://docs.fedoraproject.org/en-US/project/brand/>

The service logos come from the same Simple Icons release. Only marks that
Simple Icons publishes under CC0-1.0 are bundled. A service whose mark carries
its own license, or that Simple Icons does not include, is shown as a
two-letter monogram of its name instead.

Brand names and logos are trademarks of their respective owners; WebSSH uses
them only to identify the software a host runs, which implies no endorsement.

`npm run vendor` copies the frontend library license notices from the locked
upstream packages alongside their assets. `npm run vendor:check` verifies those
copies. The application image includes `LICENSE`, `THIRD-PARTY-NOTICES` and
`NOTICE` under `/app`; the frontend vendor notices are embedded in the binary
with their assets and served below `/static/vendor/`. Release binaries ship
`LICENSE`, `NOTICE` and `THIRD-PARTY-NOTICES` in their archive. The website
code graph ships its own vendor directory, the project notices at its root,
and the Material Icons license alongside the font in
`assets/material-icons-LICENSE`.

The CI license check validates the project declarations and complete retained
license texts. The container checks verify that the runtime notices match the
source files.
