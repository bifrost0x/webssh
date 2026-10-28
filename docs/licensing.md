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
| Socket.IO client | `static/vendor/socketio/LICENSE` |
| highlight.js | `static/vendor/highlight/LICENSE` |
| Material Icons | `static/vendor/material-icons/LICENSE` |
| Terminal fonts | `static/vendor/terminal-fonts/licenses/` and its `README.md` |
| Website code graph (vis-network) | `site/vendor/vis-network-9.1.6/LICENSE-APACHE-2.0`, `LICENSE-MIT` |

`npm run vendor` copies the frontend library license notices from the locked
upstream packages alongside their assets. `npm run vendor:check` verifies those
copies. The application image includes `LICENSE`, `THIRD-PARTY-NOTICES`,
`NOTICE`, and the runtime vendor notices under `/app`. The website code graph
ships its own vendor directory, the project notices at its root, and the
Material Icons license alongside the font in `assets/material-icons-LICENSE`.
Installed Python packages retain their license
metadata in the image's Python environment.

The CI license check validates the project declarations and complete retained
license texts. The container checks verify that the runtime notices match the
source files.
