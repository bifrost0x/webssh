# WebSSH 2.0 design QA

## Scope and reference

- Approved reference: the maintainer-provided WebSSH workspace screenshot.
- Product direction: quiet, professional operations workspace; terminal remains primary; the reference is orientation only and is not copied.
- Required information architecture: connection tabs remain in the session row; Files, Commands, Diagnostics, and Notes form a separate context tab system on the right below that row.
- Required behavior: Commands inserts exact text without Enter or automatic execution; Files remains mounted while changing contexts; the terminal fits live browser resizes without reload; mobile keeps every context reachable.

## Visual comparison

The approved reference and the current implementation were compared together at
the same 1487 × 1058 viewport and equivalent single-terminal Commands state:

- Current Files context: `assets/session-workspace.png` (2560 × 1440)
- Current Commands context: `assets/session-commands-context.png` (2560 × 1440)
- Current Diagnostics context: `assets/session-diagnostics.png` (2560 × 1440)
- Current mobile workspace: `assets/mobile.png`
- Current management surfaces: `assets/connection-panel.png`, `assets/connection-options.png`, `assets/keys.png`, `assets/commandlibrary.png`, and `assets/filemanager.png`

The same-viewport reference comparison and the final login, registration,
security, admin, live SSH, and mobile captures were reviewed locally. These QA
artifacts stay outside the public image and repository history.

The current build preserves the reference's calm density and dominant terminal
while making the requested structural distinction explicit: session navigation
and context navigation no longer compete in one toolbar.

## Fidelity review

- Typography: consistent UI and monospace hierarchy, readable terminal density, no clipped labels.
- Spacing: aligned toolbar rhythm, stable panel padding, compact rows without crowded controls.
- Color: restrained dark surface hierarchy, blue interaction accent, green operational state, danger color reserved for destructive actions.
- Borders and radii: consistent low-emphasis panels; active states remain visible without heavy framing.
- Icons and assets: vendored Material Icons and existing WebSSH assets only; no placeholder or handcrafted imitation assets.
- Copy: action-oriented labels distinguish global Commands management from per-session command insertion.
- Responsive layout: desktop side panel, compact/tablet launcher, and mobile full-screen context workspace all preserve the same tab model.

## Interaction verification

- Files, Commands, Diagnostics, and Notes switch within one context workspace.
- Commands filters commands and command sets, inserts the exact command visibly, leaves the panel open, and never sends Enter automatically.
- Manage Commands opens the management modal without discarding the current session context.
- Files stays mounted while another context is active and follows session capability safely.
- Diagnostics polls only while open and remains available across responsive breakpoints.
- Browser changes from 360 to 900 to 1280 pixels preserve the active context and terminal state without reload or horizontal overflow.
- A desktop-to-mobile resize no longer triggers the virtual-keyboard layout; the compact header remains visible and usable.
- The desktop context workspace opens by default, remains dismissible, and does not reopen itself while the embedded SFTP state stays mounted.
- Mobile keeps the header, session controls, context launcher, tabs, and close action reachable.
- Mobile notifications remain fully inside the viewport and do not obscure the context tabs.
- A real LDAP login, fresh SSH connection to `host.docker.internal:2223`, xterm keyboard input, SFTP listing, remote command response, and all four context switches passed in the local Docker preview.
- OIDC login against the local Keycloak preview passed with the expected `oidc_user` account.
- Browser console collection remained clean during the local Admin, LDAP, workspace, SSH, and Commands path.

## Regression evidence

- Python: 1,771 passed, 33 skipped, 6 deselected because the integration runner's own OpenSSH fixture was intentionally already running for live verification.
- JavaScript unit tests: 256 passed.
- Browser E2E: 73 passed.
- Focused regenerated screenshot flows: 8 product captures and 2 session-workspace captures passed.
- JavaScript lint passed.
- All 10 vendored frontend assets passed integrity checks.
- Requirement lock check passed for the supported runtime sets.
- Docker image built from the Python 3.14 production base.
- Local WebSSH container is healthy; OpenLDAP and the three disposable OpenSSH targets are healthy, and Keycloak is running.

## Findings

- P0: none.
- P1: false virtual-keyboard detection after a live browser resize hid the mobile header; fixed and covered by unit and browser regressions.
- P1: closing the desktop context workspace could synchronously reopen Files while SFTP stayed mounted; fixed without discarding SFTP state.
- P2: the mobile connection notification could render outside the viewport or overlap context navigation; fixed and browser-covered.
- P2: the local all-auth preview rejected the alternate loopback origin and could retain a stale disposable SSH host key after target recreation; the preview contract now permits both loopback origins and refreshes only the disposable target trust before a fresh connection.
- P3: none blocking handoff.

final result: passed
