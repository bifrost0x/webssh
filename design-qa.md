# WebSSH design QA

## Scope and reference

- Approved reference: the maintainer-provided WebSSH workspace screenshot.
- Product direction: quiet, professional operations workspace; terminal remains primary; the reference is orientation only and is not copied.
- Required information architecture: connection tabs remain in the session row; Files, Commands, Diagnostics, and Notes form a separate context tab system on the right below that row.
- Required behavior: Commands inserts exact text without Enter or automatic execution; Files follows the active SSH pane in 1/2/4-pane layouts; Diagnostics can expand into the established metrics overlay; the terminal fits live browser resizes without reload; compact layouts keep the terminal primary.
- Responsive requirement: text, dividers, charts, controls, and panels remain inside their owning surface at every supported viewport.
- Authentication requirement: Login and registration use the real WebSSH logo, a centered workbench that occupies about 70% of desktop width, and a concise welcome area for SSH Workspaces, File Manager, Hosts, and Commands. Enabled sign-in paths remain explicit in the functional form, while MFA, recovery, and password-change pages retain their factual security guidance.
- OIDC help requirement: the Admin action points only to the public GitHub Wiki at `https://github.com/bifrost0x/webssh/wiki/OpenID-Connect`; no local guide is shipped.

## Visual comparison

The approved reference and the current implementation were reviewed together in
the equivalent single-terminal Commands state. The final QA covered desktop,
ultrawide, tablet, and mobile densities:

- Approved reference: 1487 × 1058 maintainer screenshot.
- Current Commands and Diagnostics contexts: 2560 × 1440 capture state (1920 × 1080 CSS pixels).
- Authentication workbench: 3440 × 1440, 1920 × 1080, 1292 × 860, 1280 × 720, 832 × 946, and 390 × 844 browser states.
- Registration workbench: 1280 × 720 and 390 × 844 browser states.
- Responsive workspace: desktop, tablet, and mobile states from 360 through 2560 CSS pixels.

Reference and implementation captures were inspected in combined comparison
views. The temporary QA captures were removed after review and are not part of
the repository or container image.

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
- Authentication hierarchy: the desktop workbench keeps the enlarged logo, welcome statement, 2 × 2 product-area grid, and credentials in distinct surfaces. The form surface now uses its complete column instead of nesting an additional 80% width constraint; compact layouts collapse the product explanation, preserve the logo, and expand the functional form to the available mobile width.
- Responsive layout: desktop side panel, compact/tablet launcher, and mobile full-screen context workspace preserve the same tab model without escaping content.
- Surface containment: long copy wraps, grid children can shrink, chart canvases clip to their plot surface, and panel internals scroll only on their intended axis.

## Interaction verification

- Files, Commands, Diagnostics, and Notes switch within one context workspace.
- Commands filters commands and command sets, inserts the exact command visibly, leaves the panel open, and never sends Enter automatically.
- Manage Commands opens the management modal without discarding the current session context.
- Files stays mounted while another context is active, follows the active SSH pane in 1/2/4-pane layouts, and shows a bounded target-specific unavailable state when SFTP is unsupported.
- Diagnostics polls only while open, closes on entry into a compact breakpoint so the terminal becomes primary, resumes when the user reopens session tools, and can move the same metrics view into an 80vw right-side overlay before returning it to the context panel.
- Disconnected non-persistent sessions follow the saved user choice: the backward-compatible default keeps Retry plus Close tab, while the optional close behavior removes only the finished tab and switches safely. Persistent tmux candidates always remain reconnectable.
- The header uses the repository's shipped WebSSH banner asset, while the four primary navigation labels use a stronger, calmer type hierarchy.
- Entering tablet or mobile mode closes the context panel once, leaves its launcher reachable, and reserves the viewport for the terminal without discarding session state.
- Browser changes from 360 to 900 to 1280 pixels preserve the active context and terminal state without reload or horizontal overflow.
- A desktop-to-mobile resize no longer triggers the virtual-keyboard layout; the compact header remains visible and usable.
- The desktop context workspace opens by default, remains dismissible, and does not reopen itself while the embedded SFTP state stays mounted.
- Mobile keeps the header, session controls, context launcher, tabs, and close action reachable.
- Mobile notifications remain fully inside the viewport and do not obscure the context tabs.
- A fresh SSH connection to `host.docker.internal:2222`, xterm rendering, the live SFTP listing, the Commands library, Diagnostics, Notes, and all four context switches passed in the local Docker preview.
- The deliberately changed key on `host.docker.internal:2223` was rejected fail-closed and presented the same-origin SSH trust-management action.
- The desktop context workspace opens in automatic width mode: 420 px at 1280, 492 px at 1536, 614 px at 1920, and a 720 px cap on ultrawide screens while reserving terminal space.
- Pointer and keyboard resizing switch to a persisted manual width; double-click restores automatic sizing. The legacy 420 px preference migrates to automatic mode without breaking custom existing widths.
- A live desktop-to-390 px mobile resize preserved the terminal session and active Diagnostics state without reload; closing the mobile tools restored the terminal launcher.
- The alternate `127.0.0.1` Passkey origin produced the inline configured-origin recovery action instead of a browser alert.
- Security explained the active sign-in and protected-change method in user language, and the Admin OIDC action linked directly to the public `OpenID-Connect` Wiki page.
- OIDC login against the local Keycloak preview passed with the expected `oidc_user` account.
- Browser console collection remained clean during the local Admin, LDAP, workspace, SSH, and Commands path.
- At 390 × 844 the final login shell measured 390 × 844, the auth dock ended at 670.21875 px, all three authentication methods remained visible, no element escaped the viewport, and the browser console remained clean.
- The rebuilt Docker preview repeated the logged-out responsive check at 390 × 844 and 1920 × 1080: login and registration both matched the viewport width exactly, had no horizontal overflow, and the desktop login required neither horizontal nor vertical page scrolling.
- The rebuilt preview browser console remained free of warnings and errors during the login, registration, language, and authentication-method checks.
- At 1280 × 720 the login workbench measured 896 px wide (70%); at 390 × 844 login and registration measured 370 px wide, required no horizontal scrolling, retained the real logo and all usable authentication controls, and emitted no browser warnings or errors.
- The final German login and registration views render “Willkommen bei WebSSH”, “Die Schaltzentrale für deine Server.”, and the four product areas with the exact label “SSH-Workspaces”; desktop, 390 × 844 mobile, and registration screenshots showed no escaped text, borders, or controls.
- At 1292 × 860 the access dock measured 1252 px with balanced 487 px / 761 px columns; the form and card each consumed the full 761 px right column and the document remained exactly 1292 px wide.
- At 832 × 946 the access dock collapsed to one 796 px content column inside an 800 px surface; document and viewport widths both remained 832 px. The language menu measured 168 px, stayed inside the utility bar's right edge, used the dark surface color, and rendered at z-index 120 above the dock.
- The brand tagline now forms one centered lockup with the WebSSH logo instead of anchoring the lower-left panel edge. At 3440 × 1440, the brand lockup and welcome content form one vertically centered stack whose center matches the panel center exactly; their former 285 px empty separation is reduced to a controlled 48 px. The measured logo-to-tagline gap is 7 px on desktop and 3 px at the 832 × 946 compact breakpoint; both centers remain aligned and the compact document has no horizontal overflow.

## SMB File Manager QA (2026-08-24)

- The opt-in SMB source dialog is contained at 1440 × 1024, 900 × 900, 768 × 1024, and 390 × 844. Its shell and fixed action footer remain inside the viewport without document-level horizontal overflow.
- The disabled state cannot open the dialog or emit an SMB connection request.
- Connect requests clear the password field immediately. Authentication failure returns focus to the empty password field, and browser storage contains no SMB credential value.
- Escape on mobile cancels the exact correlated request, clears the password, closes only the SMB dialog, restores the source launcher, and returns focus to the SMB source action.
- The SMB dialog remains above the File Manager surface. A successful response opens only the server-provided source descriptor and renders its encrypted SMB 3.1.1 endpoint in the selected pane.
- SMB-specific Playwright coverage: 4/4 passed. The complete browser suite passed with no failed tests before the final containment case was added; no product code changed afterward.
- Current regression evidence: Python 3.14 2,037 passed and 33 skipped; JavaScript 300 passed; disposable OpenSSH/SFTP integration 27 passed; disposable SMB integration passed; dependency locks, vendored assets, JavaScript lint, container build, and `git diff --check` passed.

## Regression evidence

### Discussion 148 MFA management QA (2026-08-26)

- The Discussion 148 reference wireframe and the implemented mixed-factor state were inspected together in one comparison input.
- The Security overview keeps the current account-wide MFA state visible, exposes the explicit global disable action only while MFA is enabled, and places Passkeys, authenticator apps, and Recovery codes together before unrelated password and SSH host-trust settings.
- Passkey and TOTP entries share one compact row pattern with label, creation time, an accessible factor-specific Delete label, and a clearly destructive action.
- The real browser state contained one Passkey and one TOTP authenticator. Both factor lists, the account-wide status, the global disable action, and the Recovery section rendered without clipping or horizontal overflow at the 1280 x 720 QA viewport.
- Empty Passkey and TOTP states were also inspected in the real browser; both remain contained and readable.
- The backend blocks deletion of the final durable factor while account MFA is enabled, but permits deleting the final TOTP authenticator when a Passkey remains (and vice versa). Individual TOTP deletion uses action- and target-bound step-up authorization.
- Regression evidence: 2,194 Python tests passed and 29 skipped. Four loopback/runtime cases that the workspace sandbox initially blocked were rerun outside that restriction and passed. The focused JavaScript test, syntax validation, ESLint, i18n parity, and `git diff --check` passed.

- Python 3.14 broad run: 1,806 passed and 33 skipped with one upstream Flask-Login deprecation warning; two stale test-only cache-version and responsive-breakpoint expectations were corrected, then both affected modules passed 45/45.
- Python 3.11 broad run: 1,806 passed and 33 skipped; the same two stale test-only expectations were corrected, then both affected modules passed 45/45.
- Disposable OpenSSH/Paramiko integration: 27 passed; its containers, network, and generated private-key fixture were removed by the runner afterward.
- JavaScript unit tests: 283 passed.
- Browser E2E: 79 passed after updating five legacy expectations to the approved Files-availability and terminal-first compact behavior.
- Focused workspace, layout, mobile-auth, 70%-workbench, registration, LDAP/OIDC/Passkey visibility, and responsive context regressions passed.
- JavaScript lint passed.
- All 10 vendored frontend assets passed integrity checks.
- Docker image built from the Python 3.14 production base.
- Local WebSSH preview image rebuilt from the current Python 3.14 production container and the container is healthy at `http://localhost:5050/`; the existing preview data volume, LDAP service, and Keycloak service were preserved.
- Final auth-shell contract, i18n parity, and shared asset checks: 36 passed; `git diff --check` passed.

## Findings

- P0: none.
- P1: false virtual-keyboard detection after a live browser resize hid the mobile header; fixed and covered by unit and browser regressions.
- P1: closing the desktop context workspace could synchronously reopen Files while SFTP stayed mounted; fixed without discarding SFTP state.
- P1: a nested automatic Files activation could be overwritten by an older SFTP render snapshot and leave a loaded Files panel blank until a tab switch; reproduced against the real OpenSSH target, fixed by ordering the visibility render before the synchronous availability update, and covered by a regression test plus live retest.
- P2: the mobile connection notification could render outside the viewport or overlap context navigation; fixed and browser-covered.
- P2: the local all-auth preview rejected the alternate loopback origin and could retain a stale disposable SSH host key after target recreation; the preview contract now permits both loopback origins and refreshes only the disposable target trust before a fresh connection.
- P2: the initial responsive auth revision extended to 953 px at a 390 × 844 viewport and pushed the primary action below the fold; compact mobile branding, a three-column authentication switcher, and reduced form spacing brought the full flow to 670.21875 px without clipping.
- P2: the final 80% desktop inner-width rule initially left the compact form too narrow and vertically centered it below unused space; the compact breakpoint now starts below the utility bar and uses the full dock width without horizontal overflow.
- P2: the 70% desktop shell could become narrower than its fixed two-column minimums before the old 820 px collapse breakpoint, squeezing labels and clipping the form on medium windows. A fluid 960–1439 px range now expands the shell to the viewport, the compact layout starts below 960 px, and the language menu uses a contained dark overlay above the dock.
- P2: diagnostics cards, status copy, dividers, and chart lines could cross their panels at narrower desktop widths; container-query grid collapse, shrinkable children, wrapping, and explicit plot containment now keep every element inside its surface.
- P1: an active Files context could remain on an unsupported server status after switching back to a capable SSH pane; the context now rebinds after every active-session update and follows the current pane without a tab change.
- P2: disconnect handling offered Retry only and could not match user preference; the additive persisted setting now supports Retry plus Close tab or automatic tab removal while protecting persistent tmux candidates.
- P2: compact breakpoint entry could leave the context sheet covering the terminal; it now closes once on desktop-to-compact transition and keeps the launcher visible.
- P3: none blocking handoff.

final result: passed
