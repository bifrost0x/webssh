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

## Shared top-level workspace QA (2026-08-27)

- The approved Hosts, File Manager, and Commands mockups were compared side by side with the implementation at the same 1487 x 1058 viewport.
- All three top-level destinations occupy the same full-width application surface directly below the global header. They no longer use a backdrop, floating card, or close control; the selected global navigation item is exposed with `aria-current="page"`.
- Returning to Workspaces reveals the original session rail, workspace DOM, and status bar without rebuilding or replacing them. A browser regression verifies the original workspace node identity, child counts, and File Manager shutdown state after traversing all top-level destinations.
- The existing Hosts, Jump Hosts, SSH Keys, File Manager, Command Sets, and Command Library content remains available. Existing nested workflows that require an overlay, including return-to-connection Command Set editing, retain dialog semantics and modal behavior.
- The full File Manager continues to suspend and restore the embedded per-session SFTP target when switching between top-level destinations. Escape closes the source chooser but cannot accidentally dismiss the top-level File Manager.
- The real in-app browser traversal covered Hosts, File Manager, Commands, and Workspaces with no console errors. Desktop and mobile containment scenarios, focus behavior, file-source selection, nested modal behavior, and embedded SFTP restoration passed their targeted browser regressions.
- Current regression evidence: 80 focused Python tests passed; all 33 JavaScript test files passed; JavaScript syntax and lint checks passed; 8 targeted cross-feature browser scenarios passed; the two corrected edge-case browser scenarios passed independently; `git diff --check` passed.

## Professional management information architecture QA (2026-08-27)

- The approved Admin Center and Hosts mockups were captured again and placed beside the final implementation in the same comparison images at the same browser viewport.
- Admin settings now use the approved grouped hierarchy: Access & identity, Security, and Operations. Authentication, registration, SSH host trust, audit logs, retention, and backup/restore remain separate destinations instead of being combined into one generic settings page.
- Hosts uses a persistent resource sidebar for Hosts, Jump Hosts, and SSH Keys. Saved connections remain grouped and searchable, primary Connect actions stay visible, and secondary edit/duplicate/delete actions move into a compact action menu.
- Commands uses the same resource hierarchy for Command Sets and Command Library. Sets are searchable, show their step count, retain all prior edit/duplicate/delete actions, and use compact secondary menus.
- The existing Workspaces and File Manager flows were not restructured. Hosts and Commands continue to occupy the shared application surface below the global header, without returning to floating top-level dialogs.
- Visual review found no clipped navigation, escaped controls, broken borders, or inconsistent destructive-action treatment in the compared desktop states. Existing WebSSH typography, Material Icons, logo assets, dark surfaces, and interaction colors were preserved.
- The in-app browser traversal covered Admin Users, Authentication, Registration, SSH host trust, Audit Logs, Audit retention, Backup & Restore, Hosts, Jump Hosts, SSH Keys, Command Sets, and Command Library. Browser logging remained clean.
- A regression exposed by the review path was fixed: an empty Command Set selector could throw before opening a saved host for review. The selector and management-search filtering are now separated, and the Tailscale review path passes again.
- Current focused regression evidence: 76 Python UI tests passed; all 33 JavaScript test files passed; all 32 relevant browser scenarios passed after the final correction; JavaScript syntax checks passed.

## Security and File Manager correction QA (2026-08-27)

- Source visual truth: `/tmp/codex-clipboard-4892cc9a-c618-444f-9007-34762780cf98.png` (Security, 3018 x 1570 pixels) and `/tmp/codex-clipboard-3ec80bf6-add4-46ee-971a-f6e7b1137eea.png` (two-pane File Manager, 3070 x 1442 pixels).
- Browser-rendered implementation: `/tmp/webssh-security-settings-fixed.jpg` and `/tmp/webssh-file-manager-empty-fixed.jpg`, each captured at a 1280 x 720 CSS viewport and saved as 1280 x 720 pixels. The in-app browser reported devicePixelRatio 2 but returned CSS-pixel screenshots; the source captures were proportionally contained rather than stretched for the comparison.
- Combined full-view evidence: `/tmp/webssh-security-comparison.png` and `/tmp/webssh-file-manager-comparison.png`. Each comparison places the reported state and corrected implementation in one 1400 x 1500 image.
- State: authenticated administrator, dark theme, Security overview with empty Passkey and TOTP lists; File Manager with two panes, no selected source, and source launcher closed.
- Focused-region evidence was not required because both defects were clearly legible in the full-view comparisons: the Security grid-track regression affected the entire content frame and the File Manager duplication was isolated to the central empty-state card.
- Typography and copy: the Security heading, explanatory text, assurance labels, and factor-card copy now have normal line lengths and no clipped words. Existing text and type hierarchy were preserved.
- Spacing and layout rhythm: the Security overview and factor cards now form one centered vertical settings flow. The File Manager empty card retains its spacing after removing the redundant decorative icon.
- Colors and tokens: existing WebSSH dark surfaces, borders, muted copy, and blue primary action token were preserved.
- Image and icon fidelity: existing vendored Material Icons remain in use. Each File Manager empty card now exposes exactly one folder icon, attached to the actionable Open source button; no custom asset substitute was introduced.
- Interaction and console verification: File Manager navigation, one-pane/two-pane switching, automatic source-launcher opening, launcher closing, and return to the empty two-pane state passed in the in-app browser. Security loaded with the corrected block layout. Browser error logs were empty for both routes.
- Earlier P1: the professional Admin Center grid applied to every `.admin-main`, forcing the Security overview into a 228 px navigation track and the factor cards into the adjacent track. Fixed by explicitly restoring block flow and centered margins only for the Security Center.
- Earlier P2: the File Manager empty-state card rendered a decorative folder icon and repeated the same icon inside the Open source button. Fixed by removing the decorative instance while retaining the actionable button icon.
- Post-fix evidence: Security measured `display: block`, a 1220 px overview width at the 1280 px viewport, and the Passkeys card began below the overview. File Manager measured two empty cards, zero decorative empty icons, and two action icons (one per pane), with no document-level horizontal overflow.
- Remaining P0/P1/P2 findings: none.
- Regression evidence: 68 focused Python tests passed, 3 focused JavaScript test files passed, browser error logs were empty, and `git diff --check` passed.

## Unified Settings Center QA (2026-08-27)

- Source visual truth: `/home/heimdall/.codex/visualizations/2026/08/27/01a04300-d47c-7fc1-80ce-2de90aa75f58/unified-settings-center.html`, captured as `/tmp/webssh-unified-settings-source.png` in its dark-theme state.
- Browser-rendered implementation: `http://127.0.0.1:4181/settings#security-overview`, captured as `/tmp/webssh-unified-settings-implementation.png` in the authenticated administrator state.
- Viewport and normalization: both source and implementation used a 1280 x 720 CSS viewport and produced 1280 x 720 screenshots. The in-app browser reported devicePixelRatio 2 but returned CSS-pixel captures, so no density resampling was required.
- Combined full-view evidence: `/tmp/webssh-unified-settings-comparison.png` (1336 x 1628). Focused navigation, assurance, and security-method evidence: `/tmp/webssh-unified-settings-focused-comparison.png` (1264 x 1380).
- State: dark theme, signed-in local administrator, optional MFA, Security overview selected, empty-factor management path available.
- Typography: the implementation preserves the source's system sans-serif hierarchy, compact uppercase metadata, readable assurance copy, and consistent row weights. The additional WebSSH headings use the existing product type tokens and do not wrap or truncate.
- Spacing and layout rhythm: both views use the 228 px settings rail, full-width content track, compact navigation rows, three-column assurance strip, and aligned security-method actions. The implementation intentionally retains the established Admin-pane outer gutter and adds Preferences because general settings are part of the approved consolidation.
- Colors and visual tokens: dark primary, secondary, raised, border, muted-copy, accent, and status colors match the approved calm operations palette through existing WebSSH theme variables.
- Image and icon fidelity: the interface uses the repository's existing WebSSH branding and vendored Material Icons. No placeholder, handcrafted SVG, CSS drawing, or substitute asset was introduced.
- Copy and content: account security, strong factors, recovery, personal SSH trust, and every admin destination remain separately named. The implementation uses action-oriented descriptions instead of claiming an empty or enrolled factor state before the live APIs respond.
- Primary interactions tested in the in-app browser: account-menu entry to `#preferences`; hash navigation across account sections; preference persistence after reload; Security method Manage action to `#factors`; Administration link to `#authentication`; and return to the overview. Browser error logs were empty.
- Responsive containment: the final 1280 x 720 page measured exactly 1280 px wide with no horizontal overflow. Mobile containment remains covered by the updated account-menu Settings Center scenario.
- Earlier P2: the first implementation comparison left the lower Security overview empty and omitted the approved security-method summary. Fixed by adding the three method rows and functional Manage actions, then recaptured at the same viewport and state.
- Post-fix evidence: the full and focused combined comparisons show the approved hierarchy, proportions, assurance strip, three method rows, and right-aligned actions. The Manage action was exercised and opened the complete Passkeys & MFA panel at `#factors`.
- Remaining P0/P1/P2 findings: none. The extra Preferences destination and product icons are intentional consequences of merging general Settings with Security while retaining the existing professional Admin-pane design system.

## Unified management navigation follow-up QA (2026-08-27)

- Source visual truth: `/tmp/codex-clipboard-c8ed4cba-999c-4ffb-9217-c05eb800c62e.png` (Commands before-state, 6826 x 2334 pixels) and `/tmp/codex-clipboard-4892cc9a-c618-444f-9007-34762780cf98.png` (Security before-state, 3018 x 1570 pixels). These are defect references rather than target mockups, so the comparison evaluates the maintainer's requested information architecture instead of treating the old layout as a fidelity target.
- Browser-rendered implementation: `/tmp/webssh-commands-left-nav.jpg`, `/tmp/webssh-settings-unified.jpg`, and `/tmp/webssh-admin-unified.jpg`, captured at a 1280 x 720 CSS viewport as 1280 x 720 pixel images in the authenticated administrator state.
- Density and viewport normalization: the ultra-wide source screenshots were proportionally contained to 1280 pixels without stretching. Their original aspect ratios differ from the available in-app-browser viewport, so no pixel-level spacing claim is made across screenshots; layout hierarchy, rail persistence, content containment, and control placement were compared instead.
- Combined full-view evidence: `/tmp/webssh-commands-qa-comparison.jpg` and `/tmp/webssh-settings-qa-comparison.jpg`. The first places the old horizontal Commands tabs and the new persistent left resource rail in one image. The second places the malformed Security grid and the unified Settings Center in one image.
- State: dark theme; Commands with Command Sets selected; Settings with Security overview selected; Admin with Users selected. The old `/admin` URL was also exercised and redirected to `/settings#users`.
- Focused-region evidence was not needed because the relevant defects and their corrections are legible in the full-view comparisons: primary versus secondary navigation, the left-rail hierarchy, header edge alignment, the assurance strip, and the users table.
- Fonts and typography: the implementation retains the established WebSSH UI font stack, weights, uppercase metadata, and compact operations density. Headings, descriptions, resource labels, and table copy remain readable without the wrapping failure visible in the Security reference.
- Spacing and layout rhythm: Commands now uses the same 228 px resource-navigation track as Hosts. Settings, Security, and Administration share one persistent 228 px settings rail and one content track. The content track consumes the available width, while cards and tables use aligned gutters rather than leaving an accidental right-side void.
- Colors and visual tokens: existing dark surfaces, low-emphasis borders, muted copy, blue selection accent, and destructive-action tokens remain unchanged. Selected destinations are clear without introducing a second visual language.
- Image and icon fidelity: the header now renders the repository's current `webssh-logo.svg`, and all navigation icons use the vendored Material Icons set. No placeholder, handcrafted SVG, CSS drawing, emoji, or substitute brand asset was introduced.
- Copy and content: Command Sets and Command Library remain separately named. Personal Settings and Security destinations are followed by an explicitly labelled admin-only group, preserving every prior Users, Authentication, Registration, SSH trust, Audit, Retention, and Backup destination.
- Primary interactions tested in the in-app browser: Command Sets to Command Library; Security overview to Users; Users to Preferences; direct hash navigation; the legacy `/admin` redirect; and return to the shared top-level workspace. The browser console log remained empty.
- Earlier P1: Commands used full-width horizontal tabs unlike Hosts and the approved management pattern. Fixed with a persistent resource sidebar and verified in both Command Sets and Command Library states.
- Earlier P1: Settings, Security, and Admin were separate surfaces, and the Security page could collapse into an unusable narrow grid. Fixed by rendering account and admin sections in one Settings Center and coordinating all section visibility through one hash-aware controller.
- Earlier P2: the management header did not use the current logo asset and the return action did not clearly anchor to the far right. Fixed with the shipped logo image, a full-width header, and edge-aligned brand and return controls.
- Post-fix evidence: the browser showed a single visible content panel for every tested hash, the complete admin users table inside the Settings Center, the Commands resource rail beside its content, and a clean browser console. Focused regressions passed 158/158, adjacent UI regressions passed 73/73, all 33 JavaScript test files passed, and `git diff --check` passed.
- Remaining P0/P1/P2 findings: none.

## Mobile Terminal Dock QA (2026-08-30)

## Reference and implementation evidence

- Selected reference: `/home/heimdall/.codex/generated_images/01a051b3-0d40-71d1-a2dd-60932f92f699/exec-439decfd-4875-4539-b8a9-0a6da7f46c7b.png` (853 x 1844 px).
- Implemented phone state: `/tmp/webssh-mobile-build-active-final.png` (390 x 844 CSS px, device scale factor 1, connected local SSH session).
- Side-by-side comparison: `/tmp/webssh-mobile-reference-comparison-final.jpg` (reference left, implementation right, both normalized to 390 x 844 px).
- Supporting states: `/tmp/webssh-mobile-menu-layer-final.png`, `/tmp/webssh-mobile-tools-working-final.png`, `/tmp/webssh-mobile-build-hosts-fixed.png`, `/tmp/webssh-tablet-build-834.png`, and `/tmp/webssh-desktop-build-1440.png`.

## Comparison history

### Pass 1

- P1: The previous phone layout spent too much vertical space on desktop navigation and controls, leaving the terminal difficult to use. Replaced it with a 52 px app bar, a 48 px session rail, an edge-to-edge terminal, a compact status capsule, and a five-destination bottom dock.
- P1: The existing Hosts workspace wrapped and overflowed horizontally at phone width. Converted the toolbar and profile cards to narrow single-column layouts and verified a 390 px document width with no horizontal overflow.
- P1: Terminal history was not reliably reachable with touch. Added a touch-to-wheel bridge that preserves xterm scrollback, alternate-buffer, and mouse-tracking semantics; horizontal gestures remain untouched.
- P2: The first More sheet placed its backdrop above the header stacking context, dimming the sheet and intercepting actions. Raised the header only while the mobile sheet is open and re-ran every sheet action in the browser.
- P2: The Tools icon exceeded its grid cell and produced internal overflow. Constrained the icon box and confirmed the sheet client and scroll widths match.

### Final pass

- Phone portrait (390 x 844): connected terminal, session switcher, command-input toggle, Hosts, File Manager, Commands, More, Quick Connect, Notes/Tools, Broadcast, transcript fallback, and account access verified.
- Tablet portrait (834 x 1194): compact static navigation and session rail verified; bottom phone dock is absent and the workspace remains full-width.
- Desktop (1440 x 1024): existing desktop navigation, split controls, and side tools remain unchanged.
- Responsive behavior is capability/viewport based rather than user-agent based: phone below 768 px (plus short, coarse-pointer phone landscape), tablet from 768 through 1023 px, and desktop from 1024 px.
- Browser console log after the final mobile interaction pass: empty.
- Typography, colors, borders, radii, logo, and icons reuse the existing WebSSH design tokens and assets. No placeholder or newly fabricated visual assets were introduced.
- New navigation and command-input labels are present in all six locale blocks.

## Automated checks

- JavaScript syntax and ESLint checks cover the changed frontend controllers.
- All 34 JavaScript test files pass, including mobile shell navigation and vertical/horizontal touch-scroll behavior.
- Focused Python UI, asset-version, and locale-parity checks: 74 passed.
- Full Python suite: 2,270 passed, 29 skipped, and four loopback/socket cases were blocked only by the restricted workspace sandbox. The exact four authorized reruns passed, for an effective result of 2,274 passed and 29 skipped; the three warnings are the existing upstream Flask-Login `datetime.utcnow()` deprecation.
- Full Playwright browser suite: 100 passed in 5.1 minutes across phone, tablet, desktop, authentication, workspace, File Manager, Settings/Admin, theme, and SMB flows.

## Final correction and acceptance pass

- P1 command-entry overlap: fixed. The floating keyboard toggle is removed from hit testing while the command bar is expanded, the Send action remains reachable, and an internal 46 x 46 px close action provides an explicit exit.
- P1 tablet accessibility: fixed. Every icon-only global navigation action retains a localized accessible name through the entire 768-1023 px tablet range.
- P2 More-sheet semantics: fixed. The sheet now receives dialog and modal semantics, makes the application background inert and hidden from assistive technology, traps Tab and Shift+Tab, closes on Escape/resize/view changes, and restores focus after a normal close.
- P2 Admin/Settings compact layout: fixed. The Users search field no longer inherits the desktop flex basis, and the compact Settings header uses the same one-row app-like hierarchy.
- P1 File Manager containment discovered by the complete browser run: fixed. The phone single-pane view now resets the pre-existing two-row tablet grid to one `minmax(0, 1fr)` row, so the active pane consumes the complete available height and the empty-state source action remains visible and clickable.
- Interactive browser measurements at 390 x 844 confirm that the File Manager pane and pane grid both use the full 590 px workspace height; the file list has 323 px available and the source action is fully contained. Tablet navigation names, More-sheet focus lifecycle, command Send hit testing, and Admin toolbar spacing were also verified in the rendered application.
- Remaining P0/P1/P2 findings: none.

final result: passed
