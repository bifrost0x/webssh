# File Workspace Design QA

## Evidence

- Source visual truth: `C:\Users\windo\.codex\generated_images\019ff9ca-ce87-7891-a71f-5f92fe020bcf\exec-8ce2eb5f-b5af-4218-aa9a-9c9630284cda.png`
- Browser-rendered implementation: `C:\Users\windo\Coding\webssh\.test-run.tmp\design-qa-implementation-final.png`
- Side-by-side comparison: `C:\Users\windo\Coding\webssh\.test-run.tmp\design-qa-side-by-side-final.png`
- Mobile implementation: `C:\Users\windo\Coding\webssh\.test-run.tmp\design-qa-mobile-2.png`
- Desktop viewport: 1488 x 1054 CSS px, source 1488 x 1054 px, implementation 1488 x 1054 px, density-normalized at 1:1 pixel dimensions.
- Mobile viewport: 390 x 844 CSS px.
- State: dark theme, split layout, source launcher for the right pane, SMB disabled with visible Coming soon status.

## Findings

No actionable P0, P1, or P2 finding remains.

- Typography: the implementation retains the product's existing system-font stack, weights, compact line height, and truncation behavior. The source hierarchy is preserved without adding a runtime font dependency.
- Spacing and layout: full viewport, symmetric dual panes, narrow transfer rail, centered layout/source controls, source tabs, identity rows, file-table columns, and bottom transfer queue follow the source composition. Single-pane mode now expands to the full workspace width.
- Colors and tokens: the existing WebSSH dark tokens drive all surfaces; accent blue, connected green, destructive red, borders, disabled states, and elevation remain consistent with the current product.
- Image quality and assets: the target contains no illustrative imagery. All visible icons use the already vendored Material Icons asset; no placeholder image, inline SVG, emoji, or CSS illustration was introduced.
- Copy and content: source-first labels explain the target pane, protocol, endpoint, security state, local-browser permission, and disabled SMB status. German, English, Vietnamese, French, Spanish, and Chinese key parity passed.
- Accessibility and responsiveness: semantic buttons, tab roles, disabled SMB controls, labels, keyboard Escape/Ctrl+K behavior, visible mobile Coming soon status, and a one-column mobile launcher were verified. The 390 px view has no clipped core control.

## Full-view comparison evidence

The same-state side-by-side browser comparison shows the same primary hierarchy: full-screen workspace, dual file surfaces, centered layout controls, contextual source launcher, and persistent transfer area. The implementation intentionally shows empty panes because no fake SSH connection or fake remote listing is rendered in the real app state; populated file rows are covered by the product-capture E2E fixture and existing SFTP data paths.

## Focused region comparison evidence

The source launcher and mobile launcher were captured separately because their text, badges, disabled state, and compact rows are too small to judge only from the full-view comparison. Search filtering exposed only the matching SMB row, the SMB row and New SMB button remained disabled, and Coming soon was visible on desktop and mobile. Browser console warnings/errors: none.

## Comparison history

1. P1: single-pane content occupied only the left grid track. Fixed by changing the single-mode grid to one full-width track. Post-fix evidence: `design-qa-implementation-3.png`, measured pane width 1465.6 px in a 1488 px viewport.
2. P2: a long saved-host list pushed SMB and browser sources below the visible launcher region. Fixed with a bounded, independently scrollable saved-host group and by keeping SMB and browser source groups visible. Post-fix evidence: `design-qa-implementation-2.png`.
3. P2: layout controls drifted to the right rather than matching the centered source composition. Fixed by centering the layout/source control cluster while leaving close at the far edge. Post-fix evidence: `design-qa-implementation-final.png`.
4. P2: the mobile launcher hid the SMB status text and cramped two creation actions into one row. Fixed by restoring the Coming soon/security row for disabled SMB and stacking creation actions. Post-fix evidence: `design-qa-mobile-2.png`.

## Primary interactions tested

- Open File Manager from the product menu.
- Initial source launcher and source search.
- Disabled SMB row and disabled New SMB share action.
- Switch between one and two panes; empty second pane opens its own source launcher.
- Open real SFTP session descriptors in the selected pane.
- Preserve tabs and paths across pane switching and modal close/reopen.
- File selection enables the real server-to-server transfer path.
- Responsive mobile menu and launcher.

## Follow-up polish

- P3: the current WebSSH system font renders slightly heavier than the source mock's compact UI type at small sizes. Keeping the existing product typography is preferable to adding a new vendored font for this isolated screen.

final result: passed
