# Terminal font assets

Four Nerd Fonts Mono families from the official Nerd Fonts v3.5.1 release:
JetBrains Mono (NL, no ligatures), Hack, Fira Mono, and Source Code Pro
(upstream patched name: SauceCodePro). Regular and bold are included. Italics
are browser-synthesized. Ligature rendering is not promised by WebSSH's xterm
renderer. CJK and emoji may use device fallback fonts.

WOFF2 is lossless font compression using Google's `woff2_compress` (1.0.2).
No glyph subsetting is applied: Nerd Fonts' private-use codepoints, including
supplementary-plane icons, are preserved. CSS aliases prefixed with `WebSSH`
avoid collisions with locally installed versions; internal font names are
unchanged. Only the selected text family and the shared Symbols Nerd Font Mono
face load, from the WebSSH origin. The symbols face follows named text families
and precedes the generic monospace fallback. Its CSS unicode-range is restricted
to private-use characters. Existing glyphs keep the chosen typeface; missing
PUA icons use the shared Mono face, including with unpatched local Fira Mono.
The regular symbols face also serves bold icons with browser synthesis.
Existing preferences keep their meaning and theme text defaults are unchanged.

`manifest.json` records release archive URLs, archive/source/output SHA-256
hashes, and weights. `licenses/` contains the release notices for each family
and the pinned upstream licensing overview, audit, glyph source notices, and
JetBrains Mono OFL. Preserve these notices when redistributing. Nerd Fonts
combines fonts and icon sets with multiple licenses; the base font license
alone does not describe every included component.

Verify committed font binaries offline:

    python scripts/vendor-terminal-fonts.py

To reproduce, download the five exact archive URLs in the manifest into a
local directory, then run (requires `woff2_compress` on PATH). The manifest
records the compressor, distribution package versions and package hashes used
for these reproducible outputs:

    python scripts/vendor-terminal-fonts.py --source-dir /path/to/archives

The script verifies each archive before reading named members, verifies the
source font, and checks conversion output before writing. Font upgrades must
update the binaries, manifest, CSS and applicable notices together. They must
also be checked visually with shell icons, bold text, box drawing, and the
supplementary-plane sample in the appearance dialog. Never fetch fonts from
third parties at application runtime.
