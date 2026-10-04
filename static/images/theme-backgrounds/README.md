# Theme background assets

The PNG files are the original sources. Pages use the smaller WebP derivatives
at the same 1672 x 941 resolution. Keep the originals for future regeneration.

Encode with Pillow using `format='WEBP', quality=90, method=6` (quality 89 for
`arctic-frost.png` to stay below the 150,000-byte per-image budget). Pillow is
an authoring tool only; no additional application dependency is required.

After regeneration, update the matching URL in `static/css/style.css` with
the first 16 hexadecimal characters of the WebP file's SHA-256 digest.
Run the static asset reference tests and browser theme tests to verify the
content versions, size budget, appearance, and saved-theme behavior.
