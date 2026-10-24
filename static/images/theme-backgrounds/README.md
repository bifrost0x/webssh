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

## Theme scenes

The separate `../theme-scenes/` directory contains nine generated landscape and
architecture wallpapers for authentication pages, the Overview list header,
and the floating-window desktop. Midnight Homelab uses the matching 1672 x 941 alpine scene in
`../redesign/midnight-lodge.webp` (WebP quality 82, below 220,000 bytes). Dense
data panels and settings keep the subtle textures from this directory.

| Theme | Scene asset | Motif |
| --- | --- | --- |
| Solarized Dark | `solar-observatory.webp` | Coastal observatory at blue hour |
| Paper | `paper-pavilion.webp` | Light stone pavilion beside a calm lake |
| Noir | `noir-retreat.webp` | Dark architecture above a misty valley |
| Arctic Ice | `arctic-fjord.webp` | Snowy fjord and aurora |
| Rose Gold | `rose-desert.webp` | Copper pavilion and rose-colored desert |
| Obsidian | `obsidian-coast.webp` | Basalt coast at violet twilight |
| Retro | `retro-lounge.webp` | Amber mid-century listening lounge |
| Cyberpunk Neon | `cyberpunk-city.webp` | Rainy skyline with cyan and magenta light |
| Emerald Matrix | `emerald-forest.webp` | Glass pavilion in a misty forest |

Only the WebP runtime assets are shipped. Images are
1672 x 941 pixels (Obsidian: 1672 x 940), encoded with Pillow, `method=6`, at
qualities 60–88 to keep each below 150,000 bytes. Encoding is an authoring step,
not an application dependency. The browser loads the selected scene, without
external image services or preloading the other themes.

After changing an asset, update its SHA-256 URL suffix in
`static/css/midnight-ui.css`. Theme-colored overlays protect header readability;
custom account/browser backgrounds take precedence. Theme, asset-delivery and
custom-background browser tests cover these contracts.

## Responsive presentation

`static/css/theme-scenes.css` places the selected scene on authentication,
Overview and the window desktop. Large screens use a centered illustration
bounded by the real source resolution, feathered into the theme canvas; images
are not enlarged into a full-screen 4K wallpaper. High-density displays reduce
the CSS bounds accordingly. Mobile layouts reserve visible scene space while
keeping credentials and data on readable surfaces. Per-theme focal points keep
the subject in frame. Custom account-local wallpapers retain priority and
deferred-loading guards still prevent unselected scene downloads.
