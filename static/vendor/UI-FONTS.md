# UI fonts

These assets are served locally. Font loading does not contact an external service.

| Asset | Source | License | SHA-256 |
| --- | --- | --- | --- |
| `roboto/Roboto-Variable.ttf` | Google Fonts, `ofl/roboto/Roboto[wdth,wght].ttf`, retrieved 2026-10-31 | SIL OFL 1.1, accompanying OFL.txt | `d7598e12c5dbef095ff8272cfc55da0250bd07fbdecbac8a530b9b277872a134` |
| `material-icons/material-icons-outlined.woff2` | `material-icons` 1.13.14, `iconfont/material-icons-outlined.woff2` | Apache 2.0, existing Material Icons license | `35dca8a7145a17c8d1306f25a3ca091578e15396f0b22d61eb8e73262ac75577` |

Roboto source: https://github.com/google/fonts/tree/main/ofl/roboto.

The Outlined icon font is the only icon face the application loads. `npm run vendor` copies it and generates `material-icons/material-icons.css`, which maps every Material Icons class to it with the same content-versioned URL as `css/design-system.css`; `npm run vendor:check` verifies both. `material-icons/material-icons.woff2` (filled) is kept only for the public project site built by `scripts/prepare_pages.py`.
