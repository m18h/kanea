# Logo

The Kanea mark: an open arc with an amber indicator at the top and two dots
descending inside it. Four variants, all 64×64 with the same geometry: only
the colours differ.

| File | Arc and dots | Indicator | Use on |
|---|---|---|---|
| `kanea-mark-dark.svg` | `#e8e8ee` | `#f2b544` | dark backgrounds |
| `kanea-mark-light.svg` | `#1c1c22` | `#e09b1a` | light backgrounds |
| `kanea-mark-mono-white.svg` | `#e8e8ee` | `#e8e8ee` | one-colour dark (stickers, silkscreen) |
| `kanea-mark-mono-black.svg` | `#1c1c22` | `#1c1c22` | one-colour light, and anywhere the amber cannot print |

These files are the source of truth. **Nothing loads them at runtime**; every
surface inlines the geometry instead, because each one needs it to adapt in a
way a static file cannot:

| Surface | How |
|---|---|
| `README.md` | `<picture>` over the light and dark files: the only consumer that reads them directly |
| `site/index.html`, `site/docs/index.html` | inline SVG; arc and dots are `currentColor`, the indicator is the `--mark` custom property (`site/style.css`, one value per theme) |
| `site/*.html` favicons | a data URI with the mark on a `#1c1c22` rounded square, so it is legible on a light *and* a dark tab strip |
| `dashboard/index.html` | the same data URI: the dashboard is embedded in the binary, and a data URI is one fewer asset to route |
| `dashboard/src/components/Mark.tsx` | inline SVG; `currentColor` follows the `.dark` class on `<html>`, which an `<img>` would not |

So a change to the mark's geometry is a change in six places. That is the cost
of a logo that is one colour on a light page, another on a dark one, and never
a second HTTP request, and it is paid rarely.

Keep the amber fixed. It is the one part of the mark that does not change with
the surface, and it is deliberately not the interface accent (teal on the site,
zinc-and-primary in the dashboard): the mark should read as itself wherever it
lands, not as part of whatever palette surrounds it.
