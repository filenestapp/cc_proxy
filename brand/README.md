# aifree brand kit

The mark is a lowercase **a** and **i** drawn as one glyph: a round bowl, a shared stem and the dot of the i. It is built from three strokes on a 64-unit grid, so it stays readable down to a 16 px tray icon.

All files here are hand-written SVG with no embedded fonts or raster data. The wordmark is drawn from strokes too, so it renders the same everywhere without a font installed.

## Files

| File | Use |
| --- | --- |
| `aifree-icon.svg` | App icon, favicon, avatars. Coral glyph on a navy tile. Default. |
| `aifree-icon-dark.svg` | Same icon for dark surfaces where navy would disappear: navy glyph on a coral tile. |
| `aifree-glyph-mono.svg` | Glyph only, solid black, no tile. Source for macOS tray template images and one-colour uses (recolour as needed). |
| `aifree-wordmark.svg` | Wordmark for light backgrounds: navy letters, coral dot on the i. |
| `aifree-wordmark-dark.svg` | Wordmark for dark backgrounds: paper letters, coral dot. |
| `aifree-lockup.svg` | Icon + wordmark, horizontal, for light backgrounds. |
| `aifree-lockup-dark.svg` | Icon + wordmark for dark backgrounds. |
| `icon-1024.png` | 1024 × 1024 master for `tauri icon` (rendered from `aifree-icon.svg`). |
| `icon-1024-dark.png` | 1024 × 1024 render of the dark icon. |

Regenerate the PNGs after editing an SVG:

```bash
rsvg-convert -w 1024 -h 1024 brand/aifree-icon.svg -o brand/icon-1024.png
rsvg-convert -w 1024 -h 1024 brand/aifree-icon-dark.svg -o brand/icon-1024-dark.png
```

Desktop icon set (WP1b):

```bash
cd client/desktop && npx tauri icon ../../brand/icon-1024.png
```

## Palette

| Name | Hex | Use |
| --- | --- | --- |
| Navy | `#14213D` | Primary brand colour: icon tile, wordmark, headings, dark sections |
| Navy deep | `#0B1426` | Dark-mode page background, footer |
| Coral | `#F2643D` | Accent: the glyph, the i-dot, primary buttons on navy, highlights |
| Coral deep | `#C2451F` | Coral used for text or links on light backgrounds (5.0:1 on white, 4.7:1 on paper) |
| Paper | `#FAF7F2` | Light page background |
| Mist | `#E7E3DA` | Borders, dividers, table stripes on paper |
| Slate | `#5B6577` | Secondary text on paper (5.5:1) |
| Paper text | `#F5F1EA` | Text and wordmark on navy |

Contrast notes:

- Coral `#F2643D` on navy `#14213D` is about 5.0:1, fine for the glyph and for buttons with navy text.
- Coral on white is about 3.1:1: use it for graphics, large display text and button fills (with navy text), not for body text. Use Coral deep for text links.
- Primary button: coral fill, navy label. Secondary button: navy outline or navy fill with paper label.

## Type

The site and apps use system fonts only, so nothing has to be downloaded and Chinese text renders with the reader's native font.

| Role | Stack |
| --- | --- |
| Chinese + Latin UI and headings | `"Inter", -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans SC", "Segoe UI", Roboto, sans-serif` |
| Numbers in prices and tables | same stack with `font-variant-numeric: tabular-nums` |
| Code, IPs, commands | `ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace` |

Inter (SIL OFL) is used only if the reader already has it installed. Headings use weight 700 with slight negative tracking (`-0.01em`); body uses 400 at 1.7 line height for Chinese.

## Usage

- Clear space around the icon and lockup: at least a quarter of the icon's height on every side.
- Minimum sizes: icon 16 px, wordmark 64 px wide, lockup 120 px wide.
- The wordmark is always lowercase: **aifree**. In running text write "aifree" too, never "AiFree" or "AIFREE".
- Keep the i-dot coral in the wordmark. On a coral background use the mono glyph in navy instead.
- Don't stretch, rotate, outline, add shadows or gradients, or recolour the glyph outside this palette.
- Don't place the mark next to other companies' logos in a way that suggests partnership, and don't call the product "official" anything.
