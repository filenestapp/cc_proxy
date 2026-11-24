# aifree.sg website

Static marketing site for aifree, served from Cloudflare Pages. Plain HTML and one stylesheet; no build step, no JavaScript, no cookies, no third-party requests.

```text
site/
  index.html              Chinese home page (default language)
  en/index.html           English home page
  download/ terms/ privacy/        Chinese sub-pages (index.html in each folder)
  en/download/ en/terms/ en/privacy/  English sub-pages
  404.html                Shared not-found page
  assets/site.css         All styles
  assets/*.svg, og.png    Copies of brand files (see ../brand)
  favicon.*, apple-touch-icon.png
  _headers                Security headers and asset caching for Cloudflare Pages
  robots.txt, sitemap.xml
```

Each Chinese page has an English twin at the same path under `/en/`. When you change copy, change both and keep the `hreflang` links in the `<head>` matching.

## Links into the account center

All account actions go to the user center on `https://app.aifree.sg` (WP6, #41):

| Button | URL |
| --- | --- |
| 注册 / Sign up | `/account/register` |
| 登录 / Log in | `/account/login` |
| Subscribe | `/account/checkout?plan=standard`, `premium` or `residential_ip` |
| Download / account center | `/account` |

The checkout route should send a signed-out visitor to register or log in first and then continue to Stripe for the chosen plan.

## Preview locally

```bash
python3 -m http.server 8765 -d site
```

Open <http://localhost:8765/>. Cloudflare Pages serves `download/index.html` at `/download/` the same way.

## Deploy

Cloudflare Pages project with build command empty and output directory `site`. Attach `aifree.sg` and `www.aifree.sg` as custom domains, and redirect `www` to the apex in the Cloudflare dashboard. Or deploy by hand:

```bash
npx wrangler pages deploy site --project-name aifree-site
```

## Brand assets

`assets/icon.svg`, `assets/lockup*.svg`, `favicon.*` and `apple-touch-icon.png` are generated from `../brand`. After a brand change:

```bash
cp brand/aifree-icon.svg site/assets/icon.svg && cp brand/aifree-icon.svg site/favicon.svg
cp brand/aifree-lockup.svg site/assets/lockup.svg && cp brand/aifree-lockup-dark.svg site/assets/lockup-dark.svg
rsvg-convert -w 180 -h 180 brand/aifree-icon.svg -o site/apple-touch-icon.png
```

## Copy rules

- Don't use other companies' product names or logos in headings, plan names or imagery. Describe the seat generically as an "AI team-plan seat".
- Don't call aifree "official", and don't promise that accounts won't be restricted or banned.
- Prices: Standard 600, Premium 1500, Residential IP 400 CNY per month. They also live in the `plans` table in the control plane; keep both in step.
