# aifree.sg website

Static marketing site for aifree, served by nginx on the control-plane server (the same host as `ccproxy.macmini.sg`) behind Cloudflare. No build step. First-party scripts recommend an installer and check whether a visitor already has an account-center session. The marketing site does not set a cookie or load third-party scripts.

```text
site/
  index.html              Chinese home page (default language)
  en/index.html           English home page
  download/ terms/ privacy/        Chinese sub-pages (index.html in each folder)
  en/download/ en/terms/ en/privacy/  English sub-pages
  404.html                Shared not-found page
  assets/site.css         All styles
  assets/site-session.js  Homepage and download navigation session check
  assets/desktop-downloads.js  Shared chooser; points to controlplane/desktop_downloads.js
  assets/*.svg, og.png    Copies of brand files (see ../brand)
  favicon.*, apple-touch-icon.png
  _headers                Security headers and asset caching (mirrored in deploy/site/aifree.sg.conf)
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
| Account center | `/account` |

The homepage and download navigation read only `signed_in` from `GET https://app.aifree.sg/v1/account/session`. The existing session cookie stays on the account host. If the status check is unavailable, the guest links remain usable.

Both download pages and the account-center download panel use the same chooser. They default to the detected system and a matching installer when the browser reports one. The universal macOS DMG runs on both Apple silicon and Intel. The public `desktop/stable.json` feed advertises current installer links; older or unavailable feeds keep the existing versioned links intact. See [desktop publishing](../docs/desktop-updates.md#publishing) for the release order.

The checkout route should send a signed-out visitor to register or log in first and then continue to Stripe for the chosen plan.

## Preview locally

```bash
python3 -m http.server 8765 -d site
```

Open <http://localhost:8765/>. The server serves `download/index.html` at `/download/` the same way. The account status endpoint only allows the production marketing origin; local previews use the guest links.

## Deploy

```bash
deploy/site/deploy.sh            # default target ubuntu@43.156.58.218
```

The script copies `site/` (without `README.md` and `_headers`) to `/www/wwwroot/aifree.sg`, resolving the shared chooser to a regular JavaScript file, installs `deploy/site/aifree.sg.conf` as the BaoTa nginx vhost, tests the config and reloads nginx. If you change `_headers`, change the `add_header` lines in that file too. Deploy the control plane session endpoint alongside the site so the new account link can reflect login state.

How it is set up (2026-11-24):

- DNS: `aifree.sg` and `www.aifree.sg` are proxied `A` records to `43.156.58.218`. The zone's SSL mode is Full, and Always Use HTTPS is off so ACME HTTP-01 reaches the origin.
- `www.aifree.sg` and plain HTTP redirect to `https://aifree.sg`.
- Origin certificate: Let's Encrypt `aifree.sg` (ECDSA, webroot `/var/lib/aifree-site/acme`), renewed by the system certbot timer. The deploy hook `/etc/letsencrypt/renewal-hooks/deploy/aifree-site-reload-nginx` reloads nginx after renewal.

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
