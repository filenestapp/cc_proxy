(function () {
  "use strict";

  const downloadOrigin = "https://downloads.aifree.sg";

  function operatingSystem(browser) {
    const hints = browser.userAgentData;
    const ua = browser.userAgent || "";
    const platform = hints?.platform || browser.platform || "";
    const macUA = /Macintosh|Mac OS X/i.test(ua);
    // iPadOS desktop mode can identify as a Mac, but cannot run desktop installers.
    if (hints?.mobile || /Android|iPhone|iPad|iPod|CrOS|Mobile/i.test(ua) ||
        /Android|iOS|iPadOS|iPhone|iPad|Chrome OS/i.test(platform) ||
        ((/^mac/i.test(platform) || macUA) && browser.maxTouchPoints > 1)) return "";
    if (/^mac/i.test(platform)) return "macos";
    if (/^win/i.test(platform)) return "windows";
    if (/^linux/i.test(platform)) return "linux";
    if (macUA) return "macos";
    if (/Windows NT/i.test(ua)) return "windows";
    if (/Linux/i.test(ua)) return "linux";
    return "";
  }

  async function processor(browser) {
    const hints = browser.userAgentData;
    if (hints?.getHighEntropyValues) {
      try {
        const { architecture, bitness } = await hints.getHighEntropyValues(["architecture", "bitness"]);
        if (bitness === "32") return "";
        if (bitness === "64" && architecture === "arm") return "arm64";
        if (bitness === "64" && architecture === "x86") return "x64";
      } catch (_) {
        // The browser can withhold these hints; do not read a frozen UA as an architecture.
      }
    }
    const ua = browser.userAgent || "";
    if (/\b(?:aarch64|arm64)\b/i.test(ua)) return "arm64";
    if (!/\b(?:Chrome|Chromium|Edg)\/\d+\.0\.0\.0\b/i.test(ua) && /\b(?:x86_64|amd64|x64|win64)\b/i.test(ua)) return "x64";
    return "";
  }

  function installerURL(manifest, link) {
    const key = link.dataset.installer;
    const url = manifest.installers?.[key];
    const prefix = `${downloadOrigin}/desktop/${manifest.version}/${key}/`;
    if (typeof url !== "string" || !url.startsWith(prefix)) return "";
    const file = url.slice(prefix.length);
    if (!/^(?:[\w.+-]|%2B)+$/i.test(file) || !file.endsWith(`.${link.dataset.kind}`)) return "";
    return url;
  }

  async function loadRelease(root) {
    // The versioned links in the HTML remain usable before a new release or if the feed is unavailable.
    try {
      const response = await fetch(`${downloadOrigin}/desktop/stable.json`, { credentials: "omit", redirect: "error" });
      if (!response.ok) return;
      const manifest = await response.json();
      if (typeof manifest.version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(manifest.version)) return;
      const links = [...root.querySelectorAll("[data-installer]")];
      const urls = links.map(link => installerURL(manifest, link));
      const universal = links.findIndex(link => link.dataset.arch === "universal");
      if (universal < 0 || !urls[universal] || links.some((link, index) => !link.hasAttribute("data-fallback") && !urls[index])) return;
      links.forEach((link, index) => {
        if (urls[index]) link.href = urls[index];
        link.hidden = !urls[index];
      });
      const version = root.querySelector("[data-download-version]");
      if (version) version.textContent = manifest.version;
    } catch (_) {
      // The static download options remain available on an offline or restricted connection.
    }
  }

  function enhanceDownloads(root) {
    if (root.hasAttribute("data-downloads-ready")) return;
    root.setAttribute("data-downloads-ready", "");
    const groups = [...root.querySelectorAll("details[data-platform]")];
    const os = operatingSystem(navigator);
    const current = groups.find(group => group.dataset.platform === os);
    // An explicit operating-system link from the homepage takes precedence over detection.
    const requested = groups.find(group => group.id && `#${group.id}` === window.location.hash);
    const selected = requested || current;
    if (selected) {
      groups.forEach(group => { group.open = group === selected; });
      selected.parentElement.prepend(selected);
    }

    const badge = root.querySelector("[data-download-badge]");
    let recommended;
    let arch = "";
    function recommend() {
      if (!current) return;
      const format = /\b(?:Debian|Ubuntu)\b/i.test(navigator.userAgent || "") ? "deb" : "AppImage";
      const available = [...current.querySelectorAll("[data-installer][href]:not([hidden])")];
      // Before a universal release, recommend the Apple-silicon-only installer
      // only when the browser identifies an ARM64 Mac.
      const next = available.find(link => link.dataset.arch === "universal") ||
        available.find(link => link.dataset.arch === arch && (os !== "linux" || link.dataset.kind === format));
      if (next === recommended) return;
      if (recommended) {
        recommended.classList.replace("btn-primary", "btn-outline");
        recommended.removeAttribute("data-recommended");
      }
      recommended = next;
      badge.hidden = !next;
      if (next) {
        next.classList.replace("btn-outline", "btn-primary");
        next.setAttribute("data-recommended", "");
        next.parentElement.prepend(badge, next);
      }
    }

    loadRelease(root).then(recommend);
    if (current) processor(navigator).then(value => { arch = value; recommend(); });
  }

  window.aifreeEnhanceDownloads = enhanceDownloads;
  document.querySelectorAll("[data-downloads-auto]").forEach(enhanceDownloads);
})();
