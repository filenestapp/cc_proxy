(function () {
  "use strict";
  const signedInLink = document.querySelector("[data-session-account]");
  const guestLinks = document.querySelectorAll("[data-session-guest]");
  let pending = null;

  async function refreshSession() {
    if (pending || document.visibilityState === "hidden") return;
    const check = new AbortController();
    pending = check;
    const timeout = setTimeout(() => check.abort(), 4000);
    let signedIn = false;
    try {
      const response = await fetch("https://app.aifree.sg/v1/account/session", {
        credentials: "include", cache: "no-store", redirect: "error", signal: check.signal,
      });
      signedIn = response.ok && (await response.json()).signed_in === true;
    } catch (_) {
      // The homepage and its sign-in links still work when the account service is unavailable.
    } finally {
      clearTimeout(timeout);
      pending = null;
    }
    signedInLink.hidden = !signedIn;
    guestLinks.forEach(link => { link.hidden = signedIn; });
  }

  if (!signedInLink) return;
  refreshSession();
  window.addEventListener("pageshow", event => { if (event.persisted) refreshSession(); });
  window.addEventListener("focus", refreshSession);
  document.addEventListener("visibilitychange", refreshSession);
})();
