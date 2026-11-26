package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountPageRoutes(t *testing.T) {
	handler := newAPIWithMail(nil, "", "", nil, nil)
	paths := []string{
		"/account", "/account/", "/account/login", "/account/register", "/account/forgot",
		"/account/verify?token=abc", "/account/reset?token=abc", "/account/checkout?plan=premium",
	}
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			if rec.Code != 200 {
				t.Fatalf("%s %s = %d, want 200", method, path, rec.Code)
			}
			h := rec.Header()
			if got := h.Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("%s content type = %q", path, got)
			}
			for header, want := range map[string]string{
				"Cache-Control":          "no-store",
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "no-referrer",
			} {
				if got := h.Get(header); got != want {
					t.Fatalf("%s %s = %q, want %q", path, header, got, want)
				}
			}
			if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") ||
				!strings.Contains(csp, "connect-src 'self' https://downloads.aifree.sg") || !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Fatalf("%s CSP = %q", path, csp)
			}
			if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), accountPage) {
				t.Fatalf("%s did not serve account.html", path)
			}
		}
	}
}

func TestAccountPageDesktopDownloadLinks(t *testing.T) {
	_, panel, found := strings.Cut(string(accountPage), `aria-labelledby="h-download">`)
	if !found {
		t.Fatal("account dashboard is missing the download panel")
	}
	panel, _, found = strings.Cut(panel, "</article>")
	if !found || strings.Contains(panel, "data-site=") {
		t.Fatal("download panel is malformed")
	}

	const base = "https://downloads.aifree.sg/desktop/0.2.0/"
	installers := []string{
		"darwin-aarch64/aifree_0.2.0_aarch64.dmg",
		"windows-x86_64/aifree_0.2.0_x64-setup.exe",
		"windows-aarch64/aifree_0.2.0_arm64-setup.exe",
		"linux-x86_64-deb/aifree_0.2.0_amd64.deb",
		"linux-x86_64-appimage/aifree_0.2.0_amd64.AppImage",
		"linux-aarch64-deb/aifree_0.2.0_arm64.deb",
		"linux-aarch64-appimage/aifree_0.2.0_aarch64.AppImage",
	}
	if count := strings.Count(panel, "<a "); count != len(installers)+1 {
		t.Fatalf("download panel has %d links, want %d", count, len(installers)+1)
	}
	for _, installer := range installers {
		if count := strings.Count(panel, `href="`+base+installer+`"`); count != 1 {
			t.Errorf("download panel has %d links to %s, want 1", count, installer)
		}
	}
	for _, platform := range []string{"macos", "windows", "linux"} {
		if !strings.Contains(panel, `details class="dl-group" data-platform="`+platform+`"`) {
			t.Errorf("download panel does not group %s installers", platform)
		}
	}
	if !strings.Contains(panel, `data-installer="darwin-universal"`) ||
		!strings.Contains(panel, `data-arch="universal"`) ||
		!strings.Contains(panel, `data-download-badge`) {
		t.Fatal("download panel has no universal macOS release placeholder or recommendation badge")
	}
	if !strings.Contains(string(accountPage), "aifreeEnhanceDownloads") {
		t.Fatal("account page does not use the shared desktop download chooser")
	}
}

func TestAccountPageUnknownSubpath(t *testing.T) {
	handler := newAPIWithMail(nil, "", "", nil, nil)
	for _, path := range []string{"/account/admin", "/account/login/extra"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != 404 {
			t.Fatalf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader("{}")))
	if rec.Code == 200 {
		t.Fatalf("POST /account/login served the page")
	}
}

// The page must stay within the CSP the server sends: no external scripts,
// styles or images, and every API call it makes must be one the contract defines.
func TestAccountPageSelfContained(t *testing.T) {
	page := string(accountPage)
	for _, banned := range []string{"<script src", `rel="stylesheet"`, "<img ", "innerHTML", "eval(", "Anthropic", "Claude", "官方", "official"} {
		if strings.Contains(page, banned) {
			t.Fatalf("account.html contains %q", banned)
		}
	}
	if !strings.Contains(page, `"X-CSRF-Token"`) {
		t.Fatal("account.html does not send X-CSRF-Token")
	}
	for _, path := range []string{
		"/v1/account/register", "/v1/account/verify", "/v1/account/verify/resend", "/v1/account/login",
		"/v1/account/logout", "/v1/account/me", "/v1/account/password", "/v1/account/password/forgot",
		"/v1/account/password/reset", "/v1/account/plans", "/v1/account/checkout", "/v1/account/portal",
		"/v1/account/subscription", "/v1/account/orders", "/v1/account/devices",
	} {
		if !strings.Contains(page, `"`+path+`"`) && !strings.Contains(page, `"`+path+`/"`) {
			t.Fatalf("account.html never calls %s", path)
		}
	}
}

// Every error code in docs/aifree-account-api.md (and the codes the server emits)
// needs a Chinese and an English message.
func TestAccountPageErrorCodes(t *testing.T) {
	page := string(accountPage)
	codes := []string{
		"invalid_email", "weak_password", "email_taken", "invalid_credentials", "invalid_token",
		"email_unverified", "suspended", "rate_limited", "already_verified", "csrf",
		"subscription_exists", "no_active_subscription", "no_entitlement", "quota_exceeded",
		"address_taken", "invalid_local_part", "mail_unavailable", "stripe_unavailable",
	}
	for _, code := range codes {
		if n := strings.Count(page, "e_"+code+":"); n != 2 {
			t.Fatalf("error code %s has %d translations, want 2 (zh, en)", code, n)
		}
	}
}

// Verify and reset links carry a one-time token in the query string. The page must
// move it out of the URL before its first request, and never send a Referer.
func TestAccountPageKeepsLinkTokenOutOfReferer(t *testing.T) {
	page := string(accountPage)
	if !strings.Contains(page, `<meta name="referrer" content="no-referrer">`) {
		t.Fatal("account.html must set referrer no-referrer")
	}
	capture := strings.Index(page, "\n  captureLinkToken();")
	firstRequest := strings.Index(page, "loadMe().then(route")
	if capture < 0 || firstRequest < 0 || capture > firstRequest {
		t.Fatal("captureLinkToken() must run before the first API request at boot")
	}
	body := page[strings.Index(page, "function captureLinkToken"):]
	body = body[:strings.Index(body, "\n  }\n")]
	if !strings.Contains(body, `q.delete("token")`) || !strings.Contains(body, "history.replaceState") {
		t.Fatal("captureLinkToken must strip the token from the address bar")
	}
	if n := strings.Count(page, `get("token")`); n != 1 {
		t.Fatalf("token read from the URL %d times; only captureLinkToken may read it", n)
	}
}

// End to end against PostgreSQL: the emailed verify/reset links open the page with
// no-referrer, a fresh token succeeds, and a used or unknown token gets invalid_token,
// which the page maps to a localized message.
func TestAccountPageLinkTokens(t *testing.T) {
	s := testStore(t)
	mail := &fakeMailSender{}
	handler := newAPIWithMail(s, testAdminToken, "", nil, mail)

	rec := accountRequest(t, handler, http.MethodPost, "/v1/account/register", `{"email":"link@example.com","password":"linkpass1"}`, nil, "")
	if rec.Code != 201 {
		t.Fatalf("register = %d %s", rec.Code, rec.Body)
	}
	verifyLink := mail.waitForMessages(t, 1)[0].content
	if !strings.HasPrefix(verifyLink, "https://app.aifree.sg/account/verify?token=") {
		t.Fatalf("verify link = %q", verifyLink)
	}
	token := tokenFromMail(t, verifyLink)

	openLink := func(link string) {
		t.Helper()
		page := accountRequest(t, handler, http.MethodGet, strings.TrimPrefix(link, "https://app.aifree.sg"), "", nil, "")
		if page.Code != 200 || page.Header().Get("Referrer-Policy") != "no-referrer" || !bytes.Equal(page.Body.Bytes(), accountPage) {
			t.Fatalf("GET %s = %d, Referrer-Policy %q", link, page.Code, page.Header().Get("Referrer-Policy"))
		}
	}
	expectCode := func(rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		var body struct{ Code string }
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != status || body.Code != code {
			t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, status, code)
		}
		if code != "" && !strings.Contains(string(accountPage), "e_"+code+":") {
			t.Fatalf("page has no message for %s", code)
		}
	}

	openLink(verifyLink)
	expectCode(accountRequest(t, handler, http.MethodPost, "/v1/account/verify", `{"token":"`+token+`"}`, nil, ""), 200, "")
	expectCode(accountRequest(t, handler, http.MethodPost, "/v1/account/verify", `{"token":"`+token+`"}`, nil, ""), 400, "invalid_token")
	expectCode(accountRequest(t, handler, http.MethodPost, "/v1/account/verify", `{"token":"not-a-token"}`, nil, ""), 400, "invalid_token")

	rec = accountRequest(t, handler, http.MethodPost, "/v1/account/password/forgot", `{"email":"link@example.com"}`, nil, "")
	if rec.Code != 202 {
		t.Fatalf("forgot = %d %s", rec.Code, rec.Body)
	}
	resetLink := mail.waitForMessages(t, 2)[1].content
	if !strings.HasPrefix(resetLink, "https://app.aifree.sg/account/reset?token=") {
		t.Fatalf("reset link = %q", resetLink)
	}
	resetToken := tokenFromMail(t, resetLink)
	openLink(resetLink)
	expectCode(accountRequest(t, handler, http.MethodPost, "/v1/account/password/reset", `{"token":"not-a-token","new_password":"newlinkpass"}`, nil, ""), 400, "invalid_token")
	if rec := accountRequest(t, handler, http.MethodPost, "/v1/account/password/reset", `{"token":"`+resetToken+`","new_password":"newlinkpass"}`, nil, ""); rec.Code != 204 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	expectCode(accountRequest(t, handler, http.MethodPost, "/v1/account/password/reset", `{"token":"`+resetToken+`","new_password":"otherpass1"}`, nil, ""), 400, "invalid_token")
	if rec := accountRequest(t, handler, http.MethodPost, "/v1/account/login", `{"email":"link@example.com","password":"newlinkpass"}`, nil, ""); rec.Code != 200 {
		t.Fatalf("login with reset password = %d %s", rec.Code, rec.Body)
	}
}
