package main

import (
	"bytes"
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
			} {
				if got := h.Get(header); got != want {
					t.Fatalf("%s %s = %q, want %q", path, header, got, want)
				}
			}
			if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Fatalf("%s CSP = %q", path, csp)
			}
			if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), accountPage) {
				t.Fatalf("%s did not serve account.html", path)
			}
		}
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
