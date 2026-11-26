package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func marketingSessionRequest(t *testing.T, handler http.Handler, method, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "https://"+customerHost+"/v1/account/session", nil)
	req.Host = customerHost
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %q missing no-store", method, origin)
	}
	if setCookie := rec.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("%s %q unexpectedly set a cookie: %q", method, origin, setCookie)
	}
	return rec
}

func marketingSessionState(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var body map[string]bool
	require(t, json.Unmarshal(rec.Body.Bytes(), &body))
	if len(body) != 1 {
		t.Fatalf("marketing session exposed fields: %s", rec.Body.String())
	}
	signedIn, ok := body["signed_in"]
	if !ok {
		t.Fatalf("marketing session response is missing signed_in: %s", rec.Body.String())
	}
	return signedIn
}

func TestMarketingSessionOriginAndGuestResponse(t *testing.T) {
	handler := newAPIWithMail(nil, "", "", nil, nil)

	guest := marketingSessionRequest(t, handler, http.MethodGet, marketingOrigin, nil)
	if guest.Code != http.StatusOK || marketingSessionState(t, guest) {
		t.Fatalf("guest session = HTTP %d %s", guest.Code, guest.Body.String())
	}
	if got := guest.Header().Get("Access-Control-Allow-Origin"); got != marketingOrigin {
		t.Fatalf("access-control-allow-origin = %q, want %q", got, marketingOrigin)
	}
	if got := guest.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("access-control-allow-credentials = %q, want true", got)
	}
	if got := guest.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}

	for _, origin := range []string{"", "https://www.aifree.sg", "https://aifree.sg.evil.example", "null"} {
		rec := marketingSessionRequest(t, handler, http.MethodGet, origin, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("origin %q = HTTP %d, want 403", origin, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q unexpectedly allowed by CORS: %q", origin, got)
		}
	}

	post := marketingSessionRequest(t, handler, http.MethodPost, marketingOrigin, nil)
	if post.Code != http.StatusNotFound {
		t.Fatalf("POST marketing session = HTTP %d, want 404", post.Code)
	}
	if got := post.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("POST marketing session unexpectedly allowed by CORS: %q", got)
	}

	controlPlane := httptest.NewRequest(http.MethodGet, "https://"+controlPlaneHost+"/v1/account/session", nil)
	controlPlane.Host = controlPlaneHost
	controlPlane.Header.Set("Origin", marketingOrigin)
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, controlPlane)
	if blocked.Code != http.StatusNotFound {
		t.Fatalf("control-plane host exposed marketing session: HTTP %d", blocked.Code)
	}
}

func TestMarketingSessionLifecycle(t *testing.T) {
	s := testStore(t)
	handler := newAPIWithMail(s, "", "", nil, nil)

	_, activeToken, _, _, err := s.registerCustomer(t.Context(), "active@example.com", testPassword, "", "127.0.0.1")
	require(t, err)
	active := &http.Cookie{Name: customerSessionCookie, Value: activeToken}
	if rec := marketingSessionRequest(t, handler, http.MethodGet, marketingOrigin, active); rec.Code != http.StatusOK || !marketingSessionState(t, rec) {
		t.Fatalf("active session = HTTP %d %s", rec.Code, rec.Body.String())
	}

	require(t, s.logoutCustomer(t.Context(), activeToken))
	if rec := marketingSessionRequest(t, handler, http.MethodGet, marketingOrigin, active); rec.Code != http.StatusOK || marketingSessionState(t, rec) {
		t.Fatalf("revoked session = HTTP %d %s", rec.Code, rec.Body.String())
	}

	_, expiredToken, _, _, err := s.registerCustomer(t.Context(), "expired@example.com", testPassword, "", "127.0.0.1")
	require(t, err)
	_, err = s.pool.Exec(t.Context(), "UPDATE customer_sessions SET expires_at = $1 WHERE token_hash = $2", s.now()-1, hashToken(expiredToken))
	require(t, err)
	expired := &http.Cookie{Name: customerSessionCookie, Value: expiredToken}
	if rec := marketingSessionRequest(t, handler, http.MethodGet, marketingOrigin, expired); rec.Code != http.StatusOK || marketingSessionState(t, rec) {
		t.Fatalf("expired session = HTTP %d %s", rec.Code, rec.Body.String())
	}
}
