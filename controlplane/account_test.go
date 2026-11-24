package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type sentMail struct {
	to      string
	subject string
	content string
}

type fakeMailSender struct {
	mu       sync.Mutex
	messages []sentMail
	err      error
}

func (m *fakeMailSender) send(_ context.Context, to, subject, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, sentMail{to: to, subject: subject, content: content})
	return m.err
}

func (m *fakeMailSender) waitForMessages(t *testing.T, count int) []sentMail {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		messages := append([]sentMail(nil), m.messages...)
		m.mu.Unlock()
		if len(messages) >= count {
			return messages
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d emails; received %d", count, len(messages))
		}
		time.Sleep(time.Millisecond)
	}
}

func tokenFromMail(t *testing.T, value string) string {
	t.Helper()
	link, err := url.Parse(value)
	require(t, err)
	token := link.Query().Get("token")
	if token == "" {
		t.Fatalf("mail has no token: %q", value)
	}
	return token
}

func accountRequest(t *testing.T, handler http.Handler, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %s missing no-store", method, path)
	}
	return rec
}

func responseCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	require(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Code
}

func responseCSRF(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		CSRF string `json:"csrf"`
	}
	require(t, json.Unmarshal(rec.Body.Bytes(), &body))
	if body.CSRF == "" {
		t.Fatal("response did not contain a CSRF token")
	}
	return body.CSRF
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == customerSessionCookie {
			return cookie
		}
	}
	t.Fatal("response did not issue the customer session cookie")
	return nil
}

func TestAdminCookieAuthorizesAdminRoutes(t *testing.T) {
	s := testStore(t)
	require(t, s.addAdmin(t.Context(), "console", testPassword))
	token, _, err := s.loginAdmin(t.Context(), "console", testPassword, "127.0.0.1")
	require(t, err)
	handler := newAPIWithMail(s, testAdminToken, "", nil, nil)

	rec := accountRequest(t, handler, http.MethodGet, "/admin/users", "", &http.Cookie{Name: sessionCookie, Value: token}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin cookie /admin/users: HTTP %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminCookieDoesNotAuthorizeCustomerRoutes(t *testing.T) {
	s := testStore(t)
	require(t, s.addAdmin(t.Context(), "console", testPassword))
	token, _, err := s.loginAdmin(t.Context(), "console", testPassword, "127.0.0.1")
	require(t, err)
	handler := newAPIWithMail(s, testAdminToken, "", nil, nil)

	rec := accountRequest(t, handler, http.MethodGet, "/v1/account/me", "", &http.Cookie{Name: sessionCookie, Value: token}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin cookie /v1/account/me: HTTP %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCustomerCookieDoesNotAuthorizeAdminRoutes(t *testing.T) {
	s := testStore(t)
	_, token, _, _, err := s.registerCustomer(t.Context(), "customer@example.com", testPassword, "", "127.0.0.1")
	require(t, err)
	handler := newAPIWithMail(s, testAdminToken, "", nil, nil)

	rec := accountRequest(t, handler, http.MethodGet, "/admin/users", "", &http.Cookie{Name: customerSessionCookie, Value: token}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("customer cookie /admin/users: HTTP %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAccountActionLimiterPrunesExpiredKeys(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	limiter := accountActionLimiter{hits: map[string][]time.Time{
		"expired": {now.Add(-accountActionWindow - time.Second)},
	}}
	if !limiter.allowedEmail(now, "register", "customer@example.com", "127.0.0.1") {
		t.Fatal("first account action was rate limited")
	}
	if _, ok := limiter.hits["expired"]; ok {
		t.Fatal("expired account action limiter key was not pruned")
	}
}

func TestCustomerStoreLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	now := time.Unix(1_000_000, 0)
	s.clock = func() time.Time { return now }

	customer, sessionA, _, verification, err := s.registerCustomer(ctx, " First@Example.com ", testPassword, "zh-CN", "127.0.0.1")
	require(t, err)
	if customer.Email != "first@example.com" || customer.EmailVerified || sessionA == "" || verification == "" {
		t.Fatalf("unexpected registration result: %+v", customer)
	}
	verified, err := s.verifyCustomerEmail(ctx, verification)
	require(t, err)
	if !verified.EmailVerified {
		t.Fatal("verification did not mark the customer verified")
	}
	_, err = s.verifyCustomerEmail(ctx, verification)
	wantStatus(t, err, http.StatusBadRequest)

	_, sessionB, _, err := s.loginCustomer(ctx, customer.Email, testPassword, "127.0.0.1")
	require(t, err)
	require(t, s.changeCustomerPassword(ctx, customer.ID, testPassword, "new "+testPassword, sessionA))
	_, err = s.customerSession(ctx, sessionB)
	if err == nil {
		t.Fatal("password change did not revoke the other customer session")
	}
	_, err = s.customerSession(ctx, sessionA)
	require(t, err)
	_, suspendedSession, _, _, err := s.registerCustomer(ctx, "suspended@example.com", testPassword, "", "127.0.0.1")
	require(t, err)
	_, err = s.pool.Exec(ctx, "UPDATE customers SET status = 'suspended' WHERE email = $1", "suspended@example.com")
	require(t, err)
	if _, err := s.customerSession(ctx, suspendedSession); err == nil {
		t.Fatal("suspended customer session was authorized")
	}

	reset, err := s.issuePasswordReset(ctx, customer.Email)
	require(t, err)
	require(t, s.resetCustomerPassword(ctx, reset, "second "+testPassword))
	_, err = s.customerSession(ctx, sessionA)
	if err == nil {
		t.Fatal("password reset did not revoke all customer sessions")
	}
	_, _, _, expiry, err := s.registerCustomer(ctx, "expiry@example.com", testPassword, "", "")
	require(t, err)
	now = now.Add(verificationTokenTTL + time.Second)
	_, err = s.verifyCustomerEmail(ctx, expiry)
	wantStatus(t, err, http.StatusBadRequest)
	resetExpiry, err := s.issuePasswordReset(ctx, customer.Email)
	require(t, err)
	now = now.Add(resetTokenTTL + time.Second)
	wantStatus(t, s.resetCustomerPassword(ctx, resetExpiry, "third "+testPassword), http.StatusBadRequest)
	require(t, s.initializeSchema(ctx))
	var hasCustomers bool
	require(t, s.pool.QueryRow(ctx, "SELECT to_regclass('customers') IS NOT NULL").Scan(&hasCustomers))
	if !hasCustomers {
		t.Fatal("existing schema initialization did not preserve customer tables")
	}
}

func TestAccountHTTPRoutes(t *testing.T) {
	s := testStore(t)
	mail := &fakeMailSender{}
	handler := newAPIWithMail(s, testAdminToken, "", nil, mail)

	register := accountRequest(t, handler, http.MethodPost, "/v1/account/register",
		`{"email":" Person@Example.com ","password":"correct horse battery","locale":"zh-CN"}`, nil, "")
	if register.Code != http.StatusCreated {
		t.Fatalf("register: HTTP %d: %s", register.Code, register.Body.String())
	}
	cookieA := responseCookie(t, register)
	if !cookieA.HttpOnly || cookieA.SameSite != http.SameSiteLaxMode || cookieA.MaxAge != int(customerSessionTTL.Seconds()) {
		t.Fatalf("unexpected customer cookie: %+v", cookieA)
	}
	messages := mail.waitForMessages(t, 1)
	if len(messages) != 1 || messages[0].to != "person@example.com" {
		t.Fatalf("unexpected verification delivery: %+v", messages)
	}
	initialMe := accountRequest(t, handler, http.MethodGet, "/v1/account/me", "", cookieA, "")
	if initialMe.Code != http.StatusOK {
		t.Fatalf("initial me: HTTP %d: %s", initialMe.Code, initialMe.Body.String())
	}
	csrfA := responseCSRF(t, initialMe)

	resent := accountRequest(t, handler, http.MethodPost, "/v1/account/verify/resend", `{}`, cookieA, csrfA)
	messages = mail.waitForMessages(t, 2)
	if resent.Code != http.StatusOK || len(messages) != 2 {
		t.Fatalf("resend verification: HTTP %d, messages=%d", resent.Code, len(messages))
	}

	verify := accountRequest(t, handler, http.MethodPost, "/v1/account/verify",
		`{"token":"`+tokenFromMail(t, messages[1].content)+`"}`, nil, "")
	if verify.Code != http.StatusOK {
		t.Fatalf("verify: HTTP %d: %s", verify.Code, verify.Body.String())
	}
	reused := accountRequest(t, handler, http.MethodPost, "/v1/account/verify",
		`{"token":"`+tokenFromMail(t, messages[1].content)+`"}`, nil, "")
	if reused.Code != http.StatusBadRequest || responseCode(t, reused) != "invalid_token" {
		t.Fatalf("reused verification token: HTTP %d: %s", reused.Code, reused.Body.String())
	}

	resend := accountRequest(t, handler, http.MethodPost, "/v1/account/verify/resend", `{}`, cookieA, csrfA)
	if resend.Code != http.StatusConflict || responseCode(t, resend) != "already_verified" {
		t.Fatalf("resend verified email: HTTP %d: %s", resend.Code, resend.Body.String())
	}
	me := accountRequest(t, handler, http.MethodGet, "/v1/account/me", "", cookieA, "")
	if me.Code != http.StatusOK || responseCSRF(t, me) != csrfA || responseCookie(t, me).MaxAge != int(customerSessionTTL.Seconds()) {
		t.Fatalf("me: HTTP %d: %s", me.Code, me.Body.String())
	}

	wrong := accountRequest(t, handler, http.MethodPost, "/v1/account/login",
		`{"email":"person@example.com","password":"wrong password"}`, nil, "")
	if wrong.Code != http.StatusUnauthorized || responseCode(t, wrong) != "invalid_credentials" {
		t.Fatalf("wrong login: HTTP %d: %s", wrong.Code, wrong.Body.String())
	}
	login := accountRequest(t, handler, http.MethodPost, "/v1/account/login",
		`{"email":"person@example.com","password":"correct horse battery"}`, nil, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login: HTTP %d: %s", login.Code, login.Body.String())
	}
	cookieB := responseCookie(t, login)

	missingCSRF := accountRequest(t, handler, http.MethodPost, "/v1/account/password",
		`{"current_password":"correct horse battery","new_password":"new correct horse battery"}`, cookieA, "")
	if missingCSRF.Code != http.StatusForbidden || responseCode(t, missingCSRF) != "csrf" {
		t.Fatalf("password without CSRF: HTTP %d: %s", missingCSRF.Code, missingCSRF.Body.String())
	}
	password := accountRequest(t, handler, http.MethodPost, "/v1/account/password",
		`{"current_password":"correct horse battery","new_password":"new correct horse battery"}`, cookieA, csrfA)
	if password.Code != http.StatusNoContent {
		t.Fatalf("password: HTTP %d: %s", password.Code, password.Body.String())
	}
	if rec := accountRequest(t, handler, http.MethodGet, "/v1/account/me", "", cookieB, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session after password change: HTTP %d", rec.Code)
	}

	forgot := accountRequest(t, handler, http.MethodPost, "/v1/account/password/forgot", `{"email":"person@example.com"}`, nil, "")
	messages = mail.waitForMessages(t, 3)
	if forgot.Code != http.StatusAccepted || len(messages) != 3 {
		t.Fatalf("forgot password: HTTP %d, messages=%d", forgot.Code, len(messages))
	}
	reset := accountRequest(t, handler, http.MethodPost, "/v1/account/password/reset",
		`{"token":"`+tokenFromMail(t, messages[2].content)+`","new_password":"reset correct horse battery"}`, nil, "")
	if reset.Code != http.StatusNoContent {
		t.Fatalf("reset password: HTTP %d: %s", reset.Code, reset.Body.String())
	}
	if rec := accountRequest(t, handler, http.MethodGet, "/v1/account/me", "", cookieA, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after password reset: HTTP %d", rec.Code)
	}

	login = accountRequest(t, handler, http.MethodPost, "/v1/account/login",
		`{"email":"person@example.com","password":"reset correct horse battery"}`, nil, "")
	cookieC, csrfC := responseCookie(t, login), responseCSRF(t, login)
	logout := accountRequest(t, handler, http.MethodPost, "/v1/account/logout", `{}`, cookieC, csrfC)
	if logout.Code != http.StatusNoContent || responseCookie(t, logout).MaxAge >= 0 {
		t.Fatalf("logout: HTTP %d: %s", logout.Code, logout.Body.String())
	}
}

func TestAccountHTTPRateLimitsAndExpiry(t *testing.T) {
	s := testStore(t)
	mail := &fakeMailSender{}
	handler := newAPIWithMail(s, testAdminToken, "", nil, mail)
	for i := 0; i < 5; i++ {
		rec := accountRequest(t, handler, http.MethodPost, "/v1/account/register",
			`{"email":"register`+strconv.Itoa(i)+`@example.com","password":"correct horse battery"}`, nil, "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("registration %d: HTTP %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	limited := accountRequest(t, handler, http.MethodPost, "/v1/account/register",
		`{"email":"register6@example.com","password":"correct horse battery"}`, nil, "")
	if limited.Code != http.StatusTooManyRequests || responseCode(t, limited) != "rate_limited" {
		t.Fatalf("registration rate limit: HTTP %d: %s", limited.Code, limited.Body.String())
	}

	s2 := testStore(t)
	now := time.Unix(2_000_000, 0)
	s2.clock = func() time.Time { return now }
	mail2 := &fakeMailSender{}
	handler2 := newAPIWithMail(s2, testAdminToken, "", nil, mail2)
	registered := accountRequest(t, handler2, http.MethodPost, "/v1/account/register",
		`{"email":"expiry@example.com","password":"correct horse battery"}`, nil, "")
	if registered.Code != http.StatusCreated {
		t.Fatalf("expiry registration: HTTP %d", registered.Code)
	}
	now = now.Add(verificationTokenTTL + time.Second)
	expired := accountRequest(t, handler2, http.MethodPost, "/v1/account/verify",
		`{"token":"`+tokenFromMail(t, mail2.waitForMessages(t, 1)[0].content)+`"}`, nil, "")
	if expired.Code != http.StatusBadRequest || responseCode(t, expired) != "invalid_token" {
		t.Fatalf("expired verification token: HTTP %d: %s", expired.Code, expired.Body.String())
	}

	s3 := testStore(t)
	_, _, _, _, err := s3.registerCustomer(t.Context(), "login@example.com", testPassword, "", "")
	require(t, err)
	handler3 := newAPIWithMail(s3, testAdminToken, "", nil, &fakeMailSender{})
	for i := 0; i < loginMaxFailures; i++ {
		rec := accountRequest(t, handler3, http.MethodPost, "/v1/account/login",
			`{"email":"login@example.com","password":"wrong password"}`, nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d: HTTP %d", i, rec.Code)
		}
	}
	blocked := accountRequest(t, handler3, http.MethodPost, "/v1/account/login",
		`{"email":"login@example.com","password":"wrong password"}`, nil, "")
	if blocked.Code != http.StatusTooManyRequests || responseCode(t, blocked) != "rate_limited" {
		t.Fatalf("login rate limit: HTTP %d: %s", blocked.Code, blocked.Body.String())
	}
}

func TestDesktopEmailLoginRequiresWP4Subscription(t *testing.T) {
	s := testStore(t)
	_, _, _, _, err := s.registerCustomer(t.Context(), "desktop@example.com", testPassword, "", "")
	require(t, err)
	handler := newAPIWithMail(s, testAdminToken, "", nil, &fakeMailSender{})
	rec := accountRequest(t, handler, http.MethodPost, "/v1/login",
		`{"username":"desktop@example.com","password":"correct horse battery","device":"desktop"}`, nil, "")
	if rec.Code != http.StatusForbidden || responseCode(t, rec) != "no_active_subscription" {
		t.Fatalf("desktop customer login: HTTP %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCloudMailSenderCachesLoginAndAccount(t *testing.T) {
	var logins, lookups, sends int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			logins++
			if r.Method != http.MethodPost {
				t.Fatalf("login used %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"code":200,"data":{"token":"mail-token"}}`))
		case "/api/account/list":
			lookups++
			if r.Header.Get("Authorization") != "mail-token" {
				t.Fatalf("account lookup missing token")
			}
			_, _ = w.Write([]byte(`{"code":200,"data":[{"accountId":5,"email":"alias@example.com"},{"accountId":7,"email":"noreply@aifree.sg"}]}`))
		case "/api/email/send":
			sends++
			if r.Header.Get("Authorization") != "mail-token" {
				t.Fatalf("email send missing token")
			}
			var body struct {
				AccountID    int64    `json:"accountId"`
				ReceiveEmail []string `json:"receiveEmail"`
				Subject      string   `json:"subject"`
				Content      string   `json:"content"`
			}
			require(t, json.NewDecoder(r.Body).Decode(&body))
			if body.AccountID != 7 || len(body.ReceiveEmail) != 1 || body.ReceiveEmail[0] != "customer@example.com" || body.Subject == "" || body.Content == "" {
				t.Fatalf("unexpected send body: %+v", body)
			}
			_, _ = w.Write([]byte(`{"code":200,"data":[]}`))
		default:
			t.Fatalf("unexpected cloud-mail request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	sender := &cloudMailSender{cloudMailConnection: cloudMailConnection{
		baseURL: server.URL, email: "noreply@aifree.sg", password: "secret", client: server.Client(),
	}}
	require(t, sender.send(t.Context(), "customer@example.com", "First", "first body"))
	require(t, sender.send(t.Context(), "customer@example.com", "Second", "second body"))
	if logins != 1 || lookups != 1 || sends != 2 {
		t.Fatalf("unexpected cloud-mail cache behavior: login=%d lookup=%d send=%d", logins, lookups, sends)
	}
}
