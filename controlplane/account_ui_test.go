package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// uiClient drives the API the way account.html does: on app.aifree.sg, with the
// session cookie the server sets and the CSRF token from login or /me.
type uiClient struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	csrf   string
	called map[string]bool
}

func (c *uiClient) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = customerHost
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if withCSRF {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		c.t.Fatalf("%s %s missing no-store", method, path)
	}
	for _, set := range rec.Result().Cookies() {
		if set.Name == customerSessionCookie {
			if set.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = &http.Cookie{Name: set.Name, Value: set.Value}
			}
		}
	}
	route := regexp.MustCompile(`/devices/[^/]+/revoke$`).ReplaceAllString(path, "/devices/")
	c.called[strings.SplitN(route, "?", 2)[0]] = true
	return rec
}

func (c *uiClient) expect(rec *httptest.ResponseRecorder, status int, code string) {
	c.t.Helper()
	if rec.Code != status {
		c.t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, status, code)
	}
	if code != "" {
		if got := responseCode(c.t, rec); got != code {
			c.t.Fatalf("code = %q, want %q (%s)", got, code, rec.Body)
		}
		if !strings.Contains(string(accountPage), "e_"+code+":") {
			c.t.Fatalf("account.html has no message for %s", code)
		}
	}
}

// mutation checks that a session request is refused without X-CSRF-Token and
// accepted with it, which is how the page sends every non-GET.
func (c *uiClient) mutation(path, body string, status int) *httptest.ResponseRecorder {
	c.t.Helper()
	c.expect(c.do(http.MethodPost, path, body, false), http.StatusForbidden, "csrf")
	rec := c.do(http.MethodPost, path, body, true)
	c.expect(rec, status, "")
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return out
}

// Every /v1/account route that account.html calls, exercised in the order a
// customer meets them, against PostgreSQL and the fake Stripe client.
func TestAccountUIRoutes(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	s := testStore(t)
	fake := &fakeStripe{}
	s.stripe = fake
	mail := &fakeMailSender{}
	c := &uiClient{t: t, h: newAPIWithMail(s, testAdminToken, "", nil, mail), called: map[string]bool{}}

	plans := decodeJSON[struct{ Plans []planView }](t, c.do(http.MethodGet, "/v1/account/plans", "", false))
	if len(plans.Plans) != 3 {
		t.Fatalf("plans = %+v", plans)
	}

	c.expect(c.do(http.MethodGet, "/v1/account/me", "", false), http.StatusUnauthorized, "")
	c.expect(c.do(http.MethodPost, "/v1/account/register", `{"email":"ui@example.com","password":"short","locale":"en"}`, false), 400, "weak_password")
	c.expect(c.do(http.MethodPost, "/v1/account/register", `{"email":"UI@example.com ","password":"uipass123","locale":"en"}`, true), 201, "")
	if c.cookie == nil {
		t.Fatal("register did not set the session cookie")
	}
	c.expect(c.do(http.MethodPost, "/v1/account/register", `{"email":"ui@example.com","password":"uipass123"}`, false), 409, "email_taken")

	me := decodeJSON[struct {
		Customer     customer
		CSRF         string
		Subscription *subscriptionView
		Mailbox      any
	}](t, c.do(http.MethodGet, "/v1/account/me", "", false))
	if me.CSRF == "" || me.Customer.Email != "ui@example.com" || me.Customer.EmailVerified || me.Subscription != nil {
		t.Fatalf("me after register = %+v", me)
	}
	c.csrf = me.CSRF

	_, err := s.pool.Exec(t.Context(), "UPDATE plans SET stripe_price_id='price_premium' WHERE code='premium'")
	require(t, err)
	c.expect(c.do(http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, true), 403, "email_unverified")

	c.mutation("/v1/account/verify/resend", "{}", 200)
	messages := mail.waitForMessages(t, 2)
	c.expect(c.do(http.MethodPost, "/v1/account/verify", `{"token":"`+tokenFromMail(t, messages[1].content)+`"}`, false), 200, "")
	c.expect(c.do(http.MethodPost, "/v1/account/verify", `{"token":"`+tokenFromMail(t, messages[0].content)+`"}`, false), 400, "invalid_token")
	c.expect(c.do(http.MethodPost, "/v1/account/verify/resend", "{}", true), 409, "already_verified")

	checkout := decodeJSON[struct{ URL string }](t, c.mutation("/v1/account/checkout", `{"plan":"premium"}`, 200))
	if checkout.URL != "https://checkout.test/session" || fake.reservation.PriceID != "price_premium" {
		t.Fatalf("checkout = %+v, reservation %+v", checkout, fake.reservation)
	}
	portal := decodeJSON[struct{ URL string }](t, c.mutation("/v1/account/portal", "{}", 200))
	if portal.URL != "https://portal.test/session" {
		t.Fatalf("portal = %+v", portal)
	}

	// The page polls this after ?checkout=success; a pending Checkout reads as null
	// or a pending subscription, never an error.
	sub := c.do(http.MethodGet, "/v1/account/subscription", "", false)
	c.expect(sub, 200, "")
	if body := strings.TrimSpace(sub.Body.String()); body != "null" && !strings.Contains(body, `"status":"pending"`) {
		t.Fatalf("subscription during checkout = %s", body)
	}

	var customerID int64
	require(t, s.pool.QueryRow(t.Context(), "SELECT id FROM customers WHERE email='ui@example.com'").Scan(&customerID))
	_, err = s.pool.Exec(t.Context(), `INSERT INTO orders(customer_id,amount_cny,status,receipt_url,paid_at,created_at) VALUES($1,150000,'paid','https://pay.stripe.com/receipts/x',$2,$2)`, customerID, s.now())
	require(t, err)
	orders := decodeJSON[[]orderView](t, c.do(http.MethodGet, "/v1/account/orders", "", false))
	if len(orders) != 1 || orders[0].Amount != 150000 || orders[0].ReceiptURL == "" {
		t.Fatalf("orders = %+v", orders)
	}

	c.expect(c.do(http.MethodGet, "/v1/account/devices", "", false), 200, "")
	const proxy = "ui-proxy"
	_, err = s.pool.Exec(t.Context(), `INSERT INTO users(name,password_hash,created_at) VALUES($1,'x',$2)`, proxy, s.now())
	require(t, err)
	_, err = s.pool.Exec(t.Context(), `INSERT INTO customer_proxy(customer_id,user_name,state,created_at,updated_at) VALUES($1,$2,'waiting_ip',$3,$3)`, customerID, proxy, s.now())
	require(t, err)
	_, err = s.pool.Exec(t.Context(), `INSERT INTO devices(user_name,name,platform,token_hash,created_at) VALUES($1,'office-pc/2','windows','ui-device-token',$2)`, proxy, s.now())
	require(t, err)
	devices := decodeJSON[[]customerDeviceView](t, c.do(http.MethodGet, "/v1/account/devices", "", false))
	if len(devices) != 1 || devices[0].Name != "office-pc/2" || !devices[0].Active {
		t.Fatalf("devices = %+v", devices)
	}
	// The page sends encodeURIComponent(name), so "/" arrives as %2F.
	c.mutation("/v1/account/devices/office-pc%2F2/revoke", "{}", 204)
	devices = decodeJSON[[]customerDeviceView](t, c.do(http.MethodGet, "/v1/account/devices", "", false))
	if len(devices) != 1 || devices[0].Active {
		t.Fatalf("devices after revoke = %+v", devices)
	}

	c.expect(c.do(http.MethodPost, "/v1/account/password", `{"current_password":"wrongpass1","new_password":"uipass456"}`, true), 401, "invalid_credentials")
	if c.cookie == nil {
		t.Fatal("a wrong current password must not end the session")
	}
	c.mutation("/v1/account/password", `{"current_password":"uipass123","new_password":"uipass456"}`, 204)
	c.mutation("/v1/account/logout", "{}", 204)
	if c.cookie != nil {
		t.Fatal("logout did not clear the session cookie")
	}
	c.expect(c.do(http.MethodGet, "/v1/account/me", "", false), http.StatusUnauthorized, "")

	c.expect(c.do(http.MethodPost, "/v1/account/login", `{"email":"ui@example.com","password":"uipass123"}`, false), 401, "invalid_credentials")
	login := decodeJSON[struct{ CSRF string }](t, c.do(http.MethodPost, "/v1/account/login", `{"email":"ui@example.com","password":"uipass456"}`, false))
	if login.CSRF == "" || c.cookie == nil {
		t.Fatalf("login = %+v", login)
	}
	c.csrf = login.CSRF

	c.expect(c.do(http.MethodPost, "/v1/account/password/forgot", `{"email":"ui@example.com"}`, true), 202, "")
	reset := mail.waitForMessages(t, 3)[2].content
	c.expect(c.do(http.MethodPost, "/v1/account/password/reset", `{"token":"`+tokenFromMail(t, reset)+`","new_password":"uipass789"}`, true), 204, "")
	c.expect(c.do(http.MethodGet, "/v1/account/me", "", false), http.StatusUnauthorized, "")

	// Every API path the page references must have been exercised above.
	var missing []string
	for _, path := range regexp.MustCompile(`"(/v1/account/[a-z/]*)"`).FindAllStringSubmatch(string(accountPage), -1) {
		if !c.called[path[1]] {
			missing = append(missing, path[1])
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("account.html calls routes this test does not cover: %v", missing)
	}
}

// The user center lives on app.aifree.sg only; the control-plane hosts hide it.
func TestAccountPageHostRouting(t *testing.T) {
	h := newAPIWithMail(nil, testAdminToken, "", nil, nil)
	paths := []string{"/account", "/account/", "/account/login", "/account/register", "/account/forgot",
		"/account/verify?token=x", "/account/reset?token=x", "/account/checkout?plan=premium"}
	for _, tc := range []struct {
		host string
		want int
	}{
		{customerHost, 200}, {customerHost + ":443", 200}, {"APP.AIFREE.SG.", 200},
		{controlPlaneHost, 404}, {legacyControlPlaneHost, 404}, {legacyControlPlaneHost + ":8443", 404},
	} {
		for _, path := range paths {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("GET %s on %s = %d, want %d", path, tc.host, rec.Code, tc.want)
			}
			if tc.want == 200 && rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("GET %s on %s missing Referrer-Policy", path, tc.host)
			}
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	req.Host = customerHost
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("console on %s = %d, want 404", customerHost, rec.Code)
	}
}
