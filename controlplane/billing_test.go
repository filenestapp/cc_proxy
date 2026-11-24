package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStripe struct {
	customers, checkout, portal int
	checkoutPlan                string
}

func (f *fakeStripe) createCustomer(_ context.Context, _ string) (string, error) {
	f.customers++
	return "cus_test", nil
}
func (f *fakeStripe) createCheckout(_ context.Context, _, price, _ string, _ int64, _, _ string) (string, error) {
	f.checkout++
	f.checkoutPlan = price
	return "https://checkout.test/session", nil
}
func (f *fakeStripe) createPortal(_ context.Context, _, _ string) (string, error) {
	f.portal++
	return "https://portal.test/session", nil
}

func billingCustomer(t *testing.T, s *store) (customer, *http.Cookie, string) {
	t.Helper()
	c, token, csrf, _, err := s.registerCustomer(t.Context(), "billing@example.com", testPassword, "", "")
	require(t, err)
	_, err = s.pool.Exec(t.Context(), "UPDATE customers SET email_verified_at=$2 WHERE id=$1", c.ID, s.now())
	require(t, err)
	return c, &http.Cookie{Name: customerSessionCookie, Value: token}, csrf
}

func stripeSignature(payload []byte, secret string, at time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	stamp := fmt.Sprint(at.Unix())
	mac.Write([]byte(stamp + "."))
	mac.Write(payload)
	return "t=" + stamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func signedWebhook(t *testing.T, handler http.Handler, payload string, secret string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", strings.NewReader(payload))
	req.Header.Set("Stripe-Signature", stripeSignature([]byte(payload), secret, now))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestBillingCustomerRoutesAndAdminCookie(t *testing.T) {
	s := testStore(t)
	c, cookie, csrf := billingCustomer(t, s)
	fake := &fakeStripe{}
	h := newAPIWithMailAndStripe(s, testAdminToken, "", nil, &fakeMailSender{}, fake)
	plans := accountRequest(t, h, http.MethodGet, "/v1/account/plans", "", nil, "")
	if plans.Code != http.StatusOK || !strings.Contains(plans.Body.String(), "residential_ip") {
		t.Fatalf("plans: %d %s", plans.Code, plans.Body.String())
	}
	checkout := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if checkout.Code != http.StatusServiceUnavailable || responseCode(t, checkout) != "stripe_unavailable" {
		// Seeded plans deliberately require an operator to configure Stripe prices.
		if checkout.Code != http.StatusOK {
			t.Fatalf("checkout before price setup: %d %s", checkout.Code, checkout.Body.String())
		}
	}
	_, err := s.pool.Exec(t.Context(), "UPDATE plans SET stripe_price_id='price_standard' WHERE code='standard'")
	require(t, err)
	checkout = accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if checkout.Code != http.StatusOK || fake.checkout != 1 || fake.checkoutPlan != "price_standard" {
		t.Fatalf("checkout: %d %s", checkout.Code, checkout.Body.String())
	}
	portal := accountRequest(t, h, http.MethodPost, "/v1/account/portal", `{}`, cookie, csrf)
	if portal.Code != http.StatusOK || fake.portal != 1 {
		t.Fatalf("portal: %d %s", portal.Code, portal.Body.String())
	}
	admin := accountRequest(t, h, http.MethodGet, "/admin/customers", "", &http.Cookie{Name: sessionCookie, Value: "not-a-session"}, "")
	if admin.Code != http.StatusUnauthorized {
		t.Fatalf("bad admin cookie: %d", admin.Code)
	}
	adminReq := httptest.NewRequest(http.MethodGet, "/admin/customers?q=billing", nil)
	adminReq.Header.Set("Authorization", "Bearer "+testAdminToken)
	adminRec := httptest.NewRecorder()
	h.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusOK || !strings.Contains(adminRec.Body.String(), "billing@example.com") {
		t.Fatalf("admin customers: %d %s", adminRec.Code, adminRec.Body.String())
	}
	for _, path := range []string{"/admin/subscriptions", "/admin/orders", "/admin/provisioning", "/admin/plans"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if c.ID == 0 {
		t.Fatal("customer was not created")
	}
}

func TestStripeWebhookReplayOrderAndProvisioning(t *testing.T) {
	s := testStore(t)
	now := time.Unix(2_000_000, 0)
	s.clock = func() time.Time { return now }
	testHost(t, s, "host", "203.0.113", 20000)
	c, _, _ := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), "UPDATE customers SET stripe_customer_id='cus_1' WHERE id=$1", c.ID)
	require(t, err)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
	h := newAPIWithMailAndStripe(s, testAdminToken, "", nil, &fakeMailSender{}, &fakeStripe{})
	created := fmt.Sprintf(`{"id":"evt_sub_new","type":"customer.subscription.created","created":20,"data":{"object":{"id":"sub_1","customer":"cus_1","status":"active","current_period_start":10,"current_period_end":10000000,"metadata":{"plan":"standard"},"items":{"data":[]}}}}`)
	rec := signedWebhook(t, h, created, "whsec_test", now)
	if rec.Code != http.StatusOK {
		t.Fatalf("created webhook: %d %s", rec.Code, rec.Body.String())
	}
	// Replaying exactly the same Stripe event must not create a second proxy or queue entry.
	if rec = signedWebhook(t, h, created, "whsec_test", now); rec.Code != http.StatusOK {
		t.Fatalf("replay: %d", rec.Code)
	}
	var user, state string
	require(t, s.pool.QueryRow(t.Context(), "SELECT user_name,state FROM customer_proxy WHERE customer_id=$1", c.ID).Scan(&user, &state))
	if user != fmt.Sprintf("c%d", c.ID) || state != "ready" {
		t.Fatalf("proxy: %s %s", user, state)
	}
	login := accountRequest(t, h, http.MethodPost, "/v1/login", `{"username":"billing@example.com","password":"correct horse battery","device":"desktop"}`, nil, "")
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"token"`) {
		t.Fatalf("desktop entitled login: %d %s", login.Code, login.Body.String())
	}
	var queues int
	require(t, s.pool.QueryRow(t.Context(), "SELECT count(*) FROM provisioning WHERE subscription_id=(SELECT id FROM subscriptions WHERE stripe_subscription_id='sub_1')").Scan(&queues))
	if queues != 1 {
		t.Fatalf("queue items after replay: %d", queues)
	}
	// Older delivery cannot regress an active subscription to past_due.
	older := strings.Replace(created, `"evt_sub_new"`, `"evt_sub_old"`, 1)
	older = strings.Replace(older, `"created":20`, `"created":10`, 1)
	older = strings.Replace(older, `"status":"active"`, `"status":"past_due"`, 1)
	if rec = signedWebhook(t, h, older, "whsec_test", now); rec.Code != http.StatusOK {
		t.Fatalf("old event: %d", rec.Code)
	}
	sub, err := s.currentSubscription(t.Context(), c.ID)
	require(t, err)
	if sub.Status != "active" {
		t.Fatalf("out of order status: %s", sub.Status)
	}
	// Cancellation revokes all devices and returns the IP to cooldown.
	_, err = s.addDevice(t.Context(), user, "mac", "darwin")
	require(t, err)
	cancelled := strings.Replace(created, `"evt_sub_new"`, `"evt_sub_cancel"`, 1)
	cancelled = strings.Replace(cancelled, `"created":20`, `"created":30`, 1)
	cancelled = strings.Replace(cancelled, `"status":"active"`, `"status":"canceled"`, 1)
	if rec = signedWebhook(t, h, cancelled, "whsec_test", now); rec.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	var revoked bool
	require(t, s.pool.QueryRow(t.Context(), "SELECT revoked_at IS NOT NULL FROM devices WHERE user_name=$1", user).Scan(&revoked))
	if !revoked {
		t.Fatal("cancellation did not revoke device")
	}
	var ip *string
	require(t, s.pool.QueryRow(t.Context(), "SELECT host(egress_ip) FROM users WHERE name=$1", user).Scan(&ip))
	if ip != nil {
		t.Fatal("cancellation did not release IP")
	}
}

func TestProvisioningWaitsForIPAndExpiry(t *testing.T) {
	s := testStore(t)
	now := time.Unix(2_000_000, 0)
	s.clock = func() time.Time { return now }
	c, _, _ := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), "UPDATE customers SET stripe_customer_id='cus_wait' WHERE id=$1", c.ID)
	require(t, err)
	event := stripeEvent{ID: "evt_wait", Type: "customer.subscription.created", Created: 1}
	event.Data.Object = []byte(`{"id":"sub_wait","customer":"cus_wait","status":"active","current_period_start":1,"current_period_end":2,"metadata":{"plan":"residential_ip"},"items":{"data":[]}}`)
	require(t, s.storeStripeEvent(t.Context(), event))
	var state string
	require(t, s.pool.QueryRow(t.Context(), "SELECT state FROM customer_proxy WHERE customer_id=$1", c.ID).Scan(&state))
	if state != "waiting_ip" {
		t.Fatalf("state=%s", state)
	}
	_, err = s.pool.Exec(t.Context(), "UPDATE subscriptions SET status='past_due',current_period_end=$1 WHERE stripe_subscription_id='sub_wait'", now.Add(-4*24*time.Hour).Unix())
	require(t, err)
	require(t, s.expireSubscriptions(t.Context()))
	sub, err := s.currentSubscription(t.Context(), c.ID)
	require(t, err)
	if sub.Status != "cancelled" {
		t.Fatalf("expiry status=%s", sub.Status)
	}
}

func TestStripeWebhookRejectsBadSignature(t *testing.T) {
	s := testStore(t)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
	h := newAPIWithMailAndStripe(s, testAdminToken, "", nil, &fakeMailSender{}, &fakeStripe{})
	req := httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", strings.NewReader(`{"id":"evt","type":"unknown"}`))
	req.Header.Set("Stripe-Signature", "t=1,v1=nope")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad sig %d", rec.Code)
	}
}
