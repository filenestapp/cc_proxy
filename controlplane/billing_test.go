package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStripe struct {
	customers, checkout, expires, portal, reads int
	reservation                                 checkoutReservation
	subscriptions                               map[string]stripeSubscription
	readErr, expireErr                          error
	checkoutErr                                 error
	onValidate                                  func(checkoutReservation) error
	onExpire                                    func()
}

func (f *fakeStripe) createCustomer(_ context.Context, _, _ string) (string, error) {
	f.customers++
	return "cus_test", nil
}
func (f *fakeStripe) validateCheckoutPrice(_ context.Context, reservation checkoutReservation) error {
	if f.onValidate != nil {
		return f.onValidate(reservation)
	}
	return nil
}
func (f *fakeStripe) createCheckout(_ context.Context, _ string, reservation checkoutReservation) (stripeCheckoutSession, error) {
	f.checkout++
	f.reservation = reservation
	if f.checkoutErr != nil {
		return stripeCheckoutSession{}, f.checkoutErr
	}
	return stripeCheckoutSession{ID: "cs_test", URL: "https://checkout.test/session"}, nil
}
func (f *fakeStripe) expireCheckout(_ context.Context, sessionID string) error {
	f.expires++
	if sessionID != "cs_test" {
		return errors.New("unexpected Checkout Session ID")
	}
	if f.onExpire != nil {
		f.onExpire()
	}
	return f.expireErr
}
func (f *fakeStripe) createPortal(_ context.Context, _, _ string) (string, error) {
	f.portal++
	return "https://portal.test/session", nil
}
func (f *fakeStripe) getSubscription(_ context.Context, id string) (stripeSubscription, error) {
	f.reads++
	if f.readErr != nil {
		return stripeSubscription{}, f.readErr
	}
	subscription, ok := f.subscriptions[id]
	if !ok {
		return stripeSubscription{}, errors.New("missing Stripe fixture subscription")
	}
	return subscription, nil
}

func billingAPI(s *store, stripe stripeClient) http.Handler {
	s.stripe = stripe
	return newAPIWithMail(s, testAdminToken, "", nil, &fakeMailSender{})
}

func stripeSubscriptionFixture(t *testing.T, id, customerID, priceID string, now time.Time) stripeSubscription {
	t.Helper()
	payload := fmt.Sprintf(`{"id":%q,"customer":%q,"status":"active","latest_invoice":{"status":"paid"},
		"items":{"data":[{"price":{"id":%q},"current_period_start":%d,"current_period_end":%d}]}}`,
		id, customerID, priceID, now.Unix(), now.Add(30*24*time.Hour).Unix())
	var subscription stripeSubscription
	require(t, json.Unmarshal([]byte(payload), &subscription))
	return subscription
}

func stripeFixtureEvent(t *testing.T, h http.Handler, eventType, id, object string, now time.Time, wantStatus int) {
	t.Helper()
	payload := fmt.Sprintf(`{"id":%q,"type":%q,"created":%d,"data":{"object":%s}}`, id, eventType, now.Unix(), object)
	rec := signedWebhook(t, h, payload, "fixture-signing-secret", now)
	if rec.Code != wantStatus {
		t.Fatalf("%s: got HTTP %d, want %d: %s", eventType, rec.Code, wantStatus, rec.Body.String())
	}
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
	h := billingAPI(s, fake)
	plans := accountRequest(t, h, http.MethodGet, "/v1/account/plans", "", nil, "")
	if plans.Code != http.StatusOK || !strings.Contains(plans.Body.String(), `"code":"residential_ip"`) ||
		!strings.Contains(plans.Body.String(), `"amount":40000`) || strings.Contains(plans.Body.String(), "stripe_price_id") {
		t.Fatalf("plans: %d %s", plans.Code, plans.Body.String())
	}
	checkout := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if checkout.Code != http.StatusServiceUnavailable || responseCode(t, checkout) != "stripe_unavailable" {
		t.Fatalf("checkout before price setup: %d %s", checkout.Code, checkout.Body.String())
	}
	update := httptest.NewRequest(http.MethodPut, "/admin/plans", strings.NewReader(`{"plans":[{"code":"standard","name":"Standard","amount":65000,"stripe_price_id":"price_standard","active":true,"sort":10}]}`))
	update.Header.Set("Authorization", "Bearer "+testAdminToken)
	updateRec := httptest.NewRecorder()
	h.ServeHTTP(updateRec, update)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update Standard plan: %d %s", updateRec.Code, updateRec.Body.String())
	}
	plans = accountRequest(t, h, http.MethodGet, "/v1/account/plans", "", nil, "")
	if !strings.Contains(plans.Body.String(), `"amount":65000`) || strings.Contains(plans.Body.String(), "price_standard") {
		t.Fatalf("updated public plans: %s", plans.Body.String())
	}
	checkout = accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if checkout.Code != http.StatusOK || fake.checkout != 1 || fake.reservation.PriceID != "price_standard" {
		t.Fatalf("checkout: %d %s", checkout.Code, checkout.Body.String())
	}
	first := fake.reservation
	checkout = accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if checkout.Code != http.StatusOK || fake.reservation != first || fake.customers != 1 {
		t.Fatalf("Checkout retry did not reuse the reservation and customer: %d %+v", checkout.Code, fake)
	}
	checkout = accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if checkout.Code != http.StatusServiceUnavailable || responseCode(t, checkout) != "stripe_unavailable" {
		t.Fatalf("competing checkout without a configured plan: %d %s", checkout.Code, checkout.Body.String())
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
	_, err := s.pool.Exec(t.Context(), `INSERT INTO orders(customer_id,amount_cny,status,created_at) VALUES($1,60000,'paid',$2)`, c.ID, s.now())
	require(t, err)
	for _, path := range []string{"/admin/subscriptions", "/admin/orders", "/admin/provisioning", "/admin/plans"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		if path == "/admin/orders" && !strings.Contains(rec.Body.String(), `"email":"billing@example.com"`) {
			t.Fatalf("admin orders omitted customer email: %s", rec.Body.String())
		}
	}
	if c.ID == 0 {
		t.Fatal("customer was not created")
	}
}

func TestCheckoutPlanChangeExpiresPendingSession(t *testing.T) {
	s := testStore(t)
	c, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id=CASE code WHEN 'standard' THEN 'price_standard' WHEN 'premium' THEN 'price_premium' ELSE stripe_price_id END`)
	require(t, err)
	fake := &fakeStripe{}
	h := billingAPI(s, fake)

	first := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if first.Code != http.StatusOK || fake.checkout != 1 {
		t.Fatalf("initial checkout: %d %s", first.Code, first.Body.String())
	}
	changed := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if changed.Code != http.StatusOK || fake.expires != 1 || fake.checkout != 2 || fake.reservation.Plan != "premium" {
		t.Fatalf("changed checkout: HTTP %d fake=%+v body=%s", changed.Code, fake, changed.Body.String())
	}
	var expired, pending int
	err = s.pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE status='expired'),count(*) FILTER (WHERE status='pending') FROM subscriptions WHERE customer_id=$1`, c.ID).Scan(&expired, &pending)
	require(t, err)
	if expired != 1 || pending != 1 {
		t.Fatalf("unexpected reservation states: expired=%d pending=%d", expired, pending)
	}
}

func TestCheckoutPlanChangeAfterExpiryWebhook(t *testing.T) {
	s := testStore(t)
	c, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id='price_' || code WHERE code IN ('standard','premium')`)
	require(t, err)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	fake := &fakeStripe{}
	h := billingAPI(s, fake)
	first := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("initial checkout: %d %s", first.Code, first.Body.String())
	}
	firstID := fake.reservation.ID
	fake.onExpire = func() {
		payload := fmt.Sprintf(`{"id":"cs_test","customer":"cus_test","metadata":{"aifree_subscription_id":%q}}`, fmt.Sprint(firstID))
		stripeFixtureEvent(t, h, "checkout.session.expired", "evt_switch_expired", payload, s.clock(), http.StatusOK)
	}
	changed := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if changed.Code != http.StatusOK || fake.reservation.ID == firstID || fake.reservation.Plan != "premium" {
		t.Fatalf("checkout after Stripe expiry webhook: %d %s", changed.Code, changed.Body.String())
	}
	var open, expired int
	require(t, s.pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE status='pending'),count(*) FILTER (WHERE status='expired')
		FROM subscriptions WHERE customer_id=$1`, c.ID).Scan(&open, &expired))
	if open != 1 || expired != 1 {
		t.Fatalf("plan switch left %d pending and %d expired reservations", open, expired)
	}
}

func TestCheckoutPlanChangeRecoversMissingSessionID(t *testing.T) {
	s := testStore(t)
	_, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id='price_' || code WHERE code IN ('standard','premium')`)
	require(t, err)
	fake := &fakeStripe{}
	h := billingAPI(s, fake)
	first := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("initial checkout: %d %s", first.Code, first.Body.String())
	}
	firstReservation := fake.reservation
	_, err = s.pool.Exec(t.Context(), "UPDATE subscriptions SET checkout_session_id='' WHERE id=$1", firstReservation.ID)
	require(t, err)
	fake.onExpire = func() {
		if fake.reservation != firstReservation || fake.checkout != 2 {
			t.Fatalf("expiration did not recover the original reservation: %+v", fake.reservation)
		}
	}
	changed := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if changed.Code != http.StatusOK || fake.reservation.Plan != "premium" || fake.checkout != 3 {
		t.Fatalf("plan switch after recovering the Session: %d %s", changed.Code, changed.Body.String())
	}
}

func TestCheckoutPlanChangeAfterPriceValidationFails(t *testing.T) {
	for _, test := range []struct {
		name   string
		legacy bool
	}{
		{name: "unstarted reservation"},
		{name: "legacy reservation with immutable mismatch", legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := testStore(t)
			c, cookie, csrf := billingCustomer(t, s)
			_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id='price_' || code WHERE code IN ('standard','premium')`)
			require(t, err)
			fake := &fakeStripe{onValidate: func(reservation checkoutReservation) error {
				if reservation.Plan == "standard" {
					return errStripeCheckoutPriceMismatch
				}
				return nil
			}}
			h := billingAPI(s, fake)
			first := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
			if first.Code != http.StatusServiceUnavailable || responseCode(t, first) != "stripe_unavailable" || fake.checkout != 0 {
				t.Fatalf("invalid price created a Session: %d %s", first.Code, first.Body.String())
			}
			if test.legacy {
				_, err := s.pool.Exec(t.Context(), "UPDATE subscriptions SET checkout_started=NULL WHERE customer_id=$1", c.ID)
				require(t, err)
			}
			changed := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
			if changed.Code != http.StatusOK || fake.checkout != 1 || fake.expires != 0 || fake.reservation.Plan != "premium" {
				t.Fatalf("valid replacement was blocked or replayed the rejected checkout: %d %s", changed.Code, changed.Body.String())
			}
			var oldStatus, oldID string
			require(t, s.pool.QueryRow(t.Context(), "SELECT status,checkout_session_id FROM subscriptions WHERE customer_id=$1 AND plan_code='standard'", c.ID).Scan(&oldStatus, &oldID))
			if oldStatus != "expired" || oldID != "" {
				t.Fatalf("unexpected rejected reservation: status=%s Session=%q", oldStatus, oldID)
			}
		})
	}
}

func TestCheckoutRetiredDuringPriceValidationCannotStart(t *testing.T) {
	s := testStore(t)
	_, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id='price_' || code WHERE code IN ('standard','premium')`)
	require(t, err)
	fake := &fakeStripe{}
	h := billingAPI(s, fake)
	fake.onValidate = func(reservation checkoutReservation) error {
		if reservation.Plan == "standard" {
			replacement := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
			if replacement.Code != http.StatusOK {
				t.Fatalf("replace checkout during Price validation: %d %s", replacement.Code, replacement.Body.String())
			}
		}
		return nil
	}
	retired := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if retired.Code != http.StatusConflict || responseCode(t, retired) != "subscription_exists" || fake.checkout != 1 || fake.reservation.Plan != "premium" {
		t.Fatalf("retired reservation sent another Checkout request: %d %s", retired.Code, retired.Body.String())
	}
}

func TestCheckoutPlanChangePreservesUnconfirmedSession(t *testing.T) {
	s := testStore(t)
	c, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id='price_' || code WHERE code IN ('standard','premium')`)
	require(t, err)
	fake := &fakeStripe{checkoutErr: errors.New("Stripe response was lost")}
	h := billingAPI(s, fake)
	first := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if first.Code != http.StatusInternalServerError || fake.checkout != 1 {
		t.Fatalf("initial Checkout did not reach Stripe: %d %s", first.Code, first.Body.String())
	}
	fake.onValidate = func(reservation checkoutReservation) error {
		if reservation.Plan == "standard" {
			return failureCode(503, "stripe_unavailable", "Stripe Price became inactive")
		}
		return nil
	}
	changed := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if changed.Code != http.StatusServiceUnavailable || fake.checkout != 1 {
		t.Fatalf("another Session was created while the prior outcome was unknown: %d %s", changed.Code, changed.Body.String())
	}
	var started bool
	require(t, s.pool.QueryRow(t.Context(), `SELECT checkout_started FROM subscriptions WHERE customer_id=$1 AND status='pending'`, c.ID).Scan(&started))
	if !started {
		t.Fatal("the possibly sent Stripe request lost its persisted marker")
	}
}

func TestCheckoutPlanChangeRejectsCompletedSession(t *testing.T) {
	s := testStore(t)
	c, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(t.Context(), `UPDATE plans SET stripe_price_id=CASE code WHEN 'standard' THEN 'price_standard' WHEN 'premium' THEN 'price_premium' ELSE stripe_price_id END`)
	require(t, err)
	fake := &fakeStripe{expireErr: errStripeCheckoutCompleted}
	h := billingAPI(s, fake)
	first := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("initial checkout: %d %s", first.Code, first.Body.String())
	}
	changed := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if changed.Code != http.StatusConflict || responseCode(t, changed) != "subscription_exists" || fake.expires != 1 || fake.checkout != 1 {
		t.Fatalf("completed Checkout Session was not rejected: HTTP %d fake=%+v body=%s", changed.Code, fake, changed.Body.String())
	}
	now := s.clock().Add(25 * time.Hour)
	s.clock = func() time.Time { return now }
	require(t, s.expireSubscriptions(t.Context()))
	changed = accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"premium"}`, cookie, csrf)
	if changed.Code != http.StatusConflict || responseCode(t, changed) != "subscription_exists" || fake.expires != 2 || fake.checkout != 1 {
		t.Fatalf("a delayed completion webhook allowed another checkout: HTTP %d body=%s", changed.Code, changed.Body.String())
	}
	var status, plan string
	err = s.pool.QueryRow(t.Context(), `SELECT status,plan_code FROM subscriptions WHERE customer_id=$1`, c.ID).Scan(&status, &plan)
	require(t, err)
	if status != "pending" || plan != "standard" {
		t.Fatalf("completed Checkout Session changed reservation: status=%s plan=%s", status, plan)
	}
}

func TestStripeWebhookReplayOrderAndProvisioning(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Unix(2_000_000, 0)
	s.clock = func() time.Time { return now }
	testHost(t, s, "host", "203.0.113", 20000)
	c, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(ctx, "UPDATE plans SET stripe_price_id='price_standard' WHERE code='standard'")
	require(t, err)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	fake := &fakeStripe{subscriptions: make(map[string]stripeSubscription)}
	h := billingAPI(s, fake)
	checkout := accountRequest(t, h, http.MethodPost, "/v1/account/checkout", `{"plan":"standard"}`, cookie, csrf)
	if checkout.Code != http.StatusOK {
		t.Fatalf("checkout: %d %s", checkout.Code, checkout.Body.String())
	}
	subscription := stripeSubscriptionFixture(t, "sub_1", "cus_test", "price_standard", now)
	subscription.Metadata = map[string]string{"aifree_subscription_id": fmt.Sprint(fake.reservation.ID)}
	fake.subscriptions["sub_1"] = subscription

	invoice := `{"id":"in_1","customer":"cus_test","parent":{"subscription_details":{"subscription":"sub_1"}},
		"amount_due":60000,"amount_paid":60000,"currency":"cny","hosted_invoice_url":"https://invoice.stripe.com/i/fixture"}`
	versionBefore, err := version(ctx, s.pool)
	require(t, err)

	// A provider read failure must leave the event eligible for a later retry.
	fake.readErr = errors.New("fixture temporarily unavailable")
	stripeFixtureEvent(t, h, "invoice.paid", "evt_paid", invoice, now, http.StatusInternalServerError)
	fake.readErr = nil
	stripeFixtureEvent(t, h, "invoice.paid", "evt_paid", invoice, now, http.StatusOK)
	stripeFixtureEvent(t, h, "invoice.paid", "evt_paid", invoice, now, http.StatusOK)
	if fake.reads != 2 {
		t.Fatalf("duplicate delivery read Stripe again: %d reads", fake.reads)
	}

	// Subscription, Checkout and failure messages can all follow the paid invoice for the same second.
	stripeFixtureEvent(t, h, "customer.subscription.updated", "evt_stale",
		`{"id":"sub_1","customer":"cus_test","status":"past_due","latest_invoice":"in_1"}`, now, http.StatusOK)
	completed := fmt.Sprintf(`{"id":"cs_test","customer":"cus_test","subscription":"sub_1","client_reference_id":%q,
		"metadata":{"plan":"standard","aifree_subscription_id":%q}}`, fmt.Sprint(c.ID), fmt.Sprint(fake.reservation.ID))
	stripeFixtureEvent(t, h, "checkout.session.completed", "evt_completed", completed, now, http.StatusOK)
	stripeFixtureEvent(t, h, "invoice.payment_failed", "evt_old_failure", invoice, now, http.StatusOK)
	sub, err := s.currentSubscription(ctx, c.ID)
	require(t, err)
	if sub == nil || sub.Status != "active" || sub.CurrentPeriodEnd == nil || *sub.CurrentPeriodEnd != float64(subscription.Items.Data[0].CurrentPeriodEnd) || sub.Proxy.State != "ready" {
		t.Fatalf("subscription after out-of-order Stripe events: %+v", sub)
	}
	orders := accountRequest(t, h, http.MethodGet, "/v1/account/orders", "", cookie, "")
	var history []orderView
	require(t, json.Unmarshal(orders.Body.Bytes(), &history))
	if len(history) != 1 || history[0].Status != "paid" || history[0].Amount != 60000 || history[0].ReceiptURL != "https://invoice.stripe.com/i/fixture" ||
		!strings.Contains(orders.Body.String(), `"status":"paid"`) {
		t.Fatalf("unexpected invoice history: %s", orders.Body.String())
	}
	versionAfter, err := version(ctx, s.pool)
	require(t, err)
	if versionAfter <= versionBefore {
		t.Fatal("the egress agent was not notified of the new binding")
	}
	var user, mode string
	require(t, s.pool.QueryRow(ctx, `SELECT u.name,u.mode FROM users u JOIN customer_proxy cp ON cp.user_name=u.name
		WHERE cp.customer_id=$1`, c.ID).Scan(&user, &mode))
	if user != fmt.Sprintf("c%d", c.ID) || mode != "exclusive" {
		t.Fatalf("unexpected proxy user or binding mode: %s %s", user, mode)
	}
	login := accountRequest(t, h, http.MethodPost, "/v1/login", `{"username":"billing@example.com","password":"correct horse battery","device":"desktop"}`, nil, "")
	var session struct{ Token string }
	require(t, json.Unmarshal(login.Body.Bytes(), &session))
	if login.Code != http.StatusOK || session.Token == "" {
		t.Fatalf("desktop entitled login: %d %s", login.Code, login.Body.String())
	}
	devices := accountRequest(t, h, http.MethodGet, "/v1/account/devices", "", cookie, "")
	if !strings.Contains(devices.Body.String(), `"active":true`) || !strings.Contains(devices.Body.String(), `"last_seen_at":`) {
		t.Fatalf("unexpected device contract: %s", devices.Body.String())
	}

	queue, err := s.listProvisioning(ctx)
	require(t, err)
	if len(queue) != 1 || queue[0].Kind != "team_seat" {
		t.Fatalf("unexpected manual provisioning queue: %+v", queue)
	}
	require(t, s.completeProvisioning(ctx, queue[0].ID, "Seat assigned"))
	stripeFixtureEvent(t, h, "customer.subscription.updated", "evt_renewal", `{"id":"sub_1","customer":"cus_test"}`, now, http.StatusOK)
	queue, err = s.listProvisioning(ctx)
	require(t, err)
	if len(queue) != 0 {
		t.Fatalf("renewal requeued an already provisioned seat: %+v", queue)
	}

	subscription.Status = "canceled"
	fake.subscriptions["sub_1"] = subscription
	stripeFixtureEvent(t, h, "customer.subscription.deleted", "evt_cancel", `{"id":"sub_1","customer":"cus_test"}`, now, http.StatusOK)
	_, err = s.identifyDevice(ctx, session.Token)
	wantStatus(t, err, http.StatusUnauthorized)
	var ip *string
	require(t, s.pool.QueryRow(ctx, "SELECT host(egress_ip) FROM users WHERE name=$1", user).Scan(&ip))
	var cooldown float64
	require(t, s.pool.QueryRow(ctx, "SELECT cooldown_until FROM egress_ips WHERE ip='203.0.113.3'").Scan(&cooldown))
	if ip != nil || cooldown <= s.now() {
		t.Fatalf("cancellation did not release the IP to cooldown: ip=%v cooldown=%f", ip, cooldown)
	}
}

func TestProvisioningWaitsForPaidInvoiceAndReleasesAtPeriodEnd(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Unix(2_000_000, 0)
	s.clock = func() time.Time { return now }
	c, _, _ := billingCustomer(t, s)
	_, err := s.pool.Exec(ctx, "UPDATE customers SET stripe_customer_id='cus_wait' WHERE id=$1", c.ID)
	require(t, err)
	_, err = s.pool.Exec(ctx, "UPDATE plans SET stripe_price_id='price_premium' WHERE code='premium'")
	require(t, err)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	subscription := stripeSubscriptionFixture(t, "sub_wait", "cus_wait", "price_premium", now)
	subscription.LatestInvoice.Status = "open"
	fake := &fakeStripe{subscriptions: map[string]stripeSubscription{"sub_wait": subscription}}
	h := billingAPI(s, fake)
	details := `{"id":"sub_wait","customer":"cus_wait"}`
	stripeFixtureEvent(t, h, "customer.subscription.created", "evt_open", details, now, http.StatusOK)
	sub, err := s.currentSubscription(ctx, c.ID)
	require(t, err)
	if sub == nil || sub.Status != "pending" || sub.Proxy.State != "none" {
		t.Fatalf("an unpaid invoice must leave service pending: %+v", sub)
	}

	subscription.LatestInvoice.Status = "paid"
	fake.subscriptions["sub_wait"] = subscription
	invoice := `{"id":"in_wait","customer":"cus_wait","subscription":"sub_wait","amount_paid":150000,"currency":"cny"}`
	stripeFixtureEvent(t, h, "invoice.paid", "evt_wait_paid", invoice, now, http.StatusOK)
	sub, err = s.currentSubscription(ctx, c.ID)
	require(t, err)
	if sub == nil || sub.Status != "active" || sub.Proxy.State != "waiting_ip" {
		t.Fatalf("paid subscription without free IP: %+v", sub)
	}
	if _, _, err := s.loginCustomerProxy(ctx, c.ID, "unassigned", "darwin"); statusOf(err) != http.StatusForbidden {
		t.Fatalf("customer without a proxy assignment received a token: %v", err)
	}
	_, err = s.evaluateAlerts(ctx, nil)
	require(t, err)
	alerts, err := listAlerts(ctx, s.pool, false)
	require(t, err)
	if len(alerts) != 1 || alerts[0].Rule != "subscription_waiting_ip" {
		t.Fatalf("IP shortage alert: %+v", alerts)
	}
	queue, err := s.listProvisioning(ctx)
	require(t, err)
	if len(queue) != 2 || queue[0].Kind != "team_seat" || queue[1].Kind != "waiting_ip" {
		t.Fatalf("both paid provisioning tasks must be queued: %+v", queue)
	}
	wantStatus(t, s.completeProvisioning(ctx, queue[1].ID, ""), http.StatusConflict)
	testHost(t, s, "host", "203.0.113", 20000)
	require(t, s.completeProvisioning(ctx, queue[1].ID, "IP pool replenished"))
	token, _, err := s.loginCustomerProxy(ctx, c.ID, "desktop", "darwin")
	require(t, err)

	subscription.CancelAtPeriodEnd = true
	subscription.Items.Data[0].CurrentPeriodEnd = now.Add(time.Hour).Unix()
	fake.subscriptions["sub_wait"] = subscription
	stripeFixtureEvent(t, h, "customer.subscription.updated", "evt_cancel_scheduled", details, now, http.StatusOK)
	now = now.Add(time.Hour)
	require(t, s.expireSubscriptions(ctx))
	sub, err = s.currentSubscription(ctx, c.ID)
	require(t, err)
	if sub.Status != "cancelled" || sub.Proxy.State != "none" {
		t.Fatalf("scheduled cancellation did not expire rights: %+v", sub)
	}
	_, err = s.identifyDevice(ctx, token)
	wantStatus(t, err, http.StatusUnauthorized)
	wantStatus(t, s.completeProvisioning(ctx, queue[0].ID, ""), http.StatusNotFound)
}

func TestStripeFailedRenewalUsesGraceFromTheUnpaidInvoice(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Unix(7_000_000, 0)
	s.clock = func() time.Time { return now }
	testHost(t, s, "host", "203.0.113", 20000)
	customer, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(ctx, "UPDATE customers SET stripe_customer_id='cus_renewal' WHERE id=$1", customer.ID)
	require(t, err)
	_, err = s.pool.Exec(ctx, "UPDATE plans SET stripe_price_id='price_ip' WHERE code='residential_ip'")
	require(t, err)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	subscription := stripeSubscriptionFixture(t, "sub_renewal", "cus_renewal", "price_ip", now.Add(-30*24*time.Hour))
	fake := &fakeStripe{subscriptions: map[string]stripeSubscription{"sub_renewal": subscription}}
	handler := billingAPI(s, fake)
	details := `{"id":"sub_renewal","customer":"cus_renewal"}`
	stripeFixtureEvent(t, handler, "customer.subscription.created", "evt_signed_up", details, now, http.StatusOK)

	subscription.Status = "past_due"
	subscription.LatestInvoice = stripeInvoice{Created: now.Unix(), Status: "open"}
	subscription.Items.Data[0].CurrentPeriodStart = now.Unix()
	subscription.Items.Data[0].CurrentPeriodEnd = now.Add(30 * 24 * time.Hour).Unix()
	fake.subscriptions["sub_renewal"] = subscription
	failed := `{"id":"in_renewal","customer":"cus_renewal","subscription":"sub_renewal","amount_due":40000,"currency":"cny"}`
	stripeFixtureEvent(t, handler, "invoice.payment_failed", "evt_renewal_failed", failed, now, http.StatusOK)
	now = now.Add(3*24*time.Hour - time.Second)
	token, _, err := s.loginCustomerProxy(ctx, customer.ID, "desktop", "darwin")
	require(t, err)
	now = now.Add(time.Second)
	require(t, s.expireSubscriptions(ctx))
	_, err = s.identifyDevice(ctx, token)
	wantStatus(t, err, http.StatusUnauthorized)
	blocked := accountRequest(t, handler, http.MethodPost, "/v1/account/checkout", `{"plan":"residential_ip"}`, cookie, csrf)
	if blocked.Code != http.StatusConflict {
		t.Fatalf("a still-collectible Stripe subscription allowed a second checkout: %d %s", blocked.Code, blocked.Body.String())
	}
	subscription.Status = "active"
	subscription.LatestInvoice.Status = "paid"
	fake.subscriptions["sub_renewal"] = subscription
	paid := `{"id":"in_renewal","customer":"cus_renewal","subscription":"sub_renewal","amount_paid":40000,"currency":"cny"}`
	stripeFixtureEvent(t, handler, "invoice.paid", "evt_renewal_paid", paid, now, http.StatusOK)
	recovered, err := s.currentSubscription(ctx, customer.ID)
	require(t, err)
	if recovered == nil || recovered.Status != "active" || recovered.Proxy.State != "ready" {
		t.Fatalf("paid renewal did not restore access: %+v", recovered)
	}
	queue, err := s.listProvisioning(ctx)
	require(t, err)
	if len(queue) != 0 {
		t.Fatalf("Residential IP does not include a manual Team seat: %+v", queue)
	}
}

type stripeFixtureTransport func(*http.Request) (*http.Response, error)

func (f stripeFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestStripeCheckoutUsesMatchingPriceAndStableIdempotencyKey(t *testing.T) {
	reservation := checkoutReservation{ID: 9, CustomerID: 7, Plan: "standard", PriceID: "price_standard", Amount: 60000, ExpiresAt: 2000000}
	priceAmount := 65000
	var keys []string
	client := stripeHTTPClient{key: "fixture-key", client: &http.Client{Transport: stripeFixtureTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.stripe.com" || req.Header.Get("Stripe-Version") != stripeAPIVersion {
			t.Fatalf("unexpected Stripe target or API version: %s", req.URL)
		}
		var body string
		switch req.Method + " " + req.URL.Path {
		case "GET /v1/prices/price_standard":
			body = fmt.Sprintf(`{"active":true,"currency":"cny","unit_amount":%d,"recurring":{"interval":"month","interval_count":1}}`, priceAmount)
		case "POST /v1/checkout/sessions":
			require(t, req.ParseForm())
			if req.Form.Get("mode") != "subscription" || req.Form.Get("client_reference_id") != "7" ||
				req.Form.Get("subscription_data[metadata][aifree_subscription_id]") != "9" || req.Form.Get("expires_at") != "2000000" {
				t.Fatalf("unexpected Checkout parameters: %v", req.Form)
			}
			keys = append(keys, req.Header.Get("Idempotency-Key"))
			body = `{"id":"cs_fixture","url":"https://checkout.stripe.com/c/pay/fixture"}`
		default:
			t.Fatalf("unexpected Stripe request: %s %s", req.Method, req.URL.Path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
	err := client.validateCheckoutPrice(t.Context(), reservation)
	wantStatus(t, err, http.StatusServiceUnavailable)
	if !errors.Is(err, errStripeCheckoutPriceMismatch) {
		t.Fatalf("mismatched Price lacks immutable rejection evidence: %v", err)
	}
	if len(keys) != 0 {
		t.Fatal("mismatched Stripe price started a Checkout Session")
	}
	priceAmount = 60000
	for range 2 {
		require(t, client.validateCheckoutPrice(t.Context(), reservation))
		checkout, err := client.createCheckout(t.Context(), "cus_fixture", reservation)
		require(t, err)
		if checkout.ID != "cs_fixture" || checkout.URL != "https://checkout.stripe.com/c/pay/fixture" {
			t.Fatalf("unexpected Checkout Session: %+v", checkout)
		}
	}
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("Checkout retries used different idempotency keys: %v", keys)
	}
}

func TestStripeExpiresCheckoutSession(t *testing.T) {
	for _, test := range []struct {
		name, retrievedStatus    string
		wantCompleted, wantError bool
	}{
		{name: "newly expired"},
		{name: "already expired", retrievedStatus: "expired"},
		{name: "already completed", retrievedStatus: "complete", wantCompleted: true, wantError: true},
		{name: "still open", retrievedStatus: "open", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			client := stripeHTTPClient{key: "fixture-key", client: &http.Client{Transport: stripeFixtureTransport(func(req *http.Request) (*http.Response, error) {
				status := http.StatusOK
				var body string
				switch req.Method + " " + req.URL.Path {
				case "POST /v1/checkout/sessions/cs_fixture/expire":
					body = `{"id":"cs_fixture","status":"expired"}`
					if test.retrievedStatus != "" {
						status = http.StatusBadRequest
						body = `{"error":{"code":"checkout_session_not_open","message":"Only open Checkout Sessions can be expired"}}`
					}
				case "GET /v1/checkout/sessions/cs_fixture":
					reads++
					body = fmt.Sprintf(`{"id":"cs_fixture","status":%q}`, test.retrievedStatus)
				default:
					t.Fatalf("unexpected Stripe request: %s %s", req.Method, req.URL.Path)
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			err := client.expireCheckout(t.Context(), "cs_fixture")
			if (err != nil) != test.wantError || errors.Is(err, errStripeCheckoutCompleted) != test.wantCompleted {
				t.Fatalf("expire Checkout Session returned %v", err)
			}
			wantReads := 0
			if test.retrievedStatus != "" {
				wantReads = 1
			}
			if reads != wantReads {
				t.Fatalf("Stripe Session was read %d times, want %d", reads, wantReads)
			}
		})
	}
}

func TestStripeWebhookRejectsBadSignature(t *testing.T) {
	s := testStore(t)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
	h := billingAPI(s, &fakeStripe{})
	req := httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", strings.NewReader(`{"id":"evt","type":"unknown"}`))
	req.Header.Set("Stripe-Signature", "t=1,v1=nope")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad sig %d", rec.Code)
	}
}
