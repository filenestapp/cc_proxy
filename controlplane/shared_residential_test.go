package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestResidentialIPWebhookHonorsSharedUserLimit(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Now()
	s.clock = func() time.Time { return now }
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	stripe := &fakeStripe{subscriptions: make(map[string]stripeSubscription)}
	handler := billingAPI(s, stripe)

	getLimit := func() int {
		t.Helper()
		response := mailboxAdminRequest(handler, http.MethodGet, "/admin/settings", "")
		wantMailboxHTTP(t, response, http.StatusOK, "")
		var cfg settings
		require(t, json.Unmarshal(response.Body.Bytes(), &cfg))
		return cfg.SharedIPUserLimit
	}
	if got := getLimit(); got != 10 {
		t.Fatalf("default shared IP user limit: got %d, want 10", got)
	}
	for _, invalid := range []string{"0", "-1", "2.5", "2147483648"} {
		response := mailboxAdminRequest(handler, http.MethodPut, "/admin/settings", `{"shared_ip_user_limit":`+invalid+`}`)
		wantMailboxHTTP(t, response, http.StatusBadRequest, "")
	}
	response := mailboxAdminRequest(handler, http.MethodPut, "/admin/settings", `{"shared_ip_user_limit":5}`)
	wantMailboxHTTP(t, response, http.StatusOK, "")
	if got := getLimit(); got != 5 {
		t.Fatalf("configured shared IP user limit: got %d, want 5", got)
	}

	const hostName, firstIP, secondIP = "test-exit", "203.0.113.3", "203.0.113.4"
	_, err := s.addHost(ctx, hostName, hostOptions{
		PublicHost: ptr("203.0.113.2"), ServerName: ptr("www.example.com"),
		PortMin: ptr(integer(20000)), PortMax: ptr(integer(20009)),
	})
	require(t, err)
	_, err = s.addIPs(ctx, hostName, []string{firstIP})
	require(t, err)
	_, err = s.pool.Exec(ctx, "UPDATE plans SET stripe_price_id='price_residential' WHERE code='residential_ip'")
	require(t, err)

	for i := 1; i <= 6; i++ {
		email := fmt.Sprintf("residential-%d@example.com", i)
		customer, session, csrf, _, err := s.registerCustomer(ctx, email, testPassword, "en", "")
		require(t, err)
		_, err = s.pool.Exec(ctx, "UPDATE customers SET email_verified_at=$2 WHERE id=$1", customer.ID, s.now())
		require(t, err)
		stripeCustomer := fmt.Sprintf("cus_residential_%d", i)
		_, err = s.setCustomerStripeID(ctx, customer.ID, stripeCustomer)
		require(t, err)
		userName := fmt.Sprintf("c%d", customer.ID)
		if i == 6 {
			// A returning customer can have an unbound proxy user from the exclusive allocation policy.
			require(t, s.addUser(ctx, userName, testPassword, "exclusive", 5))
			_, err = s.pool.Exec(ctx, `INSERT INTO customer_proxy(customer_id,user_name,state,created_at,updated_at)
				VALUES($1,$2,'none',$3,$3)`, customer.ID, userName, s.now())
			require(t, err)
		}
		cookie := &http.Cookie{Name: customerSessionCookie, Value: session}
		checkout := accountRequest(t, handler, http.MethodPost, "/v1/account/checkout", `{"plan":"residential_ip"}`, cookie, csrf)
		wantMailboxHTTP(t, checkout, http.StatusOK, "")
		subscriptionID := fmt.Sprintf("sub_residential_%d", i)
		subscription := stripeSubscriptionFixture(t, subscriptionID, stripeCustomer, "price_residential", now)
		subscription.Metadata = map[string]string{"aifree_subscription_id": fmt.Sprint(stripe.reservation.ID)}
		stripe.subscriptions[subscriptionID] = subscription
		invoice := fmt.Sprintf(`{"id":%q,"customer":%q,"subscription":%q,"amount_paid":40000,"currency":"cny"}`,
			fmt.Sprintf("in_residential_%d", i), stripeCustomer, subscriptionID)
		eventID := fmt.Sprintf("evt_residential_%d", i)
		stripeFixtureEvent(t, handler, "invoice.paid", eventID, invoice, now, http.StatusOK)

		user, err := getUser(ctx, s.pool, userName)
		require(t, err)
		sub, err := s.currentSubscription(ctx, customer.ID)
		require(t, err)
		if user.Mode != "shared" || sub == nil || sub.Status != "active" {
			t.Fatalf("customer %d did not receive the shared entitlement: user %+v, subscription %+v", i, user, sub)
		}
		if i <= 5 {
			if user.IP == nil || *user.IP != firstIP || user.Port == nil || *user.Port != 19999+i || sub.Proxy.State != "ready" {
				t.Fatalf("customer %d should share the first IP on its own port: user %+v, proxy %+v", i, user, sub.Proxy)
			}
			continue
		}

		if user.IP != nil || sub.Proxy.State != "waiting_ip" {
			t.Fatalf("the sixth customer should wait while the first IP is full: user %+v, proxy %+v", user, sub.Proxy)
		}
		_, err = s.assign(ctx, userName, assignment{IP: ptr(firstIP)}, false)
		wantStatus(t, err, http.StatusConflict)
		if !strings.Contains(err.Error(), "limit of 5 users") {
			t.Fatalf("unexpected full IP error: %v", err)
		}

		_, err = s.addIPs(ctx, hostName, []string{secondIP})
		require(t, err)
		waiting, err := s.listProvisioning(ctx)
		require(t, err)
		if len(waiting) != 1 || waiting[0].CustomerID != customer.ID || waiting[0].Kind != "waiting_ip" {
			t.Fatalf("unexpected provisioning queue: %+v", waiting)
		}
		require(t, s.completeProvisioning(ctx, waiting[0].ID, ""))
		stripeFixtureEvent(t, handler, "invoice.paid", eventID, invoice, now, http.StatusOK)
		user, err = getUser(ctx, s.pool, userName)
		require(t, err)
		if user.IP == nil || *user.IP != secondIP || user.Mode != "shared" {
			t.Fatalf("the sixth customer should use the second shared IP: %+v", user)
		}
		orders, err := s.customerOrders(ctx, customer.ID)
		require(t, err)
		if len(orders) != 1 || orders[0].Status != "paid" || orders[0].Amount != 40000 {
			t.Fatalf("unexpected order state after replay: %+v", orders)
		}
	}
}
