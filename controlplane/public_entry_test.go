package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestAutomaticPublicEntryFromAuthenticatedHeartbeat(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	handler := newAPI(s, testAdminToken, "", []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("1.0.0.1/32"),
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts",
		strings.NewReader(`{"name":"mac","port_min":20443,"port_max":20443}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create an automatic host: HTTP %d", rec.Code)
	}
	var created struct {
		Token string `json:"agent_token"`
	}
	require(t, json.Unmarshal(rec.Body.Bytes(), &created))
	if created.Token == "" {
		t.Fatal("creating a host with no public entry did not issue an Agent token")
	}

	report := func(token, peer, forwarded string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(`{"probes":[]}`))
		req.RemoteAddr = peer
		req.Header.Set("Authorization", "Bearer "+token)
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	wantEntry := func(address string, auto bool) {
		t.Helper()
		hosts, err := listHosts(ctx, s.pool)
		require(t, err)
		if len(hosts) != 1 || hosts[0].PublicHost != address || hosts[0].AutoPublicHost != auto {
			t.Fatalf("expected public entry %q (automatic %t), got %+v", address, auto, hosts)
		}
	}

	wantEntry("", true)
	host, err := getHost(ctx, s.pool, "mac")
	require(t, err)
	if host.ServerName != "google.com" || host.HandshakeServer != "google.com" {
		t.Fatalf("unexpected default TLS names: %s and %s", host.ServerName, host.HandshakeServer)
	}
	_, err = s.addIPs(ctx, "mac", []string{"192.168.1.50"})
	require(t, err)
	require(t, s.addUser(ctx, "alice", testPassword, "exclusive", 5))
	req = httptest.NewRequest(http.MethodPost, "/admin/users/alice/assign", strings.NewReader(`{"host":"mac"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign a user before the first public observation: HTTP %d", rec.Code)
	}
	var user assignmentResult
	require(t, json.Unmarshal(rec.Body.Bytes(), &user))
	if user.Entry != nil || user.EgressIP == nil || user.Port != 20443 {
		t.Fatalf("expected an assigned IP and a pending entry, got %+v", user)
	}
	device, err := s.addDevice(ctx, "alice", "test", "darwin")
	require(t, err)
	const clientPath = "/v1/config?mode=proxy"
	if status, body := get(t, handler, clientPath, device); status != http.StatusConflict || !strings.Contains(string(body), "waiting for a public IPv4") {
		t.Fatalf("unexpected pending client config: HTTP %d", status)
	}
	if status, _ := get(t, handler, "/agent/server-config", created.Token); status != http.StatusOK {
		t.Fatalf("Agent server config must be available while the entry is pending: HTTP %d", status)
	}
	entries, err := listEntries(ctx, s.pool, monitorSettings{})
	require(t, err)
	if len(entries) != 0 {
		t.Fatal("a host with no public entry was offered to entry probes")
	}
	if code := report("wrong-token", "8.8.8.8:5000", ""); code != http.StatusUnauthorized {
		t.Fatalf("heartbeat with an invalid token: HTTP %d", code)
	}
	for _, request := range []struct{ peer, forwarded string }{
		{"10.0.0.8:5000", "8.8.8.8"},       // Forwarded IP from an untrusted peer.
		{"1.0.0.1:5000", "invalid"},        // Trusted proxy with an unusable forwarding chain.
		{"127.0.0.1:5000", "100.64.1.5"},   // Carrier-grade NAT address.
		{"127.0.0.1:5000", "2606:4700::1"}, // IPv6 heartbeat.
	} {
		if code := report(created.Token, request.peer, request.forwarded); code != http.StatusOK {
			t.Fatalf("heartbeat with no usable IPv4: HTTP %d", code)
		}
	}
	wantEntry("", true)

	wantClientEntry := func(address, previousETag string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, clientPath, nil)
		req.Header.Set("Authorization", "Bearer "+device)
		if previousETag != "" {
			req.Header.Set("If-None-Match", previousETag)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var config struct {
			Outbounds []struct {
				Server string `json:"server"`
			} `json:"outbounds"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &config) != nil ||
			len(config.Outbounds) == 0 || config.Outbounds[0].Server != address {
			t.Fatalf("client config did not use entry %q: HTTP %d", address, rec.Code)
		}
		etag := rec.Header().Get("ETag")
		if etag == "" || etag == previousETag {
			t.Fatalf("expected a new config ETag after changing entry to %q", address)
		}
		return etag
	}
	if code := report(created.Token, "127.0.0.1:5000", "8.8.4.4"); code != http.StatusOK {
		t.Fatalf("heartbeat via trusted proxy: HTTP %d", code)
	}
	wantEntry("8.8.4.4", true)
	etag := wantClientEntry("8.8.4.4", "")
	entries, err = listEntries(ctx, s.pool, monitorSettings{})
	require(t, err)
	if len(entries) != 1 || entries[0].Host != "8.8.4.4" || entries[0].Port != 20443 {
		t.Fatalf("entry probes did not pick up the observed address: %+v", entries)
	}
	before, err := version(ctx, s.pool)
	require(t, err)
	if code := report(created.Token, "8.8.4.4:5000", ""); code != http.StatusOK {
		t.Fatalf("unchanged heartbeat: HTTP %d", code)
	}
	after, err := version(ctx, s.pool)
	require(t, err)
	if after != before {
		t.Fatal("an unchanged public address bumped the configuration version")
	}

	if code := report(created.Token, "9.9.9.9:5000", ""); code != http.StatusOK {
		t.Fatalf("heartbeat after the public IP changed: HTTP %d", code)
	}
	wantEntry("9.9.9.9", true)
	etag = wantClientEntry("9.9.9.9", etag)

	require(t, s.updateHost(ctx, "mac", hostOptions{PublicHost: ptr("relay.example.com")}))
	if code := report(created.Token, "8.8.4.4:5000", ""); code != http.StatusOK {
		t.Fatalf("heartbeat for a manual host: HTTP %d", code)
	}
	wantEntry("relay.example.com", false)
	wantClientEntry("relay.example.com", etag)
	require(t, s.updateHost(ctx, "mac", hostOptions{PublicHost: ptr("")}))
	wantEntry("", true)
}

func TestObservedPublicIPv4SchemaUpgradePreservesManualHosts(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	testHost(t, s, "legacy", "192.0.2", 20443)
	_, err := s.pool.Exec(ctx, "ALTER TABLE hosts DROP COLUMN observed_public_ipv4")
	require(t, err)
	require(t, s.initializeSchema(ctx))
	require(t, s.initializeSchema(ctx))
	hosts, err := listHosts(ctx, s.pool)
	require(t, err)
	if len(hosts) != 1 || hosts[0].PublicHost != "192.0.2.2" || hosts[0].AutoPublicHost {
		t.Fatalf("the additive migration changed the existing host: %+v", hosts)
	}
}
