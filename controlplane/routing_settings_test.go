package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestSettingsStoreWebURLsAsProxiedDomains(t *testing.T) {
	values, err := settingsPatch(fields{
		"client_policy": json.RawMessage(`{
			"domain_suffix": ["https://ipcheck.ing/", "https://API.IPIFY.ORG/example", ".example.com"],
			"direct_dns": "dhcp",
			"block_quic": false
		}`),
	})
	require(t, err)
	saved, err := json.Marshal(values["client_policy"])
	require(t, err)
	var policy clientPolicy
	require(t, json.Unmarshal(saved, &policy))
	if !slices.Equal(policy.DomainSuffix, []string{"ipcheck.ing", "api.ipify.org", "example.com"}) ||
		policy.DirectDNS != "dhcp" || policy.BlockQUIC {
		t.Fatalf("unexpected normalized routing policy: %+v", policy)
	}
	for _, rule := range []string{"ftp://example.com/file", "https://user@example.com/", "example.com:443"} {
		_, err := normalizeProxiedDomains([]string{rule})
		wantStatus(t, err, 400)
	}
}

func TestRoutingGroupNormalization(t *testing.T) {
	groups, err := normalizeRoutingGroups(json.RawMessage(`{
		"claude":{"enabled":true,"domain":["https://Clau.de/","clau.de"],
		          "domain_suffix":[".Claude.AI","claude.ai"]},
		"gemini":{"enabled":false,"domain":["gemini.google.com"]}
	}`))
	require(t, err)
	if !groups["claude"].Enabled ||
		!slices.Equal(groups["claude"].Domain, []string{"clau.de"}) ||
		!slices.Equal(groups["claude"].DomainSuffix, []string{"claude.ai"}) ||
		groups["gemini"].Enabled {
		t.Fatalf("unexpected grouped rules: %+v", groups)
	}
	for _, raw := range []string{
		`null`,
		`{"other":{"enabled":true}}`,
		`{"claude":null}`,
		`{"claude":{"domain":["invalid host"]}}`,
		`{"claude":{"domain_keyword":["claude"]}}`,
	} {
		_, err := normalizeRoutingGroups(json.RawMessage(raw))
		wantStatus(t, err, http.StatusBadRequest)
	}
}

func routingSettingsRequests(t *testing.T) (
	put func(string, int) *httptest.ResponseRecorder,
	config func(string, string, int) *httptest.ResponseRecorder,
) {
	t.Helper()
	s := testStore(t)
	ctx := t.Context()
	testHost(t, s, "exit", "203.0.113", 20443)
	require(t, s.addUser(ctx, "alice", testPassword, "shared", 5))
	_, err := s.assign(ctx, "alice", assignment{Host: "exit"}, false)
	require(t, err)
	token, err := s.addDevice(ctx, "alice", "client", "macos")
	require(t, err)
	handler := newAPI(s, testAdminToken, "", nil)
	request := func(method, path, credential, body, etag string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+credential)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s returned %d, want %d (%s)", method, path, rec.Code, want, rec.Body)
		}
		return rec
	}
	put = func(body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		return request("PUT", "/admin/settings", testAdminToken, body, "", want)
	}
	config = func(query, etag string, want int) *httptest.ResponseRecorder {
		t.Helper()
		return request("GET", "/v1/config?"+query, token, "", etag, want)
	}
	return put, config
}

func TestRoutingGroupsPreserveLegacySettingsAndNegotiateExactHosts(t *testing.T) {
	put, config := routingSettingsRequests(t)
	legacy := `{"client_policy":{"domain_suffix":["custom.example","claude.ai"],"block_quic":true}}`
	put(legacy, http.StatusOK)
	previous := config("mode=app", "", http.StatusOK)
	put(`{"client_policy":{"domain_suffix":["custom.example","claude.ai"],"block_quic":true,
		"domain_groups":{"claude":{"enabled":false,"domain":["clau.de"]}}}}`, http.StatusOK)
	config("mode=app&exact_domains=1", previous.Header().Get("ETag"), http.StatusNotModified)

	put(`{"client_policy":{"domain_suffix":["custom.example","claude.ai"],"block_quic":true,"domain_groups":{
		"claude":{"enabled":true,"domain":["clau.de"],"domain_suffix":["claude.ai","anthropic.com"]},
		"openai":{"enabled":true,"domain_suffix":["chatgpt.com"]},
		"gemini":{"enabled":true,"domain":["gemini.google.com"]}
	}}}`, http.StatusOK)
	// An older settings client still submits only the flat policy.
	put(legacy, http.StatusOK)
	current := config("mode=app&exact_domains=1", "", http.StatusOK)
	oldClient := config("mode=app", "", http.StatusOK)
	type dnsRule struct {
		Server string   `json:"server"`
		Suffix []string `json:"domain_suffix"`
		Domain []string `json:"domain"`
	}
	fakeIP := func(rec *httptest.ResponseRecorder) (suffix, exact []string) {
		t.Helper()
		var cfg struct {
			DNS struct{ Rules []dnsRule }
		}
		require(t, json.Unmarshal(rec.Body.Bytes(), &cfg))
		for _, rule := range cfg.DNS.Rules {
			if rule.Server == "fakeip" {
				suffix = append(suffix, rule.Suffix...)
				exact = append(exact, rule.Domain...)
			}
		}
		return suffix, exact
	}
	for _, rec := range []*httptest.ResponseRecorder{current, oldClient} {
		suffixes, exact := fakeIP(rec)
		if !slices.Equal(suffixes, []string{"custom.example", "claude.ai", "anthropic.com", "chatgpt.com"}) {
			t.Fatalf("unexpected generated suffix rules: %v", suffixes)
		}
		if rec == oldClient && len(exact) != 0 || rec == current && !slices.Equal(exact, []string{"clau.de", "gemini.google.com"}) {
			t.Fatalf("wrong exact-rule capability behavior: %v", exact)
		}
	}
	put(`{"client_policy":{"domain_groups":{"claude":{"domain":["invalid host"]}}}}`, http.StatusBadRequest)
	config("mode=app&exact_domains=1", current.Header().Get("ETag"), http.StatusNotModified)
	unchangedProxy := config("mode=proxy", "", http.StatusOK)
	config("mode=proxy&exact_domains=1", unchangedProxy.Header().Get("ETag"), http.StatusNotModified)

	put(`{"client_policy":{"domain_suffix":["custom.example","claude.ai"],"block_quic":true,"domain_groups":{
		"claude":{"enabled":false,"domain":["clau.de"],"domain_suffix":["claude.ai","anthropic.com"]},
		"openai":{"enabled":true,"domain_suffix":["chatgpt.com"]},
		"gemini":{"enabled":true,"domain":["gemini.google.com"]}
	}}}`, http.StatusOK)
	changed := config("mode=app&exact_domains=1", current.Header().Get("ETag"), http.StatusOK)
	suffixes, exact := fakeIP(changed)
	if !slices.Equal(suffixes, []string{"custom.example", "claude.ai", "chatgpt.com"}) ||
		!slices.Equal(exact, []string{"gemini.google.com"}) {
		t.Fatalf("disabling a group changed other rules: suffixes %v, exact %v", suffixes, exact)
	}

	longDomains := func(prefix string) []string {
		domains := make([]string, 500)
		for i := range domains {
			domains[i] = fmt.Sprintf("%s%03d%s.%s.%s.%s", prefix, i, strings.Repeat("a", 59),
				strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61))
		}
		return domains
	}
	largeGroups, err := json.Marshal(map[string]routingGroup{"claude": {
		Enabled: true, Domain: longDomains("e"), DomainSuffix: longDomains("s"),
	}})
	require(t, err)
	rejected := put(`{"client_policy":{"domain_groups":`+string(largeGroups)+`}}`, http.StatusBadRequest)
	if !strings.Contains(rejected.Body.String(), "1 MiB size limit") {
		t.Fatalf("expected the config size limit, got %s", rejected.Body)
	}
	config("mode=app&exact_domains=1", changed.Header().Get("ETag"), http.StatusNotModified)

	put(`{"client_policy":{"domain_suffix":[],"domain_groups":{
		"gemini":{"enabled":true,"domain":["gemini.google.com"]}
	}}}`, http.StatusOK)
	for _, mode := range []string{"app", "domain"} {
		query := "mode=" + mode
		compatible := config(query, oldClient.Header().Get("ETag"), http.StatusOK)
		suffixes, exact := fakeIP(compatible)
		var legacyConfig struct {
			Route struct{ Final string }
		}
		require(t, json.Unmarshal(compatible.Body.Bytes(), &legacyConfig))
		if len(suffixes)+len(exact) != 0 || legacyConfig.Route.Final != "direct" {
			t.Fatalf("exact-only policy should keep suffix-only %s clients connected with direct routing", mode)
		}
		config(query, compatible.Header().Get("ETag"), http.StatusNotModified)
		suffixes, exact = fakeIP(config(query+"&exact_domains=1", compatible.Header().Get("ETag"), http.StatusOK))
		if len(suffixes) != 0 || !slices.Equal(exact, []string{"gemini.google.com"}) {
			t.Fatalf("exact-capable %s client lost its exact rule", mode)
		}
	}

	put(`{"client_policy":{"domain_groups":{"gemini":{"enabled":false,"domain":["gemini.google.com"]}}}}`, http.StatusOK)
	config("mode=app", "", http.StatusConflict)
	config("mode=domain&exact_domains=1", "", http.StatusConflict)
}

func TestSTUNPolicyNegotiatesAppModeAndPreservesLegacyConfig(t *testing.T) {
	put, config := routingSettingsRequests(t)
	domains := `{"client_policy":{"domain_suffix":["custom.example"],"direct_dns":"local","block_quic":true}}`
	put(domains, http.StatusOK)

	const old = "mode=app&exact_domains=1"
	const capable = old + "&stun=1"
	withoutFlags := config("", "", http.StatusOK)
	baseline := config(old, "", http.StatusOK)
	legacyDomain := config("mode=domain", "", http.StatusOK)
	legacyProxy := config("mode=proxy", "", http.StatusOK)
	assertRule := func(rec *httptest.ResponseRecorder, key, value string) {
		t.Helper()
		var cfg struct {
			Inbounds []struct{ Address []string }
			Route    struct{ Rules []map[string]any }
		}
		require(t, json.Unmarshal(rec.Body.Bytes(), &cfg))
		if len(cfg.Inbounds) != 1 || !slices.Equal(cfg.Inbounds[0].Address, []string{tunAddress, tunIPv6Address}) {
			t.Fatalf("invalid dual-stack TUN: %+v", cfg.Inbounds)
		}
		rules := cfg.Route.Rules
		if len(rules) < 4 || rules[1]["action"] != "hijack-dns" || rules[3]["port"] != float64(443) ||
			len(rules[2]) != 3 || rules[2]["network"] != "udp" || rules[2]["protocol"] != "stun" ||
			rules[2][key] != value {
			t.Fatalf("invalid STUN rule or order: %+v", rules)
		}
	}
	defaultProxy := config(capable, baseline.Header().Get("ETag"), http.StatusOK)
	assertRule(defaultProxy, "outbound", "egress")
	put(`{"client_policy":{"stun":"proxy"}}`, http.StatusOK)
	config(capable, defaultProxy.Header().Get("ETag"), http.StatusNotModified)

	put(`{"client_policy":{"stun":"reject"}}`, http.StatusOK)
	reject := config(capable, defaultProxy.Header().Get("ETag"), http.StatusOK)
	assertRule(reject, "action", "reject")
	put(domains, http.StatusOK)
	config(capable, reject.Header().Get("ETag"), http.StatusNotModified)
	config(old, baseline.Header().Get("ETag"), http.StatusNotModified)
	config("", withoutFlags.Header().Get("ETag"), http.StatusNotModified)
	if got := config(old, "", http.StatusOK); !bytes.Equal(baseline.Body.Bytes(), got.Body.Bytes()) {
		t.Fatal("the STUN settings change modified the legacy config bytes")
	}
	config("mode=domain&stun=1", legacyDomain.Header().Get("ETag"), http.StatusNotModified)
	config("mode=proxy&stun=1", legacyProxy.Header().Get("ETag"), http.StatusNotModified)

	put(`{"client_policy":{"stun":"direct"}}`, http.StatusOK)
	config(capable, baseline.Header().Get("ETag"), http.StatusNotModified)
	for _, invalid := range []string{`"auto"`, `null`, `""`, `true`} {
		put(`{"client_policy":{"stun":`+invalid+`}}`, http.StatusBadRequest)
	}
	config(capable, baseline.Header().Get("ETag"), http.StatusNotModified)
}

func TestDefaultHandshakeFollowsSNIAndPreservesAnOverride(t *testing.T) {
	h := host{PortMin: 20443, PortMax: 20443, HandshakePort: 443}
	require(t, (hostOptions{ServerName: ptr("old.example.com")}).apply(&h))
	require(t, (hostOptions{ServerName: ptr("google.com")}).apply(&h))
	if h.HandshakeServer != "google.com" {
		t.Fatalf("default handshake target did not follow SNI: %s", h.HandshakeServer)
	}

	require(t, (hostOptions{HandshakeServer: ptr("target.example.com")}).apply(&h))
	require(t, (hostOptions{ServerName: ptr("new.example.com")}).apply(&h))
	if h.HandshakeServer != "target.example.com" {
		t.Fatalf("the explicit handshake target changed: %s", h.HandshakeServer)
	}
	require(t, (hostOptions{HandshakeServer: ptr("")}).apply(&h))
	if h.HandshakeServer != h.ServerName {
		t.Fatalf("clearing the target did not restore the default: %s", h.HandshakeServer)
	}
}
