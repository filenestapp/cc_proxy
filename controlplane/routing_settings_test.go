package main

import (
	"encoding/json"
	"slices"
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
