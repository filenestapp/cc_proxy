package main

import (
	"net/netip"
	"slices"
	"testing"
)

func TestMacAgentSeedsOnlyEmptyEgressPools(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	newHost := func(name string) string {
		t.Helper()
		token, err := s.addHost(ctx, name, hostOptions{})
		require(t, err)
		return token
	}
	report := func(name, token, ip string) error {
		return s.reportAgent(ctx, name, token, netip.Addr{}, heartbeat{LocalEgressIPv4: ip}, nil)
	}
	wantPool := func(name string, expected ...string) {
		t.Helper()
		ips, err := columnOf[string](ctx, s.pool, "SELECT host(ip) FROM egress_ips WHERE host=$1 ORDER BY ip", name)
		require(t, err)
		if !slices.Equal(ips, expected) {
			t.Fatalf("host %s has egress IPs %v, expected %v", name, ips, expected)
		}
	}

	token := newHost("mac")
	wantStatus(t, report("mac", "wrong-token", "192.168.1.217"), 401)
	for _, ip := range []string{"127.0.0.1", "169.254.1.2", "::1", "invalid"} {
		require(t, report("mac", token, ip))
	}
	wantPool("mac")

	before, err := version(ctx, s.pool)
	require(t, err)
	err = s.reportAgent(ctx, "mac", token, netip.MustParseAddr("8.8.8.8"),
		heartbeat{LocalEgressIPv4: "192.168.1.217"}, nil)
	require(t, err)
	after, err := version(ctx, s.pool)
	require(t, err)
	if after != before+1 {
		t.Fatalf("discovering both addresses should produce one revision, got %d to %d", before, after)
	}
	wantPool("mac", "192.168.1.217")
	require(t, report("mac", token, "192.168.1.218"))
	wantPool("mac", "192.168.1.217")

	other := newHost("other")
	require(t, report("other", other, "192.168.1.217"))
	wantPool("other")
	wantPool("mac", "192.168.1.217")

	manual := newHost("manual")
	_, err = s.addIPs(ctx, "manual", []string{"10.0.0.7"})
	require(t, err)
	// The Agent download omits banned IPs, but the inventory must preserve them.
	_, err = s.pool.Exec(ctx, "UPDATE egress_ips SET banned=true WHERE host='manual'")
	require(t, err)
	require(t, report("manual", manual, "192.168.1.219"))
	wantPool("manual", "10.0.0.7")

	concurrent := newHost("concurrent")
	done := make(chan error, 2)
	for _, ip := range []string{"192.168.1.220", "192.168.1.221"} {
		go func() { done <- report("concurrent", concurrent, ip) }()
	}
	require(t, <-done)
	require(t, <-done)
	var count int
	require(t, s.pool.QueryRow(ctx, "SELECT count(*) FROM egress_ips WHERE host='concurrent'").Scan(&count))
	if count != 1 {
		t.Fatalf("concurrent heartbeats added %d addresses", count)
	}
}
