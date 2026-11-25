package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// The device visitor endpoint hands a signed-in device its own user's mapping and nothing else (issue #61).
func TestDeviceXTCPVisitorScope(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	testHost(t, s, "nat", "192.0.2", 20440)  // ports 20440-20443
	testHost(t, s, "pub", "198.51.100", 30000) // stays on the public entry
	for _, name := range []string{"alice", "bob", "carol", "erin", "dave"} {
		require(t, s.addUser(ctx, name, testPassword, "shared", 5))
	}
	_, err := s.assign(ctx, "alice", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20443))}, false)
	require(t, err)
	_, err = s.assign(ctx, "bob", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20440))}, false)
	require(t, err)
	_, err = s.assign(ctx, "carol", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20441))}, false)
	require(t, err)
	_, err = s.assign(ctx, "erin", assignment{IP: ptr("198.51.100.3")}, false)
	require(t, err)
	tokens := map[string]string{}
	for _, name := range []string{"alice", "bob", "carol", "erin", "dave"} {
		tokens[name], _, err = s.loginUser(ctx, name, testPassword, name+"-desk", "macos")
		require(t, err)
	}

	handler := newAPI(s, testAdminToken, "", []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	call := func(bearer, etag string) (int, []byte, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/xtcp-visitor", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		if etag != "" {
			req.Header.Set("If-None-Match", `"`+etag+`"`)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes(), strings.Trim(rec.Header().Get("ETag"), `"`)
	}

	// Before XTCP is enabled, every assigned user is on the public entry.
	if code, body, _ := call(tokens["bob"], ""); code != 204 || len(body) != 0 {
		t.Fatalf("public-entry host: HTTP %d %s", code, body)
	}

	ca := testCertPEM(t, true)
	_, err = s.putXTCP(ctx, "nat", xtcpRequest{ServerAddr: ptr("frps.example.com"), CAPEM: &ca,
		AuthToken: ptr("frps-token-0123456789abcdef"), ProxyName: ptr("ccproxy-nat-direct"),
		SecretKey: ptr("xtcp-secret-0123456789abcdef"), LocalPort: ptr(integer(20443))})
	require(t, err)
	x, _, err := getXTCP(ctx, s.pool, "nat")
	require(t, err)

	// sing-box would dial the host's real address, where no visitor listens: refuse with a reason.
	if code, body, _ := call(tokens["bob"], ""); code != 409 || !strings.Contains(string(body), "127.0.0.1") {
		t.Fatalf("XTCP host without the loopback entry: HTTP %d %s", code, body)
	}
	require(t, s.updateHost(ctx, "nat", hostOptions{PublicHost: ptr("127.0.0.1")}))

	visitor := func(user string) (deviceVisitor, string, string) {
		t.Helper()
		code, body, etag := call(tokens[user], "")
		if code != 200 {
			t.Fatalf("visitor for %s: HTTP %d %s", user, code, body)
		}
		var v deviceVisitor
		require(t, json.Unmarshal(body, &v))
		return v, string(body), etag
	}
	va, rawA, _ := visitor("alice")
	vb, rawB, etagB := visitor("bob")
	vc, rawC, _ := visitor("carol")

	if va.ProxyName != "ccproxy-nat-direct" || va.SecretKey != x.SecretKey || va.BindPort != 20443 {
		t.Fatalf("alice holds the primary mapping: %+v", va)
	}
	wantB := userSecretKey(x.MappingSecret, "ccproxy-nat-direct-20440", "bob")
	if vb.ProxyName != "ccproxy-nat-direct-20440" || vb.SecretKey != wantB || vb.BindPort != 20440 || vb.BindAddr != "127.0.0.1" {
		t.Fatalf("bob gets his own mapping: %+v", vb)
	}
	if vb.ServerAddr != "frps.example.com" || vb.ServerPort != defaultFrpsPort || vb.TLSServerName != "frps.example.com" ||
		vb.CAPEM != x.CAPEM || vb.AuthToken != x.AuthToken {
		t.Fatalf("bob gets the frps connection settings: %+v", vb)
	}
	if vb.ExitState != xtcpSyncUpgradeNeeded {
		t.Fatalf("a host whose agent never reported XTCP sync is upgrade_needed: %q", vb.ExitState)
	}
	for user, raw := range map[string]string{"alice": rawA, "bob": rawB, "carol": rawC} {
		if strings.Contains(raw, x.MappingSecret) || strings.Contains(raw, "mapping_secret") {
			t.Fatalf("%s's response carries the mapping secret: %s", user, raw)
		}
		var fields map[string]any
		require(t, json.Unmarshal([]byte(raw), &fields))
		if len(fields) != 10 || fields["host"] != nil || fields["user"] != nil {
			t.Fatalf("%s's response has fields beyond the visitor settings: %s", user, raw)
		}
	}
	if strings.Contains(rawB, x.SecretKey) || strings.Contains(rawB, vc.SecretKey) || strings.Contains(rawB, "20441") ||
		strings.Contains(rawC, vb.SecretKey) || strings.Contains(rawA, vb.SecretKey) {
		t.Fatal("a response carries another mapping's key or port")
	}
	if strings.Contains(rawB, "198.51.100") {
		t.Fatalf("bob's response carries the other host's settings: %s", rawB)
	}

	// Polling: unchanged settings answer 304; a moved user gets a new mapping and ETag.
	if code, _, _ := call(tokens["bob"], etagB); code != 304 {
		t.Fatalf("unchanged visitor: HTTP %d", code)
	}
	_, err = s.releaseUser(ctx, "bob")
	require(t, err)
	if code, body, _ := call(tokens["bob"], etagB); code != 409 {
		t.Fatalf("released user: HTTP %d %s", code, body)
	}
	_, err = s.assign(ctx, "bob", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20442))}, false)
	require(t, err)
	if vb2, _, etag := visitor("bob"); vb2.BindPort != 20442 || vb2.SecretKey == vb.SecretKey || etag == etagB {
		t.Fatalf("bob's visitor follows his port: %+v", vb2)
	}

	// Other users: the public-entry host answers 204, an unassigned user 409.
	if code, body, _ := call(tokens["erin"], ""); code != 204 || len(body) != 0 {
		t.Fatalf("user on a public-entry host: HTTP %d %s", code, body)
	}
	if code, body, _ := call(tokens["dave"], ""); code != 409 {
		t.Fatalf("unassigned user: HTTP %d %s", code, body)
	}

	// A revoked device and an unknown token get 401 and nothing else.
	require(t, s.revokeDevice(ctx, "carol", "carol-desk"))
	if code, body, _ := call(tokens["carol"], ""); code != 401 || strings.Contains(string(body), "frps") {
		t.Fatalf("revoked device: HTTP %d %s", code, body)
	}
	if code, _, _ := call("not-a-token", ""); code != 401 {
		t.Fatalf("unknown token: HTTP %d", code)
	}
	// A device of alice whose session was signed out also loses access.
	if code, _, _ := call(tokens["alice"], ""); code != 200 {
		t.Fatal("alice is still signed in")
	}
	require(t, s.setUserPassword(ctx, "alice", "another test password", true))
	if code, _, _ := call(tokens["alice"], ""); code != 401 {
		t.Fatalf("a password reset that revokes devices must end visitor access: HTTP %d", code)
	}

	// XTCP disabled again: back to 204, so the app stops its visitor.
	require(t, s.deleteXTCP(ctx, "nat"))
	if code, _, _ := call(tokens["bob"], ""); code != 204 {
		t.Fatalf("XTCP disabled: HTTP %d", code)
	}
}
