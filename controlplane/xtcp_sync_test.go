package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// syncHarness drives the agent-facing XTCP sync routes through the real router.
type syncHarness struct {
	t       *testing.T
	s       *store
	handler http.Handler
	token   string // the XTCP host's agent token
}

const syncPath = "/agent/xtcp?ca_file=/etc/ccproxy-exit/frp-ca.pem"

func newSyncHarness(t *testing.T) *syncHarness {
	ctx := t.Context()
	s := testStore(t)
	token := testHost(t, s, "nat", "192.0.2", 20440) // ports 20440-20443
	for _, name := range []string{"alice", "bob", "carol"} {
		require(t, s.addUser(ctx, name, testPassword, "shared", 5))
	}
	_, err := s.assign(ctx, "alice", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20443))}, false)
	require(t, err)
	ca := testCertPEM(t, true)
	_, err = s.putXTCP(ctx, "nat", xtcpRequest{ServerAddr: ptr("198.51.100.10"), CAPEM: &ca,
		AuthToken: ptr("frps-token-0123456789abcdef"), ProxyName: ptr("ccproxy-nat-direct"),
		SecretKey: ptr("xtcp-secret-0123456789abcdef"), LocalPort: ptr(integer(20443))})
	require(t, err)
	return &syncHarness{t: t, s: s, token: token,
		handler: newAPI(s, testAdminToken, "", []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})}
}

func (h *syncHarness) do(method, path, bearer, body string, header ...string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func (h *syncHarness) desired(bearer string) xtcpDesired {
	h.t.Helper()
	rec := h.do("GET", syncPath, bearer, "")
	if rec.Code != 200 {
		h.t.Fatalf("GET /agent/xtcp: HTTP %d %s", rec.Code, rec.Body)
	}
	var d xtcpDesired
	require(h.t, json.Unmarshal(rec.Body.Bytes(), &d))
	if rec.Header().Get("ETag") != `"`+xtcpETag(d.Generation, d.SHA256)+`"` {
		h.t.Fatalf("ETag %q does not name generation %d", rec.Header().Get("ETag"), d.Generation)
	}
	return d
}

// heartbeat posts a report for the host; xtcp is the raw "xtcp" member or "" for an agent without XTCP sync.
// singboxCurrent makes the heartbeat confirm the current sing-box server configuration.
func (h *syncHarness) heartbeat(bearer, xtcp string, singboxCurrent bool) {
	h.t.Helper()
	etag := "stale"
	if singboxCurrent {
		host, err := getHost(h.t.Context(), h.s.pool, "nat")
		require(h.t, err)
		cfg, err := serverConfig(h.t.Context(), h.s.pool, host)
		require(h.t, err)
		etag = cfg.ETag
	}
	body := fmt.Sprintf(`{"probes":[],"config_etag":%q,"apply_state":"confirmed"`, etag)
	if xtcp != "" {
		body += `,"xtcp":` + xtcp
	}
	rec := h.do("POST", "/agent/report", bearer, body+"}")
	if rec.Code != 200 {
		h.t.Fatalf("heartbeat: HTTP %d %s", rec.Code, rec.Body)
	}
}

func applied(d xtcpDesired) string {
	proxies, _ := json.Marshal(d.Proxies)
	return fmt.Sprintf(`{"generation":%d,"state":"applied","applied_generation":%d,"applied_sha256":%q,"applied_proxies":%s}`,
		d.Generation, d.Generation, d.SHA256, proxies)
}

type syncView struct {
	Sync struct {
		State             string `json:"state"`
		DesiredGeneration int64  `json:"desired_generation"`
		Message           string `json:"message"`
		Agent             struct {
			AppliedGeneration int64  `json:"applied_generation"`
			Error             string `json:"error"`
		} `json:"agent"`
	} `json:"sync"`
	Mappings []struct {
		User   string `json:"user"`
		Port   int    `json:"port"`
		Status string `json:"status"`
	} `json:"mappings"`
	FrpcState string `json:"frpc_state"`
}

func (h *syncHarness) view() (syncView, string) {
	h.t.Helper()
	rec := h.do("GET", "/admin/hosts/nat/xtcp", testAdminToken, "")
	if rec.Code != 200 {
		h.t.Fatalf("xtcp view: HTTP %d %s", rec.Code, rec.Body)
	}
	var v syncView
	require(h.t, json.Unmarshal(rec.Body.Bytes(), &v))
	return v, rec.Body.String()
}

func statuses(v syncView) string {
	var out []string
	for _, m := range v.Mappings {
		out = append(out, fmt.Sprintf("%d=%s", m.Port, m.Status))
	}
	return strings.Join(out, " ")
}

func TestXTCPGenerationsFollowCommittedMappingChanges(t *testing.T) {
	ctx := t.Context()
	h := newSyncHarness(t)
	first := h.desired(h.token)
	if first.Generation <= 0 || len(first.Proxies) != 1 || first.Proxies[0].Name != "ccproxy-nat-direct" {
		t.Fatalf("the first fetch publishes the primary mapping: %+v", first)
	}
	if !strings.Contains(first.FrpcTOML, `trustedCaFile = '/etc/ccproxy-exit/frp-ca.pem'`) || first.CAPEM == "" {
		t.Fatal("the desired configuration carries the rendered frpc.toml and the CA")
	}
	x, _, err := getXTCP(ctx, h.s.pool, "nat")
	require(t, err)
	mappings, err := xtcpMappings(ctx, h.s.pool, x)
	require(t, err)
	if first.FrpcTOML != renderFrpcTOML(x, mappings, "/etc/ccproxy-exit/frp-ca.pem", "") {
		t.Fatal("the agent gets exactly what the installer gets")
	}

	// Unchanged: the same generation, and a conditional fetch is answered with 304.
	if again := h.desired(h.token); again.Generation != first.Generation || again.SHA256 != first.SHA256 {
		t.Fatalf("an unchanged fetch moved the generation: %d -> %d", first.Generation, again.Generation)
	}
	if rec := h.do("GET", syncPath, h.token, "", "If-None-Match", `"`+xtcpETag(first.Generation, first.SHA256)+`"`); rec.Code != 304 {
		t.Fatalf("conditional fetch: HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/agent/xtcp?ca_file=relative.pem", h.token, ""); rec.Code != 400 {
		t.Fatalf("a relative CA path is refused: HTTP %d", rec.Code)
	}

	// Assigning a second shared user publishes a new generation; the primary proxy is unchanged.
	_, err = h.s.assign(ctx, "bob", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20444 - 4))}, false)
	require(t, err)
	second := h.desired(h.token)
	if second.Generation <= first.Generation || len(second.Proxies) != 2 || second.Proxies[0] != first.Proxies[0] ||
		second.Proxies[1].Name != "ccproxy-nat-direct-20440" {
		t.Fatalf("assignment: %+v after %+v", second, first)
	}
	// Reassigning the same port to another user changes that proxy's key, so its digest, but not the primary.
	_, err = h.s.releaseUser(ctx, "bob")
	require(t, err)
	_, err = h.s.assign(ctx, "carol", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20440))}, false)
	require(t, err)
	third := h.desired(h.token)
	if third.Generation <= second.Generation || third.Proxies[1].Name != second.Proxies[1].Name ||
		third.Proxies[1].Digest == second.Proxies[1].Digest || third.Proxies[0] != first.Proxies[0] {
		t.Fatalf("reassignment: %+v after %+v", third, second)
	}
	// Release: back to the primary mapping only, as a newer generation with the original fingerprint.
	_, err = h.s.releaseUser(ctx, "carol")
	require(t, err)
	fourth := h.desired(h.token)
	if fourth.Generation <= third.Generation || fourth.SHA256 != first.SHA256 || len(fourth.Proxies) != 1 {
		t.Fatalf("release: %+v", fourth)
	}
	// Disabling and enabling XTCP never reuses a generation number.
	require(t, h.s.deleteXTCP(ctx, "nat"))
	if rec := h.do("GET", syncPath, h.token, ""); rec.Code != 204 {
		t.Fatalf("a public-entry host gets 204: HTTP %d", rec.Code)
	}
	ca := testCertPEM(t, true)
	_, err = h.s.putXTCP(ctx, "nat", xtcpRequest{ServerAddr: ptr("198.51.100.10"), CAPEM: &ca,
		AuthToken: ptr("frps-token-0123456789abcdef"), SecretKey: ptr("xtcp-secret-0123456789abcdef"), LocalPort: ptr(integer(20443))})
	require(t, err)
	if fifth := h.desired(h.token); fifth.Generation <= fourth.Generation {
		t.Fatalf("re-enabled XTCP reused generation %d (last %d)", fifth.Generation, fourth.Generation)
	}
}

func TestXTCPReadinessNeedsConfirmedRegistrationAndListener(t *testing.T) {
	ctx := t.Context()
	h := newSyncHarness(t)
	first := h.desired(h.token)

	// An agent from before this change never reports "xtcp": it needs the one-time upgrade.
	h.heartbeat(h.token, "", true)
	v, _ := h.view()
	if v.Sync.State != xtcpSyncUpgradeNeeded || statuses(v) != "20443=upgrade_needed" || !strings.Contains(v.Sync.Message, "nat") {
		t.Fatalf("legacy agent: %s %s %q", v.Sync.State, statuses(v), v.Sync.Message)
	}

	h.heartbeat(h.token, applied(first), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncReady || statuses(v) != "20443=ready" {
		t.Fatalf("confirmed primary: %s %s", v.Sync.State, statuses(v))
	}

	// A second shared user: pending until both the frpc proxy and the sing-box listener are confirmed.
	_, err := h.s.assign(ctx, "bob", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20441))}, false)
	require(t, err)
	if v, _ := h.view(); v.Sync.State != xtcpSyncPending || statuses(v) != "20443=pending 20441=pending" {
		// sing-box has not confirmed the configuration with bob's listener yet, so nothing on this host is ready.
		t.Fatalf("before the agent fetched: %s %s", v.Sync.State, statuses(v))
	}
	h.heartbeat(h.token, applied(first), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncPending || statuses(v) != "20443=ready 20441=pending" {
		t.Fatalf("sing-box current, frpc still on the old generation: %s %s", v.Sync.State, statuses(v))
	}
	second := h.desired(h.token)
	// Fetched but not confirmed (the agent wrote the file or reloaded): still pending.
	h.heartbeat(h.token, fmt.Sprintf(`{"generation":%d,"state":"pending","applied_generation":%d,"applied_sha256":%q,"applied_proxies":[]}`,
		second.Generation, first.Generation, first.SHA256), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncPending || statuses(v) != "20443=ready 20441=pending" {
		t.Fatalf("fetched, not confirmed: %s %s", v.Sync.State, statuses(v))
	}
	// frpc confirmed, but sing-box has not confirmed the listener: pending.
	h.heartbeat(h.token, applied(second), false)
	if v, _ := h.view(); v.Sync.State != xtcpSyncPending || statuses(v) != "20443=pending 20441=pending" {
		t.Fatalf("frpc confirmed, sing-box not: %s %s", v.Sync.State, statuses(v))
	}
	h.heartbeat(h.token, applied(second), true)
	v, _ = h.view()
	if v.Sync.State != xtcpSyncReady || statuses(v) != "20443=ready 20441=ready" || v.Sync.Agent.AppliedGeneration != second.Generation {
		t.Fatalf("both confirmed: %s %s", v.Sync.State, statuses(v))
	}

	// A late acknowledgement of the older generation never moves the host backwards.
	h.heartbeat(h.token, applied(first), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncReady || v.Sync.Agent.AppliedGeneration != second.Generation {
		t.Fatalf("stale acknowledgement: %s applied %d", v.Sync.State, v.Sync.Agent.AppliedGeneration)
	}

	// Release bob: a newer generation is pending, and an acknowledgement of the previous one cannot mark it ready.
	_, err = h.s.releaseUser(ctx, "bob")
	require(t, err)
	h.heartbeat(h.token, applied(second), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncPending {
		t.Fatalf("an older acknowledgement marked the newer generation ready: %s", v.Sync.State)
	}
	// Nothing beyond what was published is accepted.
	third := h.desired(h.token)
	forged := third
	forged.Generation += 1000
	h.heartbeat(h.token, applied(forged), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncPending || v.Sync.Agent.AppliedGeneration != second.Generation {
		t.Fatalf("an unpublished generation was accepted: %s applied %d", v.Sync.State, v.Sync.Agent.AppliedGeneration)
	}
	h.heartbeat(h.token, applied(third), true)
	if v, _ := h.view(); v.Sync.State != xtcpSyncReady || statuses(v) != "20443=ready" {
		t.Fatalf("after release: %s %s", v.Sync.State, statuses(v))
	}
}

func TestXTCPFailureIsVisibleWithoutCredentials(t *testing.T) {
	ctx := t.Context()
	h := newSyncHarness(t)
	first := h.desired(h.token)
	h.heartbeat(h.token, applied(first), true)
	_, err := h.s.assign(ctx, "bob", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20441))}, false)
	require(t, err)
	second := h.desired(h.token)
	report := func(msg string, listenerConfirmed bool) {
		h.heartbeat(h.token, fmt.Sprintf(`{"generation":%d,"state":"failed","error":%q,"applied_generation":%d,"applied_sha256":%q,"applied_proxies":%s}`,
			second.Generation, msg, first.Generation, first.SHA256, mustJSON(first.Proxies)), listenerConfirmed)
	}
	const failedProxy = "frpc did not confirm ccproxy-nat-direct-20441 within 20s: start error (proxy already exists)"
	report(failedProxy, false)
	if v, _ := h.view(); v.Sync.State != xtcpSyncFailed || statuses(v) != "20443=pending 20441=failed" {
		t.Fatalf("failed frpc update with unconfirmed listeners: %s %s", v.Sync.State, statuses(v))
	}
	report(failedProxy, true)
	v, raw := h.view()
	if v.Sync.State != xtcpSyncFailed || statuses(v) != "20443=ready 20441=failed" {
		t.Fatalf("failed activation: %s %s", v.Sync.State, statuses(v))
	}
	if !strings.Contains(v.Sync.Message, "Exit host nat") || !strings.Contains(v.Sync.Message, "ccproxy-nat-direct-20441") {
		t.Fatalf("the message names the exit and the proxy: %q", v.Sync.Message)
	}
	x, _, err := getXTCP(ctx, h.s.pool, "nat")
	require(t, err)
	for _, secret := range []string{x.AuthToken, x.SecretKey, x.MappingSecret, h.token} {
		if strings.Contains(raw, secret) {
			t.Fatal("the admin view leaks a credential")
		}
	}
	report("frpc verify: auth.token = \"frps-token-0123456789abcdef\" is invalid", true)
	if v, raw := h.view(); strings.Contains(raw, "frps-token") || !strings.Contains(v.Sync.Agent.Error, "withheld") {
		t.Fatalf("a credential in the agent's message must be withheld: %q", v.Sync.Agent.Error)
	}
	rec := h.do("POST", "/agent/report", h.token, `{"probes":[],"xtcp":{"generation":1,"state":"bogus"}}`)
	if rec.Code != 400 {
		t.Fatalf("an unknown state is refused: HTTP %d", rec.Code)
	}
}

func TestXTCPSyncIsHostScoped(t *testing.T) {
	ctx := t.Context()
	h := newSyncHarness(t)
	other := testHost(t, h.s, "pub", "198.51.100", 20000)
	if rec := h.do("GET", syncPath, other, ""); rec.Code != 204 {
		t.Fatalf("another (public-entry) host gets its own answer, not nat's: HTTP %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("GET", syncPath, "not-a-token", ""); rec.Code != 401 {
		t.Fatalf("an unknown token: HTTP %d", rec.Code)
	}
	ca := testCertPEM(t, true)
	_, err := h.s.putXTCP(ctx, "pub", xtcpRequest{ServerAddr: ptr("198.51.100.10"), CAPEM: &ca,
		AuthToken: ptr("frps-token-0123456789abcdef"), ProxyName: ptr("ccproxy-pub-direct"),
		SecretKey: ptr("pub-secret-0123456789abcdef"), LocalPort: ptr(integer(20001))})
	require(t, err)
	nat, pub := h.desired(h.token), h.desired(other)
	if strings.Contains(pub.FrpcTOML, "ccproxy-nat-direct") || strings.Contains(nat.FrpcTOML, "ccproxy-pub-direct") {
		t.Fatal("a host received another host's proxies")
	}
	// pub acknowledging nat's generation and fingerprint changes nothing for nat.
	h.heartbeat(h.token, "", true)
	rec := h.do("POST", "/agent/report", other, `{"probes":[],"xtcp":`+applied(nat)+`}`)
	if rec.Code != 200 {
		t.Fatalf("pub heartbeat: HTTP %d", rec.Code)
	}
	if v, _ := h.view(); v.Sync.State != xtcpSyncUpgradeNeeded {
		t.Fatalf("another host's acknowledgement changed nat: %s", v.Sync.State)
	}
}

func TestXTCPSyncSchemaIsAdditive(t *testing.T) {
	h := newSyncHarness(t)
	// Initializing again (a restart, or a newer binary over an older schema) keeps the published generation.
	first := h.desired(h.token)
	require(t, h.s.initializeSchema(t.Context()))
	if again := h.desired(h.token); again.Generation != first.Generation {
		t.Fatalf("restart moved the generation %d -> %d", first.Generation, again.Generation)
	}
	cols, err := columnOf[string](t.Context(), h.s.pool, `SELECT column_name::text FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'host_xtcp' ORDER BY column_name`)
	require(t, err)
	for _, want := range []string{"desired_generation", "desired_sha256", "mapping_secret", "delivered_sha256"} {
		if !slices.Contains(cols, want) {
			t.Fatalf("host_xtcp lacks %s: %v", want, cols)
		}
	}
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}
