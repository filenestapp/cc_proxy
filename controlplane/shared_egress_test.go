package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// deviceUUIDs returns the active device UUIDs of a user, the VLESS credentials that must survive mode changes.
func deviceUUIDs(t *testing.T, s *store, user string) []string {
	t.Helper()
	uuids, err := columnOf[string](t.Context(), s.pool,
		"SELECT uuid::text FROM devices WHERE user_name = $1 AND revoked_at IS NULL ORDER BY name", user)
	require(t, err)
	return uuids
}

func binding(t *testing.T, s *store, name string) string {
	t.Helper()
	u, err := getUser(t.Context(), s.pool, name)
	require(t, err)
	if u.IP == nil {
		return "-"
	}
	return fmt.Sprintf("%s %s:%d %s", *u.Host, *u.IP, *u.Port, u.Mode)
}

func TestSwitchingModeKeepsTheBindingAndRefusesSharedExclusive(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	testHost(t, s, "hk", "203.0.113", 20000)
	require(t, s.addUser(ctx, "alice", testPassword, "exclusive", 5))
	require(t, s.addUser(ctx, "bob", testPassword, "shared", 5))
	require(t, s.addUser(ctx, "idle", testPassword, "shared", 5))
	_, err := s.assign(ctx, "alice", assignment{IP: ptr("203.0.113.3"), Port: ptr(integer(20002))}, false)
	require(t, err)
	_, err = s.addDevice(ctx, "alice", "laptop", "darwin")
	require(t, err)
	before := deviceUUIDs(t, s, "alice")

	// An exclusive holder blocks sharing until it is switched explicitly.
	_, err = s.assign(ctx, "bob", assignment{IP: ptr("203.0.113.3")}, false)
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "alice (exclusive)") {
		t.Fatalf("the conflict should name the exclusive holder: %v", err)
	}

	require(t, s.updateUser(ctx, "alice", userUpdate{Mode: ptr("shared")}))
	if got := binding(t, s, "alice"); got != "hk 203.0.113.3:20002 shared" {
		t.Fatalf("switching to shared changed the binding: %s", got)
	}
	if after := deviceUUIDs(t, s, "alice"); !slices.Equal(before, after) {
		t.Fatalf("device credentials changed: %v -> %v", before, after)
	}

	r, err := s.assign(ctx, "bob", assignment{IP: ptr("203.0.113.3")}, false)
	require(t, err)
	if r.Port != 20000 {
		t.Fatalf("bob should get the lowest free port, got %d", r.Port)
	}

	// Back to exclusive while bob shares the IP: refused, nothing changes.
	version0, err := version(ctx, s.pool)
	require(t, err)
	err = s.updateUser(ctx, "alice", userUpdate{Mode: ptr("exclusive"), MaxDevices: ptr(2)})
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "bob") {
		t.Fatalf("the refusal should name the other holder: %v", err)
	}
	version1, err := version(ctx, s.pool)
	require(t, err)
	alice, err := getUser(ctx, s.pool, "alice")
	require(t, err)
	if version1 != version0 || alice.Mode != "shared" || alice.MaxDevices != 5 ||
		binding(t, s, "alice") != "hk 203.0.113.3:20002 shared" || binding(t, s, "bob") != "hk 203.0.113.3:20000 shared" {
		t.Fatalf("a refused switch mutated state: version %d->%d, %+v", version0, version1, alice)
	}

	// Sole holder (after bob leaves) and unassigned users can switch back.
	_, err = s.releaseUser(ctx, "bob")
	require(t, err)
	require(t, s.updateUser(ctx, "alice", userUpdate{Mode: ptr("exclusive")}))
	if got := binding(t, s, "alice"); got != "hk 203.0.113.3:20002 exclusive" {
		t.Fatalf("switching the sole holder back changed the binding: %s", got)
	}
	require(t, s.updateUser(ctx, "idle", userUpdate{Mode: ptr("exclusive")}))
	wantStatus(t, s.updateUser(ctx, "idle", userUpdate{Mode: ptr("public")}), 409)
	wantStatus(t, s.updateUser(ctx, "nobody", userUpdate{Mode: ptr("shared")}), 404)
	if after := deviceUUIDs(t, s, "alice"); !slices.Equal(before, after) {
		t.Fatalf("device credentials changed: %v -> %v", before, after)
	}
}

func TestSharedHoldersGetDistinctPortsAndIndependentLifecycles(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Unix(2_000_000, 0)
	s.clock = func() time.Time { return now }
	testHost(t, s, "hk", "203.0.113", 20000) // ports 20000-20003
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		require(t, s.addUser(ctx, name, testPassword, "shared", 5))
	}
	_, err := s.assign(ctx, "a", assignment{IP: ptr("203.0.113.3")}, false)
	require(t, err)
	_, err = s.assign(ctx, "b", assignment{IP: ptr("203.0.113.3"), Port: ptr(integer(20003))}, false)
	require(t, err)
	// Conflicts: a taken port, a port outside the range.
	_, err = s.assign(ctx, "c", assignment{IP: ptr("203.0.113.3"), Port: ptr(integer(20003))}, false)
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "used by b") {
		t.Fatalf("unexpected conflict message: %v", err)
	}
	_, err = s.assign(ctx, "c", assignment{IP: ptr("203.0.113.3"), Port: ptr(integer(20004))}, false)
	wantStatus(t, err, 409)
	_, err = s.assign(ctx, "c", assignment{IP: ptr("203.0.113.3")}, false)
	require(t, err)
	// d takes a different IP on the same host: ports are per host, so it gets the last one.
	_, err = s.assign(ctx, "d", assignment{IP: ptr("203.0.113.4")}, false)
	require(t, err)
	_, err = s.assign(ctx, "e", assignment{IP: ptr("203.0.113.3")}, false)
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "no free entry port left on host hk: all 4 ports") {
		t.Fatalf("port exhaustion should be explicit: %v", err)
	}

	ips, err := listIPs(ctx, s.pool, "hk", s.now())
	require(t, err)
	shared := ips[slices.IndexFunc(ips, func(ip ipView) bool { return ip.IP == "203.0.113.3" })]
	want := []ipHolder{{"a", 20000, "shared"}, {"c", 20001, "shared"}, {"b", 20003, "shared"}}
	if shared.Status != "assigned" || !slices.Equal(shared.Holders, want) {
		t.Fatalf("unexpected holders: %+v", shared)
	}
	hosts, err := listHosts(ctx, s.pool)
	require(t, err)
	if hosts[0].PortCapacity != 4 || hosts[0].FreePorts != 0 || hosts[0].Users != 4 {
		t.Fatalf("unexpected capacity: %+v", hosts[0])
	}

	// Each holder renders its own inbound on its own port, all leaving from the shared IP.
	h, err := getHost(ctx, s.pool, "hk")
	require(t, err)
	cfg, err := serverConfig(ctx, s.pool, h)
	require(t, err)
	var server struct {
		Inbounds []struct {
			Tag  string `json:"tag"`
			Port int    `json:"listen_port"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag  string `json:"tag"`
			Bind string `json:"inet4_bind_address"`
		} `json:"outbounds"`
	}
	require(t, json.Unmarshal(cfg.Body, &server))
	if len(server.Inbounds) != 4 || len(server.Outbounds) != 3 {
		t.Fatalf("unexpected server config: %s", cfg.Body)
	}

	// Releasing, moving, and revoking one holder leave the others alone.
	tokenC, err := s.addDevice(ctx, "c", "desk", "")
	require(t, err)
	uuidsC := deviceUUIDs(t, s, "c")
	_, err = s.addDevice(ctx, "a", "desk", "")
	require(t, err)
	require(t, s.revokeDevice(ctx, "a", "desk"))
	_, err = s.releaseUser(ctx, "a")
	require(t, err)
	_, err = s.assign(ctx, "b", assignment{IP: ptr("203.0.113.12")}, true)
	require(t, err)
	if got := binding(t, s, "c"); got != "hk 203.0.113.3:20001 shared" {
		t.Fatalf("another holder's change moved c: %s", got)
	}
	if got := binding(t, s, "b"); got != "hk 203.0.113.12:20003 shared" {
		t.Fatalf("a same-host move should keep the port: %s", got)
	}
	if _, err := s.identifyDevice(ctx, tokenC); err != nil || !slices.Equal(deviceUUIDs(t, s, "c"), uuidsC) {
		t.Fatalf("c's device credentials changed: %v", err)
	}
	ip := func(addr string) ipView {
		ips, err := listIPs(ctx, s.pool, "hk", s.now())
		require(t, err)
		return ips[slices.IndexFunc(ips, func(ip ipView) bool { return ip.IP == addr })]
	}
	if got := ip("203.0.113.3"); got.Status != "assigned" || got.CooldownUntil != nil {
		t.Fatalf("a held IP must not cool down: %+v", got)
	}
	// The final holder's release starts the cooldown, which then blocks new holders.
	_, err = s.releaseUser(ctx, "c")
	require(t, err)
	if got := ip("203.0.113.3"); got.Status != "cooldown" || *got.CooldownUntil != s.now()+defaultCooldown {
		t.Fatalf("the last release should start cooldown: %+v", got)
	}
	_, err = s.assign(ctx, "e", assignment{IP: ptr("203.0.113.3")}, false)
	wantStatus(t, err, 409)

	// A ban releases every holder of the IP, and a banned IP accepts no new holder.
	_, err = s.assign(ctx, "e", assignment{IP: ptr("203.0.113.12")}, false)
	require(t, err)
	released, err := s.banIP(ctx, "203.0.113.12", "test")
	require(t, err)
	if !slices.Equal(released, []string{"b", "e"}) && !slices.Equal(released, []string{"e", "b"}) {
		t.Fatalf("a ban should release all holders: %v", released)
	}
	_, err = s.assign(ctx, "e", assignment{IP: ptr("203.0.113.12")}, false)
	wantStatus(t, err, 409)
	if got := binding(t, s, "d"); got != "hk 203.0.113.4:20002 shared" {
		t.Fatalf("a ban on another IP moved d: %s", got)
	}
}

func TestParallelSharedAssignmentsNeverDuplicateAPort(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	_, err := s.addHost(ctx, "hk", hostOptions{PublicHost: ptr("203.0.113.2"), PortMin: ptr(integer(21000)),
		PortMax: ptr(integer(21005))})
	require(t, err)
	_, err = s.addIPs(ctx, "hk", []string{"203.0.113.3"})
	require(t, err)
	names := make([]string, 8)
	for i := range names {
		names[i] = fmt.Sprintf("u%d", i)
		require(t, s.addUser(ctx, names[i], testPassword, "shared", 5))
	}
	var wg sync.WaitGroup
	errs := make([]error, len(names))
	for i, name := range names {
		wg.Go(func() { _, errs[i] = s.assign(ctx, name, assignment{IP: ptr("203.0.113.3")}, false) })
	}
	wg.Wait()
	ports, err := columnOf[int](ctx, s.pool, "SELECT port FROM users WHERE host = 'hk' ORDER BY port")
	require(t, err)
	if !slices.Equal(ports, []int{21000, 21001, 21002, 21003, 21004, 21005}) {
		t.Fatalf("six of eight parallel holders should get the six distinct ports: %v", ports)
	}
	failed := 0
	for _, err := range errs {
		if err != nil {
			wantStatus(t, err, 409)
			failed++
		}
	}
	if failed != 2 {
		t.Fatalf("expected two port-exhaustion refusals, got %d", failed)
	}

	// Two administrators asking for the same explicit port: exactly one wins.
	require(t, s.updateHost(ctx, "hk", hostOptions{PortMax: ptr(integer(21007))}))
	var winners sync.Map
	idle, err := columnOf[string](ctx, s.pool, "SELECT name FROM users WHERE egress_ip IS NULL ORDER BY name")
	require(t, err)
	if len(idle) != 2 {
		t.Fatalf("expected the two refused users to stay unassigned: %v", idle)
	}
	for _, name := range idle {
		wg.Go(func() {
			if _, err := s.assign(ctx, name, assignment{IP: ptr("203.0.113.3"), Port: ptr(integer(21007))}, false); err == nil {
				winners.Store(name, true)
			} else if statusOf(err) != 409 {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	count := 0
	winners.Range(func(any, any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("expected one winner for port 21007, got %d", count)
	}
}

func TestXTCPMappingsPerSharedUser(t *testing.T) {
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
	x, _, err := getXTCP(ctx, s.pool, "nat")
	require(t, err)

	// The existing single-port host: the rendered configuration is byte-identical to the previous release.
	mappings, err := xtcpMappings(ctx, s.pool, x)
	require(t, err)
	single := renderFrpcTOML(x, mappings, "/etc/ccproxy-exit/frp-ca.pem", "")
	if single != singlePortFrpc(x, "/etc/ccproxy-exit/frp-ca.pem") {
		t.Fatalf("the single-port frpc configuration changed:\n%s", single)
	}

	handler := newAPI(s, testAdminToken, "", []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	call := func(path, bearer string) (int, []byte) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}
	view := func() map[string]any {
		t.Helper()
		code, body := call("/admin/hosts/nat/xtcp", testAdminToken)
		if code != 200 {
			t.Fatalf("xtcp view: HTTP %d %s", code, body)
		}
		var v map[string]any
		require(t, json.Unmarshal(body, &v))
		return v
	}
	if v := view(); v["frpc_state"] != "unknown" {
		t.Fatalf("a host that never fetched since tracking began is unknown: %v", v["frpc_state"])
	}
	code, _ := call("/install/xtcp/frpc.toml?ca_file=/etc/ccproxy-exit/frp-ca.pem", token)
	if code != 200 || view()["frpc_state"] != "current" {
		t.Fatalf("after the install fetch the host is current: HTTP %d", code)
	}

	// Bob and carol share alice's IP. Each gets a proxy on their own port with a scoped secret key.
	_, err = s.assign(ctx, "bob", assignment{IP: ptr("192.0.2.3")}, false)
	require(t, err)
	_, err = s.assign(ctx, "carol", assignment{IP: ptr("192.0.2.3")}, false)
	require(t, err)
	if v := view(); v["frpc_state"] != "outdated" {
		t.Fatalf("new holders make the installed frpc outdated: %v", v["frpc_state"])
	}
	code, body := call("/install/xtcp/frpc.toml?ca_file=/etc/ccproxy-exit/frp-ca.pem", token)
	conf := string(body)
	if code != 200 || !strings.HasPrefix(conf, single) {
		t.Fatalf("the upgraded configuration must keep the first mapping unchanged:\n%s", conf)
	}
	for _, want := range []string{`name = "ccproxy-nat-direct-20440"`, "localPort = 20440", `name = "ccproxy-nat-direct-20441"`,
		"localPort = 20441"} {
		if !strings.Contains(conf, want+"\n") {
			t.Fatalf("frpc.toml lacks %q:\n%s", want, conf)
		}
	}
	if strings.Count(conf, "[[proxies]]") != 3 || strings.Count(conf, x.SecretKey) != 1 {
		t.Fatalf("expected three proxies and the host key only on the first:\n%s", conf)
	}
	v := view()
	if v["frpc_state"] != "current" {
		t.Fatalf("after the rerun the host is current: %v", v["frpc_state"])
	}
	if raw, _ := json.Marshal(v); strings.Contains(string(raw), x.SecretKey) || strings.Contains(string(raw), x.AuthToken) ||
		!strings.Contains(string(raw), `"user":"bob"`) {
		t.Fatalf("the admin view lists mappings without secrets: %s", raw)
	}

	visitor := func(user string) map[string]any {
		t.Helper()
		code, body := call("/admin/users/"+user+"/xtcp-visitor", testAdminToken)
		if code != 200 {
			t.Fatalf("visitor for %s: HTTP %d %s", user, code, body)
		}
		var out map[string]any
		require(t, json.Unmarshal(body, &out))
		return out
	}
	va, vb, vc := visitor("alice"), visitor("bob"), visitor("carol")
	if va["secret_key"] != x.SecretKey || va["proxy_name"] != "ccproxy-nat-direct" || va["bind_port"] != float64(20443) {
		t.Fatalf("alice keeps the original mapping and key: %v", va)
	}
	if vb["proxy_name"] != "ccproxy-nat-direct-20440" || vb["bind_port"] != float64(20440) ||
		vb["secret_key"] == x.SecretKey || vb["secret_key"] == vc["secret_key"] {
		t.Fatalf("bob gets his own proxy and scoped key: %v", vb)
	}
	toml := vb["frpc_toml"].(string)
	for _, want := range []string{`serverName = "ccproxy-nat-direct-20440"`, `secretKey = "` + vb["secret_key"].(string) + `"`,
		"bindPort = 20440", `auth.token = "{{ .Envs.FRP_AUTH_TOKEN }}"`, "[[visitors]]"} {
		if !strings.Contains(toml, want+"\n") {
			t.Fatalf("visitor lacks %q:\n%s", want, toml)
		}
	}
	settings := ""
	for _, line := range strings.Split(toml, "\n") {
		if !strings.HasPrefix(line, "#") {
			settings += line + "\n"
		}
	}
	if strings.Contains(toml, x.AuthToken) || strings.Contains(toml, x.SecretKey) || strings.Contains(strings.ToLower(settings), "fallback") {
		t.Fatalf("the visitor must hold neither host credential nor a fallback:\n%s", toml)
	}

	// Moving carol to another port rotates her key; a new holder of an old port does not inherit a key.
	oldCarol := vc["secret_key"]
	_, err = s.releaseUser(ctx, "carol")
	require(t, err)
	_, err = s.assign(ctx, "carol", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20442))}, false)
	require(t, err)
	if vc = visitor("carol"); vc["secret_key"] == oldCarol || vc["proxy_name"] != "ccproxy-nat-direct-20442" {
		t.Fatalf("carol's mapping should follow her port: %v", vc)
	}
	if vb2 := visitor("bob"); vb2["secret_key"] != vb["secret_key"] {
		t.Fatal("bob's key must survive carol's move")
	}
	if userSecretKey(x.MappingSecret, "ccproxy-nat-direct-20441", "dave") == userSecretKey(x.MappingSecret, "ccproxy-nat-direct-20441", "carol") {
		t.Fatal("a later holder of the same port must get a different key")
	}
	if code, _ := call("/admin/users/nobody/xtcp-visitor", testAdminToken); code != 404 {
		t.Fatalf("unknown user: HTTP %d", code)
	}
	require(t, s.addUser(ctx, "dave", testPassword, "shared", 5))
	if code, _ := call("/admin/users/dave/xtcp-visitor", testAdminToken); code != 409 {
		t.Fatalf("unassigned user: HTTP %d", code)
	}
	if code, _ := call("/admin/users/bob/xtcp-visitor?bind_addr=x", testAdminToken); code != 400 {
		t.Fatalf("bad bind address: HTTP %d", code)
	}

	// Proxy names that another host's derived names could collide with are refused.
	testHost(t, s, "other", "198.51.100", 30000)
	_, err = s.putXTCP(ctx, "other", xtcpRequest{ServerAddr: ptr("198.51.100.10"), CAPEM: &ca,
		AuthToken: ptr("frps-token-0123456789abcdef"), ProxyName: ptr("ccproxy-nat-direct-30000"), LocalPort: ptr(integer(30000))})
	wantStatus(t, err, 409)
	_, err = s.putXTCP(ctx, "other", xtcpRequest{ServerAddr: ptr("198.51.100.10"), CAPEM: &ca,
		AuthToken: ptr("frps-token-0123456789abcdef"), ProxyName: ptr("ccproxy-nat"), LocalPort: ptr(integer(30000))})
	require(t, err)
}

func TestProxyNameOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"a", "a", true}, {"a", "a-20000", true}, {"a-20000", "a", true}, {"a", "a-b", false},
		{"a", "a-", false}, {"a", "a-99999", false}, {"a-2", "a-2-20001", true}, {"ab", "a-1", false},
	} {
		if got := proxyNamesOverlap(c.a, c.b); got != c.want {
			t.Errorf("proxyNamesOverlap(%q, %q) = %t", c.a, c.b, got)
		}
	}
}

// singlePortFrpc renders the one-mapping form for comparison with the general renderer.
func singlePortFrpc(x xtcpSettings, caFile string) string {
	return fmt.Sprintf(`# frpc for aifree exit host %[1]s, written by the installer from the control plane.
# XTCP only: the exit host and the visitor connect directly; frps on %[2]s:%[3]d only brokers the
# rendezvous. There is no relay fallback: when hole punching fails, the visitor's connection is closed.
serverAddr = "%[2]s"
serverPort = %[3]d
loginFailExit = false

auth.method = "token"
auth.token = "%[4]s"

transport.tls.enable = true
transport.tls.trustedCaFile = '%[5]s'
transport.tls.serverName = "%[6]s"

log.to = %[7]s
log.level = "info"
%[8]s
[[proxies]]
name = "%[9]s"
type = "xtcp"
secretKey = "%[10]s"
localIP = "127.0.0.1"
localPort = %[11]d
`, x.Host, x.ServerAddr, x.ServerPort, x.AuthToken, caFile, x.TLSServerName, `"console"`, "", x.ProxyName,
		x.SecretKey, x.LocalPort)
}

// An XTCP host configured by the previous release (single-port, no mapping secret) upgrades in place: the primary
// visitor key keeps working, other users get keys derived from an independent server-held secret, those keys stay
// stable across restarts and settings changes, and no response carries the derivation secret.
func TestXTCPUpgradeSeparatesTheMappingSecretFromThePrimaryKey(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	token := testHost(t, s, "nat", "192.0.2", 20440) // ports 20440-20443
	for _, name := range []string{"carol", "dave", "erin"} {
		require(t, s.addUser(ctx, name, testPassword, "shared", 5))
	}
	_, err := s.assign(ctx, "carol", assignment{IP: ptr("192.0.2.3"), Port: ptr(integer(20443))}, false)
	require(t, err)

	// The table exactly as the previous release left it, with one configured host.
	const primaryKey = "legacy-visitor-key-0123456789abcdef"
	ca := testCertPEM(t, true)
	_, err = s.pool.Exec(ctx, `ALTER TABLE host_xtcp DROP COLUMN mapping_secret, DROP COLUMN delivered_sha256,
		DROP COLUMN delivered_at`)
	require(t, err)
	_, err = s.pool.Exec(ctx, `INSERT INTO host_xtcp(host, server_addr, server_port, tls_server_name, ca_pem, auth_token,
		proxy_name, secret_key, local_port, updated_at) VALUES ('nat', '198.51.100.10', 7003, '198.51.100.10', $1,
		'frps-token-0123456789abcdef', 'ccproxy-nat-direct', $2, 20443, 1)`, ca, primaryKey)
	require(t, err)

	// Restart: the schema upgrade gives the host its own mapping secret and leaves the primary key alone.
	require(t, s.initializeSchema(ctx))
	x, _, err := getXTCP(ctx, s.pool, "nat")
	require(t, err)
	if x.SecretKey != primaryKey || !xtcpSecretPattern.MatchString(x.MappingSecret) || x.MappingSecret == x.SecretKey {
		t.Fatalf("upgrade must keep the primary key and add an independent mapping secret: %+v", x)
	}
	handler := newAPI(s, testAdminToken, "", []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	const frpcPath = "/install/xtcp/frpc.toml?ca_file=/etc/ccproxy-exit/frp-ca.pem"
	code, single := get(t, handler, frpcPath, token)
	if code != 200 || string(single) != singlePortFrpc(x, "/etc/ccproxy-exit/frp-ca.pem") {
		t.Fatalf("the upgraded single-port host must render the one-mapping configuration: HTTP %d\n%s", code, single)
	}

	_, err = s.assign(ctx, "dave", assignment{IP: ptr("192.0.2.3")}, false)
	require(t, err)
	_, err = s.assign(ctx, "erin", assignment{IP: ptr("192.0.2.3")}, false)
	require(t, err)
	visitorKeys := func() map[string]string {
		t.Helper()
		keys := map[string]string{}
		for _, user := range []string{"carol", "dave", "erin"} {
			code, body := get(t, handler, "/admin/users/"+user+"/xtcp-visitor", testAdminToken)
			if code != 200 {
				t.Fatalf("visitor for %s: HTTP %d %s", user, code, body)
			}
			var v struct {
				SecretKey string `json:"secret_key"`
				TOML      string `json:"frpc_toml"`
			}
			require(t, json.Unmarshal(body, &v))
			if strings.Contains(string(body), x.MappingSecret) {
				t.Fatalf("the visitor response for %s carries the mapping secret", user)
			}
			for other, key := range keys {
				if strings.Contains(v.TOML, key) {
					t.Fatalf("%s's visitor carries %s's key", user, other)
				}
			}
			keys[user] = v.SecretKey
		}
		return keys
	}
	keys := visitorKeys()
	if keys["carol"] != primaryKey {
		t.Fatalf("the active legacy visitor key must stay the primary credential: %q", keys["carol"])
	}
	for _, user := range []string{"dave", "erin"} {
		if !xtcpSecretPattern.MatchString(keys[user]) || keys[user] == primaryKey {
			t.Fatalf("%s needs its own visitor key: %q", user, keys[user])
		}
		port := map[string]int{"dave": 20440, "erin": 20441}[user]
		if keys[user] == userSecretKey(primaryKey, userProxyName("ccproxy-nat-direct", port), user) {
			t.Fatalf("%s's key is derivable from the primary visitor's key", user)
		}
	}
	if keys["dave"] == keys["erin"] {
		t.Fatal("dave and erin must get distinct keys")
	}

	// The exit host gets every mapping's key but never the derivation secret; the admin view gets neither.
	code, conf := get(t, handler, frpcPath, token)
	if code != 200 || !strings.HasPrefix(string(conf), string(single)) || strings.Contains(string(conf), x.MappingSecret) ||
		!strings.Contains(string(conf), keys["dave"]) || !strings.Contains(string(conf), keys["erin"]) {
		t.Fatalf("unexpected exit-host configuration: HTTP %d\n%s", code, conf)
	}
	code, view := get(t, handler, "/admin/hosts/nat/xtcp", testAdminToken)
	if code != 200 || strings.Contains(string(view), x.MappingSecret) || strings.Contains(string(view), primaryKey) ||
		strings.Contains(string(view), keys["dave"]) {
		t.Fatalf("the admin XTCP view must hold no key material: %s", view)
	}
	if _, ca := get(t, handler, "/install/xtcp/ca.pem", token); strings.Contains(string(ca), x.MappingSecret) {
		t.Fatal("the CA response carries the mapping secret")
	}

	// Stable across a restart with a fresh store, a settings change, and a primary key rotation.
	again := &store{pool: s.pool, clock: time.Now}
	require(t, again.initializeSchema(ctx))
	if got := visitorKeys(); !maps.Equal(got, keys) {
		t.Fatalf("keys changed across a restart: %v -> %v", keys, got)
	}
	req := httptest.NewRequest(http.MethodPut, "/admin/hosts/nat/xtcp", strings.NewReader(`{"server_port":7004}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), x.MappingSecret) {
		t.Fatalf("settings change: HTTP %d %s", rec.Code, rec.Body)
	}
	_, err = s.putXTCP(ctx, "nat", xtcpRequest{SecretKey: ptr("rotated-primary-key-0123456789abcdef")})
	require(t, err)
	got := visitorKeys()
	if got["carol"] != "rotated-primary-key-0123456789abcdef" || got["dave"] != keys["dave"] || got["erin"] != keys["erin"] {
		t.Fatalf("rotating the primary key must not change the other mappings: %v -> %v", keys, got)
	}
	after, _, err := getXTCP(ctx, s.pool, "nat")
	require(t, err)
	if after.MappingSecret != x.MappingSecret {
		t.Fatal("the mapping secret must persist across settings changes")
	}

	// A row without a mapping secret (written by a rolled-back binary) fails closed instead of reusing the primary
	// key, and the next start repairs it.
	_, err = s.pool.Exec(ctx, "UPDATE host_xtcp SET mapping_secret = '' WHERE host = 'nat'")
	require(t, err)
	if code, _ := get(t, handler, frpcPath, token); code != 409 {
		t.Fatalf("a missing mapping secret must fail closed: HTTP %d", code)
	}
	if code, _ := get(t, handler, "/admin/users/carol/xtcp-visitor", testAdminToken); code != 409 {
		t.Fatalf("a missing mapping secret must fail closed for visitors too: HTTP %d", code)
	}
	require(t, s.initializeSchema(ctx))
	if code, _ := get(t, handler, frpcPath, token); code != 200 {
		t.Fatalf("the next start restores the mapping secret: HTTP %d", code)
	}
}
