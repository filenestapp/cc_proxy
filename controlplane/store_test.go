package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testPassword = "correct horse battery"

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	if err == nil || statusOf(err) != status {
		t.Fatalf("expected HTTP %d, got %v", status, err)
	}
}

func ptr[T any](value T) *T { return &value }

func testStore(t *testing.T) *store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration tests")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, dsn)
	require(t, err)
	t.Cleanup(admin.Close)
	schema := "cp_go_test_" + strings.ToLower(randomToken(8))
	identifier := pgx.Identifier{schema}.Sanitize()
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+identifier)
	require(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = identifier
	cfg.ConnConfig.RuntimeParams["application_name"] = schema
	cfg.MaxConns = max(cfg.MaxConns, 4)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require(t, err)
	t.Cleanup(pool.Close)
	s := &store{pool: pool, clock: time.Now}
	require(t, s.initializeSchema(ctx))
	return s
}

func testHost(t *testing.T, s *store, name, prefix string, port int) string {
	t.Helper()
	token, err := s.addHost(t.Context(), name, hostOptions{
		PublicHost: ptr(prefix + ".2"), ServerName: ptr("www.example.com"),
		PortMin: ptr(integer(port)), PortMax: ptr(integer(port + 3)),
	})
	require(t, err)
	_, err = s.addIPs(t.Context(), name, []string{prefix + ".12", prefix + ".4", prefix + ".3"})
	require(t, err)
	return token
}

func TestPasswordHashesAndProxyAddresses(t *testing.T) {
	first, second := hashPassword(testPassword), hashPassword(testPassword)
	if first == second || !strings.HasPrefix(first, "pbkdf2_sha256$200000$") ||
		!checkPassword(testPassword, first) || checkPassword("wrong password", first) {
		t.Fatal("invalid salted password hashes")
	}
	if _, err := parseProxies([]string{"10.0.1.2/8", "127.0.0.1", "::1"}); err != nil {
		t.Fatal(err)
	}
	networks, err := parseProxies([]string{"10.0.1.2/8"})
	require(t, err)
	if !networks[0].Contains(netip.MustParseAddr("10.0.0.4")) {
		t.Fatalf("trusted range was not normalized: %s", networks[0])
	}
}

func TestAllocationRulesAndRollback(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Unix(1_000_000, 0)
	s.clock = func() time.Time { return now }
	testHost(t, s, "hk", "203.0.113", 20000)
	testHost(t, s, "jp", "198.51.100", 20000)
	for _, name := range []string{"alice", "bob", "charlie", "dave", "erin"} {
		require(t, s.addUser(ctx, name, testPassword, "shared", 5))
	}
	require(t, s.addUser(ctx, "exclusive", testPassword, "exclusive", 5))
	u, err := s.assign(ctx, "alice", assignment{}, false)
	require(t, err)
	if *u.EgressIP != "198.51.100.3" || u.Entry.Port != 20000 {
		t.Fatalf("unexpected automatic assignment: %+v", u)
	}
	u, err = s.assign(ctx, "bob", assignment{Host: "hk"}, false)
	require(t, err)
	if *u.EgressIP != "203.0.113.3" || u.Entry.Port != 20000 {
		t.Fatalf("unexpected assignment on hk: %+v", u)
	}
	u, err = s.assign(ctx, "charlie", assignment{IP: u.EgressIP}, false)
	require(t, err)
	if u.Entry.Port != 20001 {
		t.Fatalf("shared allocation did not reserve a separate port: %+v", u)
	}
	v, err := version(ctx, s.pool)
	require(t, err)
	_, err = s.assign(ctx, "exclusive", assignment{IP: u.EgressIP}, false)
	wantStatus(t, err, 409)
	_, err = s.assign(ctx, "dave", assignment{Host: "hk", Port: ptr(integer(20004))}, false)
	wantStatus(t, err, 409)
	_, err = s.assign(ctx, "dave", assignment{Host: "hk", Port: ptr(integer(20000))}, false)
	wantStatus(t, err, 409)
	_, err = s.assign(ctx, "dave", assignment{IP: u.EgressIP, Host: "jp"}, false)
	wantStatus(t, err, 409)
	_, err = s.addIPs(ctx, "jp", []string{"198.51.100.5", "203.0.113.3"})
	wantStatus(t, err, 409)
	wantStatus(t, s.updateHost(ctx, "hk", hostOptions{PortMin: ptr(integer(20001))}), 409)
	wantStatus(t, s.deleteHost(ctx, "hk"), 409)
	next, err := version(ctx, s.pool)
	require(t, err)
	if v != next {
		t.Fatalf("failed operations changed version from %d to %d", v, next)
	}
	ips, err := listIPs(ctx, s.pool, "jp", s.now())
	require(t, err)
	if len(ips) != 3 {
		t.Fatal("failed IP batch left partial data")
	}
	_, err = s.releaseUser(ctx, "charlie")
	require(t, err)
	u, err = s.assign(ctx, "bob", assignment{IP: ptr("203.0.113.4")}, true)
	require(t, err)
	if u.Entry.Port != 20000 {
		t.Fatal("moving within the host changed the port")
	}
	ips, err = listIPs(ctx, s.pool, "hk", s.now())
	require(t, err)
	if ips[0].Status != "cooldown" || *ips[0].CooldownUntil != s.now()+defaultCooldown {
		t.Fatalf("last holder did not cool the IP: %+v", ips[0])
	}
	_, err = s.assign(ctx, "dave", assignment{IP: ptr("203.0.113.3")}, false)
	wantStatus(t, err, 409)
	now = now.Add((defaultCooldown + 1) * time.Second)
	_, err = s.assign(ctx, "dave", assignment{IP: ptr("203.0.113.3")}, false)
	require(t, err)
	released, err := s.banIP(ctx, "203.0.113.3", "blocked by target")
	require(t, err)
	if !slices.Equal(released, []string{"dave"}) {
		t.Fatalf("unexpected released users: %v", released)
	}
	_, err = s.assign(ctx, "erin", assignment{IP: ptr("203.0.113.3")}, false)
	wantStatus(t, err, 409)
	require(t, s.makeAvailable(ctx, "203.0.113.3"))
	_, err = s.assign(ctx, "erin", assignment{IP: ptr("203.0.113.3")}, false)
	require(t, err)
}

func TestConcurrentAssignmentsAndSnapshots(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	testHost(t, s, "hk", "203.0.113", 20000)
	testHost(t, s, "jp", "198.51.100", 30000)
	for _, name := range []string{"alice", "bob"} {
		require(t, s.addUser(ctx, name, testPassword, "exclusive", 5))
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	names := make(chan string, 2)
	for _, name := range []string{"alice", "bob"} {
		wg.Go(func() {
			_, err := s.assign(ctx, name, assignment{IP: ptr("203.0.113.3")}, false)
			results <- err
			if err == nil {
				names <- name
			}
		})
	}
	wg.Wait()
	close(names)
	if len(names) != 1 {
		t.Fatalf("expected a single holder, got %d", len(names))
	}
	name := <-names
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			wantStatus(t, err, 409)
		}
	}

	token, err := s.addDevice(ctx, name, "desk", "")
	require(t, err)
	device, err := s.identifyDevice(ctx, token)
	require(t, err)
	polled := make(chan struct{})
	pollErrors := make(chan error, 1)
	wg.Go(func() {
		defer close(pollErrors)
		for i := 0; i < 20; i++ {
			err := s.snapshot(ctx, func(tx pgx.Tx) error {
				cfg, err := clientConfig(ctx, tx, device, "proxy")
				if err != nil {
					return err
				}
				body := string(cfg.Body)
				if !strings.Contains(body, `"server_port": 20000`) && !strings.Contains(body, `"server_port": 30000`) {
					return errors.New("saw an uncommitted entry port")
				}
				return nil
			})
			if i == 0 {
				close(polled)
			}
			if err != nil {
				pollErrors <- err
				return
			}
		}
	})
	<-polled
	_, err = s.assign(ctx, name, assignment{Host: "jp"}, true)
	wg.Wait()
	require(t, err)
	require(t, <-pollErrors)
	latest, err := userInfo(ctx, s.pool, name)
	require(t, err)
	if latest.Host != "jp" || latest.Entry.Port != 30000 {
		t.Fatalf("move failed: %+v", latest)
	}
}

func TestPasswordResetWinsOverWaitingLogin(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require(t, s.addUser(ctx, "alice", testPassword, "exclusive", 5))
	const lock = "SELECT pg_advisory_xact_lock(67143001, hashtext(current_schema()))"
	tx, err := s.pool.Begin(ctx)
	require(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, lock)
	require(t, err)

	login := make(chan error, 1)
	go func() {
		_, _, err := s.loginUser(ctx, "alice", testPassword, "desk", "")
		login <- err
	}()
	for {
		var waiting bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE application_name = current_setting('application_name') AND wait_event = 'advisory' AND query = $1)`, lock).
			Scan(&waiting)
		require(t, err)
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err = tx.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE name = 'alice'", hashPassword("new test password"))
	require(t, err)
	require(t, tx.Commit(ctx))
	wantStatus(t, <-login, 401)

	token, _, err := s.loginUser(ctx, "alice", "new test password", "desk", "")
	require(t, err)
	device, err := s.identifyDevice(ctx, token)
	require(t, err)
	token2, _, err := s.loginUser(ctx, "alice", "new test password", "desk", "")
	require(t, err)
	if token2 == token {
		t.Fatal("relogin reused the device token")
	}
	wantStatus(t, s.logoutDevice(ctx, device), 401)
	_, err = s.identifyDevice(ctx, token2)
	require(t, err)
	require(t, s.setUserPassword(ctx, "alice", testPassword, true))
	_, err = s.identifyDevice(ctx, token2)
	wantStatus(t, err, 401)
}

func TestProbeHistoryAndAlertRetries(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	now := time.Unix(1_000_000, 0)
	s.clock = func() time.Time { return now }
	token := testHost(t, s, "hk", "203.0.113", 20000)
	require(t, s.addUser(ctx, "alice", testPassword, "exclusive", 5))
	_, err := s.assign(ctx, "alice", assignment{Host: "hk"}, false)
	require(t, err)
	cfg := json.RawMessage(`{"consecutive_failures":3,"eval_interval":2,"out_of_sync_seconds":60,"agent_stale_seconds":120,"repeat_seconds":10,"webhooks":[{"url":"https://example.test/hook"}]}`)
	require(t, setSettings(ctx, s.pool, map[string]any{"alerts": cfg}))
	h, err := getHost(ctx, s.pool, "hk")
	require(t, err)
	current, err := serverConfig(ctx, s.pool, h)
	require(t, err)

	start, err := version(ctx, s.pool)
	require(t, err)
	results := make([]probeInput, 24)
	for i := range results {
		results[i] = probeInput{Subject: ptr("203.0.113.3"), Target: ptr("https://example.test/"), OK: ptr(i < 21)}
	}
	require(t, s.reportAgent(ctx, "hk", token, heartbeat{ConfigETag: current.ETag, SingboxRunning: ptr(true)}, results))
	series, err := loadSeries(ctx, s.pool, "egress", []string{"203.0.113.3"})
	require(t, err)
	p := series["203.0.113.3"][0]
	if len(p.History) != probeHistory || p.OK || !p.History[16] || p.History[17] {
		t.Fatalf("history was not bounded and ordered: %v", p.History)
	}
	err = s.reportAgent(ctx, "hk", token, heartbeat{}, []probeInput{
		{Subject: ptr("203.0.113.3"), Target: ptr("t"), OK: ptr(true)}, {Subject: ptr("198.51.100.3"), Target: ptr("t"), OK: ptr(true)},
	})
	wantStatus(t, err, 400)
	var entries int
	require(t, s.pool.QueryRow(ctx, "SELECT count(*) FROM probes").Scan(&entries))
	if entries != len(results) {
		t.Fatalf("partially persisted a rejected probe batch: %d", entries)
	}
	var delivery []object
	reject := true
	send := func(_ context.Context, _ string, payload object) error {
		delivery = append(delivery, payload)
		if reject {
			return errors.New("temporary delivery failure")
		}
		return nil
	}
	evaluate := func() {
		t.Helper()
		_, err := s.evaluateAlerts(ctx, send)
		require(t, err)
	}
	evaluate()
	firing, err := listAlerts(ctx, s.pool, false)
	require(t, err)
	if len(firing) != 1 || firing[0].Severity != "critical" || firing[0].Notify == nil || firing[0].Error == nil {
		t.Fatalf("expected a queued, failed critical notification: %+v", firing)
	}
	reject = false
	evaluate()
	evaluate()
	if len(delivery) != 2 || delivery[1]["status"] != "firing" {
		t.Fatalf("wrong retry behavior: %v", delivery)
	}
	now = now.Add(10 * time.Second)
	evaluate()
	if len(delivery) != 3 || delivery[2]["status"] != "firing" {
		t.Fatal("missed a repeat notification")
	}
	result := probeInput{Subject: ptr("203.0.113.3"), Target: ptr("https://example.test/"), OK: ptr(true)}
	require(t, s.reportAgent(ctx, "hk", token, heartbeat{ConfigETag: current.ETag}, []probeInput{result}))
	evaluate()
	if len(delivery) != 4 || delivery[3]["status"] != "resolved" {
		t.Fatal("missed the recovery notification")
	}
	now = now.Add((probeRetention + 1) * time.Second)
	require(t, s.reportAgent(ctx, "hk", token, heartbeat{ConfigETag: current.ETag}, nil))
	require(t, s.pool.QueryRow(ctx, "SELECT count(*) FROM probes").Scan(&entries))
	end, err := version(ctx, s.pool)
	require(t, err)
	if entries != 0 || end != start {
		t.Fatalf("retention or version changed incorrectly: %d probes, version %d -> %d", entries, start, end)
	}
}

func TestAlertPendingRecovery(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	cond := map[string]alertCondition{"out_of_sync/hk": {"agent_out_of_sync", "hk", "warning", "out of sync", 60}}
	cfg := alertSettings{Repeat: 0}
	for _, step := range []struct {
		now   float64
		conds map[string]alertCondition
		state string
	}{
		{100, cond, "pending"}, {159, cond, "pending"}, {159.5, nil, ""},
		{200, cond, "pending"}, {260, cond, "firing"}, {261, nil, "resolved"},
	} {
		t.Run(fmt.Sprintf("%v", step.now), func(t *testing.T) {
			_, err := updateAlerts(ctx, s.pool, step.now, cfg, step.conds)
			require(t, err)
			alerts, err := listAlerts(ctx, s.pool, true)
			require(t, err)
			if step.state == "" && len(alerts) == 0 {
				return
			}
			if len(alerts) != 1 || alerts[0].State != step.state {
				t.Fatalf("wanted %q, got %+v", step.state, alerts)
			}
		})
	}
}
