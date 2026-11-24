package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// usageEnv is a control plane with two exits: hk has one shared egress IPv4 for alice (two devices) and bob;
// jp serves carol.
type usageEnv struct {
	t       *testing.T
	s       *store
	handler http.Handler
	hk, jp  string // agent tokens
	now     time.Time
}

// 2026-11-23 15:00 UTC is 23:00 on Monday 23 November in Singapore.
var usageBase = time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)

func newUsageEnv(t *testing.T) *usageEnv {
	ctx := t.Context()
	// Accounts and devices exist hours before the traffic the tests report; the clock then moves to 15:30 UTC.
	e := &usageEnv{t: t, s: testStore(t), now: usageBase.Add(-6 * time.Hour)}
	defer func() { e.now = usageBase.Add(30 * time.Minute) }()
	e.s.clock = func() time.Time { return e.now }
	e.handler = newAPI(e.s, testAdminToken, "", []netip.Prefix{})
	e.hk = testHost(t, e.s, "hk", "203.0.113", 20000)
	e.jp = testHost(t, e.s, "jp", "198.51.100", 30000)
	for _, u := range []string{"alice", "bob", "carol"} {
		require(t, e.s.addUser(ctx, u, testPassword, "shared", 5))
	}
	shared := "203.0.113.3"
	_, err := e.s.assign(ctx, "alice", assignment{IP: &shared}, false)
	require(t, err)
	_, err = e.s.assign(ctx, "bob", assignment{IP: &shared}, false)
	require(t, err)
	_, err = e.s.assign(ctx, "carol", assignment{Host: "jp"}, false)
	require(t, err)
	for _, d := range [][2]string{{"alice", "mac"}, {"alice", "win"}, {"bob", "phone"}, {"carol", "laptop"}} {
		_, err := e.s.addDevice(ctx, d[0], d[1], "")
		require(t, err)
	}
	return e
}

func (e *usageEnv) do(method, path, token, body string) (int, map[string]any) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// fetchConfig is what an agent does every cycle; it records which devices the host serves.
func (e *usageEnv) fetchConfig(token string) {
	e.t.Helper()
	if code, _ := e.do("GET", "/agent/server-config", token, ""); code != 200 {
		e.t.Fatalf("server config: HTTP %d", code)
	}
}

type dev struct {
	name          string
	cred          string // hex SHA-256 of the VLESS UUID, as current agents send it
	up, down, cut int64
}

func usageBody(collector string, seq int64, hour time.Time, flags string, devices ...dev) string {
	var list []string
	for _, d := range devices {
		list = append(list, fmt.Sprintf(`{"name":%q,"credential":%q,"up":%d,"down":%d,"cut":%d}`, d.name, d.cred, d.up, d.down, d.cut))
	}
	if flags == "" {
		flags = `"started":false`
	}
	return fmt.Sprintf(`{"collector":%q,"agent_version":"agent-test","singbox_version":"1.14.4","state":"collecting",
		"detail":"","seq":%d,"hours":[{"hour":%d,%s,"unattributed":{"up":0,"down":0},"devices":[%s]}]}`,
		collector, seq, hour.Unix(), flags, strings.Join(list, ","))
}

// credential is what a current agent sends with a device's bytes: the SHA-256 of the device's VLESS UUID.
func (e *usageEnv) credential(user, device string) string {
	e.t.Helper()
	var uuid string
	require(e.t, e.s.pool.QueryRow(e.t.Context(), "SELECT uuid::text FROM devices WHERE user_name = $1 AND name = $2",
		user, device).Scan(&uuid))
	return credentialHash(uuid)
}

func (e *usageEnv) deviceID(user, device string) int64 {
	e.t.Helper()
	var id int64
	require(e.t, e.s.pool.QueryRow(e.t.Context(), "SELECT id FROM devices WHERE user_name = $1 AND name = $2",
		user, device).Scan(&id))
	return id
}

func (e *usageEnv) report(token, body string) (int, map[string]any) {
	e.t.Helper()
	return e.do("POST", "/agent/usage", token, body)
}

func (e *usageEnv) usage(query string) map[string]any {
	e.t.Helper()
	code, out := e.do("GET", "/admin/usage?"+query, testAdminToken, "")
	if code != 200 {
		e.t.Fatalf("GET /admin/usage?%s: HTTP %d %v", query, code, out)
	}
	return out
}

func rowFor(t *testing.T, report map[string]any, user, device string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, r := range report["rows"].([]any) {
		row := r.(map[string]any)
		if row["user"] == user && row["device"] == device {
			if found != nil {
				t.Fatalf("two rows for %s/%s", user, device)
			}
			found = row
		}
	}
	if found == nil {
		t.Fatalf("no row for %s/%s in %v", user, device, report["rows"])
	}
	return found
}

func wantRow(t *testing.T, row map[string]any, up, down int64, status string) {
	t.Helper()
	if row["upload"] != float64(up) || row["download"] != float64(down) || row["total"] != float64(up+down) || row["status"] != status {
		t.Fatalf("want upload=%d download=%d total=%d %s, got %v", up, down, up+down, status, row)
	}
}

func TestUsageReportsAreScopedDeduplicatedAndSummed(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	e.fetchConfig(e.jp)

	body := usageBody("c-hk", 1, usageBase, "",
		dev{name: "alice/mac", up: 1000, down: 50000}, dev{name: "alice/win", up: 70, down: 90},
		dev{name: "bob/phone", up: 500, down: 5000}, dev{name: "carol/laptop", up: 999, down: 999})
	code, out := e.report(e.hk, body)
	if code != 200 || out["duplicate"] != false || fmt.Sprint(out["rejected"]) != "[carol/laptop]" {
		t.Fatalf("first report: HTTP %d %v", code, out)
	}
	// The same batch again (a retry after a lost acknowledgement) and a reused seq with other content are ignored.
	if code, out := e.report(e.hk, body); code != 200 || out["duplicate"] != true {
		t.Fatalf("replay: HTTP %d %v", code, out)
	}
	if code, out := e.report(e.hk, usageBody("c-hk", 1, usageBase, "", dev{name: "alice/mac", up: 1, down: 1})); code != 200 || out["duplicate"] != true {
		t.Fatalf("reused seq: HTTP %d %v", code, out)
	}
	// jp never served alice: it cannot add to her devices, only to its own rejected counters.
	if code, out := e.report(e.jp, usageBody("c-jp", 1, usageBase, "", dev{name: "alice/mac", up: 5, down: 5},
		dev{name: "carol/laptop", up: 11, down: 22})); code != 200 || fmt.Sprint(out["rejected"]) != "[alice/mac]" {
		t.Fatalf("jp report: HTTP %d %v", code, out)
	}
	// A second batch for the same hour adds up.
	if code, _ := e.report(e.hk, usageBody("c-hk", 2, usageBase, "", dev{name: "alice/mac", up: 1, down: 2})); code != 200 {
		t.Fatal("second batch refused")
	}

	r := e.usage("period=day&date=2026-11-23")
	wantRow(t, rowFor(t, r, "alice", "mac"), 1001, 50002, "complete")
	wantRow(t, rowFor(t, r, "alice", "win"), 70, 90, "complete")
	wantRow(t, rowFor(t, r, "bob", "phone"), 500, 5000, "complete")
	wantRow(t, rowFor(t, r, "carol", "laptop"), 11, 22, "complete")
	totals := r["totals"].(map[string]any)
	if totals["upload"] != float64(1001+70+500+11) || totals["total"] != totals["upload"].(float64)+totals["download"].(float64) {
		t.Fatalf("totals: %v", totals)
	}
	hosts := r["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("expected rejected bytes on both hosts: %v", hosts)
	}
	for _, h := range hosts {
		h := h.(map[string]any)
		if (h["host"] == "hk" && h["rejected_upload"] != float64(999)) || (h["host"] == "jp" && h["rejected_upload"] != float64(5)) {
			t.Fatalf("rejected bytes: %v", hosts)
		}
	}

	// Filters by user and device.
	r = e.usage("period=day&date=2026-11-23&user=alice&device=win")
	if rows := r["rows"].([]any); len(rows) != 1 {
		t.Fatalf("filter: %v", rows)
	}
	if fmt.Sprint(r["users"]) != "[alice bob carol]" || fmt.Sprint(r["devices"]) != "[mac win]" {
		t.Fatalf("filter choices: %v %v", r["users"], r["devices"])
	}
}

func TestUsageValidationAuthorizationAndCollectorStatus(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	for _, bad := range []string{
		strings.Replace(usageBody("c", 1, usageBase, ""), fmt.Sprint(usageBase.Unix()), fmt.Sprint(usageBase.Unix()+60), 1),
		usageBody("c", 1, usageBase.Add(3*time.Hour), ""),
		usageBody("c", 1, usageBase.AddDate(-2, 0, 0), ""),
		usageBody("c", 1, usageBase, "", dev{name: "alice/mac", up: -1}),
		usageBody("c", 0, usageBase, ""),
		usageBody("bad collector!", 1, usageBase, ""),
		`{"collector":"c","state":"collecting","seq":null,"hours":[{"hour":0,"devices":[]}]}`,
		`{"collector":"c","state":"bogus"}`,
	} {
		if code, out := e.report(e.hk, bad); code != 400 {
			t.Fatalf("expected HTTP 400 for %s, got %d %v", bad, code, out)
		}
	}
	if code, _ := e.report("not-a-token", usageBody("c", 1, usageBase, "")); code != 401 {
		t.Fatal("an unknown agent token must be refused")
	}
	deviceToken, err := e.s.addDevice(t.Context(), "alice", "tablet", "")
	require(t, err)
	if code, _ := e.do("GET", "/admin/usage", deviceToken, ""); code != 401 {
		t.Fatal("the usage report is for administrators only")
	}
	if code, _ := e.do("GET", "/admin/usage", e.hk, ""); code != 401 {
		t.Fatal("agents cannot read the usage report")
	}
	if code, _ := e.do("GET", "/admin/usage?period=year", testAdminToken, ""); code != 400 {
		t.Fatal("unknown period must be refused")
	}

	// A status-only report from an exit whose sing-box lacks the API service.
	if code, _ := e.report(e.jp, `{"collector":"c-jp","state":"unavailable","detail":"sing-box 1.13.0 lacks the API service","seq":null,"hours":[]}`); code != 200 {
		t.Fatal("status report refused")
	}
	if code, _ := e.report(e.hk, `{"collector":"c-hk","state":"collecting","seq":null,"hours":[]}`); code != 200 {
		t.Fatal("status report refused")
	}
	_, err = e.s.addHost(t.Context(), "old", hostOptions{PublicHost: ptr("192.0.2.2"), ServerName: ptr("www.example.com"),
		PortMin: ptr(integer(40000)), PortMax: ptr(integer(40010))})
	require(t, err)
	collectors := map[string]map[string]any{}
	for _, c := range e.usage("")["collectors"].([]any) {
		collectors[c.(map[string]any)["host"].(string)] = c.(map[string]any)
	}
	if collectors["hk"]["status"] != "collecting" || collectors["jp"]["status"] != "unavailable" ||
		!strings.Contains(collectors["jp"]["note"].(string), "lacks the API service") ||
		collectors["old"]["status"] != "unavailable" || !strings.Contains(collectors["old"]["note"].(string), "does not report usage") {
		t.Fatalf("collector status: %v", collectors)
	}
	e.now = e.now.Add(10 * time.Minute)
	for _, c := range e.usage("")["collectors"].([]any) {
		if c := c.(map[string]any); c["host"] == "hk" && c["status"] != "stale" {
			t.Fatalf("expected a stale collector: %v", c)
		}
	}
}

func TestUsageKeepsDeviceIdentityThroughMovesRevocationAndDeletion(t *testing.T) {
	ctx := t.Context()
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	h1, h2 := usageBase.Add(-2*time.Hour), usageBase.Add(-time.Hour)
	if code, _ := e.report(e.hk, usageBody("c-hk", 1, h1, "", dev{name: "alice/mac", up: 100, down: 200})); code != 200 {
		t.Fatal("report refused")
	}

	// alice moves to jp. hk's last batch (traffic from before the move) arrives afterwards and still counts.
	_, err := e.s.assign(ctx, "alice", assignment{Host: "jp"}, true)
	require(t, err)
	e.fetchConfig(e.jp)
	e.fetchConfig(e.hk)
	if code, out := e.report(e.hk, usageBody("c-hk", 2, h2, "", dev{name: "alice/mac", up: 1, down: 2})); code != 200 || len(out["rejected"].([]any)) != 0 {
		t.Fatalf("late report from the previous exit: %d %v", code, out)
	}
	if code, out := e.report(e.jp, usageBody("c-jp", 1, h2, "", dev{name: "alice/mac", up: 10, down: 20})); code != 200 || len(out["rejected"].([]any)) != 0 {
		t.Fatalf("report from the new exit: %d %v", code, out)
	}
	row := rowFor(t, e.usage("period=day&date=2026-11-23&user=alice&device=mac"), "alice", "mac")
	wantRow(t, row, 111, 222, "complete")
	if fmt.Sprint(row["hosts"]) != "[hk jp]" {
		t.Fatalf("the device used both exits: %v", row["hosts"])
	}
	id := row["device_id"]

	// Revoked: the row stays with its history; traffic seen before the revocation is still accepted.
	require(t, e.s.revokeDevice(ctx, "alice", "mac"))
	e.fetchConfig(e.jp)
	if code, out := e.report(e.jp, usageBody("c-jp", 2, h2, "", dev{name: "alice/mac", up: 1, down: 1})); code != 200 || len(out["rejected"].([]any)) != 0 {
		t.Fatalf("report after revocation: %d %v", code, out)
	}
	row = rowFor(t, e.usage("period=day&date=2026-11-23&user=alice"), "alice", "mac")
	if row["device_state"] != "revoked" || row["device_id"] != id {
		t.Fatalf("revoked device: %v", row)
	}
	// Re-registered under the same name: the same identity (new credential), so usage continues on it.
	_, err = e.s.addDevice(ctx, "alice", "mac", "")
	require(t, err)
	e.fetchConfig(e.jp)
	if code, _ := e.report(e.jp, usageBody("c-jp", 3, usageBase, "", dev{name: "alice/mac", up: 5, down: 5})); code != 200 {
		t.Fatal("report after re-registration refused")
	}
	row = rowFor(t, e.usage("period=day&date=2026-11-23&user=alice"), "alice", "mac")
	wantRow(t, row, 117, 228, "complete")
	if row["device_state"] != "active" || row["device_id"] != id {
		t.Fatalf("re-registered device: %v", row)
	}

	// The user is deleted and a new alice signs in a "mac": old history keeps the old identity, new traffic goes to
	// the new device even though the names are equal. The new configuration names it with its own ID.
	require(t, e.s.deleteUser(ctx, "alice"))
	require(t, e.s.addUser(ctx, "alice", testPassword, "shared", 5))
	_, err = e.s.assign(ctx, "alice", assignment{Host: "jp"}, false)
	require(t, err)
	_, err = e.s.addDevice(ctx, "alice", "mac", "")
	require(t, err)
	e.fetchConfig(e.jp)
	if code, _ := e.report(e.jp, usageBody("c-jp", 4, usageBase, "", dev{name: "alice/mac", cred: e.credential("alice", "mac"), up: 3, down: 4})); code != 200 {
		t.Fatal("report for the new device refused")
	}
	rows := e.usage("period=day&date=2026-11-23&user=alice&device=mac")["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("expected the deleted and the new device separately: %v", rows)
	}
	for _, r := range rows {
		r := r.(map[string]any)
		switch r["device_state"] {
		case "deleted":
			wantRow(t, r, 117, 228, "complete")
			if r["device_id"] != id {
				t.Fatalf("history moved to another identity: %v", r)
			}
		case "active":
			wantRow(t, r, 3, 4, "complete")
		default:
			t.Fatalf("unexpected row %v", r)
		}
	}
}

func TestUsagePeriodsMeasuredZeroAndIncompleteness(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	e.now = time.Date(2026, 12, 2, 4, 0, 0, 0, time.UTC)
	// 15:00 UTC is still 23 November in Singapore; 16:00 UTC is 24 November. 30 Nov 16:00 UTC is 1 December.
	h23, h24, hDec := usageBase, usageBase.Add(time.Hour), time.Date(2026, 11, 30, 16, 0, 0, 0, time.UTC)
	e.report(e.hk, usageBody("c", 1, h23, `"started":true`, dev{name: "alice/mac", up: 1, down: 1},
		dev{name: "alice/win"}, dev{name: "bob/phone"}))
	e.report(e.hk, usageBody("c", 2, h24, `"gap_seconds":90`, dev{name: "alice/mac", up: 2, down: 2},
		dev{name: "alice/win"}, dev{name: "bob/phone", up: 5, down: 5, cut: 2}))
	e.report(e.hk, usageBody("c", 3, hDec, "", dev{name: "alice/mac", up: 4, down: 4}, dev{name: "alice/win"},
		dev{name: "bob/phone"}))

	day23 := e.usage("period=day&date=2026-11-23")
	wantRow(t, rowFor(t, day23, "alice", "mac"), 1, 1, "incomplete") // history started that day
	if day23["start"] != "2026-11-23" || day23["end"] != "2026-11-24" || day23["in_progress"] != false {
		t.Fatalf("day bounds: %v %v %v", day23["start"], day23["end"], day23["in_progress"])
	}
	wantRow(t, rowFor(t, day23, "carol", "laptop"), 0, 0, "unavailable") // jp has no collector

	day24 := e.usage("period=day&date=2026-11-24")
	wantRow(t, rowFor(t, day24, "alice", "win"), 0, 0, "incomplete") // the gap concerns the whole host
	bob := rowFor(t, day24, "bob", "phone")
	wantRow(t, bob, 5, 5, "incomplete")
	if bob["cut_connections"] != float64(2) || len(bob["reasons"].([]any)) != 2 {
		t.Fatalf("expected cut and gap reasons: %v", bob)
	}

	day30 := e.usage("period=day&date=2026-11-30")
	wantRow(t, rowFor(t, day30, "alice", "mac"), 0, 0, "unavailable") // nothing recorded that Singapore day
	dec1 := e.usage("period=day&date=2026-12-01")
	wantRow(t, rowFor(t, dec1, "alice", "win"), 0, 0, "complete") // a measured zero
	wantRow(t, rowFor(t, dec1, "alice", "mac"), 4, 4, "complete")

	// Weeks start on Monday: Sunday 29 November belongs to the week of 23 November.
	week := e.usage("period=week&date=2026-11-29")
	if week["start"] != "2026-11-23" || week["end"] != "2026-11-30" || week["previous"] != "2026-11-16" || week["next"] != "2026-11-30" {
		t.Fatalf("week bounds: %v %v %v %v", week["start"], week["end"], week["previous"], week["next"])
	}
	wantRow(t, rowFor(t, week, "alice", "mac"), 3, 3, "incomplete")

	nov := e.usage("period=month&date=2026-11-05")
	wantRow(t, rowFor(t, nov, "alice", "mac"), 3, 3, "incomplete")
	dec := e.usage("period=month&date=2026-12-31")
	wantRow(t, rowFor(t, dec, "alice", "mac"), 4, 4, "complete")
	if dec["in_progress"] != true || dec["next"] != nil {
		t.Fatalf("the current month is in progress with no next period: %v %v", dec["in_progress"], dec["next"])
	}
	if fmt.Sprint(e.usage("period=month")["recorded_periods"]) != "[2026-12-01 2026-11-01]" {
		t.Fatalf("recorded months: %v", e.usage("period=month")["recorded_periods"])
	}
	if fmt.Sprint(e.usage("period=day")["recorded_periods"]) != "[2026-12-01 2026-11-24 2026-11-23]" {
		t.Fatalf("recorded days: %v", e.usage("period=day")["recorded_periods"])
	}
}

func TestUsagePeriodBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 23, 16, 30, 0, 0, time.UTC) // 00:30 on 24 November in Singapore
	for _, c := range []struct{ kind, date, start, end string }{
		{"day", "", "2026-11-24", "2026-11-25"},
		{"week", "", "2026-11-23", "2026-11-30"},
		{"week", "2026-11-23", "2026-11-23", "2026-11-30"},
		{"week", "2026-11-22", "2026-11-16", "2026-11-23"},
		{"month", "2026-02-28", "2026-02-01", "2026-03-01"},
		{"month", "2024-02-29", "2024-02-01", "2024-03-01"},
	} {
		p, err := parseUsagePeriod(c.kind, c.date, now)
		require(t, err)
		if p.Start.Format("2006-01-02") != c.start || p.End.Format("2006-01-02") != c.end || p.Start.Weekday() == time.Sunday && c.kind == "week" {
			t.Fatalf("%s %s: got %s..%s", c.kind, c.date, p.Start, p.End)
		}
		if _, offset := p.Start.Zone(); offset != 8*3600 || p.Start.Unix()%3600 != 0 {
			t.Fatalf("periods must start on a Singapore midnight, an exact UTC hour: %v", p.Start)
		}
	}
	if _, err := parseUsagePeriod("day", "23/11/2026", now); err == nil {
		t.Fatal("bad date accepted")
	}
}

// -- deleted and recreated accounts with the same names ----------------------------------------------------------

// The regression from the independent review, unchanged: a delayed batch with a legacy name from an hour before the
// account was recreated stays with the original device.
func TestReviewDelayedUsageStaysWithDeletedDevice(t *testing.T) {
	e := newUsageEnv(t)
	ctx := t.Context()
	e.fetchConfig(e.hk)

	readDevice := func() int64 {
		t.Helper()
		var id int64
		require(t, e.s.pool.QueryRow(ctx,
			"SELECT id FROM devices WHERE user_name = 'alice' AND name = 'mac'").Scan(&id))
		return id
	}
	upload := func(id int64) int64 {
		t.Helper()
		var up int64
		require(t, e.s.pool.QueryRow(ctx,
			"SELECT COALESCE(sum(up), 0)::bigint FROM usage_device_hours WHERE device_id = $1", id).Scan(&up))
		return up
	}
	oldID := readDevice()
	report := func(seq, up int64) {
		t.Helper()
		if code, _ := e.report(e.hk, usageBody("review-hk", seq, usageBase, "",
			dev{name: "alice/mac", up: up})); code != 200 {
			t.Fatalf("report returned HTTP %d", code)
		}
	}
	report(1, 100)
	e.now = usageBase.Add(2 * time.Hour)
	require(t, e.s.deleteUser(ctx, "alice"))
	require(t, e.s.addUser(ctx, "alice", testPassword, "shared", 5))
	_, err := e.s.assign(ctx, "alice", assignment{IP: ptr("203.0.113.3")}, false)
	require(t, err)
	_, err = e.s.addDevice(ctx, "alice", "mac", "")
	require(t, err)
	newID := readDevice()
	if oldID == newID {
		t.Fatal("the recreated account must have a different device identity")
	}
	e.fetchConfig(e.hk)
	// This delayed sample is from an hour before the new account existed.
	report(2, 7)
	if old, fresh := upload(oldID), upload(newID); old != 107 || fresh != 0 {
		t.Fatalf("late traffic moved to the recreated account: old device %d bytes, new device %d bytes", old, fresh)
	}
}

// recreate deletes alice and creates her again with a "mac" on the same shared IP, at the current clock.
func (e *usageEnv) recreateAlice() {
	e.t.Helper()
	ctx := e.t.Context()
	require(e.t, e.s.deleteUser(ctx, "alice"))
	require(e.t, e.s.addUser(ctx, "alice", testPassword, "shared", 5))
	_, err := e.s.assign(ctx, "alice", assignment{IP: ptr("203.0.113.3")}, false)
	require(e.t, err)
	_, err = e.s.addDevice(ctx, "alice", "mac", "")
	require(e.t, err)
	e.fetchConfig(e.hk)
}

func (e *usageEnv) deviceBytes(id int64) (up, down int64, ambiguous bool) {
	e.t.Helper()
	require(e.t, e.s.pool.QueryRow(e.t.Context(), `SELECT COALESCE(sum(up), 0)::bigint, COALESCE(sum(down), 0)::bigint,
		COALESCE(bool_or(ambiguous), false) FROM usage_device_hours WHERE device_id = $1`, id).Scan(&up, &down, &ambiguous))
	return
}

func (e *usageEnv) hostCounters(host string) (rejected, unresolved [2]int64) {
	e.t.Helper()
	require(e.t, e.s.pool.QueryRow(e.t.Context(), `SELECT COALESCE(sum(rejected_up), 0)::bigint,
		COALESCE(sum(rejected_down), 0)::bigint, COALESCE(sum(unresolved_up), 0)::bigint,
		COALESCE(sum(unresolved_down), 0)::bigint FROM usage_host_hours WHERE host = $1`, host).
		Scan(&rejected[0], &rejected[1], &unresolved[0], &unresolved[1]))
	return
}

// Both accounts exist within one reporting hour. With the credential hashes current agents send, every byte lands
// on the device that moved it, whichever order the batches arrive in, and retries change nothing.
func TestUsageSameHourRecreationKeepsEachDevicesTraffic(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	oldID, oldCred := e.deviceID("alice", "mac"), e.credential("alice", "mac")
	e.now = usageBase.Add(40 * time.Minute)
	e.recreateAlice()
	newID, newCred := e.deviceID("alice", "mac"), e.credential("alice", "mac")
	if oldID == newID || oldCred == newCred {
		t.Fatal("the recreated device must have a new ID and credential")
	}
	// The new device's traffic is reported first; the old device's delayed batch for the same hour arrives later.
	fresh := usageBody("c-hk", 1, usageBase, "", dev{name: "alice/mac", cred: newCred, up: 5, down: 6})
	late := usageBody("c-hk", 2, usageBase, "", dev{name: "alice/mac", cred: oldCred, up: 100, down: 200},
		dev{name: "alice/mac", cred: newCred, up: 1, down: 1})
	for _, body := range []string{fresh, late, late, fresh} { // each batch twice: retries after a lost acknowledgement
		if code, out := e.report(e.hk, body); code != 200 || len(out["unresolved"].([]any))+len(out["rejected"].([]any)) != 0 {
			t.Fatalf("report: HTTP %d %v", code, out)
		}
	}
	// A reused seq with other content is still a duplicate.
	if _, out := e.report(e.hk, usageBody("c-hk", 2, usageBase, "", dev{name: "alice/mac", cred: oldCred, up: 999})); out["duplicate"] != true {
		t.Fatalf("reused seq: %v", out)
	}
	if up, down, amb := e.deviceBytes(oldID); up != 100 || down != 200 || amb {
		t.Fatalf("original device: %d/%d ambiguous=%v, want 100/200", up, down, amb)
	}
	if up, down, amb := e.deviceBytes(newID); up != 6 || down != 7 || amb {
		t.Fatalf("recreated device: %d/%d ambiguous=%v, want 6/7", up, down, amb)
	}
	if _, unresolved := e.hostCounters("hk"); unresolved != [2]int64{} {
		t.Fatalf("nothing should be unresolved: %v", unresolved)
	}
	rows := e.usage("period=day&date=2026-11-23&user=alice&device=mac")["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("expected the deleted and the recreated device: %v", rows)
	}
	for _, r := range rows {
		r := r.(map[string]any)
		switch r["device_state"] {
		case "deleted":
			wantRow(t, r, 100, 200, "complete")
		case "active":
			wantRow(t, r, 6, 7, "complete")
		default:
			t.Fatalf("unexpected row %v", r)
		}
	}
	// Revoked and registered again: a new credential for the same device, and both credentials count for it.
	require(t, e.s.revokeDevice(t.Context(), "alice", "mac"))
	_, err := e.s.addDevice(t.Context(), "alice", "mac", "")
	require(t, err)
	e.fetchConfig(e.hk)
	rotated := e.credential("alice", "mac")
	if rotated == newCred || e.deviceID("alice", "mac") != newID {
		t.Fatal("re-registration keeps the device ID and changes the credential")
	}
	// Moving the account to another exit keeps credential-tagged traffic attributable on both exits.
	_, err = e.s.assign(t.Context(), "alice", assignment{Host: "jp"}, true)
	require(t, err)
	e.fetchConfig(e.jp)
	for _, c := range []struct {
		token, collector string
		cred             string
	}{{e.jp, "c-jp", rotated}, {e.hk, "c-hk", newCred}, {e.hk, "c-hk", rotated}} {
		seq := map[string]int64{"c-jp": 1, "c-hk": 3}[c.collector]
		if c.cred == rotated && c.collector == "c-hk" {
			seq = 4
		}
		if code, out := e.report(c.token, usageBody(c.collector, seq, usageBase, "", dev{name: "alice/mac", cred: c.cred, up: 10, down: 10})); code != 200 ||
			len(out["rejected"].([]any))+len(out["unresolved"].([]any)) != 0 {
			t.Fatalf("after the move (%s): %d %v", c.collector, code, out)
		}
	}
	if up, down, _ := e.deviceBytes(newID); up != 36 || down != 37 {
		t.Fatalf("recreated device after the move: %d/%d, want 36/37", up, down)
	}
}

// Without a credential (an agent that cannot prove which configuration sing-box runs), two devices that both existed
// in the hour cannot be told apart: the bytes are counted once as unresolved on the exit, never on either device,
// and both devices show the hour as incomplete. An hour only one of them could have carried still resolves.
func TestUsageLegacyNamesThatCannotBeToldApartStayUnresolved(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	oldID := e.deviceID("alice", "mac")
	if code, _ := e.report(e.hk, usageBody("c-hk", 1, usageBase, "", dev{name: "alice/mac", up: 100})); code != 200 {
		t.Fatal("report refused")
	}
	e.now = usageBase.Add(45 * time.Minute)
	e.recreateAlice()
	newID := e.deviceID("alice", "mac")

	same := usageBody("c-hk", 2, usageBase, "", dev{name: "alice/mac", up: 7, down: 3})
	for i := 0; i < 2; i++ { // the retry must not count the unresolved bytes twice
		code, out := e.report(e.hk, same)
		if code != 200 || (i == 0 && fmt.Sprint(out["unresolved"]) != "[alice/mac]") || (i == 1 && out["duplicate"] != true) {
			t.Fatalf("attempt %d: HTTP %d %v", i, code, out)
		}
	}
	if up, _, amb := e.deviceBytes(oldID); up != 100 || !amb {
		t.Fatalf("original device: up %d ambiguous=%v, want 100 and ambiguous", up, amb)
	}
	if up, _, amb := e.deviceBytes(newID); up != 0 || !amb {
		t.Fatalf("recreated device: up %d ambiguous=%v, want 0 and ambiguous", up, amb)
	}
	if _, unresolved := e.hostCounters("hk"); unresolved != [2]int64{7, 3} {
		t.Fatalf("unresolved bytes on hk: %v, want [7 3]", unresolved)
	}
	r := e.usage("period=day&date=2026-11-23&user=alice&device=mac")
	for _, row := range r["rows"].([]any) {
		row := row.(map[string]any)
		if row["status"] != "incomplete" || !strings.Contains(fmt.Sprint(row["reasons"]), "unresolved") {
			t.Fatalf("both devices must show the ambiguity: %v", row)
		}
	}
	if hosts := r["hosts"].([]any); len(hosts) != 1 || hosts[0].(map[string]any)["unresolved_upload"] != float64(7) {
		t.Fatalf("host summary: %v", hosts)
	}
	// An unknown credential leaves the name-matched bytes unresolved.
	unknown := strings.Repeat("ab", 32)
	if _, out := e.report(e.hk, usageBody("c-hk", 3, usageBase, "", dev{name: "alice/mac", cred: unknown, up: 1})); fmt.Sprint(out["unresolved"]) != "[alice/mac]" {
		t.Fatalf("an unknown credential must not pick a device: %v", out)
	}
	// An hour before any alice/mac existed belongs to nobody.
	e.now = usageBase.Add(3 * time.Hour)
	if _, out := e.report(e.hk, usageBody("c-hk", 4, usageBase.Add(-24*time.Hour), "", dev{name: "alice/mac", up: 1})); fmt.Sprint(out["rejected"]) != "[alice/mac]" {
		t.Fatalf("an hour before any alice/mac existed: %v", out)
	}
}

// A credential counts only for the names it was served under, on an exit that served it.
func TestUsageCredentialsMustMatchTheirNamesAndExit(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	e.fetchConfig(e.jp)
	aliceID, bobID := e.deviceID("alice", "mac"), e.deviceID("bob", "phone")
	_, out := e.report(e.hk, usageBody("c-hk", 1, usageBase, "",
		dev{name: "alice/mac", cred: e.credential("bob", "phone"), up: 50},       // bob's credential, alice's names
		dev{name: "carol/laptop", cred: e.credential("carol", "laptop"), up: 60}, // served by jp, not hk
		dev{name: "alice/mac/7", up: 1},                                          // not a VLESS user name we render
		dev{name: "alice/mac", cred: e.credential("alice", "mac"), up: 5}))
	if fmt.Sprint(out["rejected"]) != "[alice/mac carol/laptop alice/mac/7]" {
		t.Fatalf("rejected: %v", out["rejected"])
	}
	if up, _, _ := e.deviceBytes(bobID); up != 0 {
		t.Fatal("bob must not receive bytes reported under alice's names")
	}
	if up, _, _ := e.deviceBytes(aliceID); up != 5 {
		t.Fatal("alice's own credential must count")
	}
	if rejected, _ := e.hostCounters("hk"); rejected[0] != 111 {
		t.Fatalf("rejected upload on hk: %d, want 111", rejected[0])
	}
	if code, _ := e.report(e.hk, usageBody("c-hk", 2, usageBase, "", dev{name: "alice/mac", cred: "NOT-HEX"})); code != 400 {
		t.Fatal("a malformed credential must be refused")
	}
	// The server configuration itself is unchanged by usage: names stay "<user>/<device>".
	_, cfg := e.do("GET", "/agent/server-config", e.hk, "")
	users := cfg["inbounds"].([]any)[0].(map[string]any)["users"].([]any)
	if users[0].(map[string]any)["name"] != "alice/mac" {
		t.Fatalf("rendered VLESS user name changed: %v", users[0])
	}
}

func TestUsageUnknownCredentialDoesNotCountForTheOnlyMatchingName(t *testing.T) {
	e := newUsageEnv(t)
	e.fetchConfig(e.hk)
	id := e.deviceID("alice", "mac")
	unrecorded := strings.Repeat("ab", 32)
	code, out := e.report(e.hk, usageBody("review-hk", 1, usageBase, "",
		dev{name: "alice/mac", cred: unrecorded, up: 7, down: 3}))
	if code != 200 || fmt.Sprint(out["unresolved"]) != "[alice/mac]" {
		t.Fatalf("unknown credential must remain unresolved: HTTP %d %v", code, out)
	}
	if up, down, ambiguous := e.deviceBytes(id); up != 0 || down != 0 || !ambiguous {
		t.Fatalf("device totals: %d/%d ambiguous=%v, want 0/0 ambiguous=true", up, down, ambiguous)
	}
	if _, unresolved := e.hostCounters("hk"); unresolved != [2]int64{7, 3} {
		t.Fatalf("unresolved bytes on hk: %v, want [7 3]", unresolved)
	}
}
